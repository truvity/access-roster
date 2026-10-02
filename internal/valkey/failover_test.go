package valkey_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/truvity/access-roster/internal/valkey"
)

// The property a redundant store exists for, in the form of a test: a
// shard's primary dies without warning, its replica takes over, and the
// client keeps working -- **without the process being restarted and
// without anything already written being lost**.
//
// The reconnect test proves one server coming back. This one proves the
// thing a single server cannot do: a node that never comes back. It runs
// the client the way a store with more than one shard is dialled, in
// cluster mode through one seed address, and kills (SIGKILL, not a
// graceful stop: a drain hands the shard over before it exits, a dead
// node does not) the primary holding a key that was written before.
//
// Two things are asserted, and they are different promises:
//
//   - what was written before the kill is still there afterwards. A
//     session and its refresh token surviving a node loss is the whole
//     point; an empty store after a failover is a sign-in for everyone.
//   - the client answers again on its own, within a bound. Every shard
//     takes writes again, including the one that lost its primary.
//
// Needs docker and a Valkey Cluster of at least three shards with one
// replica each, every node a container. Set VALKEY_TEST_CLUSTER_ADDR to
// any node's address and VALKEY_TEST_CLUSTER_CONTAINERS to the
// comma-separated container names. The killed container is started again
// at the end, and rejoins as a replica.
func TestTheClientSurvivesTheLossOfAPrimary(t *testing.T) {
	seed, names := os.Getenv("VALKEY_TEST_CLUSTER_ADDR"), os.Getenv("VALKEY_TEST_CLUSTER_CONTAINERS")
	if seed == "" || names == "" {
		t.Skip("set VALKEY_TEST_CLUSTER_ADDR and VALKEY_TEST_CLUSTER_CONTAINERS")
	}

	ctx := context.Background()

	store, err := valkey.OpenState(ctx, valkey.Config{Address: seed, Cluster: true, Prefix: "failover-test"})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Enough keys that every shard holds some, so "every shard answers
	// again" is checked rather than hoped.
	const keys = 64
	for i := range keys {
		if err = store.Set(ctx, fmt.Sprintf("before-%d", i), []byte("kept"), time.Hour); err != nil {
			t.Fatalf("write before the kill: %v", err)
		}
	}

	// Replication is asynchronous. A write acknowledged a moment before
	// its primary dies can be lost with it, and that is the documented
	// price of this design, not what this test is about; give the
	// replicas the moment they need so that what is asserted afterwards
	// is the failover, not the race.
	time.Sleep(time.Second)

	victim := primaryContainer(ctx, t, seed, "failover-test:before-0", strings.Split(names, ","))
	t.Logf("killing %s, the primary of the first key's shard", victim)

	if out, err := exec.Command("docker", "kill", "--signal", "KILL", victim).CombinedOutput(); err != nil {
		t.Fatalf("kill: %v %s", err, out)
	}
	defer func() {
		if out, err := exec.Command("docker", "start", victim).CombinedOutput(); err != nil {
			t.Logf("start %s again: %v %s", victim, err, out)
		}
	}()

	killed := time.Now()
	// The whole test: no reconstruction, no restart, just time. The bound
	// is the cluster's own: a node is declared failed after
	// cluster-node-timeout (two seconds under the operator), an election
	// follows, and the client must find the new primary by itself.
	deadline := killed.Add(30 * time.Second)

	for attempt := 0; ; attempt++ {
		failed := writeEverywhere(ctx, store, attempt, keys)
		if failed == 0 {
			t.Logf("every shard takes writes again %s after the kill", time.Since(killed).Round(10*time.Millisecond))

			break
		}

		if time.Now().After(deadline) {
			t.Fatalf("%d of %d writes still failing 30s after the kill", failed, keys)
		}

		time.Sleep(250 * time.Millisecond)
	}

	for i := range keys {
		value, found, err := store.Get(ctx, fmt.Sprintf("before-%d", i))
		if err != nil || !found || string(value) != "kept" {
			t.Errorf("before-%d after the failover = %q, %v, %v: a key written before the kill was lost", i, value, found, err)
		}
	}
}

// writeEverywhere writes one round of keys and reports how many failed.
// Each write gets a short deadline of its own, so that a round against a
// dead node fails fast instead of waiting out the client's timeouts.
func writeEverywhere(ctx context.Context, store *valkey.State, round, keys int) int {
	failed := 0

	for i := range keys {
		probe, cancel := context.WithTimeout(ctx, time.Second)
		if err := store.Set(probe, fmt.Sprintf("after-%d-%d", round, i), []byte("new"), time.Minute); err != nil {
			failed++
		}

		cancel()
	}

	return failed
}

// primaryContainer names the container that is the primary for key's slot.
func primaryContainer(ctx context.Context, t *testing.T, seed, key string, containers []string) string {
	t.Helper()

	probe := redis.NewClusterClient(&redis.ClusterOptions{Addrs: []string{seed}})
	defer func() { _ = probe.Close() }()

	primary, err := probe.MasterForKey(ctx, key)
	if err != nil {
		t.Fatalf("find the primary of %s: %v", key, err)
	}

	host, _, _ := strings.Cut(primary.Options().Addr, ":")

	for _, name := range containers {
		out, err := exec.Command("docker", "inspect", "--format",
			"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
		if err == nil && strings.TrimSpace(string(out)) == host {
			return name
		}
	}

	t.Fatalf("no container among %v has the address %s", containers, host)

	return ""
}

// The failure that remained after the client learned to follow a
// failover by itself: one write that was already on its way to the dead
// primary when the replica took over. The topology is reloaded by then,
// but the command that found out is the one that fails -- a sign-in
// refused, with a healthy shard already serving its key.
//
// The test keeps a steady stream of writes going while the primary of
// their shard is killed, each with the deadline a request has. Writes
// that finish before the takeover may fail: nothing can take them. One
// still in flight when a fresh client sees the new primary may not.
func TestNoWriteFailsOnceTheReplicaHasTakenOver(t *testing.T) {
	seed, names := os.Getenv("VALKEY_TEST_CLUSTER_ADDR"), os.Getenv("VALKEY_TEST_CLUSTER_CONTAINERS")
	if seed == "" || names == "" {
		t.Skip("set VALKEY_TEST_CLUSTER_ADDR and VALKEY_TEST_CLUSTER_CONTAINERS")
	}

	ctx := context.Background()

	store, err := valkey.OpenState(ctx, valkey.Config{Address: seed, Cluster: true, Prefix: "stream-test"})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = store.Close() }()

	containers := strings.Split(names, ",")
	victim := primaryContainer(ctx, t, seed, "stream-test:w-0", containers)

	type result struct {
		started, ended time.Time
		err            error
	}

	var (
		mu      sync.Mutex
		results []result
		stop    = make(chan struct{})
		done    = make(chan struct{})
	)

	// Every key hashes to the victim's shard only by luck, so the stream
	// is wide: some keys on every shard, a third of them on the victim's.
	go func() {
		defer close(done)

		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}

			go func() {
				started := time.Now()
				call, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()

				err := store.Set(call, fmt.Sprintf("w-%d", i), []byte("v"), time.Minute)

				mu.Lock()
				results = append(results, result{started, time.Now(), err})
				mu.Unlock()
			}()
		}
	}()

	time.Sleep(time.Second)

	if out, err := exec.Command("docker", "kill", "--signal", "KILL", victim).CombinedOutput(); err != nil {
		t.Fatalf("kill: %v %s", err, out)
	}
	defer func() {
		if out, err := exec.Command("docker", "start", victim).CombinedOutput(); err != nil {
			t.Logf("start %s again: %v %s", victim, err, out)
		}
	}()

	// A client that has never seen the old topology is the judge of when
	// the election is over.
	var elected time.Time

	for deadline := time.Now().Add(30 * time.Second); elected.IsZero(); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no replica took over within 30s")
		}

		if now := primaryContainerOrEmpty(ctx, seed, "stream-test:w-0", containers); now != "" && now != victim {
			elected = time.Now()
		}
	}

	t.Logf("a replica took over; the stream goes on for 10s")
	time.Sleep(10 * time.Second)
	close(stop)
	<-done
	time.Sleep(11 * time.Second) // the last writes' own deadlines

	mu.Lock()
	defer mu.Unlock()

	var during, after int

	for _, r := range results {
		switch {
		case r.err == nil:
		case r.ended.Before(elected):
			during++
		default:
			after++
			t.Errorf("a write that started %s before the takeover failed %s after it: %v",
				elected.Sub(r.started).Round(time.Millisecond), r.ended.Sub(elected).Round(time.Millisecond), r.err)
		}
	}

	t.Logf("%d writes, %d failed before the takeover (tolerated), %d at or after", len(results), during, after)
}

// primaryContainerOrEmpty is primaryContainer for a poll: "" while the
// cluster cannot say.
//
// The seed may be the very node that was killed, so the probe dials them
// all.
func primaryContainerOrEmpty(ctx context.Context, _, key string, containers []string) string {
	var addrs []string

	for _, name := range containers {
		out, err := exec.Command("docker", "inspect", "--format",
			"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			addrs = append(addrs, strings.TrimSpace(string(out))+":6379")
		}
	}

	probe := redis.NewClusterClient(&redis.ClusterOptions{Addrs: addrs, DialTimeout: time.Second})
	defer func() { _ = probe.Close() }()

	primary, err := probe.MasterForKey(ctx, key)
	if err != nil {
		return ""
	}

	host, _, _ := strings.Cut(primary.Options().Addr, ":")

	for _, name := range containers {
		out, err := exec.Command("docker", "inspect", "--format",
			"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
		if err == nil && strings.TrimSpace(string(out)) == host {
			return name
		}
	}

	return ""
}
