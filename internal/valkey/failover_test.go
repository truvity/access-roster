package valkey_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
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
