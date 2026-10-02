package valkey

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2/server"
)

// A rollout that replaces every pod of a Valkey Cluster at once leaves a
// client holding six addresses, all of them dead, and one name -- the
// Service -- that now leads to the new pods. 2026-10-02: both issuer
// replicas dialled the old pods for minutes.
//
// The test is that situation without a cluster to do it to: pods are
// miniredis servers, the "network" is a dialer that answers the Service
// name with the live pod and leaves every replaced pod's address
// unanswered, as a deleted pod's is (no refusal, only silence until the
// dial gives up), and the topology each pod reports lists six nodes, as
// three shards of two do.
type roll struct {
	mu     sync.Mutex
	live   string
	dead   map[string]bool
	wasted map[string]int // dials into the dark, by port
}

const serviceName = "valkey.test:6379"

func (r *roll) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	_, port, _ := net.SplitHostPort(addr)

	r.mu.Lock()
	if addr == serviceName {
		port = r.live
	}
	dead := r.dead[port]
	r.mu.Unlock()

	if dead {
		r.mu.Lock()
		r.wasted[port]++
		r.mu.Unlock()
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: network, Err: context.DeadlineExceeded}
	}
	return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+port)
}

// pod is a server that reports itself and five neighbours as the
// topology, and takes writes.
func pod(t *testing.T, neighbours []string) *server.Server {
	t.Helper()
	srv, err := server.NewServer("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	port := portOf(srv)
	register := func(name string, f server.Cmd) {
		if err := srv.Register(name, f); err != nil {
			t.Fatal(err)
		}
	}
	register("HELLO", func(c *server.Peer, _ string, _ []string) { c.WriteError("ERR unknown command 'HELLO'") })
	register("CLIENT", func(c *server.Peer, _ string, _ []string) { c.WriteOK() })
	register("COMMAND", func(c *server.Peer, _ string, _ []string) { c.WriteLen(0) })
	register("PING", func(c *server.Peer, _ string, _ []string) { c.WriteInline("PONG") })
	register("SET", func(c *server.Peer, _ string, _ []string) { c.WriteOK() })
	register("CLUSTER", func(c *server.Peer, _ string, _ []string) {
		c.WriteLen(1)
		c.WriteLen(2 + 1 + len(neighbours))
		c.WriteInt(0)
		c.WriteInt(16383)
		for _, n := range append([]string{"127.0.0.1:" + port}, neighbours...) {
			host, nport, _ := net.SplitHostPort(n)
			np, _ := strconv.Atoi(nport)
			c.WriteLen(3)
			c.WriteBulk(host)
			c.WriteInt(np)
			c.WriteBulk("id-" + nport)
		}
	})
	return srv
}

func TestTheClientFindsTheNewPodsWhenEveryPodHasMoved(t *testing.T) {
	ctx := context.Background()

	var old, next []string
	for i := range 5 {
		old = append(old, "127.0.0.1:"+strconv.Itoa(7001+i))
		next = append(next, "127.0.0.1:"+strconv.Itoa(7101+i))
	}
	before, after := pod(t, old), pod(t, next)
	oldPort, newPort := portOf(before), portOf(after)
	network := &roll{live: oldPort, dead: map[string]bool{}, wasted: map[string]int{}}

	client, _, err := dialWith(ctx, Config{Address: serviceName, Cluster: true}, network.dial)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = client.Close() }()
	state := NewState(client, "test")

	if err := state.Set(ctx, "a", []byte("1"), time.Hour); err != nil {
		t.Fatalf("before the roll: %v", err)
	}

	// Every pod is replaced: the old ones go dark, the Service follows the
	// new one.
	before.Close()
	network.mu.Lock()
	network.dead[oldPort] = true
	for i := range 5 {
		network.dead[strconv.Itoa(7001+i)] = true
	}
	network.live = newPort
	network.mu.Unlock()

	started := time.Now()
	for {
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := state.Set(call, "b", []byte("2"), time.Hour)
		cancel()
		if err == nil {
			break
		}
		if time.Since(started) > 8*time.Second {
			t.Fatalf("still failing %s after every pod moved: %v", time.Since(started).Round(time.Millisecond), err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The command that found the master gone has to try it, and the
	// library has always been right to. What it must not do is then walk
	// the dead replicas one dial budget at a time looking for a node that
	// will tell it the topology: the Service already knows a live one.
	network.mu.Lock()
	defer network.mu.Unlock()
	for i := range 5 {
		if n := network.wasted[strconv.Itoa(7001+i)]; n > 0 {
			t.Errorf("the client dialled the replaced pod on port %d %d times to learn the topology", 7001+i, n)
		}
	}
	t.Logf("working again %s after every pod moved", time.Since(started).Round(10*time.Millisecond))
}

func portOf(s *server.Server) string { _, p, _ := net.SplitHostPort(s.Addr().String()); return p }
