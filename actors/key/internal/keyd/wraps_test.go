//go:build sluis_test

package keyd

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
)

// A key made by one node is wrapped for every recipient that is published when it is made, in one batch, and
// every one of them opens it.
func TestTwoNodesShareADataKey(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	b := e.startedNode(nodeOpts{name: "node-2"})
	if a.srv.recipient == b.srv.recipient {
		t.Fatal("two nodes have one recipient label")
	}

	grant := a.grant("session", []string{"acme"}, []string{"seal", "open"}, time.Minute)
	env, err := seal1(a.client("session"), "data", "person", "acme", vecID, []byte("from a"), grant)
	if err != nil {
		t.Fatal(err)
	}
	// The grant key and the tenant's data key, each wrapped for the two nodes.
	if got := e.store.wrapCount(); got != 4 {
		t.Fatalf("wraps = %d, want 4", got)
	}
	pt, err := open1(b.client("session"), "data", "person", "acme", vecID, env, grant)
	if err != nil || string(pt) != "from a" {
		t.Fatalf("B opens A's value: %q, %v", pt, err)
	}
	// ...and the other way round.
	env2, err := seal1(b.client("session"), "data", "person", "acme", "second", []byte("from b"), grant)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := open1(a.client("session"), "data", "person", "acme", "second", env2, grant); err != nil || string(pt) != "from b" {
		t.Fatalf("A opens B's value: %q, %v", pt, err)
	}
	if got := e.store.wrapCount(); got != 4 {
		t.Fatalf("wraps = %d after the second seal, want 4: a key was made twice", got)
	}
	// Audit: the data keys that were made and their wraps.
	if a.audit.count(ActionDataKeyMake) != 2 || a.audit.count(ActionWrapWrite) != 4 {
		t.Fatalf("A audited %d keys and %d wraps, want 2 and 4", a.audit.count(ActionDataKeyMake), a.audit.count(ActionWrapWrite))
	}
	if b.audit.count(ActionDataKeyMake) != 0 {
		t.Fatalf("B made %d keys, want 0", b.audit.count(ActionDataKeyMake))
	}
}

// A node that joins later has no wrap until a node that can open the key rewraps it. Until then it neither
// opens nor makes a second key.
func TestLateRecipientGetsItsWrapByRewrap(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	grant := a.grant("session", []string{"acme"}, []string{"seal", "open"}, time.Minute)
	env, err := seal1(a.client("session"), "data", "person", "acme", vecID, []byte("early"), grant)
	if err != nil {
		t.Fatal(err)
	}
	before := e.store.wrapWriteCount()

	c := e.startedNode(nodeOpts{name: "node-3"})
	_, err = open1(c.client("session"), "data", "person", "acme", vecID, env, grant)
	if err == nil {
		t.Fatal("a node with no wrap opened the value")
	}
	// Sealing there does not make a second key either.
	_, err = seal1(c.client("session"), "data", "person", "acme", "x", []byte("x"), grant)
	if err == nil {
		t.Fatal("a node with no wrap sealed under a new key")
	}
	if got := e.store.wrapWriteCount(); got != before {
		t.Fatalf("wraps written = %d, want %d: the late node made a key", got, before)
	}

	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	if got := e.store.wrapCount(); got != 4 {
		t.Fatalf("wraps = %d after the rewrap, want 4 (two keys, two nodes)", got)
	}
	// The grant key is wrapped for C now too; the value opens.
	pt, err := open1(c.client("session"), "data", "person", "acme", vecID, env, grant)
	if err != nil || string(pt) != "early" {
		t.Fatalf("C opens after the rewrap: %q, %v", pt, err)
	}
	// A second pass writes nothing.
	n := e.store.wrapWriteCount()
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.store.wrapWriteCount() != n {
		t.Fatal("a second rewrap pass wrote wraps")
	}
}

// A restart with an empty cache opens the same key from its wrap, and makes no new wrap.
func TestRestartOpensFromTheWrap(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	env, err := seal1(a.client("session"), "cookie", "cookie", "", "s1", []byte("cookie value"), nil)
	if err != nil {
		t.Fatal(err)
	}
	writes := e.store.wrapWriteCount()
	a.stop()

	a2 := e.startedNode(nodeOpts{name: "node-1", driver: a.driver})
	if a2.srv.recipient != a.srv.recipient {
		t.Fatal("the same card gave another recipient label")
	}
	ecdhs := a.driver.ecdhs.Load()
	pt, err := open1(a2.client("session"), "cookie", "cookie", "", "s1", env, nil)
	if err != nil || string(pt) != "cookie value" {
		t.Fatalf("after the restart: %q, %v", pt, err)
	}
	if a.driver.ecdhs.Load() != ecdhs+1 {
		t.Fatalf("ECDH calls = %d, want %d: the key was not opened from its wrap", a.driver.ecdhs.Load(), ecdhs+1)
	}
	if got := e.store.wrapWriteCount(); got != writes {
		t.Fatalf("wraps written = %d, want %d: the restart made a new wrap", got, writes)
	}
	// The certificate was not rewritten either: its version stays 1.
	if v := e.store.items["|key-certificate|wrapping/"+a.srv.recipient].GetVersion(); v != 1 {
		t.Fatalf("certificate version = %d, want 1", v)
	}
}

// Two nodes that need the same new key at once: one wins the CREATE, the other discards its key and uses the
// winner's. Every value opens on both, and the store holds one wrap per node.
func TestConcurrentKeyMakingConverges(t *testing.T) {
	for round := range 3 {
		t.Run(fmt.Sprint(round), func(t *testing.T) {
			e := newTestEnv(t, "development")
			a := e.startedNode(nodeOpts{name: "node-1"})
			b := e.startedNode(nodeOpts{name: "node-2"})
			const each = 6
			envs := make([][]byte, 2*each)
			var wg sync.WaitGroup
			errs := make(chan error, 2*each)
			for i := range 2 * each {
				wg.Add(1)
				go func() {
					defer wg.Done()
					nd := a
					if i%2 == 1 {
						nd = b
					}
					env, err := seal1(nd.client("session"), "cookie", "cookie", "", fmt.Sprintf("s%d", i), []byte(fmt.Sprint("v", i)), nil)
					envs[i] = env
					errs <- err
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}
			}
			if got := e.store.wrapCount(); got != 2 {
				t.Fatalf("wraps = %d, want 2 (one key, two recipients)", got)
			}
			for i, env := range envs {
				for _, nd := range []*node{a, b} {
					pt, err := open1(nd.client("session"), "cookie", "cookie", "", fmt.Sprintf("s%d", i), env, nil)
					if err != nil || string(pt) != fmt.Sprint("v", i) {
						t.Fatalf("value %d does not open on %s: %q, %v", i, nd.srv.cfg.Node, pt, err)
					}
				}
			}
		})
	}
}

// A data key is cached for the KeyPlan's time to live and opened again after it.
func TestCacheTimeToLive(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	b := e.startedNode(nodeOpts{name: "node-2"})
	env, err := seal1(a.client("session"), "cookie", "cookie", "", "s1", []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	read := func() {
		t.Helper()
		if _, err := open1(b.client("session"), "cookie", "cookie", "", "s1", env, nil); err != nil {
			t.Fatal(err)
		}
	}
	read()
	read()
	if got := b.driver.ecdhs.Load(); got != 1 {
		t.Fatalf("ECDH calls after two opens = %d, want 1 (the second is cached)", got)
	}
	e.clock.advance(14 * time.Minute)
	read()
	if got := b.driver.ecdhs.Load(); got != 1 {
		t.Fatalf("ECDH calls inside the TTL = %d, want 1", got)
	}
	e.clock.advance(2 * time.Minute)
	read()
	if got := b.driver.ecdhs.Load(); got != 2 {
		t.Fatalf("ECDH calls after the TTL = %d, want 2", got)
	}
}

func TestCacheTTLRange(t *testing.T) {
	for _, c := range []struct {
		in      *configv2alpha1.KeyPlan
		want    time.Duration
		refused bool
	}{
		{&configv2alpha1.KeyPlan{}, 15 * time.Minute, false},
		{&configv2alpha1.KeyPlan{CacheTtl: durationpb.New(0)}, 15 * time.Minute, false},
		{&configv2alpha1.KeyPlan{CacheTtl: durationpb.New(5 * time.Minute)}, 5 * time.Minute, false},
		{&configv2alpha1.KeyPlan{CacheTtl: durationpb.New(time.Hour)}, time.Hour, false},
		{&configv2alpha1.KeyPlan{CacheTtl: durationpb.New(-time.Second)}, 0, true},
		{&configv2alpha1.KeyPlan{CacheTtl: durationpb.New(time.Hour + time.Nanosecond)}, 0, true},
		{&configv2alpha1.KeyPlan{CacheTtl: durationpb.New(2 * time.Hour)}, 0, true},
	} {
		got, err := cacheTTL(c.in)
		if (err != nil) != c.refused || got != c.want {
			t.Errorf("cacheTTL(%v) = %v, %v; want %v, refused=%v", c.in.GetCacheTtl().AsDuration(), got, err, c.want, c.refused)
		}
	}
}

func TestStoreDownFailsClosed(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{})
	e.store.mu.Lock()
	e.store.failWrites = true
	e.store.mu.Unlock()
	_, err := seal1(a.client("session"), "cookie", "cookie", "", "s1", []byte("x"), nil)
	wantRefusal(t, err, connect.CodeUnavailable, "store")
	e.store.mu.Lock()
	e.store.failWrites = false
	e.store.mu.Unlock()
	if _, err := seal1(a.client("session"), "cookie", "cookie", "", "s1", []byte("x"), nil); err != nil {
		t.Fatalf("after the store came back: %v", err)
	}
}
