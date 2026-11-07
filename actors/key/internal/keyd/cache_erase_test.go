//go:build sluis_test

package keyd

import (
	"testing"
	"time"

	"connectrpc.com/connect"
)

// verifies: REQ-KEYS-040
// A cached data key is dropped when its DataKeyWrap is deleted. Two tenants and the boundary have keys in the cache of a
// running board. The wraps of one tenant are deleted, as its exit does; until the board looks (a rewrap pass), the cached
// key still opens, which is the delay the test makes visible; after the pass the next Open of that tenant's value is
// refused as an envelope that does not open, no key is made for it, and the other tenant's value and the boundary's
// value open as before. A board with a short pass period does it by itself, with no
// call from the test.
func TestADeletedWrapDropsTheCachedKey(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	g := n.grant("session", []string{"acme", "globex"}, []string{"seal", "open"}, time.Minute)
	acme, err := seal1(n.client("session"), "data", "person", "acme", vecID, []byte("acme value"), g)
	if err != nil {
		t.Fatal(err)
	}
	globex, err := seal1(n.client("session"), "data", "person", "globex", vecID, []byte("globex value"), g)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := seal1(n.client("session"), "cookie", "cookie", "", "s1", []byte("cookie value"), nil)
	if err != nil {
		t.Fatal(err)
	}
	open := func(tenant string, env []byte) error {
		_, err := open1(n.client("session"), "data", "person", tenant, vecID, env, g)
		return err
	}
	if erased := e.store.eraseWraps("acme"); erased == 0 {
		t.Fatal("the tenant had no wraps to erase")
	}
	// The key is still cached: the delay between the deletion and the pass.
	if err := open("acme", acme); err != nil {
		t.Fatalf("before the pass the cached key was expected to open: %v", err)
	}
	if err := n.srv.Rewrap(t.Context()); err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	wraps := e.store.wrapWriteCount()
	wantRefusalNamed(t, "the erased tenant after the pass", open("acme", acme), connect.CodePermissionDenied, "open")
	// Nothing made a key for the erased tenant: a refused Open never creates one.
	if got := e.store.wrapWriteCount(); got != wraps {
		t.Fatalf("%d wraps were written after the erasure was seen, want none", got-wraps)
	}
	// Erasure holds when the tenant is used again: a Seal with a grant makes a new key for the tenant (there is no "erased"
	// state to refuse it, and the grant is what lets a tenant's value be sealed), and a new key opens nothing sealed under
	// the erased one. The old value stays unreadable; the new one opens.
	fresh, err := seal1(n.client("session"), "data", "person", "acme", vecID, []byte("after the exit"), g)
	if err != nil {
		t.Fatalf("a Seal for the erased tenant with a grant: %v", err)
	}
	wantRefusalNamed(t, "the old value after the tenant has a new key", open("acme", acme), connect.CodePermissionDenied, "open")
	if err := open("acme", fresh); err != nil {
		t.Fatalf("the value sealed under the new key: %v", err)
	}
	if err := open("globex", globex); err != nil {
		t.Fatalf("another tenant's value after the erasure: %v", err)
	}
	if _, err := open1(n.client("session"), "cookie", "cookie", "", "s1", cookie, nil); err != nil {
		t.Fatalf("the boundary's value after the erasure: %v", err)
	}

	// A board with a short period sees it with no call from the test.
	e2 := newTestEnv(t, "development")
	m := e2.startedNode(nodeOpts{rewrapEvery: 20 * time.Millisecond})
	g2 := m.grant("session", []string{"acme"}, []string{"seal", "open"}, time.Minute)
	env, err := seal1(m.client("session"), "data", "person", "acme", vecID, []byte("v"), g2)
	if err != nil {
		t.Fatal(err)
	}
	e2.store.eraseWraps("acme")
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := open1(m.client("session"), "data", "person", "acme", vecID, env, g2)
		if err != nil {
			wantRefusal(t, err, connect.CodePermissionDenied, "open")
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a board with a pass period of 20 ms still opened the erased tenant's value after 5 s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
