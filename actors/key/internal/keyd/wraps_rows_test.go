//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
	"github.com/truvity/sluis/v2/actors/key/internal/wrap"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
)

// wrapsSnapshot is every DataKeyWrap in the store, by store key, as the bytes that are stored.
func (e *testEnv) wrapsSnapshot() map[string][]byte {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	out := map[string][]byte{}
	for k, it := range e.store.items {
		if it.GetAddress().GetKind() == "data-key-wrap" {
			out[k] = bytes.Clone(it.GetValue())
		}
	}
	return out
}

// otherItemsSnapshot is every stored item that is not a DataKeyWrap, with its version.
func (e *testEnv) otherItemsSnapshot() map[string]uint64 {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	out := map[string]uint64{}
	for k, it := range e.store.items {
		if it.GetAddress().GetKind() != "data-key-wrap" {
			out[k] = it.GetVersion()
		}
	}
	return out
}

// keysOfWraps is the data keys that have a wrap, as "tenant|purpose/generation", with the recipients that hold one.
func (e *testEnv) keysOfWraps(t *testing.T) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for k, raw := range e.wrapsSnapshot() {
		w := &keyv2alpha1.DataKeyWrap{}
		if err := proto.Unmarshal(raw, w); err != nil {
			t.Fatal(err)
		}
		tenant := k[:bytes.IndexByte([]byte(k), '|')]
		key := tenant + "|" + w.GetPurpose() + "/" + fmtAny(w.GetGeneration())
		if out[key] == nil {
			out[key] = map[string]bool{}
		}
		out[key][w.GetRecipient()] = true
	}
	return out
}

// unwrapAsOutsider opens the wrap of a data key for an outsider, as the holder of a recovery key would, and returns the key.
func unwrapAsOutsider(t *testing.T, e *testEnv, o outsider, tenant, purpose string) []byte {
	t.Helper()
	w := ownWrapOf(t, e, tenant, purpose, o.label)
	eph, err := wrap.ParsePublic(w.GetEphemeralPublic())
	if err != nil {
		t.Fatal(err)
	}
	ek, err := o.priv.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := ek.ECDH(eph)
	if err != nil {
		t.Fatal(err)
	}
	ctxTenant := tenant
	if ctxTenant == "" {
		ctxTenant = envelope.NoTenant
	}
	key, err := wrap.Unwrap(wrap.Context{Boundary: testBoundary, Tenant: ctxTenant, Purpose: purpose, Generation: 1, Recipient: o.label}, secret, w.GetWrappedKey())
	if err != nil {
		t.Fatalf("the recovery holder cannot open the wrap of %s/%s: %v", tenant, purpose, err)
	}
	return key
}

// verifies: REQ-KEYS-052
// On a board a data key has one wrap for the key-agreement key of each board's card and one for the recovery recipient,
// and every one of them opens it to the key that sealed the value. Three boards are listed and a recovery key that the
// test holds (the way the ceremony's holder does); the keys are the boundary's cookie key, the grant key and a tenant's
// data key. For each key the set of recipients with a wrap is exactly the boards and the recovery recipient, each board
// opens the value, and the recovery holder's own unwrap gives the key that opens it too.
func TestEveryDataKeyHasOneWrapPerBoardAndOneForTheRecoveryRecipient(t *testing.T) {
	e := newTestEnv(t, "development")
	recovery := newOutsider(t)
	e.list(recovery.id)
	e.inject(recovery)
	a := e.startedNode(nodeOpts{name: "node-1"})
	b := e.startedNode(nodeOpts{name: "node-2"})
	c := e.startedNode(nodeOpts{name: "node-3"})
	boards := map[string]*node{a.srv.recipient: a, b.srv.recipient: b, c.srv.recipient: c}
	if len(boards) != 3 {
		t.Fatal("three boards have fewer than three recipient labels")
	}
	grant := a.grant("session", []string{"acme"}, []string{"seal", "open"}, time.Minute)
	cookie, err := seal1(a.client("session"), "cookie", "cookie", "", "s1", []byte("cookie value"), nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := seal1(a.client("session"), "data", "person", "acme", vecID, []byte("tenant value"), grant)
	if err != nil {
		t.Fatal(err)
	}
	keys := e.keysOfWraps(t)
	want := []string{"|cookie/1", "|grant/1", "acme|data/1"}
	if len(keys) != len(want) {
		t.Fatalf("data keys with a wrap: %v, want %v", keys, want)
	}
	for _, k := range want {
		got := keys[k]
		if len(got) != 4 || !got[recovery.label] {
			t.Errorf("%s has wraps for %v, want the three boards and the recovery recipient", k, got)
		}
		for label := range boards {
			if !got[label] {
				t.Errorf("%s has no wrap for board %s", k, label)
			}
		}
	}
	if n := len(e.wrapsSnapshot()); n != 12 {
		t.Fatalf("%d wraps for three keys and four recipients, want 12", n)
	}
	// Every board opens the values with its own card key.
	for label, n := range boards {
		if pt, err := open1(n.client("session"), "cookie", "cookie", "", "s1", cookie, nil); err != nil || string(pt) != "cookie value" {
			t.Errorf("board %s opens the cookie: %q, %v", label, pt, err)
		}
		if pt, err := open1(n.client("session"), "data", "person", "acme", vecID, data, grant); err != nil || string(pt) != "tenant value" {
			t.Errorf("board %s opens the tenant value: %q, %v", label, pt, err)
		}
	}
	// The recovery holder's wrap gives the key that sealed the values.
	addrCookie := envelope.Address{Boundary: testBoundary, Tenant: envelope.NoTenant, Kind: "cookie", ID: "s1"}
	if pt, err := envelope.Open(unwrapAsOutsider(t, e, recovery, "", "cookie"), cookie, addrCookie); err != nil || string(pt) != "cookie value" {
		t.Errorf("the recovery key does not open the cookie: %q, %v", pt, err)
	}
	addrData := envelope.Address{Boundary: testBoundary, Tenant: "acme", Kind: "person", ID: vecID}
	if pt, err := envelope.Open(unwrapAsOutsider(t, e, recovery, "acme", "data"), data, addrData); err != nil || string(pt) != "tenant value" {
		t.Errorf("the recovery key does not open the tenant value: %q, %v", pt, err)
	}
}

// verifies: REQ-KEYS-055
// Adding a card or a board rewraps each data key for its public key and touches no sealed value. A board with its card
// and a recovery recipient are running with keys of the boundary and of two tenants; a second card is listed in the
// KeyPlan (a new board, or a new card in a board: either is a new key-agreement key); the next rewrap pass of the
// board that can open the keys writes one wrap for the new card for every data key, rewrites no wrap that was there,
// writes nothing else, and the values sealed before still open, byte for byte as they were, on the new card.
func TestAddingACardRewrapsEveryDataKeyAndChangesNoSealedValue(t *testing.T) {
	e := newTestEnv(t, "development")
	recovery := newOutsider(t)
	e.list(recovery.id)
	e.inject(recovery)
	a := e.startedNode(nodeOpts{name: "node-1"})
	gAcme := a.grant("session", []string{"acme", "globex"}, []string{"seal", "open"}, time.Minute)
	sealed := map[string][]byte{}
	for _, tenant := range []string{"acme", "globex"} {
		env, err := seal1(a.client("session"), "data", "person", tenant, vecID, []byte("value of "+tenant), gAcme)
		if err != nil {
			t.Fatal(err)
		}
		sealed[tenant] = env
	}
	cookie, err := seal1(a.client("session"), "cookie", "cookie", "", "s1", []byte("cookie value"), nil)
	if err != nil {
		t.Fatal(err)
	}
	before := e.wrapsSnapshot()
	keysBefore := e.keysOfWraps(t)
	if len(keysBefore) != 4 { // cookie, grant, and the data key of each tenant
		t.Fatalf("data keys before the new card: %v", keysBefore)
	}
	envCopies := map[string][]byte{"cookie": bytes.Clone(cookie), "acme": bytes.Clone(sealed["acme"]), "globex": bytes.Clone(sealed["globex"])}

	// The new card: a board whose key is not in the plan yet, then listed by a commit.
	b := e.newNode(nodeOpts{name: "node-2", unlisted: true})
	b.start() // publishes its own certificate, the one item that is no wrap and is new
	if _, err := open1(b.client("session"), "cookie", "cookie", "", "s1", cookie, nil); err == nil {
		t.Fatal("a card that is not listed opened a value")
	}
	othersBefore := e.otherItemsSnapshot()
	e.list(b.driver.wrappingID())
	b.srv.cache.wipeAll()
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	// Every data key gained exactly the new card's wrap.
	keysAfter := e.keysOfWraps(t)
	if len(keysAfter) != len(keysBefore) {
		t.Fatalf("data keys with a wrap: %d, was %d", len(keysAfter), len(keysBefore))
	}
	for k, got := range keysAfter {
		if len(got) != len(keysBefore[k])+1 || !got[b.srv.recipient] {
			t.Errorf("%s: wraps for %v, was %v: want the new card added and no other change", k, got, keysBefore[k])
		}
	}
	// No wrap that was there was rewritten, and no item of another kind was touched.
	after := e.wrapsSnapshot()
	for k, v := range before {
		if !bytes.Equal(after[k], v) {
			t.Errorf("wrap %s was rewritten", k)
		}
	}
	if len(after) != len(before)+len(keysBefore) {
		t.Errorf("%d wraps after, %d before: want one more per data key (%d)", len(after), len(before), len(keysBefore))
	}
	othersAfter := e.otherItemsSnapshot()
	for k, v := range othersBefore {
		if othersAfter[k] != v {
			t.Errorf("item %s changed (version %d, was %d)", k, othersAfter[k], v)
		}
	}
	if len(othersAfter) != len(othersBefore) {
		t.Errorf("%d other items after, %d before: the rewrap made or removed an item that is no wrap", len(othersAfter), len(othersBefore))
	}
	// The sealed values are byte for byte what they were, and open on the new card.
	if !bytes.Equal(cookie, envCopies["cookie"]) || !bytes.Equal(sealed["acme"], envCopies["acme"]) || !bytes.Equal(sealed["globex"], envCopies["globex"]) {
		t.Fatal("a sealed value changed")
	}
	if pt, err := open1(b.client("session"), "cookie", "cookie", "", "s1", cookie, nil); err != nil || string(pt) != "cookie value" {
		t.Errorf("the new card opens the cookie: %q, %v", pt, err)
	}
	for tenant, env := range sealed {
		if pt, err := open1(b.client("session"), "data", "person", tenant, vecID, env, gAcme); err != nil || string(pt) != "value of "+tenant {
			t.Errorf("the new card opens %s's value: %q, %v", tenant, pt, err)
		}
	}
}
