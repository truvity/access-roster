//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

func (n *node) statusClient() keyv2alpha1connect.KeyStatusServiceClient {
	hc, url := rpc.Dial(filepath.Join(n.runDir, adminSocketName))
	return keyv2alpha1connect.NewKeyStatusServiceClient(hc, url, rpc.ClientOptions()...)
}

func (n *node) status() (*keyv2alpha1.StatusResponse, error) {
	res, err := n.statusClient().Status(context.Background(), connect.NewRequest(&keyv2alpha1.StatusRequest{}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// versions is every item of the store with its version, to show that a call changed none.
func (e *testEnv) versions() map[string]uint64 {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	out := map[string]uint64{}
	for k, it := range e.store.items {
		out[k] = it.GetVersion()
	}
	return out
}

func keyByPurpose(r *keyv2alpha1.StatusResponse, purpose string) *keyv2alpha1.KeyStatus {
	for _, k := range r.GetKeys() {
		if k.GetPurpose() == purpose {
			return k
		}
	}
	return nil
}

// verifies: REQ-KEYS-236
// Status lists the asymmetric keys of the KeyPlan in its order with their store, algorithm, public key and thumbprint,
// and no data key purpose. A key has the chain that is installed for it and no other: a certificate for another key, one
// for another purpose and one without a chain are not its chain; with two, the one published last.
func TestStatusListsTheKeysOfThePlanWithTheChainInstalledForEach(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})

	r, err := n.status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	var purposes []string
	for _, k := range r.GetKeys() {
		purposes = append(purposes, k.GetPurpose())
	}
	if !slices.Equal(purposes, []string{"wrapping", "token-signing", "audit-log"}) {
		t.Fatalf("purposes = %v, want the asymmetric ones of the plan in its order", purposes)
	}
	if r.GetStore() != "software" || r.GetEnvironment() != "development" {
		t.Fatalf("store %q, environment %q", r.GetStore(), r.GetEnvironment())
	}
	for _, k := range r.GetKeys() {
		pk := n.srv.keys[k.GetPurpose()]
		if k.GetKeyId() != pk.keyID || !bytes.Equal(k.GetSpkiDer(), pk.spki) || k.GetAlgorithm() != pk.algorithm {
			t.Errorf("%s: %v does not describe the key key@ holds", k.GetPurpose(), k)
		}
		if k.GetSlot() != "" {
			t.Errorf("%s: a software store has no slot, and the status names %q", k.GetPurpose(), k.GetSlot())
		}
		if len(k.GetChain()) != 0 {
			t.Errorf("%s: no chain is installed, and the status shows %d certificates", k.GetPurpose(), len(k.GetChain()))
		}
	}

	tok := n.srv.keys["token-signing"]
	other := n.srv.keys["audit-log"]
	at := e.clock.now()
	e.store.put("key-certificate", "", "token-signing/old", &keyv2alpha1.KeyCertificate{
		Purpose: "token-signing", SpkiDer: tok.spki, Chain: [][]byte{[]byte("old-leaf")}, AddedAt: timestamppb.New(at.Add(-time.Hour))})
	e.store.put("key-certificate", "", "token-signing/new", &keyv2alpha1.KeyCertificate{
		Purpose: "token-signing", SpkiDer: tok.spki, Chain: [][]byte{[]byte("new-leaf"), []byte("root")}, AddedAt: timestamppb.New(at)})
	// Another node's certificate for the same purpose, a certificate for another purpose with this key, and one with no chain.
	e.store.put("key-certificate", "", "token-signing/peer", &keyv2alpha1.KeyCertificate{
		Purpose: "token-signing", SpkiDer: other.spki, Chain: [][]byte{[]byte("peer-leaf")}, AddedAt: timestamppb.New(at.Add(time.Hour))})
	e.store.put("key-certificate", "", "ssh-user/x", &keyv2alpha1.KeyCertificate{
		Purpose: "ssh-user", SpkiDer: tok.spki, Chain: [][]byte{[]byte("ssh-leaf")}, AddedAt: timestamppb.New(at.Add(time.Hour))})
	e.store.put("key-certificate", "", "token-signing/bare", &keyv2alpha1.KeyCertificate{
		Purpose: "token-signing", SpkiDer: tok.spki, AddedAt: timestamppb.New(at.Add(2 * time.Hour))})
	e.store.put("key-certificate", "", "audit-log/bare", &keyv2alpha1.KeyCertificate{
		Purpose: "audit-log", SpkiDer: other.spki, AddedAt: timestamppb.New(at)})

	r, err = n.status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got := keyByPurpose(r, "token-signing").GetChain(); len(got) != 2 || string(got[0]) != "new-leaf" || string(got[1]) != "root" {
		t.Fatalf("token-signing chain = %q, want the chain published last", got)
	}
	if got := keyByPurpose(r, "audit-log").GetChain(); len(got) != 0 {
		t.Fatalf("audit-log chain = %q, want none", got)
	}
}

// verifies: REQ-KEYS-236
// On a card the status names the slot of each key from the KeyPlan, and on a store with no slots it names none.
func TestStatusNamesTheSlotOnACardOnly(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{driver: newFakeDriver("yubikey-piv")})
	r, err := n.status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	want := map[string]string{"wrapping": "9d", "token-signing": "9a", "audit-log": "84"}
	for purpose, slot := range want {
		if got := keyByPurpose(r, purpose).GetSlot(); got != slot {
			t.Errorf("%s slot = %q, want %q", purpose, got, slot)
		}
	}
	if r.GetStore() != "yubikey-piv" {
		t.Errorf("store = %q", r.GetStore())
	}
}

// verifies: REQ-KEYS-237, REQ-KEYS-238
// Status writes nothing, audits nothing and looks up no item that is absent (each such lookup is a refusal that store@
// audits, REQ-AUDIT-180): it lists the kind.
func TestStatusWritesNothingAndAsksForNoAbsentItem(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	versions, facts, absent := e.versions(), len(n.audit.all()), e.store.absentCount()
	e.store.mu.Lock()
	e.store.failWrites = true // a write would now fail the call
	e.store.mu.Unlock()
	for range 3 {
		if _, err := n.status(); err != nil {
			t.Fatalf("Status: %v", err)
		}
	}
	if got := e.versions(); len(got) != len(versions) {
		t.Fatalf("the store holds %d items, was %d", len(got), len(versions))
	} else {
		for k, v := range versions {
			if got[k] != v {
				t.Errorf("item %s changed from version %d to %d", k, v, got[k])
			}
		}
	}
	if got := len(n.audit.all()); got != facts {
		t.Errorf("Status made %d audit facts", got-facts)
	}
	if got := e.store.absentCount(); got != absent {
		t.Errorf("Status asked for %d items that are absent", got-absent)
	}
}

// verifies: REQ-KEYS-239, REQ-KEYS-240
// Only root reaches the status call: another peer is refused before the request is read. A store@ that is down is
// "unavailable" with the reason store, and the status makes no claim.
func TestStatusIsRootOnlyAndSaysWhenStoreIsDown(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})

	e.store.mu.Lock()
	e.store.failKind = "key-certificate"
	e.store.mu.Unlock()
	_, err := n.status()
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("Status with the store down = %v, want unavailable", err)
	}
	e.store.mu.Lock()
	e.store.failKind = ""
	e.store.mu.Unlock()

	// The guard is chosen when the socket is served, so a second node is started with a rule that names the test's user
	// as someone who is not root.
	m := e.newNode(nodeOpts{name: "node-2"})
	m.srv.adminAllow = func(uid uint32) bool { return int(uid) != os.Getuid() }
	m.start()
	_, err = m.status()
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("Status as a peer that is not root = %v, want permission_denied", err)
	}
}
