//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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

// leafCert is a certificate that holds the public key spki and ends at notAfter, signed by a key of its own: the chain a
// root custodian returned. name tells two of them apart.
func leafCert(t *testing.T, spki []byte, name string, notAfter time.Time) []byte {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: notAfter.Add(-400 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// rootCert is a certificate for a key of its own, the root that ends a chain.
func rootCert(t *testing.T, name string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return leafCert(t, spki, name, time.Now().Add(1000*24*time.Hour))
}

func keyByPurpose(r *keyv2alpha1.StatusResponse, purpose string) *keyv2alpha1.KeyStatus {
	for _, k := range r.GetKeys() {
		if k.GetPurpose() == purpose {
			return k
		}
	}
	return nil
}

// verifies: REQ-KEYS-236, REQ-KEYS-248, REQ-KEYS-249
// Status lists the asymmetric keys of the KeyPlan in its order with their store, algorithm, public key and thumbprint,
// and no data key purpose. A key has the chain that is installed for it and no other: a leaf that holds another key (whatever
// the item says), a certificate for another purpose, one without a chain and one that is no certificate are not its chain;
// with two, the one whose leaf lives longest.
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
	day := 24 * time.Hour
	root := rootCert(t, "root")
	// Chains for the key: the ones published last (by key@'s clock) end sooner than the oldest, which has no spki_der at all, so
	// the longest-lived leaf wins and the time of publication does not.
	e.store.put("key-certificate", "", "token-signing/old", &keyv2alpha1.KeyCertificate{
		Purpose: "token-signing", SpkiDer: tok.spki, Chain: [][]byte{leafCert(t, tok.spki, "long", at.Add(300*day))}, AddedAt: timestamppb.New(at.Add(-time.Hour))})
	e.store.put("key-certificate", "", "token-signing/new", &keyv2alpha1.KeyCertificate{
		Purpose: "token-signing", SpkiDer: tok.spki, Chain: [][]byte{leafCert(t, tok.spki, "short", at.Add(100*day))}, AddedAt: timestamppb.New(at)})
	// An item that says it is for this key and holds a leaf of another key: the leaf decides, not the item's field.
	e.store.put("key-certificate", "", "token-signing/liar", &keyv2alpha1.KeyCertificate{
		Purpose: "token-signing", SpkiDer: tok.spki, Chain: [][]byte{leafCert(t, other.spki, "liar", at.Add(900*day))}, AddedAt: timestamppb.New(at.Add(time.Hour))})
	// An item that does not say so and holds this key's leaf: the leaf decides this way too.
	e.store.put("key-certificate", "", "token-signing/unlabelled", &keyv2alpha1.KeyCertificate{
		Purpose: "token-signing", Chain: [][]byte{leafCert(t, tok.spki, "unlabelled", at.Add(350*day)), root}, AddedAt: timestamppb.New(at.Add(-2 * time.Hour))})
	// Another node's certificate for the same purpose, a certificate for another purpose with this key, one with no chain, and one
	// with a chain that is not a certificate.
	e.store.put("key-certificate", "", "token-signing/peer", &keyv2alpha1.KeyCertificate{
		Purpose: "token-signing", SpkiDer: other.spki, Chain: [][]byte{leafCert(t, other.spki, "peer", at.Add(999*day))}, AddedAt: timestamppb.New(at.Add(time.Hour))})
	e.store.put("key-certificate", "", "ssh-user/x", &keyv2alpha1.KeyCertificate{
		Purpose: "ssh-user", SpkiDer: tok.spki, Chain: [][]byte{leafCert(t, tok.spki, "ssh", at.Add(999*day))}, AddedAt: timestamppb.New(at.Add(time.Hour))})
	e.store.put("key-certificate", "", "token-signing/bare", &keyv2alpha1.KeyCertificate{
		Purpose: "token-signing", SpkiDer: tok.spki, AddedAt: timestamppb.New(at.Add(2 * time.Hour))})
	e.store.put("key-certificate", "", "token-signing/junk", &keyv2alpha1.KeyCertificate{
		Purpose: "token-signing", SpkiDer: tok.spki, Chain: [][]byte{[]byte("not a certificate")}, AddedAt: timestamppb.New(at.Add(3 * time.Hour))})
	e.store.put("key-certificate", "", "audit-log/bare", &keyv2alpha1.KeyCertificate{
		Purpose: "audit-log", SpkiDer: other.spki, AddedAt: timestamppb.New(at)})

	r, err = n.status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	got := keyByPurpose(r, "token-signing").GetChain()
	if len(got) != 2 {
		t.Fatalf("token-signing chain has %d certificates, want the longest-lived one, with its root", len(got))
	}
	if leaf, err := x509.ParseCertificate(got[0]); err != nil || leaf.Subject.CommonName != "unlabelled" {
		t.Fatalf("token-signing chain leaf = %v, %v: want the leaf that lives longest, whatever key@'s clock said when it was published", leaf, err)
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

// verifies: REQ-KEYS-237, REQ-KEYS-238, REQ-KEYS-250
// Status writes nothing, audits nothing and looks up no item that is absent (each such lookup is a refusal that store@
// audits, REQ-AUDIT-180): it lists the kind.
func TestStatusWritesNothingAndAsksForNoAbsentItem(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	versions, facts, absent := e.versions(), len(n.audit.all()), e.store.absentCount()
	e.store.mu.Lock()
	e.store.listKind = "key-certificate"
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
	// It lists the kind, and asks for a listing that sees every write acknowledged before it: a status that missed the
	// certificate installed a moment ago would say "none".
	if e.store.listCallCount() == 0 || e.store.weakListCount() != 0 {
		t.Errorf("Status listed KeyCertificate %d times, %d of them without asking for a linearizable read", e.store.listCallCount(), e.store.weakListCount())
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

// verifies: REQ-KEYS-249
// Two chains whose leaves end together are told apart by the time key@ published them: the later one.
func TestStatusBreaksATieOfTwoLeavesByThePublicationTime(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	k := n.srv.keys["audit-log"]
	at := e.clock.now()
	end := at.Add(200 * 24 * time.Hour)
	e.store.put("key-certificate", "", "audit-log/a", &keyv2alpha1.KeyCertificate{
		Purpose: "audit-log", Chain: [][]byte{leafCert(t, k.spki, "a", end)}, AddedAt: timestamppb.New(at.Add(-time.Hour))})
	e.store.put("key-certificate", "", "audit-log/b", &keyv2alpha1.KeyCertificate{
		Purpose: "audit-log", Chain: [][]byte{leafCert(t, k.spki, "b", end), rootCert(t, "root")}, AddedAt: timestamppb.New(at)})
	r, err := n.status()
	if err != nil {
		t.Fatal(err)
	}
	if got := keyByPurpose(r, "audit-log").GetChain(); len(got) != 2 {
		t.Fatalf("chain of %d certificates, want the one published last", len(got))
	}
}

// verifies: REQ-KEYS-251
// A chain meant for this key that cannot be used is not "no certificate": the status names how it fails. A leaf that holds
// another key and a certificate that does not parse are two ways; another node's certificate, an item with no chain and a
// usable chain next to a bad one are not.
func TestStatusSaysWhenAChainForTheKeyCannotBeUsed(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		name  string
		items func(e *testEnv, n *node) // puts the items
		want  string
		chain bool
	}{
		{"nothing at all", func(*testEnv, *node) {}, "", false},
		{"another node's certificate", func(e *testEnv, n *node) {
			o := n.srv.keys["audit-log"]
			e.store.put("key-certificate", "", "token-signing/peer", &keyv2alpha1.KeyCertificate{Purpose: "token-signing", SpkiDer: o.spki,
				Chain: [][]byte{leafCert(t, o.spki, "peer", e.clock.now().Add(100*day))}})
		}, "", false},
		{"another node's certificate named by its label only", func(e *testEnv, _ *node) {
			e.store.put("key-certificate", "", "token-signing/other", &keyv2alpha1.KeyCertificate{Purpose: "token-signing", Recipient: "someothernodeslabel", Chain: [][]byte{[]byte("not ours")}})
		}, "", false},
		{"an item with no chain", func(e *testEnv, n *node) {
			e.store.put("key-certificate", "", "token-signing/bare", &keyv2alpha1.KeyCertificate{Purpose: "token-signing", SpkiDer: n.srv.keys["token-signing"].spki})
		}, "", false},
		{"a leaf that holds another key", func(e *testEnv, n *node) {
			o := n.srv.keys["audit-log"]
			e.store.put("key-certificate", "", "token-signing/liar", &keyv2alpha1.KeyCertificate{Purpose: "token-signing", SpkiDer: n.srv.keys["token-signing"].spki,
				Chain: [][]byte{leafCert(t, o.spki, "liar", e.clock.now().Add(100*day))}})
		}, chainOtherKey, false},
		{"a leaf that does not parse, named by its label", func(e *testEnv, n *node) {
			e.store.put("key-certificate", "", "token-signing/junk", &keyv2alpha1.KeyCertificate{Purpose: "token-signing",
				Recipient: recipientLabel(n.srv.keys["token-signing"].keyID), Chain: [][]byte{[]byte("junk")}})
		}, chainUnreadable, false},
		{"a root that does not parse", func(e *testEnv, n *node) {
			k := n.srv.keys["token-signing"]
			e.store.put("key-certificate", "", "token-signing/x", &keyv2alpha1.KeyCertificate{Purpose: "token-signing", SpkiDer: k.spki,
				Chain: [][]byte{leafCert(t, k.spki, "leaf", e.clock.now().Add(100*day)), []byte("junk")}})
		}, chainUnreadable, false},
		{"a usable chain next to a bad one", func(e *testEnv, n *node) {
			k := n.srv.keys["token-signing"]
			e.store.put("key-certificate", "", "token-signing/good", &keyv2alpha1.KeyCertificate{Purpose: "token-signing", SpkiDer: k.spki,
				Chain: [][]byte{leafCert(t, k.spki, "good", e.clock.now().Add(100*day))}})
			e.store.put("key-certificate", "", "token-signing/junk", &keyv2alpha1.KeyCertificate{Purpose: "token-signing", SpkiDer: k.spki, Chain: [][]byte{[]byte("junk")}})
		}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newTestEnv(t, "development")
			n := e.startedNode(nodeOpts{})
			c.items(e, n)
			r, err := n.status()
			if err != nil {
				t.Fatal(err)
			}
			k := keyByPurpose(r, "token-signing")
			if k.GetChainProblem() != c.want || (len(k.GetChain()) > 0) != c.chain {
				t.Fatalf("chain problem %q, %d certificates; want %q and a chain: %t", k.GetChainProblem(), len(k.GetChain()), c.want, c.chain)
			}
		})
	}
}

// verifies: REQ-KEYS-249
// Of two usable chains the one whose earliest end is later wins, and not the one whose leaf ends later: a root that ends
// first ends the chain.
func TestStatusChoosesByTheEarliestEndOfTheWholeChain(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	k := n.srv.keys["token-signing"]
	at := e.clock.now()
	day := 24 * time.Hour
	shortRoot := leafCert(t, n.srv.keys["audit-log"].spki, "short root", at.Add(120*day))
	e.store.put("key-certificate", "", "token-signing/a", &keyv2alpha1.KeyCertificate{Purpose: "token-signing", SpkiDer: k.spki,
		Chain: [][]byte{leafCert(t, k.spki, "long leaf, short root", at.Add(300*day)), shortRoot}, AddedAt: timestamppb.New(at.Add(time.Hour))})
	e.store.put("key-certificate", "", "token-signing/b", &keyv2alpha1.KeyCertificate{Purpose: "token-signing", SpkiDer: k.spki,
		Chain: [][]byte{leafCert(t, k.spki, "shorter leaf", at.Add(200*day))}, AddedAt: timestamppb.New(at)})
	r, err := n.status()
	if err != nil {
		t.Fatal(err)
	}
	got := keyByPurpose(r, "token-signing").GetChain()
	if len(got) != 1 {
		t.Fatalf("chain of %d certificates: the chain whose root ends in 120 days won", len(got))
	}
	if leaf, _ := x509.ParseCertificate(got[0]); leaf.Subject.CommonName != "shorter leaf" {
		t.Fatalf("leaf = %v", leaf.Subject.CommonName)
	}
}
