//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/truvity/sluis/v2/actors/key/internal/envelope"
	"github.com/truvity/sluis/v2/actors/key/internal/wrap"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
)

func mustMarshal(m proto.Message) []byte {
	b, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

// The thumbprint vectors are committed in testdata: RFC 7638, section 3.1, which pins the procedure, and a P-384
// key whose thumbprint was computed outside Go.
func TestThumbprintVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/thumbprint-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []struct {
			Name       string `json:"name"`
			SPKI       string `json:"spki_der_base64"`
			Canonical  string `json:"canonical"`
			Thumbprint string `json:"thumbprint"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) < 2 {
		t.Fatalf("%d vectors, want the RFC example and a P-384 key", len(f.Vectors))
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if got := thumbprintOf(v.Canonical); got != v.Thumbprint {
				t.Fatalf("thumbprintOf = %s, want %s", got, v.Thumbprint)
			}
			if !validRecipientID(v.Thumbprint) {
				t.Fatalf("%s is not accepted as a recipient id", v.Thumbprint)
			}
			if v.SPKI == "" {
				return
			}
			der, err := base64.StdEncoding.DecodeString(v.SPKI)
			if err != nil {
				t.Fatal(err)
			}
			got, err := spkiThumbprint(der)
			if err != nil || got != v.Thumbprint {
				t.Fatalf("spkiThumbprint = %s, %v; want %s", got, err, v.Thumbprint)
			}
		})
	}
}

func TestRecipientIDForm(t *testing.T) {
	good := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if !validRecipientID(good) {
		t.Fatal("a thumbprint is refused")
	}
	for _, bad := range []string{"", "node-1-abcdefghijklmnop", good + "=", good[:42], good + "A", strings.ToUpper(good) + "?", strings.Repeat("!", 43)} {
		if validRecipientID(bad) {
			t.Errorf("%q is accepted as a recipient id", bad)
		}
	}
}

// outsider is a key pair that is not a node of the installation: a certificate for it can only come from the store.
type outsider struct {
	priv  *ecdsa.PrivateKey
	spki  []byte
	id    string // its thumbprint
	label string
}

func newOutsider(t *testing.T) outsider {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id, err := spkiThumbprint(der)
	if err != nil {
		t.Fatal(err)
	}
	return outsider{priv: k, spki: der, id: id, label: recipientLabel(id)}
}

// inject puts a KeyCertificate into the store as store@ itself could: key@ did not write it.
func (e *testEnv) inject(o outsider) {
	e.store.put("key-certificate", "", certPrefix+o.label, &keyv2alpha1.KeyCertificate{
		Purpose: wrappingPurpose, Recipient: o.label, SpkiDer: o.spki,
	})
}

// wrapsOf lists the recipients that hold a wrap of the boundary's keys.
func (e *testEnv) wrapRecipients() map[string]int {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	out := map[string]int{}
	for _, it := range e.store.items {
		if it.GetAddress().GetKind() != "data-key-wrap" {
			continue
		}
		w := &keyv2alpha1.DataKeyWrap{}
		if err := proto.Unmarshal(it.GetValue(), w); err != nil {
			panic(err)
		}
		out[w.GetRecipient()]++
	}
	return out
}

func (e *testEnv) cookieEnvelope(n *node, id string) []byte {
	e.t.Helper()
	env, err := seal1(n.client("session"), "cookie", "cookie", "", id, []byte("a cookie"), nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return env
}

// verifies: REQ-KEYS-075
// A KeyCertificate that store@ makes up for a key the KeyPlan does not list is never used: its key gets no wrap,
// not from a new data key and not from a rewrap pass, and the refusal is audited once.
func TestUnlistedCertificateIsNeverUsed(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	evil := newOutsider(t)
	e.inject(evil)

	e.cookieEnvelope(a, "s1")
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.cookieEnvelope(a, "s2")
	got := e.wrapRecipients()
	if got[evil.label] != 0 {
		t.Fatalf("the unlisted key holds %d wraps", got[evil.label])
	}
	if got[a.srv.recipient] == 0 || len(got) != 1 {
		t.Fatalf("wrap recipients = %v, want this node only", got)
	}
	var refused int
	for _, ev := range a.audit.all() {
		if ev.Action == ActionRefuse && ev.Reason == reasonRecipient && ev.Fields["what"] == "certificate-not-listed" {
			refused++
			if ev.Fields["recipient"] != evil.id || ev.Fields["path"] != certPrefix+evil.label {
				t.Fatalf("the refusal names %v", ev.Fields)
			}
			if !ev.Failure {
				t.Fatal("the refusal is not a failure fact")
			}
		}
	}
	if refused != 1 {
		t.Fatalf("%d refusals audited, want 1 (the same finding is not audited at every pass)", refused)
	}
}

// verifies: REQ-KEYS-075
// A certificate for a listed key under a label other than the one derived from the listed id is
// ignored: the store does not choose the address of a wrap. With the derived label also there, the wrap goes under it
// and under no other, whatever the order of the labels.
func TestStrayLabelDoesNotChooseTheAddress(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	o := newOutsider(t)
	e.list(o.id)
	stray := "aaa-aaaaaaaaaaaaaaaa" // sorts before the derived label
	e.store.put("key-certificate", "", certPrefix+stray, &keyv2alpha1.KeyCertificate{
		Purpose: wrappingPurpose, Recipient: stray, SpkiDer: o.spki,
	})
	e.cookieEnvelope(a, "s1")
	if got := e.wrapRecipients(); len(got) != 1 {
		t.Fatalf("wrap recipients = %v, want this node only: a stray label stood for the listed key", got)
	}
	if err := a.srv.Check(context.Background()); err == nil || !strings.Contains(err.Error(), o.id) {
		t.Fatalf("check = %v, want the listed key reported as without a key", err)
	}
	e.inject(o)
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := e.wrapRecipients()
	if len(got) != 2 || got[o.label] != 1 || got[stray] != 0 {
		t.Fatalf("wrap recipients = %v, want the node and the derived label of the listed key", got)
	}
}

// verifies: REQ-KEYS-075
// A listed key is used: the certificate only supplies its public key, every data key is wrapped for it, and its
// holder opens the wrap.
func TestListedKeyIsUsed(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	o := newOutsider(t)
	e.list(o.id)
	e.inject(o)

	env := e.cookieEnvelope(a, "s1")
	got := e.wrapRecipients()
	if got[o.label] != 1 || got[a.srv.recipient] != 1 {
		t.Fatalf("wrap recipients = %v, want one wrap each for the node and the listed key", got)
	}
	// The holder of the listed key opens the wrap and the key opens the value.
	var w *keyv2alpha1.DataKeyWrap
	e.store.mu.Lock()
	for _, it := range e.store.items {
		if it.GetAddress().GetKind() == "data-key-wrap" && strings.HasSuffix(it.GetAddress().GetId(), "/"+o.label) {
			w = &keyv2alpha1.DataKeyWrap{}
			if err := proto.Unmarshal(it.GetValue(), w); err != nil {
				panic(err)
			}
		}
	}
	e.store.mu.Unlock()
	if w == nil {
		t.Fatal("no wrap for the listed key")
	}
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
	key, err := wrap.Unwrap(wrap.Context{Boundary: testBoundary, Tenant: envelope.NoTenant, Purpose: w.GetPurpose(), Generation: w.GetGeneration(), Recipient: o.label}, secret, w.GetWrappedKey())
	if err != nil {
		t.Fatalf("the listed key cannot open its wrap: %v", err)
	}
	pt, err := envelope.Open(key, env, envelope.Address{Boundary: testBoundary, Tenant: envelope.NoTenant, Kind: "cookie", ID: "s1"})
	if err != nil || string(pt) != "a cookie" {
		t.Fatalf("the listed key opens the value: %q, %v", pt, err)
	}
}

// A change of the list is followed by the rewrap pass: a key listed after the data keys were made gets a wrap of
// each of them, and a second pass writes nothing.
func TestPlanChangeIsRewrapped(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	e.cookieEnvelope(a, "s1")
	o := newOutsider(t)
	e.inject(o) // there, and not listed
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.wrapRecipients()[o.label] != 0 {
		t.Fatal("wrapped for a key that is not listed")
	}
	e.list(o.id) // the reviewed commit
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := e.wrapRecipients(); got[o.label] != got[a.srv.recipient] || got[o.label] == 0 {
		t.Fatalf("wrap recipients = %v after the change, want as many for the new key as for the node", got)
	}
	n := e.store.wrapWriteCount()
	if err := a.srv.Rewrap(context.Background()); err != nil || e.store.wrapWriteCount() != n {
		t.Fatalf("a second pass wrote wraps (%v)", err)
	}
}

// A KeyPlan that lists many recipients with no key is reported with one fact for each, and every fact fits a record: the
// thumbprints of 24 recipients joined are longer than the 1024 bytes of a record string, and the fact that held them
// would be refused by the emitter and lost.
func TestManyMissingKeysAreReportedOneFactEach(t *testing.T) {
	e := newTestEnv(t, "development")
	const n = 30
	want := map[string]bool{}
	for i := 0; i < n; i++ {
		o := newOutsider(t)
		e.list(o.id)
		want[o.id] = true
	}
	if n*(len(newOutsider(t).id)+1) <= audit.StringMax {
		t.Fatalf("%d recipients no longer pass a record string: the test checks nothing", n)
	}
	a := e.startedNode(nodeOpts{name: "node-1"})
	e.cookieEnvelope(a, "s1")
	got := map[string]bool{}
	for _, ev := range a.audit.all() {
		if ev.Action != ActionRefuse || ev.Reason != reasonRecipient || ev.Fields["what"] != "recipient-has-no-key" {
			continue
		}
		id, ok := ev.Fields["recipient"].(string)
		if !ok || len(id) > audit.StringMax {
			t.Fatalf("the report holds %v", ev.Fields)
		}
		got[id] = true
	}
	if len(got) != n {
		t.Fatalf("%d recipients reported, want %d", len(got), n)
	}
	for id := range want {
		if !got[id] {
			t.Errorf("%s was not reported", id)
		}
	}
}

// verifies: REQ-KEYS-075
// A listed recipient with no key leaves the wrap set incomplete: the wraps go to the keys that are there, the
// check says so and fails, the finding is audited, and it is never filled with an unlisted key. When the key
// appears, the next pass completes the set and the check passes.
func TestMissingListedKeyIsReported(t *testing.T) {
	e := newTestEnv(t, "development")
	missing := newOutsider(t)
	e.list(missing.id)
	a := e.startedNode(nodeOpts{name: "node-1"})
	var out bytes.Buffer
	a.srv.cfg.Out = &out
	stranger := newOutsider(t)
	e.inject(stranger) // a key there is no commit for

	e.cookieEnvelope(a, "s1")
	got := e.wrapRecipients()
	if len(got) != 1 || got[a.srv.recipient] != 1 {
		t.Fatalf("wrap recipients = %v, want this node only", got)
	}
	var reports int
	for _, ev := range a.audit.all() {
		if ev.Action == ActionRefuse && ev.Reason == reasonRecipient && ev.Fields["what"] == "recipient-has-no-key" {
			reports++
			if ev.Fields["recipient"] != missing.id {
				t.Fatalf("the report names %v", ev.Fields)
			}
		}
	}
	if reports != 1 {
		t.Fatalf("%d reports audited, want 1", reports)
	}
	err := a.srv.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "incomplete") || !strings.Contains(err.Error(), missing.id) {
		t.Fatalf("check = %v, want the incomplete wrap set with the missing id", err)
	}
	if !strings.Contains(out.String(), "wrapping key id: "+a.srv.wrappingID) || !strings.Contains(out.String(), "wrapping key listed: true") {
		t.Fatalf("check printed %q", out.String())
	}

	e.inject(missing)
	if err := a.srv.Rewrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := e.wrapRecipients(); got[missing.label] != 1 || got[stranger.label] != 0 {
		t.Fatalf("wrap recipients = %v after the key appeared", got)
	}
	if err := a.srv.Check(context.Background()); err != nil {
		t.Fatalf("check after the key appeared: %v", err)
	}
}

// A node whose key the KeyPlan does not list makes no data key (it could not open it again) and says so in the
// check, which still passes: it is how a node joins. Once it is listed it works.
func TestUnlistedNodeMakesNoKey(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{name: "node-1", unlisted: true})
	var out bytes.Buffer
	n.srv.cfg.Out = &out
	_, err := seal1(n.client("session"), "cookie", "cookie", "", "s1", []byte("x"), nil)
	wantRefusal(t, err, connect.CodeUnavailable, "wrap")
	if got := e.wrapRecipients(); len(got) != 0 {
		t.Fatalf("wraps were written: %v", got)
	}
	if err := n.srv.Check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if !strings.Contains(out.String(), "wrapping key id: "+n.srv.wrappingID) || !strings.Contains(out.String(), "wrapping key listed: false") {
		t.Fatalf("check printed %q", out.String())
	}
	e.list(n.driver.wrappingID())
	if _, err := seal1(n.client("session"), "cookie", "cookie", "", "s1", []byte("x"), nil); err != nil {
		t.Fatalf("after the node was listed: %v", err)
	}
}

// The check before the wrapping key exists reports that and passes; it makes no key.
func TestCheckBeforeTheKeyExists(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.newNode(nodeOpts{unlisted: true})
	var out bytes.Buffer
	n.srv.cfg.Out = &out
	if err := n.srv.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "wrapping key id: none yet") || len(n.driver.keys) != 0 {
		t.Fatalf("check printed %q and the driver made %d keys", out.String(), len(n.driver.keys))
	}
}

// A list that is not thumbprints, or that names one twice, stops key@ at start.
func TestMalformedRecipientsStopTheStart(t *testing.T) {
	good := newOutsider(t).id
	for name, c := range map[string]struct {
		list []string
		want string
	}{
		// The schema of the KeyPlan answers first, by the form of a thumbprint and by a repeat (REQ-DATA-038).
		"a label":   {[]string{"node-1-abcdefghijklmnop"}, "default.recipients[0]: not in the form the schema requires"},
		"a repeat":  {[]string{good, good}, "default.recipients: items are not unique"},
		"too short": {[]string{good[:40]}, "default.recipients[0]: not in the form the schema requires"},
		// Of the right form and not the canonical encoding of a hash: the schema accepts it, and key@'s own check refuses it.
		"a last character that is not canonical": {[]string{good[:42] + "B"}, "recipients[0] is not an RFC 7638 thumbprint"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t, "development")
			n := e.newNode(nodeOpts{unlisted: true})
			plan := defaultPlan()
			plan.Recipients = c.list
			e.putPlan(plan)
			err := n.srv.Init(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Init = %v, want a refusal that says %q", err, c.want)
			}
			if len(n.driver.keys) != 0 {
				t.Fatal("the driver made keys for a refused KeyPlan")
			}
		})
	}
}

// verifies: REQ-KEYS-075
// A certificate that store@ swaps for a listed node's own, with the attacker's key under the listed
// node's label, is not used: the thumbprint of the key in it is not the listed id, so the listed node is missing and
// the attacker's key is not a recipient.
func TestSwappedCertificateKeyIsNotUsed(t *testing.T) {
	e := newTestEnv(t, "development")
	a := e.startedNode(nodeOpts{name: "node-1"})
	honest, evil := newOutsider(t), newOutsider(t)
	e.list(honest.id)
	e.store.put("key-certificate", "", certPrefix+honest.label, &keyv2alpha1.KeyCertificate{
		Purpose: wrappingPurpose, Recipient: honest.label, SpkiDer: evil.spki,
	})
	e.cookieEnvelope(a, "s1")
	if got := e.wrapRecipients(); len(got) != 1 || got[a.srv.recipient] != 1 {
		t.Fatalf("wrap recipients = %v, want this node only", got)
	}
	if err := a.srv.Check(context.Background()); err == nil || !strings.Contains(err.Error(), honest.id) {
		t.Fatalf("check = %v, want the listed node reported as without a key", err)
	}
}

// Wraps under the old label format (<node>-<hash>), made before the label was derived from the listed id, are not
// opened by anyone now. That fails closed, and it says why: the log names the label once, and the check fails with
// the remedy, so that an unpurged board is not left to fail every seal and open with a message that says "wait".
func TestOldLabelWrapsAreSaidNotSilent(t *testing.T) {
	e := newTestEnv(t, "development")
	logs := captureLog(t)
	a := e.startedNode(nodeOpts{name: "node-1"})
	old := "node-1-abcdefghijklmnop"
	e.store.mu.Lock()
	e.store.items["|data-key-wrap|cookie/1/"+old] = &storev2alpha1.Item{
		Address: &typev2alpha1.Address{Kind: "data-key-wrap", Id: "cookie/1/" + old}, Version: 1,
		Value:   mustMarshal(&keyv2alpha1.DataKeyWrap{Purpose: "cookie", Generation: 1, Recipient: old}),
		Indexes: []*typev2alpha1.IndexEntry{{Name: indexByPurpose, Value: []byte("cookie")}, {Name: indexByRecipient, Value: []byte(old)}},
	}
	e.store.mu.Unlock()

	_, err := seal1(a.client("session"), "cookie", "cookie", "", "s1", []byte("x"), nil)
	wantRefusal(t, err, connect.CodeUnavailable, "wrap")
	if !strings.Contains(logs.String(), "old recipient label format") || !strings.Contains(logs.String(), old) {
		t.Fatalf("the log does not name the old label:\n%s", logs.String())
	}
	if n := strings.Count(logs.String(), "old recipient label format"); n != 1 {
		t.Fatalf("the warning was logged %d times, want once", n)
	}
	err = a.srv.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), old) || !strings.Contains(err.Error(), "delete those DataKeyWrap items") {
		t.Fatalf("check = %v, want the old label and the remedy", err)
	}
	// Once they are gone the node makes its key and the check passes.
	e.store.mu.Lock()
	delete(e.store.items, "|data-key-wrap|cookie/1/"+old)
	e.store.mu.Unlock()
	if _, err := seal1(a.client("session"), "cookie", "cookie", "", "s1", []byte("x"), nil); err != nil {
		t.Fatalf("after the old wraps were deleted: %v", err)
	}
	if err := a.srv.Check(context.Background()); err != nil {
		t.Fatalf("check after the old wraps were deleted: %v", err)
	}
}
