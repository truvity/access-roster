//go:build sluis_test

package keyd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	signerv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// declarationPayload is the payload of a declaration, as `sluis key revoke` produces it.
func declarationPayload(boundary, reason string, kids ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "boundary: %s\nkids:\n", boundary)
	for _, k := range kids {
		fmt.Fprintf(&b, "  - %s\n", k)
	}
	fmt.Fprintf(&b, "reason: %s\n", reason)
	return []byte(b.String())
}

// declare signs a declaration with the publisher of the test's boundary.
func (e *testEnv) declare(seq uint64, reason string, kids ...string) []byte {
	e.t.Helper()
	return e.signKind("publisher-1", e.pub, seq, declarationKind, declarationPayload(testBoundary, reason, kids...))
}

// admin is a client of the node's admin socket.
func (n *node) admin() keyv2alpha1connect.KeyAdminServiceClient {
	hc, url := rpc.Dial(filepath.Join(n.runDir, adminSocketName))
	return keyv2alpha1connect.NewKeyAdminServiceClient(hc, url, rpc.ClientOptions()...)
}

func (n *node) revoke(doc []byte) (*keyv2alpha1.RevokeResponse, error) {
	res, err := n.admin().Revoke(context.Background(), connect.NewRequest(&keyv2alpha1.RevokeRequest{Declaration: doc}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// revocations returns the KeyRevocation items of the store, by id.
func (e *testEnv) revocationItems() map[string]*keyv2alpha1.KeyRevocation {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	out := map[string]*keyv2alpha1.KeyRevocation{}
	for _, it := range e.store.items {
		if it.GetAddress().GetKind() != "key-revocation" {
			continue
		}
		v := &keyv2alpha1.KeyRevocation{}
		if err := proto.Unmarshal(it.GetValue(), v); err != nil {
			e.t.Fatal(err)
		}
		out[it.GetAddress().GetId()] = v
	}
	return out
}

// refusedAdmin checks a refusal of the admin socket and its audit fact, and that nothing was written.
func (n *node) refusedAdmin(t *testing.T, err error, code connect.Code, reason, path string) {
	t.Helper()
	before := len(n.e.revocationItems())
	n.refusal(t, err, code, reason, path)
	if got := len(n.e.revocationItems()); got != before {
		t.Fatalf("a refused declaration wrote %d items", got-before)
	}
}

// verifies: REQ-KEYS-087
// verifies: REQ-KEYS-108
// verifies: REQ-SEC-034
// A declaration signed with the publisher key revokes exactly the keys it names: one KeyRevocation item each, with
// the reason, and the revoked keys sign nothing more. One audit fact names the keys, the reason and the operator (the
// publisher key that signed). A later declaration that names a revoked key again writes nothing new for it.
func TestADeclarationRevokesTheKeysItNames(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	token, logKey := n.srv.keys["token-signing"].keyID, n.srv.keys["audit-log"].keyID
	tokenIn, logIn := signContent(t, n, "token-signing"), signContent(t, n, "audit-log")

	res, err := n.revoke(e.declare(100, "compromise", token))
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if res.GetSeq() != 100 || len(res.GetKeys()) != 1 || res.GetKeys()[0].GetKid() != token || res.GetKeys()[0].GetAlready() || !res.GetAudited() {
		t.Fatalf("Revoke = %v", res)
	}
	items := e.revocationItems()
	it := items[revocationID(targetKid, token)]
	if len(items) != 1 || it.GetTargetKind() != targetKid || it.GetTarget() != token || it.GetReasonCode() != "compromise" ||
		!it.GetRevokedAt().AsTime().Equal(e.clock.now()) {
		t.Fatalf("items = %v", items)
	}
	// The item is dated at the declaration and holds nothing else: no later effective time, no pre-publication or
	// retention period (REQ-KEYS-087). The key is refused at once, with the clock where it was.
	populated := 0
	it.ProtoReflect().Range(func(protoreflect.FieldDescriptor, protoreflect.Value) bool { populated++; return true })
	if populated != 4 {
		t.Fatalf("the item has %d fields set, want the four of a plain revocation: %v", populated, it)
	}
	n.refusal(t, n.signFor("token-signing", tokenIn), connect.CodePermissionDenied, reasonRevoked, targetKid)
	if err := n.signFor("audit-log", logIn); err != nil {
		t.Fatalf("a key the declaration did not name stopped signing: %v", err)
	}
	var facts []Event
	for _, ev := range n.audit.all() {
		if ev.Action == ActionRevoke {
			facts = append(facts, ev)
		}
	}
	if len(facts) != 1 {
		t.Fatalf("%d revocation facts, want 1", len(facts))
	}
	f := facts[0].Fields
	if !slices.Equal(f["kids"].([]string), []string{token}) || f["reason"] != "compromise" ||
		!slices.Equal(f["operator"].([]string), []string{"publisher-1"}) || f["seq"] != int64(100) || facts[0].Reason != "compromise" {
		t.Fatalf("the fact = %v", f)
	}

	// The next declaration names both: the token key is already revoked and only the log key is new.
	res, err = n.revoke(e.declare(101, "drill", token, logKey))
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !res.GetKeys()[0].GetAlready() || res.GetKeys()[1].GetAlready() {
		t.Fatalf("Revoke = %v", res)
	}
	if got := e.revocationItems()[revocationID(targetKid, token)].GetReasonCode(); got != "compromise" {
		t.Fatalf("the first revocation was changed: reason %q", got)
	}
	n.refusal(t, n.signFor("audit-log", logIn), connect.CodePermissionDenied, reasonRevoked, targetKid)
}

// verifies: REQ-KEYS-108
// A declaration that was changed after it was signed, or signed by a key the bootstrap file does not pin, or under
// the kid of the pinned key by another key, is refused and writes nothing.
func TestATamperedOrForgedDeclarationIsRefused(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	token := n.srv.keys["token-signing"].keyID

	// One byte of the payload changed: the payload of a valid declaration for another key is swapped in.
	good := e.declare(10, "compromise", token)
	other := e.signKind("publisher-1", e.pub, 10, declarationKind, declarationPayload(testBoundary, "drill", token))
	tampered := swapPayload(t, good, other)
	_, err := n.revoke(tampered)
	n.refusedAdmin(t, err, connect.CodePermissionDenied, reasonDeclaration, "declaration")

	stranger, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string][]byte{
		"an unpinned kid":           e.signKind("publisher-2", stranger, 11, declarationKind, declarationPayload(testBoundary, "compromise", token)),
		"another key, a pinned kid": e.signKind("publisher-1", stranger, 11, declarationKind, declarationPayload(testBoundary, "compromise", token)),
		"not a JWS":                 []byte(`{"payload":"","signatures":[]}`),
	} {
		_, err := n.revoke(doc)
		t.Run(name, func(t *testing.T) {
			n.refusedAdmin(t, err, connect.CodePermissionDenied, reasonDeclaration, "declaration")
		})
	}
	if err := n.signFor("token-signing", signContent(t, n, "token-signing")); err != nil {
		t.Fatalf("a refused declaration stopped the key: %v", err)
	}
	// The good one is still taken: a refusal burns no seq.
	if _, err := n.revoke(good); err != nil {
		t.Fatalf("the untampered declaration: %v", err)
	}
}

// swapPayload returns doc with the payload of from: the signature of doc over another payload.
func swapPayload(t *testing.T, doc, from []byte) []byte {
	t.Helper()
	payload := func(b []byte) string {
		s := string(b)
		i := strings.Index(s, `"payload":"`) + len(`"payload":"`)
		return s[i : i+strings.Index(s[i:], `"`)]
	}
	out := strings.Replace(string(doc), payload(doc), payload(from), 1)
	if out == string(doc) {
		t.Fatal("the payloads are the same")
	}
	return []byte(out)
}

// verifies: REQ-KEYS-112
// key@ takes a declaration only with a seq above the highest it took, or the same seq with the same payload, which is
// a retry of the last one and writes nothing that exists. The same seq with another payload, and an older seq, are
// refused, in the process and after a restart, because the mark is kept in the state directory with its digest.
func TestADeclarationIsTakenOnceAndNeverAnOlderOne(t *testing.T) {
	e := newTestEnv(t, "development")
	state := shortDir(t)
	n := e.startedNode(nodeOpts{stateDir: state})
	token, logKey := n.srv.keys["token-signing"].keyID, n.srv.keys["audit-log"].keyID
	first := e.declare(50, "suspicion", token)
	if _, err := n.revoke(first); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	res, err := n.revoke(first)
	if err != nil || !res.GetKeys()[0].GetAlready() {
		t.Fatalf("the same declaration again is a retry that writes nothing new: %v, %v", res, err)
	}
	_, err = n.revoke(e.declare(50, "suspicion", logKey))
	n.refusedAdmin(t, err, connect.CodeFailedPrecondition, reasonSeq, "seq")
	_, err = n.revoke(e.declare(49, "suspicion", logKey))
	n.refusedAdmin(t, err, connect.CodeFailedPrecondition, reasonSeq, "seq")

	// After a restart on the same state the mark still holds 50 and its digest.
	n.stop()
	m := e.startedNode(nodeOpts{stateDir: state, driver: n.driver})
	_, err = m.revoke(e.declare(50, "suspicion", logKey))
	m.refusedAdmin(t, err, connect.CodeFailedPrecondition, reasonSeq, "seq")
	if _, err := m.revoke(first); err != nil {
		t.Fatalf("a retry of the last declaration after the restart: %v", err)
	}
	if _, err := m.revoke(e.declare(51, "suspicion", logKey)); err != nil {
		t.Fatalf("a higher seq after the restart: %v", err)
	}
}

// verifies: REQ-KEYS-112
// A store@ that fails after the mark is saved leaves the declaration taken in part: key@ refuses it as "partial",
// names the keys still pending in the detail, and the audit fact says so. Delivering the same declaration again, also
// after a restart, completes it.
func TestADeclarationStoppedHalfWayIsCompletedByARetry(t *testing.T) {
	e := newTestEnv(t, "development")
	state := shortDir(t)
	n := e.startedNode(nodeOpts{stateDir: state})
	token, logKey := n.srv.keys["token-signing"].keyID, n.srv.keys["audit-log"].keyID
	decl := e.declare(70, "compromise", token, logKey)
	e.store.mu.Lock()
	e.store.writesLeft = 1 // the first item is written, then store@ is down
	e.store.mu.Unlock()
	_, err := n.revoke(decl)
	wantRefusal(t, err, connect.CodeUnavailable, reasonPartial)
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("not a Connect error: %v", err)
	}
	var detail *keyv2alpha1.RevokeResponse
	for _, d := range ce.Details() {
		if v, derr := d.Value(); derr == nil {
			if m, ok := v.(*keyv2alpha1.RevokeResponse); ok {
				detail = m
			}
		}
	}
	if len(detail.GetKeys()) != 2 || detail.GetKeys()[0].GetPending() || !detail.GetKeys()[1].GetPending() {
		t.Fatalf("the detail = %v", detail)
	}
	if len(e.revocationItems()) != 1 {
		t.Fatalf("%d items, want the first only", len(e.revocationItems()))
	}
	var partial bool
	for _, ev := range n.audit.all() {
		if ev.Action == ActionRevoke && ev.Failure && ev.Fields["partial"] == true && slices.Equal(ev.Fields["pending"].([]string), []string{logKey}) {
			partial = true
		}
	}
	if !partial {
		t.Fatal("no audit fact of the partial declaration")
	}

	// store@ is back and key@ restarted: the same declaration completes.
	e.store.mu.Lock()
	e.store.failWrites = false
	e.store.mu.Unlock()
	n.stop()
	m := e.startedNode(nodeOpts{stateDir: state, driver: n.driver})
	res, err := m.revoke(decl)
	if err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if !res.GetKeys()[0].GetAlready() || res.GetKeys()[1].GetAlready() || res.GetKeys()[1].GetPending() || len(e.revocationItems()) != 2 {
		t.Fatalf("the retry = %v", res)
	}
}

// verifies: REQ-KEYS-113
// verifies: REQ-KEYS-092
// Every kid of a declaration must be a key that key@ knows: a signing key it holds, or a token key of any node in
// the SigningRing. One unknown kid refuses the whole declaration, so a typo is never written as a revocation that
// stops nothing; a wrapping key is not a signing key. Another node's token key is revoked from this node, and that
// node's key@ refuses to sign with it.
func TestEveryKidOfADeclarationMustBeKnown(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{name: "node-1"})
	token := n.srv.keys["token-signing"].keyID
	for name, kids := range map[string][]string{
		"a typo":          {token, "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"another's token": {token, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"},
	} {
		_, err := n.revoke(e.declare(e.nextSeq(), "compromise", kids...))
		t.Run(name, func(t *testing.T) {
			n.refusedAdmin(t, err, connect.CodeFailedPrecondition, reasonUnknownKid, "kids[1]")
		})
	}

	// node-2's token key is in the ring: node-1 takes a declaration for it.
	o := e.startedNode(nodeOpts{name: "node-2"})
	oIn := signContent(t, o, "token-signing")
	otherToken := o.srv.keys["token-signing"].keyID
	e.store.put("signing-ring", "", "default", &signerv2alpha1.SigningRing{Keys: []*signerv2alpha1.SigningKey{
		{KeyId: token, Node: "node-1"}, {KeyId: otherToken, Node: "node-2"},
	}})
	if _, err := n.revoke(e.declare(e.nextSeq(), "lost-board", otherToken)); err != nil {
		t.Fatalf("another node's key: %v", err)
	}
	o.refusal(t, o.signFor("token-signing", oIn), connect.CodePermissionDenied, reasonRevoked, targetKid)
	if err := n.signFor("token-signing", signContent(t, n, "token-signing")); err != nil {
		t.Fatalf("node-1's key stopped: %v", err)
	}

	// A ring that cannot be read is "unavailable", not "unknown", and only when a kid is not the node's own.
	e.store.mu.Lock()
	e.store.failKind = "signing-ring"
	e.store.mu.Unlock()
	_, err := n.revoke(e.declare(e.nextSeq(), "compromise", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"))
	n.refusedAdmin(t, err, connect.CodeUnavailable, reasonStore, "")
	if _, err := n.revoke(e.declare(e.nextSeq(), "compromise", n.srv.keys["audit-log"].keyID)); err != nil {
		t.Fatalf("the node's own key while the ring is down: %v", err)
	}
}

// verifies: REQ-KEYS-108
// A document of another kind is not a declaration: a KeyPlan signed by the same publisher, and a declaration's payload
// signed under the kind KeyPlan, are refused. So is a declaration for another boundary, and a payload that is not a
// declaration.
func TestADocumentOfAnotherKindOrBoundaryIsRefused(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	token := n.srv.keys["token-signing"].keyID
	_, err := n.revoke(e.signKind("publisher-1", e.pub, 5, keyPlanKind, declarationPayload(testBoundary, "compromise", token)))
	n.refusedAdmin(t, err, connect.CodePermissionDenied, reasonDeclaration, "declaration")
	_, err = n.revoke(e.store.signed["key-plan"])
	n.refusedAdmin(t, err, connect.CodePermissionDenied, reasonDeclaration, "declaration")
	_, err = n.revoke(e.signKind("publisher-1", e.pub, 6, declarationKind, declarationPayload(testBoundary+"-other", "compromise", token)))
	n.refusedAdmin(t, err, connect.CodePermissionDenied, reasonOtherBoundary, "boundary")
	for path, payload := range map[string]string{
		"reason":   string(declarationPayload(testBoundary, "because", token)),
		"kids[1]":  string(declarationPayload(testBoundary, "drill", token, token)),
		"kids":     "boundary: " + testBoundary + "\nkids: []\nreason: drill\n",
		"purpose":  string(declarationPayload(testBoundary, "drill", token)) + "purpose: token-signing\n",
		"boundary": "kids: [" + token + "]\nreason: drill\n",
	} {
		_, err := n.revoke(e.signKind("publisher-1", e.pub, e.nextSeq(), declarationKind, []byte(payload)))
		t.Run(path, func(t *testing.T) { n.refusedAdmin(t, err, connect.CodeInvalidArgument, reasonSchema, path) })
	}
}

// verifies: REQ-KEYS-108
// The admin socket serves root only: another user is refused from the transport before the declaration is read.
func TestTheAdminSocketRefusesAnotherUser(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.newNode(nodeOpts{})
	n.srv.adminAllow = func(uint32) bool { return false }
	n.start()
	_, err := n.revoke(e.declare(1, "compromise", n.srv.keys["token-signing"].keyID))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("Revoke by another user = %v, want permission_denied", err)
	}
	if len(e.revocationItems()) != 0 {
		t.Fatal("a refused caller wrote an item")
	}
}

// nextSeq is a seq above every one the test used.
func (e *testEnv) nextSeq() uint64 {
	e.seqD += 1000
	return e.seqD
}

// verifies: REQ-KEYS-113
// A key that a KeyCertificate of a signing purpose certifies is known; a wrapping certificate does not make a key
// known. A declaration with allow_unknown revokes keys that no source knows, and the audit fact and the answer mark
// them unknown; without it they are refused.
func TestAllowUnknownRevokesKeysNoSourceKnows(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	certified := newSPKIKid(t)
	e.store.put("key-certificate", "", "x509/"+strings.ToLower(certified.kid[:8]), &keyv2alpha1.KeyCertificate{Purpose: "x509", SpkiDer: certified.spki})
	wrapping := newSPKIKid(t)
	e.store.put("key-certificate", "", "wrapping/"+strings.ToLower(wrapping.kid[:8]), &keyv2alpha1.KeyCertificate{Purpose: "wrapping", SpkiDer: wrapping.spki})
	if _, err := n.revoke(e.declare(e.nextSeq(), "compromise", certified.kid)); err != nil {
		t.Fatalf("a certified key: %v", err)
	}
	_, err := n.revoke(e.declare(e.nextSeq(), "compromise", wrapping.kid))
	n.refusedAdmin(t, err, connect.CodeFailedPrecondition, reasonWrappingKey, "kids[0]")

	lost := "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	token := n.srv.keys["token-signing"].keyID
	payload := string(declarationPayload(testBoundary, "lost-board", token, lost)) + "allow_unknown: true\n"
	res, err := n.revoke(e.signKind("publisher-1", e.pub, e.nextSeq(), declarationKind, []byte(payload)))
	if err != nil {
		t.Fatalf("allow_unknown: %v", err)
	}
	if res.GetKeys()[0].GetUnknown() || !res.GetKeys()[1].GetUnknown() {
		t.Fatalf("Revoke = %v", res)
	}
	if e.revocationItems()[revocationID(targetKid, lost)].GetReasonCode() != "lost-board" {
		t.Fatal("the unknown key was not written")
	}
	var marked bool
	for _, ev := range n.audit.all() {
		if ev.Action == ActionRevoke && slices.Equal(ev.Fields["unknown"].([]string), []string{lost}) {
			marked = true
		}
	}
	if !marked {
		t.Fatal("the audit fact does not mark the unknown key")
	}
	bad := string(declarationPayload(testBoundary, "drill", token)) + "allow_unknown: yes\n"
	_, err = n.revoke(e.signKind("publisher-1", e.pub, e.nextSeq(), declarationKind, []byte(bad)))
	n.refusedAdmin(t, err, connect.CodeInvalidArgument, reasonSchema, "allow_unknown")
}

// verifies: REQ-SEC-034, REQ-AUDIT-015, REQ-AUDIT-187
// The audit fact names the node that took the declaration and the uid that delivered it. When the fact cannot be
// made durable the keys are still revoked, and the answer says the fact is missing.
func TestTheRevocationFactNamesTheNodeAndTheCaller(t *testing.T) {
	e := newTestEnv(t, "development")
	rec := &recorder{}
	n := e.startedNode(nodeOpts{name: "node-7", audit: rec})
	token := n.srv.keys["token-signing"].keyID
	if _, err := n.revoke(e.declare(1, "drill", token)); err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	for _, ev := range rec.all() {
		if ev.Action == ActionRevoke {
			f = ev.Fields
		}
	}
	if f["node"] != "node-7" || f["peer_uid"] != int64(os.Getuid()) {
		t.Fatalf("the fact = %v", f)
	}
	// The revocation stands whatever the audit transport does, so its fact is lost when the transport refuses it and
	// the emitter must count it (REQ-AUDIT-187): the event asks for the best-effort variant of the blocking emit.
	for _, ev := range rec.all() {
		if ev.Action == ActionRevoke && (!ev.Blocking || !ev.BestEffort) {
			t.Fatalf("the revocation fact is blocking %v, best effort %v; want both", ev.Blocking, ev.BestEffort)
		}
	}

	rec.mu.Lock()
	rec.failing = true
	rec.mu.Unlock()
	logKey := n.srv.keys["audit-log"].keyID
	res, err := n.revoke(e.declare(2, "drill", logKey))
	if err != nil || res.GetAudited() {
		t.Fatalf("Revoke with the audit transport down = %v, %v; want audited false", res, err)
	}
	if _, ok := e.revocationItems()[revocationID(targetKid, logKey)]; !ok {
		t.Fatal("the key is not revoked when the audit fact fails")
	}
}

// The admin socket's own rule, root only, refuses this test's user through a real Unix socket and SO_PEERCRED.
func TestTheAdminSocketServesRootOnly(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("SKIP: the test runs as root, which the rule allows; it needs another user")
	}
	e := newTestEnv(t, "development")
	n := e.newNode(nodeOpts{})
	n.srv.adminAllow = rootOnly
	n.start()
	_, err := n.revoke(e.declare(1, "compromise", n.srv.keys["token-signing"].keyID))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("Revoke as uid %d = %v, want permission_denied", os.Getuid(), err)
	}
	if len(e.revocationItems()) != 0 {
		t.Fatal("a refused caller wrote an item")
	}
}

type spkiKid struct {
	spki []byte
	kid  string
}

// newSPKIKid makes a P-384 public key and its RFC 7638 thumbprint.
func newSPKIKid(t *testing.T) spkiKid {
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
	return spkiKid{spki: der, kid: id}
}

// verifies: REQ-KEYS-113
// A wrapping key is never revoked by a declaration of signing keys, with or without allow_unknown: this node's own,
// another recipient of the KeyPlan and one that a wrapping KeyCertificate certifies are refused with their own reason,
// and nothing is written.
func TestAWrappingKeyIsRefusedEvenWithAllowUnknown(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{name: "node-1"})
	o := e.startedNode(nodeOpts{name: "node-2"}) // lists its wrapping key as a recipient of the KeyPlan
	certified := newSPKIKid(t)
	e.store.put("key-certificate", "", "wrapping/"+strings.ToLower(certified.kid[:8]), &keyv2alpha1.KeyCertificate{Purpose: "wrapping", SpkiDer: certified.spki})
	token := n.srv.keys["token-signing"].keyID
	for name, kid := range map[string]string{
		"this node's":   n.srv.wrappingID,
		"a recipient's": o.srv.wrappingID,
		"a certified":   certified.kid,
	} {
		for _, allow := range []bool{false, true} {
			payload := string(declarationPayload(testBoundary, "lost-board", token, kid))
			if allow {
				payload += "allow_unknown: true\n"
			}
			_, err := n.revoke(e.signKind("publisher-1", e.pub, e.nextSeq(), declarationKind, []byte(payload)))
			t.Run(fmt.Sprintf("%s, allow_unknown %t", name, allow), func(t *testing.T) {
				n.refusedAdmin(t, err, connect.CodeFailedPrecondition, reasonWrappingKey, "kids[1]")
			})
		}
	}
}

// verifies: REQ-KEYS-112
// A retry does not ask again whether a key it already revoked is known: a token key that left the ring after the first
// delivery wrote it does not turn the retry into unknown-kid, and the retry completes the rest. A new declaration for
// that key is refused as unknown, as it was never retried.
func TestARetryKeepsTheKeysItAlreadyRevoked(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{name: "node-1"})
	o := e.startedNode(nodeOpts{name: "node-2"})
	other, logKey := o.srv.keys["token-signing"].keyID, n.srv.keys["audit-log"].keyID
	e.store.put("signing-ring", "", "default", &signerv2alpha1.SigningRing{Keys: []*signerv2alpha1.SigningKey{{KeyId: other, Node: "node-2"}}})
	decl := e.declare(e.nextSeq(), "compromise", other, logKey)
	e.store.mu.Lock()
	e.store.writesLeft = 1 // the ring key is written, then store@ is down
	e.store.mu.Unlock()
	_, err := n.revoke(decl)
	wantRefusal(t, err, connect.CodeUnavailable, reasonPartial)

	// The ring key leaves the ring, and store@ is back.
	e.store.mu.Lock()
	e.store.failWrites = false
	e.store.mu.Unlock()
	e.store.put("signing-ring", "", "default", &signerv2alpha1.SigningRing{})
	res, err := n.revoke(decl)
	if err != nil {
		t.Fatalf("the retry after the key left the ring: %v", err)
	}
	if !res.GetKeys()[0].GetAlready() || res.GetKeys()[0].GetUnknown() || res.GetKeys()[1].GetAlready() || len(e.revocationItems()) != 2 {
		t.Fatalf("the retry = %v", res)
	}
	_, err = n.revoke(e.declare(e.nextSeq(), "compromise", other))
	n.refusedAdmin(t, err, connect.CodeFailedPrecondition, reasonUnknownKid, "kids[0]")
}

// verifies: REQ-SEC-036
// A declaration that revokes keys raises the alert of key@: an error line with the closed word, the keys it revoked now, the
// reason and the operator (the publisher key that signed). A retry that finds the keys revoked already revokes nothing and
// raises none; a declaration that names an old and a new key names only the new one. The alert stands when the audit
// transport is down.
func TestARevocationRaisesTheAlertThatNamesTheKeysTheReasonAndTheOperator(t *testing.T) {
	logs := captureLog(t)
	e := newTestEnv(t, "development")
	rec := &recorder{}
	n := e.startedNode(nodeOpts{name: "node-3", audit: rec})
	token, logKey := n.srv.keys["token-signing"].keyID, n.srv.keys["audit-log"].keyID
	alerts := func() []string {
		var out []string
		for _, l := range strings.Split(logs.String(), "\n") {
			if strings.Contains(l, "alert=key-revoked") {
				out = append(out, l)
			}
		}
		return out
	}
	if len(alerts()) != 0 {
		t.Fatal("an alert before any revocation")
	}
	rec.mu.Lock()
	rec.failing = true // the audit transport is down: the alert is the log's, and does not wait for the fact
	rec.mu.Unlock()
	doc := e.declare(e.nextSeq(), "compromise", token)
	if _, err := n.revoke(doc); err != nil {
		t.Fatal(err)
	}
	got := alerts()
	if len(got) != 1 {
		t.Fatalf("%d alerts, want 1:\n%s", len(got), logs.String())
	}
	for _, want := range []string{"level=ERROR", token, "reason=compromise", "publisher-1", "node=node-3", "audited=false"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("the alert lacks %q: %s", want, got[0])
		}
	}
	if strings.Contains(got[0], logKey) {
		t.Errorf("the alert names a key the declaration did not revoke: %s", got[0])
	}
	// The same declaration again revokes nothing new: no second alert.
	if _, err := n.revoke(doc); err != nil {
		t.Fatal(err)
	}
	if len(alerts()) != 1 {
		t.Fatalf("a retry raised an alert:\n%s", logs.String())
	}
	// A declaration of an old and a new key alerts for the new one alone.
	if _, err := n.revoke(e.declare(e.nextSeq(), "drill", token, logKey)); err != nil {
		t.Fatal(err)
	}
	got = alerts()
	if len(got) != 2 || strings.Contains(got[1], "kids=\"["+token) || !strings.Contains(got[1], logKey) || !strings.Contains(got[1], "reason=drill") {
		t.Fatalf("alerts = %v", got)
	}
}
