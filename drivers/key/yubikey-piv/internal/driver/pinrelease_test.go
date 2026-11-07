//go:build sluis_test

package driver_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card/cardtest"
	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/driver"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/pinrelease"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
)

// The card tests of the PIN release run on the fake cards of cardtest, in factory state (PIN 123456): two cards of one
// TEST ONLY PKI, as two YubiKeys both chain to Yubico's root. No real card and no real PIN is used. The publisher key
// that signs the KeyPlan is made at test time; the slot map lists the pin-release key of each card, as the harness
// that signs the KeyPlan takes it from each node.

const (
	testBoundary = "test"
	releaserNode = "node-r"
	lockedNode   = "node-l"
	publisherKID = "test-publisher"
)

// boundary is two card drivers of one boundary: an unlocked one (the peer that releases) and a locked one (the board
// that asks), with the publisher key whose KeyPlan both verify.
type boundary struct {
	publisher        *ecdsa.PrivateKey
	publishers       []signedconfig.Publisher
	releaser, locked running
	releaserState    string
	// plan is the KeyPlan document of seq 1 that lists both nodes.
	plan []byte
}

func stateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func newBoundary(t *testing.T) *boundary {
	t.Helper()
	pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := &boundary{publisher: pk, publishers: []signedconfig.Publisher{{KID: publisherKID, Key: &pk.PublicKey}}, releaserState: stateDir(t)}
	a := cardtest.New()
	c := cardtest.New()
	c.SerialNo = 87654321
	c.PKI = a
	b.releaser = startOpts(t, a, driver.Development, "key", self(), driver.Options{Node: releaserNode, Publishers: b.publishers, StateDir: b.releaserState})
	b.locked = startOpts(t, c, driver.Development, "key", self(), driver.Options{Node: lockedNode, Publishers: b.publishers, StateDir: stateDir(t)})
	b.releaser.unlock(t, "123456")
	b.plan = b.signPlan(t, 1, b.entry(t, releaserNode, b.releaser), b.entry(t, lockedNode, b.locked))
	return b
}

// entry is a node of the slot map: its pin-release key in slot 87.
type entry struct {
	node string
	spki []byte
}

func (b *boundary) entry(t *testing.T, node string, r running) entry {
	t.Helper()
	return entry{node: node, spki: ensure(t, r.key, "pin-release", "ES384").GetSpkiDer()}
}

// signPlan signs a KeyPlan of a seq whose slot map lists the entries.
func (b *boundary) signPlan(t *testing.T, seq uint64, entries ...entry) []byte {
	t.Helper()
	return signPlanWith(t, b.publisher, seq, "KeyPlan", entries...)
}

func signPlanWith(t *testing.T, key *ecdsa.PrivateKey, seq uint64, kind string, entries ...entry) []byte {
	t.Helper()
	var p strings.Builder
	p.WriteString("default:\n  cache_ttl: 15m\n  slot_map:")
	if len(entries) == 0 {
		p.WriteString(" []")
	}
	p.WriteString("\n")
	for _, e := range entries {
		fmt.Fprintf(&p, "    - node: %s\n      slots:\n        - { slot: \"87\", purpose: pin-release, public_key: %s }\n",
			e.node, base64.RawURLEncoding.EncodeToString(e.spki))
	}
	doc, err := signedconfig.Sign(key, publisherKID, seq, kind, []byte(p.String()))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// begin makes the locked driver's one-time key and its signed request, as key@ asks for them.
func begin(t *testing.T, r running) (text, sig []byte) {
	t.Helper()
	res, err := r.key.BeginPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{RequestId: newID(t)}))
	if err != nil {
		t.Fatalf("BeginPinRelease: %v", err)
	}
	return res.Msg.GetRequestText(), res.Msg.GetRequestSignatureDer()
}

// signSoft signs a text with a key that is no card's: key@'s own, as a compromised key@ could make one.
func signSoft(t *testing.T, text []byte) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, k, pinrelease.Digest(text))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func sealPin(r running, text, sig, plan []byte) (*keystorev2alpha1.SealPinResponse, error) {
	res, err := r.key.SealPin(context.Background(), connect.NewRequest(&keystorev2alpha1.SealPinRequest{RequestText: text, RequestSignatureDer: sig, KeyPlan: plan}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// seal is the releaser's signed answer to a signed request.
func seal(t *testing.T, b *boundary, text, sig []byte) *keystorev2alpha1.SealPinResponse {
	t.Helper()
	res, err := sealPin(b.releaser, text, sig, b.plan)
	if err != nil {
		t.Fatalf("SealPin: %v", err)
	}
	return res
}

func finish(r running, at, sig, plan []byte) error {
	_, err := r.key.FinishPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.FinishPinReleaseRequest{
		AnswerText: at, AnswerSignatureDer: sig, KeyPlan: plan,
	}))
	return err
}

func newEphemeral(t *testing.T) []byte {
	t.Helper()
	eph, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return eph.PublicKey().Bytes()
}

// verifies: REQ-KEYS-059, REQ-KEYS-115
// The happy path at the drivers: the locked driver writes and signs its request; the unlocked driver verifies the
// KeyPlan and the request, seals the PIN it holds to the locked driver's one-time key and signs the answer; the locked
// driver verifies the KeyPlan and the answer, opens it and gives it to its card once. Then it signs with a PIN-once key.
func TestALockedDriverIsUnlockedByAPeersRelease(t *testing.T) {
	b := newBoundary(t)
	text, sig := begin(t, b.locked)
	a := seal(t, b, text, sig)
	ans, err := pinrelease.ParseAnswer(a.GetAnswerText())
	if err != nil || ans.Releaser != releaserNode || ans.Requester != lockedNode || ans.Boundary != testBoundary {
		t.Fatalf("answer %+v, %v", ans, err)
	}
	if err := finish(b.locked, a.GetAnswerText(), a.GetAnswerSignatureDer(), b.plan); err != nil {
		t.Fatalf("FinishPinRelease: %v", err)
	}
	if b.locked.card.LoginAttempts != 1 {
		t.Fatalf("%d PIN attempts, want 1", b.locked.card.LoginAttempts)
	}
	ensure(t, b.locked.key, "token-signing", "ES384")
	if _, err := sign(b.locked.key, "token-signing", "ES384", digest384()); err != nil {
		t.Fatalf("the unlocked driver does not sign: %v", err)
	}
	// Unlocked now: a second request has nothing to release to.
	_, err = b.locked.key.BeginPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{RequestId: newID(t)}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "unlocked")
}

// key@ asks an unlocked driver for a request every 30 s, as the only way to learn that the driver was locked again. The answer
// is the same refusal as ever, and it is the answer of a board that is well: the journal holds it below a warning, so a
// quiet-journal check of the board does not see it, and any other refusal of the call is still a warning.
func TestAnUnlockedDriverRefusesTheKeyPollWithoutAWarning(t *testing.T) {
	b := newBoundary(t)
	text, sig := begin(t, b.locked)
	a := seal(t, b, text, sig)
	if err := finish(b.locked, a.GetAnswerText(), a.GetAnswerSignatureDer(), b.plan); err != nil {
		t.Fatalf("FinishPinRelease: %v", err)
	}
	j := captureJournal(t)
	for range 3 {
		_, err := b.locked.key.BeginPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{RequestId: newID(t)}))
		wantRefused(t, err, connect.CodeFailedPrecondition, "unlocked")
	}
	if n := j.count("DEBUG refused method=BeginPinRelease code=failed_precondition reason=unlocked"); n != 3 {
		t.Errorf("%d debug lines for the refusals of an unlocked driver, want 3: %q", n, j.logs)
	}
	if n := j.count("WARN"); n != 0 {
		t.Errorf("%d warnings for the poll of an unlocked driver: %q", n, j.logs)
	}
	// Another refusal of the same call is not the expected one and stays a warning.
	_, err := b.locked.key.BeginPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{RequestId: "not-a-uuid"}))
	wantRefused(t, err, connect.CodeInvalidArgument, "request_text")
	if n := j.count("WARN refused method=BeginPinRelease"); n != 1 {
		t.Errorf("%d warnings for a bad request id, want 1: %q", n, j.logs)
	}
}

// verifies: REQ-KEYS-115
// The pin-release key signs without the PIN, so the driver signs with it only the texts it writes itself: Sign refuses
// the purpose, locked or unlocked, and the request text names the driver's own boundary and node, whatever key@ asks.
// So a compromised key@ cannot have its card sign a request with an ephemeral key of its own.
func TestThePinReleaseKeySignsOnlyTheDriversOwnTexts(t *testing.T) {
	b := newBoundary(t)
	for _, r := range []running{b.locked, b.releaser} {
		_, err := sign(r.key, "pin-release", "ES384", digest384())
		wantRefused(t, err, connect.CodeInvalidArgument, "purpose")
	}
	text, sig := begin(t, b.locked)
	r, err := pinrelease.ParseRequest(text)
	if err != nil || r.Boundary != testBoundary || r.Node != lockedNode {
		t.Fatalf("request %+v, %v", r, err)
	}
	pub, err := x509.ParsePKIXPublicKey(ensure(t, b.locked.key, "pin-release", "ES384").GetSpkiDer())
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), pinrelease.Digest(text), sig) {
		t.Fatal("the request is not signed by the driver's pin-release key")
	}
	_, err = b.locked.key.BeginPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{RequestId: "not-a-uuid"}))
	wantRefused(t, err, connect.CodeInvalidArgument, "request_text")
}

// verifies: REQ-KEYS-115
// A compromised key@ of the unlocked board cannot have the PIN sealed to a key of its own: a request it signs with a
// key of its own, unsigned, signed by its own card (an answer's signature), or made in its own node's name, is
// refused; so is a genuine signature over another text.
func TestARequestNoListedPeerCardSignedIsNotSealed(t *testing.T) {
	b := newBoundary(t)
	text, sig := begin(t, b.locked)

	_, err := sealPin(b.releaser, text, signSoft(t, text), b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "signature")
	_, err = sealPin(b.releaser, text, nil, b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "signature")
	// The releaser's own card signs only answers: an answer's signature is no request's.
	a := seal(t, b, text, sig)
	_, err = sealPin(b.releaser, text, a.GetAnswerSignatureDer(), b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "signature")

	// A request in the releasing node's own name, with key@'s own ephemeral key.
	own, err := pinrelease.RequestText(pinrelease.Request{Boundary: testBoundary, Node: releaserNode, ID: newID(t), Ephemeral: newEphemeral(t)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sealPin(b.releaser, own, signSoft(t, own), b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "peer")

	// The text that is verified is the text that is sealed to: a genuine signature over another text does not carry.
	forged, err := pinrelease.RequestText(pinrelease.Request{Boundary: testBoundary, Node: lockedNode, ID: newID(t), Ephemeral: newEphemeral(t)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sealPin(b.releaser, forged, sig, b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "signature")
}

// verifies: REQ-KEYS-115
// A request from a node that the verified slot map does not list is refused, though a genuine card of the boundary
// signed it.
func TestARequestFromANodeNotInTheSlotMapIsRefused(t *testing.T) {
	b := newBoundary(t)
	text, sig := begin(t, b.locked)
	only := b.signPlan(t, 2, b.entry(t, releaserNode, b.releaser))
	_, err := sealPin(b.releaser, text, sig, only)
	wantRefused(t, err, connect.CodeFailedPrecondition, "peer")

	empty := b.signPlan(t, 3)
	_, err = sealPin(b.releaser, text, sig, empty)
	wantRefused(t, err, connect.CodeFailedPrecondition, "peer")
}

// verifies: REQ-KEYS-115
// A request of another boundary is refused, though the card that signed it is listed: a driver configured for another
// boundary writes that boundary into its request.
func TestARequestOfAnotherBoundaryIsRefused(t *testing.T) {
	b := newBoundary(t)
	c := cardtest.New()
	c.PKI = b.releaser.card
	other := startOpts(t, c, driver.Development, "key", self(), driver.Options{Node: "node-o", Boundary: "other", Publishers: b.publishers})
	plan := b.signPlan(t, 2, b.entry(t, releaserNode, b.releaser), b.entry(t, "node-o", other))
	text, sig := begin(t, other)
	if r, err := pinrelease.ParseRequest(text); err != nil || r.Boundary != "other" {
		t.Fatalf("request %+v, %v", r, err)
	}
	_, err := sealPin(b.releaser, text, sig, plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "boundary")
}

// verifies: REQ-KEYS-115
// The driver verifies the KeyPlan itself: a KeyPlan signed by another key, for another kind, a lower seq than one it
// verified (also after a restart, from its mark), or another payload under that seq, is refused.
func TestTheDriverVerifiesTheKeyPlanAndItsSeq(t *testing.T) {
	b := newBoundary(t)
	both := []entry{b.entry(t, releaserNode, b.releaser), b.entry(t, lockedNode, b.locked)}
	text, sig := begin(t, b.locked)

	stranger, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string][]byte{
		"another key":  signPlanWith(t, stranger, 5, "KeyPlan", both...),
		"another kind": signPlanWith(t, b.publisher, 5, "Boundary", both...),
		"no document":  nil,
		"not a JWS":    []byte("{}"),
	} {
		_, err := sealPin(b.releaser, text, sig, doc)
		wantRefusedReason(t, name, err, "key_plan")
	}

	if _, err := sealPin(b.releaser, text, sig, b.signPlan(t, 2, both...)); err != nil {
		t.Fatalf("seq 2: %v", err)
	}
	_, err = sealPin(b.releaser, text, sig, b.plan) // seq 1
	wantRefused(t, err, connect.CodeFailedPrecondition, "key_plan")
	_, err = sealPin(b.releaser, text, sig, b.signPlan(t, 2, both[1])) // seq 2, another payload
	wantRefused(t, err, connect.CodeFailedPrecondition, "key_plan")

	fi, err := os.Stat(filepath.Join(b.releaserState, "keyplan.mark"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the mark: %v %v", fi, err)
	}
	// A driver started on the same state takes the mark: seq 1 is refused from its first call.
	c := cardtest.New()
	c.PKI = b.releaser.card
	again := startOpts(t, c, driver.Development, "key", self(), driver.Options{Node: releaserNode, Publishers: b.publishers, StateDir: b.releaserState})
	again.unlock(t, "123456")
	_, err = sealPin(again, text, sig, b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "key_plan")

	// A driver without publisher keys verifies no KeyPlan and releases nothing.
	none := startOpts(t, cardtest.New(), driver.Development, "key", self(), driver.Options{Node: releaserNode})
	none.unlock(t, "123456")
	_, err = sealPin(none, text, sig, b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "key_plan")
}

func wantRefusedReason(t *testing.T, name string, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: taken, want a refusal %q", name, reason)
	}
	if got, _ := refusal.Reason(err); got != reason {
		t.Fatalf("%s: reason %q, want %q (%v)", name, got, reason, err)
	}
}

// verifies: REQ-KEYS-114, REQ-KEYS-115
// A compromised key@ of the locked board cannot spend the card's PIN tries: an answer that is unsigned, signed by a key
// of its own or by its own card (its request's signature), tampered with, in its own name, for another request, from
// a releaser the KeyPlan does not list, or under an older KeyPlan is refused before anything is opened, and the card
// is sent no PIN. The one-time key stays, so the true answer still unlocks it.
func TestAnAnswerNoListedPeerCardSignedIsNoPINAttempt(t *testing.T) {
	b := newBoundary(t)
	old, oldSig := begin(t, b.locked)
	oldAnswer := seal(t, b, old, oldSig)
	text, sig := begin(t, b.locked) // a new request replaces the one-time key of the old one
	a := seal(t, b, text, sig)
	at, asig := a.GetAnswerText(), a.GetAnswerSignatureDer()
	ans, err := pinrelease.ParseAnswer(at)
	if err != nil {
		t.Fatal(err)
	}
	tamperedAnswer := ans
	tamperedAnswer.Sealed = append([]byte(nil), ans.Sealed...)
	tamperedAnswer.Sealed[len(tamperedAnswer.Sealed)-1] ^= 1
	tampered, err := pinrelease.AnswerText(tamperedAnswer)
	if err != nil {
		t.Fatal(err)
	}
	selfAnswer := ans
	selfAnswer.Releaser = lockedNode
	inOwnName, err := pinrelease.AnswerText(selfAnswer)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		at     []byte
		sig    []byte
		plan   []byte
		reason string
	}{
		{"unsigned", at, nil, b.plan, "signature"},
		{"signed by key@'s own key", at, signSoft(t, at), b.plan, "signature"},
		{"signed by the requester's own card", at, sig, b.plan, "signature"},
		{"tampered with", tampered, asig, b.plan, "signature"},
		{"in the requester's own name", inOwnName, signSoft(t, inOwnName), b.plan, "peer"},
		{"for the old request", oldAnswer.GetAnswerText(), oldAnswer.GetAnswerSignatureDer(), b.plan, "answer_text"},
		{"from a releaser the KeyPlan does not list", at, asig, b.signPlan(t, 2, b.entry(t, lockedNode, b.locked)), "peer"},
		{"under an older KeyPlan", at, asig, b.plan, "key_plan"},
	}
	for _, c := range cases {
		err := finish(b.locked, c.at, c.sig, c.plan)
		wantRefusedReason(t, c.name, err, c.reason)
		if b.locked.card.LoginAttempts != 0 {
			t.Fatalf("%s: %d PIN attempts, want 0", c.name, b.locked.card.LoginAttempts)
		}
	}
	plan3 := b.signPlan(t, 3, b.entry(t, releaserNode, b.releaser), b.entry(t, lockedNode, b.locked))
	if err := finish(b.locked, at, asig, plan3); err != nil {
		t.Fatalf("FinishPinRelease: %v", err)
	}
	if b.locked.card.LoginAttempts != 1 {
		t.Fatalf("%d PIN attempts, want 1", b.locked.card.LoginAttempts)
	}
}

// verifies: REQ-KEYS-059
// A released PIN that the card refuses stops the PIN release in the driver, durably: no request is made and no answer
// is sent to the card, after a restart of the driver too, until a person unlocks the board on the admin socket.
func TestARefusedReleasedPINStopsTheReleaseAcrossARestart(t *testing.T) {
	b := newBoundary(t)
	// The locked card takes another PIN than the boundary's, as a card set up apart would.
	c := cardtest.New()
	c.SerialNo = 11223344
	c.PKI = b.releaser.card
	c.PIN = "654321"
	state := stateDir(t)
	opts := driver.Options{Node: lockedNode, Publishers: b.publishers, StateDir: state}
	locked := startOpts(t, c, driver.Development, "key", self(), opts)
	plan := b.signPlan(t, 2, b.entry(t, releaserNode, b.releaser), b.entry(t, lockedNode, locked))

	text, sig := begin(t, locked)
	a, err := sealPin(b.releaser, text, sig, plan)
	if err != nil {
		t.Fatalf("SealPin: %v", err)
	}
	wantRefused(t, finish(locked, a.GetAnswerText(), a.GetAnswerSignatureDer(), plan), connect.CodePermissionDenied, "pin")
	if c.LoginAttempts != 1 {
		t.Fatalf("%d PIN attempts, want 1", c.LoginAttempts)
	}
	wantStopped := func(r running) {
		t.Helper()
		_, err := r.key.BeginPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{RequestId: newID(t)}))
		wantRefused(t, err, connect.CodeFailedPrecondition, "pin_refused")
		wantRefused(t, finish(r, a.GetAnswerText(), a.GetAnswerSignatureDer(), plan), connect.CodeFailedPrecondition, "pin_refused")
	}
	wantStopped(locked)
	if _, err := os.Stat(filepath.Join(state, "pin-release.refused")); err != nil {
		t.Fatalf("the stop is not in the state directory: %v", err)
	}

	// A restart: a new driver on the same state directory makes no request and tries no released PIN either.
	c2 := cardtest.New()
	c2.SerialNo = 55667788
	c2.PKI = b.releaser.card
	again := startOpts(t, c2, driver.Development, "key", self(), opts)
	wantStopped(again)
	if c.LoginAttempts+c2.LoginAttempts != 1 {
		t.Fatalf("%d PIN attempts in all, want 1", c.LoginAttempts+c2.LoginAttempts)
	}
	// A person unlocks the board: the stop is gone.
	again.unlock(t, "123456")
	if _, err := os.Stat(filepath.Join(state, "pin-release.refused")); !os.IsNotExist(err) {
		t.Fatalf("the stop outlived the unlock: %v", err)
	}
}

// verifies: REQ-KEYS-059
// A stop that cannot be saved fails closed: the driver exits non-zero, to be started again by systemd, and a driver
// cannot start on a state directory it cannot write, so no restart forgets the stop.
func TestAStopThatCannotBeSavedEndsTheDriver(t *testing.T) {
	b := newBoundary(t)
	c := cardtest.New()
	c.SerialNo = 11223344
	c.PKI = b.releaser.card
	c.PIN = "654321"
	state := stateDir(t)
	locked, res := startRun(t, c, driver.Development, "key", self(), driver.Options{Node: lockedNode, Publishers: b.publishers, StateDir: state}, false)
	plan := b.signPlan(t, 2, b.entry(t, releaserNode, b.releaser), b.entry(t, lockedNode, locked))
	text, sig := begin(t, locked)
	a, err := sealPin(b.releaser, text, sig, plan)
	if err != nil {
		t.Fatalf("SealPin: %v", err)
	}
	// The driver takes the KeyPlan first (an unsigned answer is refused after the KeyPlan is verified and marked), so
	// that the only write left is the stop.
	wantRefused(t, finish(locked, a.GetAnswerText(), nil, plan), connect.CodeFailedPrecondition, "signature")
	// The state directory goes away under the driver: a file stands at its path, which no user can write into.
	if err := os.Rename(state, state+".gone"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, finish(locked, a.GetAnswerText(), a.GetAnswerSignatureDer(), plan), connect.CodePermissionDenied, "pin")
	select {
	case <-res.finished:
		if res.err == nil || !strings.Contains(res.err.Error(), "stop cannot be saved") {
			t.Fatalf("Run ended with %v", res.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the driver did not exit")
	}
	if c.LoginAttempts != 1 {
		t.Fatalf("%d PIN attempts, want 1", c.LoginAttempts)
	}
}

func TestADriverDoesNotStartOnAStateDirectoryItCannotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("SKIP: root writes into a directory of mode 0500; TestAStopThatCannotBeSavedEndsTheDriver covers the exit")
	}
	state := stateDir(t)
	if err := os.Chmod(state, 0o500); err != nil { //nolint:gosec // a directory, read and search only
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(state, 0o700) }) //nolint:gosec // a directory, back to the mode of a state directory
	c := cardtest.New()
	if _, err := driver.New(driver.Options{Environment: driver.Development, Node: lockedNode, StateDir: state, Serial: c.SerialNo, Open: c.Opener()}); err == nil ||
		!strings.Contains(err.Error(), "cannot be written") {
		t.Fatalf("New on an unwritable state directory: %v", err)
	}
}

// The released PIN reaches the card through the same floor as an unlock: a card with one attempt left is not sent it.
func TestAReleaseIsNotTriedOnACardWithOneAttemptLeft(t *testing.T) {
	b := newBoundary(t)
	b.locked.card.Retries = 1
	text, sig := begin(t, b.locked)
	a := seal(t, b, text, sig)
	wantRefused(t, finish(b.locked, a.GetAnswerText(), a.GetAnswerSignatureDer(), b.plan), connect.CodeFailedPrecondition, "pin_retries")
	if b.locked.card.LoginAttempts != 0 {
		t.Fatal("a PIN was sent to a card with one attempt left")
	}
}

func TestALockedDriverSealsNothingAndAnIdleOneFinishesNothing(t *testing.T) {
	b := newBoundary(t)
	text, sig := begin(t, b.locked)
	_, err := sealPin(b.locked, text, sig, b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "locked")
	_, err = sealPin(b.releaser, []byte("x"), nil, b.plan)
	wantRefused(t, err, connect.CodeInvalidArgument, "request_text")
	// No request in flight: an answer finds no one-time key.
	idle := startOpts(t, cardtest.New(), driver.Development, "key", self(), driver.Options{Node: lockedNode, Publishers: b.publishers})
	a := seal(t, b, text, sig)
	wantRefused(t, finish(idle, a.GetAnswerText(), a.GetAnswerSignatureDer(), b.plan), connect.CodeFailedPrecondition, "one_time_key")
}

// The attestation of a peer's slot 87 is read through the driver: the key, the slot and the policies the card states.
func TestAPeersAttestationIsVerifiedByTheDriver(t *testing.T) {
	b := newBoundary(t)
	releaser, locked := b.releaser, b.locked
	att, err := locked.key.Attest(context.Background(), connect.NewRequest(&keystorev2alpha1.AttestRequest{Purpose: "pin-release"}))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	res, err := releaser.key.VerifyAttestation(context.Background(), connect.NewRequest(&keystorev2alpha1.VerifyAttestationRequest{
		Attestation: att.Msg.GetAttestation(), AttestationSigner: att.Msg.GetAttestationSigner(),
	}))
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
	pub := ensure(t, locked.key, "pin-release", "ES384").GetSpkiDer()
	if m := res.Msg; m.GetSlot() != "87" || m.GetPinPolicy() != "never" || m.GetTouchPolicy() != "never" || m.GetSerial() != 87654321 || string(m.GetSpkiDer()) != string(pub) {
		t.Fatalf("read %v", m)
	}
}

func TestAnAttestationOfAnotherPKIIsRefused(t *testing.T) {
	releaser := newBoundary(t).releaser
	stranger := cardtest.New() // its own TEST ONLY root
	if _, err := stranger.PutKey(0x87, card.KeySpec{Algorithm: card.EC384, PIN: card.PINNever, Touch: card.TouchNever}); err != nil {
		t.Fatal(err)
	}
	c, err := stranger.Opener()(0)
	if err != nil {
		t.Fatal(err)
	}
	slotCert, err := c.Attest(0x87)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := c.AttestationCertificate()
	if err != nil {
		t.Fatal(err)
	}
	_, err = releaser.key.VerifyAttestation(context.Background(), connect.NewRequest(&keystorev2alpha1.VerifyAttestationRequest{
		Attestation: slotCert.Raw, AttestationSigner: signer.Raw,
	}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "attestation")
}

func newID(t *testing.T) string {
	t.Helper()
	id, err := pinrelease.NewID(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// verifies: REQ-KEYS-115
// No answer of the key-store port carries a PIN: the port that key@ reaches has no field that could return one, so the
// PIN stays in the driver. The admin socket's Unlock takes one in, and is not part of this port.
func TestNoAnswerOfTheKeyStorePortCarriesAPIN(t *testing.T) {
	svc := keystorev2alpha1.File_sluis_port_keystore_v2alpha1_keystore_proto.Services().ByName("KeyStoreService")
	if svc == nil || svc.Methods().Len() < 10 {
		t.Fatal("the KeyStoreService and its PIN release calls are not in the descriptor")
	}
	seen := map[protoreflect.FullName]bool{}
	var walk func(m protoreflect.MessageDescriptor)
	walk = func(m protoreflect.MessageDescriptor) {
		if seen[m.FullName()] {
			return
		}
		seen[m.FullName()] = true
		for i := 0; i < m.Fields().Len(); i++ {
			f := m.Fields().Get(i)
			if n := string(f.Name()); n == "pin" || strings.HasSuffix(n, "_pin") || strings.HasPrefix(n, "pin_") && !strings.HasSuffix(n, "_policy") && !strings.HasSuffix(n, "_retries") {
				t.Errorf("%s.%s could carry a PIN", m.FullName(), n)
			}
			if f.Message() != nil {
				walk(f.Message())
			}
		}
	}
	for i := 0; i < svc.Methods().Len(); i++ {
		walk(svc.Methods().Get(i).Output())
	}
}
