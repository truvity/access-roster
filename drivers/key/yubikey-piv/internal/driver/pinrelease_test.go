//go:build sluis_test

package driver_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// begin makes the locked driver's one-time key and the request text, as key@ asks for them.
func begin(t *testing.T, r running) []byte {
	t.Helper()
	res, err := r.key.BeginPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{RequestId: newID(t)}))
	if err != nil {
		t.Fatalf("BeginPinRelease: %v", err)
	}
	return res.Msg.GetRequestText()
}

// signPin signs a text with a driver's pin-release key, slot 87, as key@ does; it signs whether or not the driver is
// locked.
func signPin(t *testing.T, r running, text []byte) []byte {
	t.Helper()
	res, err := sign(r.key, "pin-release", "ES384", pinrelease.Digest(text))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return res.GetSignatureDer()
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

func seal(t *testing.T, b *boundary, text []byte) *keystorev2alpha1.SealPinResponse {
	t.Helper()
	res, err := sealPin(b.releaser, text, signPin(t, b.locked, text), b.plan)
	if err != nil {
		t.Fatalf("SealPin: %v", err)
	}
	return res
}

// answerText is the answer of a releaser to a request, unsigned.
func answerText(t *testing.T, releaser string, text []byte, s *keystorev2alpha1.SealPinResponse) []byte {
	t.Helper()
	r, err := pinrelease.ParseRequest(text)
	if err != nil {
		t.Fatal(err)
	}
	at, err := pinrelease.AnswerText(pinrelease.Answer{
		Boundary: r.Boundary, Releaser: releaser, Requester: r.Node, ID: r.ID, RequestSHA384: pinrelease.Digest(text),
		Ephemeral: s.GetReleaserPublic(), Sealed: s.GetSealed(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func finish(r running, at, sig, plan []byte) error {
	_, err := r.key.FinishPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.FinishPinReleaseRequest{
		AnswerText: at, AnswerSignatureDer: sig, KeyPlan: plan,
	}))
	return err
}

// verifies: REQ-KEYS-059, REQ-KEYS-115
// The happy path at the drivers: the unlocked driver verifies the KeyPlan and the request and seals the PIN it holds
// to the locked driver's one-time key; the locked driver verifies the KeyPlan and the answer, opens it and gives it to
// its card once. Then it signs with a PIN-once key.
func TestALockedDriverIsUnlockedByAPeersRelease(t *testing.T) {
	b := newBoundary(t)
	text := begin(t, b.locked)
	at := answerText(t, releaserNode, text, seal(t, b, text))
	if err := finish(b.locked, at, signPin(t, b.releaser, at), b.plan); err != nil {
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
	_, err := b.locked.key.BeginPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{RequestId: newID(t)}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "unlocked")
}

// verifies: REQ-KEYS-115
// A compromised key@ of the unlocked board cannot have the PIN sealed to a key of its own: a request it signs with a
// key of its own, or with its own card's pin-release key, for the peer or in its own node's name, is refused.
func TestARequestNoListedPeerCardSignedIsNotSealed(t *testing.T) {
	b := newBoundary(t)
	text := begin(t, b.locked)

	_, err := sealPin(b.releaser, text, signSoft(t, text), b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "signature")
	_, err = sealPin(b.releaser, text, nil, b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "signature")
	// The releaser's own card signs anything key@ asks, but it is not the requesting node's key.
	_, err = sealPin(b.releaser, text, signPin(t, b.releaser, text), b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "signature")

	// A request of key@'s own: its own ephemeral key, in the releasing node's own name, signed by its own card.
	eph, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	own, err := pinrelease.RequestText(pinrelease.Request{Boundary: testBoundary, Node: releaserNode, ID: newID(t), Ephemeral: eph.PublicKey().Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sealPin(b.releaser, own, signPin(t, b.releaser, own), b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "peer")

	// The text that is verified is the text that is sealed to: a valid signature over another text does not carry.
	forged, err := pinrelease.RequestText(pinrelease.Request{Boundary: testBoundary, Node: lockedNode, ID: newID(t), Ephemeral: eph.PublicKey().Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sealPin(b.releaser, forged, signPin(t, b.locked, text), b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "signature")
}

// verifies: REQ-KEYS-115
// A request from a node that the verified slot map does not list is refused, even signed by a genuine card of the
// boundary.
func TestARequestFromANodeNotInTheSlotMapIsRefused(t *testing.T) {
	b := newBoundary(t)
	text := begin(t, b.locked)
	only := b.signPlan(t, 2, b.entry(t, releaserNode, b.releaser))
	_, err := sealPin(b.releaser, text, signPin(t, b.locked, text), only)
	wantRefused(t, err, connect.CodeFailedPrecondition, "peer")

	empty := b.signPlan(t, 3)
	_, err = sealPin(b.releaser, text, signPin(t, b.locked, text), empty)
	wantRefused(t, err, connect.CodeFailedPrecondition, "peer")
}

// verifies: REQ-KEYS-115
// A request of another boundary is refused, signed by a listed peer's card or not.
func TestARequestOfAnotherBoundaryIsRefused(t *testing.T) {
	b := newBoundary(t)
	eph, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	text, err := pinrelease.RequestText(pinrelease.Request{Boundary: "other", Node: lockedNode, ID: newID(t), Ephemeral: eph.PublicKey().Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sealPin(b.releaser, text, signPin(t, b.locked, text), b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "boundary")
}

// verifies: REQ-KEYS-115
// The driver verifies the KeyPlan itself: a KeyPlan signed by another key, for another kind, a lower seq than one it
// verified (also after a restart, from its mark), or another payload under that seq, is refused.
func TestTheDriverVerifiesTheKeyPlanAndItsSeq(t *testing.T) {
	b := newBoundary(t)
	both := []entry{b.entry(t, releaserNode, b.releaser), b.entry(t, lockedNode, b.locked)}
	text := begin(t, b.locked)
	sig := signPin(t, b.locked, text)

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
// of its own, by its own card, in its own name, for another request or under an older KeyPlan is refused before
// anything is opened, and the card is sent no PIN. The one-time key stays, so the true answer still unlocks it.
func TestAnAnswerNoListedPeerCardSignedIsNoPINAttempt(t *testing.T) {
	b := newBoundary(t)
	old := begin(t, b.locked)
	oldAnswer := answerText(t, releaserNode, old, seal(t, b, old))
	text := begin(t, b.locked) // a new request replaces the one-time key of the old one
	sealed := seal(t, b, text)
	at := answerText(t, releaserNode, text, sealed)

	cases := []struct {
		name   string
		at     []byte
		sig    []byte
		plan   []byte
		reason string
	}{
		{"unsigned", at, nil, b.plan, "signature"},
		{"signed by key@'s own key", at, signSoft(t, at), b.plan, "signature"},
		{"signed by the requester's own card", at, signPin(t, b.locked, at), b.plan, "signature"},
		{"in the requester's own name", answerText(t, lockedNode, text, sealed), signPin(t, b.locked, answerText(t, lockedNode, text, sealed)), b.plan, "peer"},
		{"for the old request", oldAnswer, signPin(t, b.releaser, oldAnswer), b.plan, "answer_text"},
		{"under a releaser the KeyPlan does not list", at, signPin(t, b.releaser, at), b.signPlan(t, 2, b.entry(t, lockedNode, b.locked)), "peer"},
		{"under an older KeyPlan", at, signPin(t, b.releaser, at), b.plan, "key_plan"},
	}
	for _, c := range cases {
		err := finish(b.locked, c.at, c.sig, c.plan)
		wantRefusedReason(t, c.name, err, c.reason)
		if b.locked.card.LoginAttempts != 0 {
			t.Fatalf("%s: %d PIN attempts, want 0", c.name, b.locked.card.LoginAttempts)
		}
	}
	plan2 := b.signPlan(t, 3, b.entry(t, releaserNode, b.releaser), b.entry(t, lockedNode, b.locked))
	if err := finish(b.locked, at, signPin(t, b.releaser, at), plan2); err != nil {
		t.Fatalf("FinishPinRelease: %v", err)
	}
	if b.locked.card.LoginAttempts != 1 {
		t.Fatalf("%d PIN attempts, want 1", b.locked.card.LoginAttempts)
	}
}

// verifies: REQ-KEYS-059
// A signed answer whose sealed PIN does not open (a releaser that signs what it should not) is no PIN attempt, and
// uses the one-time key: a second try finds none.
func TestASignedAnswerThatDoesNotOpenIsNoPINAttempt(t *testing.T) {
	b := newBoundary(t)
	text := begin(t, b.locked)
	s := seal(t, b, text)
	s.Sealed[len(s.Sealed)-1] ^= 1
	at := answerText(t, releaserNode, text, s)
	err := finish(b.locked, at, signPin(t, b.releaser, at), b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "sealed")
	err = finish(b.locked, at, signPin(t, b.releaser, at), b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "one_time_key")
	if b.locked.card.LoginAttempts != 0 {
		t.Fatal("a release that does not open reached the card")
	}
}

func TestALockedDriverSealsNothingAndBeginNeedsAnID(t *testing.T) {
	b := newBoundary(t)
	text := begin(t, b.locked)
	_, err := sealPin(b.locked, text, signPin(t, b.releaser, text), b.plan)
	wantRefused(t, err, connect.CodeFailedPrecondition, "locked")
	_, err = sealPin(b.releaser, []byte("x"), nil, b.plan)
	wantRefused(t, err, connect.CodeInvalidArgument, "request_text")
	_, err = b.locked.key.BeginPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{RequestId: "not-a-uuid"}))
	wantRefused(t, err, connect.CodeInvalidArgument, "request_text")
	// The text is the driver's: its own boundary and node.
	r, err := pinrelease.ParseRequest(text)
	if err != nil || r.Boundary != testBoundary || r.Node != lockedNode {
		t.Fatalf("request %+v, %v", r, err)
	}
	// No request in flight: an answer finds no one-time key.
	idle := startOpts(t, cardtest.New(), driver.Development, "key", self(), driver.Options{Node: lockedNode, Publishers: b.publishers})
	at := answerText(t, releaserNode, text, seal(t, b, text))
	wantRefused(t, finish(idle, at, signPin(t, b.releaser, at), b.plan), connect.CodeFailedPrecondition, "one_time_key")
}

// The released PIN reaches the card through the same floor as an unlock: a card with one attempt left is not sent it.
func TestAReleaseIsNotTriedOnACardWithOneAttemptLeft(t *testing.T) {
	b := newBoundary(t)
	locked := b.locked
	locked.card.Retries = 1
	text := begin(t, locked)
	at := answerText(t, releaserNode, text, seal(t, b, text))
	wantRefused(t, finish(locked, at, signPin(t, b.releaser, at), b.plan), connect.CodeFailedPrecondition, "pin_retries")
	if locked.card.LoginAttempts != 0 {
		t.Fatal("a PIN was sent to a card with one attempt left")
	}
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
