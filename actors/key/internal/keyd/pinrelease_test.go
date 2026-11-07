//go:build sluis_test

package keyd

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/pinrelease"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// The fake driver's side of the PIN release: the same calls as the card driver, over a PIN in memory, and an
// attestation that is a JSON of what a card would state, signed by nothing (the card driver's own tests verify real
// chains on the cards of cardtest). The PIN is the factory default of a test card.

const fakeSigner = "fake attestation signer"

type fakeAttestation struct {
	SPKI  []byte `json:"spki"`
	Slot  string `json:"slot"`
	PIN   string `json:"pin"`
	Touch string `json:"touch"`
}

func (d *fakeDriver) isLocked() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.locked
}

func (d *fakeDriver) Attest(_ context.Context, req *connect.Request[keystorev2alpha1.AttestRequest]) (*connect.Response[keystorev2alpha1.AttestResponse], error) {
	if req.Msg.GetPurpose() != "pin-release" {
		return nil, refusal.New(connect.CodeFailedPrecondition, "no_attestation", "")
	}
	k, err := d.key("pin-release")
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	a := fakeAttestation{SPKI: spki, Slot: "87", PIN: "never", Touch: "never"}
	if d.attestLie {
		a.PIN = "once"
	}
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&keystorev2alpha1.AttestResponse{Attestation: b, AttestationSigner: []byte(fakeSigner)}), nil
}

func (d *fakeDriver) VerifyAttestation(_ context.Context, req *connect.Request[keystorev2alpha1.VerifyAttestationRequest]) (*connect.Response[keystorev2alpha1.VerifyAttestationResponse], error) {
	d.verifyCalls.Add(1)
	var a fakeAttestation
	if string(req.Msg.GetAttestationSigner()) != fakeSigner || json.Unmarshal(req.Msg.GetAttestation(), &a) != nil {
		return nil, refusal.New(connect.CodeFailedPrecondition, "attestation", "attestation")
	}
	return connect.NewResponse(&keystorev2alpha1.VerifyAttestationResponse{SpkiDer: a.SPKI, Slot: a.Slot, PinPolicy: a.PIN, TouchPolicy: a.Touch}), nil
}

func (d *fakeDriver) BeginPinRelease(_ context.Context, req *connect.Request[keystorev2alpha1.BeginPinReleaseRequest]) (*connect.Response[keystorev2alpha1.BeginPinReleaseResponse], error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.locked {
		return nil, refusal.New(connect.CodeFailedPrecondition, "unlocked", "")
	}
	k, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	text, err := pinrelease.RequestText(pinrelease.Request{Boundary: d.boundary, Node: d.node, ID: req.Msg.GetRequestId(), Ephemeral: k.PublicKey().Bytes()})
	if err != nil {
		return nil, refusal.New(connect.CodeInvalidArgument, "request_text", "request_id")
	}
	sig, err := d.signPin(text)
	if err != nil {
		return nil, err
	}
	d.oneTime, d.oneText = k, text
	return connect.NewResponse(&keystorev2alpha1.BeginPinReleaseResponse{EphemeralPublic: k.PublicKey().Bytes(), RequestText: text, RequestSignatureDer: sig}), nil
}

// signPin signs a text the fake wrote with its pin-release key, as the card driver does. The caller holds mu.
func (d *fakeDriver) signPin(text []byte) ([]byte, error) {
	k, ok := d.keys["pin-release"]
	if !ok {
		return nil, refusal.New(connect.CodeNotFound, "absent", "")
	}
	return ecdsa.SignASN1(rand.Reader, k, pinrelease.Digest(text))
}

// The fake verifies nothing (the card driver's own tests do): it checks only that key@ hands it a signature and the
// KeyPlan document, and refuses as the card driver's check does when refuseCheck is set.
func (d *fakeDriver) checked(sig, keyPlan []byte) error {
	if d.refuseCheck != "" {
		return refusal.New(connect.CodeFailedPrecondition, d.refuseCheck, "")
	}
	if len(sig) == 0 || len(keyPlan) == 0 {
		return refusal.New(connect.CodeFailedPrecondition, "key_plan", "key_plan")
	}
	return nil
}

func (d *fakeDriver) SealPin(_ context.Context, req *connect.Request[keystorev2alpha1.SealPinRequest]) (*connect.Response[keystorev2alpha1.SealPinResponse], error) {
	d.sealCalls.Add(1)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.locked || d.held == nil {
		return nil, refusal.New(connect.CodeFailedPrecondition, "locked", "")
	}
	if err := d.checked(req.Msg.GetRequestSignatureDer(), req.Msg.GetKeyPlan()); err != nil {
		return nil, err
	}
	text := req.Msg.GetRequestText()
	r, err := pinrelease.ParseRequest(text)
	if err != nil {
		return nil, refusal.New(connect.CodeInvalidArgument, "request_text", "request_text")
	}
	pub, sealed, err := pinrelease.Seal(d.held, text)
	if err != nil {
		return nil, refusal.New(connect.CodeInvalidArgument, "request_text", "request_text")
	}
	at, err := pinrelease.AnswerText(pinrelease.Answer{Boundary: d.boundary, Releaser: d.node, Requester: r.Node, ID: r.ID,
		RequestSHA384: pinrelease.Digest(text), Ephemeral: pub, Sealed: sealed})
	if err != nil {
		return nil, err
	}
	sig, err := d.signPin(at)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&keystorev2alpha1.SealPinResponse{AnswerText: at, AnswerSignatureDer: sig}), nil
}

func (d *fakeDriver) FinishPinRelease(_ context.Context, req *connect.Request[keystorev2alpha1.FinishPinReleaseRequest]) (*connect.Response[keystorev2alpha1.FinishPinReleaseResponse], error) {
	d.finishCalls.Add(1)
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.locked {
		return nil, refusal.New(connect.CodeFailedPrecondition, "unlocked", "")
	}
	if err := d.checked(req.Msg.GetAnswerSignatureDer(), req.Msg.GetKeyPlan()); err != nil {
		return nil, err
	}
	a, err := pinrelease.ParseAnswer(req.Msg.GetAnswerText())
	if err != nil {
		return nil, refusal.New(connect.CodeInvalidArgument, "answer_text", "answer_text")
	}
	k, text := d.oneTime, d.oneText
	d.oneTime, d.oneText = nil, nil
	if k == nil {
		return nil, refusal.New(connect.CodeFailedPrecondition, "one_time_key", "")
	}
	pin, err := pinrelease.Open(k, text, a.Ephemeral, a.Sealed)
	if err != nil {
		return nil, refusal.New(connect.CodeFailedPrecondition, "sealed", "sealed")
	}
	d.pinTries.Add(1)
	if string(pin) != d.cardPIN {
		return nil, refusal.New(connect.CodePermissionDenied, "pin", "pin")
	}
	d.locked, d.held = false, pin
	return connect.NewResponse(&keystorev2alpha1.FinishPinReleaseResponse{}), nil
}

// board is one board of the PIN release tests: its driver and its key@.
type board struct {
	name string
	d    *fakeDriver
	n    *node
}

func ensureKey(t *testing.T, d *fakeDriver, purpose, alg string) []byte {
	t.Helper()
	res, err := d.Ensure(context.Background(), connect.NewRequest(&keystorev2alpha1.EnsureRequest{Purpose: purpose, Algorithm: alg}))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg.GetSpkiDer()
}

// slotMapOf is the slot map entry of a board's driver, as its key@'s check prints it.
func slotMapOf(t *testing.T, name string, d *fakeDriver) *configv2alpha1.NodeSlotMap {
	t.Helper()
	ensureKey(t, d, "pin-release", "ES384")
	att, err := d.Attest(context.Background(), connect.NewRequest(&keystorev2alpha1.AttestRequest{Purpose: "pin-release"}))
	if err != nil {
		t.Fatal(err)
	}
	return &configv2alpha1.NodeSlotMap{Node: name, Slots: []*configv2alpha1.SlotKey{
		{Slot: "9d", Purpose: "wrapping", PublicKey: ensureKey(t, d, "wrapping", "ECDH-P384")},
		{Slot: "87", Purpose: "pin-release", PublicKey: ensureKey(t, d, "pin-release", "ES384"),
			Attestation: att.Msg.GetAttestation(), AttestationSigner: att.Msg.GetAttestationSigner()},
	}}
}

// boards makes a boundary of boards: the first unlocked, the others locked, all with the factory PIN of a test card.
// The KeyPlan names the pin-release purpose and lists every board in the slot map; edit changes it before it is
// signed. The key@ are made and initialised, not served.
func boards(t *testing.T, names []string, edit func(*configv2alpha1.KeyPlan)) (*testEnv, []*board) {
	t.Helper()
	e := newTestEnv(t, "development")
	var out []*board
	plan := defaultPlan()
	plan.Purposes = append(plan.Purposes, &configv2alpha1.KeyPurposePlan{Purpose: "pin-release", Algorithm: "ES384", Slot: "87"})
	for i, name := range names {
		d := newFakeDriver("yubikey-piv")
		d.now = e.clock.now
		d.cardPIN = "123456"
		d.node, d.boundary = name, testBoundary
		if i == 0 {
			d.held = []byte("123456")
		} else {
			d.locked = true
		}
		plan.SlotMap = append(plan.SlotMap, slotMapOf(t, name, d))
		out = append(out, &board{name: name, d: d})
	}
	if edit != nil {
		edit(plan)
	}
	e.putPlan(plan)
	for _, b := range out {
		b.n = e.newNode(nodeOpts{name: b.name, driver: b.d})
		b.n.srv.cfg.PinReleaseScale = 0.01
		if err := b.n.srv.Init(context.Background()); err != nil {
			t.Fatalf("Init %s: %v", b.name, err)
		}
	}
	return e, out
}

// request writes a PinReleaseRequest of a board as its key@ would, at a time, for a boundary; it returns the id.
func request(t *testing.T, e *testEnv, b *board, boundary string, at time.Time) (string, []byte) {
	t.Helper()
	eph, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rid, err := pinrelease.NewID(at)
	if err != nil {
		t.Fatal(err)
	}
	r := pinrelease.Request{Boundary: boundary, Node: b.name, ID: rid, Ephemeral: eph.PublicKey().Bytes()}
	text, err := pinrelease.RequestText(r)
	if err != nil {
		t.Fatal(err)
	}
	id := b.name + "/" + r.ID
	e.store.put("pin-release-request", "", id, &keyv2alpha1.PinReleaseRequest{Text: text, SignatureDer: signWith(t, b.d, text)})
	return id, text
}

func signWith(t *testing.T, d *fakeDriver, text []byte) []byte {
	t.Helper()
	k, err := d.key("pin-release")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, k, pinrelease.Digest(text))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func answered(e *testEnv, id string) bool {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	return e.store.items["|pin-release|"+id] != nil
}

// refusedWhy is the reasons of the PIN release refusals that a node audited.
func refusedWhy(n *node) []string {
	var out []string
	for _, ev := range n.audit.all() {
		if ev.Action == ActionRefuse && ev.Reason == reasonPinRelease {
			out = append(out, fmtAny(ev.Fields["why"]))
		}
	}
	return out
}

func release(t *testing.T, b *board) {
	t.Helper()
	if _, err := b.n.srv.ReleasePins(context.Background()); err != nil {
		t.Fatalf("ReleasePins: %v", err)
	}
}

func wantWhy(t *testing.T, n *node, why string) {
	t.Helper()
	for _, w := range refusedWhy(n) {
		if w == why {
			return
		}
	}
	t.Fatalf("no refusal %q audited; got %v", why, refusedWhy(n))
}

// verifies: REQ-KEYS-059, REQ-KEYS-093
// The happy path, both sides served: a locked board asks, the unlocked peer verifies the request and seals its PIN to
// the request's one-time key, and the locked board verifies the signed answer, its driver opens it and its card takes
// the PIN once. Nothing crosses but the store.
func TestALockedBoardIsUnlockedByItsPeer(t *testing.T) {
	_, bs := boards(t, []string{"board-a", "board-b"}, nil)
	for _, b := range bs {
		b.n.start()
	}
	deadline := time.Now().Add(10 * time.Second)
	for bs[1].d.isLocked() {
		if time.Now().After(deadline) {
			t.Fatalf("board-b is still locked; refusals a=%v b=%v", refusedWhy(bs[0].n), refusedWhy(bs[1].n))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := bs[1].d.pinTries.Load(); got != 1 {
		t.Fatalf("%d PIN attempts, want 1", got)
	}
	if bs[0].n.audit.count(ActionPinRelease) != 1 {
		t.Fatalf("the releaser audited %d releases, want 1", bs[0].n.audit.count(ActionPinRelease))
	}
	// The unlock fact is emitted after the driver took the PIN; give the emit a moment.
	for bs[1].n.audit.count(ActionPinUnlock) != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if bs[1].n.audit.count(ActionPinUnlock) != 1 {
		t.Fatal("the unlocked board audited no unlock")
	}
	for _, ev := range append(bs[0].n.audit.all(), bs[1].n.audit.all()...) {
		if strings.Contains(fmtAny(ev.Fields), "123456") {
			t.Fatal("an audit fact holds the PIN")
		}
	}
}

// verifies: REQ-KEYS-059
// A request is answered once, with an answer that only the request's own one-time key opens.
func TestAVerifiedRequestIsAnsweredOnce(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b"}, nil)
	id, text := request(t, e, bs[1], testBoundary, e.clock.now())
	release(t, bs[0])
	if !answered(e, id) {
		t.Fatalf("not answered; refusals %v", refusedWhy(bs[0].n))
	}
	it, err := bs[1].n.srv.pinRels.Get(context.Background(), "", id)
	if err != nil {
		t.Fatal(err)
	}
	a, err := pinrelease.ParseAnswer(it.Value.GetText())
	if err != nil || a.Releaser != "board-a" || a.Requester != "board-b" || !bytes.Equal(a.RequestSHA384, pinrelease.Digest(text)) {
		t.Fatalf("answer %+v, %v", a, err)
	}
	k, _ := bs[0].d.key("pin-release")
	if !ecdsa.VerifyASN1(&k.PublicKey, pinrelease.Digest(it.Value.GetText()), it.Value.GetSignatureDer()) {
		t.Fatal("the answer is not signed by the releaser's pin-release key")
	}
	release(t, bs[0])
	if bs[0].n.audit.count(ActionPinRelease) != 1 {
		t.Fatal("a request was answered twice")
	}
}

// verifies: REQ-AUDIT-015
// A PIN is not released while the fact of its release cannot be made durable: the releaser asks for the fact with a
// blocking emit, the transport refuses, and no answer is written. Once the transport takes the fact, the same request
// is answered.
func TestAPinIsNotReleasedWhenItsAuditFactIsNotDurable(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b"}, nil)
	id, _ := request(t, e, bs[1], testBoundary, e.clock.now())
	bs[0].n.audit.mu.Lock()
	bs[0].n.audit.failing = true
	bs[0].n.audit.mu.Unlock()
	if _, err := bs[0].n.srv.ReleasePins(context.Background()); err == nil {
		t.Fatal("a release whose audit fact was refused reported success")
	}
	if answered(e, id) {
		t.Fatal("the PIN was released although its audit fact was refused")
	}
	var blocking int
	for _, ev := range bs[0].n.audit.all() {
		if ev.Action == ActionPinRelease && ev.Blocking {
			blocking++
		}
	}
	if blocking == 0 {
		t.Fatal("the release fact was not asked for with a blocking emit")
	}
	bs[0].n.audit.mu.Lock()
	bs[0].n.audit.failing = false
	bs[0].n.audit.mu.Unlock()
	release(t, bs[0])
	if !answered(e, id) {
		t.Fatalf("not answered once the transport took the fact; refusals %v", refusedWhy(bs[0].n))
	}
}

// verifies: REQ-KEYS-115
// key@ hands the card driver the request's signature and the KeyPlan document it verified, and a refusal of the
// driver's own check is a refused request: audited once, marked as decided, and never answered or retried.
func TestARequestTheCardDriverRefusesIsRefused(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b"}, nil)
	bs[0].d.refuseCheck = "signature"
	id, _ := request(t, e, bs[1], testBoundary, e.clock.now())
	release(t, bs[0])
	release(t, bs[0])
	if answered(e, id) {
		t.Fatal("a request the driver refused was answered")
	}
	wantWhy(t, bs[0].n, "driver-signature")
	if n := len(refusedWhy(bs[0].n)); n != 1 {
		t.Fatalf("%d refusals audited, want 1", n)
	}
	if bs[0].n.audit.count(ActionPinRelease) != 0 {
		t.Fatal("a release was audited")
	}
}

// verifies: REQ-KEYS-093
// A request for another boundary is refused and audited, and gets no answer.
func TestARequestOfAnotherBoundaryIsRefused(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b"}, nil)
	id, _ := request(t, e, bs[1], "staging", e.clock.now())
	release(t, bs[0])
	if answered(e, id) {
		t.Fatal("a request of another boundary was answered")
	}
	wantWhy(t, bs[0].n, "boundary")
}

// verifies: REQ-KEYS-093
// A board whose recipient, pin-release key or wrapping key is revoked gets no PIN; and a revocation that
// cannot be read refuses nothing and releases nothing (it fails closed and is tried again).
func TestARevokedBoardGetsNoPIN(t *testing.T) {
	for _, c := range []struct {
		name string
		id   func(b *board) string
	}{
		{"recipient", func(b *board) string { return "recipient/" + recipientLabel(b.d.wrappingID()) }},
		{"kid", func(b *board) string {
			pub, _ := parseP384(ensureKey(t, b.d, "pin-release", "ES384"))
			kid, _ := thumbprint(pub)
			return revocationID(targetKid, kid)
		}},
		{"wrapping kid", func(b *board) string { return revocationID(targetKid, b.d.wrappingID()) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, bs := boards(t, []string{"board-a", "board-b"}, nil)
			kind := "kid"
			if c.name == "recipient" {
				kind = "recipient"
			}
			e.store.put("key-revocation", "", c.id(bs[1]), &keyv2alpha1.KeyRevocation{
				TargetKind: kind, Target: "x", ReasonCode: "lost-board", RevokedAt: timestamppb.New(e.clock.now()),
			})
			id, _ := request(t, e, bs[1], testBoundary, e.clock.now())
			release(t, bs[0])
			if answered(e, id) {
				t.Fatal("a revoked board was given its PIN")
			}
			wantWhy(t, bs[0].n, "revoked")
		})
	}
	t.Run("unreadable", func(t *testing.T) {
		e, bs := boards(t, []string{"board-a", "board-b"}, nil)
		e.store.failKind = "key-revocation"
		id, _ := request(t, e, bs[1], testBoundary, e.clock.now())
		if _, err := bs[0].n.srv.ReleasePins(context.Background()); err == nil {
			t.Fatal("a pass with KeyRevocation unreadable reported no error")
		}
		if answered(e, id) {
			t.Fatal("a PIN was released while KeyRevocation could not be read")
		}
		e.store.failKind = ""
		release(t, bs[0])
		if !answered(e, id) {
			t.Fatal("the request was not answered once KeyRevocation could be read")
		}
	})
}

// verifies: REQ-KEYS-109
// A releasing board whose own pin-release key, wrapping key or recipient is revoked releases no PIN: the request is
// refused with a reason of its own ("self-revoked"), audited as refused and never as key.pin.release, and the driver is
// not called (no attestation check, no seal). A revocation of this node that cannot be read releases nothing and is
// tried again.
func TestARevokedReleaserReleasesNoPIN(t *testing.T) {
	for _, c := range []struct {
		name string
		id   func(b *board) string
	}{
		{"pin-release kid", func(b *board) string {
			pub, _ := parseP384(ensureKey(t, b.d, "pin-release", "ES384"))
			kid, _ := thumbprint(pub)
			return revocationID(targetKid, kid)
		}},
		{"wrapping kid", func(b *board) string { return revocationID(targetKid, b.d.wrappingID()) }},
		{"recipient", func(b *board) string { return "recipient/" + recipientLabel(b.d.wrappingID()) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, bs := boards(t, []string{"board-a", "board-b"}, nil)
			kind := "kid"
			if c.name == "recipient" {
				kind = "recipient"
			}
			e.store.put("key-revocation", "", c.id(bs[0]), &keyv2alpha1.KeyRevocation{
				TargetKind: kind, Target: "x", ReasonCode: "lost-board", RevokedAt: timestamppb.New(e.clock.now()),
			})
			id, _ := request(t, e, bs[1], testBoundary, e.clock.now())
			release(t, bs[0])
			release(t, bs[0])
			if answered(e, id) {
				t.Fatal("a revoked releaser answered a request")
			}
			wantWhy(t, bs[0].n, "self-revoked")
			if n := len(refusedWhy(bs[0].n)); n != 1 {
				t.Fatalf("%d refusals audited, want 1: %v", n, refusedWhy(bs[0].n))
			}
			if bs[0].n.audit.count(ActionPinRelease) != 0 {
				t.Fatal("a release was audited")
			}
			if s, v := bs[0].d.sealCalls.Load(), bs[0].d.verifyCalls.Load(); s != 0 || v != 0 {
				t.Fatalf("the driver was called: %d seals, %d attestation checks", s, v)
			}
		})
	}
	t.Run("unreadable", func(t *testing.T) {
		e, bs := boards(t, []string{"board-a", "board-b"}, nil)
		e.store.failKind = "key-revocation"
		id, _ := request(t, e, bs[1], testBoundary, e.clock.now())
		if _, err := bs[0].n.srv.ReleasePins(context.Background()); err == nil {
			t.Fatal("a pass with KeyRevocation unreadable reported no error")
		}
		if answered(e, id) || bs[0].d.sealCalls.Load() != 0 {
			t.Fatal("a PIN was sealed while this node's revocation could not be read")
		}
		if len(refusedWhy(bs[0].n)) != 0 {
			t.Fatalf("an unreadable revocation was audited as a refusal: %v", refusedWhy(bs[0].n))
		}
		e.store.failKind = ""
		release(t, bs[0])
		if !answered(e, id) {
			t.Fatalf("the request was not answered once KeyRevocation could be read; refusals %v", refusedWhy(bs[0].n))
		}
	})
}

// verifies: REQ-KEYS-093
// A request id is answered once. The same request written again after its answer is gone gets no second answer, and a
// different request under a used id is refused as a replay; a stale request and one from the future are refused.
func TestAReusedOrStaleRequestIdIsRefused(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b"}, nil)
	id, text := request(t, e, bs[1], testBoundary, e.clock.now())
	release(t, bs[0])
	if !answered(e, id) {
		t.Fatal("not answered")
	}
	e.store.mu.Lock()
	delete(e.store.items, "|pin-release|"+id) // the answer expired
	e.store.mu.Unlock()
	release(t, bs[0])
	if answered(e, id) || bs[0].n.audit.count(ActionPinRelease) != 1 {
		t.Fatal("the same request id was answered twice")
	}
	// Another text under the used id: another ephemeral key, signed by the board.
	r, _ := pinrelease.ParseRequest(text)
	eph, _ := ecdh.P384().GenerateKey(rand.Reader)
	r.Ephemeral = eph.PublicKey().Bytes()
	other, err := pinrelease.RequestText(r)
	if err != nil {
		t.Fatal(err)
	}
	e.store.put("pin-release-request", "", id, &keyv2alpha1.PinReleaseRequest{Text: other, SignatureDer: signWith(t, bs[1].d, other)})
	release(t, bs[0])
	if answered(e, id) {
		t.Fatal("a replayed id was answered")
	}
	wantWhy(t, bs[0].n, "replayed")

	stale, _ := request(t, e, bs[1], testBoundary, e.clock.now().Add(-20*time.Minute))
	future, _ := request(t, e, bs[1], testBoundary, e.clock.now().Add(10*time.Minute))
	release(t, bs[0])
	if answered(e, stale) || answered(e, future) {
		t.Fatal("a request that is not fresh was answered")
	}
	wantWhy(t, bs[0].n, "stale")
	wantWhy(t, bs[0].n, "future")
}

// verifies: REQ-KEYS-093
// A tampered request (its text changed after it was signed, or signed by another key, or filed under another id) is
// refused and gets no answer.
func TestATamperedRequestIsRefused(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b", "board-c"}, nil)
	ctx := context.Background()

	id, text := request(t, e, bs[1], testBoundary, e.clock.now())
	it, _ := bs[0].n.srv.pinReqs.Get(ctx, "", id)
	r, _ := pinrelease.ParseRequest(text)
	eph, _ := ecdh.P384().GenerateKey(rand.Reader)
	r.Ephemeral = eph.PublicKey().Bytes() // a key the attacker holds, under the board's signature
	swapped, _ := pinrelease.RequestText(r)
	e.store.put("pin-release-request", "", id, &keyv2alpha1.PinReleaseRequest{Text: swapped, SignatureDer: it.Value.GetSignatureDer()})

	id2, text2 := request(t, e, bs[1], testBoundary, e.clock.now().Add(time.Second))
	e.store.put("pin-release-request", "", id2, &keyv2alpha1.PinReleaseRequest{Text: text2, SignatureDer: signWith(t, bs[2].d, text2)})

	_, text3 := request(t, e, bs[1], testBoundary, e.clock.now().Add(2*time.Second))
	r3, _ := pinrelease.ParseRequest(text3)
	misfiled := "board-c/" + r3.ID
	e.store.put("pin-release-request", "", misfiled, &keyv2alpha1.PinReleaseRequest{Text: text3, SignatureDer: signWith(t, bs[1].d, text3)})

	release(t, bs[0])
	for _, x := range []string{id, id2, misfiled} {
		if answered(e, x) {
			t.Fatalf("a tampered request %s was answered", x)
		}
	}
	wantWhy(t, bs[0].n, "signature")
	wantWhy(t, bs[0].n, "format")
}

// verifies: REQ-KEYS-093
// The slot map decides: a board missing from it, one whose wrapping key the recipients do not list, one whose
// pin-release key is not the attested key, one in another slot, and one whose attestation states PIN once all get no
// PIN.
func TestTheSlotMapMustListAndMatchTheBoard(t *testing.T) {
	for _, c := range []struct {
		name, why string
		edit      func(*configv2alpha1.KeyPlan)
		driver    func(*fakeDriver)
	}{
		{"missing", "unlisted", func(p *configv2alpha1.KeyPlan) { p.SlotMap = p.SlotMap[:1] }, nil},
		{"another key", "attestation", func(p *configv2alpha1.KeyPlan) {
			other := newFakeDriver("yubikey-piv")
			p.SlotMap[1].Slots[1].PublicKey = ensureKey(t, other, "pin-release", "ES384")
		}, nil},
		{"another slot", "slot-map", func(p *configv2alpha1.KeyPlan) { p.SlotMap[1].Slots[1].Slot = "88" }, nil},
		{"no attestation", "slot-map", func(p *configv2alpha1.KeyPlan) {
			p.SlotMap[1].Slots[1].Attestation, p.SlotMap[1].Slots[1].AttestationSigner = nil, nil
		}, nil},
		{"pin once", "attestation", func(p *configv2alpha1.KeyPlan) {
			var a fakeAttestation
			_ = json.Unmarshal(p.SlotMap[1].Slots[1].Attestation, &a)
			a.PIN = "once"
			p.SlotMap[1].Slots[1].Attestation, _ = json.Marshal(a)
		}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, bs := boards(t, []string{"board-a", "board-b"}, c.edit)
			id, _ := request(t, e, bs[1], testBoundary, e.clock.now())
			release(t, bs[0])
			if answered(e, id) {
				t.Fatal("answered")
			}
			wantWhy(t, bs[0].n, c.why)
		})
	}
	t.Run("not a recipient", func(t *testing.T) {
		e, bs := boards(t, []string{"board-a", "board-b"}, nil)
		plan := proto.Clone(e.plan).(*configv2alpha1.KeyPlan)
		plan.Recipients = []string{bs[0].d.wrappingID()}
		e.putPlan(plan)
		id, _ := request(t, e, bs[1], testBoundary, e.clock.now())
		release(t, bs[0])
		if answered(e, id) {
			t.Fatal("a board that the recipients do not list was answered")
		}
		wantWhy(t, bs[0].n, "unlisted")
	})
}

// waitRequest waits for the request of a locked board's RequestPin, and returns its id and text.
func waitRequest(t *testing.T, e *testEnv, node string) (string, []byte) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		e.store.mu.Lock()
		for k, it := range e.store.items {
			if strings.HasPrefix(k, "|pin-release-request|"+node+"/") {
				var v keyv2alpha1.PinReleaseRequest
				_ = proto.Unmarshal(it.GetValue(), &v)
				e.store.mu.Unlock()
				return it.GetAddress().GetId(), v.GetText()
			}
		}
		e.store.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no request appeared")
	return "", nil
}

// answerWith writes an answer to a request, sealed with the PIN and signed by the driver's pin-release key; tamper
// changes the text after it was signed.
func answerWith(t *testing.T, e *testEnv, releaser string, d *fakeDriver, id string, text []byte, tamper bool) {
	t.Helper()
	answerFor(t, e, testBoundary, releaser, d, id, text, tamper)
}

// answerFor is answerWith for a boundary.
func answerFor(t *testing.T, e *testEnv, boundary, releaser string, d *fakeDriver, id string, text []byte, tamper bool) {
	t.Helper()
	r, _ := pinrelease.ParseRequest(text)
	pub, sealed, err := pinrelease.Seal([]byte("123456"), text)
	if err != nil {
		t.Fatal(err)
	}
	at, err := pinrelease.AnswerText(pinrelease.Answer{Boundary: boundary, Releaser: releaser, Requester: r.Node, ID: r.ID,
		RequestSHA384: pinrelease.Digest(text), Ephemeral: pub, Sealed: sealed})
	if err != nil {
		t.Fatal(err)
	}
	sig := signWith(t, d, at)
	if tamper {
		at[len(at)-1] ^= 1
	}
	e.store.put("pin-release", "", id, &keyv2alpha1.PinRelease{Text: at, SignatureDer: sig})
}

// verifies: REQ-KEYS-114
// A forged or tampered answer never reaches the card: it is refused before the driver is called, so a compromised
// store@ cannot burn the card's PIN tries. Then a good answer unlocks the board.
func TestAForgedOrTamperedAnswerIsNeverAPINAttempt(t *testing.T) {
	for _, c := range []struct {
		name, releaser, why string
		tamper, stranger    bool
	}{
		{"tampered", "board-a", "signature", true, false},
		{"unlisted signer", "board-x", "unlisted", false, true},
		{"listed name, other key", "board-a", "signature", false, true},
		{"itself", "board-b", "self", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, bs := boards(t, []string{"board-a", "board-b"}, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- bs[1].n.srv.RequestPin(ctx) }()
			id, text := waitRequest(t, e, "board-b")
			d := bs[0].d
			if c.stranger {
				d = newFakeDriver("yubikey-piv")
				ensureKey(t, d, "pin-release", "ES384")
			}
			if c.releaser == "board-b" {
				d = bs[1].d
			}
			answerWith(t, e, c.releaser, d, id, text, c.tamper)
			if err := <-done; !errors.Is(err, errNoAnswer) {
				t.Fatalf("RequestPin: %v, want no answer", err)
			}
			if bs[1].d.finishCalls.Load() != 0 || bs[1].d.pinTries.Load() != 0 {
				t.Fatal("an unverified answer reached the driver")
			}
			wantWhy(t, bs[1].n, c.why)
		})
	}
	t.Run("good", func(t *testing.T) {
		e, bs := boards(t, []string{"board-a", "board-b"}, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- bs[1].n.srv.RequestPin(ctx) }()
		id, text := waitRequest(t, e, "board-b")
		answerWith(t, e, "board-a", bs[0].d, id, text, false)
		if err := <-done; err != nil {
			t.Fatalf("RequestPin: %v", err)
		}
		if bs[1].d.isLocked() || bs[1].d.pinTries.Load() != 1 {
			t.Fatal("the board was not unlocked by one PIN attempt")
		}
	})
}

// A released PIN that the card refuses stops the requests: the card is never asked twice for a released PIN.
// verifies: REQ-KEYS-118
func TestARefusedReleasedPINIsNotAskedForAgain(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b"}, nil)
	bs[1].d.cardPIN = "654321" // D20a says one PIN per boundary; this card was given another
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- bs[1].n.srv.RequestPin(ctx) }()
	id, text := waitRequest(t, e, "board-b")
	answerWith(t, e, "board-a", bs[0].d, id, text, false)
	if err := <-done; !errors.Is(err, ErrPINRefused) {
		t.Fatalf("RequestPin: %v, want ErrPINRefused", err)
	}
	if bs[1].d.pinTries.Load() != 1 {
		t.Fatal("the released PIN was tried more than once")
	}
}

// The check prints this node's slot map entry for the harness: the keys of the plan's slots, the pin-release slot with
// its attestation.
func TestTheCheckPrintsTheSlotMapEntry(t *testing.T) {
	_, bs := boards(t, []string{"board-a"}, nil)
	line, err := bs[0].n.srv.slotMapLine(context.Background(), bs[0].n.srv.plan.last.value)
	if err != nil {
		t.Fatal(err)
	}
	var got slotMapEntry
	if !strings.HasPrefix(line, "slot map: ") || json.Unmarshal([]byte(strings.TrimPrefix(line, "slot map: ")), &got) != nil {
		t.Fatalf("line %q", line)
	}
	if got.Node != "board-a" {
		t.Fatalf("node %q", got.Node)
	}
	var rel *slotMapSlot
	for i, s := range got.Slots {
		if s.Purpose == "pin-release" {
			rel = &got.Slots[i]
		}
	}
	want := base64.RawURLEncoding.EncodeToString(ensureKey(t, bs[0].d, "pin-release", "ES384"))
	if rel == nil || rel.Slot != "87" || rel.PublicKey != want || rel.Attestation == "" || rel.AttestationSigner == "" {
		t.Fatalf("pin-release entry %+v", rel)
	}
	// What it prints is what the KeyPlan reads.
	payload := []byte(`{"default": {"cache_ttl": "15m", "slot_map": [` + strings.TrimPrefix(line, "slot map: ") + `]}}`)
	plan, err := decodeKeyPlan(payload)
	if err != nil || len(plan.GetSlotMap()) != 1 {
		t.Fatalf("the printed entry does not read back: %v", err)
	}
}

// verifies: REQ-KEYS-114
// The answer side checks the releaser as the releasing side checks the requester: an answer for another boundary, and
// one from a releaser whose pin-release key is revoked, are refused before the driver is called.
func TestAnAnswerOfAnotherBoundaryOrARevokedReleaserIsRefused(t *testing.T) {
	for _, c := range []struct{ name, why string }{{"another boundary", "not-this-request"}, {"revoked releaser", "revoked"}} {
		t.Run(c.name, func(t *testing.T) {
			e, bs := boards(t, []string{"board-a", "board-b"}, nil)
			boundary := testBoundary
			if c.name == "another boundary" {
				boundary = "staging"
			} else {
				pub, _ := parseP384(ensureKey(t, bs[0].d, "pin-release", "ES384"))
				kid, _ := thumbprint(pub)
				e.store.put("key-revocation", "", revocationID(targetKid, kid), &keyv2alpha1.KeyRevocation{
					TargetKind: "kid", Target: kid, ReasonCode: "lost-board", RevokedAt: timestamppb.New(e.clock.now()),
				})
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- bs[1].n.srv.RequestPin(ctx) }()
			id, text := waitRequest(t, e, "board-b")
			answerFor(t, e, boundary, "board-a", bs[0].d, id, text, false)
			if err := <-done; !errors.Is(err, errNoAnswer) {
				t.Fatalf("RequestPin: %v, want no answer", err)
			}
			if bs[1].d.finishCalls.Load() != 0 {
				t.Fatal("a refused answer reached the driver")
			}
			wantWhy(t, bs[1].n, c.why)
		})
	}
}

// One node's request id never stands for another's: two boards that send the same id are each answered once.
func TestTheSameIdFromTwoNodesIsAnsweredForEach(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b", "board-c"}, nil)
	_, text := request(t, e, bs[1], testBoundary, e.clock.now())
	r, _ := pinrelease.ParseRequest(text)
	eph, _ := ecdh.P384().GenerateKey(rand.Reader)
	other, err := pinrelease.RequestText(pinrelease.Request{Boundary: testBoundary, Node: "board-c", ID: r.ID, Ephemeral: eph.PublicKey().Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	e.store.put("pin-release-request", "", "board-c/"+r.ID, &keyv2alpha1.PinReleaseRequest{Text: other, SignatureDer: signWith(t, bs[2].d, other)})
	release(t, bs[0])
	if !answered(e, "board-b/"+r.ID) || !answered(e, "board-c/"+r.ID) {
		t.Fatalf("not both answered; refusals %v", refusedWhy(bs[0].n))
	}
}

// A KeyPlan without a slot map is valid and releases nothing: every request is refused as unlisted.
func TestAKeyPlanWithoutASlotMapReleasesNothing(t *testing.T) {
	e, bs := boards(t, []string{"board-a", "board-b"}, func(p *configv2alpha1.KeyPlan) { p.SlotMap = nil })
	id, _ := request(t, e, bs[1], testBoundary, e.clock.now())
	release(t, bs[0])
	if answered(e, id) {
		t.Fatal("a KeyPlan without a slot map released a PIN")
	}
	wantWhy(t, bs[0].n, "unlisted")
}
