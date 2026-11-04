//go:build sluis_test

package driver_test

import (
	"context"
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
)

// The card tests of the PIN release run on the fake cards of cardtest, in factory state (PIN 123456): two cards of one
// TEST ONLY PKI, as two YubiKeys both chain to Yubico's root. No real card and no real PIN is used.

// pair is an unlocked driver (the peer that releases) and a locked one (the board that asks), on sibling cards.
func pair(t *testing.T) (releaser, locked running) {
	t.Helper()
	a := cardtest.New()
	b := cardtest.New()
	b.SerialNo = 87654321
	b.PKI = a
	releaser = startWith(t, a, driver.Development, "key", self())
	locked = startWith(t, b, driver.Development, "key", self())
	ensure(t, releaser.key, "pin-release", "ES384")
	ensure(t, locked.key, "pin-release", "ES384")
	releaser.unlock(t, "123456")
	return releaser, locked
}

// begin makes the locked driver's one-time key and the request text, as key@ does.
func begin(t *testing.T, r running) []byte {
	t.Helper()
	res, err := r.key.BeginPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{}))
	if err != nil {
		t.Fatalf("BeginPinRelease: %v", err)
	}
	text, err := pinrelease.RequestText(pinrelease.Request{Boundary: "test", Node: "node-a", ID: newID(t), Ephemeral: res.Msg.GetEphemeralPublic()})
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func seal(t *testing.T, r running, text []byte) *keystorev2alpha1.SealPinResponse {
	t.Helper()
	res, err := r.key.SealPin(context.Background(), connect.NewRequest(&keystorev2alpha1.SealPinRequest{RequestText: text}))
	if err != nil {
		t.Fatalf("SealPin: %v", err)
	}
	return res.Msg
}

func finish(r running, text []byte, s *keystorev2alpha1.SealPinResponse) error {
	_, err := r.key.FinishPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.FinishPinReleaseRequest{
		RequestText: text, ReleaserPublic: s.GetReleaserPublic(), Sealed: s.GetSealed(),
	}))
	return err
}

// verifies: REQ-KEYS-059, REQ-KEYS-115
// The happy path at the drivers: the unlocked driver seals the PIN it holds to the locked driver's one-time key, and
// the locked driver opens it and gives it to its card once. Then it signs with a PIN-once key.
func TestALockedDriverIsUnlockedByAPeersRelease(t *testing.T) {
	releaser, locked := pair(t)
	text := begin(t, locked)
	if err := finish(locked, text, seal(t, releaser, text)); err != nil {
		t.Fatalf("FinishPinRelease: %v", err)
	}
	if locked.card.LoginAttempts != 1 {
		t.Fatalf("%d PIN attempts, want 1", locked.card.LoginAttempts)
	}
	ensure(t, locked.key, "token-signing", "ES384")
	if _, err := sign(locked.key, "token-signing", "ES384", digest384()); err != nil {
		t.Fatalf("the unlocked driver does not sign: %v", err)
	}
	// Unlocked now: a second request has nothing to release to.
	_, err := locked.key.BeginPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "unlocked")
}

// verifies: REQ-KEYS-059
// A release sealed to another request's key, or tampered with, opens nothing and is never a PIN attempt; and the
// one-time key is used once.
func TestAReleaseForAnotherKeyOrTamperedIsNoPINAttempt(t *testing.T) {
	releaser, locked := pair(t)

	old := begin(t, locked)
	cur := begin(t, locked) // a new request replaces the one-time key of the old one
	err := finish(locked, cur, seal(t, releaser, old))
	wantRefused(t, err, connect.CodeFailedPrecondition, "sealed")

	cur = begin(t, locked)
	s := seal(t, releaser, cur)
	s.Sealed[len(s.Sealed)-1] ^= 1
	wantRefused(t, finish(locked, cur, s), connect.CodeFailedPrecondition, "sealed")

	// The key was dropped by the failed attempt: the right answer now finds no key.
	cur2 := begin(t, locked)
	good := seal(t, releaser, cur2)
	if err := finish(locked, cur2, good); err != nil {
		t.Fatalf("FinishPinRelease: %v", err)
	}
	if locked.card.LoginAttempts != 1 {
		t.Fatalf("%d PIN attempts, want 1: a release that does not open must not reach the card", locked.card.LoginAttempts)
	}
	wantRefused(t, finish(locked, cur2, good), connect.CodeFailedPrecondition, "unlocked")
}

func TestALockedDriverSealsNothingAndAnUnknownRequestFinishesNothing(t *testing.T) {
	_, locked := pair(t)
	text := begin(t, locked)
	_, err := locked.key.SealPin(context.Background(), connect.NewRequest(&keystorev2alpha1.SealPinRequest{RequestText: text}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "locked")
	_, err = locked.key.SealPin(context.Background(), connect.NewRequest(&keystorev2alpha1.SealPinRequest{RequestText: []byte("x")}))
	wantRefused(t, err, connect.CodeInvalidArgument, "request_text")

	// A request of another node is not this driver's.
	other, err := pinrelease.RequestText(pinrelease.Request{Boundary: "test", Node: "node-b", ID: newID(t), Ephemeral: mustEphemeral(t, locked)})
	if err != nil {
		t.Fatal(err)
	}
	wantRefused(t, finish(locked, other, &keystorev2alpha1.SealPinResponse{}), connect.CodeInvalidArgument, "request_text")
}

func mustEphemeral(t *testing.T, r running) []byte {
	t.Helper()
	res, err := r.key.BeginPinRelease(context.Background(), connect.NewRequest(&keystorev2alpha1.BeginPinReleaseRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg.GetEphemeralPublic()
}

// The released PIN reaches the card through the same floor as an unlock: a card with one attempt left is not sent it.
func TestAReleaseIsNotTriedOnACardWithOneAttemptLeft(t *testing.T) {
	releaser, locked := pair(t)
	locked.card.Retries = 1
	text := begin(t, locked)
	wantRefused(t, finish(locked, text, seal(t, releaser, text)), connect.CodeFailedPrecondition, "pin_retries")
	if locked.card.LoginAttempts != 0 {
		t.Fatal("a PIN was sent to a card with one attempt left")
	}
}

// The attestation of a peer's slot 87 is read through the driver: the key, the slot and the policies the card states.
func TestAPeersAttestationIsVerifiedByTheDriver(t *testing.T) {
	releaser, locked := pair(t)
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
	releaser, _ := pair(t)
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
