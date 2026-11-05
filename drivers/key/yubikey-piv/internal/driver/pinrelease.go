package driver

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"log/slog"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/pinrelease"
)

// The PIN release between boards (ADR 0006, "Touch and PIN"; decided 2026-11-04). The PIN never leaves this process:
// an unlocked driver seals the PIN it holds to a request that key@ has verified (SealPin), and a locked driver makes a
// one-time key for its own request (BeginPinRelease) and opens the answer with it, then gives the PIN to its card once
// (FinishPinRelease), as the admin socket's Unlock does. key@ makes every check on the request and the answer, and the
// store writes; the driver also verifies the attestation of another card's slot for key@ (VerifyAttestation), because
// piv-go and the pinned Yubico anchors live in the driver only.

// The reasons of the refusals of the PIN release calls.
const (
	reasonUnlocked    = "unlocked"     // the driver holds a PIN already: nothing to release to it
	reasonOneTimeKey  = "one_time_key" // no one-time key, or the request is not of it
	reasonSealed      = "sealed"       // the sealed PIN does not open
	reasonRequest     = "request_text" // the request text is not of the format, or not this node's
	reasonAttestation = "attestation"  // the attestation does not verify
)

// oneTime is the private half of the one-time key of the request in flight. The caller holds mu.
type oneTime struct{ key *ecdh.PrivateKey }

// Attest returns the attestation of the key of a purpose, for the slot map of the KeyPlan.
func (s *Service) Attest(ctx context.Context, req *connect.Request[keystorev2alpha1.AttestRequest]) (*connect.Response[keystorev2alpha1.AttestResponse], error) {
	purpose := req.Msg.GetPurpose()
	if _, ok := planFor(purpose); !ok {
		return nil, refuse(ctx, "Attest", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[purpose]
	if !ok {
		return nil, refuse(ctx, "Attest", connect.CodeNotFound, reasonAbsent, "purpose")
	}
	cert, err := s.card.Attest(k.slot)
	if err != nil {
		return nil, s.failed(ctx, "Attest", err)
	}
	return connect.NewResponse(&keystorev2alpha1.AttestResponse{Attestation: cert.Raw, AttestationSigner: s.attCert.Raw}), nil
}

// VerifyAttestation reads the attestation of a slot of another card against the same anchors as this card's own: the
// chain to the Yubico root and the firmware floor. What the slot must be (87, PIN never, touch never, the key of the
// slot map) is key@'s check, on what this answers.
func (s *Service) VerifyAttestation(ctx context.Context, req *connect.Request[keystorev2alpha1.VerifyAttestationRequest]) (*connect.Response[keystorev2alpha1.VerifyAttestationResponse], error) {
	slotCert, err := x509.ParseCertificate(req.Msg.GetAttestation())
	if err != nil {
		return nil, refuse(ctx, "VerifyAttestation", connect.CodeInvalidArgument, reasonAttestation, "attestation")
	}
	signer, err := x509.ParseCertificate(req.Msg.GetAttestationSigner())
	if err != nil {
		return nil, refuse(ctx, "VerifyAttestation", connect.CodeInvalidArgument, reasonAttestation, "attestation_signer")
	}
	s.mu.Lock()
	a, err := s.card.VerifyAttestation(signer, slotCert)
	s.mu.Unlock()
	if err != nil {
		slog.Warn("a peer's attestation refused", "error", err.Error())
		return nil, refuse(ctx, "VerifyAttestation", connect.CodeFailedPrecondition, reasonAttestation, "attestation")
	}
	if !a.Version.AtLeast(FirmwareFloor.Major, FirmwareFloor.Minor, FirmwareFloor.Patch) {
		return nil, refuse(ctx, "VerifyAttestation", connect.CodeFailedPrecondition, reasonAttestation, "attestation")
	}
	pub, ok := slotCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, refuse(ctx, "VerifyAttestation", connect.CodeFailedPrecondition, reasonAttestation, "attestation")
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, refuse(ctx, "VerifyAttestation", connect.CodeFailedPrecondition, reasonAttestation, "attestation")
	}
	return connect.NewResponse(&keystorev2alpha1.VerifyAttestationResponse{
		SpkiDer: spki, Slot: a.Slot.String(), PinPolicy: pinPolicyName(a.PIN), TouchPolicy: touchPolicyName(a.Touch), Serial: a.Serial,
	}), nil
}

func pinPolicyName(p card.PINPolicy) string {
	switch p {
	case card.PINNever:
		return "never"
	case card.PINOnce:
		return "once"
	}
	return "always"
}

func touchPolicyName(t card.TouchPolicy) string {
	switch t {
	case card.TouchNever:
		return "never"
	case card.TouchAlways:
		return "always"
	case card.TouchCached:
		return "cached"
	}
	return ""
}

// BeginPinRelease makes the one-time key of a request, in place of any earlier one. A driver that holds the PIN
// refuses: there is nothing to release to it.
func (s *Service) BeginPinRelease(ctx context.Context, _ *connect.Request[keystorev2alpha1.BeginPinReleaseRequest]) (*connect.Response[keystorev2alpha1.BeginPinReleaseResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pin.held() {
		return nil, refuse(ctx, "BeginPinRelease", connect.CodeFailedPrecondition, reasonUnlocked, "")
	}
	k, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, internalRefusal(ctx, "BeginPinRelease")
	}
	s.oneTime = &oneTime{key: k}
	return connect.NewResponse(&keystorev2alpha1.BeginPinReleaseResponse{EphemeralPublic: k.PublicKey().Bytes()}), nil
}

// SealPin seals the PIN this driver holds to the ephemeral key of a request that key@ verified.
//
// planned: #914 — verify the KeyPlan's signature and the peer's slot 87 signature over the request here, so that a
// compromised key@ cannot have the PIN sealed to a key of its own (ADR 0006, "Touch and PIN"). D20a: a boundary has
// one PIN, so the PIN of this card is the PIN of the requesting card.
func (s *Service) SealPin(ctx context.Context, req *connect.Request[keystorev2alpha1.SealPinRequest]) (*connect.Response[keystorev2alpha1.SealPinResponse], error) {
	text := req.Msg.GetRequestText()
	if _, err := pinrelease.ParseRequest(text); err != nil {
		return nil, refuse(ctx, "SealPin", connect.CodeInvalidArgument, reasonRequest, "request_text")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pin, ok := s.pin.get()
	if !ok {
		return nil, refuse(ctx, "SealPin", connect.CodeFailedPrecondition, reasonLocked, "")
	}
	defer clear(pin)
	pub, sealed, err := pinrelease.Seal(pin, text)
	if err != nil {
		return nil, internalRefusal(ctx, "SealPin")
	}
	return connect.NewResponse(&keystorev2alpha1.SealPinResponse{ReleaserPublic: pub, Sealed: sealed}), nil
}

// FinishPinRelease opens a release with the one-time key and gives the PIN to the card once. The one-time key is used
// once and dropped, whatever the outcome; a release that does not open is not a PIN attempt. key@ calls it only after
// it has verified the answer's signature, so a forged answer never reaches the card.
func (s *Service) FinishPinRelease(ctx context.Context, req *connect.Request[keystorev2alpha1.FinishPinReleaseRequest]) (*connect.Response[keystorev2alpha1.FinishPinReleaseResponse], error) {
	text := req.Msg.GetRequestText()
	r, err := pinrelease.ParseRequest(text)
	if err != nil || r.Node != s.node {
		return nil, refuse(ctx, "FinishPinRelease", connect.CodeInvalidArgument, reasonRequest, "request_text")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pin.held() {
		return nil, refuse(ctx, "FinishPinRelease", connect.CodeFailedPrecondition, reasonUnlocked, "")
	}
	ot := s.oneTime
	if ot == nil {
		return nil, refuse(ctx, "FinishPinRelease", connect.CodeFailedPrecondition, reasonOneTimeKey, "")
	}
	s.oneTime = nil // used once, whatever follows
	pin, err := pinrelease.Open(ot.key, text, req.Msg.GetReleaserPublic(), req.Msg.GetSealed())
	if err != nil {
		if errors.Is(err, pinrelease.ErrFormat) {
			return nil, refuse(ctx, "FinishPinRelease", connect.CodeInvalidArgument, reasonSealed, "releaser_public")
		}
		return nil, refuse(ctx, "FinishPinRelease", connect.CodeFailedPrecondition, reasonSealed, "sealed")
	}
	defer clear(pin)
	if cerr := s.unlockHeld(ctx, "FinishPinRelease", pin); cerr != nil {
		return nil, cerr
	}
	slog.Info("unlocked by a peer's PIN release: the driver holds the PIN in locked memory")
	return connect.NewResponse(&keystorev2alpha1.FinishPinReleaseResponse{}), nil
}

// internalRefusal is an internal failure of a PIN release call, logged without a value.
func internalRefusal(ctx context.Context, method string) *connect.Error {
	return refuse(ctx, method, connect.CodeInternal, reasonStore, "")
}
