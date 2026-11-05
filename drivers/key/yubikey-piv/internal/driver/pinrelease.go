package driver

import (
	"bytes"
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
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// The PIN release between boards (ADR 0006, "Touch and PIN"; decided 2026-11-04). The PIN never leaves this process:
// an unlocked driver seals the PIN it holds to a request (SealPin), and a locked driver makes a one-time key and the
// text of its own request (BeginPinRelease), opens the answer with the key, then gives the PIN to its card once
// (FinishPinRelease), as the admin socket's Unlock does.
//
// key@ makes every check on the request and the answer, and the store writes; the driver makes the checks that a
// compromised key@ must not be able to skip, with its own crypto (#914). It verifies the signed KeyPlan (keyplan.go),
// and seals only to a request signed by the pin-release key that the slot map lists for a peer of this boundary, and
// opens only an answer signed likewise for the request it began itself. The pin-release key, slot 87, signs without
// the PIN, so the driver signs with it only the texts it writes itself, from its own configuration: the request in
// BeginPinRelease and the answer in SealPin; Sign refuses its purpose. So key@ can neither have the boundary PIN
// sealed to a key of its own nor spend the card's PIN tries with an answer no listed peer card's driver wrote, and a
// released PIN that the card refused stops the release until a person unlocks the board (refused.go). What stays
// key@'s alone: revocation (the driver cannot read the store), the freshness and the reuse of a request id, and the
// attestation of the slot map, which the driver reads for key@ (VerifyAttestation) because piv-go and the pinned Yubico
// anchors live in the driver only.

// The reasons of the refusals of the PIN release calls.
const (
	reasonUnlocked    = "unlocked"     // the driver holds a PIN already: nothing to release to it
	reasonOneTimeKey  = "one_time_key" // no one-time key, or the request is not of it
	reasonSealed      = "sealed"       // the sealed PIN does not open
	reasonRequest     = "request_text" // the request text is not of the format, or not this node's
	reasonAttestation = "attestation"  // the attestation does not verify
	reasonKeyPlan     = "key_plan"     // the KeyPlan does not verify, is older than one seen, or the driver has no anchor
	reasonBoundary    = "boundary"     // the request or answer is of another boundary
	reasonUnlisted    = "peer"         // the other node is this one, or the slot map lists no pin-release key for it
	reasonSignature   = "signature"    // the signature does not verify with the peer's pin-release key
	reasonAnswer      = "answer_text"  // the answer is not of the format, or not for the request in flight
	reasonRefused     = "pin_refused"  // the card refused a released PIN before: a person unlocks the board
)

// oneTime is the one-time key of the request in flight and the text the driver wrote for it. The caller holds mu.
type oneTime struct {
	key  *ecdh.PrivateKey
	id   string
	text []byte
}

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

// BeginPinRelease makes the one-time key of a request and the request's text, in place of any earlier ones. key@
// gives the id, and the driver writes its own boundary and node into the text and keeps it: FinishPinRelease takes an
// answer for this text only. A driver that holds the PIN refuses: there is nothing to release to it.
func (s *Service) BeginPinRelease(ctx context.Context, req *connect.Request[keystorev2alpha1.BeginPinReleaseRequest]) (*connect.Response[keystorev2alpha1.BeginPinReleaseResponse], error) {
	id := req.Msg.GetRequestId()
	if _, err := pinrelease.UUIDv7Time(id); err != nil {
		return nil, refuse(ctx, "BeginPinRelease", connect.CodeInvalidArgument, reasonRequest, "request_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pin.held() {
		return nil, refuse(ctx, "BeginPinRelease", connect.CodeFailedPrecondition, reasonUnlocked, "")
	}
	k, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, internalRefusal(ctx, "BeginPinRelease")
	}
	text, err := pinrelease.RequestText(pinrelease.Request{Boundary: s.boundary, Node: s.node, ID: id, Ephemeral: k.PublicKey().Bytes()})
	if err != nil {
		return nil, refuse(ctx, "BeginPinRelease", connect.CodeFailedPrecondition, reasonRequest, "")
	}
	sig, cerr := s.signPinText(ctx, "BeginPinRelease", text)
	if cerr != nil {
		return nil, cerr
	}
	s.oneTime = &oneTime{key: k, id: id, text: text}
	return connect.NewResponse(&keystorev2alpha1.BeginPinReleaseResponse{EphemeralPublic: k.PublicKey().Bytes(), RequestText: text, RequestSignatureDer: sig}), nil
}

// signPinText signs a text the driver wrote with the pin-release key, slot 87, which needs no PIN. The caller holds mu.
func (s *Service) signPinText(ctx context.Context, method string, text []byte) ([]byte, *connect.Error) {
	k, ok := s.keys[pinrelease.PurposePinRelease]
	if !ok {
		return nil, refuse(ctx, method, connect.CodeNotFound, reasonAbsent, "")
	}
	digest := pinrelease.Digest(text)
	sig, err := s.card.Sign(k.slot, k.pub, k.spec.PIN, s.pinSource, digest)
	if err != nil {
		return nil, s.failed(ctx, method, err)
	}
	if !ecdsa.VerifyASN1(k.pub, digest, sig) {
		slog.Error("the card's pin-release signature does not verify with its public key")
		return nil, internalRefusal(ctx, method)
	}
	return sig, nil
}

// SealPin seals the PIN this driver holds to the ephemeral key of a request, after it verified the request itself: the
// KeyPlan's publisher signature and seq, a request of this boundary from another node, and its signature with the
// pin-release key that the verified slot map lists for that node. The text it verifies is the one it seals to, byte
// for byte, and the ephemeral key is the one inside it. It writes the answer itself, as this node of this boundary,
// and signs it with the pin-release key. D20a: a boundary has one PIN, so the PIN of this card, which its card took,
// is the PIN of the requesting card.
func (s *Service) SealPin(ctx context.Context, req *connect.Request[keystorev2alpha1.SealPinRequest]) (*connect.Response[keystorev2alpha1.SealPinResponse], error) {
	const method = "SealPin"
	text := req.Msg.GetRequestText()
	r, err := pinrelease.ParseRequest(text)
	if err != nil {
		return nil, refuse(ctx, method, connect.CodeInvalidArgument, reasonRequest, "request_text")
	}
	s.mu.Lock()
	held := s.pin.held()
	s.mu.Unlock()
	if !held {
		return nil, refuse(ctx, method, connect.CodeFailedPrecondition, reasonLocked, "")
	}
	if cerr := s.verifyPeer(ctx, method, req.Msg.GetKeyPlan(), r.Boundary, r.Node, text, req.Msg.GetRequestSignatureDer(), "request_signature_der"); cerr != nil {
		return nil, cerr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pin, ok := s.pin.get()
	if !ok {
		return nil, refuse(ctx, method, connect.CodeFailedPrecondition, reasonLocked, "")
	}
	defer clear(pin)
	pub, sealed, err := pinrelease.Seal(pin, text)
	if err != nil {
		return nil, internalRefusal(ctx, method)
	}
	at, err := pinrelease.AnswerText(pinrelease.Answer{
		Boundary: s.boundary, Releaser: s.node, Requester: r.Node, ID: r.ID, RequestSHA384: pinrelease.Digest(text),
		Ephemeral: pub, Sealed: sealed,
	})
	if err != nil {
		return nil, internalRefusal(ctx, method)
	}
	sig, cerr := s.signPinText(ctx, method, at)
	if cerr != nil {
		return nil, cerr
	}
	slog.Info("sealed the PIN to a verified request of a peer", "node", r.Node, "request", r.ID)
	return connect.NewResponse(&keystorev2alpha1.SealPinResponse{AnswerText: at, AnswerSignatureDer: sig}), nil
}

// FinishPinRelease takes a signed answer to the request this driver began, verifies it, opens it with the one-time key
// and gives the PIN to the card once. It verifies before it opens: the KeyPlan, an answer of this boundary from another
// node to this node's request in flight (its id and the SHA-384 of the text the driver wrote), and the answer's
// signature with the pin-release key that the slot map lists for the releasing node. An answer that fails is no PIN
// attempt and leaves the one-time key in place; one that verifies uses the key once, whatever follows.
func (s *Service) FinishPinRelease(ctx context.Context, req *connect.Request[keystorev2alpha1.FinishPinReleaseRequest]) (*connect.Response[keystorev2alpha1.FinishPinReleaseResponse], error) {
	const method = "FinishPinRelease"
	at := req.Msg.GetAnswerText()
	a, err := pinrelease.ParseAnswer(at)
	if err != nil {
		return nil, refuse(ctx, method, connect.CodeInvalidArgument, reasonAnswer, "answer_text")
	}
	s.mu.Lock()
	if s.pin.held() {
		s.mu.Unlock()
		return nil, refuse(ctx, method, connect.CodeFailedPrecondition, reasonUnlocked, "")
	}
	if s.refused.set {
		s.mu.Unlock()
		return nil, refuse(ctx, method, connect.CodeFailedPrecondition, reasonRefused, "")
	}
	ot := s.oneTime
	s.mu.Unlock()
	if ot == nil {
		return nil, refuse(ctx, method, connect.CodeFailedPrecondition, reasonOneTimeKey, "")
	}
	if a.Requester != s.node || a.ID != ot.id || !bytes.Equal(a.RequestSHA384, pinrelease.Digest(ot.text)) {
		return nil, refuse(ctx, method, connect.CodeFailedPrecondition, reasonAnswer, "answer_text")
	}
	if cerr := s.verifyPeer(ctx, method, req.Msg.GetKeyPlan(), a.Boundary, a.Releaser, at, req.Msg.GetAnswerSignatureDer(), "answer_signature_der"); cerr != nil {
		return nil, cerr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pin.held() {
		return nil, refuse(ctx, method, connect.CodeFailedPrecondition, reasonUnlocked, "")
	}
	if s.refused.set {
		return nil, refuse(ctx, method, connect.CodeFailedPrecondition, reasonRefused, "")
	}
	if s.oneTime != ot {
		// A new request replaced this one while the answer was verified: the answer is for a key that is gone.
		return nil, refuse(ctx, method, connect.CodeFailedPrecondition, reasonOneTimeKey, "")
	}
	s.oneTime = nil // used once, whatever follows
	pin, err := pinrelease.Open(ot.key, ot.text, a.Ephemeral, a.Sealed)
	if err != nil {
		if errors.Is(err, pinrelease.ErrFormat) {
			return nil, refuse(ctx, method, connect.CodeInvalidArgument, reasonSealed, "answer_text")
		}
		return nil, refuse(ctx, method, connect.CodeFailedPrecondition, reasonSealed, "answer_text")
	}
	defer clear(pin)
	if cerr := s.unlockHeld(ctx, method, pin); cerr != nil {
		// The card refused the PIN, or is blocked: no released PIN is tried again, after a restart neither, until a
		// person unlocks the board.
		if reason, _ := refusal.Reason(cerr); (reason == reasonPIN && cerr.Code() == connect.CodePermissionDenied) || reason == reasonBlocked {
			s.refused.mark()
		}
		return nil, cerr
	}
	slog.Info("unlocked by a peer's PIN release: the driver holds the PIN in locked memory", "releaser", a.Releaser, "request", a.ID)
	return connect.NewResponse(&keystorev2alpha1.FinishPinReleaseResponse{}), nil
}

// verifyPeer is the check of the other side of a PIN release, with the driver's own crypto: the signed KeyPlan, the
// boundary, a node that is not this one and that the verified slot map lists with a pin-release key in slot 87, and
// an ES384 signature over the text by that key. It logs a refusal by its word and names, never a value.
func (s *Service) verifyPeer(ctx context.Context, method string, keyPlan []byte, boundary, node string, text, sig []byte, sigField string) *connect.Error {
	if boundary != s.boundary {
		slog.Warn("a PIN release of another boundary refused", "call", method)
		return refuse(ctx, method, connect.CodeFailedPrecondition, reasonBoundary, "")
	}
	slotMap, err := s.slotMap(keyPlan)
	if err != nil {
		slog.Warn("a PIN release refused: the KeyPlan", "call", method, "why", err.Error())
		return refuse(ctx, method, connect.CodeFailedPrecondition, reasonKeyPlan, "key_plan")
	}
	pub, ok := s.peerKey(slotMap, node)
	if !ok {
		slog.Warn("a PIN release refused: not a listed peer", "call", method, "node", node)
		return refuse(ctx, method, connect.CodeFailedPrecondition, reasonUnlisted, "")
	}
	if !verifySigned(pub, text, sig) {
		slog.Warn("a PIN release refused: the signature", "call", method, "node", node)
		return refuse(ctx, method, connect.CodeFailedPrecondition, reasonSignature, sigField)
	}
	return nil
}

// internalRefusal is an internal failure of a PIN release call, logged without a value.
func internalRefusal(ctx context.Context, method string) *connect.Error {
	return refuse(ctx, method, connect.CodeInternal, reasonStore, "")
}
