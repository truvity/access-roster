package keyd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"log/slog"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/handoff"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// The hand-off to root custody, on key@'s side (ADR 0024, "The hand-off"): what `sluis key request` and
// `sluis key install` ask of the node they run on. The calls are on the admin socket beside Revoke, served only to root
// (admin.go), and are not part of the actor call graph. The first working version hands off the X.509 intermediate.

// handoffPurpose is the one purpose of the first working version's hand-off.
const handoffPurpose = "x509-intermediate"

// The reasons of the hand-off calls, beside the closed list of refuse.go.
const (
	reasonAttestation = "attestation"  // failed_precondition: the card's attestation does not verify or attests another key
	reasonKeyMismatch = "key-mismatch" // invalid_argument: the leaf of an installed chain holds another key than the purpose's
	reasonProfile     = "profile"      // invalid_argument: the leaf is not an intermediate of the hand-off's profile
	reasonValidity    = "validity"     // invalid_argument: the leaf is not valid now
	reasonChain       = "chain"        // invalid_argument: a certificate is not signed by the next
	reasonStale       = "stale"        // failed_precondition: the chain would replace a newer one
)

// maxChain bounds the certificates of an installed chain: an intermediate under a root is a chain of one.
const maxChain = 4

// maxCertificate bounds one certificate of an installed chain.
const maxCertificate = 16 << 10

// maxHandoffRequest bounds a request of the hand-off calls: the chain of Install is the largest.
const maxHandoffRequest = 256 << 10

// ActionCertificateInstall is the audit fact of an installed certificate chain.
const ActionCertificateInstall = "key.certificate.install"

// Prepare says where the key of the purpose lives and gives the evidence for it: the store in the contract's words, and
// for a card the attestation of the slot, which key@'s card driver has checked against the maker's anchors and against
// the key it holds before it is handed on (ADR 0024: "sluis checks the attestation of its own keys when it requests").
// The software store has no evidence.
func (s *Server) Prepare(ctx context.Context, req *connect.Request[keyv2alpha1.PrepareRequest]) (*connect.Response[keyv2alpha1.PrepareResponse], error) {
	const caller, op = "admin", "prepare"
	purpose := req.Msg.GetPurpose()
	pk, err := s.handoffKey(ctx, caller, op, purpose)
	if err != nil {
		return nil, err
	}
	caps, err := s.driver.Capabilities(ctx, connect.NewRequest(&keystorev2alpha1.CapabilitiesRequest{}))
	if err != nil {
		return nil, unavailable(reasonDriver)
	}
	out := &keyv2alpha1.PrepareResponse{SpkiDer: pk.spki, KeyId: pk.keyID}
	switch caps.Msg.GetStore() {
	case "software":
		out.Store = handoff.StoreSoftware
	case "yubikey-piv":
		out.Store = handoff.StorePIV
		att, err := s.driver.Attest(ctx, connect.NewRequest(&keystorev2alpha1.AttestRequest{Purpose: purpose}))
		if err != nil {
			return nil, unavailable(reasonDriver)
		}
		ver, err := s.driver.VerifyAttestation(ctx, connect.NewRequest(&keystorev2alpha1.VerifyAttestationRequest{
			Attestation: att.Msg.GetAttestation(), AttestationSigner: att.Msg.GetAttestationSigner(),
		}))
		if err != nil || !bytes.Equal(ver.Msg.GetSpkiDer(), pk.spki) {
			// The card's own word does not hold: the chain does not reach the maker's anchors, or it attests another key.
			return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeFailedPrecondition, reasonAttestation, "attestation")
		}
		out.Attestation = [][]byte{att.Msg.GetAttestation(), att.Msg.GetAttestationSigner()}
	default:
		// A store the hand-off has no word for (aws-kms comes with its proof file, #1069).
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeFailedPrecondition, reasonStore, "store")
	}
	return connect.NewResponse(out), nil
}

// SignRequest signs a CertificationRequestInfo with the key of the purpose. The info must be exactly the shape the
// contract defines for an intermediate and for this key (handoff.CheckInfo), so the key signs a request and no other
// structure; a revoked key signs nothing; the signature is rate-limited and is an audit fact that is durable before the
// signature leaves.
func (s *Server) SignRequest(ctx context.Context, req *connect.Request[keyv2alpha1.SignRequestRequest]) (*connect.Response[keyv2alpha1.SignRequestResponse], error) {
	const caller, op = "admin", "sign-request"
	purpose := req.Msg.GetPurpose()
	pk, err := s.handoffKey(ctx, caller, op, purpose)
	if err != nil {
		return nil, err
	}
	target, err := s.revoked(ctx, pk)
	if err != nil {
		slog.Warn("KeyRevocation cannot be read: no SignRequest", "purpose", purpose)
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeUnavailable, reasonRevocationUnreadable, "")
	}
	if target != "" {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodePermissionDenied, reasonRevoked, target)
	}
	if err := handoff.CheckInfo(req.Msg.GetInfo(), pk.spki); err != nil {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeInvalidArgument, reasonContent, "info")
	}
	if !s.limits.allow(purpose) {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeResourceExhausted, reasonRate, "")
	}
	digest := sha512.Sum384(req.Msg.GetInfo())
	res, err := s.driver.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{Purpose: purpose, Digest: digest[:], Algorithm: algES384}))
	if err != nil {
		return nil, unavailable(reasonDriver)
	}
	der := res.Msg.GetSignatureDer()
	// A driver that signs wrongly is caught before the signature leaves, as in Sign.
	if !ecdsa.VerifyASN1(pk.pub, digest[:], der) {
		return nil, refusal.New(connect.CodeInternal, reasonDriver, "")
	}
	if err := s.auditBlocking(ctx, Event{Action: ActionSign, Fields: map[string]any{
		"purpose": purpose, "key_id": pk.keyID, "caller": caller, "info_sha384": hex.EncodeToString(digest[:]),
	}}); err != nil {
		return nil, unavailable(reasonAudit)
	}
	return connect.NewResponse(&keyv2alpha1.SignRequestResponse{SignatureDer: der}), nil
}

// Install stores the certificate chain that root custody returned for the key of the purpose, as the kind
// KeyCertificate with the id <purpose>/<label of the key>. key@ holds no anchors and does not repeat the requester's
// checks of the contract against them: the caller holds the anchors and the request (ADR 0024: "hands the verified chain
// to key@"). It checks what it can know itself, so that a caller on the root-only socket cannot store a chain that could
// never have passed: every certificate parses without trailing bytes and is under the size cap; the chain is short; the
// leaf holds this purpose's key, is a CA with path length 0 and the key usage keyCertSign, and is valid now; its name
// constraints are critical with a permitted subtree; nothing unrequested is critical (only basic constraints, key usage
// and name constraints are); and each certificate is signed by the next. A chain does not replace an installed one whose
// leaf ends no later, or whose trust sequence is lower, unless the caller says so, so that an older answer put back in
// place cannot win over a newer one; a renewal, which ends later, replaces it. It is audited, durably, before it is
// stored.
func (s *Server) Install(ctx context.Context, req *connect.Request[keyv2alpha1.InstallRequest]) (*connect.Response[keyv2alpha1.InstallResponse], error) {
	const caller, op = "admin", "install"
	purpose := req.Msg.GetPurpose()
	pk, err := s.handoffKey(ctx, caller, op, purpose)
	if err != nil {
		return nil, err
	}
	refuse := func(code connect.Code, reason, path string) error {
		return s.refuse(ctx, caller, op, purpose, "", code, reason, path)
	}
	chain := req.Msg.GetChain()
	if len(chain) == 0 || len(chain) > maxChain || req.Msg.GetTrustSequence() < 0 {
		return nil, refuse(connect.CodeInvalidArgument, reasonSchema, "chain")
	}
	certs := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil || len(der) > maxCertificate || !bytes.Equal(c.Raw, der) {
			return nil, refuse(connect.CodeInvalidArgument, reasonSchema, "chain")
		}
		certs[i] = c
	}
	leaf := certs[0]
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, pk.spki) {
		return nil, refuse(connect.CodeInvalidArgument, reasonKeyMismatch, "chain[0]")
	}
	if err := checkIntermediate(leaf); err != "" {
		return nil, refuse(connect.CodeInvalidArgument, reasonProfile, "chain[0]."+err)
	}
	if now := s.now(); now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, refuse(connect.CodeInvalidArgument, reasonValidity, "chain[0]")
	}
	for i := 0; i+1 < len(certs); i++ {
		if certs[i].CheckSignatureFrom(certs[i+1]) != nil {
			return nil, refuse(connect.CodeInvalidArgument, reasonChain, "chain")
		}
	}
	id := handoffPurpose + "/" + recipientLabel(pk.keyID)
	// One install at a time: the guard reads the installed chain and the write replaces it, and two installs that both
	// read the same chain must not both pass.
	s.handoffMu.Lock()
	defer s.handoffMu.Unlock()
	cur, err := s.installed(ctx, id)
	if err != nil {
		return nil, refuse(connect.CodeUnavailable, reasonStore, "")
	}
	fact := map[string]any{
		"purpose": purpose, "key_id": pk.keyID, "caller": caller, "chain_length": int64(len(chain)),
		"trust_sequence": req.Msg.GetTrustSequence(), "replace": req.Msg.GetReplace(),
	}
	replaced := false
	if cur != nil {
		if sameChain(cur.GetChain(), chain) {
			return connect.NewResponse(&keyv2alpha1.InstallResponse{Id: id, Already: true}), nil
		}
		replaced = true
		old, oerr := x509.ParseCertificate(firstOf(cur.GetChain()))
		if oerr == nil {
			// The end of the leaf that this one replaces, so that a bypass of the guard below shows in the log.
			fact["previous_not_after"] = old.NotAfter.Unix()
		}
		// The same certificate with its root behind it is not an older answer put back: it is the same answer, completed. The
		// completion is exactly that: the stored chain is the leaf alone, the new one is the same leaf and one certificate that
		// is a root (self-signed: its issuer is its subject and it verifies under its own key), and the trust sequence does not
		// go back. Anything else that keeps the leaf (a longer tail, another certificate behind it) is not recognised as
		// completing, and meets the guard like any other chain.
		completed := len(cur.GetChain()) == 1 && len(chain) == 2 && bytes.Equal(cur.GetChain()[0], chain[0]) && isRoot(certs[1]) &&
			req.Msg.GetTrustSequence() >= cur.GetTrustSequence()
		if !completed && !req.Msg.GetReplace() && (oerr != nil || !leaf.NotAfter.After(old.NotAfter) || req.Msg.GetTrustSequence() < cur.GetTrustSequence()) {
			return nil, refuse(connect.CodeFailedPrecondition, reasonStale, "chain")
		}
	}
	if err := s.auditBlocking(ctx, Event{Action: ActionCertificateInstall, Fields: fact}); err != nil {
		return nil, unavailable(reasonAudit)
	}
	_, err = s.certs.Apply(ctx, "", id, &keyv2alpha1.KeyCertificate{
		Purpose: purpose, Recipient: recipientLabel(pk.keyID), SpkiDer: pk.spki, Chain: chain, AddedAt: timestamppb.New(s.now()),
		TrustSequence: req.Msg.GetTrustSequence(),
	}, store.WithIndex(indexByPurpose, []byte(purpose)))
	if err != nil {
		return nil, refuse(connect.CodeUnavailable, reasonStore, "")
	}
	return connect.NewResponse(&keyv2alpha1.InstallResponse{Id: id, Audited: true, Replaced: replaced}), nil
}

// isRoot says that the certificate is self-signed: a CA whose issuer is its subject and whose signature verifies under its own
// key. key@ holds no anchors, so this is what it can know of a root.
func isRoot(c *x509.Certificate) bool {
	return c.IsCA && bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
}

func firstOf(chain [][]byte) []byte {
	if len(chain) == 0 {
		return nil
	}
	return chain[0]
}

func sameChain(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// The extensions an intermediate certificate of the hand-off may mark critical: the ones it asked for.
var criticalOK = map[string]bool{"2.5.29.19": true, "2.5.29.15": true, "2.5.29.30": true}

// checkIntermediate checks the leaf of an installed chain for what an intermediate of the hand-off is, without an anchor:
// a CA with path length 0 and keyCertSign, critical name constraints with a permitted subtree, and no critical extension
// that the request did not ask for. It returns the place that fails, or "".
func checkIntermediate(c *x509.Certificate) string {
	switch {
	case !c.BasicConstraintsValid || !c.IsCA || c.MaxPathLen != 0 || !c.MaxPathLenZero:
		return "basic constraints"
	case c.KeyUsage&x509.KeyUsageCertSign == 0:
		return "key usage"
	case !c.PermittedDNSDomainsCritical || len(c.PermittedDNSDomains)+len(c.PermittedURIDomains)+len(c.PermittedIPRanges)+len(c.PermittedEmailAddresses) == 0:
		return "name constraints"
	}
	for _, e := range c.Extensions {
		if e.Critical && !criticalOK[e.Id.String()] {
			return "critical extension"
		}
	}
	return ""
}

// installed returns the item with this id, or nil. It lists the kind and never asks for one id: store@ audits a refusal
// for an absent item, and the answer "not there yet" is the expected one (ADR 0005; REQ-AUDIT-180).
func (s *Server) installed(ctx context.Context, id string) (*keyv2alpha1.KeyCertificate, error) {
	all, err := s.certificates(ctx)
	if err != nil {
		return nil, err
	}
	return all[id], nil
}

// handoffKey is the key of the one purpose the hand-off takes, or the refusal.
func (s *Server) handoffKey(ctx context.Context, caller, op, purpose string) (purposeKey, error) {
	if purpose != handoffPurpose {
		// A purpose the caller chose is not echoed: it reaches the audit fact and the log, and it may be as long as the
		// request is. The refusal names a fixed one.
		return purposeKey{}, s.refuse(ctx, caller, op, "other", "", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	pk, ok := s.planned(purpose)
	if !ok || pk.algorithm != algES384 {
		return purposeKey{}, s.refuse(ctx, caller, op, purpose, "", connect.CodeFailedPrecondition, reasonPurpose, "purpose")
	}
	return pk, nil
}
