package keyd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
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
)

// maxChain bounds the certificates of an installed chain: an intermediate under a root is a chain of one.
const maxChain = 4

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
	if err := s.auditBlocking(ctx, Event{Action: ActionSign, Fields: map[string]any{"purpose": purpose, "key_id": pk.keyID, "caller": caller}}); err != nil {
		return nil, unavailable(reasonAudit)
	}
	return connect.NewResponse(&keyv2alpha1.SignRequestResponse{SignatureDer: der}), nil
}

// Install stores the certificate chain that root custody returned for the key of the purpose, as the kind
// KeyCertificate with the id <purpose>/<label of the key>. key@ does not repeat the requester's checks of the contract:
// they need the anchors and the request, which the caller holds, and which key@ does not (ADR 0024: "hands the verified
// chain to key@"). It checks what it can know itself: every certificate parses, the leaf holds this purpose's key, and
// the chain is short. It is audited, durably, before it is stored.
func (s *Server) Install(ctx context.Context, req *connect.Request[keyv2alpha1.InstallRequest]) (*connect.Response[keyv2alpha1.InstallResponse], error) {
	const caller, op = "admin", "install"
	purpose := req.Msg.GetPurpose()
	pk, err := s.handoffKey(ctx, caller, op, purpose)
	if err != nil {
		return nil, err
	}
	chain := req.Msg.GetChain()
	if len(chain) == 0 || len(chain) > maxChain || req.Msg.GetTrustSequence() < 0 {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeInvalidArgument, reasonSchema, "chain")
	}
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(c.Raw, der) {
			return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeInvalidArgument, reasonSchema, "chain")
		}
		if i == 0 && !bytes.Equal(c.RawSubjectPublicKeyInfo, pk.spki) {
			return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeInvalidArgument, reasonKeyMismatch, "chain[0]")
		}
	}
	id := handoffPurpose + "/" + recipientLabel(pk.keyID)
	already, err := s.installed(ctx, id, chain)
	if err != nil {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeUnavailable, reasonStore, "")
	}
	if already {
		return connect.NewResponse(&keyv2alpha1.InstallResponse{Id: id, Already: true}), nil
	}
	if err := s.auditBlocking(ctx, Event{Action: ActionCertificateInstall, Fields: map[string]any{
		"purpose": purpose, "key_id": pk.keyID, "caller": caller, "chain_length": int64(len(chain)), "trust_sequence": req.Msg.GetTrustSequence(),
	}}); err != nil {
		return nil, unavailable(reasonAudit)
	}
	_, err = s.certs.Apply(ctx, "", id, &keyv2alpha1.KeyCertificate{
		Purpose: purpose, Recipient: recipientLabel(pk.keyID), SpkiDer: pk.spki, Chain: chain, AddedAt: timestamppb.New(s.now()),
	}, store.WithIndex(indexByPurpose, []byte(purpose)))
	if err != nil {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeUnavailable, reasonStore, "")
	}
	return connect.NewResponse(&keyv2alpha1.InstallResponse{Id: id, Audited: true}), nil
}

// installed reports whether the item exists with this chain. It lists the kind and never asks for one id: store@ audits
// a refusal for an absent item, and the answer "not there yet" is the expected one (ADR 0005; REQ-AUDIT-180).
func (s *Server) installed(ctx context.Context, id string, chain [][]byte) (bool, error) {
	for token := ""; ; {
		items, next, err := s.certs.List(ctx, "", store.PageSize(200), store.PageToken(token))
		if err != nil {
			return false, err
		}
		for _, it := range items {
			if it.ID != id {
				continue
			}
			got := it.Value.GetChain()
			if len(got) != len(chain) {
				return false, nil
			}
			for i := range got {
				if !bytes.Equal(got[i], chain[i]) {
					return false, nil
				}
			}
			return true, nil
		}
		if next == "" {
			return false, nil
		}
		token = next
	}
}

// handoffKey is the key of the one purpose the hand-off takes, or the refusal.
func (s *Server) handoffKey(ctx context.Context, caller, op, purpose string) (purposeKey, error) {
	if purpose != handoffPurpose {
		return purposeKey{}, s.refuse(ctx, caller, op, purpose, "", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	pk, ok := s.planned(purpose)
	if !ok || pk.algorithm != algES384 {
		return purposeKey{}, s.refuse(ctx, caller, op, purpose, "", connect.CodeFailedPrecondition, reasonPurpose, "purpose")
	}
	return pk, nil
}
