package keyd

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"strconv"
	"unicode/utf8"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/actors/key/internal/content"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// planned returns the key of a purpose that the KeyPlan enables. A purpose the plan does not list has no key.
func (s *Server) planned(purpose string) (purposeKey, bool) {
	k, ok := s.keys[purpose]
	return k, ok
}

// Sign signs content with the key of a purpose, in place, after it has checked the content (ADR 0006, "Keys sign
// in place"). A token purpose signs only a JWS signing input, and the audit log purpose only a checkpoint body.
func (s *Server) Sign(ctx context.Context, req *connect.Request[keyv2alpha1.SignRequest]) (*connect.Response[keyv2alpha1.SignResponse], error) {
	m := req.Msg
	caller, err := s.callerOf(ctx, "sign")
	if err != nil {
		return nil, err
	}
	purpose := m.GetPurpose()
	if !registry.KeyAllows(caller, purpose, "sign") {
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodePermissionDenied, reasonRule, "purpose")
	}
	pk, ok := s.planned(purpose)
	if !ok || pk.algorithm != algES384 {
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	if m.GetAlgorithm() != algES384 {
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodeInvalidArgument, reasonAlgorithm, "algorithm")
	}
	var cerr error
	switch purpose {
	case "token-signing":
		cerr = content.JWSSigningInput(m.GetContent(), pk.keyID)
	case "audit-log":
		cerr = content.Checkpoint(m.GetContent())
	default:
		cerr = errors.New("no content rule for the purpose")
	}
	if cerr != nil {
		path := "content"
		var ce *content.ErrContent
		if errors.As(cerr, &ce) {
			path = ce.Path
		}
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodeInvalidArgument, reasonContent, path)
	}
	if !s.limits.allow(purpose) {
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodeResourceExhausted, reasonRate, "")
	}
	digest := sha512.Sum384(m.GetContent())
	res, err := s.driver.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{
		Purpose: purpose, Digest: digest[:], Algorithm: algES384,
	}))
	if err != nil {
		return nil, unavailable(reasonDriver)
	}
	der := res.Msg.GetSignatureDer()
	// Verify with the public key before the signature leaves: a driver that signs wrongly is caught here.
	if !ecdsa.VerifyASN1(pk.pub, digest[:], der) {
		return nil, refusal.New(connect.CodeInternal, reasonDriver, "")
	}
	raw, err := rawSignature(der)
	if err != nil {
		return nil, refusal.New(connect.CodeInternal, reasonDriver, "")
	}
	// D-24: every token-signing signature is an audit fact; an audit-log signature is not, because the signed
	// checkpoint is itself the evidence and auditing it would feed a new record into the log for ever.
	if purpose == "token-signing" {
		s.audit(ctx, Event{Action: ActionSign, Fields: map[string]any{"purpose": purpose, "key_id": pk.keyID, "caller": caller}})
	}
	return connect.NewResponse(&keyv2alpha1.SignResponse{SignatureRaw: raw, SignatureDer: der, KeyId: pk.keyID}), nil
}

// rawSignature converts an ASN.1 DER ECDSA signature to the fixed-width r||s form of JWS (RFC 7518, section
// 3.4): 48 bytes each for P-384.
func rawSignature(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, errors.New("keyd: bad signature encoding")
	}
	if sig.R.BitLen() > 384 || sig.S.BitLen() > 384 {
		return nil, errors.New("keyd: signature is too large for P-384")
	}
	out := make([]byte, 96)
	sig.R.FillBytes(out[:48])
	sig.S.FillBytes(out[48:])
	return out, nil
}

// PublicKey returns the public key of a purpose, with its RFC 7638 thumbprint. There is no certificate chain
// tonight (D-8), so x5c is empty.
func (s *Server) PublicKey(ctx context.Context, req *connect.Request[keyv2alpha1.PublicKeyRequest]) (*connect.Response[keyv2alpha1.PublicKeyResponse], error) {
	caller, err := s.callerOf(ctx, "public-key")
	if err != nil {
		return nil, err
	}
	purpose := req.Msg.GetPurpose()
	if !registry.KeyAllows(caller, purpose, "public-key") {
		return nil, s.refuse(ctx, caller, "public-key", purpose, "", connect.CodePermissionDenied, reasonRule, "purpose")
	}
	pk, ok := s.planned(purpose)
	if !ok {
		return nil, s.refuse(ctx, caller, "public-key", purpose, "", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	return connect.NewResponse(&keyv2alpha1.PublicKeyResponse{SpkiDer: pk.spki, KeyId: pk.keyID, Algorithm: pk.algorithm}), nil
}

// macEpoch reads a pseudonym epoch, YYYYMM, as the generation of the tenant's pseudonym key (0029,
// "Pseudonyms").
func macEpoch(epoch string) (uint32, bool) {
	if len(epoch) != 6 {
		return 0, false
	}
	n, err := strconv.ParseUint(epoch, 10, 32)
	if err != nil {
		return 0, false
	}
	if y, m := n/100, n%100; y < 2000 || m < 1 || m > 12 {
		return 0, false
	}
	return uint32(n), true
}

// maxLabel bounds a label, which is length-prefixed with 16 bits.
const maxLabel = 1024

// Mac makes a keyed hash with HMAC-SHA384 over a data key (ADR 0006, "Sign and Mac"): the label is bound into
// the input as u16 length | label | input, so two uses never produce the same hash for the same input. The
// purposes are mac (the boundary's), pseudonym (a tenant's, by epoch) and pairwise (a tenant's). MacRequest.grant
// exists but is not checked tonight (D-5: the boundary purposes are checked by rule only).
func (s *Server) Mac(ctx context.Context, req *connect.Request[keyv2alpha1.MacRequest]) (*connect.Response[keyv2alpha1.MacResponse], error) {
	m := req.Msg
	caller, err := s.callerOf(ctx, "mac")
	if err != nil {
		return nil, err
	}
	purpose, tenant := m.GetPurpose(), m.GetTenant()
	switch purpose {
	case "mac", "pseudonym", "pairwise":
	default:
		return nil, s.refuse(ctx, caller, "mac", purpose, "", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	if !registry.KeyAllows(caller, purpose, "mac") {
		return nil, s.refuse(ctx, caller, "mac", purpose, "", connect.CodePermissionDenied, reasonRule, "purpose")
	}
	if (purpose == "mac") != (tenant == "") || (tenant != "" && !validTenant(tenant)) {
		return nil, s.refuse(ctx, caller, "mac", purpose, "", connect.CodeInvalidArgument, reasonTenant, "tenant")
	}
	generation := uint32(sealGeneration)
	switch purpose {
	case "pseudonym":
		var ok bool
		if generation, ok = macEpoch(m.GetEpoch()); !ok {
			return nil, s.refuse(ctx, caller, "mac", purpose, tenant, connect.CodeInvalidArgument, reasonEpoch, "epoch")
		}
	default:
		if m.GetEpoch() != "" {
			return nil, s.refuse(ctx, caller, "mac", purpose, tenant, connect.CodeInvalidArgument, reasonEpoch, "epoch")
		}
	}
	if label := m.GetLabel(); label == "" || len(label) > maxLabel || !utf8.ValidString(label) {
		return nil, s.refuse(ctx, caller, "mac", purpose, tenant, connect.CodeInvalidArgument, reasonLabel, "label")
	}
	var tag []byte
	err = s.withKey(ctx, keyRef{tenant, purpose, generation}, true, func(key []byte) error {
		h := hmac.New(sha512.New384, key)
		h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(m.GetLabel())))) //nolint:gosec // bounded by maxLabel
		h.Write([]byte(m.GetLabel()))
		h.Write(m.GetInput())
		tag = h.Sum(nil)
		return nil
	})
	if err != nil {
		return nil, s.keyFailure(ctx, caller, "mac", purpose, tenant, err, false)
	}
	return connect.NewResponse(&keyv2alpha1.MacResponse{Mac: tag}), nil
}
