package keyd

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/big"
	"strconv"
	"unicode/utf8"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/actors/key/internal/content"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
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
	if !registry.KeyAllows(caller, registry.ScopeBoundary, purpose, "sign") {
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodePermissionDenied, reasonRule, "purpose")
	}
	// The audit-log purpose is the one exception to P-384 (ADR 0006, "Named exceptions"; D-25): its key is P-256
	// and signs SHA-256, the C2SP signed-note signature type 0x02. Every other signing purpose is ES384.
	want := algES384
	if purpose == "audit-log" {
		want = algES256
	}
	if purpose == rs256Purpose {
		// The RS256 purpose is the other exception (ADR 0006): RSA-2048, RSASSA-PKCS1-v1_5 over SHA-256.
		want = algRS256
	}
	pk, ok := s.planned(purpose)
	if !ok || pk.algorithm != want {
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	if m.GetAlgorithm() != want {
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodeInvalidArgument, reasonAlgorithm, "algorithm")
	}
	// A revoked key signs nothing more, whatever the purpose and whoever asks (REQ-KEYS-109). The check comes before the
	// content is read. An unreadable KeyRevocation refuses the Sign and the refusal is audited: fail closed, so a store@
	// outage stops token signing and audit checkpoints (principle 4: "not revoked" is verified, never assumed).
	target, err := s.revoked(ctx, pk)
	if err != nil {
		slog.Warn("KeyRevocation cannot be read: no Sign", "purpose", purpose)
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodeUnavailable, reasonRevocationUnreadable, "")
	}
	if target != "" {
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodePermissionDenied, reasonRevoked, target)
	}
	var cerr error
	switch purpose {
	case "token-signing":
		cerr = content.JWSSigningInput(m.GetContent(), pk.keyID)
	case rs256Purpose:
		cerr = content.JWSSigningInputRS256(m.GetContent(), pk.keyID)
	case "audit-log", "issuance-log":
		// Both logs are C2SP tlog-checkpoint bodies: the issuance log of ca is a third log kind of the writer
		// (REQ-KEYS-063). Their keys differ in algorithm (P-256 and P-384), not in what they sign.
		cerr = content.Checkpoint(m.GetContent())
	case handoffPurpose:
		// A certificate for a revoked token key is not signed (REQ-KEYS-109 is for the signing key; this is the key that
		// would be certified). The check comes before the content is read and before the driver is asked.
		if tok, ok := s.planned(tokenPurpose); ok {
			target, err := s.revoked(ctx, tok)
			if err != nil {
				slog.Warn("KeyRevocation cannot be read: no Sign", "purpose", purpose)
				return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodeUnavailable, reasonRevocationUnreadable, "")
			}
			if target != "" {
				return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodePermissionDenied, reasonRevoked, target)
			}
		}
		// The intermediate signs the token certificate of this node and nothing else (REQ-ISO-006). Its other
		// signature, of a CertificationRequestInfo, is SignRequest's and has its own rule; neither passes the other.
		rules, _, err := s.tokenCertificateRules(ctx)
		if err != nil {
			return nil, s.refuseTokenCertificate(ctx, caller, "sign", purpose, err)
		}
		cerr = content.TokenCertificate(m.GetContent(), rules)
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
	var allowed bool
	if purpose == handoffPurpose {
		// A certificate has a bucket of its own, far smaller than a token's; SignRequest keeps the purpose's, and a
		// certificate takes nothing from it.
		allowed = s.limits.allowCertificate()
	} else {
		allowed = s.limits.allow(purpose)
	}
	if !allowed {
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodeResourceExhausted, reasonRate, "")
	}
	if want == algRS256 {
		return s.signRS256(ctx, caller, pk, m.GetContent())
	}
	var digest []byte
	if want == algES256 {
		d := sha256.Sum256(m.GetContent())
		digest = d[:]
	} else {
		d := sha512.Sum384(m.GetContent())
		digest = d[:]
	}
	res, err := s.driver.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{
		Purpose: purpose, Digest: digest, Algorithm: want,
	}))
	if err != nil {
		return nil, unavailable(reasonDriver)
	}
	der := res.Msg.GetSignatureDer()
	// Verify with the public key before the signature leaves: a driver that signs wrongly is caught here.
	if !ecdsa.VerifyASN1(pk.pub, digest, der) {
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodeInternal, reasonDriver, "")
	}
	raw, err := rawSignature(der, pk.pub.Curve.Params().BitSize)
	if err != nil {
		return nil, s.refuse(ctx, caller, "sign", purpose, "", connect.CodeInternal, reasonDriver, "")
	}
	// D-24: every token-signing signature is an audit fact, durable before the signature is returned; if the
	// fact cannot be made durable the signature is withheld. An audit-log signature is not an audit fact, because
	// the signed checkpoint is itself the evidence and auditing it would feed a new record into the log for ever.
	switch purpose {
	case "token-signing":
		if err := s.auditBlocking(ctx, Event{Action: ActionSign, Fields: map[string]any{"purpose": purpose, "key_id": pk.keyID, "caller": caller}}); err != nil {
			return nil, unavailable(reasonAudit)
		}
	case handoffPurpose:
		// A certificate is evidence of what the key vouched for: the fact names what the signature covers.
		if err := s.auditBlocking(ctx, Event{Action: ActionSign, Fields: map[string]any{
			"purpose": purpose, "key_id": pk.keyID, "caller": caller, "tbs_sha384": hex.EncodeToString(digest),
		}}); err != nil {
			return nil, unavailable(reasonAudit)
		}
	}
	return connect.NewResponse(&keyv2alpha1.SignResponse{SignatureRaw: raw, SignatureDer: der, KeyId: pk.keyID}), nil
}

// rs256SignatureLen is the length of an RSASSA-PKCS1-v1_5 signature under a 2048-bit modulus (RFC 8017, section 8.2.1).
const rs256SignatureLen = 256

// signRS256 signs content with the RSA key of the RS256 purpose through the driver: the SHA-256 digest goes to the driver and
// the signature comes back as the fixed-length octet string of RFC 7518, section 3.3, which is the form a JWS carries. It is
// verified with rsa.VerifyPKCS1v15 under the public key before it leaves, so a driver that signs wrongly, with another key or
// with another padding (PSS) is caught here. An RSA signature has no DER form, so signature_der is empty. As every token
// signature (D-24) it is an audit fact, durable before the signature is returned.
func (s *Server) signRS256(ctx context.Context, caller string, pk purposeKey, content []byte) (*connect.Response[keyv2alpha1.SignResponse], error) {
	// On a card one RSA signature takes seconds of the card's time: a bucket of its own (rsalimit.go).
	if s.cardRSA != nil && !s.cardRSA.allow() {
		return nil, s.refuse(ctx, caller, "sign", rs256Purpose, "", connect.CodeResourceExhausted, reasonRate, "")
	}
	digest := sha256.Sum256(content)
	res, err := s.driver.Sign(ctx, connect.NewRequest(&keystorev2alpha1.KeyStoreSignRequest{
		Purpose: rs256Purpose, Digest: digest[:], Algorithm: algRS256,
	}))
	if err != nil {
		return nil, unavailable(reasonDriver)
	}
	sig := res.Msg.GetSignatureDer()
	if len(sig) != rs256SignatureLen || rsa.VerifyPKCS1v15(pk.rsa, crypto.SHA256, digest[:], sig) != nil {
		return nil, s.refuse(ctx, caller, "sign", rs256Purpose, "", connect.CodeInternal, reasonDriver, "")
	}
	if err := s.auditBlocking(ctx, Event{Action: ActionSign, Fields: map[string]any{"purpose": rs256Purpose, "key_id": pk.keyID, "caller": caller}}); err != nil {
		return nil, unavailable(reasonAudit)
	}
	return connect.NewResponse(&keyv2alpha1.SignResponse{SignatureRaw: sig, KeyId: pk.keyID}), nil
}

// rawSignature converts an ASN.1 DER ECDSA signature to the fixed-width r||s form of JWS (RFC 7518, section
// 3.4): 48 bytes each for P-384, 32 for P-256.
func rawSignature(der []byte, bits int) ([]byte, error) {
	n := (bits + 7) / 8
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, errors.New("keyd: bad signature encoding")
	}
	if sig.R.BitLen() > bits || sig.S.BitLen() > bits {
		return nil, errors.New("keyd: signature is too large for the curve")
	}
	out := make([]byte, 2*n)
	sig.R.FillBytes(out[:n])
	sig.S.FillBytes(out[n:])
	return out, nil
}

// PublicKey returns the public key of a purpose, with its RFC 7638 thumbprint. For the token-signing purpose it
// carries the chain of the key's certificate (tokenChain) once ca has made one; for every other purpose x5c is empty.
func (s *Server) PublicKey(ctx context.Context, req *connect.Request[keyv2alpha1.PublicKeyRequest]) (*connect.Response[keyv2alpha1.PublicKeyResponse], error) {
	caller, err := s.callerOf(ctx, "public-key")
	if err != nil {
		return nil, err
	}
	purpose := req.Msg.GetPurpose()
	if !registry.KeyAllows(caller, registry.ScopeBoundary, purpose, "public-key") {
		return nil, s.refuse(ctx, caller, "public-key", purpose, "", connect.CodePermissionDenied, reasonRule, "purpose")
	}
	pk, ok := s.planned(purpose)
	if !ok {
		return nil, s.refuse(ctx, caller, "public-key", purpose, "", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	out := &keyv2alpha1.PublicKeyResponse{SpkiDer: pk.spki, KeyId: pk.keyID, Algorithm: pk.algorithm}
	if purpose == tokenPurpose {
		out.X5C, out.X5CWithdrawn = s.tokenChainState(ctx, pk)
	}
	return connect.NewResponse(out), nil
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

// macTag is the construction of Mac (REQ-KEYS-042): HMAC-SHA384 (RFC 2104 with SHA-384, the vectors of RFC 4231)
// under the data key, over the label's length as 16 bits big-endian, the label and the input. The epoch of a
// pseudonym is not in the input: it chooses the key's generation. The label is at most maxLabel bytes.
func macTag(key []byte, label string, input []byte) []byte {
	return hmacSHA384(key, binary.BigEndian.AppendUint16(nil, uint16(len(label))), []byte(label), input) //nolint:gosec // bounded by maxLabel
}

// hmacSHA384 is HMAC-SHA384 under key over the parts, one after the other.
func hmacSHA384(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha512.New384, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// Mac makes a keyed hash with HMAC-SHA384 over a data key (ADR 0006, "Sign and Mac"): the label is bound into
// the input as u16 length | label | input, so two uses never produce the same hash for the same input. The
// purposes are mac (the boundary's), pseudonym (a tenant's, by epoch) and pairwise (a tenant's). MacRequest.grant
// is checked only to make a tenant's first pairwise key (mayMake); a key that exists is used by rule alone.
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
	scope := registry.ScopeTenant
	if purpose == "mac" {
		scope = registry.ScopeBoundary
	}
	if !registry.KeyAllows(caller, scope, purpose, "mac") {
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
	if !labelAllowed(caller, m.GetLabel()) {
		return nil, s.refuse(ctx, caller, "mac", purpose, tenant, connect.CodePermissionDenied, reasonRule, "label")
	}
	// The tenant's first pairwise key is made under a grant that names the tenant. The pseudonym key is not (the audit
	// emitters of every actor make it, and none holds a grant): that is reported, not decided here.
	create := true
	if purpose != "pseudonym" {
		if create, err = s.mayMake(ctx, newGrantState(m.GetGrant()), caller, "mac", tenant); err != nil {
			return nil, s.keyFailure(ctx, caller, "mac", purpose, tenant, err, false)
		}
	}
	var tag []byte
	mac := func(key []byte) error {
		tag = macTag(key, m.GetLabel(), m.GetInput())
		return nil
	}
	if ref := (keyRef{tenant, purpose, generation}); create {
		err = s.withKey(ctx, ref, true, mac)
	} else {
		err = s.withExistingKey(ctx, ref, mac)
	}
	if errors.Is(err, errNoKey) && !create {
		return nil, s.refuse(ctx, caller, "mac", purpose, tenant, connect.CodePermissionDenied, reasonGrant, "grant")
	}
	if err != nil {
		return nil, s.keyFailure(ctx, caller, "mac", purpose, tenant, err, false)
	}
	return connect.NewResponse(&keyv2alpha1.MacResponse{Mac: tag}), nil
}
