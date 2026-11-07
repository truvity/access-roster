package keyd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/truvity/sluis/v2/actors/key/internal/content"
	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// The token certificate, on key@'s side (ADR 0023, "Leaf profiles"; ADR 0006, "The token-signing key"). `ca` builds the
// TBSCertificate of the certificate that the node's intermediate gives to the token-signing key and asks key@ to sign it
// (Sign, purpose x509-intermediate; sign.go). key@ signs only that structure (content.TokenCertificate). `ca` then
// assembles the certificate and hands it back (PutCertificate), and key@ checks it again and keeps it as the
// KeyCertificate of the token-signing key, so that PublicKey can give the chain to signer. key@ is the only writer of
// KeyCertificate, and ca can write nothing there that key@ would not have signed.

// tokenPurpose is the purpose whose key the token certificate certifies.
const tokenPurpose = "token-signing"

var errNoIntermediate = errors.New("keyd: no intermediate installed")

// certificatesByID lists KeyCertificate whole, by id. The kind is small (a wrapping key for each node, an intermediate, a
// token certificate) and it is listed, never asked for by id: store@ audits a refusal for an absent item, and "not there
// yet" is the expected answer (ADR 0005; REQ-AUDIT-180).
func (s *Server) certificatesByID(ctx context.Context) (map[string]*keyv2alpha1.KeyCertificate, error) {
	out := map[string]*keyv2alpha1.KeyCertificate{}
	for token := ""; ; {
		items, next, err := s.certs.List(ctx, "", store.PageSize(200), store.PageToken(token))
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			out[it.ID] = it.Value
		}
		if next == "" {
			return out, nil
		}
		token = next
	}
}

// tokenCert is what key@ holds to certify the token-signing key: the intermediate and the rules built from it.
type tokenCert struct {
	rules    content.TokenCertificateRules
	issuer   *x509.Certificate
	chain    [][]byte // the installed chain of the intermediate, leaf first
	sequence int64
	all      map[string]*keyv2alpha1.KeyCertificate
}

// tokenCertificateRules reads the installed intermediate of this node and returns the rules a token certificate must
// meet. It returns errNoIntermediate when none is installed, and another error when store@ failed.
func (s *Server) tokenCertificateRules(ctx context.Context) (content.TokenCertificateRules, *tokenCert, error) {
	inter, ok := s.planned(handoffPurpose)
	tok, ok2 := s.planned(tokenPurpose)
	if !ok || !ok2 || inter.algorithm != algES384 || tok.algorithm != algES384 {
		return content.TokenCertificateRules{}, nil, errNoIntermediate
	}
	all, err := s.certificatesByID(ctx)
	if err != nil {
		return content.TokenCertificateRules{}, nil, err
	}
	cur := all[handoffPurpose+"/"+recipientLabel(inter.keyID)]
	if cur == nil || len(cur.GetChain()) == 0 {
		return content.TokenCertificateRules{}, nil, errNoIntermediate
	}
	c, err := x509.ParseCertificate(cur.GetChain()[0])
	if err != nil || !bytes.Equal(c.RawSubjectPublicKeyInfo, inter.spki) {
		return content.TokenCertificateRules{}, nil, errNoIntermediate
	}
	r := content.TokenCertificateRules{
		Issuer: c.RawSubject, IssuerKeyID: c.SubjectKeyId, SPKI: tok.spki, Boundary: s.cfg.Boundary,
		IssuerNotBefore: c.NotBefore, IssuerNotAfter: c.NotAfter, Now: s.now(),
	}
	return r, &tokenCert{rules: r, issuer: c, chain: cur.GetChain(), sequence: cur.GetTrustSequence(), all: all}, nil
}

// refuseTokenCertificate refuses a call that could not read the intermediate.
func (s *Server) refuseTokenCertificate(ctx context.Context, caller, op, purpose string, err error) error {
	if errors.Is(err, errNoIntermediate) {
		return s.refuse(ctx, caller, op, purpose, "", connect.CodeFailedPrecondition, reasonIntermediate, "intermediate")
	}
	return s.refuse(ctx, caller, op, purpose, "", connect.CodeUnavailable, reasonStore, "")
}

// tokenCertificateID is the id of the KeyCertificate of the token-signing key.
func tokenCertificateID(pk purposeKey) string { return tokenPurpose + "/" + recipientLabel(pk.keyID) }

// tokenChain is the chain for the x5c member of the token-signing key's entry (see tokenChainState).
func (s *Server) tokenChain(ctx context.Context, pk purposeKey) [][]byte {
	chain, _ := s.tokenChainState(ctx, pk)
	return chain
}

// tokenChainState is the chain for the x5c member of the token-signing key's entry: the token certificate, then the chain of
// the intermediate installed now. It is empty when there is none, and also when what is stored no longer fits: the
// certificate is for another key, it has not begun or has ended, or the installed intermediate did not sign it. A
// certificate that an earlier certificate of the intermediate's key signed is still given after the intermediate was
// renewed, as long as it verifies under the renewed one and names it as issuer (same key, same subject): the key set has
// no gap while ca makes the certificate again (ADR 0023). Nothing is given while either key is revoked.
//
// withdrawn tells an empty answer that means "take it down" from one that means "none yet": it is true when a certificate
// is stored for the key and is not given because it does not serve (ended, not begun, not signed by the installed
// intermediate, or the intermediate or the key is revoked, as KeyRevocation says). When the kinds cannot be read, or
// KeyRevocation cannot, key@ cannot tell and says false: a caller keeps what it has then, and the answer is true again when
// they can be read. This fails open, on purpose: a store@ outage must not take down a key set that is right, and the chain
// is custody evidence for a verifier that wants it, never what a token is checked with.
func (s *Server) tokenChainState(ctx context.Context, pk purposeKey) (chain [][]byte, withdrawn bool) {
	all, err := s.certificatesByID(ctx)
	if err != nil {
		slog.Warn("KeyCertificate cannot be read: no x5c")
		return nil, false
	}
	cur := all[tokenCertificateID(pk)]
	if cur == nil || len(cur.GetChain()) == 0 {
		return nil, false
	}
	// A certificate is stored for the key. From here every way of not giving it is a withdrawal, and that includes a plan that
	// no longer has the intermediate, or has another one with nothing installed: the chain under an intermediate that is not
	// this node's now must not stay in the key set (the intermediate may have been revoked and dropped from the plan).
	inter, ok := s.planned(handoffPurpose)
	if !ok || inter.algorithm != algES384 {
		return nil, true
	}
	ic := all[handoffPurpose+"/"+recipientLabel(inter.keyID)]
	if ic == nil || len(ic.GetChain()) == 0 {
		return nil, true
	}
	issuer, err := x509.ParseCertificate(ic.GetChain()[0])
	if err != nil || !bytes.Equal(issuer.RawSubjectPublicKeyInfo, inter.spki) {
		return nil, true
	}
	leaf, err := x509.ParseCertificate(cur.GetChain()[0])
	if err != nil || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, pk.spki) || !bytes.Equal(leaf.RawIssuer, issuer.RawSubject) || leaf.CheckSignatureFrom(issuer) != nil {
		return nil, true
	}
	if now := s.now(); now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, true
	}
	for _, k := range []purposeKey{pk, inter} {
		target, err := s.revoked(ctx, k)
		if err != nil {
			return nil, false
		}
		if target != "" {
			return nil, true
		}
	}
	return append([][]byte{cur.GetChain()[0]}, ic.GetChain()...), false
}

// PutCertificate keeps the token certificate that ca made. key@ does not take ca's word for it: the certificate must be
// the one key@ signs (the structure of content.TokenCertificate, with the standard library's reading of it besides),
// it must verify under the intermediate's key, and it must certify the token-signing key of this node. The chain stored is
// the certificate and the intermediate's chain as installed. A revoked key of either purpose stores nothing. The write
// is audited, durably, before it is made; storing the same chain again writes nothing.
func (s *Server) PutCertificate(ctx context.Context, req *connect.Request[keyv2alpha1.PutCertificateRequest]) (*connect.Response[keyv2alpha1.PutCertificateResponse], error) {
	const op = "put-certificate"
	caller, err := s.callerOf(ctx, op)
	if err != nil {
		return nil, err
	}
	purpose := req.Msg.GetPurpose()
	if purpose != tokenPurpose {
		// A purpose the caller chose is not echoed: the refusal names a fixed one.
		return nil, s.refuse(ctx, caller, op, "other", "", connect.CodeInvalidArgument, reasonPurpose, "purpose")
	}
	if !s.allows(caller, registry.ScopeBoundary, handoffPurpose, "certify") {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodePermissionDenied, reasonRule, "purpose")
	}
	inter, ok := s.planned(handoffPurpose)
	tok, ok2 := s.planned(tokenPurpose)
	if !ok || !ok2 || inter.algorithm != algES384 || tok.algorithm != algES384 {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeFailedPrecondition, reasonPurpose, "purpose")
	}
	for _, pk := range []purposeKey{inter, tok} {
		target, err := s.revoked(ctx, pk)
		if err != nil {
			slog.Warn("KeyRevocation cannot be read: no PutCertificate")
			return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeUnavailable, reasonRevocationUnreadable, "")
		}
		if target != "" {
			return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodePermissionDenied, reasonRevoked, target)
		}
	}
	der := req.Msg.GetCertificate()
	if len(der) == 0 || len(der) > maxCertificate {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeInvalidArgument, reasonSchema, "certificate")
	}
	rules, tc, err := s.tokenCertificateRules(ctx)
	if err != nil {
		return nil, s.refuseTokenCertificate(ctx, caller, op, purpose, err)
	}
	leaf, err := content.CheckTokenCertificate(der, rules, tc.issuer)
	if err != nil {
		path := "certificate"
		var ce *content.ErrContent
		if errors.As(err, &ce) {
			path = ce.Path
		}
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeInvalidArgument, reasonContent, path)
	}
	// The signature verifies under the key key@ holds, not only under the installed certificate's copy of it.
	digest := sha512.Sum384(leaf.RawTBSCertificate)
	if !ecdsa.VerifyASN1(inter.pub, digest[:], leaf.Signature) {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeInvalidArgument, reasonContent, "content.signature")
	}
	chain := append([][]byte{der}, tc.chain...)
	id := tokenCertificateID(tok)
	// One write at a time, as Install: the guard reads the stored chain and the write replaces it.
	s.handoffMu.Lock()
	defer s.handoffMu.Unlock()
	all, err := s.certificatesByID(ctx)
	if err != nil {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeUnavailable, reasonStore, "")
	}
	// The hashes tie the store to the signature: tbs_sha384 is the one key.sign names, leaf_sha384 the certificate.
	tbsSum, leafSum := sha512.Sum384(leaf.RawTBSCertificate), sha512.Sum384(der)
	fact := map[string]any{
		"purpose": purpose, "key_id": tok.keyID, "caller": caller, "chain_length": int64(len(chain)),
		"trust_sequence": tc.sequence, "replace": false,
		"tbs_sha384": hex.EncodeToString(tbsSum[:]), "leaf_sha384": hex.EncodeToString(leafSum[:]),
		// The serial number and the end of the validity make the certificate findable in the audit log. The serial number is the
		// content octets of the INTEGER (at most 17 for a 128-bit number): hex of the big-endian bytes, which is what a
		// certificate viewer shows.
		"serial": hex.EncodeToString(leaf.SerialNumber.Bytes()), "not_after": leaf.NotAfter.Unix(),
	}
	replaced := false
	if cur := all[id]; cur != nil {
		if sameChain(cur.GetChain(), chain) {
			return connect.NewResponse(&keyv2alpha1.PutCertificateResponse{Id: id, Already: true}), nil
		}
		replaced = true
		// The rule of Install: a certificate does not replace one that serves as well or better. It replaces a stored one that
		// ends earlier (a renewal), or that has ended, or that the installed intermediate did not sign; or the caller says
		// so, and the fact shows it. Without the rule a valid certificate with a nearer end would shorten the published chain.
		old, oerr := x509.ParseCertificate(firstOf(cur.GetChain()))
		if oerr == nil {
			fact["previous_not_after"] = old.NotAfter.Unix()
		}
		serves := oerr == nil && s.now().Before(old.NotAfter) && !s.now().Before(old.NotBefore) && old.CheckSignatureFrom(tc.issuer) == nil &&
			bytes.Equal(old.RawIssuer, tc.issuer.RawSubject) && bytes.Equal(old.RawSubjectPublicKeyInfo, tok.spki)
		if serves && !leaf.NotAfter.After(old.NotAfter) && !req.Msg.GetReplace() {
			return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeFailedPrecondition, reasonStale, "certificate")
		}
		fact["replace"] = req.Msg.GetReplace()
	}
	if err := s.auditBlocking(ctx, Event{Action: ActionCertificateInstall, Fields: fact}); err != nil {
		return nil, unavailable(reasonAudit)
	}
	_, err = s.certs.Apply(ctx, "", id, &keyv2alpha1.KeyCertificate{
		Purpose: tokenPurpose, Recipient: recipientLabel(tok.keyID), SpkiDer: tok.spki, Chain: chain, AddedAt: timestamppb.New(s.now()),
		TrustSequence: tc.sequence,
	}, store.WithIndex(indexByPurpose, []byte(tokenPurpose)))
	if err != nil {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeUnavailable, reasonStore, "")
	}
	return connect.NewResponse(&keyv2alpha1.PutCertificateResponse{Id: id, Replaced: replaced}), nil
}

// TokenKey tells ca which key it certifies and whether key@ has a chain for it that fits. The registry gives the
// token-signing key to signer alone, so ca has no rule to ask for its public key (check-registries); this call is the
// one place ca learns it, and only ca, by its rule for the intermediate, may ask. It says what PublicKey would say to
// signer and nothing more.
func (s *Server) TokenKey(ctx context.Context, _ *connect.Request[keyv2alpha1.TokenKeyRequest]) (*connect.Response[keyv2alpha1.TokenKeyResponse], error) {
	const op = "token-key"
	caller, err := s.callerOf(ctx, op)
	if err != nil {
		return nil, err
	}
	if !s.allows(caller, registry.ScopeBoundary, handoffPurpose, "certify") {
		return nil, s.refuse(ctx, caller, op, tokenPurpose, "", connect.CodePermissionDenied, reasonRule, "purpose")
	}
	// A plan without a token-signing key is a plan without anything to certify, not a mistake of ca's: the answer is empty and
	// nothing is refused, so that a ca that looks every few seconds writes no record each time (REQ-AUDIT-180).
	tok, ok := s.planned(tokenPurpose)
	if !ok || tok.algorithm != algES384 {
		return connect.NewResponse(&keyv2alpha1.TokenKeyResponse{}), nil
	}
	out := &keyv2alpha1.TokenKeyResponse{SpkiDer: tok.spki, KeyId: tok.keyID, Chain: s.tokenChain(ctx, tok)}
	if inter, ok := s.planned(handoffPurpose); ok && inter.algorithm == algES384 {
		out.IntermediateSpkiDer = inter.spki
	}
	return connect.NewResponse(out), nil
}
