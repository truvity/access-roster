package keyd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
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

// certificates lists KeyCertificate whole, by id. The kind is small (a wrapping key for each node, an intermediate, a
// token certificate) and it is listed, never asked for by id: store@ audits a refusal for an absent item, and "not there
// yet" is the expected answer (ADR 0005; REQ-AUDIT-180).
func (s *Server) certificates(ctx context.Context) (map[string]*keyv2alpha1.KeyCertificate, error) {
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
	all, err := s.certificates(ctx)
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

// tokenChain is the chain for the x5c member of the token-signing key's entry: the token certificate, then the chain of
// the intermediate that signed it, as stored. It is empty when there is none, and also when what is stored no longer
// fits: the certificate is for another key, it has ended, or the intermediate was replaced since (ca makes the certificate
// again over the same key when its intermediate is renewed, ADR 0023). An empty answer is the truth then; a store@ failure
// is also an empty answer, logged, and the caller asks again.
func (s *Server) tokenChain(ctx context.Context, pk purposeKey) [][]byte {
	_, tc, err := s.tokenCertificateRules(ctx)
	if err != nil {
		if !errors.Is(err, errNoIntermediate) {
			slog.Warn("KeyCertificate cannot be read: no x5c")
		}
		return nil
	}
	cur := tc.all[tokenCertificateID(pk)]
	if cur == nil || len(cur.GetChain()) != 1+len(tc.chain) {
		return nil
	}
	for i, der := range tc.chain {
		if !bytes.Equal(cur.GetChain()[1+i], der) {
			return nil
		}
	}
	leaf, err := x509.ParseCertificate(cur.GetChain()[0])
	if err != nil || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, pk.spki) {
		return nil
	}
	if now := s.now(); now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil
	}
	return cur.GetChain()
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
	// ca signs for the intermediate; the same rule lets it hand the result back.
	if !registry.KeyAllows(caller, registry.ScopeBoundary, handoffPurpose, "sign") {
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
	all, err := s.certificates(ctx)
	if err != nil {
		return nil, s.refuse(ctx, caller, op, purpose, "", connect.CodeUnavailable, reasonStore, "")
	}
	fact := map[string]any{
		"purpose": purpose, "key_id": tok.keyID, "caller": caller, "chain_length": int64(len(chain)),
		"trust_sequence": tc.sequence, "replace": false,
	}
	replaced := false
	if cur := all[id]; cur != nil {
		if sameChain(cur.GetChain(), chain) {
			return connect.NewResponse(&keyv2alpha1.PutCertificateResponse{Id: id, Already: true}), nil
		}
		replaced = true
		if old, oerr := x509.ParseCertificate(firstOf(cur.GetChain())); oerr == nil {
			fact["previous_not_after"] = old.NotAfter.Unix()
		}
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
