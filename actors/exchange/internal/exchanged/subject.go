package exchanged

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"
	"google.golang.org/protobuf/types/known/timestamppb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	exchangev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/exchange/v2alpha1"
	signerv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1/signerv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// KindOwn is the Kind of a Subject that this boundary's own issuer signed.
const KindOwn = "own"

const (
	// maxToken bounds a subject token. An access token of the first version is under 2 KiB.
	maxToken = 16 << 10

	// skew is the leeway for the clocks of the two sides, on iat and nbf. exp has none: a token that has expired is
	// over.
	skew = 30 * time.Second

	// refetchGap is how soon a key set is fetched again for a key id it does not hold. A rotation shows within the
	// gap, and an unknown kid cannot be used to flood the signer or an issuer.
	refetchGap = 30 * time.Second

	// ownSetTTL is how long the key set of the boundary's own issuer is kept in memory.
	ownSetTTL = time.Minute

	// maxKeys bounds a key set of an issuer.
	maxKeys = 32

	// minRSABits is the smallest RSA key a trusted issuer may sign with.
	minRSABits = 2048

	// replayCap is the longest a proof may stay valid and still be guarded: the maximum of the kind ReplayGuard.
	replayCap = time.Hour
)

// Subject is a verified subject token: the claims exchange reads, never the token itself.
type Subject struct {
	// Kind is KindOwn, or the proof kind of the trusted issuer that signed the token (ADR 0022).
	Kind     string
	Issuer   string
	Subject  string // sub
	Audience string // aud, the one client id
	ClientID string // client_id, the client the token was issued to
	JTI      string
	SID      string // sid, the session chain that backs the token

	ACR         *string
	AMR         []string
	AMRPresent  bool
	AuthTime    *int64
	Issued, Exp time.Time
}

// Verifier checks subject tokens (RFC 8693 section 2.1, subject_token; ADR 0022, "Proofs and the exchange"). It holds
// public material only: the key set of the boundary's own issuer, from signer, and the key sets of the issuers that
// ExchangeTrust names.
type Verifier struct {
	cfg    *Config
	signer signerv2alpha1connect.SignerServiceClient
	now    func() time.Time
	dev    *http.Client
	strict *http.Client

	mu        sync.Mutex
	own       *jose.JSONWebKeySet
	ownAt     time.Time
	ownTried  time.Time
	triedKeys map[string]time.Time // issuer -> the last fetch for an unknown kid
}

// NewVerifier returns the verifier. now is the clock; nil means time.Now.
func NewVerifier(cfg *Config, signer signerv2alpha1connect.SignerServiceClient, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		cfg: cfg, signer: signer, now: now,
		dev: newHTTPClient(true), strict: newHTTPClient(false),
		triedKeys: map[string]time.Time{},
	}
}

func (v *Verifier) client(dev bool) *http.Client {
	if dev {
		return v.dev
	}
	return v.strict
}

// Verify checks a subject token: its signature against the keys of its issuer, then its claims. The issuer is the
// boundary's own, or one that ExchangeTrust names; any other is refused (REQ-EXCH-006). It returns an answer in the
// form of the token endpoint for a token that is not acceptable, and an outage for a dependency that did not answer.
func (v *Verifier) Verify(ctx context.Context, raw string, b *configv2alpha1.Boundary) (*Subject, error) {
	if raw == "" || len(raw) > maxToken {
		return nil, invalidRequest(reasonSubjectToken)
	}
	tok, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.ES384, jose.ES256, jose.RS256})
	if err != nil || len(tok.Signatures) != 1 {
		// Not a compact JWS, or an algorithm outside the list: none, HS256 and the rest never get as far as a key.
		return nil, invalidRequest(reasonSignature)
	}
	// The issuer picks the keys, and only the keys. Nothing else of the unverified payload is read before the
	// signature has verified.
	var peek struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(tok.UnsafePayloadWithoutVerification(), &peek) != nil || peek.Iss == "" {
		return nil, invalidRequest(reasonClaims)
	}
	if peek.Iss == b.GetIssuer() {
		return v.verifyOwn(ctx, tok)
	}
	trust, err := v.cfg.Trust(ctx)
	if err != nil {
		return nil, unavailable("store", err)
	}
	for _, ti := range trust.GetIssuers() {
		if ti.GetIssuer() == peek.Iss {
			return v.verifyTrusted(ctx, tok, ti, b)
		}
	}
	return nil, invalidRequest(reasonIssuer)
}

// verifyOwn checks a token that the boundary's own issuer signed: ES384, typ at+jwt (RFC 9068 section 4), and a
// client that the boundary registered.
func (v *Verifier) verifyOwn(ctx context.Context, tok *jose.JSONWebSignature) (*Subject, error) {
	sig := tok.Signatures[0]
	if sig.Header.Algorithm != string(jose.ES384) {
		return nil, invalidRequest(reasonSignature)
	}
	// RFC 9068 section 4: a resource server checks typ, so that an ID token cannot be taken for an access token.
	if typ, _ := sig.Protected.ExtraHeaders[jose.HeaderType].(string); typ != "at+jwt" {
		return nil, invalidRequest(reasonSignature)
	}
	payload, err := v.verifyWith(tok, sig.Header.KeyID, func(refresh bool) (*jose.JSONWebKeySet, error) { return v.ownKeys(ctx, refresh) })
	if err != nil {
		return nil, err
	}
	s, err := v.claims(payload, v.now())
	if err != nil {
		return nil, err
	}
	s.Kind = KindOwn
	if s.JTI == "" || s.ClientID == "" || s.Audience == "" || s.Audience != s.ClientID {
		// A token that the boundary issued to a client carries that client as aud and client_id (ADR 0020). A
		// token that names another audience is an exchanged token or a token for a relying party, and neither may
		// be exchanged again: an exchange only narrows (REQ-EXCH-004).
		return nil, invalidRequest(reasonClaims)
	}
	if _, err := v.cfg.Client(ctx, s.ClientID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, invalidRequest(reasonClient)
		}
		return nil, unavailable("store", err)
	}
	return s, nil
}

// verifyTrusted checks a token of an issuer that ExchangeTrust names: the keys are the issuer's published ones, the
// audience is one the entry accepts, and a proof with a jti is accepted once (ADR 0022: ReplayGuard).
func (v *Verifier) verifyTrusted(ctx context.Context, tok *jose.JSONWebSignature, ti *configv2alpha1.TrustedIssuer, b *configv2alpha1.Boundary) (*Subject, error) {
	// A proof kind of "own" would make a trusted issuer's token pass for a token of this boundary.
	if ti.GetProofKind() == "" || ti.GetProofKind() == KindOwn || ti.GetJwksUri() == "" || len(ti.GetAudiences()) == 0 {
		return nil, invalidRequest(reasonIssuer)
	}
	sig := tok.Signatures[0]
	payload, err := v.verifyWith(tok, sig.Header.KeyID, func(refresh bool) (*jose.JSONWebKeySet, error) {
		return v.trustedKeys(ctx, ti, development(b), refresh)
	})
	if err != nil {
		return nil, err
	}
	now := v.now()
	s, err := v.claims(payload, now)
	if err != nil {
		return nil, err
	}
	s.Kind = ti.GetProofKind()
	if !contains(ti.GetAudiences(), s.Audience) && !audienceIn(payload, ti.GetAudiences()) {
		return nil, invalidRequest(reasonClaims)
	}
	if s.JTI != "" {
		if err := v.guard(ctx, s, now); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// audienceIn says whether an aud that is an array holds one of the accepted audiences (RFC 7519 section 4.1.3).
func audienceIn(payload []byte, accepted []string) bool {
	var m struct {
		Aud []string `json:"aud"`
	}
	if json.Unmarshal(payload, &m) != nil {
		return false
	}
	for _, a := range m.Aud {
		if contains(accepted, a) {
			return true
		}
	}
	return false
}

// guard marks the proof as presented, and refuses a proof that was (ADR 0022: a proof that carries a jti is checked
// against ReplayGuard). The id is the hash of the issuer and the jti, so the store shows neither. The mark lives as
// long as the proof is valid; a proof that is valid for longer than the kind allows cannot be guarded and is refused.
func (v *Verifier) guard(ctx context.Context, s *Subject, now time.Time) error {
	left := s.Exp.Sub(now)
	if left <= 0 {
		return invalidRequest(reasonExpired)
	}
	if left > replayCap {
		return invalidRequest(reasonReplay)
	}
	h := sha512.New384()
	h.Write([]byte(s.Issuer))
	h.Write([]byte{0})
	h.Write([]byte(s.JTI))
	id := "exchange/" + hex.EncodeToString(h.Sum(nil))
	_, err := v.cfg.replay.Create(ctx, "", id, &exchangev2alpha1.ReplayGuard{SeenAt: timestamppb.New(now)}, store.WithTTL(left))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrExists):
		return invalidRequest(reasonReplay)
	}
	return unavailable("store", err)
}

// verifyWith verifies the token with the key of kid, from the set that keys returns. A key id the set does not
// hold, or a signature that does not verify, makes one fresh fetch (a key rotation), which the callers limit.
func (v *Verifier) verifyWith(tok *jose.JSONWebSignature, kid string, keys func(refresh bool) (*jose.JSONWebKeySet, error)) ([]byte, error) {
	for _, refresh := range []bool{false, true} {
		set, err := keys(refresh)
		if err != nil {
			return nil, err
		}
		candidates := set.Keys
		if kid != "" {
			candidates = set.Key(kid)
		}
		for _, k := range candidates {
			if k.Use != "" && k.Use != "sig" {
				continue
			}
			if rk, ok := k.Key.(*rsa.PublicKey); ok && rk.N.BitLen() < minRSABits {
				continue
			}
			if b, err := tok.Verify(k); err == nil {
				return b, nil
			}
		}
	}
	return nil, invalidRequest(reasonSignature)
}

// ownKeys returns the key set of the boundary's own issuer, from signer (ADR 0017: the key set is the kind
// SigningRing, which signer writes; exchange is not a reader of the kind, so it asks signer for it).
func (v *Verifier) ownKeys(ctx context.Context, refresh bool) (*jose.JSONWebKeySet, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	if v.own != nil && now.Sub(v.ownAt) < ownSetTTL && (!refresh || now.Sub(v.ownTried) < refetchGap) {
		return v.own, nil
	}
	if refresh {
		v.ownTried = now
	}
	res, err := v.signer.KeySet(ctx, connect.NewRequest(&signerv2alpha1.KeySetRequest{}))
	if err != nil {
		if v.own != nil {
			// A key set that was good a minute ago still checks a signature; a stale set is never used past
			// ownSetTTL, so the signer being down for longer than that fails closed.
			if now.Sub(v.ownAt) < ownSetTTL {
				return v.own, nil
			}
		}
		return nil, unavailable("signer", err)
	}
	set, err := parseSet(res.Msg.GetJwksJson())
	if err != nil {
		return nil, unavailable("signer", err)
	}
	v.own, v.ownAt = set, now
	return set, nil
}

// parseSet reads a JWK Set (RFC 7517 section 5): public keys only, at most maxKeys.
func parseSet(b []byte) (*jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, errors.New("not a JWK Set")
	}
	if len(set.Keys) == 0 || len(set.Keys) > maxKeys {
		return nil, errors.New("no key, or too many")
	}
	out := set.Keys[:0]
	for _, k := range set.Keys {
		if k.Valid() && k.IsPublic() {
			out = append(out, k)
		}
	}
	set.Keys = out
	if len(set.Keys) == 0 {
		return nil, errors.New("no usable key")
	}
	return &set, nil
}

// trustedKeys returns the key set of a trusted issuer: from VerifierKeyCache while it is fresh, otherwise fetched
// from the issuer's jwks_uri and kept for as long as HTTP caching allows, 24 hours at most (ADR 0022). A refresh
// fetches again, at most once in refetchGap for the issuer.
func (v *Verifier) trustedKeys(ctx context.Context, ti *configv2alpha1.TrustedIssuer, dev, refresh bool) (*jose.JSONWebKeySet, error) {
	sum := sha256.Sum256([]byte(ti.GetIssuer()))
	id := hex.EncodeToString(sum[:])
	now := v.now()
	var cached *jose.JSONWebKeySet
	it, err := v.cfg.keys.Get(ctx, "", id)
	switch {
	case err == nil:
		if cached, err = parseSet(it.Value.GetJwksJson()); err != nil {
			cached = nil
		}
	case !errors.Is(err, store.ErrNotFound):
		return nil, unavailable("store", err)
	}
	if cached != nil && !refresh {
		return cached, nil
	}
	v.mu.Lock()
	if refresh && cached != nil && now.Sub(v.triedKeys[ti.GetIssuer()]) < refetchGap {
		v.mu.Unlock()
		return cached, nil
	}
	v.triedKeys[ti.GetIssuer()] = now
	v.mu.Unlock()

	f, err := get(ctx, v.client(dev), ti.GetJwksUri(), dev)
	if err != nil {
		if cached != nil {
			return cached, nil
		}
		return nil, unavailable("issuer_keys", err)
	}
	set, err := parseSet(f.body)
	if err != nil {
		return nil, unavailable("issuer_keys", err)
	}
	if f.ttl > 0 {
		_, err := v.cfg.keys.Apply(ctx, "", id, &exchangev2alpha1.VerifierKeyCache{
			Issuer: ti.GetIssuer(), JwksJson: f.body, FetchedAt: timestamppb.New(now),
		}, store.WithTTL(f.ttl))
		if err != nil {
			return nil, unavailable("store", err)
		}
	}
	return set, nil
}

// claims reads the claims of a token whose signature verified, and checks the ones every subject token needs: iss,
// sub and the times (RFC 7519 sections 4.1.1 to 4.1.7). The caller checks the rest.
func (v *Verifier) claims(payload []byte, now time.Time) (*Subject, error) {
	var m map[string]json.RawMessage
	if json.Unmarshal(payload, &m) != nil {
		return nil, invalidRequest(reasonClaims)
	}
	bad := false
	text := func(name string) string {
		raw, ok := m[name]
		if !ok {
			return ""
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			bad = true
		}
		return s
	}
	integer := func(name string) *int64 {
		raw, ok := m[name]
		if !ok {
			return nil
		}
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil || n < 0 {
			bad = true
			return nil
		}
		return &n
	}
	s := Subject{
		Issuer: text("iss"), Subject: text("sub"), ClientID: text("client_id"), JTI: text("jti"), SID: text("sid"),
		AuthTime: integer("auth_time"),
	}
	if raw, ok := m["aud"]; ok {
		// An access token has one audience (ADR 0017). A trusted issuer's may be an array; the caller reads it.
		var a string
		if json.Unmarshal(raw, &a) == nil {
			s.Audience = a
		}
	}
	if _, ok := m["acr"]; ok {
		a := text("acr")
		if a == "" {
			bad = true
		}
		s.ACR = &a
	}
	if raw, ok := m["amr"]; ok {
		if json.Unmarshal(raw, &s.AMR) != nil {
			bad = true
		}
		s.AMRPresent = true
	}
	exp, iat, nbf := integer("exp"), integer("iat"), integer("nbf")
	if bad || s.Issuer == "" || s.Subject == "" || exp == nil {
		return nil, invalidRequest(reasonClaims)
	}
	s.Exp = time.Unix(*exp, 0)
	if !s.Exp.After(now) {
		return nil, invalidRequest(reasonExpired)
	}
	if iat != nil {
		s.Issued = time.Unix(*iat, 0)
		if s.Issued.After(now.Add(skew)) {
			return nil, invalidRequest(reasonClaims)
		}
	}
	if nbf != nil && time.Unix(*nbf, 0).After(now.Add(skew)) {
		return nil, invalidRequest(reasonClaims)
	}
	return &s, nil
}
