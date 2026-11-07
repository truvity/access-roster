package sessiond

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	signerv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// The bearer check: what an endpoint of session that takes a sluis access token as a bearer token (RFC 6750) runs
// first, and the only place that decides whether a bearer token is good (REQ-SEC-038). A new bearer endpoint calls
// bearer and reads nothing of the token before it has answered.
//
// A token is good when all of this holds, and an endpoint gets nothing else:
//
//   - Type. The header's typ is at+jwt (RFC 9068 section 4) and the algorithm is ES384. An ID token has typ JWT, and an ID
//     token is handed to relying parties and sits in their logs, so it is not a credential.
//   - Signature. It verifies against the issuer's key set, which signer serves without a revoked key. A token signed by a
//     key that has been revoked therefore fails within keySetTTL (the set is kept that long, and fetched again at once for
//     a kid it does not hold, at most once in refetchGap).
//   - Claims. iss is this issuer, exp is in the future (no leeway), iat (and nbf, if present) is not in this clock's future by more
//     than a minute, and aud, client_id, sub, sid and jti are present. aud is
//     the client the token was issued to: a token for another audience (the product of a token exchange) is not served.
//   - Client. client_id is a client the installation declares.
//   - Session. The chain that sid names is there, belongs to that client, and has not reached its absolute or idle limit.
//     A chain that is gone (signed out, revoked, reused, expired, lost with the temp engine) makes the token not good,
//     whatever its exp says. See sessionLive for how fresh that is.
//   - Scope. The chain's scope holds the scope the endpoint needs.
//
// Every failure but the last answers 401 invalid_token in the same words, so a caller cannot tell which check refused; the
// audit record and the log name the closed reason. The last answers 403 insufficient_scope (RFC 6750 section 3.1). What
// is not served here: recalling a token that was issued before its session ended, for a resource server that checks the
// signature and exp alone (REQ-SESS-055).

const (
	// maxBearerHeader bounds an Authorization header. An access token of sluis is under 2 KiB.
	maxBearerHeader = 4096

	// keySetTTL is how long the issuer's key set is kept in memory, and so how long a token signed by a key that has just been
	// revoked is still accepted by this check.
	keySetTTL = 10 * time.Second

	// refetchGap is how soon a key set is fetched again for a key id it does not hold: a rotation shows within the gap, and
	// a token with a made-up kid cannot be used to flood signer.
	refetchGap = 30 * time.Second

	// maxSetKeys bounds the key set of the issuer.
	maxSetKeys = 32

	// endedCap bounds the memory of ended chains.
	endedCap = 4096

	// bearerSkew is the leeway for the clocks of the two sides on iat and nbf, the same minute that signer allows. exp has
	// none: a token that has expired is over.
	bearerSkew = time.Minute

	// keyFetchTimeout bounds a fetch of the key set.
	keyFetchTimeout = 5 * time.Second

	// keyFailGap is how long a failure to get the key set is remembered: while it lasts every request is answered unavailable
	// without asking signer, so a stranger's requests cannot make session hammer a signer that is down (or log for each one).
	keyFailGap = 2 * time.Second

	// clientGoneFor is how long a client that the installation does not declare is remembered as not declared. A client can be
	// added (a reload of the configuration), so unlike a chain this memory is short.
	clientGoneFor = time.Minute
)

// The closed reasons of a refused bearer token (audit status_code, log reason). They name the check that refused.
const (
	reasonBearer       = "bearer_token"  // not a valid access token of this issuer: shape, signature, claims or expiry
	reasonBearerType   = "token_type"    // the type is not at+jwt (an ID token, for one)
	reasonBearerClient = "token_client"  // the audience is not the client of the token, or the client is not declared, or the chain is another client's
	reasonSessionEnded = "session_ended" // the session chain the token names is gone or over
)

// bearerError is what a refused bearer token is answered with: RFC 6750 section 3.
type bearerError struct {
	status int
	code   string // the error of RFC 6750 section 3.1; empty when the request had no credentials
	desc   string
}

func (e *bearerError) challenge() string {
	c := `Bearer realm="sluis"`
	if e.code != "" {
		c += `, error="` + e.code + `"`
	}
	return c
}

func (e *bearerError) reply() *connect.Response[typev2alpha1.HttpReply] {
	hs := append([]*typev2alpha1.Header{header("Content-Type", "application/json"), header("WWW-Authenticate", e.challenge())}, noStore()...)
	var body []byte
	if e.code != "" {
		body, _ = json.Marshal(map[string]string{"error": e.code, "error_description": e.desc}) //nolint:errchkjson // two fixed strings
	}
	return reply(e.status, body, hs...)
}

// The errors of RFC 6750 section 3.1. The description is fixed per code.
var (
	errNoBearer     = &bearerError{status: http.StatusUnauthorized}
	errBadBearerReq = &bearerError{status: http.StatusBadRequest, code: "invalid_request", desc: "the request is malformed"}
	errInvalidToken = &bearerError{status: http.StatusUnauthorized, code: "invalid_token", desc: "the access token is invalid, expired or revoked"}
	errScope        = &bearerError{status: http.StatusForbidden, code: "insufficient_scope", desc: "the access token does not carry the scope the request needs"}
)

// accessClaims are the claims of a verified access token that an endpoint may read: sluis's own claim set (0020).
type accessClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	ClientID string `json:"client_id"`
	SID      string `json:"sid"`
	JTI      string `json:"jti"`
	Exp      *int64 `json:"exp"`
	Iat      *int64 `json:"iat"`
	Nbf      *int64 `json:"nbf"`
}

// bearerToken is a token that passed every check.
type bearerToken struct {
	claims accessClaims
	tenant string
	client *configv2alpha1.InstallationClient
	chain  *sessionv2alpha1.SessionChain
}

// bearer checks the Authorization header of a request as a bearer access token that needs `scope`. It returns the
// token when it is good. Otherwise it has recorded the refusal (action names the endpoint) and returns the answer, or an
// error when a dependency failed: the request is then not answered with a verdict, and the caller returns the error
// (unavailable, fail closed).
func (s *Service) bearer(ctx context.Context, authorization string, action audit.Action, scope string) (*bearerToken, *connect.Response[typev2alpha1.HttpReply], error) {
	b, err := s.opts.Config.Boundary(ctx)
	if err != nil {
		return nil, nil, unavailable("boundary", err)
	}
	// Until the token has told which client it is for, a refusal is of the boundary's default tenant and of no client.
	tenant, subj := b.GetDefaultTenant(), clientSubject(b.GetDefaultTenant(), "unregistered")
	refuse := func(e *bearerError, reason, client string) (*bearerToken, *connect.Response[typev2alpha1.HttpReply], error) {
		logRefusal(action, orCode(e), reason, client)
		_ = s.record(ctx, audited{action: action, tenant: tenant, subject: subj, reason: reason}) // best effort: the refusal is the answer
		return nil, e.reply(), nil
	}

	raw, e := bearerValue(authorization)
	if e != nil {
		return refuse(e, reasonBearer, "")
	}
	tok, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil || len(tok.Signatures) != 1 {
		return refuse(errInvalidToken, reasonBearer, "")
	}
	sig := tok.Signatures[0]
	// RFC 9068 section 4: the resource server checks typ, so that an ID token cannot be taken for an access token.
	if typ, _ := sig.Protected.ExtraHeaders[jose.HeaderType].(string); typ != "at+jwt" {
		return refuse(errInvalidToken, reasonBearerType, "")
	}
	if sig.Header.KeyID == "" {
		return refuse(errInvalidToken, reasonBearer, "")
	}
	payload, ok, err := s.verified(ctx, tok, sig.Header.KeyID)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return refuse(errInvalidToken, reasonBearer, "")
	}
	// From here the payload is signed by this issuer's key, and still checked: a claim set that is not the set of an access
	// token (no sid, a second audience) is not served.
	var c accessClaims
	now := s.now()
	if json.Unmarshal(payload, &c) != nil || c.Iss != b.GetIssuer() || c.Exp == nil || !now.Before(time.Unix(*c.Exp, 0)) ||
		c.Sub == "" || c.SID == "" || c.JTI == "" || c.ClientID == "" || c.Aud == "" {
		return refuse(errInvalidToken, reasonBearer, "")
	}
	// A token issued, or not yet valid, in this clock's future is refused: a clock that is behind (a board that has not been
	// set by its time service) would otherwise take a token for live that expired, and a chain for inside its limits that is
	// not, because every limit here is read against this clock. With iat required, a clock that is behind the moment the token was
	// made fails closed. A clock that is behind by less than the age of the token is not caught by this: no claim of the token
	// can show it.
	if c.Iat == nil || time.Unix(*c.Iat, 0).After(now.Add(bearerSkew)) || c.Nbf != nil && time.Unix(*c.Nbf, 0).After(now.Add(bearerSkew)) {
		return refuse(errInvalidToken, reasonBearer, "")
	}
	if c.Aud != c.ClientID {
		return refuse(errInvalidToken, reasonBearerClient, "")
	}
	goneKey := "\x00client\x00" + c.ClientID
	if s.endedChains.has(goneKey, now) {
		return refuse(errInvalidToken, reasonBearerClient, "")
	}
	cl, err := s.opts.Config.Client(ctx, c.ClientID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// A validly signed token of a client that has been removed: one absent read at store@ is a refusal it audits, so the
		// next requests are answered from memory for a minute (or until the token expires, if sooner).
		until := time.Unix(*c.Exp, 0)
		if lim := now.Add(clientGoneFor); lim.Before(until) {
			until = lim
		}
		s.endedChains.add(goneKey, until)
		return refuse(errInvalidToken, reasonBearerClient, "")
	case err != nil:
		return nil, nil, unavailable("client", err)
	}
	if tenant, err = tenantOf(b, cl); err != nil {
		return nil, nil, internal("tenant", err)
	}
	subj = clientSubject(tenant, cl.GetId())
	chain, live, err := s.sessionLive(ctx, tenant, c.SID, cl.GetId(), time.Unix(*c.Exp, 0))
	if err != nil {
		return nil, nil, err
	}
	switch live {
	case liveEnded:
		return refuse(errInvalidToken, reasonSessionEnded, cl.GetId())
	case liveOtherClient:
		return refuse(errInvalidToken, reasonBearerClient, cl.GetId())
	}
	if scope != "" && !hasScope(chain.GetScope(), scope) {
		return refuse(errScope, reasonScope, cl.GetId())
	}
	return &bearerToken{claims: c, tenant: tenant, client: cl, chain: chain}, nil, nil
}

func orCode(e *bearerError) string {
	if e.code == "" {
		return "no_credentials"
	}
	return e.code
}

// bearerValue is the token in an Authorization header: the scheme Bearer (any case), one space, and the token (RFC 6750
// section 2.1: b64token). Another scheme, or no header, is a request with no credentials for this resource (section 3.1).
func bearerValue(h string) (string, *bearerError) {
	if h == "" {
		return "", errNoBearer
	}
	scheme, tok, found := strings.Cut(h, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", errNoBearer
	}
	if !found || tok == "" {
		// "Bearer" and nothing after it carries no credentials.
		return "", errNoBearer
	}
	if len(h) > maxBearerHeader || !b64token(tok) {
		return "", errBadBearerReq
	}
	return tok, nil
}

// b64token is the syntax of RFC 6750 section 2.1: letters, digits and -._~+/ , then any number of =.
func b64token(s string) bool {
	body := strings.TrimRight(s, "=")
	if body == "" {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~+/", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// ---- the issuer's key set ----------------------------------------------------------------------------------------

// keySet keeps the issuer's public keys, from signer. session holds no key of its own and verifies with the public ones.
type keySet struct {
	mu    sync.Mutex
	set   *jose.JSONWebKeySet
	at    time.Time
	tried time.Time // the last fetch made for a kid the set did not hold
	err   error     // the last failure to get the set, and when: while it is fresh no one asks signer again
	errAt time.Time
}

// verified verifies the token with the key of kid. A kid the set does not hold makes one fresh fetch, at most once in
// refetchGap (a key rotation); a key set that cannot be had and is not fresh is an outage, not a refusal.
func (s *Service) verified(ctx context.Context, tok *jose.JSONWebSignature, kid string) (payload []byte, ok bool, err error) {
	for _, refresh := range []bool{false, true} {
		set, err := s.issuerKeys(ctx, refresh)
		if err != nil {
			return nil, false, err
		}
		keys := set.Key(kid)
		for _, k := range keys {
			if k.Use != "" && k.Use != "sig" {
				continue
			}
			if p, err := tok.Verify(k); err == nil {
				return p, true, nil
			}
		}
		if len(keys) > 0 {
			// The key is there and the signature is not its: a fresh set cannot change that.
			return nil, false, nil
		}
	}
	return nil, false, nil
}

func (s *Service) issuerKeys(ctx context.Context, refresh bool) (*jose.JSONWebKeySet, error) {
	k := &s.keySet
	k.mu.Lock()
	defer k.mu.Unlock()
	now := s.now()
	if k.set != nil && now.Sub(k.at) < keySetTTL && (!refresh || now.Sub(k.tried) < refetchGap) {
		return k.set, nil
	}
	// A fetch is needed. If the last one failed a moment ago, no one asks again yet.
	if k.err != nil && now.Sub(k.errAt) < keyFailGap {
		return nil, k.err
	}
	if refresh {
		k.tried = now
	}
	// The fetch is made on a context of its own (the request's values, not its cancellation): it serves every request that
	// waits for the set, and one caller that gives up or drops its connection must not fail it for the rest, or leave a
	// failure in memory that is not signer's.
	fetch, cancel := context.WithTimeout(context.WithoutCancel(ctx), keyFetchTimeout)
	defer cancel()
	res, err := s.opts.Signer.KeySet(fetch, connect.NewRequest(&signerv2alpha1.KeySetRequest{}))
	var set *jose.JSONWebKeySet
	if err == nil {
		set, err = parseKeySet(res.Msg.GetJwksJson())
	}
	if err != nil {
		// A set that is older than keySetTTL is never used, so a signer that is down for longer than that fails closed. The
		// failure is logged once and kept for keyFailGap.
		k.err, k.errAt = unavailable("signer", err), now
		return nil, k.err
	}
	k.set, k.at, k.err = set, now, nil
	return set, nil
}

// parseKeySet reads a JWK Set (RFC 7517 section 5): public ES384 keys only, at most maxSetKeys.
func parseKeySet(b []byte) (*jose.JSONWebKeySet, error) {
	var in jose.JSONWebKeySet
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, errors.New("not a JWK Set")
	}
	if len(in.Keys) == 0 || len(in.Keys) > maxSetKeys {
		return nil, errors.New("no key, or too many")
	}
	out := &jose.JSONWebKeySet{}
	for _, k := range in.Keys {
		if k.Valid() && k.IsPublic() && (k.Algorithm == "" || k.Algorithm == string(jose.ES384)) {
			out.Keys = append(out.Keys, k)
		}
	}
	if len(out.Keys) == 0 {
		return nil, errors.New("no usable key")
	}
	return out, nil
}

// ---- the session behind a token ----------------------------------------------------------------------------------

type liveness int

const (
	liveYes liveness = iota
	liveEnded
	liveOtherClient
)

// ended remembers the chains found gone. An id is 128 random bits, made once, so a chain that is gone never comes back,
// and what is remembered cannot go stale: a replica that remembers fails a request that a Get would fail too. It is
// there so that one token of an ended session, presented many times, costs one refusal at store@ and not one each
// (store@ audits every refusal, and an absent item is one). An entry is dropped when the token that proved it would have
// expired. It is bounded; when full it is emptied, which costs a few Gets.
type ended struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func (e *ended) has(key string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	until, ok := e.m[key]
	if ok && !now.Before(until) {
		delete(e.m, key)
		return false
	}
	return ok
}

func (e *ended) add(key string, until time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.m == nil || len(e.m) >= endedCap {
		e.m = map[string]time.Time{}
	}
	e.m[key] = until
}

// sessionLive reads the chain that a token names and says whether the session is still there. The read is a Get at store@
// (linearizable, which is the Get's default), made on every request: a session that ended before the request began is
// seen, with no cache of a live chain. What is not seen is a session that ends while the request is in flight, which is
// the length of one request. A chain that is over by its own times is ended even if the store has not dropped it yet
// (the absolute limit is the item's time to live, the idle limit is read from the chain and the configuration).
// tokenExp bounds how long a gone chain is remembered.
func (s *Service) sessionLive(ctx context.Context, tenant, sid, clientID string, tokenExp time.Time) (*sessionv2alpha1.SessionChain, liveness, error) {
	key := tenant + "\x00" + sid
	now := s.now()
	if s.endedChains.has(key, now) {
		return nil, liveEnded, nil
	}
	it, err := s.chains.Get(ctx, tenant, sid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.endedChains.add(key, tokenExp)
		return nil, liveEnded, nil
	case err != nil:
		return nil, liveYes, unavailable("store", err)
	}
	chain := it.Value
	if !equal(chain.GetClientId(), clientID) || chain.GetClass() != chainClassHuman {
		return nil, liveOtherClient, nil
	}
	life, err := s.opts.Config.Lifetimes(ctx)
	if err != nil {
		return nil, liveYes, unavailable("token_lifetime", err)
	}
	if !now.Before(chain.GetEndsAt().AsTime()) || !now.Before(chain.GetRefreshedAt().AsTime().Add(life.RefreshIdle)) {
		return nil, liveEnded, nil
	}
	return chain, liveYes, nil
}
