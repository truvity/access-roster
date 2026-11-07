package sessiond

import (
	"context"
	"errors"
	"maps"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	signerv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/signer/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/clientauth"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// maxCredential bounds a code or a refresh token a client presents.
const maxCredential = 512

// Token serves the token endpoint: the authorization_code grant (RFC 6749 section 4.1.3) and the refresh_token grant
// (section 6). Every other grant type is refused as unsupported; the token exchange is exchange's.
func (s *Service) Token(ctx context.Context, req *connect.Request[sessionv2alpha1.TokenRequest]) (*connect.Response[typev2alpha1.HttpReply], error) {
	switch req.Msg.GetGrantType() {
	case "authorization_code":
		return s.codeGrant(ctx, req.Msg)
	case "refresh_token":
		return s.refreshGrant(ctx, req.Msg)
	}
	return tokenError(errUnsupportedGrant()), nil
}

// tokenCtx is what both grants need once the client is known.
type tokenCtx struct {
	boundary *configv2alpha1.Boundary
	client   *configv2alpha1.InstallationClient
	tenant   string
	now      time.Time
	life     Lifetimes
	action   audit.Action
	// method is how the request authenticated the client, "" when it presented no credentials; authenticated says the
	// secret was right (only a confidential client's can be). Both are for the audit record.
	method        string
	authenticated bool
}

// refuse answers with an OAuth error and records the step as failed. The reason is a closed word of the audit.
func (s *Service) refuse(ctx context.Context, tc *tokenCtx, subj *audit.Subject, pol *verdict, reason string, e *oauthError) *connect.Response[typev2alpha1.HttpReply] {
	// The client is named in the log when the installation declares it: tokenContext sets tc.client only for one it found.
	declared := ""
	if tc.client != nil {
		declared = tc.client.GetId()
	}
	logRefusal(tc.action, e.code, reason, declared)
	a := audited{action: tc.action, tenant: tc.tenant, subject: subj, reason: reason, sluis: tc.facts(nil)}
	if pol != nil {
		a.policy = pol.ref()
	}
	_ = s.record(ctx, a) // a failed step is recorded best effort; the refusal is the answer either way
	return tokenError(e)
}

// tokenContext authenticates the client of the token endpoint, for the code grant, the refresh grant and the revocation
// (RFC 6749 section 2.3). Three kinds of client reach it:
//
//   - A public client is known by its id alone (RFC 6749 sections 2.1 and 3.2.1), and one that sends a secret is refused: a
//     secret it was never given proves nothing, and accepting one would make it look like a confidential client
//     (REQ-CLIENT-001).
//   - A confidential client presents its secret by client_secret_basic or client_secret_post (REQ-CLIENT-042); a request
//     with no secret, or the wrong one, is refused.
//   - An exchange client is exchange's, and never signs a person in here.
//
// Every refusal is the same invalid_client (REQ-CLIENT-042), whichever of these it was; the closed reason in the log and
// the audit record says which. A request that presents credentials takes one path whoever the client is: the secret is
// asked for and compared, and the declaration is read, for an unknown client, a public client, a confidential client with
// no secret provisioned and one with the wrong secret alike, so that the answer and the work do not tell them apart
// (REQ-CLIENT-043; the kit counts it: kits/go/clientauth).
func (s *Service) tokenContext(ctx context.Context, r *sessionv2alpha1.TokenRequest, action audit.Action) (*tokenCtx, *connect.Response[typev2alpha1.HttpReply], error) {
	b, err := s.opts.Config.Boundary(ctx)
	if err != nil {
		return nil, nil, unavailable("boundary", err)
	}
	tc := &tokenCtx{boundary: b, tenant: b.GetDefaultTenant(), now: s.now(), action: action}
	creds, present, perr := clientauth.Parse(r.GetAuthorization(), r.GetClientId(), r.GetClientSecret())
	switch {
	case errors.Is(perr, clientauth.ErrBothMethods):
		// RFC 6749 section 2.3: more than one method in a request is an invalid request. It depends on the shape of the
		// request alone, not on the client.
		return nil, s.refuse(ctx, tc, clientSubject(tc.tenant, "unregistered"), nil, reasonClientMethods, errInvalidRequest()), nil
	case perr != nil:
		return nil, s.refuse(ctx, tc, clientSubject(tc.tenant, "unregistered"), nil, reasonClientAuth, errInvalidClient()), nil
	}
	clientID := r.GetClientId()
	authenticated := false
	if present {
		clientID, tc.method = creds.ClientID, string(creds.Method)
		if authenticated, err = s.auth.Authenticate(ctx, creds); err != nil {
			return nil, nil, unavailable("store", err)
		}
	}
	cl, err := s.opts.Config.Client(ctx, clientID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, s.refuse(ctx, tc, clientSubject(tc.tenant, "unregistered"), nil, reasonClient, errInvalidClient()), nil
	case err != nil:
		return nil, nil, unavailable("client", err)
	}
	tc.client = cl
	switch cl.GetKind() {
	case kindPublic:
		if present {
			return nil, s.refuse(ctx, tc, clientSubject(tc.tenant, cl.GetId()), nil, reasonClientSecret, errInvalidClient()), nil
		}
	case kindConfidential:
		if !present || !authenticated {
			return nil, s.refuse(ctx, tc, clientSubject(tc.tenant, cl.GetId()), nil, reasonClientAuth, errInvalidClient()), nil
		}
		tc.authenticated = true
	default:
		return nil, s.refuse(ctx, tc, clientSubject(tc.tenant, cl.GetId()), nil, reasonClient, errInvalidClient()), nil
	}
	if tc.tenant, err = tenantOf(b, cl); err != nil {
		return nil, nil, internal("tenant", err)
	}
	if tc.life, err = s.opts.Config.Lifetimes(ctx); err != nil {
		return nil, nil, unavailable("token_lifetime", err)
	}
	return tc, nil, nil
}

// The kinds of an InstallationClient that session serves (ADR 0021). An exchange client is exchange's.
const (
	kindPublic       = "public"
	kindConfidential = "confidential"
)

// facts are the members of the audit record of a step of this client: the given ones, and how the client authenticated
// when it presented credentials. The record names the method and the outcome and never a secret, a header or a body.
func (tc *tokenCtx) facts(m map[string]any) map[string]any {
	if tc.method == "" {
		return m
	}
	out := make(map[string]any, len(m)+1)
	maps.Copy(out, m)
	out["client"] = map[string]any{"method": tc.method, "authenticated": tc.authenticated}
	return out
}

// codeGrant redeems an authorization code: the code is spent once, the PKCE verifier and the client are checked, policy
// decides again with the person's own subject, a session chain begins, and signer signs the ID token and the access
// token.
func (s *Service) codeGrant(ctx context.Context, r *sessionv2alpha1.TokenRequest) (*connect.Response[typev2alpha1.HttpReply], error) {
	tc, done, err := s.tokenContext(ctx, r, actionToken)
	if done != nil || err != nil {
		return done, err
	}
	clientSubj := clientSubject(tc.tenant, tc.client.GetId())
	code, uri, verifier := r.GetCode(), r.GetRedirectUri(), r.GetCodeVerifier()
	if !vschar(code, maxCredential, false) || uri == "" || len(uri) > maxRedirectURI || !validVerifier(verifier) {
		return s.refuse(ctx, tc, clientSubj, nil, reasonRequest, errInvalidRequest()), nil
	}

	id := secretID(code)
	it, err := s.codes.Get(ctx, tc.tenant, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return s.refuse(ctx, tc, clientSubj, nil, reasonCode, errInvalidGrant()), nil
	case err != nil:
		return nil, unavailable("store", err)
	}
	ac := it.Value
	if ac.GetSpent() {
		return s.replayed(ctx, tc, id, ac)
	}
	// The code belongs to one client and one redirect_uri, and its PKCE verifier proves the redeemer is the one that
	// asked (RFC 6749 section 4.1.3; RFC 7636 section 4.6). Each check is the same answer.
	if !equal(ac.GetClientId(), tc.client.GetId()) || !equal(ac.GetRedirectUri(), uri) {
		return s.refuse(ctx, tc, clientSubj, nil, reasonCode, errInvalidGrant()), nil
	}
	if !equal(ac.GetCodeChallenge(), s256(verifier)) {
		return s.refuse(ctx, tc, clientSubj, nil, reasonPKCE, errInvalidGrant()), nil
	}
	person := personSubject(tc.tenant, ac.GetSubject())

	var facts sessionv2alpha1.SignInFacts
	if err := s.keys.openFlow(ctx, authCodeKind, id, ac.GetSealedFacts(), &facts); err != nil {
		if errors.Is(err, errNotOurs) {
			return s.refuse(ctx, tc, person, nil, reasonCode, errInvalidGrant()), nil
		}
		return nil, unavailable("key", err)
	}
	assure := assuranceFrom(ac.GetAuthTime(), ac.Acr, ac.GetAmr(), ac.GetAmrPresent())
	state, err := s.stateOf(ctx, tc.tenant, ac.GetSubject())
	if err != nil {
		return nil, unavailable("store", err)
	}
	v, err := s.decide(ctx, question{
		tenant: tc.tenant, subject: ac.GetSubject(), accounts: facts.GetAccounts(), state: state,
		client: tc.client, assure: assure, now: tc.now, verbs: []string{"update", "create"}, ops: []string{"seal", "mac"},
	})
	if err != nil {
		return nil, unavailable("policy", err)
	}
	if !v.allow {
		return s.refuse(ctx, tc, person, &v, deniedReason(state, v), deniedError(v)), nil
	}

	ends := ac.GetAuthenticatedAt().AsTime().Add(tc.life.SessionAbsolute)
	if !tc.now.Before(ends) {
		return s.refuse(ctx, tc, person, &v, reasonExpired, errInvalidGrant()), nil
	}
	sid, err := randomID()
	if err != nil {
		return nil, internal("random", err)
	}
	secret, err := randomToken()
	if err != nil {
		return nil, internal("random", err)
	}
	// One copy of the facts, under the chain key of the tenant: session opens it at a refresh, exchange for a token
	// exchange, and the tenant's exit deletes the key (REQ-KEYS-082).
	chainFacts, err := s.keys.sealChain(ctx, tc.tenant, sid, &facts, v.grant)
	if err != nil {
		return nil, unavailable("key", err)
	}

	// Spend the code and begin the chain in one write: the conditional update of the code makes it single use (of two
	// redemptions, one wins), and the chain is created with it, so a loser that finds the code spent also finds the
	// chain to end (RFC 6749 section 4.1.2: a replayed code revokes what it issued). Apart, a replay could land between
	// the two writes and find no chain.
	ac.Spent, ac.SessionId = true, sid
	chain := &sessionv2alpha1.SessionChain{
		Subject: ac.GetSubject(), ClientId: tc.client.GetId(), Class: chainClassHuman, Scope: ac.GetScope(),
		RefreshHash: secretHash(secret), StartedAt: ac.GetAuthenticatedAt(), EndsAt: timestamppb.New(ends),
		RefreshedAt: timestamppb.New(tc.now), AuthTime: ac.GetAuthTime(), Acr: ac.Acr, Amr: ac.GetAmr(),
		AmrPresent: ac.GetAmrPresent(), SealedFacts: chainFacts,
	}
	if err := s.spendAndBegin(ctx, tc.tenant, id, ac, it.Version, sid, chain, ends.Sub(tc.now), v.grant); err != nil {
		if errors.Is(err, store.ErrVersion) || errors.Is(err, store.ErrNotFound) {
			return s.replayed(ctx, tc, id, nil)
		}
		return nil, unavailable("store", err)
	}
	out, err := s.mint(ctx, tc, mintInput{
		person: ac.GetSubject(), sid: sid, scope: ac.GetScope(), nonce: ac.GetNonce(), assure: assure,
		groups: narrowGroups(v.grantNames, tc.client.GetRequires()), chainEnd: ends, refresh: sid + "." + secret, grant: v.grant,
	})
	switch {
	case errors.Is(err, errSessionOver):
		return s.refuse(ctx, tc, person, &v, reasonExpired, errInvalidGrant()), nil
	case err != nil:
		return nil, err
	}
	if aerr := s.record(ctx, audited{
		action: tc.action, tenant: tc.tenant, subject: person, policy: v.ref(),
		sluis: tc.facts(map[string]any{"grant_type": "authorization_code", "sid": sid}),
	}); aerr != nil {
		return nil, aerr
	}
	return tokenOK(out)
}

// replayed handles a code that was already redeemed. It is refused, and the chain the first redemption made is ended
// (RFC 6749 section 4.1.2: "If an authorization code is used more than once, the authorization server MUST deny the
// request and SHOULD revoke (when possible) all tokens previously issued based on that authorization code"). ac is the
// item when the caller has just read it; nil makes this read it again, after losing a race.
func (s *Service) replayed(ctx context.Context, tc *tokenCtx, id string, ac *sessionv2alpha1.AuthCode) (*connect.Response[typev2alpha1.HttpReply], error) {
	if ac == nil {
		it, err := s.codes.Get(ctx, tc.tenant, id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return s.refuse(ctx, tc, clientSubject(tc.tenant, tc.client.GetId()), nil, reasonCode, errInvalidGrant()), nil
		case err != nil:
			return nil, unavailable("store", err)
		}
		ac = it.Value
	}
	// Only the client the code was issued to ends the chain by replaying it. Another client that presents a spent code, with a
	// secret of its own or none, is refused as for any code that is not its own, and ends nothing: a replay is the owner's
	// evidence that the code has leaked, and it is not a way for one client to end another's sessions.
	if !equal(ac.GetClientId(), tc.client.GetId()) {
		return s.refuse(ctx, tc, clientSubject(tc.tenant, tc.client.GetId()), nil, reasonCode, errInvalidGrant()), nil
	}
	person := personSubject(tc.tenant, ac.GetSubject())
	if sid := ac.GetSessionId(); sid != "" {
		if err := s.endChain(ctx, tc, sid, reasonReuse); err != nil {
			return nil, err
		}
	}
	return s.refuse(ctx, tc, person, nil, reasonReuse, errInvalidGrant()), nil
}

// stateOf is the person's state for policy (0019 "States"): held when an operator's PersonHold exists, live otherwise.
func (s *Service) stateOf(ctx context.Context, tenant, subject string) (string, error) {
	held, err := s.sealed.held(ctx, tenant, subject)
	if err != nil {
		return "", err
	}
	if held {
		return stateHeld, nil
	}
	return stateLive, nil
}

// deniedError is the answer to a denial: a step-up when a policy that denied asked for one (RFC 9470), and the
// refusal that looks like every other bad grant otherwise.
func deniedError(v verdict) *oauthError {
	if len(v.stepUp) > 0 {
		return errStepUp(v.stepUp)
	}
	return errInvalidGrant()
}

func deniedReason(state string, v verdict) string {
	switch {
	case state == stateHeld:
		return reasonHeld
	case len(v.stepUp) > 0:
		return reasonStepUp
	}
	return reasonDenied
}

// validVerifier is a PKCE code verifier: 43 to 128 characters of the unreserved set (RFC 7636 section 4.1).
func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	return strings.IndexFunc(v, func(r rune) bool { return !unreserved(r) }) < 0
}

func unreserved(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_' || r == '~'
}

// The class of a chain. Only the human class is built: an agent session starts from a consent, which has no consumer
// yet (0018 "Agent sessions").
const chainClassHuman = "human"

// chainKind is the address segment of the kind SessionChain.
const chainKind = "session-chain"

// assuranceFrom rebuilds the assurance a sign-in recorded in an AuthCode or a SessionChain.
func assuranceFrom(authTime *timestamppb.Timestamp, acr *string, amr []string, present bool) assurance {
	a := assurance{acr: acr, amr: amr, amrPresent: present}
	if authTime != nil {
		a.authTime, a.hasAuthTime = authTime.AsTime(), true
	}
	return a
}

// errSessionOver says the session ended before a token could be made.
var errSessionOver = errors.New("sessiond: the session is over")

// mintInput is what a token pair is made of.
type mintInput struct {
	person, sid, scope, nonce string
	assure                    assurance
	groups                    []string
	chainEnd                  time.Time
	refresh                   string
	grant                     []byte // the grant of the decision the tokens follow, for the tenant's first pairwise key
}

// mint makes the ID token and the access token, signed by signer through key@, and the response around them. sub is
// the subject of the tenant's sector (0034): pairwise per tenant unless the tenant declared the public sector. exp is
// the earliest of the issuer's lifetime, the client's ttl_cap and the end of the chain (0020 "Lifetimes").
func (s *Service) mint(ctx context.Context, tc *tokenCtx, in mintInput) (tokenResponse, error) {
	sub, err := s.keys.pairwiseSubject(ctx, tc.tenant, s.sectorOf(tc.tenant), in.person, in.grant)
	if err != nil {
		return tokenResponse{}, unavailable("key", err)
	}
	ttlCap := tc.client.GetTtlCap().AsDuration()
	idExp := expiry(tc.now, tc.life.IDToken, ttlCap, in.chainEnd)
	atExp := expiry(tc.now, tc.life.AccessToken, ttlCap, in.chainEnd)
	if !idExp.After(tc.now) || !atExp.After(tc.now) {
		return tokenResponse{}, errSessionOver
	}
	jti, err := randomID()
	if err != nil {
		return tokenResponse{}, internal("random", err)
	}
	c := claims{
		issuer: tc.boundary.GetIssuer(), audience: tc.client.GetId(), subject: sub, sid: in.sid,
		issuedAt: tc.now, assure: in.assure, groups: in.groups,
	}
	out := tokenResponse{TokenType: "Bearer", ExpiresIn: int64(atExp.Sub(tc.now) / time.Second), RefreshToken: in.refresh, Scope: in.scope}
	if hasScope(in.scope, "openid") {
		c.expires, c.nonce = idExp, in.nonce
		b, err := c.idToken()
		if err != nil {
			return tokenResponse{}, internal("claims", err)
		}
		if out.IDToken, err = s.sign(ctx, "JWT", b); err != nil {
			return tokenResponse{}, err
		}
	}
	c.expires, c.nonce, c.jti, c.clientID = atExp, "", jti, tc.client.GetId()
	b, err := c.accessToken()
	if err != nil {
		return tokenResponse{}, internal("claims", err)
	}
	if out.AccessToken, err = s.sign(ctx, "at+jwt", b); err != nil {
		return tokenResponse{}, err
	}
	return out, nil
}

// sign has signer sign the claims as a token of the type (0020: the header's typ is JWT for an ID token and at+jwt
// for an access token, RFC 9068 section 2.1). signer checks the claims against the fixed set again.
func (s *Service) sign(ctx context.Context, typ string, claimsJSON []byte) (string, error) {
	res, err := s.opts.Signer.SignToken(ctx, connect.NewRequest(&signerv2alpha1.SignTokenRequest{Typ: typ, ClaimsJson: claimsJSON}))
	if err != nil {
		return "", unavailable("signer", err)
	}
	if res.Msg.GetToken() == "" {
		return "", internal("signer", errors.New("empty token"))
	}
	return res.Msg.GetToken(), nil
}

func hasScope(scope, want string) bool {
	for _, sc := range strings.Fields(scope) {
		if sc == want {
			return true
		}
	}
	return false
}
