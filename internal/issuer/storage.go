package issuer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/truvity/access-roster/policy"
)

// Verifier turns a third-party subject token into a proof. It is the
// whole of the issuer's trust in another system: GitHub's keys and the
// organisation allow-list, or a Kubernetes TokenReview. Everything after
// it is policy.
//
// It is an interface because the spike needs a fake and a deployment
// needs the real thing, and because a new CI platform should be a new
// implementation rather than a change to the exchange.
type Verifier interface {
	// Verify checks a subject token and returns what it proves. tokenType
	// is the RFC 8693 subject_token_type as presented.
	Verify(ctx context.Context, token, tokenType string) (Proof, error)
}

// ErrUnverified is returned when no verifier recognises a subject token.
var ErrUnverified = errors.New("the subject token was not verified by any configured proof")

// Verifiers tries each in turn. The first to recognise a token owns it;
// none recognising it is a refusal, never a fallback to trusting it.
type Verifiers []Verifier

// Verify implements [Verifier].
func (v Verifiers) Verify(ctx context.Context, token, tokenType string) (Proof, error) {
	for _, one := range v {
		proof, err := one.Verify(ctx, token, tokenType)
		if err == nil {
			return proof, nil
		}
		// A verifier that recognised the token and rejected it is final:
		// a GitHub token with a bad signature must not fall through to
		// being tried as a ServiceAccount token.
		if !errors.Is(err, ErrUnverified) {
			return Proof{}, err
		}
	}
	return Proof{}, ErrUnverified
}

// token is one issued access token, remembered so that userinfo and
// revocation can find it.
type token struct {
	id       string
	subject  string
	clientID string
	audience []string
	scopes   []string
	claims   map[string]any
	expires  time.Time
}

// authRequest is a login in progress. The spike keeps them in memory;
// a deployment keeps them in Valkey, where they expire on their own.
type authRequest struct {
	id       string
	req      *oidc.AuthRequest
	subject  string
	authTime time.Time
	done     bool
}

var _ op.AuthRequest = (*authRequest)(nil)

func (a *authRequest) GetID() string          { return a.id }
func (a *authRequest) GetACR() string         { return "" }
func (a *authRequest) GetAMR() []string       { return []string{"pwd"} }
func (a *authRequest) GetAudience() []string  { return []string{a.req.ClientID} }
func (a *authRequest) GetAuthTime() time.Time { return a.authTime }
func (a *authRequest) GetClientID() string    { return a.req.ClientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.req.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: a.req.CodeChallenge, Method: a.req.CodeChallengeMethod}
}
func (a *authRequest) GetNonce() string                   { return a.req.Nonce }
func (a *authRequest) GetRedirectURI() string             { return a.req.RedirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType { return a.req.ResponseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return a.req.ResponseMode }
func (a *authRequest) GetScopes() []string                { return a.req.Scopes }
func (a *authRequest) GetState() string                   { return a.req.State }
func (a *authRequest) GetSubject() string                 { return a.subject }
func (a *authRequest) Done() bool                         { return a.done }

// Storage is the shell the OpenID library needs, over the issuer's
// decision core. It stores; it does not decide. Every question about
// entitlement goes to the [Issuer], so that the console, the token and
// the audit trail cannot disagree about what someone is allowed.
type Storage struct {
	*Devices

	iss     *Issuer
	verify  Verifier
	key     *signingKey
	secrets func(clientID string) (string, bool)

	mu       sync.Mutex
	requests map[string]*authRequest
	codes    map[string]string // code → auth request id
	tokens   map[string]*token
	grants   sync.Map // op.TokenExchangeRequest → Grant
}

var (
	_ op.Storage                            = (*Storage)(nil)
	_ op.TokenExchangeStorage               = (*Storage)(nil)
	_ op.TokenExchangeTokensVerifierStorage = (*Storage)(nil)
	_ op.DeviceAuthorizationStorage         = (*Storage)(nil)
)

// NewStorage returns the storage over an issuer. secrets resolves a
// confidential client's secret, which lives in a Kubernetes Secret and
// never in the policy file.
func NewStorage(iss *Issuer, verify Verifier, secrets func(string) (string, bool)) (*Storage, error) {
	key, err := newSigningKey()
	if err != nil {
		return nil, err
	}
	if secrets == nil {
		secrets = func(string) (string, bool) { return "", false }
	}
	return &Storage{
		Devices:  NewDevices(),
		iss:      iss,
		verify:   verify,
		key:      key,
		secrets:  secrets,
		requests: map[string]*authRequest{},
		codes:    map[string]string{},
		tokens:   map[string]*token{},
	}, nil
}

// ---------------------------------------------------------------- keys

// SigningKey implements [op.AuthStorage].
func (s *Storage) SigningKey(context.Context) (op.SigningKey, error) { return s.key, nil }

// SignatureAlgorithms implements [op.AuthStorage].
func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet implements [op.AuthStorage].
func (s *Storage) KeySet(context.Context) ([]op.Key, error) {
	return []op.Key{publicKey{s.key}}, nil
}

// Health implements [op.Storage].
func (s *Storage) Health(context.Context) error { return nil }

// ------------------------------------------------------------- clients

// GetClientByClientID implements [op.OPStorage].
func (s *Storage) GetClientByClientID(_ context.Context, clientID string) (op.Client, error) {
	declared, ok := s.iss.Policy().Client(clientID)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTarget, clientID)
	}
	return &client{id: clientID, declared: declared, lifetime: s.iss.Config().TokenLifetime}, nil
}

// AuthorizeClientIDSecret implements [op.OPStorage].
func (s *Storage) AuthorizeClientIDSecret(_ context.Context, clientID, secret string) error {
	declared, ok := s.iss.Policy().Client(clientID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownTarget, clientID)
	}
	// A public client holds no secret, and the library asks all the same,
	// including for a token exchange. That is the right question with the
	// wrong premise: in an exchange the subject token is the credential —
	// a GitHub identity token verified against GitHub's keys — and the
	// client id only names who is asking. So a public client presenting
	// nothing is authenticated, and one presenting a secret is refused,
	// because it should not have one to present.
	if declared.Kind == policy.KindPublic {
		if secret != "" {
			return errors.New("a public client presents no secret")
		}
		return nil
	}
	want, ok := s.secrets(clientID)
	if !ok || want == "" || want != secret {
		return errors.New("the client secret does not match")
	}
	return nil
}

// --------------------------------------------------------- auth requests

// CreateAuthRequest implements [op.AuthStorage].
func (s *Storage) CreateAuthRequest(_ context.Context, req *oidc.AuthRequest, subject string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := &authRequest{id: uuid.NewString(), req: req, subject: subject, authTime: time.Now()}
	s.requests[out.id] = out
	return out, nil
}

// AuthRequestByID implements [op.AuthStorage].
func (s *Storage) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return nil, errors.New("no such authorization request")
	}
	return req, nil
}

// AuthRequestByCode implements [op.AuthStorage].
func (s *Storage) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, ok := s.codes[code]
	if !ok {
		return nil, errors.New("no such authorization code")
	}
	req, ok := s.requests[id]
	if !ok {
		return nil, errors.New("no such authorization request")
	}
	return req, nil
}

// SaveAuthCode implements [op.AuthStorage].
func (s *Storage) SaveAuthCode(_ context.Context, id, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.requests[id]; !ok {
		return errors.New("no such authorization request")
	}
	s.codes[code] = id
	return nil
}

// DeleteAuthRequest implements [op.AuthStorage].
func (s *Storage) DeleteAuthRequest(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.requests, id)
	for code, forID := range s.codes {
		if forID == id {
			delete(s.codes, code)
		}
	}
	return nil
}

// Complete marks a login as finished, which is what the issuer's own
// sign-in page calls once an identity provider has said who is there.
func (s *Storage) Complete(id, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return errors.New("no such authorization request")
	}
	req.subject, req.done, req.authTime = strings.ToLower(subject), true, time.Now()
	return nil
}

// --------------------------------------------------------------- tokens

// CreateAccessToken implements [op.AuthStorage].
func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	issued, err := s.issue(ctx, request)
	if err != nil {
		return "", time.Time{}, err
	}
	return issued.id, issued.expires, nil
}

// CreateAccessAndRefreshTokens implements [op.AuthStorage].
func (s *Storage) CreateAccessAndRefreshTokens(
	ctx context.Context, request op.TokenRequest, currentRefreshToken string,
) (string, string, time.Time, error) {
	issued, err := s.issue(ctx, request)
	if err != nil {
		return "", "", time.Time{}, err
	}
	refresh := uuid.NewString()

	// A refresh spends the old token: the session carries on, the
	// credential does not, so a stolen refresh token is good for one use
	// before its rightful holder's next refresh reveals the theft.
	if currentRefreshToken != "" {
		if _, ok := s.iss.Sessions().Refreshed(currentRefreshToken, refresh); !ok {
			return "", "", time.Time{}, oidc.ErrInvalidGrant().WithDescription("the refresh token is not live")
		}
		return issued.id, refresh, issued.expires, nil
	}

	how := HowCode
	if _, ok := request.(op.TokenExchangeRequest); ok {
		how = HowExchange
	}
	s.iss.Sessions().Record(issued.subject, clientOf(request), how, refresh)
	return issued.id, refresh, issued.expires, nil
}

// issue records one access token and returns it.
func (s *Storage) issue(ctx context.Context, request op.TokenRequest) (*token, error) {
	claims, err := s.claimsFor(ctx, request)
	if err != nil {
		return nil, err
	}
	lifetime := s.iss.Config().TokenLifetime
	if exchange, ok := request.(op.TokenExchangeRequest); ok {
		if grant, ok := s.grantFor(exchange); ok {
			if capped := time.Duration(s.iss.Lifetime(grant)); capped > 0 && capped < lifetime {
				lifetime = capped
			}
		}
	}

	issued := &token{
		id:       uuid.NewString(),
		subject:  request.GetSubject(),
		clientID: clientOf(request),
		audience: request.GetAudience(),
		scopes:   request.GetScopes(),
		claims:   claims,
		expires:  time.Now().Add(lifetime),
	}
	s.mu.Lock()
	s.tokens[issued.id] = issued
	s.mu.Unlock()
	return issued, nil
}

// clientOf reads the client id off whichever kind of request this is.
func clientOf(request op.TokenRequest) string {
	type withClient interface{ GetClientID() string }
	if c, ok := request.(withClient); ok {
		return c.GetClientID()
	}
	return ""
}

// claimsFor is what a token carries beyond its identity fields.
func (s *Storage) claimsFor(ctx context.Context, request op.TokenRequest) (map[string]any, error) {
	if exchange, ok := request.(op.TokenExchangeRequest); ok {
		return s.GetPrivateClaimsFromTokenExchangeRequest(ctx, exchange)
	}
	return s.GetPrivateClaimsFromScopes(ctx, request.GetSubject(), clientOf(request), request.GetScopes())
}

// TokenRequestByRefreshToken implements [op.AuthStorage].
func (s *Storage) TokenRequestByRefreshToken(_ context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	session, ok := s.iss.Sessions().ByToken(refreshToken)
	if !ok {
		return nil, op.ErrInvalidRefreshToken
	}
	return &refreshRequest{session: session}, nil
}

// refreshRequest is a live session presented for renewal.
type refreshRequest struct {
	session Session
	scopes  []string
}

var _ op.RefreshTokenRequest = (*refreshRequest)(nil)

func (r *refreshRequest) GetAMR() []string            { return []string{"pwd"} }
func (r *refreshRequest) GetAudience() []string       { return []string{r.session.ClientID} }
func (r *refreshRequest) GetAuthTime() time.Time      { return r.session.IssuedAt }
func (r *refreshRequest) GetClientID() string         { return r.session.ClientID }
func (r *refreshRequest) GetScopes() []string         { return r.scopes }
func (r *refreshRequest) GetSubject() string          { return r.session.Identity }
func (r *refreshRequest) SetCurrentScopes(s []string) { r.scopes = s }

// GetRefreshTokenInfo implements [op.AuthStorage].
func (s *Storage) GetRefreshTokenInfo(_ context.Context, _ string, tok string) (string, string, error) {
	session, ok := s.iss.Sessions().ByToken(tok)
	if !ok {
		return "", "", op.ErrInvalidRefreshToken
	}
	return session.Identity, session.ID, nil
}

// RevokeToken ends a session or an access token. It is RFC 7009, and it
// is the mechanism under both Revoke in the console and a person's own
// sign-out-everywhere.
func (s *Storage) RevokeToken(_ context.Context, tokenOrTokenID, _, _ string) *oidc.Error {
	// The library resolves a refresh token through GetRefreshTokenInfo
	// first and then hands back what that returned, so this is the
	// session id for a refresh token and the raw value for anything else.
	// Both have to work, or revocation silently succeeds while the
	// session lives on — which is the worst possible outcome for a
	// security control whose entire job is to end access.
	if s.iss.Sessions().RevokeToken(tokenOrTokenID) || s.iss.Sessions().RevokeID(tokenOrTokenID) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, tokenOrTokenID)
	// A token that was already gone is a success: revocation is
	// idempotent, and saying otherwise tells a caller whether a token
	// they do not hold ever existed.
	return nil
}

// TerminateSession ends what an identity holds at one client, which is
// where RP-initiated logout arrives after the proxy has ended its own.
func (s *Storage) TerminateSession(_ context.Context, identity, clientID string) error {
	s.iss.Sessions().Revoke(Query{Identity: identity, ClientID: clientID})
	return nil
}

// --------------------------------------------------------------- claims

// SetUserinfoFromScopes implements [op.OPStorage].
func (s *Storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	// Deprecated in the library in favour of SetUserinfoFromToken; an
	// empty implementation is what it asks for.
	return nil
}

// SetUserinfoFromToken implements [op.OPStorage].
func (s *Storage) SetUserinfoFromToken(ctx context.Context, info *oidc.UserInfo, tokenID, _, _ string) error {
	s.mu.Lock()
	issued, ok := s.tokens[tokenID]
	s.mu.Unlock()
	if !ok {
		return errors.New("no such token")
	}
	return s.fill(ctx, info, issued.subject, issued.claims)
}

// SetIntrospectionFromToken implements [op.OPStorage].
func (s *Storage) SetIntrospectionFromToken(context.Context, *oidc.IntrospectionResponse, string, string, string) error {
	// Introspection is deliberately not served: access tokens are JWTs
	// verified offline against the JWKS, so an endpoint that answers
	// questions about them is surface with no consumer.
	return errors.New("introspection is not served by this issuer")
}

// GetPrivateClaimsFromScopes implements [op.OPStorage].
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, subject, _ string, _ []string) (map[string]any, error) {
	resolved, err := s.iss.resolver.Resolve(ctx, subject)
	if err != nil {
		return nil, err
	}
	return Claims(s.iss.Policy().Evaluate(resolved.Input(subject))), nil
}

func (s *Storage) fill(_ context.Context, info *oidc.UserInfo, subject string, claims map[string]any) error {
	info.Subject = subject
	if strings.Contains(subject, "@") {
		info.Email = subject
		info.EmailVerified = true
	}
	for name, value := range claims {
		info.AppendClaims(name, value)
	}
	return nil
}

// GetKeyByIDAndClientID implements [op.OPStorage].
func (s *Storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("the JWT profile for client authentication is not wired in the spike")
}

// ValidateJWTProfileScopes implements [op.OPStorage].
func (s *Storage) ValidateJWTProfileScopes(_ context.Context, _ string, scopes []string) ([]string, error) {
	return scopes, nil
}

// ------------------------------------------------------------- exchange

// VerifyExchangeSubjectToken is where the issuer's trust in another
// system begins and ends: a GitHub identity token checked against
// GitHub's keys and the organisation allow-list, or a ServiceAccount
// token checked with TokenReview. What comes back is a proof, not a
// permission.
func (s *Storage) VerifyExchangeSubjectToken(
	ctx context.Context, tok string, tokenType oidc.TokenType,
) (string, string, map[string]any, error) {
	if s.verify == nil {
		return "", "", nil, ErrUnverified
	}
	proof, err := s.verify.Verify(ctx, tok, string(tokenType))
	if err != nil {
		return "", "", nil, err
	}
	subject := proof.Subject()
	if subject == "" {
		return "", "", nil, ErrUnverified
	}
	return tok, subject, proofClaims(proof), nil
}

// VerifyExchangeActorToken is not served: delegation, where one party
// acts for another, is a second principal in a token and this design has
// exactly one.
func (s *Storage) VerifyExchangeActorToken(
	context.Context, string, oidc.TokenType,
) (string, string, map[string]any, error) {
	return "", "", nil, errors.New("acting for another party is not served by this issuer")
}

// proofClaims carries the verified proof through the library, which hands
// the claims back at validation time.
func proofClaims(proof Proof) map[string]any {
	out := map[string]any{}
	if proof.Email != "" {
		out["email"] = proof.Email
	}
	if g := proof.GitHub; g != nil {
		out["repository"], out["repository_owner"] = g.Repository, g.Owner
		out["ref"], out["workflow"], out["environment"] = g.Ref, g.Workflow, g.Environment
	}
	if sa := proof.ServiceAccount; sa != nil {
		out["namespace"], out["serviceaccount"] = sa.Namespace, sa.Name
	}
	return out
}

// ValidateTokenExchangeRequest is the gate. The requested audience is a
// client; the proof resolves to internal groups; the client's `requires`
// decides. Refusing here is the whole of the rule-gated audience design,
// because a cloud trust policy for a custom issuer can see only sub, aud,
// amr and email — so the decision has to ride in the audience, and an
// audience wrongly minted is an audience wrongly trusted.
func (s *Storage) ValidateTokenExchangeRequest(ctx context.Context, request op.TokenExchangeRequest) error {
	audiences := request.GetAudience()
	if len(audiences) != 1 {
		return oidc.ErrInvalidTarget().WithDescription("name exactly one audience: it is the decision")
	}

	proof := proofFrom(request.GetExchangeSubjectTokenClaims())
	grant, err := s.iss.Exchange(ctx, proof, audiences[0])
	switch {
	case errors.Is(err, ErrUnknownTarget), errors.Is(err, ErrNoTarget):
		return oidc.ErrInvalidTarget().WithDescription("%s", err)
	case errors.Is(err, ErrRefused):
		return oidc.ErrInvalidTarget().WithDescription("%s", err)
	case err != nil:
		return oidc.ErrInvalidGrant().WithDescription("%s", err)
	}

	// The subject is the proof's, never the caller's, and the token is
	// good for one audience only.
	request.SetSubject(grant.Subject)
	// An access token and nothing else: an exchange must not hand back a
	// refresh token. The proof a job presented is short-lived by design —
	// GitHub mints it per run — and trading it for a credential that
	// outlives the run would undo that, leaving a standing key on a
	// machine whose whole appeal is that it holds none. When the token
	// expires the job asks again, or it is over.
	request.SetRequestedTokenType(oidc.AccessTokenType)
	s.grants.Store(request, grant)
	return nil
}

// proofFrom rebuilds a proof from the claims the verifier returned.
func proofFrom(claims map[string]any) Proof {
	str := func(name string) string {
		s, _ := claims[name].(string)
		return s
	}
	proof := Proof{Email: str("email")}
	if repo := str("repository"); repo != "" {
		proof.GitHub = &policy.GitHubClaims{
			Repository: repo, Owner: str("repository_owner"), Ref: str("ref"),
			Workflow: str("workflow"), Environment: str("environment"),
		}
	}
	if ns := str("namespace"); ns != "" {
		proof.ServiceAccount = &policy.ServiceAccountRef{Namespace: ns, Name: str("serviceaccount")}
	}
	return proof
}

func (s *Storage) grantFor(request op.TokenExchangeRequest) (Grant, bool) {
	value, ok := s.grants.Load(request)
	if !ok {
		return Grant{}, false
	}
	grant, ok := value.(Grant)
	return grant, ok
}

// CreateTokenExchangeRequest implements [op.TokenExchangeStorage].
func (s *Storage) CreateTokenExchangeRequest(context.Context, op.TokenExchangeRequest) error {
	// Nothing to store: the grant is already decided and held for the
	// life of this request, and an audit record belongs in the log rather
	// than in the token store.
	return nil
}

// GetPrivateClaimsFromTokenExchangeRequest implements [op.TokenExchangeStorage].
func (s *Storage) GetPrivateClaimsFromTokenExchangeRequest(
	_ context.Context, request op.TokenExchangeRequest,
) (map[string]any, error) {
	grant, ok := s.grantFor(request)
	if !ok {
		return nil, errors.New("the exchange was not validated")
	}
	return grant.Claims, nil
}

// SetUserinfoFromTokenExchangeRequest implements [op.TokenExchangeStorage].
func (s *Storage) SetUserinfoFromTokenExchangeRequest(
	ctx context.Context, info *oidc.UserInfo, request op.TokenExchangeRequest,
) error {
	grant, ok := s.grantFor(request)
	if !ok {
		return errors.New("the exchange was not validated")
	}
	return s.fill(ctx, info, grant.Subject, grant.Claims)
}
