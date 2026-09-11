package issuer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/truvity/access-roster/internal/logsafe"
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
	ID       string         `json:"id"`
	Subject  string         `json:"subject"`
	ClientID string         `json:"clientID"`
	Audience []string       `json:"audience,omitempty"`
	Scopes   []string       `json:"scopes,omitempty"`
	Claims   map[string]any `json:"claims,omitempty"`
	Expires  time.Time      `json:"expires"`
	// The account's own names, as the directory gave them at the moment
	// this token was minted. Identity and not authorization: they are
	// what `userinfo` and an ID token say so that a relying party's UI
	// shows a person rather than an address. Empty is normal.
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// authRequest is a login in progress: a browser part-way between the
// application that sent it and the directory that will say who it is.
//
// It is written down rather than held, because the browser that starts at
// one replica comes back at another. The library's own request travels
// with it: everything the protocol decided at /authorize — the scopes,
// the redirect, the PKCE challenge — has to survive to the moment the
// code is redeemed, and re-deriving any of it would be deciding it twice.
type authRequest struct {
	ID       string            `json:"id"`
	Req      *oidc.AuthRequest `json:"request"`
	Subject  string            `json:"subject,omitempty"`
	AuthTime time.Time         `json:"authTime,omitempty"`
	IsDone   bool              `json:"done,omitempty"`

	// How the person was proved: a provider kind, or "recovery". It is
	// the token's `acr`.
	How string `json:"how,omitempty"`

	// SSO is the browser session this request was completed against,
	// whether it was established just now or already existed. It travels
	// down into the per-client session so that ending the browser session
	// can find everything opened from it.
	SSO string `json:"sso,omitempty"`

	// Session is the session this request opened, learned when the code
	// is redeemed and used one step later to put `sid` in the ID token.
	// It is not written down with the rest: the library hands the SAME
	// request object to the token creation and to the ID token creation
	// within one exchange, and after that the request is deleted.
	Session string `json:"-"`
}

var _ op.AuthRequest = (*authRequest)(nil)

func (a *authRequest) GetID() string { return a.ID }

// GetACR says HOW this person was proved, which is the one claim a
// relying party can read to refuse a break-glass sign-in.
//
// It was empty, so a client asking with `acr_values` got no `acr` back —
// conformance says the server SHOULD return one, and more to the point a
// deployment had no way to tell a Google sign-in from recovery in a
// token. Recovery bypasses the directory by design; a relying party that
// wants to refuse it needs to be able to see it.
func (a *authRequest) GetACR() string { return acrFor(a.How) }

// GetAMR is what was presented. It used to say `pwd` unconditionally,
// which is untrue of every sign-in this issuer serves: a recovery
// sign-in presents a ServiceAccount token, and a directory sign-in
// presents whatever the provider asked for — which we are not told, so
// claiming a password is an invention.
func (a *authRequest) GetAMR() []string       { return amrFor(a.How) }
func (a *authRequest) GetAudience() []string  { return []string{a.Req.ClientID} }
func (a *authRequest) GetAuthTime() time.Time { return a.AuthTime }
func (a *authRequest) GetClientID() string    { return a.Req.ClientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.Req.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: a.Req.CodeChallenge, Method: a.Req.CodeChallengeMethod}
}
func (a *authRequest) GetNonce() string                   { return a.Req.Nonce }
func (a *authRequest) GetRedirectURI() string             { return a.Req.RedirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType { return a.Req.ResponseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return a.Req.ResponseMode }
func (a *authRequest) GetScopes() []string                { return a.Req.Scopes }
func (a *authRequest) GetState() string                   { return a.Req.State }
func (a *authRequest) GetSubject() string                 { return a.Subject }
func (a *authRequest) Done() bool                         { return a.IsDone }

// Storage is the shell the OpenID library needs, over the issuer's
// decision core. It stores; it does not decide. Every question about
// entitlement goes to the [Issuer], so that the console, the token and
// the audit trail cannot disagree about what someone is allowed.
type Storage struct {
	iss     *Issuer
	verify  Verifier
	key     *SigningKey
	secrets func(clientID string) (string, bool)
	// log is for the few things here worth saying out loud. Nothing in
	// this file logged until a reused authorization code needed to be —
	// which is either a broken client or a stolen code, and both are
	// worth seeing.
	log *slog.Logger

	// state is shared by every replica, because a login is not: a browser
	// starts at /authorize on one, comes back from the provider at
	// another, and the client redeems the code at a third.
	state State

	// grants is per-process on purpose. It carries an exchange decision
	// between two calls the library makes about the *same* request, in
	// the same handler, microseconds apart — writing that down would be
	// storing something that never outlives the function that made it.
	grants sync.Map // op.TokenExchangeRequest → Grant
}

// The authentication context classes this issuer can report. Custom
// URNs because no registered class describes "a corporate directory
// federated here" or "a ServiceAccount the cluster vouched for", and an
// approximate standard value would be a claim that reads as precise.
const (
	ACRDirectory = "urn:truvity:access-roster:acr:directory"
	ACRRecovery  = "urn:truvity:access-roster:acr:recovery"
)

// RecoveryHow is what a recovery sign-in records as its method. The
// rest of that vocabulary is a PROVIDER KIND -- "google", "entra" --
// which is a different set from the per-client session's `How`, and
// the reason this maps rather than switching on that type.
const RecoveryHow = "recovery"

// acrFor maps how somebody was proved onto a class a relying party can
// act on. The distinction that earns its keep is DIRECTORY against
// RECOVERY: one went through the company's own identity provider, the
// other bypassed it on purpose.
func acrFor(how string) string {
	if how == RecoveryHow {
		return ACRRecovery
	}

	// A provider kind, or empty on a deployment that records none:
	// the directory answered, which is the ordinary case.
	return ACRDirectory
}

// amrFor is what was actually presented, and nothing more. An empty list
// is the honest answer where we were not told, which is most of the time:
// the provider knows whether there was a second factor and does not say.
func amrFor(how string) []string {
	if how == RecoveryHow {
		// Not a password and not a person: a token the API server
		// vouched for.
		return []string{"swk"}
	}

	return nil
}

// How long each kind of thing in a login flow is worth keeping. Nothing
// here is state a person would miss: an abandoned login is abandoned, and
// a code nobody redeemed is a browser that closed.
const (
	// authRequestTTL bounds a login from /authorize to the redirect back.
	// Generous, because it spans a person reading a consent screen.
	authRequestTTL = 30 * time.Minute
	// authCodeTTL bounds the moment between the redirect and the token
	// call, which is a machine talking to a machine.
	authCodeTTL = 5 * time.Minute
)

// Keys. The prefix is what tells one kind from another in a store shared
// with the hub's snapshots.
func requestKey(id string) string { return "issuer:request:" + id }
func codeKey(code string) string  { return "issuer:code:" + code }

// logger is the storage's, or the default when a caller supplied none.
func (s *Storage) logger() *slog.Logger {
	if s.log != nil {
		return s.log
	}

	return slog.Default()
}

// codeSessionKey remembers which session one authorization code opened,
// so that a reuse of that code can end it.
func codeSessionKey(request string) string { return "issuer:code-session:" + request }
func tokenKey(id string) string            { return "issuer:token:" + id }

var (
	_ op.Storage                            = (*Storage)(nil)
	_ op.TokenExchangeStorage               = (*Storage)(nil)
	_ op.TokenExchangeTokensVerifierStorage = (*Storage)(nil)
)

// NewStorage returns the storage over an issuer.
//
// secrets resolves a confidential client's secret, which lives in a
// Kubernetes Secret and never in the policy file. key is the signing key;
// a nil one is generated, which is right for a local run and wrong for a
// deployment — see [SigningKey]. state is where a login in progress
// lives; a nil one is kept in this process, which is right for one
// replica and wrong for more — see [State].
func NewStorage(
	iss *Issuer, verify Verifier, secrets func(string) (string, bool),
	key *SigningKey, state State,
) (*Storage, error) {
	if key == nil {
		generated, err := NewSigningKey()
		if err != nil {
			return nil, err
		}
		key = generated
	}
	if secrets == nil {
		secrets = func(string) (string, bool) { return "", false }
	}
	if state == nil {
		state = NewMemoryState()
	}
	// Nothing here implements op.DeviceAuthorizationStorage, and that is
	// the mechanism by which the device flow is not served (INF-693). The
	// library type-asserts for it and refuses the grant when the
	// assertion fails, so there is no device state to keep and no way for
	// a device code to be stored by something that changed its mind.
	return &Storage{
		iss:     iss,
		verify:  verify,
		key:     key,
		secrets: secrets,
		state:   state,
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
func (s *Storage) CreateAuthRequest(
	ctx context.Context, req *oidc.AuthRequest, subject string,
) (op.AuthRequest, error) {
	out := &authRequest{ID: uuid.NewString(), Req: req, Subject: subject, AuthTime: time.Now()}
	if err := setJSON(ctx, s.state, requestKey(out.ID), out, authRequestTTL); err != nil {
		return nil, err
	}
	return out, nil
}

// AuthRequestByID implements [op.AuthStorage].
func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	req, err := s.request(ctx, id)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (s *Storage) request(ctx context.Context, id string) (*authRequest, error) {
	req, err := getJSON[authRequest](ctx, s.state, requestKey(id))
	switch {
	case err != nil:
		return nil, err
	case req == nil:
		// Expired or never existed, and the two are the same answer to
		// the caller: there is nothing to continue.
		return nil, errors.New("no such authorization request")
	}
	return req, nil
}

// AuthRequestByCode implements [op.AuthStorage].
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	raw, found, err := s.state.Get(ctx, codeKey(code))
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, errors.New("no such authorization code")
	}

	request, err := s.AuthRequestByID(ctx, string(raw))
	if err != nil {
		// The code is known and its request is gone, which is what a
		// SECOND redemption looks like: the first one deleted the
		// request. RFC 6749 4.1.2 says deny it and revoke what it
		// already issued, and the second half is the one that matters —
		// a code presented twice is a code somebody else has, and the
		// tokens from its first use are the ones now in doubt.
		s.revokeCodeSession(ctx, string(raw))

		return nil, err
	}

	return request, nil
}

// revokeCodeSession ends the session one authorization code opened, on
// learning that the code was presented a second time.
//
// Best effort and silent about it: this runs while answering a request
// that is being refused anyway, and a failure here must not turn a
// refusal into a server error.
func (s *Storage) revokeCodeSession(ctx context.Context, request string) {
	raw, found, err := s.state.Get(ctx, codeSessionKey(request))
	if err != nil || !found {
		return
	}

	gone, err := s.iss.Sessions().RevokeID(ctx, string(raw))
	if err != nil {
		s.logger().WarnContext(ctx, "an authorization code was reused and its session could not be ended",
			"error", err)

		return
	}

	// WARN and not INFO: a code presented twice is either a broken client
	// or a stolen code, and both are worth seeing in a log.
	s.logger().WarnContext(ctx, "an authorization code was reused; the session it opened has been ended",
		"ended", gone)

	_ = s.state.Delete(ctx, codeSessionKey(request))
}

// SaveAuthCode implements [op.AuthStorage].
func (s *Storage) SaveAuthCode(ctx context.Context, id, code string) error {
	if _, err := s.request(ctx, id); err != nil {
		return err
	}
	return s.state.Set(ctx, codeKey(code), []byte(id), authCodeTTL)
}

// DeleteAuthRequest implements [op.AuthStorage].
//
// The code is not deleted with it, and does not need to be: it expires on
// its own, and it resolves to a request that is already gone. Hunting for
// it would mean an index from request to code kept only to tidy up.
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.state.Delete(ctx, requestKey(id))
}

// Complete marks a login as finished, which is what the issuer's own
// sign-in page calls once an identity provider has said who is there.
func (s *Storage) Complete(id string, who Authenticated) error {
	ctx := context.Background()
	req, err := s.request(ctx, id)
	if err != nil {
		return err
	}

	authTime := who.AuthTime
	if authTime.IsZero() {
		authTime = time.Now()
	}

	req.Subject, req.IsDone = strings.ToLower(who.Subject), true
	// NOT time.Now(): a request completed silently against a session
	// established an hour ago authenticated an hour ago, and `auth_time`
	// is the one claim that has to say so — it is what a
	// re-authenticate-for-this-action rule reads.
	req.AuthTime, req.SSO, req.How = authTime, who.SSO, who.How

	return setJSON(ctx, s.state, requestKey(id), req, authRequestTTL)
}

// Pending reports what an authorization request asks of a sign-in, so
// that the sign-in pages can answer it without knowing the protocol.
func (s *Storage) Pending(id string) (Pending, error) {
	req, err := s.request(context.Background(), id)
	if err != nil {
		return Pending{}, err
	}

	out := Pending{RedirectURI: req.Req.RedirectURI, State: req.Req.State}

	for _, prompt := range req.Req.Prompt {
		switch prompt {
		case oidc.PromptLogin, oidc.PromptSelectAccount:
			out.ForcesLogin = true
		case oidc.PromptNone:
			out.ForbidsUI = true
		}
	}

	if req.Req.MaxAge != nil {
		out.MaxAge = time.Duration(*req.Req.MaxAge) * time.Second
		// `max_age=0` is "authenticate now" -- the same demand
		// `prompt=login` makes, said with a different word. Reading it as
		// "no maximum" (which a zero duration otherwise means here) would
		// answer a request for a fresh authentication with an old one.
		if *req.Req.MaxAge == 0 {
			out.ForcesLogin = true
		}
	}

	return out, nil
}

// --------------------------------------------------------------- tokens

// CreateAccessToken implements [op.AuthStorage].
func (s *Storage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	issued, err := s.issue(ctx, request)
	if err != nil {
		return "", time.Time{}, err
	}
	return issued.ID, issued.Expires, nil
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
		live, ok, err := s.iss.Sessions().Refreshed(ctx, currentRefreshToken, refresh)
		if err != nil {
			return "", "", time.Time{}, oidc.ErrServerError().WithDescription("%s", err)
		}

		if !ok {
			return "", "", time.Time{}, oidc.ErrInvalidGrant().WithDescription("the refresh token is not live")
		}

		_ = live
		return issued.ID, refresh, issued.Expires, nil
	}

	how := HowCode
	if _, ok := request.(op.TokenExchangeRequest); ok {
		how = HowExchange
	}
	session, err := s.iss.Sessions().Record(ctx, Opened{
		Identity: issued.Subject,
		ClientID: clientOf(request),
		How:      how,
		Token:    refresh,
		Scopes:   request.GetScopes(),
		SSO:      ssoOf(request),
		AuthTime: authTimeOf(request),
	})
	if err != nil {
		return "", "", time.Time{}, oidc.ErrServerError().WithDescription("%s", err)
	}

	// The ID token minted a moment from now names this session. The
	// library passes this very request object on to CreateIDToken, which
	// is the only reason the id can travel without a second lookup.
	if opened, ok := request.(*authRequest); ok {
		opened.Session = session.ID

		// And remember which session this CODE produced, so that a reuse
		// of it can end that session. RFC 6749 4.1.2: a code used twice
		// must be denied and SHOULD revoke the tokens already issued from
		// it — denying alone leaves a stolen code's first redemption
		// working while telling us it was stolen.
		//
		// Kept only as long as a code lives. After that a second
		// redemption is impossible anyway, and the note would be a record
		// of who signed in with nothing to do.
		if err = s.state.Set(ctx, codeSessionKey(opened.ID), []byte(session.ID), authCodeTTL); err != nil {
			// Not fatal to the sign-in that just succeeded: the person is
			// authenticated, and what is lost is a defence against a reuse
			// that may never come.
			s.logger().WarnContext(ctx, "could not record which session a code opened; "+
				"reusing that code will be denied but will revoke nothing", "error", err)
		}
	}

	return issued.ID, refresh, issued.Expires, nil
}

// SetUserinfoFromRequest implements [op.CanSetUserinfoFromRequest]: it is
// what puts a person INTO the ID token.
//
// The library's older hook, SetUserinfoFromScopes, is deprecated and
// empty here — and that emptiness was quietly load-bearing. Every client
// asserts userinfo claims in its ID token, so the library assembles one
// from whatever this storage supplies and assigns the result wholesale.
// Supplying nothing did not leave the ID token's own claims alone; it
// OVERWROTE them, so an ID token arrived carrying no `sub`, no `email`,
// no name and no `groups` — a token that is not merely thin but invalid,
// since `sub` is required of every one. A relying party reading the ID
// token, which is what ArgoCD and Kargo do, saw nobody.
//
// So this fills the same answer the userinfo endpoint gives, plus the one
// claim that belongs to the exchange rather than to the person: `sid`,
// the session this token belongs to. It lets a relying party say WHICH
// of a person's sessions it is holding — the same id the console lists
// and revokes — instead of only that it holds one. A token with no
// session behind it (a workload trading a proof, which opens none)
// carries no `sid` rather than an empty one.
func (s *Storage) SetUserinfoFromRequest(
	ctx context.Context, info *oidc.UserInfo, request op.IDTokenRequest, _ []string,
) error {
	subject := request.GetSubject()

	claims, given, family, err := s.identityOf(ctx, subject)
	if err != nil {
		return err
	}

	if err = s.fill(ctx, info, subject, claims, given, family); err != nil {
		return err
	}

	if id := sessionOf(request); id != "" {
		info.AppendClaims("sid", id)
	}

	return nil
}

// authTimeOf is when the person behind a token request authenticated, and
// the zero time for a request no person is behind. Not every kind of
// token request carries one, which is why it is asked for by shape.
func authTimeOf(request op.TokenRequest) time.Time {
	if with, ok := request.(interface{ GetAuthTime() time.Time }); ok {
		return with.GetAuthTime()
	}

	return time.Time{}
}

// ssoOf is the browser session a token request was authorized from, and
// nothing for a flow where no browser was involved.
func ssoOf(request op.TokenRequest) string {
	switch req := request.(type) {
	case *authRequest:
		return req.SSO
	case *refreshRequest:
		return req.session.SSO
	default:
		return ""
	}
}

// sessionOf is the session a token request belongs to: the one just
// opened for a redeemed code, or the one being renewed.
func sessionOf(request op.IDTokenRequest) string {
	switch req := request.(type) {
	case *authRequest:
		return req.Session
	case *refreshRequest:
		return req.session.ID
	default:
		return ""
	}
}

// issue records one access token and returns it.
func (s *Storage) issue(ctx context.Context, request op.TokenRequest) (*token, error) {
	claims, given, family, err := s.claimsFor(ctx, request)
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
		ID:       uuid.NewString(),
		Subject:  request.GetSubject(),
		ClientID: clientOf(request),
		Audience: request.GetAudience(),
		Scopes:   request.GetScopes(),
		Claims:   claims,
		Expires:  time.Now().Add(lifetime),
	}
	issued.GivenName, issued.FamilyName = given, family
	// Kept only until it expires: an access token past its lifetime
	// answers nothing, and a store that has to be swept is a store that
	// grows when the sweeper stops.
	if err = setJSON(ctx, s.state, tokenKey(issued.ID), issued, time.Until(issued.Expires)); err != nil {
		return nil, err
	}
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

// claimsFor is what a token carries beyond its identity fields, and what
// the account is called — from ONE answer, because they come from one.
func (s *Storage) claimsFor(
	ctx context.Context, request op.TokenRequest,
) (claims map[string]any, given, family string, err error) {
	if exchange, ok := request.(op.TokenExchangeRequest); ok {
		// An exchange is usually a job or a workload, which has no name.
		// A person trading one of their own tokens does, and the grant
		// decided what they may have without asking the directory what
		// they are called — so that stays a separate question here.
		claims, err = s.GetPrivateClaimsFromTokenExchangeRequest(ctx, exchange)
		if err != nil {
			return nil, "", "", err
		}

		given, family = s.namesOf(ctx, request.GetSubject())

		return claims, given, family, nil
	}

	return s.identityOf(ctx, request.GetSubject())
}

// TokenRequestByRefreshToken implements [op.AuthStorage].
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	session, ok, err := s.iss.Sessions().ByToken(ctx, refreshToken)
	if err != nil {
		return nil, oidc.ErrServerError().WithDescription("%s", err)
	}

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
func (r *refreshRequest) GetClientID() string         { return r.session.ClientID }
func (r *refreshRequest) GetSubject() string          { return r.session.Identity }
func (r *refreshRequest) SetCurrentScopes(s []string) { r.scopes = s }

// GetAuthTime is when the person behind this session authenticated —
// carried down from the browser session at sign-in, not the moment this
// session was opened and never the moment of this refresh. A session
// recorded before the field existed falls back to when it was issued,
// which is what the code answered for every session until now.
func (r *refreshRequest) GetAuthTime() time.Time {
	if !r.session.AuthTime.IsZero() {
		return r.session.AuthTime
	}

	return r.session.IssuedAt
}

// GetScopes is what this session was granted, until a narrower set is
// asked for and accepted.
//
// Answering nil here was wrong twice over: a refresh naming any scope at
// all was refused as though it had asked for more than it held, and one
// naming none produced an ID token with no `email` and no name, because
// the library assembles those from the scopes it is given. A relying
// party that shows who is signed in would have shown an address for an
// hour and then nothing.
func (r *refreshRequest) GetScopes() []string {
	if r.scopes != nil {
		return r.scopes
	}

	return r.session.Scopes
}

// GetRefreshTokenInfo implements [op.AuthStorage].
func (s *Storage) GetRefreshTokenInfo(ctx context.Context, _ string, tok string) (string, string, error) {
	session, ok, err := s.iss.Sessions().ByToken(ctx, tok)
	if err != nil {
		return "", "", oidc.ErrServerError().WithDescription("%s", err)
	}

	if !ok {
		return "", "", op.ErrInvalidRefreshToken
	}
	return session.Identity, session.ID, nil
}

// RevokeToken ends a session or an access token. It is RFC 7009, and it
// is the mechanism under both Revoke in the console and a person's own
// sign-out-everywhere.
func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID, _, _ string) *oidc.Error {
	// The library resolves a refresh token through GetRefreshTokenInfo
	// first and then hands back what that returned, so this is the
	// session id for a refresh token and the raw value for anything else.
	// Both have to work, or revocation silently succeeds while the
	// session lives on — which is the worst possible outcome for a
	// security control whose entire job is to end access.
	// Both, always, and in that order — never one *or* the other. A hit
	// on either is not proof that revocation is done: the access token
	// lives under its own key, and leaving it there would keep it valid
	// at every replica. A security control that reports success and
	// leaves access in place is worse than one that fails.
	if _, err := s.iss.Sessions().RevokeToken(ctx, tokenOrTokenID); err != nil {
		return oidc.ErrServerError().WithDescription("%s", err)
	}

	if _, err := s.iss.Sessions().RevokeID(ctx, tokenOrTokenID); err != nil {
		return oidc.ErrServerError().WithDescription("%s", err)
	}

	if err := s.state.Delete(ctx, tokenKey(tokenOrTokenID)); err != nil {
		return oidc.ErrServerError().WithDescription("%s", err)
	}
	// A token that was already gone is a success: revocation is
	// idempotent, and saying otherwise tells a caller whether a token
	// they do not hold ever existed.
	return nil
}

// TerminateSession is where the library lands RP-initiated logout, and
// it deliberately ends NOTHING. [SignOut] has already run by then and has
// ended the sign-in this browser holds and every session opened under it.
//
// It ends nothing because it cannot tell whose logout this is. The
// library calls it with the subject and client taken from the request,
// and a request can say anything:
//
//   - Nothing at all. No `id_token_hint` and no `client_id` leaves both
//     arguments empty, and an empty [Query] selects EVERY session in the
//     installation. That was live: one unauthenticated GET, by anyone, to
//     an address the discovery document publishes, ended every session
//     every person and every workload held.
//   - An `id_token_hint` belonging to somebody else. The specification
//     calls it a hint, not a credential, and the library accepts an
//     EXPIRED one by design (`IDTokenHintExpiredError` is tolerated in
//     ValidateEndSessionRequest). Old ID tokens sit in logs, in browser
//     history and in referrer headers, so honouring one as authority to
//     revoke hands anybody who finds one a way to sign that person out.
//
// What the request CAN prove is the cookie it carries, and that is what
// [SignOut] acts on. The hint keeps its real job — deciding which
// client's `signed_out` page the person lands on — which the library does
// without any help from here.
//
// The narrower job this used to do, ending one identity's sessions at one
// client, is served by `RevokeSessions` on the session service, which
// authorizes the caller before it acts.
func (s *Storage) TerminateSession(ctx context.Context, identity, clientID string) error {
	s.logger().DebugContext(ctx, "end_session revokes nothing here; the browser's sign-in decides",
		"identity", logsafe.Value(identity), "client_id", logsafe.Value(clientID))

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
	issued, err := getJSON[token](ctx, s.state, tokenKey(tokenID))
	if err != nil {
		return err
	}
	if issued == nil {
		return errors.New("no such token")
	}
	return s.fill(ctx, info, issued.Subject, issued.Claims, issued.GivenName, issued.FamilyName)
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
	claims, _, _, err := s.identityOf(ctx, subject)

	return claims, err
}

// identityOf asks the directory ONCE and returns everything one answer
// contains: what the policy grants this identity, and what the directory
// calls it.
//
// Once matters. The hub call behind this is the issuer's hottest, and
// every claim a token carries comes from the same answer — so asking
// twice is not only two round trips where the design counted on one, it
// is two answers that can disagree, with the grants from before a change
// and the name from after.
//
// A ServiceAccount subject is a recovery sign-in, and the hub is the
// wrong place to ask about it: it holds directories, and this is not a
// person in one. The policy's `service_account` matchers decide, exactly
// as they do for a workload exchanging a token -- one table, one
// evaluation, and nothing here that a matcher did not grant. It has no
// name, which is the truthful answer rather than a missing one.
func (s *Storage) identityOf(
	ctx context.Context, subject string,
) (claims map[string]any, given, family string, err error) {
	if account, ok := serviceAccountSubject(subject); ok {
		return Claims(s.iss.Policy().Evaluate(policy.Input{
			ServiceAccount: &account,
		})), "", "", nil
	}

	resolved, err := s.iss.resolver.Resolve(ctx, subject)
	if err != nil {
		return nil, "", "", err
	}

	return Claims(s.iss.Policy().Evaluate(resolved.Input(subject))),
		resolved.GivenName, resolved.FamilyName, nil
}

// serviceAccountSubject reads a ServiceAccount out of a subject, in
// whichever spelling minted it. [policy.ParseServiceAccountSubject] is
// the one place that knows there is more than one.
func serviceAccountSubject(subject string) (policy.ServiceAccountRef, bool) {
	return policy.ParseServiceAccountSubject(subject)
}

func (s *Storage) fill(
	_ context.Context, info *oidc.UserInfo, subject string, claims map[string]any, given, family string,
) error {
	info.Subject = subject

	if strings.Contains(subject, "@") {
		info.Email = subject
		info.EmailVerified = true
		// The address is also the username a relying party shows when it
		// has nothing better, and it is what this issuer's subject IS for
		// a person -- so saying it twice costs nothing and spares every
		// consumer a fallback.
		info.PreferredUsername = subject
	}

	// A person, when the directory said so. `name` is the whole of what a
	// UI usually renders, and given/family are there for the ones that
	// want the halves; none of it is authorization, and all of it is
	// absent for a workload or a recovery sign-in, which have no names to
	// give.
	info.GivenName, info.FamilyName = given, family

	switch {
	case given != "" && family != "":
		info.Name = given + " " + family
	case given != "":
		info.Name = given
	case family != "":
		info.Name = family
	}

	for name, value := range claims {
		info.AppendClaims(name, value)
	}

	return nil
}

// namesOf asks the directory what this account is called, for the claims
// that name a person. A failure is not one: the token is about what the
// identity may do, and a UI that shows an address instead of a name is a
// smaller thing than a login that did not happen.
func (s *Storage) namesOf(ctx context.Context, subject string) (given, family string) {
	if !strings.Contains(subject, "@") {
		return "", ""
	}

	resolved, err := s.iss.resolver.Resolve(ctx, subject)
	if err != nil {
		return "", ""
	}

	return resolved.GivenName, resolved.FamilyName
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
		// WHICH cluster, and it has to survive this round trip. The same
		// namespace and name exist on every cluster, so a subject without
		// it is the collision the qualifier exists to prevent — and a
		// `service_account` matcher that narrows to one cluster would
		// match nothing at all, silently, because the rule would be
		// compared against an empty string.
		if sa.Cluster != "" {
			out["cluster"] = sa.Cluster
		}
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
		proof.ServiceAccount = &policy.ServiceAccountRef{
			Cluster: str("cluster"), Namespace: ns, Name: str("serviceaccount"),
		}
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

	// An exchange is usually a job or a workload, which has no names. A
	// person exchanging one of their own tokens does, so ask the same way.
	given, family := s.namesOf(ctx, grant.Subject)

	return s.fill(ctx, info, grant.Subject, grant.Claims, given, family)
}
