package sessiond

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// pendingLife is how long a sign-in may take between the authorize request and the callback: the time to live of
// the kind PendingSignIn (10 minutes, its default and its maximum).
const pendingLife = 10 * time.Minute

// The bounds of what session takes from a client. They keep a request small enough to seal in a cookie and out of
// an audit field.
const (
	maxState       = 256 // RFC 6749 appendix A.5 gives no bound
	maxNonce       = 256
	maxRedirectURI = 1024
	maxScope       = 256
	// maxACRValues bounds the whole acr_values parameter, and maxACRCount the values in it. A value longer than maxACRLen
	// (assurance.go) could never be an acr of a token anyway.
	maxACRValues = 256
	maxACRCount  = 8

	// maxCookie is the longest sign-in cookie value entry passes on (HEADER_VALUE_MAX in entry's handler.rs). The
	// pending sign-in is sealed into it, so the client-supplied fields above (the state, the nonce, the redirect_uri and the
	// scope) and the subject of an id_token_hint (maxHintSubject) are bounded to keep it under.
	maxCookie = 4096
)

// The scopes session grants. The claims for profile and email arrive with the upstream claims allow-list; until
// then a token asked for them carries none (0020: personal data only where the scope asks and the upstream sent it).
var knownScopes = map[string]bool{"openid": true, "profile": true, "email": true}

// Authorize starts a sign-in: it checks the request against the client's declaration (RFC 6749 section 4.1.1, RFC
// 7636, OpenID Connect Core section 3.1.2), makes the upstream request with a state, a nonce and a PKCE challenge of
// its own, seals what it must remember in the sign-in cookie and redirects the browser to the upstream.
//
// An error that cannot go to the client's redirect_uri (an unknown client, a redirect_uri that is not registered)
// gets a fixed page, because redirecting to an address the client did not register is an open redirect (RFC 6749
// section 10.15). Every other error goes to the registered redirect_uri as RFC 6749 section 4.1.2.1 says.
func (s *Service) Authorize(ctx context.Context, req *connect.Request[sessionv2alpha1.AuthorizeRequest]) (*connect.Response[typev2alpha1.HttpReply], error) {
	r := req.Msg
	b, err := s.opts.Config.Boundary(ctx)
	if err != nil {
		return nil, unavailable("boundary", err)
	}
	tenant := b.GetDefaultTenant()
	// page answers what cannot be redirected: code is the error of RFC 6749 section 4.1.2.1 that the client would have had,
	// and declared says the client is one the installation declares.
	page := func(code, reason, clientID string, declared bool) (*connect.Response[typev2alpha1.HttpReply], error) {
		named := ""
		if declared {
			named = clientID
		}
		logRefusal(actionAuthorize, code, reason, named)
		if aerr := s.record(ctx, audited{action: actionAuthorize, tenant: tenant, subject: clientSubject(tenant, clientID), reason: reason}); aerr != nil {
			return nil, aerr
		}
		return errorPage(ctx), nil
	}
	cl, err := s.opts.Config.Client(ctx, r.GetClientId())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return page("invalid_request", reasonClient, "unregistered", false)
	case err != nil:
		return nil, unavailable("client", err)
	}
	// Only a public client signs people in tonight: a confidential client needs its secret checked (the secret
	// kinds are not served yet), and an exchange client never asks for a person's code.
	if cl.GetKind() != "public" {
		return page("unauthorized_client", reasonClient, cl.GetId(), true)
	}
	if tenant, err = tenantOf(b, cl); err != nil {
		return nil, internal("tenant", err)
	}
	if len(r.GetRedirectUri()) > maxRedirectURI || !redirectRegistered(cl.GetRedirects(), r.GetRedirectUri()) ||
		!plainRedirectAllowed(b.GetEnvironment(), cl, r.GetRedirectUri()) {
		return page("invalid_request", reasonRedirectURI, cl.GetId(), true)
	}

	// From here the redirect_uri is the client's own.
	fail := func(code, desc, reason string) (*connect.Response[typev2alpha1.HttpReply], error) {
		logRefusal(actionAuthorize, code, reason, cl.GetId())
		out, rerr := clientRedirect(answerMode(r.GetResponseMode()), r.GetRedirectUri(), safeState(r.GetState()), b.GetIssuer(), url.Values{"error": {code}, "error_description": {desc}})
		if rerr != nil {
			return nil, internal("redirect", rerr)
		}
		if aerr := s.record(ctx, audited{action: actionAuthorize, tenant: tenant, subject: clientSubject(tenant, cl.GetId()), reason: reason}); aerr != nil {
			return nil, aerr
		}
		return out, nil
	}
	// Parameters of OpenID Connect Core that session does not serve are answered with the error of section 3.1.2.6 for each,
	// to the client's redirect_uri, and are never ignored: ignoring a request object would drop what the client signed or
	// asked for. Discovery says so (request_uri_parameter_supported false; request_parameter_supported is absent, so false).
	switch {
	case r.GetRequest() != "":
		return fail("request_not_supported", "request objects are not served", reasonRequest)
	case r.GetRequestUri() != "":
		return fail("request_uri_not_supported", "request_uri is not served", reasonRequest)
	case r.GetRegistration() != "":
		return fail("registration_not_supported", "registration is not served", reasonRequest)
	}
	if !vschar(r.GetState(), maxState, true) {
		return fail("invalid_request", "state is malformed", reasonRequest)
	}
	if !vschar(r.GetNonce(), maxNonce, true) {
		return fail("invalid_request", "nonce is malformed", reasonRequest)
	}
	// A request with no response_type is missing a required parameter (RFC 6749 section 4.1.2.1: invalid_request); one that
	// names a type session does not serve is unsupported_response_type.
	if r.GetResponseType() == "" {
		return fail("invalid_request", "response_type is required", reasonRequest)
	}
	if r.GetResponseType() != "code" {
		return fail("unsupported_response_type", "only the code flow is served", reasonRequest)
	}
	// The query and form_post are the response modes of the code flow (OAuth 2.0 Form Post Response Mode); fragment, and the
	// JWT modes, are not served. A refusal of the mode itself goes to the client in the query.
	if m := r.GetResponseMode(); m != "" && m != "query" && m != responseModeFormPost {
		return fail("invalid_request", "only the query and form_post response modes are served", reasonRequest)
	}
	if r.GetCodeChallengeMethod() != "S256" || !validChallenge(r.GetCodeChallenge()) {
		return fail("invalid_request", "PKCE with S256 is required", reasonPKCE)
	}
	// An unknown scope is refused, not dropped (REQ-CLIENT-022): invalid_scope is "invalid, unknown, or malformed"
	// (RFC 6749 section 4.1.2.1). The description names no scope; the audit record says which rule refused.
	scope, err := grantedScope(r.GetScope())
	switch {
	case errors.Is(err, errScopeUnknown):
		return fail("invalid_scope", "a requested scope is not served", reasonScope)
	case err != nil:
		return fail("invalid_scope", "the openid scope is required", reasonRequest)
	}
	// What the client asks of the person's authentication (OpenID Connect Core section 3.1.2.1) is the upstream's to
	// do: session keeps no sign-in session of its own for a returning browser (0018), so prompt=none asks the upstream
	// to answer without interaction, and prompt=login and max_age=0 ask it to authenticate the person again. Each is
	// passed on in BeginRequest, and the callback holds the upstream to it.
	pr, perr := parsePrompt(r.GetPrompt())
	switch {
	case errors.Is(perr, errPromptMalformed), errors.Is(perr, errPromptNoneAndOther):
		return fail("invalid_request", "the prompt is malformed", reasonPrompt)
	case errors.Is(perr, errPromptConsent):
		return fail("consent_required", "consent is not asked for", reasonPrompt)
	case errors.Is(perr, errPromptAccount):
		return fail("account_selection_required", "an account is not chosen here", reasonPrompt)
	}
	// acr_values (OpenID Connect Core section 3.1.2.1, RFC 9470): the client names the authentication it needs, and the
	// callback holds the upstream to it. The list goes to the upstream as given, so that the upstream can meet it.
	// The whole request is held to the limits first; then only the values this boundary lists are enforced (OpenID Connect
	// Core makes acr_values voluntary, and a client that asks for a level this boundary does not know is served, not refused),
	// and the others are ignored and counted.
	asked, err := parseACRValues(r.GetAcrValues())
	if err != nil {
		return fail("invalid_request", "acr_values is malformed", reasonACR)
	}
	acrValues, ignoredACR := enforcedACRValues(asked, b.GetAcrValuesSupported())
	// max_age is kept in the pending sign-in and checked against the upstream's auth_time at the callback. max_age=0
	// asks for a fresh authentication, the same as prompt=login.
	var maxAge *int64
	if m := r.GetMaxAge(); m != "" {
		n, err := strconv.ParseUint(m, 10, 31)
		if err != nil {
			return fail("invalid_request", "max_age is malformed", reasonRequest)
		}
		v := int64(n)
		maxAge = &v
	}

	// An id_token_hint names the person the client expects (OpenID Connect Core section 3.1.2.1). Its subject is kept in the
	// pending sign-in, and the callback refuses a sign-in of another person with login_required: ignoring the hint would
	// answer for whoever signs in.
	hintSub := ""
	if h := r.GetIdTokenHint(); h != "" {
		if hintSub, err = hintSubject(h, b.GetIssuer(), cl.GetId()); err != nil {
			return fail("invalid_request", "id_token_hint is not an ID token of this issuer for this client", reasonHint)
		}
	}

	up, err := s.opts.Config.Upstream(ctx, s.opts.UpstreamName)
	if err != nil {
		return nil, unavailable("upstream", err)
	}
	upState, err := randomToken()
	if err != nil {
		return nil, internal("random", err)
	}
	upNonce, err := randomToken()
	if err != nil {
		return nil, internal("random", err)
	}
	verifier, err := randomToken()
	if err != nil {
		return nil, internal("random", err)
	}
	pid, err := randomID()
	if err != nil {
		return nil, internal("random", err)
	}
	now := s.now()
	begin, err := s.opts.Upstream.Begin(ctx, connect.NewRequest(&integrationv2alpha1.BeginRequest{
		Upstream:      up.GetName(),
		RedirectUri:   callbackURL(b.GetIssuer()),
		State:         upState,
		Nonce:         upNonce,
		CodeChallenge: s256(verifier),
		Prompt:        pr,
		MaxAge:        maxAge,
		AcrValues:     acrValues,
	}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnavailable || connect.CodeOf(err) == connect.CodeDeadlineExceeded {
			return nil, unavailable("upstream", err)
		}
		return fail("server_error", "the sign-in could not start", reasonUpstream)
	}
	pending := &sessionv2alpha1.PendingSignIn{
		ClientId: cl.GetId(), RedirectUri: r.GetRedirectUri(), Scope: scope, State: r.GetState(), Nonce: r.GetNonce(),
		CodeChallenge: r.GetCodeChallenge(), Tenant: tenant, Upstream: up.GetName(),
		UpstreamState: upState, UpstreamNonce: upNonce, UpstreamVerifier: verifier,
		CreatedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(pendingLife)), MaxAge: maxAge, Prompt: pr,
		HintSubject: hintSub, ResponseMode: answerMode(r.GetResponseMode()), AcrValues: acrValues,
	}
	envelope, err := s.keys.sealFlow(ctx, pendingKind, pid, pending)
	if err != nil {
		return nil, unavailable("key", err)
	}
	cookie := pid + "." + base64.RawURLEncoding.EncodeToString(envelope)
	// entry reads a cookie value of at most 4096 bytes (maxCookie). The bounds above keep a request well inside it;
	// this is the check that no later change to them sets a cookie the browser's return would be refused for.
	if len(cookie) > maxCookie {
		return fail("invalid_request", "the request is too large", reasonRequest)
	}
	rec := audited{action: actionAuthorize, tenant: tenant, subject: clientSubject(tenant, cl.GetId())}
	if ignoredACR > 0 {
		// A count, never the values: the client chose them.
		rec.sluis = map[string]any{"ignored_acr_values": int64(ignoredACR)}
	}
	if aerr := s.record(ctx, rec); aerr != nil {
		return nil, aerr
	}
	return redirect(begin.Msg.GetAuthorizationUrl(), setCookie(cookie, cookieMaxAge)), nil
}

// errACRValues says the acr_values parameter is not a space-separated list of acr values.
var errACRValues = errors.New("acr_values: malformed")

// parseACRValues checks the space-separated acr_values of an authorization request and returns it as sent. Each value is
// a non-empty run of the characters of a scope token (RFC 6749 section 3.3: no space, quote or backslash) of at most
// maxACRLen bytes, separated by single spaces; the whole is at most maxACRValues bytes and maxACRCount values, so that it fits the
// sealed pending sign-in. Empty means the client sent none.
func parseACRValues(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if len(raw) > maxACRValues {
		return "", errACRValues
	}
	vs := strings.Split(raw, " ")
	if len(vs) > maxACRCount {
		return "", errACRValues
	}
	for _, v := range vs {
		if len(v) > maxACRLen || !scopeToken(v) {
			return "", errACRValues
		}
	}
	return raw, nil
}

// enforcedACRValues splits a request's acr_values by the boundary's list: the listed values, in the client's order and as one
// space-separated string, and the number of values that are not listed. A request with no listed value is enforced against
// none (the string is empty) and still succeeds; a request with one is enforced against the listed values alone and is met
// when one of them is. The unlisted values are never kept or logged, only counted.
func enforcedACRValues(asked string, supported []string) (enforced string, ignored int) {
	if asked == "" {
		return "", 0
	}
	var keep []string
	for _, v := range strings.Split(asked, " ") {
		if slices.Contains(supported, v) {
			keep = append(keep, v)
		} else {
			ignored++
		}
	}
	return strings.Join(keep, " "), ignored
}

// acrMet says whether the authentication met one of the acr values the client asked for: the acr the upstream stated is one
// of them, exactly. An upstream that stated none has shown nothing, so it meets none (REQ-AUTHN-009, REQ-AUTHN-034: no
// silent downgrade, and no guess from the methods in amr).
func acrMet(asked string, a assurance) bool {
	if a.acr == nil {
		return false
	}
	for _, v := range strings.Split(asked, " ") {
		if v == *a.acr {
			return true
		}
	}
	return false
}

// The ways a prompt is not served (OpenID Connect Core section 3.1.2.1). errPromptMalformed is a value outside the four
// the specification defines, an empty one, or a repeat; errPromptNoneAndOther is "none" with another value, which has no
// meaning; consent and select_account are values session cannot honour, because it shows no consent and no account
// chooser, so it answers the errors the specification names for that.
var (
	errPromptMalformed    = errors.New("prompt: malformed")
	errPromptNoneAndOther = errors.New("prompt: none with another value")
	errPromptConsent      = errors.New("prompt: consent cannot be asked")
	errPromptAccount      = errors.New("prompt: no account chooser")
)

// parsePrompt reads the space-delimited prompt of an authorization request and returns what the upstream is asked for:
// "none", "login", or "" when the client sent none. A value session cannot honour is an error, and is answered before
// any other value is acted on, so a client never gets a login in place of the consent it asked for.
func parsePrompt(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	seen := map[string]bool{}
	for _, v := range strings.Split(raw, " ") {
		switch v {
		case "none", "login", "consent", "select_account":
		default:
			return "", errPromptMalformed
		}
		if seen[v] {
			return "", errPromptMalformed
		}
		seen[v] = true
	}
	switch {
	case seen["none"] && len(seen) > 1:
		return "", errPromptNoneAndOther
	case seen["consent"]:
		return "", errPromptConsent
	case seen["select_account"]:
		return "", errPromptAccount
	case seen["none"]:
		return "none", nil
	}
	return "login", nil
}

// freshSkew is how far before the authorization request an upstream's auth_time may lie and still count as a fresh
// authentication for prompt=login or max_age=0: the clocks of sluis and of the upstream differ by seconds.
const freshSkew = 10 * time.Second

// pendingKind is the address segment of the kind PendingSignIn.
const pendingKind = "pending-sign-in"

// callbackURL is sluis's callback: the redirect_uri the upstream sends the person back to. entry serves /callback.
func callbackURL(issuer string) string { return strings.TrimSuffix(issuer, "/") + "/callback" }

// safeState returns the client's state for an error redirect, or "" when it is not a valid state: a malformed state
// is not reflected (RFC 6749 section 4.1.2.1 sends it back "if present").
func safeState(s string) string {
	if vschar(s, maxState, true) {
		return s
	}
	return ""
}

// vschar reports whether s is made of VSCHAR, %x20-7E (RFC 6749 appendix A), at most limit bytes; empty is allowed
// when emptyOK.
func vschar(s string, limit int, emptyOK bool) bool {
	if s == "" {
		return emptyOK
	}
	if len(s) > limit {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// validChallenge is an S256 challenge: 43 characters of base64url without padding (RFC 7636 section 4.2).
func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if !base64URLChar(ch) {
			return false
		}
	}
	return true
}

// The ways a requested scope is refused.
var (
	errScopeMalformed = errors.New("scope: malformed or without openid")
	errScopeUnknown   = errors.New("scope: unknown")
)

// grantedScope returns the requested scopes, each once, in the order asked. A scope session does not serve is an
// error, errScopeUnknown, and not left out (REQ-CLIENT-022): RFC 6749 section 3.3 lets a server grant less than was
// asked, but a client that asked for a scope it does not get would find out only from the token. A scope over the
// bound, one that is not scope-tokens joined by single spaces, or one without openid (OpenID Connect Core section
// 3.1.2.1), is errScopeMalformed.
func grantedScope(requested string) (string, error) {
	if len(requested) > maxScope {
		return "", errScopeMalformed
	}
	var out []string
	seen := map[string]bool{}
	// scope = scope-token *( SP scope-token ), scope-token = 1*NQCHAR (RFC 6749 section 3.3): one space between
	// tokens, so another whitespace, a doubled, leading or trailing space or a quote makes the scope malformed.
	for _, sc := range strings.Split(requested, " ") {
		if !scopeToken(sc) {
			return "", errScopeMalformed
		}
		if !knownScopes[sc] {
			return "", errScopeUnknown
		}
		if !seen[sc] {
			seen[sc] = true
			out = append(out, sc)
		}
	}
	if !seen["openid"] {
		return "", errScopeMalformed
	}
	return strings.Join(out, " "), nil
}

// scopeToken reports whether s is a scope-token of RFC 6749 section 3.3: one or more NQCHAR, %x21 / %x23-5B /
// %x5D-7E (appendix A), which leaves out space, '"' and '\\'.
func scopeToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// redirectRegistered reports whether got is one of the client's registered redirect URIs. The match is an exact string
// comparison (RFC 6749 section 3.1.2.3, and the Security BCP: no pattern), with the one exception of RFC 8252 section
// 7.3: a registered redirect on the loopback IP literal without a port matches any port, because a native app takes
// a free one at run time. A URI with a fragment or userinfo never matches (RFC 6749 section 3.1.2).
//
// A plain-http URI never matches unless its host is a loopback IP literal, even when the client registered it
// (REQ-AUTHN-004): store@ refuses such a registration at load, and this is the same rule where the redirect is used.
func redirectRegistered(registered []string, got string) bool {
	u, err := url.Parse(got)
	if err != nil || got == "" || u.Fragment != "" || u.User != nil || u.Opaque != "" || strings.Contains(got, "#") {
		return false
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !loopbackIP(u.Hostname())) {
		return false
	}
	for _, reg := range registered {
		if reg == got {
			return true
		}
		if loopbackMatch(reg, u) {
			return true
		}
	}
	return false
}

// plainRedirectAllowed is store@'s https floor where the redirect is used: outside a development boundary, a
// plain-http redirect (which redirectRegistered has already held to a loopback IP literal) is only a public client's
// with the native profile, an app on the person's own host (ADR 0011, "The local installation"; ADR 0021; RFC 8252
// section 7.3).
func plainRedirectAllowed(environment string, cl *configv2alpha1.InstallationClient, uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	if u.Scheme != "http" || environment == "development" {
		return true
	}
	return cl.GetKind() == "public" && cl.GetProfile() == "native"
}

func loopbackMatch(reg string, got *url.URL) bool {
	r, err := url.Parse(reg)
	if err != nil || r.Scheme != "http" || r.Port() != "" || got.Scheme != "http" {
		return false
	}
	if !loopbackIP(r.Hostname()) {
		return false
	}
	if got.Hostname() != r.Hostname() || got.EscapedPath() != r.EscapedPath() || got.RawQuery != r.RawQuery {
		return false
	}
	if p := got.Port(); p != "" {
		n, err := strconv.Atoi(p)
		return err == nil && n >= 1 && n <= 65535
	}
	return true
}

// loopbackIP reports whether host is a loopback IP literal of RFC 8252 section 7.3. Only the IP literals: "localhost"
// is a name that may not resolve to loopback (RFC 8252 section 8.3).
func loopbackIP(host string) bool { return host == "127.0.0.1" || host == "::1" }

func base64URLChar(ch byte) bool {
	return ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_'
}
