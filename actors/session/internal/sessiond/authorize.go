package sessiond

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

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

	// maxCookie is the longest sign-in cookie value entry passes on (HEADER_VALUE_MAX in entry's handler.rs). The
	// pending sign-in is sealed into it, so the five client-supplied fields above are bounded to keep it under.
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
	page := func(reason, clientID string) (*connect.Response[typev2alpha1.HttpReply], error) {
		if aerr := s.record(ctx, audited{action: actionAuthorize, tenant: tenant, subject: clientSubject(tenant, clientID), reason: reason}); aerr != nil {
			return nil, aerr
		}
		return errorPage(), nil
	}
	cl, err := s.opts.Config.Client(ctx, r.GetClientId())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return page(reasonClient, "unregistered")
	case err != nil:
		return nil, unavailable("client", err)
	}
	// Only a public client signs people in tonight: a confidential client needs its secret checked (the secret
	// kinds are not served yet), and an exchange client never asks for a person's code.
	if cl.GetKind() != "public" {
		return page(reasonClient, cl.GetId())
	}
	if tenant, err = tenantOf(b, cl); err != nil {
		return nil, internal("tenant", err)
	}
	if len(r.GetRedirectUri()) > maxRedirectURI || !redirectRegistered(cl.GetRedirects(), r.GetRedirectUri()) {
		return page(reasonRedirectURI, cl.GetId())
	}

	// From here the redirect_uri is the client's own.
	fail := func(code, desc, reason string) (*connect.Response[typev2alpha1.HttpReply], error) {
		out, rerr := clientRedirect(r.GetRedirectUri(), safeState(r.GetState()), b.GetIssuer(), url.Values{"error": {code}, "error_description": {desc}})
		if rerr != nil {
			return nil, internal("redirect", rerr)
		}
		if aerr := s.record(ctx, audited{action: actionAuthorize, tenant: tenant, subject: clientSubject(tenant, cl.GetId()), reason: reason}); aerr != nil {
			return nil, aerr
		}
		return out, nil
	}
	if !vschar(r.GetState(), maxState, true) {
		return fail("invalid_request", "state is malformed", reasonRequest)
	}
	if !vschar(r.GetNonce(), maxNonce, true) {
		return fail("invalid_request", "nonce is malformed", reasonRequest)
	}
	if r.GetResponseType() != "code" {
		return fail("unsupported_response_type", "only the code flow is served", reasonRequest)
	}
	// Query is the only response mode: session builds no form_post page.
	if m := r.GetResponseMode(); m != "" && m != "query" {
		return fail("invalid_request", "only the query response mode is served", reasonRequest)
	}
	if r.GetCodeChallengeMethod() != "S256" || !validChallenge(r.GetCodeChallenge()) {
		return fail("invalid_request", "PKCE with S256 is required", reasonPKCE)
	}
	scope, ok := grantedScope(r.GetScope())
	if !ok {
		return fail("invalid_scope", "the openid scope is required", reasonRequest)
	}
	// A prompt asks for something the upstream must be told to do: login forces a fresh authentication, none forbids
	// any interaction. BeginRequest carries neither (0025 names them for the adapter, which does not take them yet), so
	// an upstream with a single sign-on session could answer silently and session would pass that off as what the
	// client asked for. A value that cannot be honoured is refused (OpenID Connect Core section 3.1.2.6).
	if r.GetPrompt() != "" {
		return fail("login_required", "the prompt cannot be honoured", reasonRequest)
	}
	// max_age is kept in the pending sign-in and checked against the upstream's auth_time at the callback (OpenID
	// Connect Core section 3.1.2.1). max_age=0 asks for a fresh authentication, the same as prompt=login.
	var maxAge *int64
	if m := r.GetMaxAge(); m != "" {
		n, err := strconv.ParseUint(m, 10, 31)
		if err != nil {
			return fail("invalid_request", "max_age is malformed", reasonRequest)
		}
		if n == 0 {
			return fail("login_required", "a fresh authentication cannot be forced", reasonRequest)
		}
		v := int64(n)
		maxAge = &v
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
		CreatedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(pendingLife)), MaxAge: maxAge,
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
	if aerr := s.record(ctx, audited{action: actionAuthorize, tenant: tenant, subject: clientSubject(tenant, cl.GetId())}); aerr != nil {
		return nil, aerr
	}
	return redirect(begin.Msg.GetAuthorizationUrl(), setCookie(cookie, cookieMaxAge)), nil
}

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

// grantedScope returns the scopes session grants out of the requested ones, and false when openid is not among
// them. Unknown scopes are left out (RFC 6749 section 3.3: the server may grant less than was asked).
func grantedScope(requested string) (string, bool) {
	if len(requested) > maxScope {
		return "", false
	}
	var out []string
	seen := map[string]bool{}
	for _, sc := range strings.Fields(requested) {
		if knownScopes[sc] && !seen[sc] {
			seen[sc] = true
			out = append(out, sc)
		}
	}
	if !seen["openid"] {
		return "", false
	}
	return strings.Join(out, " "), true
}

// redirectRegistered reports whether got is one of the client's registered redirect URIs. The match is an exact string
// comparison (RFC 6749 section 3.1.2.3, and the Security BCP: no pattern), with the one exception of RFC 8252 section
// 7.3: a registered redirect on the loopback IP literal without a port matches any port, because a native app takes
// a free one at run time. A URI with a fragment or userinfo never matches (RFC 6749 section 3.1.2).
func redirectRegistered(registered []string, got string) bool {
	u, err := url.Parse(got)
	if err != nil || got == "" || u.Fragment != "" || u.User != nil || u.Opaque != "" || strings.Contains(got, "#") {
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

func loopbackMatch(reg string, got *url.URL) bool {
	r, err := url.Parse(reg)
	if err != nil || r.Scheme != "http" || r.Port() != "" || got.Scheme != "http" {
		return false
	}
	// Only the IP literals: "localhost" is a name that may not resolve to loopback (RFC 8252 section 8.3).
	if h := r.Hostname(); h != "127.0.0.1" && h != "::1" {
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

func base64URLChar(ch byte) bool {
	return ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_'
}
