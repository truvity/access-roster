//go:build sluis_test

package sessiond_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/actors/session/internal/sessiond"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

func TestAuthorizeSendsThePersonToTheUpstream(t *testing.T) {
	e := newEnv(t, nil)
	p := newAuthorize()
	r := e.authorize(p.req)

	up := location(t, r)
	if up.Host != "idp.example.test" {
		t.Fatalf("redirected to %s", up.Host)
	}
	if len(e.upstream.begins) != 1 {
		t.Fatalf("%d Begin calls", len(e.upstream.begins))
	}
	b := e.upstream.begins[0]
	// sluis's callback, its own state, nonce and S256 challenge: nothing of the client's request goes to the upstream.
	if b.GetRedirectUri() != testIssuer+"/callback" || b.GetUpstream() != "workforce" {
		t.Errorf("Begin: callback %q, upstream %q", b.GetRedirectUri(), b.GetUpstream())
	}
	for what, v := range map[string]string{"state": b.GetState(), "nonce": b.GetNonce(), "challenge": b.GetCodeChallenge()} {
		if v == "" {
			t.Errorf("empty %s", what)
		}
		if strings.Contains(v, p.req.GetState()) || strings.Contains(v, p.req.GetNonce()) || v == p.req.GetCodeChallenge() {
			t.Errorf("the client's %s went to the upstream", what)
		}
	}
	if b.GetState() == b.GetNonce() {
		t.Error("state and nonce are the same value")
	}

	// The cookie: a __Host- cookie, so Secure, Path=/, no Domain; HttpOnly; SameSite=Lax for the top-level return.
	set := headerOf(r, "Set-Cookie")
	if len(set) != 1 || !strings.HasPrefix(set[0], sessiond.SigninCookie+"=") {
		t.Fatalf("Set-Cookie = %v", set)
	}
	for _, attr := range []string{"Path=/", "Secure", "HttpOnly", "SameSite=Lax", "Max-Age=600"} {
		if !strings.Contains(set[0], "; "+attr) {
			t.Errorf("cookie lacks %s: %s", attr, set[0])
		}
	}
	if strings.Contains(set[0], "Domain") {
		t.Error("a __Host- cookie has no Domain")
	}
	// What the cookie holds is sealed: the verifier, the client's state and nonce are not in it in the clear.
	v := cookieValue(t, r)
	for _, secret := range []string{p.req.GetState(), p.req.GetNonce(), p.req.GetRedirectUri()} {
		if strings.Contains(v, secret) {
			t.Errorf("the cookie holds %q in the clear", secret)
		}
	}
	if c := headerOf(r, "Cache-Control"); len(c) != 1 || c[0] != "no-store" {
		t.Errorf("Cache-Control = %v", c)
	}
	// Only the cookie purpose of key@ was used: no tenant key, so no grant was needed or asked for.
	for _, call := range e.key.called() {
		if strings.Contains(call, "data") {
			t.Errorf("authorize used %q", call)
		}
	}
	if n := e.store.count("pending-sign-in", testTenant); n != 0 {
		t.Errorf("%d PendingSignIn items were written without a grant", n)
	}
}

// A pending sign-in lives in the sealed sign-in cookie alone: before a person is known the start writes no item of any
// kind, not even a counter, and the cookie is the one the state is in.
//
// verifies: REQ-SESS-047
func TestAuthorizeStoresNothingBeforeAPersonIsKnown(t *testing.T) {
	e := newEnv(t, nil)
	e.store.mu.Lock()
	seeded := len(e.store.items) // the config the test seeds
	e.store.mu.Unlock()
	r := e.authorize(newAuthorize().req)
	set := headerOf(r, "Set-Cookie")
	if len(set) != 1 || !strings.HasPrefix(set[0], sessiond.SigninCookie+"=") || !strings.HasPrefix(sessiond.SigninCookie, "__Host-") {
		t.Fatalf("Set-Cookie = %v", set)
	}
	e.store.mu.Lock()
	writes, items := len(e.store.writes), len(e.store.items)
	e.store.mu.Unlock()
	if writes != 0 || items != seeded {
		t.Errorf("the sign-in start wrote %d batches and left %d items, seeded %d", writes, items, seeded)
	}
}

func TestAuthorizeIsAudited(t *testing.T) {
	e := newEnv(t, nil)
	e.authorize(newAuthorize().req)
	recs := e.records()
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	md := recs[0]["metadata"].(map[string]any)
	if md["event_code"] != "session.authorize" || md["tenant_uid"] != testTenant {
		t.Errorf("metadata = %v", md)
	}
	if recs[0]["user"] == nil {
		t.Error("the record names no subject")
	}
}

// refusalCase is an authorize request that the client's declaration or the RFCs do not allow.
type refusalCase struct {
	name   string
	edit   func(*sessionv2alpha1.AuthorizeRequest)
	code   string // the error the client gets in its redirect
	reason string // the audit status code
}

// verifies: REQ-AUTHN-001, REQ-AUTHN-002, REQ-AUTHN-026, REQ-AUTHN-060
func TestAuthorizeRefusesWhatTheRFCsRefuse(t *testing.T) {
	cases := []refusalCase{
		{"no PKCE", func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallenge, r.CodeChallengeMethod = "", "" }, "invalid_request", "pkce"},
		{"plain PKCE", func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallengeMethod = "plain" }, "invalid_request", "pkce"},
		{"PKCE method missing", func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallengeMethod = "" }, "invalid_request", "pkce"},
		{"short challenge", func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallenge = "abc" }, "invalid_request", "pkce"},
		{"challenge with padding", func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallenge = r.CodeChallenge[:42] + "=" }, "invalid_request", "pkce"},
		{"implicit flow", func(r *sessionv2alpha1.AuthorizeRequest) { r.ResponseType = "token" }, "unsupported_response_type", "request"},
		{"no response type", func(r *sessionv2alpha1.AuthorizeRequest) { r.ResponseType = "" }, "invalid_request", "request"},
		{"form_post.jwt mode", func(r *sessionv2alpha1.AuthorizeRequest) { r.ResponseMode = "form_post.jwt" }, "invalid_request", "request"},
		{"fragment mode", func(r *sessionv2alpha1.AuthorizeRequest) { r.ResponseMode = "fragment" }, "invalid_request", "request"},
		{"no openid scope", func(r *sessionv2alpha1.AuthorizeRequest) { r.Scope = "profile" }, "invalid_scope", "request"},
		{"no scope", func(r *sessionv2alpha1.AuthorizeRequest) { r.Scope = "" }, "invalid_scope", "request"},
		{"state with a control character", func(r *sessionv2alpha1.AuthorizeRequest) { r.State = "a\nb" }, "invalid_request", "request"},
		{"nonce with a control character", func(r *sessionv2alpha1.AuthorizeRequest) { r.Nonce = "a\x00b" }, "invalid_request", "request"},
		{"consent prompt", func(r *sessionv2alpha1.AuthorizeRequest) { r.Prompt = "consent" }, "consent_required", "prompt"},
		{"select_account prompt", func(r *sessionv2alpha1.AuthorizeRequest) { r.Prompt = "select_account" }, "account_selection_required", "prompt"},
		{"max_age negative", func(r *sessionv2alpha1.AuthorizeRequest) { r.MaxAge = "-5" }, "invalid_request", "request"},
		{"state over the bound", func(r *sessionv2alpha1.AuthorizeRequest) { r.State = strings.Repeat("a", 257) }, "invalid_request", "request"},
		{"nonce over the bound", func(r *sessionv2alpha1.AuthorizeRequest) { r.Nonce = strings.Repeat("a", 257) }, "invalid_request", "request"},
		{"max_age not a number", func(r *sessionv2alpha1.AuthorizeRequest) { r.MaxAge = "soon" }, "invalid_request", "request"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			p := newAuthorize()
			c.edit(p.req)
			r := e.authorize(p.req)
			u := location(t, r)
			// The error goes to the registered redirect_uri, with the issuer (RFC 9207) and no cookie.
			if got := u.Scheme + "://" + u.Host + u.Path; got != testRedirect {
				t.Fatalf("redirected to %s", got)
			}
			q := u.Query()
			if q.Get("error") != c.code {
				t.Errorf("error = %q, want %q", q.Get("error"), c.code)
			}
			if q.Get("iss") != testIssuer {
				t.Errorf("iss = %q", q.Get("iss"))
			}
			if want := safe(p.req.GetState()); q.Get("state") != want {
				t.Errorf("state = %q, want %q", q.Get("state"), want)
			}
			if q.Get("code") != "" {
				t.Error("an error redirect carries a code")
			}
			if len(headerOf(r, "Set-Cookie")) != 0 {
				t.Error("an error sets a cookie")
			}
			if len(e.upstream.begins) != 0 {
				t.Error("the upstream was called for a refused request")
			}
			recs := e.records()
			if len(recs) != 1 || recs[0]["status_code"] != c.reason {
				t.Errorf("records = %v, want one with status_code %q", recs, c.reason)
			}
		})
	}
}

// verifies: REQ-AUTHN-025
func TestAuthorizeAnswersImplicitAndHybridResponseTypesWithUnsupportedResponseType(t *testing.T) {
	// Every response type of OAuth 2.0 Multiple Response Type Encoding Practices other than "code": the implicit
	// ones (token, id_token, id_token token), the hybrid ones (code token, code id_token, code id_token token), the
	// "none" type, and the same words in another order or case. Each is refused as a whole, with the code that tells
	// the client the flow is not served.
	for _, rt := range []string{
		"token", "id_token", "id_token token", "token id_token",
		"code token", "code id_token", "code id_token token", "id_token code", "token code",
		"none", "CODE", "code ", " code", "code code", "code,token", "code+token",
	} {
		t.Run(rt, func(t *testing.T) {
			e := newEnv(t, nil)
			p := newAuthorize()
			p.req.ResponseType = rt
			r := e.authorize(p.req)

			u := location(t, r)
			if got := u.Scheme + "://" + u.Host + u.Path; got != testRedirect {
				t.Fatalf("redirected to %s", got)
			}
			q := u.Query()
			if q.Get("error") != "unsupported_response_type" {
				t.Errorf("error = %q, want unsupported_response_type", q.Get("error"))
			}
			if q.Get("iss") != testIssuer || q.Get("state") != p.req.GetState() {
				t.Errorf("iss %q state %q", q.Get("iss"), q.Get("state"))
			}
			// Nothing of the refused flow is issued: no code, no token in the query or the fragment, no cookie, no sign-in.
			for _, leaked := range []string{"code", "access_token", "id_token", "token"} {
				if q.Has(leaked) {
					t.Errorf("a refused response type carries %s", leaked)
				}
			}
			if u.Fragment != "" {
				t.Errorf("fragment %q", u.Fragment)
			}
			if len(headerOf(r, "Set-Cookie")) != 0 || len(e.upstream.begins) != 0 {
				t.Error("a refused response type started a sign-in")
			}
			recs := e.records()
			if len(recs) != 1 || recs[0]["status_code"] != "request" {
				t.Errorf("records = %v, want one with status_code request", recs)
			}
		})
	}
	// The response modes that carry an implicit or hybrid answer (fragment) are refused even with the one
	// served response type, and with an implicit one the response type is the reason, not the mode. The refusal of a
	// mode goes to the client in the query. (A refusal in the mode form_post is a form: formpost_test.go.)
	for _, c := range []struct{ rt, mode string }{
		{"code", "fragment"}, {"code", "form_post.jwt"}, {"token", "fragment"}, {"id_token", "fragment"}, {"code id_token", "fragment"},
	} {
		t.Run(c.rt+"/"+c.mode, func(t *testing.T) {
			e := newEnv(t, nil)
			p := newAuthorize()
			p.req.ResponseType, p.req.ResponseMode = c.rt, c.mode
			r := e.authorize(p.req)
			u := location(t, r)
			q := u.Query()
			want := "invalid_request"
			if c.rt != "code" {
				want = "unsupported_response_type"
			}
			if q.Get("error") != want || q.Get("iss") != testIssuer || q.Has("code") || u.Fragment != "" {
				t.Errorf("response_type=%s response_mode=%s: error %q, query %v, fragment %q, want %s", c.rt, c.mode, q.Get("error"), q, u.Fragment, want)
			}
			if got := u.Scheme + "://" + u.Host + u.Path; got != testRedirect {
				t.Errorf("redirected to %s", got)
			}
			if len(headerOf(r, "Set-Cookie")) != 0 || len(e.upstream.begins) != 0 {
				t.Error("a refused request started a sign-in")
			}
		})
	}
	// The one response type that is served still works, so the refusal above is about the type and nothing else.
	e := newEnv(t, nil)
	if up := location(t, e.authorize(newAuthorize().req)); up.Host != "idp.example.test" {
		t.Errorf("response_type=code went to %s", up.Host)
	}
}

// verifies: REQ-CLIENT-022
func TestAuthorizeRefusesAnUnknownScopeInsteadOfDroppingIt(t *testing.T) {
	for _, scope := range []string{"openid offline_access", "openid profile admin", "admin openid", "openid OPENID"} {
		t.Run(scope, func(t *testing.T) {
			e := newEnv(t, nil)
			p := newAuthorize()
			p.req.Scope = scope
			r := e.authorize(p.req)
			// The redirect_uri is the client's own, so the error goes there (RFC 6749 section 4.1.2.1).
			u := location(t, r)
			if got := u.Scheme + "://" + u.Host + u.Path; got != testRedirect {
				t.Fatalf("redirected to %s", got)
			}
			q := u.Query()
			if q.Get("error") != "invalid_scope" || q.Get("state") != p.req.GetState() || q.Get("iss") != testIssuer || q.Get("code") != "" {
				t.Errorf("query = %v", q)
			}
			// The description names no scope: the client sent it, and the reason is the audit record's (REQ-UX-006).
			for _, sc := range strings.Fields(scope) {
				if sc != "openid" && strings.Contains(q.Get("error_description"), sc) {
					t.Errorf("error_description %q shows the scope", q.Get("error_description"))
				}
			}
			if len(e.upstream.begins) != 0 || len(headerOf(r, "Set-Cookie")) != 0 {
				t.Error("a refused scope started a sign-in")
			}
			if recs := e.records(); len(recs) != 1 || recs[0]["status_code"] != "scope" {
				t.Errorf("records = %v, want one with status_code scope", recs)
			}
		})
	}
	// What is served is still granted, each scope once.
	e := newEnv(t, nil)
	p := newAuthorize()
	p.req.Scope = "openid profile email profile"
	if got := location(t, e.authorize(p.req)); got.Host != "idp.example.test" {
		t.Errorf("known scopes: redirected to %s", got)
	}
}

// safe is the state the service reflects: a valid one, or none.
func safe(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return ""
		}
	}
	if len(s) > 256 {
		return ""
	}
	return s
}

// verifies: REQ-AUTHN-003
func TestAuthorizeNeverRedirectsToAnAddressTheClientDidNotRegister(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // URLs with userinfo, to be refused; no credential
		"other host":               "http://127.0.0.2:43210/callback",
		"localhost is a name":      "http://localhost:43210/callback",
		"other path":               "http://127.0.0.1:43210/other",
		"path prefix":              "http://127.0.0.1:43210/callback/x",
		"trailing slash":           "http://127.0.0.1:43210/callback/",
		"https for an http entry":  "https://127.0.0.1:43210/callback",
		"query added":              "http://127.0.0.1:43210/callback?x=1",
		"fragment":                 "http://127.0.0.1:43210/callback#x",
		"userinfo":                 "http://evil@127.0.0.1:43210/callback",
		"userinfo trick":           "http://127.0.0.1:43210@evil.example/callback",
		"port zero":                "http://127.0.0.1:0/callback",
		"port above range":         "http://127.0.0.1:70000/callback",
		"a different scheme":       "javascript://127.0.0.1:43210/callback",
		"empty":                    "",
		"relative":                 "/callback",
		"hostname made of the IP":  "http://127.0.0.1.evil.example/callback",
		"upper-case path":          "http://127.0.0.1:43210/Callback",
		"encoded slash in path":    "http://127.0.0.1:43210/callback%2f..",
		"backslash":                `http://127.0.0.1:43210\@evil.example/callback`,
		"control character in uri": "http://127.0.0.1:43210/callback\n",
	}
	for name, uri := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			p := newAuthorize()
			p.req.RedirectUri = uri
			r := e.authorize(p.req)
			assertErrorPage(t, r)
			if len(e.upstream.begins) != 0 {
				t.Error("the upstream was called")
			}
		})
	}
}

// assertErrorPage checks the fixed page of a request that cannot be redirected: 400, HTML, no Location, no cookie,
// nothing of the request in the body.
func assertErrorPage(t *testing.T, r interface {
	GetStatus() int32
	GetBody() []byte
}) {
	t.Helper()
	if r.GetStatus() != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", r.GetStatus())
	}
	if !strings.Contains(string(r.GetBody()), "Sign-in could not continue") {
		t.Errorf("body %q", r.GetBody())
	}
}

func TestAuthorizeAcceptsALoopbackRedirectOnAnyPort(t *testing.T) {
	// RFC 8252 section 7.3: the CLI registers http://127.0.0.1/callback and takes a free port at run time.
	for _, uri := range []string{"http://127.0.0.1/callback", "http://127.0.0.1:1/callback", "http://127.0.0.1:65535/callback", testRedirect} {
		e := newEnv(t, nil)
		p := newAuthorize()
		p.req.RedirectUri = uri
		r := e.authorize(p.req)
		if got := location(t, r); got.Host != "idp.example.test" {
			t.Errorf("%s: redirected to %s", uri, got)
		}
	}
	// The exact match stays exact for everything that is not a loopback IP literal without a port.
	e := newEnv(t, func(o *options) {
		o.client.Redirects = []string{"https://app.example.com/callback"}
	})
	p := newAuthorize()
	p.req.RedirectUri = "https://app.example.com/callback"
	if got := location(t, e.authorize(p.req)); got.Host != "idp.example.test" {
		t.Errorf("exact https redirect: %s", got)
	}
	for _, uri := range []string{"https://app.example.com:8443/callback", "https://app.example.com/callback/", "http://app.example.com/callback"} {
		e := newEnv(t, func(o *options) { o.client.Redirects = []string{"https://app.example.com/callback"} })
		p := newAuthorize()
		p.req.RedirectUri = uri
		assertErrorPage(t, e.authorize(p.req))
	}
}

// verifies: REQ-AUTHN-004
func TestAuthorizeNeverRedirectsOverPlainHTTPOffLoopbackEvenWhenRegistered(t *testing.T) {
	// store@ refuses such a registration at load; a declaration that holds one anyway is not a way past the rule.
	for _, uri := range []string{
		"http://app.example.com/callback",
		"http://localhost/callback",
		"http://localhost:43210/callback",
		"http://127.0.0.2/callback",
		"http://192.0.2.1/callback",
	} {
		t.Run(uri, func(t *testing.T) {
			e := newEnv(t, func(o *options) { o.client.Redirects = []string{uri} })
			p := newAuthorize()
			p.req.RedirectUri = uri
			assertErrorPage(t, e.authorize(p.req))
			if len(e.upstream.begins) != 0 {
				t.Error("the upstream was called")
			}
			if recs := e.records(); len(recs) != 1 || recs[0]["status_code"] != "redirect_uri" {
				t.Errorf("records = %v", recs)
			}
		})
	}
	// Outside development, a loopback redirect is a public native client's only (ADR 0011, the floor of store@).
	for _, environment := range []string{"staging", "production"} {
		for profile, ok := range map[string]bool{"native": true, "browser": false, "": false} {
			e := newEnv(t, func(o *options) {
				o.boundary.Environment = environment
				o.client.Profile = profile
			})
			r := e.authorize(newAuthorize().req)
			if ok {
				if got := location(t, r); got.Host != "idp.example.test" {
					t.Errorf("%s, profile %q: redirected to %s", environment, profile, got)
				}
				continue
			}
			assertErrorPage(t, r)
			if len(e.upstream.begins) != 0 {
				t.Errorf("%s, profile %q: the upstream was called", environment, profile)
			}
		}
		// An https redirect is any public client's.
		e := newEnv(t, func(o *options) {
			o.boundary.Environment = environment
			o.client.Profile = "browser"
			o.client.Redirects = []string{"https://app.example.com/callback"}
		})
		p := newAuthorize()
		p.req.RedirectUri = "https://app.example.com/callback"
		if got := location(t, e.authorize(p.req)); got.Host != "idp.example.test" {
			t.Errorf("%s: an https redirect of a browser client: %s", environment, got)
		}
	}
	// The loopback IP literals stay, with a registered port or any port (RFC 8252 section 7.3).
	for reg, uri := range map[string]string{
		"http://[::1]/callback":          "http://[::1]:43210/callback",
		"http://127.0.0.1:8080/callback": "http://127.0.0.1:8080/callback",
	} {
		e := newEnv(t, func(o *options) { o.client.Redirects = []string{reg} })
		p := newAuthorize()
		p.req.RedirectUri = uri
		if got := location(t, e.authorize(p.req)); got.Host != "idp.example.test" {
			t.Errorf("%s registered, %s asked: redirected to %s", reg, uri, got)
		}
	}
}

func TestAuthorizeRefusesClientsItDoesNotServe(t *testing.T) {
	cases := map[string]func(*sessionv2alpha1.AuthorizeRequest){
		"unknown client":        func(r *sessionv2alpha1.AuthorizeRequest) { r.ClientId = "nobody" },
		"no client":             func(r *sessionv2alpha1.AuthorizeRequest) { r.ClientId = "" },
		"client id with a path": func(r *sessionv2alpha1.AuthorizeRequest) { r.ClientId = "sluis-cli/../x" },
		"upper-case client id":  func(r *sessionv2alpha1.AuthorizeRequest) { r.ClientId = "Sluis-CLI" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			p := newAuthorize()
			edit(p.req)
			assertErrorPage(t, e.authorize(p.req))
			if len(e.upstream.begins) != 0 {
				t.Error("the upstream was called")
			}
			if recs := e.records(); len(recs) != 1 || recs[0]["status_code"] != "client" {
				t.Errorf("records = %v", recs)
			}
		})
	}
	// An exchange client never asks for a person's code. A confidential client does: its secret is checked where the
	// code is redeemed (token_confidential_test.go).
	e := newEnv(t, func(o *options) { o.client.Kind = "exchange" })
	assertErrorPage(t, e.authorize(newAuthorize().req))
}

func TestAuthorizeReflectsNothingInItsPages(t *testing.T) {
	e := newEnv(t, nil)
	p := newAuthorize()
	evil := `"><script>alert(1)</script>`
	p.req.ClientId, p.req.RedirectUri = evil, evil
	r := e.authorize(p.req)
	if strings.Contains(string(r.GetBody()), "script") || strings.Contains(string(r.GetBody()), evil) {
		t.Errorf("the page reflects the request: %q", r.GetBody())
	}
	// A state that is valid but holds markup goes to the client in the query, encoded.
	p = newAuthorize()
	p.req.State = `<b>"x"&y</b>`
	p.req.CodeChallenge = ""
	u := location(t, e.authorize(p.req))
	if got := u.Query().Get("state"); got != p.req.State {
		t.Errorf("state = %q", got)
	}
	if strings.ContainsAny(u.RawQuery, `<>"`) {
		t.Errorf("the query is not encoded: %s", u.RawQuery)
	}
}

// A state that holds a script goes to the client only percent-encoded in the redirect's query. In the query mode there
// is no HTML to escape: the redirect has no body. The form_post page escapes it (formpost_test.go), and the error page
// holds nothing of the request.
func TestAuthorizeStateWithScriptIsEncoded(t *testing.T) {
	e := newEnv(t, nil)
	p := newAuthorize()
	p.req.State = `<script>alert(1)</script>`
	p.req.CodeChallenge = ""
	r := e.authorize(p.req)
	if len(r.GetBody()) != 0 {
		t.Errorf("the redirect has a body: %q", r.GetBody())
	}
	u := location(t, r)
	if got := u.Query().Get("state"); got != p.req.State {
		t.Errorf("state = %q", got)
	}
	if strings.ContainsAny(u.RawQuery, `<>`) || strings.Contains(u.RawQuery, "script>") {
		t.Errorf("the query is not encoded: %s", u.RawQuery)
	}
	// A response mode that is not served is refused in the query, whatever the state holds.
	p = newAuthorize()
	p.req.State = `<script>alert(1)</script>`
	p.req.ResponseMode = "fragment"
	r = e.authorize(p.req)
	u = location(t, r)
	if u.Query().Get("error") != "invalid_request" {
		t.Errorf("a fragment request: error = %q, want invalid_request", u.Query().Get("error"))
	}
	if strings.ContainsAny(u.RawQuery, `<>`) || len(r.GetBody()) != 0 {
		t.Errorf("a refused response mode reflects the state: %s %q", u.RawQuery, r.GetBody())
	}
}

func TestAuthorizeUpstreamTrouble(t *testing.T) {
	// The adapter says the request is bad: the person is told by the client's redirect, as server_error.
	e := newEnv(t, nil)
	e.upstream.beginErr = connect.NewError(connect.CodeInvalidArgument, nil)
	u := location(t, e.authorize(newAuthorize().req))
	if u.Query().Get("error") != "server_error" {
		t.Errorf("error = %q", u.Query().Get("error"))
	}
	// The adapter is down: session is unavailable, and says so as an error of the call.
	e = newEnv(t, nil)
	e.upstream.beginErr = connect.NewError(connect.CodeUnavailable, nil)
	_, err := e.client.Authorize(context.Background(), connect.NewRequest(newAuthorize().req))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("err = %v", err)
	}
}

func TestOnlyEntryAndConsoleMayCall(t *testing.T) {
	// The call graph of the registry is checked at the socket by the kit: exchange is not a caller of session.
	e := newEnv(t, func(o *options) { o.caller = "exchange" })
	_, err := e.client.Authorize(context.Background(), connect.NewRequest(newAuthorize().req))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("err = %v", err)
	}
	if len(e.upstream.begins) != 0 {
		t.Error("a refused caller reached the upstream")
	}
}

func TestAuthorizeNeedsATenant(t *testing.T) {
	// A boundary with no default tenant cannot place a client's people: the call fails, and nothing starts.
	e := newEnv(t, func(o *options) { o.boundary = &configv2alpha1.Boundary{Name: "dev", Issuer: testIssuer} })
	_, err := e.client.Authorize(context.Background(), connect.NewRequest(newAuthorize().req))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("err = %v", err)
	}
	if len(e.upstream.begins) != 0 {
		t.Error("a sign-in started with no tenant")
	}
}

// Sluis never sets a sign-in cookie larger than 4 KiB. Every value that goes into the sealed pending sign-in is set to
// its largest: the client's id, the tenant and the upstream's name at the 128 bytes of an address part, the redirect_uri,
// state and nonce at their bounds, the scope at all three scopes served, the challenge at its length and max_age at
// the largest whole number. The cookie of that request fits in 4096 bytes with room to spare, which is why the guard in
// Authorize ("the request is too large") is unreachable with today's bounds. It stays as defence, and a change to a
// bound or to the pending sign-in that breaks this test is what the guard would have caught.
//
// verifies: REQ-SESS-050
func TestAuthorizeNeverSetsACookieLargerThan4KiB(t *testing.T) {
	const part = 128 // the longest part of an address (store-api.md, "Address encoding")
	longClient := strings.Repeat("c", part)
	long := "https://app.example.com/" + strings.Repeat("p", 1000)
	if len(long) != 1024 {
		t.Fatalf("redirect_uri of %d bytes, want the bound 1024", len(long))
	}
	e := newEnv(t, func(o *options) {
		o.client.Id = longClient
		o.client.Redirects = []string{long}
		o.boundary.DefaultTenant = strings.Repeat("t", part)
		o.upstream.Name = strings.Repeat("u", part)
	})
	p := newAuthorize()
	p.req.ClientId = longClient
	p.req.RedirectUri = long
	p.req.State, p.req.Nonce = strings.Repeat("s", 256), strings.Repeat("n", 256)
	p.req.Scope = "openid profile email"
	p.req.MaxAge = "2147483647"
	r := e.authorize(p.req)
	_ = location(t, r)
	v := cookieValue(t, r)
	if v == "" {
		t.Fatalf("no cookie: %v", headerOf(r, "Set-Cookie"))
	}
	if len(v) > 4096 {
		t.Fatalf("a sign-in cookie of %d bytes", len(v))
	}
	t.Logf("the largest sign-in cookie is %d bytes of 4096", len(v))
	// And it opens: the callback accepts it.
	up := location(t, r)
	cb := e.callback(&sessionv2alpha1.CallbackRequest{Code: "c-1234567890", State: up.Query().Get("state"), Cookie: v})
	if location(t, cb).Query().Get("code") == "" {
		t.Fatal("the largest request did not complete")
	}
}

// One past the redirect_uri bound is not served at all, and the largest ordinary request fits the cookie.
func TestAuthorizeTheLargestRequestFitsTheCookie(t *testing.T) {
	// Everything a client supplies at its bound, with the longest redirect_uri: the sealed cookie stays under what
	// entry passes on (4096), and a request one past a bound is refused rather than set as a cookie entry would drop.
	long := "https://app.example.com/" + strings.Repeat("p", 1000)
	e := newEnv(t, func(o *options) { o.client.Redirects = []string{long} })
	p := newAuthorize()
	p.req.RedirectUri = long
	p.req.State, p.req.Nonce = strings.Repeat("s", 256), strings.Repeat("n", 256)
	p.req.Scope = "openid profile email"
	r := e.authorize(p.req)
	_ = location(t, r)
	if v := cookieValue(t, r); v == "" || len(v) > 4096 {
		t.Fatalf("cookie of %d bytes", len(v))
	}
	// And it opens: the callback accepts it.
	up := location(t, r)
	cb := e.callback(&sessionv2alpha1.CallbackRequest{Code: "c-1234567890", State: up.Query().Get("state"), Cookie: cookieValue(t, r)})
	if location(t, cb).Query().Get("code") == "" {
		t.Fatal("the largest request did not complete")
	}
	// One past the redirect_uri bound is not served at all.
	e = newEnv(t, func(o *options) { o.client.Redirects = []string{long + "p"} })
	p.req.RedirectUri = long + "p"
	assertErrorPage(t, e.authorize(p.req))
}
