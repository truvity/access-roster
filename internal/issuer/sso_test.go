package issuer_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/issuer"
	"github.com/truvity/access-roster/policy"
)

// oneProvider stands in for a corporate directory. It never fails, which
// is the point: what these tests are about is what the ISSUER remembers
// between sign-ins, not what a provider does during one.
type oneProvider struct{ email string }

func (oneProvider) Kind() string { return "google" }

func (oneProvider) URL(state string) (string, error) {
	return "https://idp.example/authorize?state=" + url.QueryEscape(state), nil
}

func (p oneProvider) Identify(context.Context, string) (string, error) { return p.email, nil }

// signInServer is the issuer with its sign-in pages mounted, which the
// other HTTP tests do not need and these cannot do without.
func signInServer(t *testing.T, email string) (*httptest.Server, *issuer.Issuer) {
	t.Helper()

	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatalf("parse the demonstration policy: %v", err)
	}

	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}

	dir := &fakeDirectory{standing: map[string]issuer.Standing{
		email: {Found: true, Authoritative: true, Groups: []string{"engineering@north.example"}},
	}}
	iss := issuer.New(
		issuer.Config{URL: "http://issuer.example", AllowInsecure: true},
		set, dir, issuer.NewMemoryState(),
	)

	storage, err := issuer.NewStorage(iss, fakeVerifier{}, nil, nil, nil)
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	handler, err := issuer.HandlerWithSignIn(iss, storage, issuer.SignInDeps{
		Providers: []issuer.SignIn{oneProvider{email: email}},
		State:     access.NewStateCodec([]byte("a-test-key-for-signing-state"), 0),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return server, iss
}

// browser is one person's browser: it keeps cookies and does not follow
// redirects, because every assertion here is about WHERE it was sent.
type browser struct {
	t       *testing.T
	server  *httptest.Server
	cookies map[string]string
}

func newBrowser(t *testing.T, server *httptest.Server) *browser {
	return &browser{t: t, server: server, cookies: map[string]string{}}
}

func (b *browser) do(method, path string) (status int, location, body string) {
	b.t.Helper()

	request, err := http.NewRequestWithContext(b.t.Context(), method, b.server.URL+path, nil)
	if err != nil {
		b.t.Fatalf("build the request: %v", err)
	}

	for name, value := range b.cookies {
		request.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	response, err := client.Do(request)
	if err != nil {
		b.t.Fatalf("request %s: %v", path, err)
	}

	defer func() { _ = response.Body.Close() }()

	for _, cookie := range response.Cookies() {
		if cookie.MaxAge < 0 {
			delete(b.cookies, cookie.Name)
			continue
		}

		b.cookies[cookie.Name] = cookie.Value
	}

	buf := make([]byte, 1<<16)
	n, _ := response.Body.Read(buf)

	return response.StatusCode, response.Header.Get("Location"), string(buf[:n])
}

// authorize starts one authorization request and returns where the
// browser was sent — which is the whole assertion in these tests.
func (b *browser) authorize(extra string) string {
	b.t.Helper()

	verifier := "a-verifier-long-enough-to-be-a-real-one-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"client_id":             {"local-dev"},
		"redirect_uri":          {"http://localhost:8000/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"sso-test"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}

	status, where, body := b.do(http.MethodGet, "/authorize?"+query.Encode()+extra)
	if status != http.StatusFound {
		b.t.Fatalf("/authorize: %d %s", status, body)
	}

	// The library always sends a browser to the login page; what happens
	// THERE is where single sign-on lives.
	status, next, _ := b.do(http.MethodGet, where)
	if status != http.StatusFound {
		return "rendered a page"
	}

	return next
}

// signIn walks the provider round trip once, so the issuer has a browser
// session to remember.
func (b *browser) signIn() {
	b.t.Helper()

	where := b.authorize("")
	if !strings.Contains(where, "/login/google/start") {
		b.t.Fatalf("first sign-in went to %q, want the provider", where)
	}

	status, toProvider, _ := b.do(http.MethodGet, where)
	if status != http.StatusFound {
		b.t.Fatalf("provider start: %d", status)
	}

	// The provider would send the browser back with this state; the code
	// is ignored by the stand-in.
	state := toProvider[strings.Index(toProvider, "state=")+len("state="):]

	status, _, _ = b.do(http.MethodGet, "/login/google/callback?code=x&state="+state)
	if status != http.StatusFound {
		b.t.Fatalf("provider callback: %d", status)
	}
}

// A second console costs no login. This is the whole of single sign-on,
// and the reason the issuer holds a session of its own at all: before it
// did, every console bounced the person through the corporate directory
// again, and "it asked me to log in twice" was the report.
func TestASecondConsoleCostsNoLogin(t *testing.T) {
	t.Parallel()
	server, _ := signInServer(t, "ada@north.example")
	b := newBrowser(t, server)
	b.signIn()

	if _, ok := b.cookies[issuer.SSOCookieName]; !ok {
		t.Fatal("signing in left no browser session")
	}

	// The second application's request completes against that session
	// instead of going back to the provider.
	if where := b.authorize(""); !strings.Contains(where, "/authorize/callback") {
		t.Errorf("second sign-in went to %q, want it completed silently", where)
	}
}

// `prompt=login` is a relying party asking for a fresh authentication,
// and a live browser session must not answer it. Anything that re-uses a
// session here silently breaks step-up authentication for every consumer
// that asks for one.
func TestPromptLoginAuthenticatesAgain(t *testing.T) {
	t.Parallel()
	server, _ := signInServer(t, "ada@north.example")
	b := newBrowser(t, server)
	b.signIn()

	if where := b.authorize("&prompt=login"); !strings.Contains(where, "/login/google/start") {
		t.Errorf("prompt=login went to %q, want the provider again", where)
	}

	// And `max_age=0` says the same thing a different way.
	if where := b.authorize("&max_age=0"); !strings.Contains(where, "/login/google/start") {
		t.Errorf("max_age=0 went to %q, want the provider again", where)
	}
}

// Signing out ends the sign-in, not only one application's session. The
// failure this pins is the one that looks exactly like success: the
// person clicks "sign out", lands on the signed-out page, opens another
// console and is admitted with no password.
func TestSigningOutEndsTheBrowserSession(t *testing.T) {
	t.Parallel()
	server, _ := signInServer(t, "ada@north.example")
	b := newBrowser(t, server)
	b.signIn()

	if _, _, _ = b.do(http.MethodGet, "/end_session"); b.cookies[issuer.SSOCookieName] != "" {
		t.Fatal("end_session left the browser session behind")
	}

	if where := b.authorize(""); !strings.Contains(where, "/login/google/start") {
		t.Errorf("after signing out the next request went to %q, want the provider", where)
	}
}

// The account page is served BY the issuer, at the issuer's host, which
// is what lets it need no bearer and no CORS: the browser already holds
// this issuer's session here.
func TestTheAccountPageListsAndEndsYourSessions(t *testing.T) {
	t.Parallel()
	server, iss := signInServer(t, "ada@north.example")
	b := newBrowser(t, server)
	b.signIn()

	// Something to list: a session on a client, as a redeemed code would
	// have left behind.
	if _, err := iss.Sessions().Record(t.Context(), issuer.Opened{
		Identity: "ada@north.example", ClientID: "argocd", How: issuer.HowCode, Token: "t-1",
	}); err != nil {
		t.Fatalf("record a session: %v", err)
	}

	status, _, page := b.do(http.MethodGet, "/account")
	if status != http.StatusOK {
		t.Fatalf("/account: %d", status)
	}

	if !strings.Contains(page, "ada@north.example") {
		t.Error("the account page does not say who is signed in")
	}

	if !strings.Contains(page, "argocd") {
		t.Error("the account page does not list the session that is open")
	}

	if !strings.Contains(page, "Sign out everywhere") {
		t.Error("the account page offers no way to end everything")
	}

	// Ending everything ends the sign-in too, so the next request is a
	// fresh authentication.
	status, _, _ = b.do(http.MethodPost, "/account/sign-out")
	if status != http.StatusSeeOther {
		t.Fatalf("sign out everywhere: %d", status)
	}

	if b.cookies[issuer.SSOCookieName] != "" {
		t.Error("signing out everywhere left the browser session behind")
	}

	// Both halves: the sessions that were running are gone, not only the
	// sign-in that would have opened more.
	left, err := iss.Sessions().List(t.Context(), issuer.Query{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(left) != 0 {
		t.Errorf("%d session(s) survived signing out everywhere", len(left))
	}

	if where := b.authorize(""); !strings.Contains(where, "/login/google/start") {
		t.Errorf("after signing out everywhere the next request went to %q, want the provider", where)
	}
}

// Somebody who is not signed in gets a page, not a stack trace and not
// somebody else's sessions.
func TestTheAccountPageNeedsASession(t *testing.T) {
	t.Parallel()
	server, _ := signInServer(t, "ada@north.example")
	b := newBrowser(t, server)

	status, _, page := b.do(http.MethodGet, "/account")
	if status != http.StatusOK || !strings.Contains(page, "not signed in") {
		t.Errorf("/account without a session = %d %q, want a page saying so", status, page)
	}

	if status, _, _ = b.do(http.MethodPost, "/account/sign-out"); status != http.StatusForbidden {
		t.Errorf("signing out without a session = %d, want it refused", status)
	}
}
