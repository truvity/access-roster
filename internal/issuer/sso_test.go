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
		// Where an old /account bookmark is sent, now that the page it
		// named lives in the console (INF-695).
		ConsoleMount: "/console",
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

// `/account` was the person's own page here — their sessions, and the
// button that ends all of them. It has moved into the console (INF-695),
// which is same-origin with this issuer and now the same process, and
// whose page for a person already shows both. One directory UI; this
// service's UI is the login form.
//
// The address stays as a redirect and not as a 404, because it was
// linked to and bookmarked, and a person following an old link wants the
// page rather than the news that it moved.
func TestTheAccountAddressSendsYouToTheConsole(t *testing.T) {
	t.Parallel()
	server, _ := signInServer(t, "ada@north.example")
	b := newBrowser(t, server)
	b.signIn()

	status, to, _ := b.do(http.MethodGet, "/account")
	if status != http.StatusFound {
		t.Fatalf("/account = %d, want a redirect into the console", status)
	}
	// The console routes in the FRAGMENT, so the path is the console and
	// the page is what follows the hash.
	if to != "/console/#/people/ada@north.example" {
		t.Errorf("/account went to %q, want the console's page for the signed-in person", to)
	}

	// The page it moved to is not the only thing that moved: the two
	// POSTs behind it are gone as well, because the console does both
	// through SessionService. An endpoint that answers after the page
	// using it is deleted is surface nobody is keeping honest.
	for _, path := range []string{"/account/sign-out", "/account/revoke"} {
		if status, _, _ = b.do(http.MethodPost, path); status == http.StatusSeeOther || status == http.StatusOK {
			t.Errorf("POST %s still answers: %d", path, status)
		}
	}
}

// Somebody not signed in has no page about themselves to be sent to, so
// they get the console itself rather than a URL naming an empty identity.
func TestTheAccountAddressWithoutASessionGoesToTheConsole(t *testing.T) {
	t.Parallel()
	server, _ := signInServer(t, "ada@north.example")
	b := newBrowser(t, server)

	status, to, _ := b.do(http.MethodGet, "/account")
	if status != http.StatusFound {
		t.Fatalf("/account without a session = %d, want a redirect", status)
	}
	if to != "/console/" {
		t.Errorf("/account without a session went to %q, want the console's root", to)
	}
}

// The session service is there whether or not a cross-origin console was
// configured.
//
// It used to be mounted only when `console.origin` was set — a value that
// answers a DIFFERENT question, whether some other origin may call it. On
// one origin there is no CORS to configure, so nobody sets it, so the
// service was not mounted and every sessions section in the console
// answered 404 while `/account`, server-rendered beside them off the same
// store, worked perfectly. That is a bad failure to have: the half a
// person is most likely to try works, and the half a console shows does
// not.
func TestTheSessionServiceIsMountedWithoutAConsoleOrigin(t *testing.T) {
	t.Parallel()
	server, _ := signInServer(t, "ada@north.example")

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		server.URL+"/accessissuer.v1.SessionService/ListSessions", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}

	request.Header.Set("Content-Type", "application/json")

	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("post: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	// Unauthenticated, so it refuses — but it must be THERE to refuse.
	// A 404 means the route does not exist at all.
	if response.StatusCode == http.StatusNotFound {
		t.Fatal("the session service is not mounted without console.origin")
	}
}

// endSessionRequest is one RP-initiated logout, with whatever the
// browser's cookies are and whatever it says it accepts. The shared
// `browser.do` cannot be used: these cases turn on the Accept header and
// on the query, and both of those are the thing under test.
func endSessionRequest(t *testing.T, b *browser, query, accept string) (int, string, string) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		b.server.URL+"/end_session"+query, nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}

	if accept != "" {
		request.Header.Set("Accept", accept)
	}

	for name, value := range b.cookies {
		request.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	body := make([]byte, 4096)
	n, _ := response.Body.Read(body)

	return response.StatusCode, response.Header.Get("Location"), string(body[:n])
}

// A sign-out that names nowhere to go lands on the page that says it
// happened. It used to land on the issuer root, which redirects to the
// console, which starts a new authorization — so the last thing a person
// saw after signing out was a login page, and that reads as sign-out
// having failed.
func TestEndSessionWithNoParamsLandsOnTheSignedOutPage(t *testing.T) {
	t.Parallel()
	server, _ := signInServer(t, "ada@north.example")
	b := newBrowser(t, server)
	b.signIn()

	status, location, _ := endSessionRequest(t, b, "", "text/html")
	if status != http.StatusFound || location != "/signed-out" {
		t.Fatalf("end_session = %d to %q, want 302 to /signed-out", status, location)
	}
}

// A `post_logout_redirect_uri` with nothing naming the client that
// registered it is refused rather than quietly dropped. The library
// ignores such a URI and signs the person out anyway: safe, because
// nobody is sent anywhere unregistered, but the caller asked for
// something and was told nothing.
func TestEndSessionRefusesAnUnattributableRedirectURI(t *testing.T) {
	t.Parallel()
	server, _ := signInServer(t, "ada@north.example")
	b := newBrowser(t, server)
	b.signIn()

	status, _, body := endSessionRequest(t, b,
		"?post_logout_redirect_uri=https%3A%2F%2Felsewhere.example%2Fout", "text/html")
	if status != http.StatusBadRequest {
		t.Fatalf("end_session = %d, want 400", status)
	}

	if !strings.Contains(body, "post_logout_redirect_uri") {
		t.Errorf("the page does not say what was wrong: %q", body)
	}

	// And the refusal left the sign-in alone, which is what the page
	// tells the person.
	if where := b.authorize(""); !strings.Contains(where, "/authorize/callback") {
		t.Errorf("a refused sign-out ended the session anyway: next authorize went to %q", where)
	}
}

// A request the library refuses must not sign anybody out. The order ran
// the other way once — the session was ended on the way in — so an error
// page was shown for a sign-out that had already happened.
func TestARefusedEndSessionDoesNotSignOut(t *testing.T) {
	t.Parallel()
	server, _ := signInServer(t, "ada@north.example")
	b := newBrowser(t, server)
	b.signIn()

	if status, _, _ := endSessionRequest(t, b, "?id_token_hint=not.a.token", "text/html"); status != http.StatusBadRequest {
		t.Fatalf("end_session with a broken id_token_hint = %d, want 400", status)
	}

	if where := b.authorize(""); !strings.Contains(where, "/authorize/callback") {
		t.Errorf("a refused sign-out ended the session anyway: next authorize went to %q", where)
	}
}

// The browser gets a page and a program gets the OAuth error it reads.
// One endpoint, two audiences, and the JSON keeps its `error` code.
func TestEndSessionAnswersInTheCallersLanguage(t *testing.T) {
	t.Parallel()
	server, _ := signInServer(t, "ada@north.example")
	b := newBrowser(t, server)
	b.signIn()

	_, _, page := endSessionRequest(t, b, "?id_token_hint=not.a.token", "text/html")
	if !strings.Contains(page, "<!doctype html>") {
		t.Errorf("a browser got %q, want a page", page)
	}

	_, _, raw := endSessionRequest(t, b, "?id_token_hint=not.a.token", "application/json")
	if !strings.Contains(raw, `"error"`) {
		t.Errorf("a client got %q, want an OAuth error", raw)
	}
}

// Both doors sign the person out the same way, and the one that had the
// weaker half was the one a PROXY uses.
//
// `/logout` revoked every session the browser had opened; `/end_session`
// — which is what oauth2-proxy chains to on its own sign-out — only ended
// the sign-in. So the console behind a proxy went on refreshing
// successfully and serving pages after a sign-out that reported success,
// which is how it was reported from hubble.
func TestEndSessionRevokesWhatTheBrowserOpened(t *testing.T) {
	t.Parallel()
	server, iss := signInServer(t, "ada@north.example")
	b := newBrowser(t, server)
	b.signIn()

	sso := b.cookies[issuer.SSOCookieName]
	if sso == "" {
		t.Fatal("the browser holds no sign-in to revoke under")
	}

	// A session this browser opened at another console, the way a proxy's
	// code redemption files one.
	if _, err := iss.Sessions().Record(t.Context(), issuer.Opened{
		Identity: "ada@north.example",
		ClientID: "argocd",
		How:      issuer.HowCode,
		Token:    "a-refresh-token",
		SSO:      sso,
	}); err != nil {
		t.Fatalf("record a session: %v", err)
	}

	// Proved present first. Without this the assertion below passes on an
	// empty list for any reason at all, which is a test that cannot fail.
	before, err := iss.Sessions().List(t.Context(), issuer.Query{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(before) != 1 {
		t.Fatalf("recorded 1 session, list says %d", len(before))
	}

	if _, _, _ = b.do(http.MethodGet, "/end_session"); b.cookies[issuer.SSOCookieName] != "" {
		t.Fatal("end_session left the browser session behind")
	}

	open, err := iss.Sessions().List(t.Context(), issuer.Query{Identity: "ada@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(open) != 0 {
		t.Errorf("end_session left %d session(s) running; sign-out must end what the browser opened", len(open))
	}
}

// A STRANGER must not be able to sign out the installation.
//
// `/end_session` with no parameters reached the library's
// `TerminateSession(userID, clientID)` with both empty, because nothing
// in the request named either — and the storage turned that into
// `Revoke(Query{})`, whose own comment says an empty query ends
// everything. So one unauthenticated GET, from anyone, to a URL that is
// published in the discovery document, ended every session every person
// and every workload held.
func TestEndSessionCannotSignOutTheInstallation(t *testing.T) {
	t.Parallel()
	server, iss := signInServer(t, "ada@north.example")

	for _, who := range []string{"ada@north.example", "grace@north.example"} {
		if _, err := iss.Sessions().Record(t.Context(), issuer.Opened{
			Identity: who, ClientID: "argocd", How: issuer.HowCode, Token: "token-" + who,
		}); err != nil {
			t.Fatalf("record a session for %s: %v", who, err)
		}
	}

	// No cookie, no id_token_hint, no client_id: a passer-by.
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/end_session", nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}

	_ = response.Body.Close()

	left, err := iss.Sessions().List(t.Context(), issuer.Query{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(left) != 2 {
		t.Fatalf("a stranger's end_session left %d of 2 sessions; it must end none", len(left))
	}
}

// An `id_token_hint` is a HINT, and must not be authority to revoke.
//
// The specification calls it a hint about which session is being ended,
// and the library accepts an EXPIRED one by design. Old ID tokens sit in
// logs, in browser history and in referrer headers — so a hint that could
// revoke would hand anybody who finds one a way to sign that person out
// of a console. What a logout request can actually prove is the cookie it
// carries, and that is what decides.
func TestAnIDTokenHintDoesNotRevokeOnItsOwn(t *testing.T) {
	t.Parallel()
	server, iss := signInServer(t, "ada@north.example")

	if _, err := iss.Sessions().Record(t.Context(), issuer.Opened{
		Identity: "grace@north.example", ClientID: "argocd",
		How: issuer.HowCode, Token: "grace-refresh-token",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	// A browser that is signed in as somebody ELSE, ending its own
	// session while naming Grace's client. Grace must be untouched.
	b := newBrowser(t, server)
	b.signIn()

	if _, _, _ = b.do(http.MethodGet, "/end_session?client_id=argocd"); b.cookies[issuer.SSOCookieName] != "" {
		t.Fatal("end_session left the browser session behind")
	}

	left, err := iss.Sessions().List(t.Context(), issuer.Query{Identity: "grace@north.example"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	if len(left) != 1 {
		t.Errorf("another person's sign-out ended %d of Grace's sessions; it must end none", 1-len(left))
	}
}
