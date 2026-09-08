package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/backend/fake"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/policy"
)

// signInConnector is a directory whose sign-in screen is a redirect back,
// answering with whichever address the test wants.
type signInConnector struct {
	email string
	fail  error
}

func (signInConnector) Kind() string { return "demo" }
func (signInConnector) AuthURL(string) (string, error) {
	return "https://consent.example", nil
}
func (c signInConnector) SignInURL(state string) (string, error) {
	return "https://provider.example/authorize?state=" + state, nil
}
func (c signInConnector) Identify(context.Context, string) (string, error) {
	if c.fail != nil {
		return "", c.fail
	}
	return c.email, nil
}
func (signInConnector) Exchange(context.Context, string, string) (hub.Workspace, backend.Backend, error) {
	return hub.Workspace{}, nil, nil
}

// signInHarness is a console over one directory holding two people: one an
// operator by membership, one in the directory and in no group.
func signInHarness(t *testing.T, email string) *ConsoleServer {
	t.Helper()
	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	directory := fake.New("C0north", "north.example").
		WithAccount("ada@north.example", "Ada", "North").
		WithAccount("brian@north.example", "Brian", "Bell").
		WithAccount("cleo@north.example", "Cleo", "Chase").
		WithGroup("platform@north.example", "ada@north.example")
	directory.Suspend("cleo@north.example")

	directoryHub := hub.New(hub.NewMemoryStore(), hub.NewMemorySnapshots(), hub.Config{}, quiet)
	if _, err := directoryHub.Adopt(ctx, hub.Workspace{Admin: "admin@north.example"}, directory); err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	directoryHub.Wait()
	declared, err := policy.Parse([]byte(`
version: 1
groups:
  hub-operators: { members: [platform@north.example] }
claims:
  hub-operators: { groups: [hub:operator] }
lifetimes: { default: 12h }
`))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("policy set: %v", err)
	}
	key, err := access.NewSessionKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	sessions, err := access.NewSessions(key, time.Hour, false)
	if err != nil {
		t.Fatalf("sessions: %v", err)
	}
	return &ConsoleServer{
		signIn:     true,
		authz:      access.NewAuthorizer(set, directoryHub, time.Hour),
		sessions:   sessions,
		state:      access.NewStateCodec(key, 10*time.Minute),
		connectors: map[string]Connector{"demo": signInConnector{email: email}},
		hub:        directoryHub,
		log:        quiet,
	}
}

// The round trip: the start sets a state cookie and sends the browser to
// the provider, the callback proves it is the same browser, and what comes
// back is a session for the address the provider named.
func TestSigningInWithADirectory(t *testing.T) {
	t.Parallel()
	server := signInHarness(t, "ada@north.example")

	start := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/login/demo/start", nil)
	request.SetPathValue("backend", "demo")
	server.signInStart(start, request)

	if start.Code != http.StatusFound {
		t.Fatalf("start = %d, want a redirect", start.Code)
	}
	cookie := start.Result().Cookies()[0] //nolint:bodyclose // a recorder's result has no body to close
	if cookie.Name != access.LoginCookieName || cookie.Value == "" {
		t.Fatalf("start set %+v, want the sign-in state cookie", cookie)
	}
	// The state in the URL and the state in the cookie are the same, which
	// is the whole of what makes the callback this browser's.
	if !strings.Contains(start.Header().Get("Location"), "state="+cookie.Value) {
		t.Errorf("location = %q, want the state in it", start.Header().Get("Location"))
	}

	done := httptest.NewRecorder()
	callback := httptest.NewRequest(http.MethodGet, "/login/demo/callback?code=x&state="+cookie.Value, nil)
	callback.SetPathValue("backend", "demo")
	callback.Header.Set("Accept", "text/html")
	callback.AddCookie(cookie)
	server.signInCallback(done, callback)

	if done.Code != http.StatusFound {
		t.Fatalf("callback = %d (%s), want a redirect into the console", done.Code, done.Body.String())
	}
	var session *http.Cookie
	for _, c := range done.Result().Cookies() { //nolint:bodyclose // a recorder's result has no body to close
		if c.Name == access.CookieName {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session was issued")
	}
	signed := httptest.NewRequest(http.MethodGet, "/", nil)
	signed.AddCookie(session)
	principal, err := server.sessions.Read(signed)
	if err != nil || principal.Email != "ada@north.example" || principal.Source != access.SourceDirectory {
		t.Errorf("session = %+v, %v", principal, err)
	}
}

// A callback that did not start here finishes nothing. Without this a
// provider's redirect could be replayed at anyone's browser.
func TestASignInCallbackMustBeTheBrowserThatStarted(t *testing.T) {
	t.Parallel()
	server := signInHarness(t, "ada@north.example")

	for _, tc := range []struct{ name, query, cookie string }{
		{"no cookie", "?code=x&state=abc", ""},
		{"cookie does not match the state", "?code=x&state=abc", "def"},
		{"state is not ours", "?code=x&state=forged", "forged"},
	} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/login/demo/callback"+tc.query, nil)
		request.SetPathValue("backend", "demo")
		if tc.cookie != "" {
			request.AddCookie(&http.Cookie{Name: access.LoginCookieName, Value: tc.cookie})
		}
		server.signInCallback(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want it refused", tc.name, recorder.Code)
		}
	}
}

// An address the hub cannot serve is refused at the door. Issuing a
// session and then showing empty pages is a worse answer than saying why.
func TestASignInTheHubCannotServeIsRefusedAtTheDoor(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, email string
	}{
		{"suspended in the directory", "cleo@north.example"},
		{"a domain this hub does not serve", "someone@elsewhere.example"},
	} {
		server := signInHarness(t, tc.email)
		start := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/login/demo/start", nil)
		request.SetPathValue("backend", "demo")
		server.signInStart(start, request)
		cookie := start.Result().Cookies()[0] //nolint:bodyclose // a recorder's result has no body to close

		done := httptest.NewRecorder()
		callback := httptest.NewRequest(http.MethodGet, "/login/demo/callback?code=x&state="+cookie.Value, nil)
		callback.SetPathValue("backend", "demo")
		callback.AddCookie(cookie)
		server.signInCallback(done, callback)

		if done.Code != http.StatusForbidden {
			t.Errorf("%s = %d, want it refused", tc.name, done.Code)
		}
		if !strings.Contains(done.Body.String(), tc.email) {
			t.Errorf("%s did not say which address was refused: %q", tc.name, done.Body.String())
		}
		for _, c := range done.Result().Cookies() { //nolint:bodyclose // a recorder's result has no body to close
			if c.Name == access.CookieName && c.Value != "" {
				t.Errorf("%s was given a session anyway", tc.name)
			}
		}
	}
}

// A person in the directory who is in no group signs in and is a viewer or
// nothing — but the hub still lets them in, because "who you are" and
// "what you may do" are different questions and the second one has a page
// that explains itself.
func TestSomebodyWithNoMembershipStillSignsIn(t *testing.T) {
	t.Parallel()
	server := signInHarness(t, "brian@north.example")

	start := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/login/demo/start", nil)
	request.SetPathValue("backend", "demo")
	server.signInStart(start, request)
	cookie := start.Result().Cookies()[0] //nolint:bodyclose // a recorder's result has no body to close

	done := httptest.NewRecorder()
	callback := httptest.NewRequest(http.MethodGet, "/login/demo/callback?code=x&state="+cookie.Value, nil)
	callback.SetPathValue("backend", "demo")
	callback.AddCookie(cookie)
	server.signInCallback(done, callback)

	// No Accept: text/html, so this is the API answer rather than a
	// browser's redirect — the same session either way.
	if done.Code != http.StatusNoContent {
		t.Errorf("callback = %d (%s), want them signed in", done.Code, done.Body.String())
	}
}

// A console reached only through a gateway that has already run the login
// wants one door, not two. Turning the hub's own sign-in off must close
// the routes, not merely hide the buttons — and it must leave connecting a
// directory alone, which is an operator granting this hub access rather
// than a way in.
func TestTheHubsOwnSignInCanBeTurnedOff(t *testing.T) {
	t.Parallel()
	server := signInHarness(t, "ada@north.example")
	server.signIn = false

	for _, path := range []string{"/login/demo/start", "/login/demo/callback"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.SetPathValue("backend", "demo")
		if strings.HasSuffix(path, "start") {
			server.signInStart(recorder, request)
		} else {
			server.signInCallback(recorder, request)
		}
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want it closed", path, recorder.Code)
		}
	}

	page := httptest.NewRecorder()
	server.loginPage(page, httptest.NewRequest(http.MethodGet, "/login", nil))
	if strings.Contains(page.Body.String(), "Continue with") {
		t.Error("the page still offers a button for a route that is closed")
	}

	// The connector is still there for Connect: an operator adding a
	// directory is not signing in.
	if _, ok := server.connectors["demo"]; !ok {
		t.Error("turning off sign-in also removed the way to connect a directory")
	}
}
