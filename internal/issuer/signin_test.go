package issuer_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/issuer"
)

// stubPending is an authorization request waiting to be completed, with
// no storage behind it: these routes decide what to do about a request
// before anyone is established, so what they need is what it ASKS.
type stubPending struct {
	asks issuer.Pending
}

func (s stubPending) Pending(string) (issuer.Pending, error)      { return s.asks, nil }
func (s stubPending) Complete(string, issuer.Authenticated) error { return nil }

// signInHandlerWith is signInHandler with a pending request to answer.
func signInHandlerWith(t *testing.T, sso *issuer.SSO, pending stubPending) http.Handler {
	t.Helper()

	mux := http.NewServeMux()
	issuer.SignInRoutes(mux, issuer.SignInDeps{
		SSO:     sso,
		Storage: pending,
		Log:     slog.New(slog.DiscardHandler),
	})

	return mux
}

// signInHandler is the issuer's own pages, with nothing behind them but
// the sign-in store: these routes run BEFORE there is anyone to
// authorize, so none of them needs a provider or a policy.
func signInHandler(t *testing.T, sso *issuer.SSO) http.Handler {
	t.Helper()

	mux := http.NewServeMux()
	issuer.SignInRoutes(mux, issuer.SignInDeps{
		SSO: sso,
		Log: slog.New(slog.DiscardHandler),
	})

	return mux
}

// `/logout` is the sign-out a person follows, and it must actually end
// the sign-in.
//
// The console's button pointed here and nothing served it: 404, and the
// session survived. Reported as "even sign-out does not work", which it
// did not.
func TestLogoutEndsTheSignIn(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := issuer.NewMemoryState()
	sso := issuer.NewSSO(state, time.Hour)

	session, err := sso.Begin(ctx, "ada@north.example", "google")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	handler := signInHandler(t, sso)

	requestLogout(t, handler, sso, session.ID, http.MethodGet)
}

// The console sends POST, because its own sign-out was a POST. A
// GET-only route answered that with 404 — sign-out fixed once and still
// not working, which is exactly how it was reported the second time.
func TestLogoutAcceptsThePostTheConsoleSends(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := issuer.NewMemoryState()
	sso := issuer.NewSSO(state, time.Hour)

	session, err := sso.Begin(ctx, "ada@north.example", "google")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	requestLogout(t, signInHandler(t, sso), sso, session.ID, http.MethodPost)
}

// requestLogout signs out with one method and checks the whole of what
// sign-out must do: redirect, end the record, clear the cookie.
func requestLogout(t *testing.T, handler http.Handler, sso *issuer.SSO, id, method string) {
	t.Helper()

	request := httptest.NewRequest(method, "/logout", nil)
	request.AddCookie(&http.Cookie{Name: issuer.SSOCookieName, Value: id})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("%s /logout = %d, want a redirect", method, recorder.Code)
	}
	if to := recorder.Header().Get("Location"); to != "/signed-out" {
		t.Errorf("landed on %q, want /signed-out", to)
	}

	// The half that was missing: the record itself.
	if _, found, err := sso.Get(context.Background(), id); err != nil || found {
		t.Errorf("the sign-in survived %s sign-out: found=%v err=%v", method, found, err)
	}

	// And the cookie is cleared, so a request carrying the old value
	// does not look signed in until something checks the store.
	cleared := false
	for _, c := range recorder.Result().Cookies() {
		if c.Name == issuer.SSOCookieName && c.Value == "" {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the session cookie was not cleared")
	}
}

// `prompt=none` with nobody signed in answers the CLIENT, not the person.
//
// OpenID Connect Core 3.1.2.6 requires `login_required` at the redirect
// URI. This rendered a page saying so, which is worse than it sounds:
// the caller of `prompt=none` is usually a hidden iframe doing a silent
// renewal, and it cannot read an HTML page, has nobody to show it to,
// and waits until it times out. Conformance called it "expected an
// error but did not get one" — the same fact from the other side.
func TestPromptNoneWithNoSessionRefusesToTheClient(t *testing.T) {
	t.Parallel()

	handler := signInHandlerWith(t, nil, stubPending{
		asks: issuer.Pending{
			ForbidsUI:   true,
			RedirectURI: "https://rp.example/callback",
			State:       "the-client-state",
		},
	})

	request := httptest.NewRequest(http.MethodGet, "/login?auth=abc", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("GET /login = %d, want a redirect to the client", recorder.Code)
	}

	to, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}

	if got, want := to.Scheme+"://"+to.Host+to.Path, "https://rp.example/callback"; got != want {
		t.Errorf("redirected to %q, want the client's own %q", got, want)
	}

	if got := to.Query().Get("error"); got != "login_required" {
		t.Errorf("error = %q, want login_required", got)
	}

	// The state is the client's and must come back, or the client cannot
	// match the answer to the request it sent.
	if got := to.Query().Get("state"); got != "the-client-state" {
		t.Errorf("state = %q, want it echoed", got)
	}
}
