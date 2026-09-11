package issuer_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/issuer"
)

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
