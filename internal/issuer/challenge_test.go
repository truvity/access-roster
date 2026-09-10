package issuer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// RFC 6750 §3: a resource server refusing a bearer token MUST say so
// with a challenge. The library answers an unusable access token at
// /userinfo with a bare http.Error, and a 401 with no challenge is the
// one shape a conforming client cannot act on — it is told it is
// unauthenticated and not told what would fix it, so a client library
// reports a transport failure or retries the same token for ever.
func TestUserinfoRefusalCarriesAChallenge(t *testing.T) {
	t.Parallel()

	handler := challenges(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userinfo":
			http.Error(w, "access token invalid", http.StatusUnauthorized)
		case "/authorize":
			http.Error(w, "not signed in", http.StatusUnauthorized)
		default:
			_, _ = w.Write([]byte("fine"))
		}
	}))

	for name, tc := range map[string]struct {
		path      string
		status    int
		challenge bool
	}{
		"a bearer endpoint refusing a token": {"/userinfo", http.StatusUnauthorized, true},
		// Not every 401 in this service is a bearer failure. The
		// authorize endpoint takes a browser session, and offering it a
		// Bearer challenge would tell a browser to go and find a token.
		"an endpoint that takes no bearer": {"/authorize", http.StatusUnauthorized, false},
		"anything that succeeds":           {"/keys", http.StatusOK, false},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tc.path, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			if recorder.Code != tc.status {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.status)
			}

			got := recorder.Header().Get("WWW-Authenticate") != ""
			if got != tc.challenge {
				t.Errorf("challenge present = %v, want %v", got, tc.challenge)
			}
		})
	}
}

// The library sets its own challenge on some paths. Ours must not
// replace a more specific one with a generic one.
func TestAnExistingChallengeIsLeftAlone(t *testing.T) {
	t.Parallel()

	handler := challenges(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="openid"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/userinfo", nil))

	if got := recorder.Header().Get("WWW-Authenticate"); got != `Bearer error="insufficient_scope", scope="openid"` {
		t.Errorf("challenge = %q, want the one the handler set", got)
	}
}
