package issuer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A response that carries a credential must never be cached.
//
// RFC 6749 5.1 requires `Cache-Control` on the token endpoint and the
// library does not set it — conformance failed `oidcc-refresh-token`
// with "token endpoint response does not contain 'cache-control'
// header". The rule exists because a token response sitting in a proxy's
// cache is a credential anybody who can reach that cache now holds.
//
// And the public documents must stay cacheable: telling the world not to
// cache a key set would put a fetch of it in front of every verification
// anybody does.
func TestOnlyCredentialResponsesRefuseCaching(t *testing.T) {
	t.Parallel()

	handler := neverCached(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, tc := range []struct {
		path    string
		noStore bool
	}{
		{"/token", true},
		{"/revoke", true},
		{"/userinfo", true},
		{"/introspect", true},
		{"/keys", false},
		{"/.well-known/openid-configuration", false},
		{"/authorize", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tc.path, nil))

			got := recorder.Header().Get("Cache-Control")
			switch {
			case tc.noStore && got != "no-store":
				t.Errorf("Cache-Control = %q, want no-store: this answer carries a credential", got)
			case !tc.noStore && got != "":
				t.Errorf("Cache-Control = %q, want none: this is a public document", got)
			}

			if pragma := recorder.Header().Get("Pragma"); tc.noStore != (pragma == "no-cache") {
				t.Errorf("Pragma = %q for %s", pragma, tc.path)
			}
		})
	}
}

// A token says HOW the person was proved.
//
// `acr` was empty, so a client asking with `acr_values` got none back —
// which conformance flags, and which matters more than the flag: a
// recovery sign-in bypasses the directory by design, and a relying party
// that wants to refuse one needs to be able to see it in the token.
//
// `amr` said "pwd" for everything, which is untrue of every sign-in this
// issuer serves. It is empty now where we were not told, because the
// provider knows whether there was a second factor and does not say.
func TestATokenSaysHowThePersonWasProved(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		how string
		acr string
		amr []string
	}{
		{"google", ACRDirectory, nil},
		{"entra", ACRDirectory, nil},
		{"", ACRDirectory, nil},
		{RecoveryHow, ACRRecovery, []string{"swk"}},
	} {
		t.Run(tc.how, func(t *testing.T) {
			t.Parallel()

			request := &authRequest{How: tc.how}

			if got := request.GetACR(); got != tc.acr {
				t.Errorf("acr = %q, want %q", got, tc.acr)
			}

			got := request.GetAMR()
			if len(got) != len(tc.amr) {
				t.Fatalf("amr = %v, want %v", got, tc.amr)
			}
			for i := range got {
				if got[i] != tc.amr[i] {
					t.Errorf("amr = %v, want %v", got, tc.amr)
				}
			}
		})
	}
}
