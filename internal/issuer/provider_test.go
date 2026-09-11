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
