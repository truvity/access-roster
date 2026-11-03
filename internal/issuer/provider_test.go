package issuer

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"
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
		{"github", ACRDirectory, nil},
		{"slack", ACRDirectory, nil},
		{"", ACRDirectory, nil},
		{RecoveryHow, ACRRecovery, []string{"swk"}},
		{RecoveryPasswordHow, ACRRecovery, []string{"pwd"}},
		{ConformanceHow, ACRConformance, []string{"pwd", "conformance"}},
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

func TestNormalizeACRReadsEitherSpelling(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"urn:truvity:access-roster:acr:directory": ACRDirectory,
		"urn:truvity:access-roster:acr:recovery":  ACRRecovery,
		ACRDirectory:                              ACRDirectory,
		"urn:other":                               "urn:other",
	} {
		if got := NormalizeACR(in); got != want {
			t.Errorf("NormalizeACR(%q) = %q, want %q", in, got, want)
		}
	}

	if ACRDirectory != "urn:truvity:sluis:acr:directory" || ACRRecovery != "urn:truvity:sluis:acr:recovery" {
		t.Errorf("tokens carry %q and %q", ACRDirectory, ACRRecovery)
	}

	want := map[string]bool{
		ACRDirectory: true, ACRRecovery: true,
		"urn:truvity:access-roster:acr:directory": true, "urn:truvity:access-roster:acr:recovery": true,
	}
	for _, v := range servedACRValues(false) {
		delete(want, v)
	}

	if len(want) != 0 {
		t.Errorf("discovery lacks %v", want)
	}
}

// `acr` is the class the sign-in met, whatever `acr_values` asked for.
//
// A requested class that the sign-in met comes back. One it did not meet is
// never claimed: the token says how the person was proved instead, which a
// relying party can then refuse (OpenID Connect Core 3.1.2.1). A request in
// the old spelling is answered in the new.
func TestRequestedACRValuesAreHonouredOnlyWhenMet(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		how       string
		requested []string
		want      string
	}{
		{"directory asked of a directory sign-in", "google", []string{ACRDirectory}, ACRDirectory},
		{"recovery asked of a recovery sign-in", RecoveryHow, []string{ACRRecovery}, ACRRecovery},
		{"recovery asked of a password recovery", RecoveryPasswordHow, []string{ACRDirectory, ACRRecovery}, ACRRecovery},
		{"conformance asked of a conformance sign-in", ConformanceHow, servedACRValues(true), ACRConformance},
		{"old spelling", "google", []string{legacyACRDirectory}, ACRDirectory},
		{"recovery asked of a directory sign-in", "google", []string{ACRRecovery}, ACRDirectory},
		{"directory asked of a recovery sign-in", RecoveryHow, []string{ACRDirectory}, ACRRecovery},
		{"directory asked of a conformance sign-in", ConformanceHow, []string{ACRDirectory, ACRRecovery}, ACRConformance},
		{"an unknown class", "google", []string{"urn:mace:incommon:iap:silver"}, ACRDirectory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			request := &authRequest{How: tc.how, Req: &oidc.AuthRequest{ACRValues: tc.requested}}
			if got := request.GetACR(); got != tc.want {
				t.Errorf("acr = %q, want %q", got, tc.want)
			}
		})
	}
}

// Discovery lists the conformance class only while the account is on, and
// every class a token can carry otherwise.
func TestServedACRValuesFollowTheConformanceAccount(t *testing.T) {
	t.Parallel()

	if slices.Contains(servedACRValues(false), ACRConformance) {
		t.Errorf("the conformance class is listed while the account is off: %v", servedACRValues(false))
	}
	on := servedACRValues(true)
	for _, v := range []string{ACRDirectory, ACRRecovery, ACRConformance} {
		if !slices.Contains(on, v) {
			t.Errorf("%s is not listed while the account is on: %v", v, on)
		}
	}
}

// The public documents' `Cache-Control` goes on a successful GET or HEAD of
// exactly those paths, and nowhere else: an error is not worth keeping, and a
// `Cache-Control` the handler chose is its own.
func TestPublicDocumentsAreCachedOnlyWhenServed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, method, path string
		status             int
		own                string
		want               string
	}{
		{"the key set", http.MethodGet, "/keys", http.StatusOK, "", "public, max-age=300"},
		{"HEAD", http.MethodHead, "/keys", http.StatusOK, "", "public, max-age=300"},
		{"discovery", http.MethodGet, "/.well-known/openid-configuration", http.StatusOK, "", "public, max-age=300"},
		{"RFC 8414, issuer path", http.MethodGet, "/.well-known/oauth-authorization-server/tenant", http.StatusOK, "", "public, max-age=300"},
		{"RFC 8414 without the issuer's path", http.MethodGet, "/.well-known/oauth-authorization-server", http.StatusOK, "", ""},
		{"an error", http.MethodGet, "/keys", http.StatusInternalServerError, "", ""},
		{"not modified", http.MethodGet, "/keys", http.StatusNotModified, "", ""},
		{"the handler's own", http.MethodGet, "/keys", http.StatusOK, "no-cache", "no-cache"},
		{"OPTIONS", http.MethodOptions, "/keys", http.StatusOK, "", ""},
		{"another path", http.MethodGet, "/authorize", http.StatusOK, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := publicDocuments("https://issuer.example/tenant", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.own != "" {
					w.Header().Set("Cache-Control", tc.own)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("{}"))
			}))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(tc.method, tc.path, nil))
			if got := recorder.Header().Get("Cache-Control"); got != tc.want {
				t.Errorf("Cache-Control = %q, want %q", got, tc.want)
			}
		})
	}

	// A handler that writes the body without a status is a 200.
	handler := publicDocuments("https://issuer.example", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{}"))
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	if got := recorder.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("an implicit 200: Cache-Control = %q", got)
	}
}
