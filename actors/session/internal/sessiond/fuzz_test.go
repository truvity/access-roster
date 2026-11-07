//go:build sluis_test

package sessiond

import (
	"net/url"
	"strings"
	"testing"
)

// Fuzz targets for the parameters that session takes from a client (REQ-SEC-007: authorization and token parameter
// parsing). `go test` runs the seeds below and the files of testdata/fuzz on every run; `just go-fuzz-session` explores
// beyond them. Each target checks what must hold of the answer, not only that nothing panics.

// FuzzAuthorizeParameters holds the checks on the strings of an authorization request: the scope, the state and the nonce, the PKCE
// challenge and the redirect_uri.
func FuzzAuthorizeParameters(f *testing.F) {
	for _, s := range [][5]string{
		{"openid", "client-state-1", "client-nonce-1", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "https://app.example.test/cb"},
		{"openid profile email", "", "", "", "http://127.0.0.1:43210/cb"},
		{"openid  profile", "a b", "\x00", strings.Repeat("a", 43), "http://[::1]:1/cb"},
		{"profile", "\n", "é", strings.Repeat("A", 44), "https://app.example.test/cb#f"},
		{"openid\tprofile", strings.Repeat("s", 257), strings.Repeat("n", 257), "====", "https://u:p@app.example.test/cb"},
		{"openid openid", "%", "~", strings.Repeat("-", 43), "HTTP://127.0.0.1/cb"},
		{"", "", "", "", ""},
	} {
		f.Add(s[0], s[1], s[2], s[3], s[4])
	}
	registered := []string{"https://app.example.test/cb", "http://127.0.0.1/cb", "http://[::1]/cb"}
	f.Fuzz(func(t *testing.T, scope, state, nonce, challenge, redirect string) {
		if granted, err := grantedScope(scope); err == nil {
			seen := map[string]bool{}
			for _, sc := range strings.Split(granted, " ") {
				if !knownScopes[sc] || seen[sc] {
					t.Fatalf("scope %q granted %q", scope, granted)
				}
				seen[sc] = true
			}
			if !seen["openid"] || len(granted) > maxScope {
				t.Fatalf("scope %q granted %q", scope, granted)
			}
		}
		for _, v := range []string{state, nonce} {
			if vschar(v, maxState, true) {
				for i := 0; i < len(v); i++ {
					if v[i] < 0x20 || v[i] > 0x7e {
						t.Fatalf("%q passed as a state", v)
					}
				}
				if len(v) > maxState || safeState(v) != v {
					t.Fatalf("%q passed as a state", v)
				}
			} else if safeState(v) != "" {
				t.Fatalf("%q is reflected as a state", v)
			}
		}
		if validChallenge(challenge) {
			if len(challenge) != 43 || strings.ContainsAny(challenge, "=+/ \n") {
				t.Fatalf("%q passed as a challenge", challenge)
			}
		}
		if redirectRegistered(registered, redirect) {
			u, err := url.Parse(redirect)
			if err != nil || u.Fragment != "" || u.User != nil || strings.Contains(redirect, "#") {
				t.Fatalf("%q matched", redirect)
			}
			exact := false
			for _, r := range registered {
				exact = exact || r == redirect
			}
			// Not exact: only plain http on a loopback IP literal, which may take a port of its own (RFC 8252 section 7.3).
			if !exact && (u.Scheme != "http" || !loopbackIP(u.Hostname())) {
				t.Fatalf("%q matched without being registered", redirect)
			}
			if u.Scheme != "https" && !loopbackIP(u.Hostname()) {
				t.Fatalf("%q matched over plain http off loopback", redirect)
			}
		}
	})
}

// FuzzTokenParameters holds the checks on what a client sends to the token endpoint: the code, the PKCE verifier, and the
// identifier made of a code.
func FuzzTokenParameters(f *testing.F) {
	for _, s := range [][2]string{
		{"abc", strings.Repeat("a", 43)},
		{"", ""},
		{strings.Repeat("c", 513), strings.Repeat("-._~Az09", 16)},
		{"a\nb", strings.Repeat("a", 42) + " "},
		{"é", strings.Repeat("a", 129)},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, code, verifier string) {
		if validVerifier(verifier) {
			if len(verifier) < 43 || len(verifier) > 128 || strings.IndexFunc(verifier, func(r rune) bool { return !unreserved(r) }) >= 0 {
				t.Fatalf("%q passed as a verifier", verifier)
			}
		}
		if vschar(code, maxCredential, false) && (code == "" || len(code) > maxCredential || strings.ContainsAny(code, "\n\x00\t")) {
			t.Fatalf("%q passed as a code", code)
		}
		// An item is found by the hash of its secret: 96 lower-case hex characters, the same for the same code, and never the
		// code itself.
		id := secretID(code)
		if id != secretID(code) || len(id) != 96 || strings.Trim(id, "0123456789abcdef") != "" {
			t.Fatalf("secretID(%q) = %q", code, id)
		}
	})
}
