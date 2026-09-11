package issuerapp

import (
	"net/url"
	"strings"
	"testing"
)

// The console is a client of this issuer like any other application, so
// what it sends a browser to is an ordinary authorization request
// (INF-701). Everything in it has to be right: a client the policy
// declares, a redirect the client declares back, and a challenge,
// because a public client is a native one and the library requires one.
func TestTheConsoleSendsAnOrdinaryAuthorizationRequest(t *testing.T) {
	t.Parallel()

	entry := signInEntry("https://access.example/", "directory-console", "/console")
	if entry == nil {
		t.Fatal("no entry built from a complete configuration")
	}

	raw := entry()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != "https://access.example/authorize" {
		t.Errorf("entry = %q, want this issuer's authorization endpoint", raw)
	}

	query := parsed.Query()
	for field, want := range map[string]string{
		"client_id":             "directory-console",
		"response_type":         "code",
		"scope":                 "openid",
		"redirect_uri":          "https://access.example/console/",
		"code_challenge_method": "S256",
	} {
		if got := query.Get(field); got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
	}
	if len(query.Get("code_challenge")) < 40 {
		t.Errorf("code_challenge = %q, want a real S256 challenge", query.Get("code_challenge"))
	}

	// Fresh each time. Neither is checked on the way back — the console
	// does not process the response, it reads the session the response
	// left behind — but a constant would still be a constant in every
	// browser's history.
	if second := entry(); second == raw {
		t.Error("two entries are identical: the state and challenge are not fresh")
	}
	if strings.Contains(raw, "code_verifier") {
		t.Error("the verifier is in the URL: it is generated and discarded, never sent")
	}
}

// Without a client there is nothing to be, so the console keeps a
// sign-in page of its own rather than sending somebody to a request the
// issuer will refuse.
func TestNoConsoleClientMeansNoEntry(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, issuer, client, mount string }{
		{"no client", "https://access.example", "", "/console"},
		{"no console", "https://access.example", "directory-console", ""},
		{"no issuer", "", "directory-console", "/console"},
	} {
		if entry := signInEntry(tc.issuer, tc.client, tc.mount); entry != nil {
			t.Errorf("%s: built an entry anyway (%q)", tc.name, entry())
		}
	}
}
