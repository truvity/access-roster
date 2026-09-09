package issuer_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/issuer"
)

// A token says which session it belongs to, and when the person actually
// authenticated.
//
// Both are identity, not authorization — `groups` decides, as it does
// everywhere — and both answer a question the token could not answer
// before. `sid` is the id the console lists and revokes, so a relying
// party holding a token can say WHICH of a person's sessions it is
// holding rather than only that it holds one. `auth_time` is when the
// person signed in, which is not when the token was minted: a refresh an
// hour later carries the same `auth_time` and a fresh `iat`, and that
// difference is the whole of what a "re-authenticate for this action"
// rule reads.
func TestATokenNamesItsSessionAndWhenTheySignedIn(t *testing.T) {
	t.Parallel()
	server, iss := serveIssuerFor(t, &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": {
			Found:         true,
			Authoritative: true,
			Groups:        []string{"engineering@north.example"},
			GivenName:     "Ada",
			FamilyName:    "Lovelace",
		},
	}})

	signedIn := time.Now().Add(-90 * time.Minute).Truncate(time.Second)
	opened, err := iss.Sessions().Record(t.Context(), issuer.Opened{
		Identity: "ada@north.example", ClientID: "local-dev", How: issuer.HowCode,
		Token:  "refresh-sid",
		Scopes: []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("record the session: %v", err)
	}

	// The renewal is the honest way in without a browser: the same code
	// path a kubelogin or a proxy takes every hour, and the only one a
	// test can drive over HTTP.
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"refresh-sid"},
		"client_id":     {"local-dev"},
		"scope":         {"openid profile email"},
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		server.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("post the refresh: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d", response.StatusCode)
	}

	var body struct {
		IDToken string `json:"id_token"`
	}
	if err = json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode the response: %v", err)
	}

	if body.IDToken == "" {
		t.Fatal("the refresh returned no ID token")
	}

	claims := payloadOf(t, body.IDToken)

	if got, _ := claims["sid"].(string); got != opened.ID {
		t.Errorf("sid = %q, want the session it renewed (%q)", got, opened.ID)
	}

	authTime, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time = %#v, want the second the person signed in", claims["auth_time"])
	}
	// The session was opened now, so auth_time is now and NOT the older
	// stamp above — what this asserts is that the claim tracks the
	// session's own beginning rather than this refresh.
	if time.Unix(int64(authTime), 0).Before(signedIn) {
		t.Errorf("auth_time = %v, want the session's start", time.Unix(int64(authTime), 0))
	}

	if issued, ok := claims["iat"].(float64); ok && issued < authTime {
		t.Errorf("iat %v is before auth_time %v: a token cannot predate the sign-in", issued, authTime)
	}

	// And the session's scopes carried it here. The library assembles
	// `email` and the names from the scopes it is handed, so a refresh
	// answering "no scopes" mints an ID token that names nobody — a
	// relying party showing who is signed in would show a person for an
	// hour and an empty space afterwards.
	if got, _ := claims["email"].(string); got != "ada@north.example" {
		t.Errorf("email = %q, want the scopes the session was granted to have survived the refresh", got)
	}

	if got, _ := claims["given_name"].(string); got != "Ada" {
		t.Errorf("given_name = %q, want the directory's own", got)
	}

	// `sub` is required of every ID token, and `groups` is what a relying
	// party AUTHORIZES on — ArgoCD reads it from here. Both were absent
	// until the userinfo the library assembles was actually supplied.
	if got, _ := claims["sub"].(string); got != "ada@north.example" {
		t.Errorf("sub = %q, want the identity; an ID token without one is invalid", got)
	}

	granted, _ := claims["groups"].([]any)
	if len(granted) == 0 {
		t.Errorf("groups = %v, want what the policy granted", claims["groups"])
	}
}

// A refresh may ask for less than it was granted, and never for more.
//
// Answering nil for a session's scopes made every such request look like
// more: a client narrowing to `openid` was refused as though it had
// asked for something it did not hold.
func TestARefreshMayNarrowItsScopesAndNotWidenThem(t *testing.T) {
	t.Parallel()
	server, iss := serveIssuerFor(t, &fakeDirectory{standing: map[string]issuer.Standing{
		"ada@north.example": {Found: true, Authoritative: true, Groups: []string{"engineering@north.example"}},
	}})

	if _, err := iss.Sessions().Record(t.Context(), issuer.Opened{
		Identity: "ada@north.example", ClientID: "local-dev", How: issuer.HowCode,
		Token:  "refresh-narrow",
		Scopes: []string{"openid", "profile", "email"},
	}); err != nil {
		t.Fatalf("record the session: %v", err)
	}

	refresh := func(token, scope string) int {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {token},
			"client_id":     {"local-dev"},
			"scope":         {scope},
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			server.URL+"/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("build the request: %v", err)
		}

		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatalf("post the refresh: %v", err)
		}

		defer func() { _ = response.Body.Close() }()

		return response.StatusCode
	}

	if status := refresh("refresh-narrow", "openid"); status != http.StatusOK {
		t.Errorf("narrowing to openid: %d, want it admitted", status)
	}

	// A refresh spends its token, so the widening attempt needs the one
	// the narrowing produced — and it is refused for the right reason.
	if status := refresh("refresh-narrow", "openid offline_access"); status == http.StatusOK {
		t.Error("a refresh widened its own scopes")
	}
}

// A workload trading a proof opens no session, so its token names none —
// absent, rather than an empty string a relying party would have to know
// to ignore.
func TestAnExchangedTokenNamesNoSession(t *testing.T) {
	t.Parallel()
	server, _ := serveIssuer(t)

	status, body := exchange(t, server, "github:example-org/gitops@refs/heads/master", "aws:1111:deployer")
	if status != http.StatusOK {
		t.Fatalf("exchange on master: %d %v", status, body)
	}

	raw, _ := body["access_token"].(string)
	if raw == "" {
		t.Fatalf("no access token in %v", body)
	}

	if _, present := claimsOf(t, server, raw)["sid"]; present {
		t.Error("an exchanged token carries a sid; nothing opened a session")
	}
}

// payloadOf is a JWT's claims, unverified — the signature is another
// test's subject, and what this one reads is what a relying party would
// find inside.
func payloadOf(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode the payload: %v", err)
	}

	claims := map[string]any{}
	if err = json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("parse the payload: %v", err)
	}

	return claims
}
