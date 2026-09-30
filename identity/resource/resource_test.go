package resource_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/identity"
	"github.com/truvity/access-roster/identity/resource"
	"github.com/truvity/access-roster/internal/testissuer"
)

const resourceURL = "https://mcp.example.com/metrics"

func setup(t *testing.T) (*testissuer.Issuer, *resource.Resource, http.Handler) {
	t.Helper()
	iss := testissuer.New(t)
	res, err := resource.New(resource.Config{IssuerURL: iss.URL, ResourceURL: resourceURL, Scope: "openid"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var seen identity.Verified
	h := res.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = identity.FromContext(r.Context())
		_, _ = w.Write([]byte(seen.Subject + "|" + seen.ClientID))
	}))
	return iss, res, h
}

func do(h http.Handler, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const challengeBase = `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/metrics", scope="openid"`

func TestValidTokenPassesAndCallerIsEstablished(t *testing.T) {
	t.Parallel()
	iss, _, h := setup(t)
	tok := iss.Mint(t, map[string]any{"sub": "ada@example.com", "aud": []string{resourceURL}, "azp": "https://client.example/cimd.json"})

	rec := do(h, "Bearer "+tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if got := rec.Body.String(); got != "ada@example.com|https://client.example/cimd.json" {
		t.Errorf("caller = %q", got)
	}
	// The scheme is case-insensitive.
	if rec := do(h, "bearer "+tok); rec.Code != http.StatusOK {
		t.Errorf("lowercase scheme: status = %d", rec.Code)
	}
}

func TestRefusals(t *testing.T) {
	t.Parallel()
	iss, _, h := setup(t)

	bad := func(claims map[string]any) string {
		claims["sub"] = "a"
		return "Bearer " + iss.Mint(t, claims)
	}
	invalid := challengeBase + `, error="invalid_token"`
	tests := []struct {
		name      string
		auth      string
		challenge string
	}{
		{"no token", "", challengeBase},
		{"not a bearer", "Basic abc", challengeBase},
		{"garbage", "Bearer not-a-jwt", invalid},
		{"wrong audience", bad(map[string]any{"aud": []string{"https://mcp.example.com/logs"}}), invalid},
		{"wrong issuer", bad(map[string]any{"aud": []string{resourceURL}, "iss": "https://other.example"}), invalid},
		{"expired", bad(map[string]any{"aud": []string{resourceURL}, "exp": time.Now().Add(-time.Hour).Unix()}), invalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := do(h, tc.auth)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tc.challenge {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tc.challenge)
			}
		})
	}
}

// The forwarded-token header is for a gateway in front of a console; a
// public resource server reads Authorization alone.
func TestForwardedHeaderIsNotATokenSource(t *testing.T) {
	t.Parallel()
	iss, _, h := setup(t)
	tok := iss.Mint(t, map[string]any{"sub": "a", "aud": []string{resourceURL}})
	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	req.Header.Set(identity.HeaderForwarded, tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// An unreachable issuer is an outage, not a bad token.
func TestUnreachableIssuerIs503(t *testing.T) {
	t.Parallel()
	iss := testissuer.New(t)
	res, err := resource.New(resource.Config{IssuerURL: iss.URL, ResourceURL: resourceURL})
	if err != nil {
		t.Fatal(err)
	}
	tok := iss.Mint(t, map[string]any{"sub": "a", "aud": []string{resourceURL}})
	iss.Close()
	rec := do(res.Protect(http.NotFoundHandler()), "Bearer "+tok)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Error("an outage must not send the caller to sign in again")
	}
	if err := res.Ready(t.Context()); err == nil {
		t.Error("Ready = nil with the issuer down")
	}
}

func TestReadyOnceTheIssuerAnswers(t *testing.T) {
	t.Parallel()
	_, res, _ := setup(t)
	if err := res.Ready(t.Context()); err != nil {
		t.Errorf("Ready: %v", err)
	}
}

func TestMetadataDocument(t *testing.T) {
	t.Parallel()
	iss, res, _ := setup(t)
	rec := httptest.NewRecorder()
	res.Metadata().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, res.Path(), nil))
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["resource"] != resourceURL {
		t.Errorf("resource = %v", doc["resource"])
	}
	if as, _ := doc["authorization_servers"].([]any); len(as) != 1 || as[0] != iss.URL {
		t.Errorf("authorization_servers = %v", doc["authorization_servers"])
	}
	if sc, _ := doc["scopes_supported"].([]any); len(sc) != 1 || sc[0] != "openid" {
		t.Errorf("scopes_supported = %v", doc["scopes_supported"])
	}
	if bm, _ := doc["bearer_methods_supported"].([]any); len(bm) != 1 || bm[0] != "header" {
		t.Errorf("bearer_methods_supported = %v", doc["bearer_methods_supported"])
	}
}

func TestNoScopeOmitsBothFields(t *testing.T) {
	t.Parallel()
	res, err := resource.New(resource.Config{IssuerURL: "https://i.example", ResourceURL: resourceURL})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Challenge(), "scope") {
		t.Errorf("challenge = %q", res.Challenge())
	}
	rec := httptest.NewRecorder()
	res.Metadata().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(rec.Body.String(), "scopes_supported") {
		t.Errorf("doc = %s", rec.Body)
	}
}

func TestWellKnownPath(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"https://mcp.example.com":           "/.well-known/oauth-protected-resource",
		"https://mcp.example.com/":          "/.well-known/oauth-protected-resource",
		"https://mcp.example.com/metrics":   "/.well-known/oauth-protected-resource/metrics",
		"https://mcp.example.com/devel/mcp": "/.well-known/oauth-protected-resource/devel/mcp",
	}
	for in, want := range tests {
		if got := resource.WellKnownPath(in); got != want {
			t.Errorf("WellKnownPath(%q) = %q, want %q", in, got, want)
		}
	}
	res, _ := resource.New(resource.Config{IssuerURL: "https://i.example", ResourceURL: "https://mcp.example.com/metrics"})
	if res.MetadataURL() != "https://mcp.example.com/.well-known/oauth-protected-resource/metrics" {
		t.Errorf("MetadataURL = %q", res.MetadataURL())
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	t.Parallel()
	for _, c := range []resource.Config{
		{IssuerURL: "", ResourceURL: resourceURL},
		{IssuerURL: "https://i.example", ResourceURL: "mcp.example.com/metrics"},
		{IssuerURL: "https://i.example", ResourceURL: "https://h/x#frag"},
	} {
		if _, err := resource.New(c); err == nil {
			t.Errorf("New(%+v) accepted", c)
		}
	}
}
