package githubapp_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/truvity/access-roster/internal/githubapp"
)

// The package points at GitHub through two variables, so every test that
// moves them shares state: they run serially, never in parallel.

func key(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)})
	return private, string(encoded)
}

func fakeGitHub(t *testing.T, mux *http.ServeMux) {
	t.Helper()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	api, web := githubapp.APIBase, githubapp.WebBase
	githubapp.APIBase, githubapp.WebBase = server.URL, server.URL
	t.Cleanup(func() { githubapp.APIBase, githubapp.WebBase = api, web })
}

// The App the controller acts through: private, members to act with and
// organisation administration read-only to count seats, no webhook — and a
// name GitHub will accept.
func TestTheManifestAsksForMembersAndSeatsAndNoWebhook(t *testing.T) {
	manifest := githubapp.NewManifest("globex", "https://access.example/console/",
		"https://access.example/connect/github/callback", "https://access.example/connect/github/setup")
	if manifest.Public {
		t.Error("the App is public: anybody could install it on anything")
	}
	if len(manifest.DefaultPermissions) != 2 || manifest.DefaultPermissions["members"] != "write" ||
		manifest.DefaultPermissions["organization_administration"] != "read" {
		t.Errorf("permissions = %v, want members:write and organization_administration:read, nothing else", manifest.DefaultPermissions)
	}
	if manifest.HookAttributes.Active {
		t.Error("the webhook is active: nothing of ours should need to be reachable from GitHub")
	}
	if manifest.Name != "globex-access-roster" {
		t.Errorf("name = %q", manifest.Name)
	}
	long := githubapp.NewManifest("an-organisation-with-a-very-long-login", "h", "r", "s")
	if len(long.Name) > 34 || strings.HasSuffix(long.Name, "-") {
		t.Errorf("a long organisation's App name %q would be refused on the create page", long.Name)
	}
}

// The code a browser brings back is escaped into the path: a code
// carrying a path would otherwise address a different endpoint with
// whatever authority the request has.
func TestConvertingKeepsTheKeyAndEscapesTheCode(t *testing.T) {
	_, pemKey := key(t)
	var gotPath string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app-manifests/{code}/conversions", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": 42, "slug": "globex-access-roster", "pem": pemKey, "html_url": "https://github.com/apps/globex-access-roster",
			"owner": map[string]any{"login": "globex"}, "client_secret": "not kept", "webhook_secret": "not kept",
		})
	})
	fakeGitHub(t, mux)

	registration, err := githubapp.Convert(context.Background(), http.DefaultClient, "abc123")
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if registration.ID != 42 || registration.Owner != "globex" || registration.PEM != pemKey {
		t.Errorf("registration = %+v", registration)
	}

	gotPath = ""
	_, _ = githubapp.Convert(context.Background(), http.DefaultClient, "../../users/x")
	if want := "/app-manifests/..%2F..%2Fusers%2Fx/conversions"; gotPath != want {
		t.Errorf("a code carrying a path reached %q, want it confined to one segment: %q", gotPath, want)
	}
	if _, err = githubapp.Convert(context.Background(), http.DefaultClient, ""); err == nil {
		t.Error("an empty code was sent to GitHub")
	}
}

// The App JWT is what GitHub checks against the key it issued: the App's
// id as issuer, RS256, and a lifetime GitHub accepts.
func TestTheAppTokenIsWhatGitHubVerifies(t *testing.T) {
	private, pemKey := key(t)
	now := time.Date(2026, 9, 12, 22, 0, 0, 0, time.UTC)
	raw, err := githubapp.AppToken(42, pemKey, now)
	if err != nil {
		t.Fatalf("AppToken: %v", err)
	}
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var claims jwt.Claims
	if err = parsed.Claims(&private.PublicKey, &claims); err != nil {
		t.Fatalf("the token does not verify with the App's key: %v", err)
	}
	if claims.Issuer != "42" {
		t.Errorf("iss = %q, want the App id", claims.Issuer)
	}
	if lifetime := claims.Expiry.Time().Sub(claims.IssuedAt.Time()); lifetime > 10*time.Minute {
		t.Errorf("lifetime = %s; GitHub refuses more than ten minutes", lifetime)
	}
	if _, err = githubapp.AppToken(42, "not a key", now); err == nil {
		t.Error("a malformed key produced a token")
	}
}

// The setup redirect's installation id is a browser's word for it. What
// is kept is what GitHub says, as the App, across every page of its
// installations — and a next page on any other host is refused rather
// than handed the App's token.
func TestFindingAnInstallationAsksGitHubAndFollowsOnlyItsOwnPages(t *testing.T) {
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /app/installations", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer app-jwt" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Query().Get("page") {
		case "":
			w.Header().Set("Link", "<"+server.URL+`/app/installations?per_page=100&page=2>; rel="next"`)
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 1, "account": map[string]any{"login": "someone-else"}}})
		case "2":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 7, "account": map[string]any{"login": "Globex"}}})
		}
	})
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)
	api := githubapp.APIBase
	githubapp.APIBase = server.URL
	t.Cleanup(func() { githubapp.APIBase = api })

	id, err := githubapp.FindInstallation(context.Background(), server.Client(), "app-jwt", "globex")
	if err != nil || id != 7 {
		t.Fatalf("FindInstallation = %d, %v; want 7 from the second page, matched case-insensitively", id, err)
	}
	if _, err = githubapp.FindInstallation(context.Background(), server.Client(), "app-jwt", "acme"); !errors.Is(err, githubapp.ErrNotInstalled) {
		t.Errorf("an organisation with no installation = %v, want ErrNotInstalled", err)
	}

	elsewhere := http.NewServeMux()
	elsewhere.HandleFunc("GET /app/installations", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<https://attacker.example/steal?page=2>; rel="next"`)
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	})
	hostile := httptest.NewServer(elsewhere)
	t.Cleanup(hostile.Close)
	githubapp.APIBase = hostile.URL
	if _, err = githubapp.FindInstallation(context.Background(), hostile.Client(), "app-jwt", "globex"); err == nil ||
		errors.Is(err, githubapp.ErrNotInstalled) {
		t.Errorf("a next page on another host = %v, want a refusal", err)
	}
}

// Disconnect's revoke: the installation goes, and GitHub's own words come
// back when it refuses.
func TestUninstallingReportsGitHubsOwnReason(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /app/installations/{id}", func(w http.ResponseWriter, r *http.Request) {
		if id, _ := strconv.Atoi(r.PathValue("id")); id == 7 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	})
	fakeGitHub(t, mux)

	if err := githubapp.DeleteInstallation(context.Background(), http.DefaultClient, "app-jwt", 7); err != nil {
		t.Errorf("DeleteInstallation: %v", err)
	}
	err := githubapp.DeleteInstallation(context.Background(), http.DefaultClient, "app-jwt", 8)
	if err == nil || !strings.Contains(err.Error(), "Not Found") {
		t.Errorf("an unknown installation = %v, want GitHub's message", err)
	}
}

// A runner App asks for registering organisation runners and nothing else,
// is private, has no webhook, and keeps its tier in its name however long
// the organisation's login is.
func TestTheRunnerManifestAsksOnlyForRunnersAndKeepsItsTier(t *testing.T) {
	t.Parallel()

	manifest := githubapp.NewRunnerManifest("north", "stable", "https://home.example", "https://home.example/cb", "https://home.example/setup")
	if manifest.Name != "north-runners-stable" || manifest.Public || manifest.HookAttributes.Active ||
		len(manifest.DefaultPermissions) != 1 || manifest.DefaultPermissions["organization_self_hosted_runners"] != "write" ||
		manifest.RedirectURL != "https://home.example/cb" || manifest.SetupURL != "https://home.example/setup" {
		t.Errorf("manifest = %+v", manifest)
	}

	long := githubapp.NewRunnerManifest(strings.Repeat("organisation-", 4), "preview", "", "", "")
	if len(long.Name) > 34 || !strings.HasSuffix(long.Name, "-runners-preview") {
		t.Errorf("long name = %q (%d)", long.Name, len(long.Name))
	}
}
