package rosterapp_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/truvity/access-roster/internal/rosterapp"
)

// boot assembles the whole service from the environment, which is what
// the chart sets. It cannot run in parallel: t.Setenv and t.Parallel are
// mutually exclusive, and reading the environment is part of what is
// under test.
//
// Nothing here is configured to reach a network: STORE defaults to
// memory, there is no Valkey and no OAuth client, and the point is the
// SHAPE of one process — what answers at which path, and what a login
// would have to dial. Which is nothing.
func boot(t *testing.T) *rosterapp.App {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(`
version: 1
groups:
  all:access-roster:operator: { members: [platform@north.example] }
  all:access-roster:viewer: {}
lifetimes: { default: 12h }
clients:
  console: { kind: public, requires: [all:access-roster:operator], redirects: ["https://access.example/console/callback"] }
`), 0o600); err != nil {
		t.Fatalf("write the policy: %v", err)
	}
	for k, v := range map[string]string{
		"ISSUER_URL":  "https://access.example",
		"PUBLIC_URL":  "https://access.example/console",
		"POLICY_DIR":  dir,
		"PORT":        "0",
		"HEALTH_PORT": "0",
		// HUB_ADDRESS is deliberately unset: there is no hub to dial.
		"HUB_ADDRESS": "",
	} {
		t.Setenv(k, v)
	}
	cfg, err := rosterapp.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	app, err := rosterapp.New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(app.Close)
	return app
}

// where is the Location a handler redirects a request to.
func where(t *testing.T, handler http.Handler, path string) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder.Header().Get("Location")
}

func get(t *testing.T, handler http.Handler, path string) (int, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder.Code, recorder.Body.String()
}

// The issuer keeps the ORIGIN ROOT. Discovery must sit at
// /.well-known/openid-configuration of the origin named in every token's
// `iss`, so nothing may be mounted in front of it.
func TestTheIssuerHoldsTheOriginRoot(t *testing.T) {
	app := boot(t)
	code, body := get(t, app.Handler(), "/.well-known/openid-configuration")
	if code != http.StatusOK {
		t.Fatalf("discovery = %d, %q", code, body)
	}
}

// The console is served by the same process on the same origin, which is
// what lets its session pages call the issuer with the browser's own
// cookie and no bearer in JavaScript.
func TestTheConsoleIsMountedUnderTheIssuersOrigin(t *testing.T) {
	app := boot(t)

	// The bare prefix is a different page to a browser: the bundle
	// references its assets relatively, so "./assets/..." on a page at
	// "/console" resolves against the root and every asset 404s.
	code, _ := get(t, app.Handler(), "/console")
	if code != http.StatusFound {
		t.Errorf("GET /console = %d, want a redirect to /console/", code)
	}

	// Nobody is signed in, so the console sends the browser to a login —
	// and it has to be a login UNDER THE MOUNT. A browser resolves
	// "/login" against the origin, where it would land on the issuer's
	// page instead, which is the whole reason the console is told where
	// it sits.
	code, body := get(t, app.Handler(), "/console/")
	if code != http.StatusFound {
		t.Fatalf("GET /console/ = %d, %q", code, body)
	}
	if to := where(t, app.Handler(), "/console/"); to != "/console/login" {
		t.Errorf("GET /console/ redirects to %q, want /console/login", to)
	}
	if code, body := get(t, app.Handler(), "/console/login"); code != http.StatusOK {
		t.Errorf("GET /console/login = %d, %q", code, body)
	}

	// The prefix is stripped, so the console's own routes never learn it
	// exists — exactly what the gateway's URLRewrite used to do for it.
	if code, body := get(t, app.Handler(), "/console/.access/whoami"); code == http.StatusNotFound {
		t.Errorf("GET /console/.access/whoami = %d, %q: the prefix was not stripped", code, body)
	}
}

// Both halves act on ONE policy, loaded once.
//
// Found by running the thing: with DEMO=1 the directory half built a
// demonstration policy and the issuer half refused to start on an empty
// POLICY_DIR, because each loaded its own. They read the same file in a
// real deployment, so the disagreement stayed hidden — but two halves
// that CAN disagree about the policy is exactly the class of failure the
// merge existed to end.
func TestBothHalvesActOnOnePolicy(t *testing.T) {
	for k, v := range map[string]string{
		"ISSUER_URL":  "https://access.example",
		"PUBLIC_URL":  "https://access.example/console",
		"PORT":        "0",
		"HEALTH_PORT": "0",
		"HUB_ADDRESS": "",
		"STORE":       "memory",
		// No POLICY_DIR at all, and a directory half with something to
		// fall back on. Before the fix this combination could not start.
		"POLICY_DIR": "",
		"DEMO":       "1",
	} {
		t.Setenv(k, v)
	}

	cfg, err := rosterapp.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	app, err := rosterapp.New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(app.Close)

	if code, body := get(t, app.Handler(), "/.well-known/openid-configuration"); code != http.StatusOK {
		t.Fatalf("discovery = %d, %q", code, body)
	}
}

// One /readyz answers for both halves. A process that cannot read a
// snapshot cannot answer who anyone is, and one that cannot reach its
// session store can neither mint nor find a session; either way it must
// leave the gateway's rotation rather than report ready and hang.
func TestOneHealthEndpointAnswersForBothHalves(t *testing.T) {
	app := boot(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		if code, body := get(t, app.HealthHandler(), path); code != http.StatusOK {
			t.Errorf("%s = %d, %q", path, code, body)
		}
	}
}

// The console tells a browser where the SessionService is.
//
// It used to learn that from the FORWARDED bearer's issuer, which the
// proxy in front configured. On one origin there is no proxy, so the
// field was empty, and the console reads an empty issuer as "there is no
// issuer to talk to" — hiding the Sessions page and the sessions section
// of a person's page, on precisely the deployment where they work best:
// the call is same-origin and carries the browser's own SSO cookie.
//
// Found in production, after the cutover, by somebody noticing the page
// was gone. Nothing failed and nothing was logged.
func TestTheConsoleIsToldWhereTheIssuerIs(t *testing.T) {
	// Not parallel: boot reads the environment, and t.Setenv forbids it.
	app := boot(t)

	code, body := get(t, app.Handler(), "/console/.access/whoami")
	if code != http.StatusOK {
		t.Fatalf("GET /console/.access/whoami = %d, %q", code, body)
	}

	var who struct {
		IssuerURL string `json:"issuerUrl"`
	}
	if err := json.Unmarshal([]byte(body), &who); err != nil {
		t.Fatalf("parse whoami: %v", err)
	}
	if who.IssuerURL == "" {
		t.Fatal("whoami reports no issuer: the console will hide its sessions pages")
	}
	// Its OWN issuer, which is the same origin the console is served on.
	if who.IssuerURL != "https://access.example" {
		t.Errorf("issuerUrl = %q, want this process's own issuer", who.IssuerURL)
	}
}

// Signing out leads back to signing in.
//
// The signed-out page said what had happened and left you there; Oleg
// asked for the login page instead. Not `/login` itself — its buttons
// carry the id of a pending authorization request, so without one it is
// a page that looks like a sign-in and cannot finish. The console's
// front page sends an unauthenticated browser through `/authorize`,
// which makes that request, so it is the address that actually reaches
// a working sign-in.
func TestSigningOutLeadsBackToSigningIn(t *testing.T) {
	// Not parallel: boot reads the environment, and t.Setenv forbids it.
	app := boot(t)

	if to := where(t, app.Handler(), "/logout"); to != "/console/" {
		t.Errorf("sign-out lands on %q, want the console's front page", to)
	}

	// And that page is a sign-in a person can finish: it sends them to
	// the issuer's chooser WITH a request id.
	to := where(t, app.Handler(), "/console/")
	if to == "" {
		t.Fatal("the console's front page did not redirect an unauthenticated browser")
	}
}
