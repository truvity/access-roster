package app_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/app"
)

// boot assembles a hub the way a deployment would: through the
// environment, because that is the contract the chart writes to and the
// place four settings were being read and never set.
// Each of these builds a whole hub from the environment, so none of them
// can run in parallel: t.Setenv and t.Parallel are mutually exclusive,
// and reading the environment is exactly what is being tested.
func boot(t *testing.T, env map[string]string) *app.App {
	t.Helper()
	base := map[string]string{
		"DEMO":             "1",
		"STORE":            "memory",
		"API_PORT":         "0",
		"CONSOLE_PORT":     "0",
		"HEALTH_PORT":      "0",
		"ADMIN_PASSWORD":   "recover-me",
		"RECOVERY_ENABLED": "true",
	}
	for k, v := range env {
		base[k] = v
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
	cfg, err := app.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assembled, err := app.New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(assembled.Close)
	return assembled
}

// console boots a hub that knows its own address.
//
// The order matters: a sign-in redirect is built from PUBLIC_URL, so the
// hub has to be told where it is before it can send a browser back to
// itself. The listener is opened first with a handler it does not have
// yet, which is the only way round the circle.
func console(t *testing.T, env map[string]string) (*http.Client, string, *app.App) {
	t.Helper()
	var handler http.Handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	settings := map[string]string{"PUBLIC_URL": server.URL}
	for k, v := range env {
		settings[k] = v
	}
	assembled := boot(t, settings)
	handler = assembled.ConsoleHandler()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{Jar: jar}, server.URL, assembled
}

// browser is a client that keeps cookies and follows redirects, which is
// what makes a login flow testable as a person experiences it.
func browser(t *testing.T, handler http.Handler) (*http.Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{Jar: jar}, server
}

func get(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	request.Header.Set("Accept", "text/html")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

func rpc(t *testing.T, client *http.Client, url, body string) (int, string) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(raw)
}

// A person signs in through a directory and reaches the console with the
// role their membership grants. This is the walk-through the whole
// service exists for, and until recently the button on the sign-in page
// led to a route that did not exist.
func TestAPersonSignsInAndReachesTheConsole(t *testing.T) {
	client, at, _ := console(t, nil)

	code, page := get(t, client, at+"/login")
	if code != http.StatusOK || !strings.Contains(page, "Continue with") {
		t.Fatalf("the sign-in page = %d, %q", code, page)
	}
	// Never one button per company: an anonymous page that names the
	// tenants has published them.
	for _, company := range []string{"north.example", "south.example"} {
		if strings.Contains(page, company) {
			t.Errorf("the sign-in page names the tenant %s", company)
		}
	}

	if code, page = get(t, client, at+"/login/demo/start"); code != http.StatusOK {
		t.Fatalf("signing in = %d, %q", code, page)
	}
	code, who := get(t, client, at+"/.access/whoami")
	if code != http.StatusOK || !strings.Contains(who, `"email":"ada@north.example"`) {
		t.Fatalf("whoami = %d, %q", code, who)
	}
	if !strings.Contains(who, `"operator"`) {
		t.Errorf("whoami = %q, want the role the membership grants", who)
	}
	if !strings.Contains(who, `"source":"directory"`) {
		t.Errorf("whoami = %q, want the directory as the source", who)
	}

	// And the console answers an operator call, which is the thing the
	// session is for.
	code, body := rpc(t, client, at+"/directoryroster.v1.WorkspaceService/ListWorkspaces", "{}")
	if code != http.StatusOK || !strings.Contains(body, "C0demo-north") {
		t.Fatalf("ListWorkspaces = %d, %q", code, body)
	}
}

// Both OAuth redirect URIs are built from PUBLIC_URL, and so are the
// values the setup steps tell an operator to paste. A deployment that
// leaves it unset registers a redirect no browser will reach — which is
// what the chart was doing.
func TestTheRedirectsFollowThePublicURL(t *testing.T) {
	// A fixed public URL, so the values are assertable — and recovery
	// rather than a sign-in to read them, because a sign-in redirect
	// built from that URL would go somewhere this test is not.
	client, at, _ := console(t, map[string]string{"PUBLIC_URL": "https://directory.example"})
	if code, body := rpc(t, client, at+"/login/recovery", `{"proof":"recover-me"}`); code != http.StatusNoContent {
		t.Fatalf("recovery = %d, %q", code, body)
	}
	code, body := rpc(t, client, at+"/directoryroster.v1.SettingsService/GetSettings", "{}")
	if code != http.StatusOK {
		t.Fatalf("GetSettings = %d, %q", code, body)
	}
	for _, want := range []string{
		"https://directory.example/connect/google/callback",
		"https://directory.example/login/google/callback",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the setup step does not offer %q: %s", want, body)
		}
	}
	if strings.Contains(body, "localhost") {
		t.Errorf("the setup step still names localhost: %s", body)
	}
}

// The API listener answers everything the hub knows about every company
// it serves. Outside a cluster there is nothing to verify a token
// against, so it is open — and that is a development posture, asserted
// here so that it cannot become a deployed one unnoticed.
func TestTheAPIListenerIsOpenOnlyWithNothingToVerifyAgainst(t *testing.T) {
	assembled := boot(t, nil)
	client, server := browser(t, assembled.APIHandler())

	code, body := rpc(t, client, server.URL+"/directory.v1.DirectoryService/Describe", "{}")
	if code != http.StatusOK {
		t.Fatalf("Describe = %d, %q", code, body)
	}
	if !strings.Contains(body, "north.example") {
		t.Errorf("Describe = %q, want the served domains", body)
	}
}

// Turning the hub's own sign-in off closes the routes, and leaves the
// recovery path and the API alone.
func TestSignInOffLeavesOneDoor(t *testing.T) {
	client, at, _ := console(t, map[string]string{"LOGIN_DIRECTORY": "false"})

	code, page := get(t, client, at+"/login")
	if code != http.StatusOK || strings.Contains(page, "Continue with") {
		t.Errorf("the page still offers a sign-in: %q", page)
	}
	if !strings.Contains(page, "Recovery sign-in") {
		t.Error("recovery went with it")
	}
	if code, _ = get(t, client, at+"/login/demo/start"); code != http.StatusNotFound {
		t.Errorf("the sign-in route = %d, want it closed", code)
	}
}

// Recovery is the way in when the ordinary one is broken, and it grants
// operator without any membership at all.
func TestRecoveryReachesTheConsole(t *testing.T) {
	client, at, _ := console(t, nil)

	code, body := rpc(t, client, at+"/login/recovery", `{"proof":"wrong"}`)
	if code != http.StatusUnauthorized {
		t.Fatalf("a wrong proof = %d, %q", code, body)
	}
	if code, body = rpc(t, client, at+"/login/recovery", `{"proof":"recover-me"}`); code != http.StatusNoContent {
		t.Fatalf("recovery = %d, %q", code, body)
	}
	code, who := get(t, client, at+"/.access/whoami")
	if code != http.StatusOK || !strings.Contains(who, `"source":"recovery"`) {
		t.Fatalf("whoami = %d, %q", code, who)
	}
	if !strings.Contains(who, `"operator"`) {
		t.Errorf("recovery did not grant operator: %q", who)
	}
}

// A deployment with no recovery path has none: the page offers nothing
// and the route is closed.
func TestRecoveryCanBeTurnedOff(t *testing.T) {
	client, at, _ := console(t, map[string]string{"RECOVERY_ENABLED": "false"})

	code, page := get(t, client, at+"/login")
	if code != http.StatusOK || strings.Contains(page, "Recovery sign-in") {
		t.Errorf("the page still offers recovery: %q", page)
	}
	if code, _ = rpc(t, client, at+"/login/recovery", `{"proof":"recover-me"}`); code != http.StatusForbidden {
		t.Errorf("the recovery route = %d, want it closed", code)
	}
}

// Configuration that cannot work is refused at start rather than
// producing a hub that behaves unlike the one that was asked for.
func TestImpossibleConfigurationIsRefused(t *testing.T) {

	for _, tc := range []struct{ name, key, value string }{
		{"an unknown store", "STORE", "postgres"},
		{"a duration that is not one", "REFRESH_INTERVAL", "soon"},
		{"a log level that is not one", "LOG_LEVEL", "chatty"},
	} {
		t.Setenv(tc.key, tc.value)
		if _, err := app.Load(); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
		t.Setenv(tc.key, "")
	}
}
