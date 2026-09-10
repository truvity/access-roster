package issuerapp_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/issuerapp"
)

// Each of these assembles a whole issuer from the environment, so none
// can run in parallel: t.Setenv and t.Parallel are mutually exclusive,
// and reading the environment is what is being tested.
func boot(t *testing.T, env map[string]string) *issuerapp.App {
	t.Helper()
	policyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"), []byte(`
version: 1
groups:
  platform: { members: [platform@north.example] }
claims:
  platform: { groups: [cluster:admin] }
lifetimes: { default: 12h }
clients:
  console: { kind: public, requires: [platform], redirects: ["https://console.example/callback"] }
`), 0o600); err != nil {
		t.Fatalf("write the policy: %v", err)
	}
	// The hub admits nobody without a projected token, and the client
	// reads it fresh on every call.
	if err := os.WriteFile(filepath.Join(policyDir, "token"), []byte("a-projected-token"), 0o600); err != nil {
		t.Fatalf("write the token: %v", err)
	}
	base := map[string]string{
		"ISSUER_URL":     "https://issuer.example",
		"HUB_ADDRESS":    "http://hub.invalid:8080",
		"HUB_TOKEN_FILE": filepath.Join(policyDir, "token"),
		"POLICY_DIR":     policyDir,
		"PORT":           "0",
		"HEALTH_PORT":    "0",
	}
	for k, v := range env {
		base[k] = v
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
	cfg, err := issuerapp.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	app, err := issuerapp.New(context.Background(), cfg, issuerapp.Deps{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return app
}

func get(t *testing.T, handler http.Handler, path string) (int, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder.Code, recorder.Body.String()
}

// Discovery is the whole of what a relying party reads before it trusts
// anything, and every value in it has to be true: an endpoint advertised
// and not served is a client that fails at the worst moment.
func TestDiscoveryDescribesWhatIsActuallyServed(t *testing.T) {
	app := boot(t, nil)

	code, body := get(t, app.Handler(), "/.well-known/openid-configuration")
	if code != http.StatusOK {
		t.Fatalf("discovery = %d, %q", code, body)
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatalf("discovery is not JSON: %v", err)
	}
	if document["issuer"] != "https://issuer.example" {
		t.Errorf("issuer = %v, want the configured URL", document["issuer"])
	}
	for _, field := range []string{"jwks_uri", "authorization_endpoint", "token_endpoint"} {
		value, _ := document[field].(string)
		if !strings.HasPrefix(value, "https://issuer.example/") {
			t.Errorf("%s = %q, want it under the issuer URL", field, value)
		}
	}
	// The device flow and token exchange are what the CLIs and CI use;
	// advertising them wrongly is how a client picks a flow that is not
	// there.
	if _, ok := document["device_authorization_endpoint"]; !ok {
		t.Error("the device flow is served and not advertised")
	}
	grants, _ := document["grant_types_supported"].([]any)
	var offered []string
	for _, grant := range grants {
		text, _ := grant.(string)
		offered = append(offered, text)
	}
	for _, want := range []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"} {
		if !contains(offered, want) {
			t.Errorf("%s is served and not advertised: %v", want, offered)
		}
	}
	// Implicit is not served, and a relying party that saw it advertised
	// could choose it.
	if contains(offered, "implicit") {
		t.Errorf("implicit is advertised and not served: %v", offered)
	}
}

// The JWKS is what every verifier fetches. An empty one, or one whose key
// id does not match the tokens, verifies nothing.
func TestTheKeysAreServedAndCarryAnId(t *testing.T) {
	app := boot(t, nil)

	code, body := get(t, app.Handler(), "/keys")
	if code != http.StatusOK {
		t.Fatalf("keys = %d, %q", code, body)
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Use string `json:"use"`
			Kty string `json:"kty"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(body), &jwks); err != nil {
		t.Fatalf("the JWKS is not JSON: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("the JWKS is empty: nothing this issuer signs can be verified")
	}
	if jwks.Keys[0].Kid == "" || jwks.Keys[0].Use != "sig" || jwks.Keys[0].Kty != "RSA" {
		t.Errorf("key = %+v", jwks.Keys[0])
	}
}

// Configuration that cannot work is refused at start. The issuer URL is
// the one that matters most: it is baked into every token and every
// relying party's trust, so a default would be a value nobody chose
// spread across an estate.
func TestImpossibleConfigurationIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, key, value string }{
		{"no issuer URL", "ISSUER_URL", ""},
		{"a lifetime that is not a duration", "TOKEN_LIFETIME", "a while"},
		{"a log level that is not one", "LOG_LEVEL", "chatty"},
	} {
		t.Setenv("ISSUER_URL", "https://issuer.example")
		t.Setenv("HUB_ADDRESS", "http://hub.invalid:8080")
		t.Setenv("TOKEN_LIFETIME", "")
		t.Setenv("LOG_LEVEL", "")
		t.Setenv(tc.key, tc.value)
		if _, err := issuerapp.Load(); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}

	// Where the answer about a person comes from is checked at ASSEMBLY,
	// not at load, because there are now two ways to supply it: an
	// address to dial, or a directory in this process (INF-691). Neither
	// is a failure on its own; having neither is.
	t.Setenv("ISSUER_URL", "https://issuer.example")
	t.Setenv("HUB_ADDRESS", "")
	t.Setenv("TOKEN_LIFETIME", "")
	t.Setenv("LOG_LEVEL", "")
	cfg, err := issuerapp.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err = issuerapp.New(context.Background(), cfg, issuerapp.Deps{},
		slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Error("an issuer with no directory at all was accepted")
	}
}

// Health answers before anything else does, because that is what decides
// whether a rollout proceeds.
func TestHealthAnswers(t *testing.T) {
	app := boot(t, nil)
	for _, path := range []string{"/healthz", "/readyz"} {
		if code, body := get(t, app.HealthHandler(), path); code != http.StatusOK {
			t.Errorf("%s = %d, %q", path, code, body)
		}
	}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// The signing key arrives from somewhere else — cert-manager issuing one,
// external-secrets delivering one — as a mounted file. The issuer neither
// creates it nor reads a Secret through the API: it holds no permission
// to read Secrets at all.
func TestTheSigningKeyIsTheOneItWasGiven(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.key")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err = os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	app := boot(t, map[string]string{"SIGNING_KEY_FILE": path})
	code, body := get(t, app.Handler(), "/keys")
	if code != http.StatusOK {
		t.Fatalf("keys = %d, %q", code, body)
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
		} `json:"keys"`
	}
	if err = json.Unmarshal([]byte(body), &jwks); err != nil {
		t.Fatalf("the JWKS is not JSON: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("the JWKS has %d keys", len(jwks.Keys))
	}
	// The published modulus is the one from the file, not one this
	// service invented.
	want := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	if jwks.Keys[0].N != want {
		t.Error("the issuer published a key other than the one it was given")
	}
	if jwks.Keys[0].Kid == "" {
		t.Error("the published key has no id")
	}
}

// Starting without the key it was told to use would mean signing with one
// nobody else has: tokens that look fine and verify nowhere, which is
// worse than not starting.
func TestAMissingSigningKeyStopsTheService(t *testing.T) {
	policyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyDir, "policy.yaml"),
		[]byte("version: 1\nlifetimes: { default: 12h }\n"), 0o600); err != nil {
		t.Fatalf("write the policy: %v", err)
	}
	for name, value := range map[string]string{
		"a path that is not there": filepath.Join(policyDir, "absent.key"),
		"a file that is not a key": mustWrite(t, policyDir, "junk.key", "hello"),
	} {
		for k, v := range map[string]string{
			"ISSUER_URL": "https://issuer.example", "HUB_ADDRESS": "http://hub.invalid:8080",
			"POLICY_DIR": policyDir, "SIGNING_KEY_FILE": value,
		} {
			t.Setenv(k, v)
		}
		cfg, err := issuerapp.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if _, err = issuerapp.New(context.Background(), cfg, issuerapp.Deps{},
			slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
			t.Errorf("%s was accepted as a signing key", name)
		}
	}
}

func mustWrite(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// The sign-in round trip, with a directory that answers instantly and a
// hub that says the person is real. This is the path every human login in
// the estate takes, and until now the issuer had no way to establish who
// anybody was.
func TestAPersonSignsInAndTheRequestIsCompleted(t *testing.T) {
	// A provider that redirects straight back, the way the demonstration
	// connector does: the round trip and its state cookie are the real
	// ones, only the screen at the far end is missing.
	var issuerURL string
	directory := &stubProvider{email: "ada@north.example", back: func(state string) string {
		return issuerURL + "/login/stub/callback?code=x&state=" + url.QueryEscape(state)
	}}
	hub := stubHub(t, true, false)

	app := bootWithSignIn(t, hub, directory, &issuerURL)
	client, at := browser(t, app.Handler())
	issuerURL = at

	// The library sends a browser here with the request it is in the
	// middle of; one provider means no question to ask.
	code, body := follow(t, client, at+"/login?auth=req-123")
	if code != http.StatusOK {
		t.Fatalf("sign-in = %d, %q", code, body)
	}
	if !strings.Contains(body, "the application continues here") {
		t.Errorf("the browser did not land back at the application: %q", body)
	}
	if directory.completed != "req-123" {
		t.Fatalf("the authorization request was not completed: %q", directory.completed)
	}
	if directory.subject != "ada@north.example" {
		t.Errorf("completed as %q", directory.subject)
	}
}

// The hub's no is the only place a person reads it. Everywhere downstream
// they would simply find themselves admitted nowhere, with nothing that
// explained why.
func TestASuspendedPersonIsRefusedAtTheDoor(t *testing.T) {
	var issuerURL string
	directory := &stubProvider{email: "cleo@north.example", back: func(state string) string {
		return issuerURL + "/login/stub/callback?code=x&state=" + url.QueryEscape(state)
	}}
	hub := stubHub(t, true, true)

	app := bootWithSignIn(t, hub, directory, &issuerURL)
	client, at := browser(t, app.Handler())
	issuerURL = at

	code, body := follow(t, client, at+"/login?auth=req-456")
	if code != http.StatusForbidden {
		t.Fatalf("a suspended person = %d, want it refused (%q)", code, body)
	}
	if !strings.Contains(body, "cleo@north.example") {
		t.Errorf("the refusal does not say who was refused: %q", body)
	}
	if directory.completed != "" {
		t.Error("a refused sign-in completed the request anyway")
	}
}

// A callback that did not start here finishes nothing: without it, a
// provider's redirect could be replayed at anyone's browser and complete
// somebody else's half-finished login.
func TestASignInCallbackMustBeTheBrowserThatStarted(t *testing.T) {
	var issuerURL string
	directory := &stubProvider{email: "ada@north.example"}
	app := bootWithSignIn(t, stubHub(t, true, false), directory, &issuerURL)
	client, at := browser(t, app.Handler())
	issuerURL = at

	code, _ := follow(t, client, at+"/login/stub/callback?code=x&state=forged")
	if code != http.StatusBadRequest {
		t.Errorf("a callback with no cookie = %d, want it refused", code)
	}
	if directory.completed != "" {
		t.Error("a forged callback completed a request")
	}
}
