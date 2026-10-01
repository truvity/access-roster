package resourceproxy

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeIssuerToken struct {
	*httptest.Server
	mu        sync.Mutex
	calls     int
	subjects  []string
	clients   []string
	audiences []string
	lifetime  int
	fail      bool
}

func newTokenEndpoint(t *testing.T, lifetime int) *fakeIssuerToken {
	t.Helper()
	f := &fakeIssuerToken{lifetime: lifetime}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		user, _, _ := r.BasicAuth()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		f.subjects = append(f.subjects, r.PostForm.Get("subject_token"))
		f.audiences = append(f.audiences, r.PostForm.Get("audience"))
		f.clients = append(f.clients, user)
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" || f.fail {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": "no"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "minted-" + string(rune('0'+f.calls)), "expires_in": f.lifetime, "token_type": "Bearer",
		})
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeIssuerToken) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func outboundCfg(t *testing.T, endpoint, target, saFile string) Config {
	t.Helper()
	cfg := Config{
		Listen: ":0", Upstream: "http://127.0.0.1:1", IssuerURL: "https://i.example", ResourceURL: resURL,
		OutboundListen: "127.0.0.1:0", OutboundTarget: target, OutboundTokenEndpoint: endpoint + "/token",
		OutboundClientID: "observability-mcp", OutboundAudience: "backend", OutboundSATokenFile: saFile,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestOutboundInjectsTheWorkloadsOwnToken(t *testing.T) {
	t.Parallel()
	tokenEP := newTokenEndpoint(t, 3600)
	var gotAuth, gotPath string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path+"?"+r.URL.RawQuery
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(target.Close)
	sa := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(sa, []byte("sa-token-1\n"), 0o600)

	cfg := outboundCfg(t, tokenEP.URL, target.URL, sa)
	src, err := NewTokenSource(cfg, slog.New(slog.DiscardHandler), nil)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := NewOutbound(cfg, slog.New(slog.DiscardHandler), src)
	srv := httptest.NewServer(out.Handler())
	t.Cleanup(srv.Close)

	// The stock server's own (or a stray) credential is replaced.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/query?query=up", nil)
	req.Header.Set("Authorization", "Bearer something-else")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if gotAuth != "Bearer minted-1" {
		t.Errorf("target saw Authorization %q", gotAuth)
	}
	if gotPath != "/api/v1/query?query=up" {
		t.Errorf("target saw %q", gotPath)
	}
	tokenEP.mu.Lock()
	defer tokenEP.mu.Unlock()
	if tokenEP.subjects[0] != "sa-token-1" || tokenEP.audiences[0] != "backend" || tokenEP.clients[0] != "observability-mcp" {
		t.Errorf("exchange saw subject %q audience %q client %q", tokenEP.subjects[0], tokenEP.audiences[0], tokenEP.clients[0])
	}
	if !src.Obtained() {
		t.Error("Obtained = false after a token was minted")
	}
}

func TestTokenIsCachedThenRefreshedBeforeExpiryFromAFreshSAFile(t *testing.T) {
	t.Parallel()
	tokenEP := newTokenEndpoint(t, 600) // ten minutes
	sa := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(sa, []byte("sa-1"), 0o600)
	cfg := outboundCfg(t, tokenEP.URL, "http://127.0.0.1:1", sa)
	src, _ := NewTokenSource(cfg, slog.New(slog.DiscardHandler), nil)

	clock := time.Now()
	src.now = func() time.Time { return clock }

	first, err := src.Token(t.Context())
	if err != nil || first != "minted-1" {
		t.Fatalf("first = %q, %v", first, err)
	}
	again, _ := src.Token(t.Context())
	if again != first || tokenEP.count() != 1 {
		t.Errorf("not cached: %q, %d exchanges", again, tokenEP.count())
	}

	// Inside the refresh margin (default one minute before expiry).
	_ = os.WriteFile(sa, []byte("sa-2"), 0o600) // the kubelet rotated it
	clock = clock.Add(9*time.Minute + 30*time.Second)
	next, err := src.Token(t.Context())
	if err != nil || next != "minted-2" {
		t.Fatalf("after the margin = %q, %v", next, err)
	}
	tokenEP.mu.Lock()
	defer tokenEP.mu.Unlock()
	if tokenEP.subjects[1] != "sa-2" {
		t.Errorf("the second exchange presented %q, want the re-read file", tokenEP.subjects[1])
	}
}

func TestAFailedRefreshServesTheTokenStillInDate(t *testing.T) {
	t.Parallel()
	tokenEP := newTokenEndpoint(t, 600)
	sa := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(sa, []byte("sa-1"), 0o600)
	cfg := outboundCfg(t, tokenEP.URL, "http://127.0.0.1:1", sa)
	src, _ := NewTokenSource(cfg, slog.New(slog.DiscardHandler), nil)
	clock := time.Now()
	src.now = func() time.Time { return clock }

	_, _ = src.Token(t.Context())
	tokenEP.mu.Lock()
	tokenEP.fail = true
	tokenEP.mu.Unlock()

	clock = clock.Add(9*time.Minute + 30*time.Second)
	if tok, err := src.Token(t.Context()); err != nil || tok != "minted-1" {
		t.Errorf("in the margin, issuer failing: %q, %v", tok, err)
	}
	clock = clock.Add(time.Minute) // now expired
	if _, err := src.Token(t.Context()); err == nil {
		t.Error("an expired token was served")
	}
}

func TestNoTokenMeansBadGatewayNotAnUnauthenticatedCall(t *testing.T) {
	t.Parallel()
	tokenEP := newTokenEndpoint(t, 600)
	tokenEP.fail = true
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	t.Cleanup(target.Close)
	sa := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(sa, []byte("sa"), 0o600)
	cfg := outboundCfg(t, tokenEP.URL, target.URL, sa)
	src, _ := NewTokenSource(cfg, slog.New(slog.DiscardHandler), nil)
	out, _ := NewOutbound(cfg, slog.New(slog.DiscardHandler), src)

	rec := httptest.NewRecorder()
	out.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusBadGateway || called {
		t.Errorf("status %d, target called %v", rec.Code, called)
	}
	if strings.Contains(rec.Body.String(), "sa") && strings.Contains(rec.Body.String(), "token") {
		t.Errorf("body leaks detail: %q", rec.Body)
	}
}

func TestOutboundRefusesANonLoopbackListenUnlessAllowed(t *testing.T) {
	t.Parallel()
	base := Config{
		Listen: ":8080", Upstream: "http://127.0.0.1:8081", IssuerURL: "https://i.example", ResourceURL: resURL,
		OutboundTarget: "https://vmauth.example", OutboundTokenEndpoint: "https://i.example/token",
		OutboundClientID: "c", OutboundAudience: "a", OutboundSATokenFile: "/f",
	}
	for listen, loopback := range map[string]bool{
		"127.0.0.1:8429": true, "localhost:8429": true, "[::1]:8429": true,
		":8429": false, "0.0.0.0:8429": false, "10.1.2.3:8429": false, "[::]:8429": false,
	} {
		cfg := base
		cfg.OutboundListen = listen
		err := cfg.Validate()
		if loopback && err != nil {
			t.Errorf("%s refused: %v", listen, err)
		}
		if !loopback {
			if err == nil {
				t.Errorf("%s accepted", listen)
			}
			cfg.OutboundAllowNonLoopback = true
			if err := cfg.Validate(); err != nil {
				t.Errorf("%s with the explicit allowance: %v", listen, err)
			}
		}
	}
}

func TestConfigRefusals(t *testing.T) {
	t.Parallel()
	good := Config{Listen: ":8080", Upstream: "http://127.0.0.1:8081", IssuerURL: "https://i.example", ResourceURL: resURL}
	if err := (&Config{}).Validate(); err == nil {
		t.Error("an empty config was accepted")
	}
	halfway := good
	halfway.OutboundTarget = "https://vmauth.example"
	if err := halfway.Validate(); err == nil {
		t.Error("OUTBOUND_* without OUTBOUND_LISTEN was accepted")
	}
	short := good
	short.OutboundListen = "127.0.0.1:8429"
	if err := short.Validate(); err == nil {
		t.Error("outbound with no target was accepted")
	}
	wrongEndpoint := short
	wrongEndpoint.OutboundTarget, wrongEndpoint.OutboundClientID, wrongEndpoint.OutboundAudience = "https://v.example", "c", "a"
	wrongEndpoint.OutboundSATokenFile, wrongEndpoint.OutboundTokenEndpoint = "/f", "https://i.example/oauth"
	if err := wrongEndpoint.Validate(); err == nil {
		t.Error("a token endpoint not ending in /token was accepted")
	}
	if err := good.Validate(); err != nil {
		t.Errorf("inbound alone: %v", err)
	}
}

// A stock server that holds no credential still sends
// `Authorization: Bearer ` with an empty token. It is replaced, not
// joined or passed.
func TestOutboundReplacesAnEmptyBearer(t *testing.T) {
	t.Parallel()
	tokenEP := newTokenEndpoint(t, 3600)
	var seen []string
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Values("Authorization")
	}))
	t.Cleanup(target.Close)
	sa := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(sa, []byte("sa"), 0o600)
	cfg := outboundCfg(t, tokenEP.URL, target.URL, sa)
	src, _ := NewTokenSource(cfg, slog.New(slog.DiscardHandler), nil)
	out, _ := NewOutbound(cfg, slog.New(slog.DiscardHandler), src)
	srv := httptest.NewServer(out.Handler())
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	req.Header["Authorization"] = []string{"Bearer ", "Bearer second"}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(seen) != 1 || seen[0] != "Bearer minted-1" {
		t.Errorf("target saw Authorization %q, want exactly the minted token", seen)
	}
}

func caFileOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func getVia(t *testing.T, out *Outbound) int {
	t.Helper()
	srv := httptest.NewServer(out.Handler())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestOutboundCAFileTrustsAPrivateTarget(t *testing.T) {
	t.Parallel()
	tokenEP := newTokenEndpoint(t, 3600)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(target.Close)
	sa := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(sa, []byte("sa"), 0o600)
	log := slog.New(slog.DiscardHandler)

	cfg := outboundCfg(t, tokenEP.URL, target.URL, sa)
	src, _ := NewTokenSource(cfg, log, nil)
	unset, err := NewOutbound(cfg, log, src)
	if err != nil {
		t.Fatal(err)
	}
	if code := getVia(t, unset); code != http.StatusBadGateway {
		t.Errorf("without OUTBOUND_CA_FILE: status %d, want 502", code)
	}

	cfg.OutboundCAFile = caFileOf(t, target)
	withCA, err := NewOutbound(cfg, log, src)
	if err != nil {
		t.Fatal(err)
	}
	if code := getVia(t, withCA); code != http.StatusOK {
		t.Errorf("with OUTBOUND_CA_FILE: status %d, want 200", code)
	}
}

func TestOutboundCAFileRefusedAtStartWhenInvalid(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	empty := filepath.Join(t.TempDir(), "empty.pem")
	_ = os.WriteFile(empty, []byte("not a certificate\n"), 0o600)
	for name, file := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "absent.pem"), "no certificates": empty,
	} {
		cfg := outboundCfg(t, "https://i.example", "https://vmauth.example", "/f")
		cfg.OutboundCAFile = file
		if _, err := NewOutbound(cfg, log, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	half := Config{Listen: ":8080", Upstream: "http://127.0.0.1:8081", IssuerURL: "https://i.example", ResourceURL: resURL,
		OutboundCAFile: "/ca.pem"}
	if err := half.Validate(); err == nil {
		t.Error("OUTBOUND_CA_FILE without OUTBOUND_LISTEN was accepted")
	}
}

// The CA bundle is for the target alone: an issuer served by that same
// private CA is still refused by the token-exchange client.
func TestOutboundCAFileDoesNotReachTheIssuerClient(t *testing.T) {
	t.Parallel()
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "x", "expires_in": 60, "token_type": "Bearer"})
	}))
	t.Cleanup(issuer.Close)
	sa := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(sa, []byte("sa"), 0o600)
	cfg := outboundCfg(t, issuer.URL, "https://vmauth.example", sa)
	cfg.OutboundCAFile = caFileOf(t, issuer)
	src, _ := NewTokenSource(cfg, slog.New(slog.DiscardHandler), nil)
	if _, err := src.Token(context.Background()); err == nil {
		t.Error("the issuer client trusted the outbound CA bundle")
	}
}
