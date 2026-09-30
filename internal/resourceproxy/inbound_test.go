package resourceproxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/testissuer"
)

const resURL = "https://mcp.example.com/metrics"

type rig struct {
	iss   *testissuer.Issuer
	proxy *httptest.Server
	logs  *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// lines waits for n audit lines: the line is written after the response
// is finished, which can be after the client has read it.
func (s *syncBuffer) lines(t *testing.T, n int) []map[string]any {
	t.Helper()
	for range 200 {
		var out []map[string]any
		for _, l := range strings.Split(strings.TrimSpace(s.String()), "\n") {
			if l == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatalf("log line is not JSON: %q", l)
			}
			if m["msg"] == "mcp_request" {
				out = append(out, m)
			}
		}
		if len(out) >= n {
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("fewer than %d audit lines: %s", n, s.String())
	return nil
}

func newRig(t *testing.T, upstream http.Handler, upstreamPath string) *rig {
	t.Helper()
	iss := testissuer.New(t)
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)

	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	cfg := Config{
		Listen: ":0", Upstream: up.URL + upstreamPath, IssuerURL: iss.URL, ResourceURL: resURL, Scope: "openid",
		MaxRequestBytes: 1 << 10,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(cfg, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(in.Handler())
	t.Cleanup(srv.Close)
	return &rig{iss: iss, proxy: srv, logs: logs}
}

func (r *rig) token(t *testing.T) string {
	t.Helper()
	return r.iss.Mint(t, map[string]any{
		"sub": "ada@example.com", "email": "ada@example.com", "name": "Ada L", "aud": []string{resURL}, "azp": "https://claude.example/client.json",
	})
}

func post(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestCredentialsNeverReachTheUpstreamAndThePathIsMapped(t *testing.T) {
	t.Parallel()
	var got http.Header
	var gotPath, gotQuery string
	r := newRig(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got, gotPath, gotQuery = req.Header.Clone(), req.URL.Path, req.URL.RawQuery
		body, _ := io.ReadAll(req.Body)
		_, _ = w.Write(body) // echo: the body must arrive intact
	}), "/mcp")

	tok := r.token(t)
	req, _ := http.NewRequest(http.MethodPost, r.proxy.URL+"/metrics/sub?x=1", strings.NewReader(`{"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Auth-Request-Access-Token", tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != 200 || string(body) != `{"method":"ping"}` {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	for _, h := range []string{"Authorization", "X-Auth-Request-Access-Token"} {
		if v := got.Get(h); v != "" {
			t.Errorf("upstream saw %s = %q", h, v)
		}
	}
	for name, vals := range got {
		for _, v := range vals {
			if strings.Contains(v, tok) {
				t.Errorf("upstream header %s carries the token", name)
			}
		}
	}
	if gotPath != "/mcp/sub" || gotQuery != "x=1" {
		t.Errorf("upstream got %s?%s, want /mcp/sub?x=1", gotPath, gotQuery)
	}

	// The bare resource path maps to the upstream's own path.
	resp = post(t, r.proxy.URL+"/metrics", tok, `{"method":"ping"}`)
	_ = resp.Body.Close()
	if gotPath != "/mcp" {
		t.Errorf("upstream got %s, want /mcp", gotPath)
	}

	// UPSTREAM's path is MAPPED to, not appended to: the resource's own
	// path, with or without a trailing slash, is exactly UPSTREAM's path.
	resp = post(t, r.proxy.URL+"/metrics/", tok, `{"method":"ping"}`)
	_ = resp.Body.Close()
	if gotPath != "/mcp/" {
		t.Errorf("upstream got %s for /metrics/, want /mcp/", gotPath)
	}

	// A path outside the resource is not proxied.
	resp = post(t, r.proxy.URL+"/elsewhere", tok, `{}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("outside the prefix: %d, want 404", resp.StatusCode)
	}
}

func TestRefusedWithoutAValidToken(t *testing.T) {
	t.Parallel()
	called := false
	r := newRig(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), "")

	resp := post(t, r.proxy.URL+"/metrics", "", `{}`)
	_ = resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	want := `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/metrics", scope="openid"`
	if got := resp.Header.Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q", got)
	}
	wrongAud := r.iss.Mint(t, map[string]any{"sub": "x", "aud": []string{"https://other.example"}})
	resp = post(t, r.proxy.URL+"/metrics", wrongAud, `{}`)
	_ = resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("wrong audience: %d", resp.StatusCode)
	}
	if called {
		t.Error("the upstream was reached without a valid token")
	}

	// A refused request is audited too, with no caller.
	lines := r.logs.lines(t, 2)
	if lines[0]["status"] != float64(401) || lines[0]["sub"] != nil {
		t.Errorf("audit line for a refusal: %v", lines[0])
	}
}

func TestMetadataAndHealthNeedNoToken(t *testing.T) {
	t.Parallel()
	r := newRig(t, http.NotFoundHandler(), "")
	for _, path := range []string{"/.well-known/oauth-protected-resource/metrics", "/.well-known/oauth-protected-resource"} {
		resp, err := http.Get(r.proxy.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || doc["resource"] != resURL {
			t.Errorf("%s: %d %v", path, resp.StatusCode, doc)
		}
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(r.proxy.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
}

func TestReadyzIs503WhileTheIssuerIsDown(t *testing.T) {
	t.Parallel()
	iss := testissuer.New(t)
	cfg := Config{Listen: ":0", Upstream: "http://127.0.0.1:1", IssuerURL: iss.URL, ResourceURL: resURL}
	_ = cfg.Validate()
	in, _ := NewInbound(cfg, slog.New(slog.DiscardHandler), nil)
	iss.Close()
	rec := httptest.NewRecorder()
	in.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != 503 {
		t.Errorf("readyz = %d", rec.Code)
	}
}

func TestAuditLineNamesWhoAndWhatAndNeverTheTokenOrTheBody(t *testing.T) {
	t.Parallel()
	r := newRig(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		w.WriteHeader(http.StatusAccepted)
	}), "")
	tok := r.token(t)

	resp := post(t, r.proxy.URL+"/metrics", tok,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{"query":"SECRET-ARGUMENT"}}}`)
	_ = resp.Body.Close()
	resp = post(t, r.proxy.URL+"/metrics", tok,
		`[{"jsonrpc":"2.0","id":1,"method":"initialize"},`+
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"alerts","arguments":{"q":"SECRET-ARGUMENT"}}}]`)
	_ = resp.Body.Close()

	lines := r.logs.lines(t, 2)
	single := lines[0]
	for k, want := range map[string]any{
		"sub": "ada@example.com", "email": "ada@example.com", "name": "Ada L",
		"client": "https://claude.example/client.json", "method": "tools/call", "tool": "query",
		"status": float64(202), "http_method": "POST", "path": "/metrics",
	} {
		if single[k] != want {
			t.Errorf("%s = %v, want %v", k, single[k], want)
		}
	}
	if _, ok := single["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms = %v", single["duration_ms"])
	}
	batch := lines[1]
	if batch["method"] != "batch" {
		t.Errorf("batch method = %v", batch["method"])
	}
	calls, _ := batch["calls"].([]any)
	if len(calls) != 2 || calls[1].(map[string]any)["tool"] != "alerts" {
		t.Errorf("batch calls = %v", batch["calls"])
	}

	all := r.logs.String()
	if strings.Contains(all, tok) || strings.Contains(all, "SECRET-ARGUMENT") || strings.Contains(all, "Bearer") {
		t.Errorf("the log holds a token or a body:\n%s", all)
	}
}

func TestOversizeBodyIs413(t *testing.T) {
	t.Parallel()
	r := newRig(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("upstream reached") }), "")
	resp := post(t, r.proxy.URL+"/metrics", r.token(t), `{"method":"x","pad":"`+strings.Repeat("a", 2000)+`"}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

// An SSE stream must reach the client as it is written, not when the
// upstream finishes.
func TestSSEIsStreamedNotBuffered(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	r := newRig(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "event: message\ndata: one\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-req.Context().Done():
		}
		_, _ = io.WriteString(w, "event: message\ndata: two\n\n")
	}), "")

	req, _ := http.NewRequest(http.MethodGet, r.proxy.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+r.token(t))
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	first := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "data:") {
				first <- sc.Text()
				return
			}
		}
	}()
	select {
	case line := <-first:
		if line != "data: one" {
			t.Errorf("first event = %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the first event did not arrive while the stream was still open: the proxy buffers")
	}
	close(release)
}
