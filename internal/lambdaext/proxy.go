package lambdaext

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"
)

// maxBody bounds one export. OTLP exporters batch well under this.
const maxBody = 32 << 20

// Tokens is what the proxy needs from a token source.
type Tokens interface {
	Token(ctx context.Context) (string, error)
	Invalidate(token string)
}

// Proxy is the localhost OTLP/HTTP endpoint. It forwards each export to the
// upstream synchronously: answering early and forwarding later would let
// the environment freeze with the export still in memory.
type Proxy struct {
	// Upstream is the OTLP base URL, without a trailing slash.
	Upstream string
	Tokens   Tokens
	Client   *http.Client
	Logf     func(format string, args ...any)
	// TokenTimeout bounds waiting for a token; zero is 15 seconds.
	TokenTimeout time.Duration
}

var signals = map[string]bool{"/v1/traces": true, "/v1/metrics": true, "/v1/logs": true}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !signals[r.URL.Path] {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil ||
		(mt != "application/x-protobuf" && mt != "application/json") {
		http.Error(w, "unsupported media type: OTLP/HTTP is protobuf or JSON", http.StatusUnsupportedMediaType)
		return
	}

	timeout := p.TokenTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	tctx, cancel := context.WithTimeout(r.Context(), timeout)
	token, err := p.Tokens.Token(tctx)
	cancel()
	if err != nil {
		// 503 is retryable in OTLP: the exporter backs off and tries again,
		// and the function itself is never told anything.
		w.Header().Set("Retry-After", "5")
		http.Error(w, "no access token available", http.StatusServiceUnavailable)
		return
	}

	out, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.Upstream+r.URL.Path,
		http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	out.ContentLength = r.ContentLength
	out.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	if enc := r.Header.Get("Content-Encoding"); enc != "" {
		out.Header.Set("Content-Encoding", enc)
	}
	if acc := r.Header.Get("Accept"); acc != "" {
		out.Header.Set("Accept", acc)
	}
	out.Header.Set("Authorization", "Bearer "+token)

	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(out)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if p.Logf != nil {
			p.Logf("access-roster-otlp: forward %s: %v", r.URL.Path, err)
		}
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		p.Tokens.Invalidate(token)
	}
	for _, h := range []string{"Content-Type", "Content-Encoding", "Retry-After"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
}
