package resourceproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/truvity/access-roster/identity"
	"github.com/truvity/access-roster/identity/resource"
)

// Headers that can carry the caller's token. None reaches the stock
// server: a server that does not know it is behind a gateway must not be
// handed a credential meant for this one.
var credentialHeaders = []string{identity.HeaderAuthorization, identity.HeaderForwarded}

// Inbound is the public side.
type Inbound struct {
	res      *resource.Resource
	cfg      Config
	log      *slog.Logger
	upstream *url.URL
	prefix   string // the resource's own path, with no trailing slash; "" for a root resource
	proxy    *httputil.ReverseProxy
	// extraReady is asked by /readyz as well: the outbound side, when it
	// is on.
	extraReady func() error
}

// NewInbound builds the inbound side from a validated Config.
func NewInbound(cfg Config, log *slog.Logger, extraReady func() error) (*Inbound, error) {
	res, err := resource.New(resource.Config{IssuerURL: cfg.IssuerURL, ResourceURL: cfg.ResourceURL, Scope: cfg.Scope})
	if err != nil {
		return nil, err
	}
	upstream, err := httpURL(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	ru, err := url.Parse(cfg.ResourceURL)
	if err != nil {
		return nil, err
	}

	in := &Inbound{
		res: res, cfg: cfg, log: log, upstream: upstream, extraReady: extraReady,
		prefix: strings.TrimSuffix(ru.Path, "/"),
	}
	in.proxy = &httputil.ReverseProxy{
		Rewrite:       in.rewrite,
		FlushInterval: -1, // SSE: every write goes straight through
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: cfg.UpstreamTimeout,
			MaxIdleConns:          32,
			IdleConnTimeout:       90 * time.Second,
			DisableCompression:    true, // pass the bytes through as they are
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// The error can name the upstream's address; the caller gets a
			// sentence, the log gets the cause.
			log.WarnContext(r.Context(), "upstream failed", slog.String("error", err.Error()))
			http.Error(w, "the upstream did not answer", http.StatusBadGateway)
		},
	}
	return in, nil
}

// Resource is the verifier and metadata the inbound side is built on.
func (in *Inbound) Resource() *resource.Resource { return in.res }

// Handler is the whole public listener.
func (in *Inbound) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("/readyz", in.ready)
	// The RFC 9728 location for this resource, and the bare prefix for a
	// gateway that rewrites a path-suffixed request to it.
	mux.Handle(in.res.Path(), in.res.Metadata())
	mux.Handle(resource.MetadataPath, in.res.Metadata())
	mux.Handle("/", audited(in.log, in.res.Protect(http.HandlerFunc(in.serve))))
	return mux
}

func (in *Inbound) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := in.res.Ready(ctx); err != nil {
		http.Error(w, "the issuer's discovery document has not been fetched", http.StatusServiceUnavailable)
		return
	}
	if in.extraReady != nil {
		if err := in.extraReady(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	_, _ = io.WriteString(w, "ready\n")
}

// serve runs after the caller is established.
func (in *Inbound) serve(w http.ResponseWriter, r *http.Request) {
	rec := recordOf(r.Context())
	if who, ok := identity.FromContext(r.Context()); ok && rec != nil {
		rec.who, rec.have = who, true
	}

	if !in.under(r.URL.Path) {
		http.NotFound(w, r)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, in.cfg.MaxRequestBytes)
	if r.Method == http.MethodPost && isJSON(r.Header.Get("Content-Type")) {
		// Read it to name the method and the tool, then hand the same
		// bytes on. Bounded twice: in size by MaxBytesReader, in time here.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(in.cfg.BodyReadTimeout))
		body, err := io.ReadAll(r.Body)
		_ = http.NewResponseController(w).SetReadDeadline(time.Time{})
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "could not read the request", http.StatusBadRequest)
			}
			return
		}
		if rec != nil {
			calls, batched, ok := parseRPC(body)
			if ok {
				rec.batched, rec.calls = batched, calls
				if batched {
					rec.method = "batch"
				} else {
					rec.method, rec.tool = calls[0].Method, calls[0].Tool
				}
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	in.proxy.ServeHTTP(w, r)
}

// under reports whether a path is the resource's own or beneath it.
func (in *Inbound) under(path string) bool {
	return in.prefix == "" || path == in.prefix || strings.HasPrefix(path, in.prefix+"/")
}

// rewrite points the request at the stock server: the resource's prefix
// is replaced by the upstream's own path, and every header that could
// carry the caller's token is dropped.
func (in *Inbound) rewrite(pr *httputil.ProxyRequest) {
	out := pr.Out
	out.URL.Scheme = in.upstream.Scheme
	out.URL.Host = in.upstream.Host
	out.Host = in.upstream.Host
	rest := strings.TrimPrefix(pr.In.URL.Path, in.prefix)
	out.URL.Path = strings.TrimSuffix(in.upstream.Path, "/") + rest
	if out.URL.Path == "" {
		out.URL.Path = "/"
	}
	out.URL.RawPath = ""
	for _, h := range credentialHeaders {
		out.Header.Del(h)
	}
	pr.SetXForwarded()
}

func isJSON(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "application/json")
}
