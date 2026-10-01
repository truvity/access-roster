package resourceproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/truvity/access-roster/tokens"
)

// unknownLifetime is assumed for a token the issuer gave no `expires_in`
// for, the same five minutes the metrics gate assumes.
const unknownLifetime = 5 * time.Minute

// TokenSource is this workload's own identity, as a bearer token: its
// projected ServiceAccount token traded at the issuer (RFC 8693) for one
// audienced at the backend. The kubelet rotates the ServiceAccount token
// under the pod, so it is read afresh for every exchange, never cached.
type TokenSource struct {
	ex       *tokens.Exchanger
	file     string
	audience string
	margin   time.Duration
	now      func() time.Time
	log      *slog.Logger

	mu      sync.Mutex
	token   string
	issued  time.Time
	expires time.Time
	ever    bool
}

// NewTokenSource builds the source from a validated Config. client is the
// transport to the issuer; nil uses tokens' default.
func NewTokenSource(cfg Config, log *slog.Logger, client *http.Client) (*TokenSource, error) {
	issuer, err := issuerOf(cfg.OutboundTokenEndpoint)
	if err != nil {
		return nil, err
	}
	return &TokenSource{
		ex:       &tokens.Exchanger{Issuer: issuer, ClientID: cfg.OutboundClientID, Client: client},
		file:     cfg.OutboundSATokenFile,
		audience: cfg.OutboundAudience,
		margin:   cfg.RefreshBefore,
		now:      time.Now,
		log:      log,
	}, nil
}

// Token returns a bearer token with at least the refresh margin left,
// exchanging when it has none. One exchange at a time: a burst of calls
// that all find the token stale waits for one answer rather than making
// one each.
//
// A failed exchange while the previous token is still valid serves the
// previous token and tries again next call: a blip at the issuer is not
// an outage of the backend.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.token != "" && s.expires.Sub(now) > s.effectiveMargin() {
		return s.token, nil
	}

	subject, err := s.readSubject()
	if err == nil {
		var granted tokens.Token
		granted, err = s.ex.Exchange(ctx, subject, tokens.TypeJWT, s.audience)
		if err == nil {
			s.token, s.issued, s.ever = granted.AccessToken, now, true
			s.expires = granted.Expires
			if s.expires.IsZero() {
				s.expires = now.Add(unknownLifetime)
			}
			return s.token, nil
		}
	}

	if s.token != "" && now.Before(s.expires) {
		s.log.Warn("token exchange failed; serving the token still in date", slog.String("error", err.Error()))
		return s.token, nil
	}
	return "", err
}

// effectiveMargin never asks for a refresh earlier than half the token's
// own life, or a short-lived token would be exchanged on every call.
func (s *TokenSource) effectiveMargin() time.Duration {
	life := s.expires.Sub(s.issued)
	if life > 0 && s.margin > life/2 {
		return life / 2
	}
	return s.margin
}

func (s *TokenSource) readSubject() (string, error) {
	raw, err := os.ReadFile(s.file)
	if err != nil {
		return "", fmt.Errorf("read the ServiceAccount token: %w", err)
	}
	subject := strings.TrimSpace(string(raw))
	if subject == "" {
		return "", errors.New("the ServiceAccount token file is empty")
	}
	return subject, nil
}

// Obtained reports whether a token has ever been obtained: what
// readiness means for the outbound side.
func (s *TokenSource) Obtained() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ever
}

// Warm tries until the first token is obtained, so readiness does not wait
// for the first request, and stops on ctx.
func (s *TokenSource) Warm(ctx context.Context) {
	for delay := time.Second; !s.Obtained(); delay = min(delay*2, 15*time.Second) {
		if _, err := s.Token(ctx); err != nil {
			s.log.Warn("outbound identity not obtained yet", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// Outbound is the loopback forwarder: whatever reaches it is sent to the
// target with this workload's own bearer token.
type Outbound struct {
	source *TokenSource
	proxy  *httputil.ReverseProxy
	log    *slog.Logger
}

// NewOutbound builds the forwarder from a validated Config.
func NewOutbound(cfg Config, log *slog.Logger, source *TokenSource) (*Outbound, error) {
	target, err := httpURL(cfg.OutboundTarget)
	if err != nil {
		return nil, err
	}
	roots, err := outboundRoots(cfg.OutboundCAFile)
	if err != nil {
		return nil, err
	}
	o := &Outbound{source: source, log: log}
	o.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// SetURL joins the target's path with the request's, so a
			// target of https://host/prefix serves /prefix/<path>.
			pr.SetURL(target)
			pr.Out.Host = target.Host
		},
		FlushInterval: -1,
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: cfg.UpstreamTimeout,
			MaxIdleConns:          32,
			IdleConnTimeout:       90 * time.Second,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.WarnContext(r.Context(), "outbound target failed", slog.String("error", err.Error()))
			http.Error(w, "the backend did not answer", http.StatusBadGateway)
		},
	}
	return o, nil
}

// Handler is the loopback listener.
func (o *Outbound) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := o.source.Token(r.Context())
		if err != nil {
			o.log.WarnContext(r.Context(), "no outbound identity", slog.String("error", err.Error()))
			http.Error(w, "no identity for the backend", http.StatusBadGateway)
			return
		}
		// Whatever the stock server sent as credentials is replaced, never
		// added to.
		r.Header.Set("Authorization", "Bearer "+token)
		o.proxy.ServeHTTP(w, r)
	})
}

// outboundRoots is the root pool for the outbound target: the system roots
// plus the PEM bundle in file, when one is named. nil (the system roots)
// when none is. A named file that cannot be read, or holds no certificate,
// is an error: a CA that was asked for and silently not loaded would only
// surface as a TLS failure on the first request.
func outboundRoots(file string) (*x509.CertPool, error) {
	if file == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("resource-proxy: OUTBOUND_CA_FILE: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("resource-proxy: OUTBOUND_CA_FILE %q contains no PEM certificate", file)
	}
	return pool, nil
}
