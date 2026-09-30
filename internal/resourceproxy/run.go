package resourceproxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Run starts the listeners and blocks until ctx is done, then drains
// them. A listener that fails to start, or dies, ends the process: a
// sidecar with half its sides gone should be restarted, not trusted.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	var (
		outbound   *Outbound
		source     *TokenSource
		extraReady func() error
	)
	if cfg.OutboundEnabled() {
		var err error
		if source, err = NewTokenSource(cfg, log, nil); err != nil {
			return err
		}
		if outbound, err = NewOutbound(cfg, log, source); err != nil {
			return err
		}
		extraReady = func() error {
			if !source.Obtained() {
				return errors.New("no outbound token has been obtained yet")
			}
			return nil
		}
	}
	inbound, err := NewInbound(cfg, log, extraReady)
	if err != nil {
		return err
	}

	servers := []*http.Server{newServer(cfg.Listen, inbound.Handler())}
	if outbound != nil {
		servers = append(servers, newServer(cfg.OutboundListen, outbound.Handler()))
		go source.Warm(ctx)
	}

	failed := make(chan error, len(servers))
	for _, srv := range servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			return err
		}
		log.Info("listening", slog.String("addr", ln.Addr().String()))
		go func() { failed <- srv.Serve(ln) }()
	}

	var result error
	select {
	case <-ctx.Done():
	case result = <-failed:
	}
	drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(drain)
	}
	if errors.Is(result, http.ErrServerClosed) {
		result = nil
	}
	return result
}

// newServer sets the limits that make sense for a streaming proxy: the
// header read is bounded, and the response is not -- an SSE stream lives
// as long as its client does.
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
}
