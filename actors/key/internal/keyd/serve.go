package keyd

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/registry"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// socketName is the socket in a caller's directory.
const socketName = "key.sock"

// sweepEvery is how often expired data keys are wiped.
const sweepEvery = time.Minute

// Run starts key@ and serves until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	if err := s.Init(ctx); err != nil {
		return err
	}
	return s.Serve(ctx)
}

// Serve serves KeyService at <run-dir>/<caller>/key.sock for every caller of key@ in the registry, each socket
// with its own exact-caller check (ADR 0006, "Exclusive card access": the caller is also checked by peer uid, per
// socket) and mode 0660, and KeyAdminService at <run-dir>/admin.sock for root (admin.go). It runs the rewrap pass at start and every period, and wipes expired data keys. It
// returns when ctx ends or a socket fails.
func (s *Server) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := s.Rewrap(ctx); err != nil {
		slog.Warn("rewrap pass failed", "err", err)
	}

	callers := registry.CallersOf("key")
	errc := make(chan error, len(callers)+1)
	var wg sync.WaitGroup
	for _, caller := range callers {
		cfg := rpc.ServerConfig{
			Actor: "key", Boundary: s.cfg.Boundary,
			Socket: filepath.Join(s.cfg.RunDir, caller, socketName),
			Mode:   0o660,
			Allow:  rpc.ExactCaller(caller),
			// A call the guard refuses never reaches a handler, so the handlers cannot audit it: the refusal of a peer
			// that is not the caller of this socket is an audit fact like every other refusal of key@ (REQ-KEYS-031).
			OnRefused:    func(r rpc.Refused) { s.auditTransportRefusal(ctx, caller, r) },
			RefusalBurst: s.cfg.RefusalBurst, RefusalWindow: s.cfg.RefusalWindow, RefusalHourly: s.cfg.RefusalHourly, RefusalTotal: s.cfg.RefusalTotal,
		}
		if s.serverConfig != nil {
			cfg = s.serverConfig(cfg)
		}
		path, h := keyv2alpha1connect.NewKeyServiceHandler(s, rpc.HandlerOptions(cfg)...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := rpc.Serve(ctx, cfg, rpc.Handler{Path: path, H: s.undecodable(h)}); err != nil {
				errc <- fmt.Errorf("socket of %s: %w", caller, err)
			}
		}()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := s.serveAdmin(ctx); err != nil {
			errc <- err
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.background(ctx)
	}()
	go func() {
		defer wg.Done()
		s.pinLoops(ctx)
	}()

	var err error
	select {
	case err = <-errc:
		cancel()
	case <-ctx.Done():
	}
	wg.Wait()
	// What the limiters still count is reported before the process goes (the guards close theirs as their servers stop).
	s.refusals.Swap(s.newRefusalLimiter()).Close()
	s.cache.wipeAll()
	return err
}

// background runs the rewrap pass and the cache sweep until ctx ends.
func (s *Server) background(ctx context.Context) {
	every := s.cfg.RewrapEvery
	if every <= 0 {
		every = DefaultRewrapEvery
	}
	rewrap := time.NewTicker(every)
	sweep := time.NewTicker(sweepEvery)
	defer rewrap.Stop()
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rewrap.C:
			if err := s.Rewrap(ctx); err != nil {
				slog.Warn("rewrap pass failed", "err", err)
			}
		case <-sweep.C:
			s.cache.sweep()
		}
	}
}
