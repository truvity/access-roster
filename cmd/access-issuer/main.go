// Command access-issuer runs access-roster.
//
// One process: it reads the corporate directories, applies the shared
// policy, issues tokens, serves the login page at the origin root and
// the console under /console/. It verifies proofs produced elsewhere and
// authenticates nobody — the line the design draws around it is in
// docs/design/access-issuer.md. Everything it decides is assembled in
// internal/rosterapp; this file only starts it and stops it.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/truvity/access-roster/internal/rosterapp"
	"github.com/truvity/access-roster/internal/telemetry"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		slog.Default().Error("access-roster stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := rosterapp.Load()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel()}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shutdown, err := telemetry.Start(ctx, "access-issuer", log)
	if err != nil {
		return err
	}
	defer func() {
		// A bounded flush: the last pass's metrics, never a hung stop.
		flush, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(flush); err != nil {
			log.Warn("metrics could not be flushed", "error", err)
		}
	}()

	service, err := rosterapp.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer service.Close()
	return service.Run(ctx)
}
