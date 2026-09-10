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

	"github.com/truvity/access-roster/internal/rosterapp"
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

	service, err := rosterapp.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer service.Close()
	return service.Run(ctx)
}
