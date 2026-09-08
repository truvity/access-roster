// Command access-issuer runs the token service.
//
// It verifies proofs produced elsewhere, applies the shared policy, and
// issues tokens. It authenticates nobody and holds no user records — the
// line the design draws around it is in docs/design/access-issuer.md.
// Everything it decides is assembled in internal/issuerapp; this file
// only starts it and stops it.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/truvity/access-roster/internal/issuerapp"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		slog.Default().Error("access-issuer stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := issuerapp.Load()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel()}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	service, err := issuerapp.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	return service.Run(ctx)
}
