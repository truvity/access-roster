// Command github-roster is the GitHub controller: it makes each GitHub
// organisation's teams match the policy's github table, and reports what
// it found and did.
//
// It runs beside access-roster's service, from the same chart, and has no
// listener. Everything it decides is assembled in
// internal/githubroster/app; this file only starts it and stops it.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/truvity/access-roster/internal/githubroster/app"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		slog.Default().Error("github-roster stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := app.Load()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel()}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	controller, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	return controller.Run(ctx)
}
