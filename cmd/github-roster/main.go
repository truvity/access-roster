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
	"time"

	"github.com/truvity/access-roster/internal/githubroster/app"
	"github.com/truvity/access-roster/internal/telemetry"
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

	shutdown, err := telemetry.Start(ctx, "github-roster", log)
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

	controller, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	return controller.Run(ctx)
}
