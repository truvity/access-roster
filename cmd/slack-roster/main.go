// Command slack-roster is the Slack controller: it makes each Slack
// workspace's channels match the policy's slack table, and reports what it
// found and did.
//
// It runs beside access-roster's service, from the same chart, and has no
// listener. Everything it decides is assembled in
// internal/slackroster/app; this file only starts it and stops it.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/truvity/access-roster/internal/slackroster/app"
	"github.com/truvity/access-roster/internal/telemetry"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		slog.Default().Error("slack-roster stopped", "error", err)
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

	shutdown, err := telemetry.Start(ctx, "slack-roster", log)
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
	defer func() {
		if err := controller.Close(); err != nil {
			log.Warn("the audit emitter could not be closed cleanly; what its queue held is dropped", "error", err)
		}
	}()
	return controller.Run(ctx)
}
