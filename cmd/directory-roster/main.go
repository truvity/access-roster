// Command directory-roster runs the directory hub.
//
// Run it with DEMO=1 for two demonstration tenants held in memory, which
// need no credential and no network. Everything it does is decided in
// internal/app; this file only starts it and stops it.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/truvity/access-roster/internal/app"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		slog.Default().Error("directory-roster stopped", "error", err)
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

	hub, err := app.New(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer hub.Close()
	return hub.Run(ctx)
}
