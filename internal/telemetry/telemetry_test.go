package telemetry_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/truvity/access-roster/internal/telemetry"
)

// With no collector named nothing is exported, and starting and stopping
// costs nothing and fails nothing.
func TestNoCollectorExportsNothing(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	if telemetry.Enabled() {
		t.Fatal("enabled with no collector named")
	}
	shutdown, err := telemetry.Start(context.Background(), "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || shutdown(context.Background()) != nil {
		t.Errorf("Start = %v", err)
	}
}

// A named collector starts the exporter; nothing is sent until the first
// interval, so a collector that is not there yet stops nothing.
func TestANamedCollectorStartsTheExporter(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	if !telemetry.Enabled() {
		t.Fatal("not enabled with a collector named")
	}
	shutdown, err := telemetry.Start(context.Background(), "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = shutdown(ctx)
}
