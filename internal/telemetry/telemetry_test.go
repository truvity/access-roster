package telemetry_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"go.opentelemetry.io/otel"

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

// With no sampler named, a root trace is kept (parent based, always_on); naming
// one in the environment replaces that without a release.
func TestTheDefaultSamplerKeepsRootTracesAndTheEnvironmentOverridesIt(t *testing.T) {
	for _, c := range []struct {
		name, sampler string
		sampled       bool
	}{
		{"default", "", true},
		{"always_off", "always_off", false},
		{"parentbased_always_off", "parentbased_always_off", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:1")
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
			t.Setenv("OTEL_TRACES_SAMPLER", c.sampler)
			if !telemetry.TracesEnabled() {
				t.Fatal("traces are not enabled with a collector named")
			}
			previous := otel.GetTracerProvider()
			shutdown, err := telemetry.Start(context.Background(), "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			defer func() {
				cancelled, cancel := context.WithCancel(context.Background())
				cancel()
				_ = shutdown(cancelled)
				otel.SetTracerProvider(previous)
			}()
			_, span := telemetry.Tracer().Start(context.Background(), "root")
			defer span.End()
			if got := span.SpanContext().IsSampled(); got != c.sampled {
				t.Errorf("sampled = %v, want %v", got, c.sampled)
			}
		})
	}
}

// No collector named for traces: the tracer is the no-op, and a metrics-only
// collector starts no trace exporter.
func TestTracesNeedTheirOwnCollector(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "http://127.0.0.1:1")
	if telemetry.TracesEnabled() || !telemetry.Enabled() {
		t.Fatalf("traces %v, metrics %v", telemetry.TracesEnabled(), telemetry.Enabled())
	}
}
