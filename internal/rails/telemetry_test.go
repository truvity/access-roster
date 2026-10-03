package rails_test

import (
	"context"
	"maps"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/rails"
)

var (
	once   sync.Once
	reader *sdkmetric.ManualReader
)

// value is the cumulative value of the series with exactly these attributes.
// One provider serves the whole binary: the package's instruments are made at
// start and the global provider delegates only once.
func value(t *testing.T, name string, want ...attribute.KeyValue) int64 {
	t.Helper()
	once.Do(func() {
		reader = sdkmetric.NewManualReader()
		otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	})
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	set := attribute.NewSet(want...)
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, p := range data.DataPoints {
					if p.Attributes.Equals(&set) {
						return p.Value
					}
				}
			case metricdata.Gauge[int64]:
				for _, p := range data.DataPoints {
					if p.Attributes.Equals(&set) {
						return p.Value
					}
				}
			case metricdata.Histogram[float64]:
				for _, p := range data.DataPoints {
					if p.Attributes.Equals(&set) {
						return int64(p.Count)
					}
				}
			}
		}
	}
	return 0
}

func kind(v string) attribute.KeyValue { return attribute.String("kind", v) }

// A tick is counted by kind, target and outcome, timed, and its last success is
// stamped only by an ok one; its span carries the kind, the target and the
// outcome and nothing else.
func TestATickIsCountedTimedAndTraced(t *testing.T) {
	value(t, "x")
	memoryExport := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(memoryExport))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	defer otel.SetTracerProvider(previous)

	target := attribute.String("target", "acme")
	failedBefore := value(t, "access_roster.ticks", kind("test-tick"), target, attribute.String("outcome", "failed"))

	_, done := rails.StartTick(context.Background(), "test-tick", "acme")
	done(rails.OutcomeFailed)
	if got := value(t, "access_roster.ticks", kind("test-tick"), target, attribute.String("outcome", "failed")); got != failedBefore+1 {
		t.Errorf("failed ticks = %d, want %d", got, failedBefore+1)
	}
	if got := value(t, "access_roster.tick.last_success_timestamp", kind("test-tick"), target); got != 0 {
		t.Errorf("a failed tick stamped a success: %d", got)
	}

	started := time.Now().Unix()
	_, done = rails.StartTick(context.Background(), "test-tick", "acme")
	done(rails.OutcomeOK)
	if got := value(t, "access_roster.tick.last_success_timestamp", kind("test-tick"), target); got < started {
		t.Errorf("last success = %d, want at least %d", got, started)
	}
	if got := value(t, "access_roster.tick.duration", kind("test-tick"), attribute.String("outcome", "ok")); got != 1 {
		t.Errorf("duration samples = %d, want 1", got)
	}

	spans := memoryExport.GetSpans()
	if len(spans) != 2 || spans[0].Name != "tick test-tick" {
		t.Fatalf("spans = %v", spans)
	}
	attrs := map[string]string{}
	for _, kv := range spans[1].Attributes {
		attrs[string(kv.Key)] = kv.Value.String()
	}
	want := map[string]string{"access_roster.target.kind": "test-tick", "access_roster.target.id": "acme", "access_roster.outcome": "ok"}
	if !maps.Equal(attrs, want) {
		t.Errorf("attributes = %v", attrs)
	}
}

// Leases are counted as acquired, contended, held and lost.
func TestLeasesAreCounted(t *testing.T) {
	value(t, "x")
	ctx := context.Background()
	store := memory.New()
	a := &rails.Leases{State: store, Holder: "a", TTL: 30 * time.Millisecond}
	b := &rails.Leases{State: store, Holder: "b", TTL: time.Minute}

	acquired := value(t, "access_roster.leases.acquired", kind("lease-test"))
	contended := value(t, "access_roster.leases.contended", kind("lease-test"))
	lost := value(t, "access_roster.leases.lost", kind("lease-test"))

	ran, err := a.Do(ctx, "lease-test", "acme", func(ctx context.Context) {
		if got := value(t, "access_roster.leases.held", kind("lease-test")); got != 1 {
			t.Errorf("held inside the tick = %d, want 1", got)
		}
		// Another runner is refused while a holds it.
		if ran, err := b.Do(ctx, "lease-test", "acme", func(context.Context) {}); ran || err != nil {
			t.Errorf("b ran under a's lease: %v, %v", ran, err)
		}
		// And a loses it when it is taken from under it.
		_ = store.Delete(ctx, rails.Key("lease-test", "acme"))
		if _, err := store.Create(ctx, rails.Key("lease-test", "acme"), []byte("b"), time.Hour); err != nil {
			t.Error(err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
			t.Error("the lease was not lost")
		}
	})
	if err != nil || !ran {
		t.Fatalf("Do = %v, %v", ran, err)
	}
	for name, c := range map[string]struct{ before int64 }{
		"access_roster.leases.acquired":  {acquired},
		"access_roster.leases.contended": {contended},
		"access_roster.leases.lost":      {lost},
	} {
		if got := value(t, name, kind("lease-test")); got != c.before+1 {
			t.Errorf("%s = %d, want %d", name, got, c.before+1)
		}
	}
	if got := value(t, "access_roster.leases.held", kind("lease-test")); got != 0 {
		t.Errorf("held after the tick = %d, want 0", got)
	}
}
