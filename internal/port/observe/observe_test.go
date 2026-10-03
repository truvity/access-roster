package observe_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/port/observe"
	"github.com/truvity/access-roster/internal/port/porttest"
	"github.com/truvity/access-roster/internal/telemetry"
)

// The wrapper changes nothing a caller can see: the same conformance suite the
// adapters pass, run over the observed memory adapter.
func TestConformanceThroughTheObserver(t *testing.T) {
	porttest.Run(t, func(*testing.T) porttest.Env {
		s := memory.New()
		s.Allow("workload-token", "system:serviceaccount:ns:sa", "access-roster")
		return porttest.Env{
			Set:          observe.Set(s.Set()),
			Advance:      s.Advance,
			BlobPrefixes: []string{"reports/", "snapshots/"},
			Proof: func() porttest.Proof {
				return porttest.Proof{Token: "workload-token", Subject: "system:serviceaccount:ns:sa", Audience: "access-roster"}
			},
		}
	})
}

var (
	once   sync.Once
	reader *sdkmetric.ManualReader
)

// One provider for the binary: the package's histogram is made at start, and
// the global provider delegates only once.
func collect(t *testing.T) map[string]uint64 {
	t.Helper()
	once.Do(func() {
		reader = sdkmetric.NewManualReader()
		otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	})
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	counts := map[string]uint64{}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			h, ok := m.Data.(metricdata.Histogram[float64])
			if !ok || m.Name != "access_roster.port.operation.duration" {
				continue
			}
			for _, p := range h.DataPoints {
				get := func(k string) string { v, _ := p.Attributes.Value(attribute.Key(k)); return v.AsString() }
				counts[get("port")+"/"+get("operation")+"/"+get("outcome")] += p.Count
				for _, kv := range p.Attributes.ToSlice() {
					if strings.Contains(kv.Value.String(), "person") {
						t.Errorf("a key reached a label: %s=%s", kv.Key, kv.Value.String())
					}
				}
			}
		}
	}
	return counts
}

// A call is counted by port, operation and how it ended: a lost compare-and-swap
// is `conflict`, not an error; an absent key is `not_found`.
func TestCallsAreCountedByOutcome(t *testing.T) {
	collect(t)
	ctx := context.Background()
	set := observe.Set(memory.New().Set())

	rev, err := set.State.Create(ctx, "ses.person-alice.1", []byte("x"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = set.State.Create(ctx, "ses.person-alice.1", []byte("x"), time.Minute); err == nil {
		t.Fatal("a second create succeeded")
	}
	if _, err = set.State.Update(ctx, "ses.person-alice.1", []byte("y"), time.Minute, rev+"stale"); err == nil {
		t.Fatal("a stale update succeeded")
	}
	if _, err = set.State.Get(ctx, "ses.person-bob.1"); err == nil {
		t.Fatal("an absent key was found")
	}
	if _, err = set.Blob.Write(ctx, "reports/person-alice", []byte("{}")); err != nil {
		t.Fatal(err)
	}

	got := collect(t)
	for _, want := range []string{"state/create/ok", "state/create/exists", "state/update/conflict", "state/get/not_found", "blob/write/ok"} {
		if got[want] == 0 {
			t.Errorf("no %s in %v", want, got)
		}
	}
}

// A port call inside a recorded trace is a child span naming the port and the
// operation; the key is not on it, and a call outside any trace starts none.
func TestASpanNamesThePortAndNeverTheKey(t *testing.T) {
	collect(t)
	memoryExport := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(telemetry.FilterExporter(memoryExport)))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	defer otel.SetTracerProvider(previous)

	set := observe.Set(memory.New().Set())
	ctx := context.Background()

	if _, err := set.State.Put(ctx, "ses.person-alice.1", []byte("x"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if n := len(memoryExport.GetSpans()); n != 0 {
		t.Fatalf("%d spans for a call outside any trace", n)
	}

	root, span := provider.Tracer("test").Start(ctx, "tick")
	if _, err := set.State.Get(root, "ses.person-alice.1"); err != nil {
		t.Fatal(err)
	}
	span.End()

	var dumped strings.Builder
	var names []string
	for _, s := range memoryExport.GetSpans() {
		names = append(names, s.Name)
		fmt.Fprintf(&dumped, "%s %v\n", s.Name, s.Attributes)
	}
	if !strings.Contains(strings.Join(names, ","), "port state get") {
		t.Errorf("no port span in %v", names)
	}
	if strings.Contains(dumped.String(), "person") {
		t.Errorf("the key is on a span:\n%s", dumped.String())
	}
}

// The optional capabilities survive exactly as the adapter has them.
func TestBlobKeepsItsOptionalCapabilities(t *testing.T) {
	blob := observe.Blob(memory.New().Set().Blob)
	if _, ok := blob.(port.Replacer); !ok {
		t.Error("Replacer lost")
	}
	if _, ok := blob.(port.ReaderAll); !ok {
		t.Error("ReaderAll lost")
	}
}
