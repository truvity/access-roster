package exports_test

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/truvity/access-roster/internal/config"
	"github.com/truvity/access-roster/internal/exports"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/port/memory"
	"github.com/truvity/access-roster/internal/portstore"
	"github.com/truvity/access-roster/internal/rails"
	slackcatalogueapp "github.com/truvity/access-roster/internal/slackapp/catalogueapp"
)

var (
	metricsOnce sync.Once
	reader      *sdkmetric.ManualReader
)

// counter is the cumulative value of the int64 series with exactly these
// attributes; one provider serves the whole test binary.
func counter(t *testing.T, name string, want ...attribute.KeyValue) int64 {
	t.Helper()
	metricsOnce.Do(func() {
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
			}
		}
	}
	return 0
}

func attempts(t *testing.T, export, outcome string) int64 {
	return counter(t, "access_roster.export.attempts", attribute.String("export", export), attribute.String("outcome", outcome))
}

type rig struct {
	state  *memory.Store
	slacks *portstore.SlackCatalogueApps
	out    *memory.Export
	runner *exports.Runner
}

// newRig is a runner with one Slack App export over State-backed stores.
func newRig(t *testing.T, name string) *rig {
	t.Helper()
	state := memory.New()
	base := portstore.New(state.Set())
	slacks := portstore.NewSlackCatalogueApps(base)
	out := memory.NewExport()
	specs, err := exports.FromConfig([]config.Export{{
		Name: name, Source: "slack-app", App: "alerts", Namespace: "kernel", Path: "slack-apps/alerts", Interval: dur(time.Hour),
	}}, exports.Declared{SlackApps: []string{"alerts"}})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{state: state, slacks: slacks, out: out, runner: &exports.Runner{
		Specs:   specs,
		Sources: exports.Sources{SlackCatalogueApps: slacks},
		Export:  out,
		State:   state,
		Leases:  &rails.Leases{State: state, Holder: "test"},
		Settle:  5 * time.Millisecond, MinGap: 5 * time.Millisecond,
		Backoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond,
		NoStagger: true,
	}}
}

func (r *rig) install(t *testing.T, token string) {
	t.Helper()
	d := data()
	if err := r.slacks.Put(ctx, d.slack, slackcatalogueapp.Credentials{ClientSecret: "s", BotToken: token}); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) run(t *testing.T) (stop func()) {
	t.Helper()
	c, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = r.runner.Run(c) }()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the runner did not stop with its context")
		}
	}
}

var target = port.ExportTarget{Namespace: "kernel", Path: "slack-apps/alerts"}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func holds(r *rig, token string) func() bool {
	return func() bool {
		got, ok := r.out.Get(target)
		return ok && maps.Equal(got, map[string]string{"bot_token": token})
	}
}

// Everything is exported once at start, and a change is exported again at
// once and not at the next interval.
func TestAnExportIsMadeAtStartAndAgainOnAChange(t *testing.T) {
	r := newRig(t, "slack-app.start")
	r.install(t, "xoxb-ONE")
	before := attempts(t, "slack-app.start", "ok")
	stop := r.run(t)
	defer stop()
	eventually(t, "the copy at start", holds(r, "xoxb-ONE"))
	if got := counter(t, "access_roster.export.last_success_timestamp", attribute.String("export", "slack-app.start")); got == 0 {
		t.Error("no last-success timestamp after a copy")
	}
	r.install(t, "xoxb-TWO") // the token rotated
	eventually(t, "the rotated token", holds(r, "xoxb-TWO"))
	if got := attempts(t, "slack-app.start", "ok"); got < before+2 {
		t.Errorf("%d ok attempts, want at least 2 more", got-before)
	}
}

// An App that is not installed has nothing to copy: nothing is written, the
// attempt is counted as skipped, and the copy is made when it is installed.
func TestAnAppNotInstalledIsSkippedUntilItIs(t *testing.T) {
	r := newRig(t, "slack-app.pending")
	d := data()
	created := d.slack
	created.TeamID = ""
	if err := r.slacks.Put(ctx, created, slackcatalogueapp.Credentials{ClientSecret: "s"}); err != nil {
		t.Fatal(err)
	}
	stop := r.run(t)
	defer stop()
	eventually(t, "a skipped attempt", func() bool { return attempts(t, "slack-app.pending", "skipped") >= 1 })
	if _, ok := r.out.Get(target); ok || r.out.Writes() != 0 {
		t.Fatal("something was written for an App that is not installed")
	}
	r.install(t, "xoxb-LATE")
	eventually(t, "the copy once installed", holds(r, "xoxb-LATE"))
}

// A store that is down stales the copy and nothing else: the attempts fail and
// are counted, are retried with backoff, and the copy is made when it is back.
func TestAnOutageIsRetriedAndMakesTheCopyWhenTheStoreIsBack(t *testing.T) {
	r := newRig(t, "slack-app.outage")
	r.install(t, "xoxb-OUT")
	r.out.Fail(errors.Join(port.ErrUnavailable, errors.New("sealed")))
	stop := r.run(t)
	defer stop()
	eventually(t, "several failed attempts", func() bool { return attempts(t, "slack-app.outage", "failed") >= 3 })
	if _, ok := r.out.Get(target); ok {
		t.Fatal("a copy was made while the store was down")
	}
	if got := counter(t, "access_roster.export.last_success_timestamp", attribute.String("export", "slack-app.outage")); got != 0 {
		t.Errorf("a last-success timestamp %d while every attempt failed", got)
	}
	r.out.Fail(nil)
	eventually(t, "the copy after the outage", holds(r, "xoxb-OUT"))
}

// Exactly one writer: an export whose lease another replica holds is not made
// here, and is counted as contended.
func TestAnExportAnotherReplicaHoldsTheLeaseOfIsNotMadeHere(t *testing.T) {
	r := newRig(t, "slack-app.leased")
	r.install(t, "xoxb-LEASED")
	other := &rails.Leases{State: r.state, Holder: "another-replica"}
	lease, err := other.Acquire(ctx, exports.KindExport, "slack-app.leased")
	if err != nil {
		t.Fatal(err)
	}
	stop := r.run(t)
	defer stop()
	eventually(t, "a contended attempt", func() bool {
		return counter(t, "access_roster.export.contended", attribute.String("export", "slack-app.leased")) >= 1
	})
	if _, ok := r.out.Get(target); ok {
		t.Fatal("an export was made without its lease")
	}
	if err = lease.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

// What a failed export does to the rest of the service is nothing: it is not
// on any path, and a runner with nothing to do returns at once.
func TestARunnerWithNoExportsReturnsAtOnce(t *testing.T) {
	r := &exports.Runner{}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("a runner with no exports blocked")
	}
}
