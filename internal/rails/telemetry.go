package rails

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/truvity/access-roster/internal/telemetry"
)

// What a tick and a lease report.
//
// The labels are the target's KIND and ID and nothing else. A target is a
// GitHub organisation or a Slack workspace the policy declares, so the ID is
// bounded by the deployment's own declaration (a handful, not a customer
// base); it is the label an alert on "this organisation has stopped" needs, and
// the only one. A person, a group or an address is never a label or an
// attribute.
const (
	// OutcomeOK is a tick that ran to its report: whatever the report says
	// about the target (in sync, applied, held, dry run), the controller did its
	// job.
	OutcomeOK = "ok"
	// OutcomeFailed is a tick that could not complete: the report says failed,
	// or the tick itself returned an error.
	OutcomeFailed = "failed"
)

const meterName = "github.com/truvity/access-roster/rails"

type instruments struct {
	ticks       metric.Int64Counter
	tickTime    metric.Float64Histogram
	lastSuccess metric.Int64Gauge

	acquired  metric.Int64Counter
	contended metric.Int64Counter
	lost      metric.Int64Counter
	held      metric.Int64UpDownCounter
}

var meters = newInstruments()

func newInstruments() instruments {
	meter := otel.Meter(meterName)
	// Instrument creation fails only on an invalid name, which these are not;
	// a failed one is a no-op instrument, never a stopped controller.
	ticks, _ := meter.Int64Counter("access_roster.ticks",
		metric.WithDescription("Ticks, by target kind, target and outcome (ok or failed)."))
	tickTime, _ := meter.Float64Histogram("access_roster.tick.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Seconds a tick took, by target kind and outcome."),
		metric.WithExplicitBucketBoundaries(0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600))
	lastSuccess, _ := meter.Int64Gauge("access_roster.tick.last_success_timestamp",
		metric.WithUnit("s"),
		metric.WithDescription("When a target's last ok tick ended, as seconds since the Unix epoch."))
	acquired, _ := meter.Int64Counter("access_roster.leases.acquired",
		metric.WithDescription("Tick leases taken by this runner, by target kind."))
	contended, _ := meter.Int64Counter("access_roster.leases.contended",
		metric.WithDescription("Tick leases this runner asked for and another held, by target kind."))
	lost, _ := meter.Int64Counter("access_roster.leases.lost",
		metric.WithDescription("Tick leases this runner held and lost, taken over or not renewable for a whole lifetime, "+
			"by target kind. The tick stopped before its next write."))
	held, _ := meter.Int64UpDownCounter("access_roster.leases.held",
		metric.WithDescription("Tick leases this runner holds now, by target kind."))
	return instruments{ticks, tickTime, lastSuccess, acquired, contended, lost, held}
}

// StartTick opens the span and the clock of one tick of a target of a kind, and
// returns the context the tick runs in and what ends it with its outcome
// ([OutcomeOK] or [OutcomeFailed]). The span is sampled by the tracer
// provider's sampler like any other, and carries the kind, the target and the
// outcome.
func StartTick(ctx context.Context, kind, target string) (context.Context, func(outcome string)) {
	ctx, span := telemetry.Tracer().Start(ctx, "tick "+kind, trace.WithAttributes(
		attribute.String(telemetry.AttrTargetKind, kind),
		attribute.String(telemetry.AttrTargetID, target),
	))
	started := time.Now()
	return ctx, func(outcome string) {
		took := time.Since(started)
		kindAttr := attribute.String("kind", kind)
		outcomeAttr := attribute.String("outcome", outcome)
		// Not the tick's ctx: a tick stopped by a lost lease still counts.
		done := context.WithoutCancel(ctx)
		meters.ticks.Add(done, 1, metric.WithAttributes(kindAttr, attribute.String("target", target), outcomeAttr))
		meters.tickTime.Record(done, took.Seconds(), metric.WithAttributes(kindAttr, outcomeAttr))
		if outcome == OutcomeOK {
			meters.lastSuccess.Record(done, time.Now().Unix(), metric.WithAttributes(kindAttr, attribute.String("target", target)))
		}
		span.SetAttributes(attribute.String(telemetry.AttrOutcome, outcome))
		if outcome != OutcomeOK {
			span.SetStatus(codes.Error, "")
		}
		span.End()
	}
}

func leaseAttr(kind string) metric.MeasurementOption {
	return metric.WithAttributes(attribute.String("kind", kind))
}
