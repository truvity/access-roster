package exports

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

// What an export attempt reports. The labels are the export's NAME, which the
// deployment declares (a handful), and the outcome; never the path, the
// namespace, an app id's content or a value.
const (
	// OutcomeOK is a copy that is in the store: written, or already as it
	// should be.
	OutcomeOK = "ok"
	// OutcomeFailed is a copy that could not be made: the store refused or
	// was unreachable, or the source could not be read. It is retried.
	OutcomeFailed = "failed"
	// OutcomeSkipped is a source with nothing to copy yet (an App created and
	// not installed). Nothing is written: a copy is never replaced by the
	// absence of its source.
	OutcomeSkipped = "skipped"

	// KindExport is the target kind and the lease kind of an export.
	KindExport = "export"
)

const meterName = "github.com/truvity/access-roster/exports"

type instruments struct {
	attempts    metric.Int64Counter
	duration    metric.Float64Histogram
	lastSuccess metric.Int64Gauge
	contended   metric.Int64Counter
}

var meters = newInstruments()

func newInstruments() instruments {
	meter := otel.Meter(meterName)
	// Instrument creation fails only on an invalid name, which these are not;
	// a failed one is a no-op instrument, never a stopped export.
	attempts, _ := meter.Int64Counter("access_roster.export.attempts",
		metric.WithDescription("Export attempts, by export and outcome (ok, failed or skipped). "+
			"failed is retried with backoff; skipped is a source with nothing to copy yet."))
	duration, _ := meter.Float64Histogram("access_roster.export.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Seconds an export attempt took, by outcome."),
		metric.WithExplicitBucketBoundaries(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60))
	lastSuccess, _ := meter.Int64Gauge("access_roster.export.last_success_timestamp",
		metric.WithUnit("s"),
		metric.WithDescription("When an export last had its copy in the store, as seconds since the Unix epoch."))
	contended, _ := meter.Int64Counter("access_roster.export.contended",
		metric.WithDescription("Export attempts another replica held the lease for, by export."))
	return instruments{attempts, duration, lastSuccess, contended}
}

// start opens the span and the clock of one attempt and returns what ends it
// with its outcome.
func start(ctx context.Context, name string) (context.Context, func(outcome string)) {
	ctx, span := telemetry.Tracer().Start(ctx, "export", trace.WithAttributes(
		attribute.String(telemetry.AttrTargetKind, KindExport),
		attribute.String(telemetry.AttrTargetID, name),
	))
	started := time.Now()
	return ctx, func(outcome string) {
		// Not the attempt's ctx: an attempt stopped by a lost lease still counts.
		done := context.WithoutCancel(ctx)
		export := attribute.String("export", name)
		out := attribute.String("outcome", outcome)
		meters.attempts.Add(done, 1, metric.WithAttributes(export, out))
		meters.duration.Record(done, time.Since(started).Seconds(), metric.WithAttributes(out))
		if outcome == OutcomeOK {
			meters.lastSuccess.Record(done, time.Now().Unix(), metric.WithAttributes(export))
		}
		span.SetAttributes(attribute.String(telemetry.AttrOutcome, outcome))
		if outcome == OutcomeFailed {
			span.SetStatus(codes.Error, "")
		}
		span.End()
	}
}

func nameAttr(name string) metric.MeasurementOption {
	return metric.WithAttributes(attribute.String("export", name))
}

func attemptAttrs(name, outcome string) metric.MeasurementOption {
	return metric.WithAttributes(attribute.String("export", name), attribute.String("outcome", outcome))
}
