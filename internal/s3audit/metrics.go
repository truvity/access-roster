package s3audit

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// meterName is the instrumentation scope of the writer's metrics.
const meterName = "github.com/truvity/access-roster/s3audit"

// instruments are what says the trail is not being written, before an
// auditor does. A write S3 refused, an event dropped because the queue was
// full, and the queue growing are the three ways it shows; each has a Warn
// line too, and these are what an alert counts. With no collector named
// the global provider is a no-op and every record costs nothing.
type instruments struct {
	writes       metric.Int64Counter
	dropped      metric.Int64Counter
	registration metric.Registration
}

func newInstruments(provider metric.MeterProvider, depth func() int) instruments {
	if provider == nil {
		provider = otel.GetMeterProvider()
	}
	meter := provider.Meter(meterName)
	// Instrument creation fails only on an invalid name, which these are
	// not; a failed one is a no-op instrument, never a trail not written.
	writes, _ := meter.Int64Counter("access_roster.audit.writes",
		metric.WithDescription("Objects put to the audit bucket, by outcome (ok, failed) and whether the write was durable."))
	dropped, _ := meter.Int64Counter("access_roster.audit.dropped",
		metric.WithDescription("Events dropped unwritten because the queue was full while S3 refused; their log lines remain."))
	queue, _ := meter.Int64ObservableGauge("access_roster.audit.queue",
		metric.WithDescription("Events accepted and not yet written to the audit bucket."))
	registration, _ := meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		o.ObserveInt64(queue, int64(depth()))
		return nil
	}, queue)
	return instruments{writes: writes, dropped: dropped, registration: registration}
}

// recordWrite counts one put.
func (m instruments) recordWrite(ctx context.Context, durable, ok bool) {
	outcome := "ok"
	if !ok {
		outcome = "failed"
	}
	m.writes.Add(context.WithoutCancel(ctx), 1, metric.WithAttributes(
		attribute.String("outcome", outcome), attribute.Bool("durable", durable)))
}

func (m instruments) stop() {
	if m.registration != nil {
		_ = m.registration.Unregister()
	}
}
