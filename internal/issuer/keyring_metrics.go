package issuer

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// keyRingMeterName is the instrumentation scope every instrument here is
// under, matching the shape [github.com/truvity/access-roster/internal/githubroster/controller]
// already uses.
const keyRingMeterName = "github.com/truvity/access-roster/issuer"

// keyRingInstruments are the ring's metrics. With no collector named the
// global provider is a no-op and every record costs nothing.
type keyRingInstruments struct {
	transitions metric.Int64Counter
	published   metric.Int64Gauge
}

func newKeyRingInstruments() keyRingInstruments {
	meter := otel.Meter(keyRingMeterName)
	// Instrument creation fails only on an invalid name, which these are
	// not; a failed one is a no-op instrument, never a stopped ring.
	transitions, _ := meter.Int64Counter("access_issuer.signing_key_transitions",
		metric.WithDescription("Signing keys, by what just happened to them and their algorithm: seen, activated, retired."))
	published, _ := meter.Int64Gauge("access_issuer.signing_keys_published",
		metric.WithDescription("Keys currently published in the JWKS by this replica, signing or retiring."))
	return keyRingInstruments{transitions: transitions, published: published}
}

// recordTransition records one key crossing into seen, activated or
// retired. The key id itself is not an attribute: it is unbounded over an
// installation's life and belongs in the log line beside this call, not
// in a metric a collector will keep every value of forever.
func (m keyRingInstruments) recordTransition(ctx context.Context, event, algorithm string) {
	m.transitions.Add(ctx, 1, metric.WithAttributes(
		attribute.String("event", event), attribute.String("algorithm", algorithm)))
}

// recordPublished records how many keys are in the JWKS right now.
func (m keyRingInstruments) recordPublished(ctx context.Context, count int64) {
	m.published.Record(ctx, count)
}
