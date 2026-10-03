package issuer

import (
	"context"
	"time"

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
	activeSince metric.Int64Gauge
}

func newKeyRingInstruments() keyRingInstruments {
	meter := otel.Meter(keyRingMeterName)
	// Instrument creation fails only on an invalid name, which these are
	// not; a failed one is a no-op instrument, never a stopped ring.
	transitions, _ := meter.Int64Counter("access_issuer.signing_key_transitions",
		metric.WithDescription("Signing keys, by what just happened to them and their algorithm: seen, activated, retired."))
	published, _ := meter.Int64Gauge("access_issuer.signing_keys_published",
		metric.WithDescription("Keys currently published in the JWKS by this replica, signing or retiring, by algorithm."))
	activeSince, _ := meter.Int64Gauge("access_issuer.signing_key.active_since_timestamp",
		metric.WithUnit("s"),
		metric.WithDescription("When the active signing key became active, as seconds since the Unix epoch, by algorithm. "+
			"The first replica to see a key decides it, so it is the key's age in the installation, not its certificate's."))
	return keyRingInstruments{transitions: transitions, published: published, activeSince: activeSince}
}

// recordTransition records one key crossing into seen, activated or
// retired. The key id itself is not an attribute: it is unbounded over an
// installation's life and belongs in the log line beside this call, not
// in a metric a collector will keep every value of forever.
func (m keyRingInstruments) recordTransition(ctx context.Context, event, algorithm string) {
	m.transitions.Add(ctx, 1, metric.WithAttributes(
		attribute.String("event", event), attribute.String("algorithm", algorithm)))
}

// recordPublished records how many keys of an algorithm are in the JWKS right
// now. Per algorithm: every ring records, and an unlabelled gauge would be
// whichever ring wrote last.
func (m keyRingInstruments) recordPublished(ctx context.Context, algorithm string, count int64) {
	m.published.Record(ctx, count, metric.WithAttributes(attribute.String("algorithm", algorithm)))
}

// recordActive records when the active key of an algorithm became active.
func (m keyRingInstruments) recordActive(ctx context.Context, algorithm string, since time.Time) {
	m.activeSince.Record(ctx, since.Unix(), metric.WithAttributes(attribute.String("algorithm", algorithm)))
}
