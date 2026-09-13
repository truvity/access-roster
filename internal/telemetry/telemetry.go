// Package telemetry is the OpenTelemetry metrics both processes publish.
//
// Push, over OTLP, and only when a collector is named. Neither process
// grows a listener for it: the GitHub controller holds App keys and must
// not have a port, and the service's ports are the issuer's. Where nothing
// names a collector, nothing is exported and every instrument records into
// a no-op — metrics cost nothing where nobody collects them.
//
// Configuration is OpenTelemetry's own environment, read by its SDK:
// OTEL_EXPORTER_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_METRICS_ENDPOINT),
// OTEL_EXPORTER_OTLP_HEADERS, OTEL_METRIC_EXPORT_INTERVAL,
// OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES. Nothing here restates it.
package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/truvity/access-roster/internal/version"
)

// Enabled reports whether a collector is named in the environment.
func Enabled() bool {
	for _, name := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"} {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return true
		}
	}
	return false
}

// Start installs the global meter provider when a collector is named, and
// returns what flushes and stops it. Without one it installs nothing and
// the returned function does nothing.
func Start(ctx context.Context, service string, log *slog.Logger) (func(context.Context) error, error) {
	if !Enabled() {
		return func(context.Context) error { return nil }, nil
	}
	exporter, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("telemetry: an OTLP exporter: %w", err)
	}
	attributes := []attribute.KeyValue{attribute.String("service.version", version.Version)}
	if strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")) == "" {
		attributes = append(attributes, attribute.String("service.name", service))
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(attributes...))
	if err != nil {
		return nil, fmt.Errorf("telemetry: the resource: %w", err)
	}
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
	)
	otel.SetMeterProvider(provider)
	log.InfoContext(ctx, "publishing metrics over OTLP", "service", service)
	return provider.Shutdown, nil
}
