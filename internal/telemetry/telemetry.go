// Package telemetry is the OpenTelemetry metrics both processes publish.
//
// Push, over OTLP, and only when a collector is named. Neither process
// grows a listener for it: the GitHub controller holds App keys and must
// not have a port, and the service's ports are the issuer's. Where nothing
// names a collector, nothing is exported and every instrument records into
// a no-op — metrics cost nothing where nobody collects them.
//
// Configuration is OpenTelemetry's own environment, read by its SDK:
// OTEL_EXPORTER_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_METRICS_ENDPOINT and
// OTEL_EXPORTER_OTLP_TRACES_ENDPOINT), OTEL_EXPORTER_OTLP_HEADERS,
// OTEL_METRIC_EXPORT_INTERVAL, OTEL_TRACES_SAMPLER, OTEL_TRACES_SAMPLER_ARG,
// OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES. Nothing here restates it.
//
// Traces carry no personal data, and this package enforces that rather than
// hoping: see [FilterExporter].
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/truvity/access-roster/internal/version"
)

// Enabled reports whether a collector is named in the environment for metrics.
func Enabled() bool {
	return named("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
}

// TracesEnabled reports whether a collector is named for traces: the same rule
// as for metrics, with the traces-specific variable. Unset means nothing is
// exported and the tracer is the API's no-op, which costs nothing.
func TracesEnabled() bool {
	return named("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
}

func named(vars ...string) bool {
	for _, name := range vars {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return true
		}
	}
	return false
}

// defaultSampler is the sampler used when OTEL_TRACES_SAMPLER names none:
// parent based, so a caller's decision always wins, and every root trace kept
// (always_on). This is the ONE place to change the default: truvity/audit keeps
// a tenth (ParentBased(TraceIDRatioBased(0.1))), and which of the two this
// service should use is a pending decision. Setting OTEL_TRACES_SAMPLER (and
// OTEL_TRACES_SAMPLER_ARG) on the pods overrides it without a release.
func defaultSampler() sdktrace.Sampler {
	return sdktrace.ParentBased(sdktrace.AlwaysSample())
}

// Start installs the global meter provider when a collector is named for
// metrics, and the global tracer provider (with the W3C trace-context
// propagator) when one is named for traces, and returns what flushes and stops
// them. Without a collector it installs nothing and the returned function does
// nothing.
func Start(ctx context.Context, service string, log *slog.Logger) (func(context.Context) error, error) {
	if !Enabled() && !TracesEnabled() {
		return func(context.Context) error { return nil }, nil
	}
	attributes := []attribute.KeyValue{attribute.String("service.version", version.Version)}
	if strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")) == "" {
		attributes = append(attributes, attribute.String("service.name", service))
	}
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(attributes...))
	if err != nil {
		return nil, fmt.Errorf("telemetry: the resource: %w", err)
	}
	var stops []func(context.Context) error
	if Enabled() {
		exporter, err := otlpmetrichttp.New(ctx)
		if err != nil {
			return nil, fmt.Errorf("telemetry: an OTLP exporter: %w", err)
		}
		provider := sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(res),
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
		)
		otel.SetMeterProvider(provider)
		stops = append(stops, provider.Shutdown)
		log.InfoContext(ctx, "publishing metrics over OTLP", "service", service)
	}
	if TracesEnabled() {
		exporter, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, fmt.Errorf("telemetry: a trace exporter: %w", err)
		}
		opts := []sdktrace.TracerProviderOption{
			sdktrace.WithResource(res),
			sdktrace.WithBatcher(FilterExporter(exporter)),
		}
		if strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER")) == "" {
			opts = append(opts, sdktrace.WithSampler(defaultSampler()))
		} // else the SDK reads OTEL_TRACES_SAMPLER and OTEL_TRACES_SAMPLER_ARG itself.
		provider := sdktrace.NewTracerProvider(opts...)
		otel.SetTracerProvider(provider)
		otel.SetTextMapPropagator(propagation.TraceContext{})
		stops = append(stops, provider.Shutdown)
		log.InfoContext(ctx, "publishing traces over OTLP", "service", service)
	}
	return func(ctx context.Context) error {
		var errs []error
		for _, stop := range stops {
			errs = append(errs, stop(ctx))
		}
		return errors.Join(errs...)
	}, nil
}
