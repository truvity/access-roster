module github.com/truvity/sluis/audit

go 1.27.0

toolchain go1.27.3

require (
	connectrpc.com/connect/v2 v2.0.1
	github.com/aws/aws-lambda-go v1.55.1
	github.com/aws/aws-sdk-go-v2 v1.47.3
	github.com/aws/aws-sdk-go-v2/config v1.33.9
	github.com/aws/aws-sdk-go-v2/credentials v1.20.9
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.72.0
	github.com/aws/aws-sdk-go-v2/service/kms v1.61.5
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.3
	github.com/aws/aws-sdk-go-v2/service/sqs v1.52.5
	github.com/aws/aws-sdk-go-v2/service/ssm v1.80.0
	github.com/aws/smithy-go v1.28.5
	github.com/google/go-cmp v0.7.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.11.0
	github.com/klauspost/compress v1.20.3
	github.com/lestrrat-go/jwx/v4 v4.5.0
	github.com/nats-io/nats-server/v2 v2.15.1
	github.com/nats-io/nats.go v1.54.0
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	github.com/truvity/cnpg/v2 v2.38.0
	github.com/truvity/gateway-auth v0.7.1
	github.com/truvity/gemaal v0.26.5
	github.com/truvity/policy v1.55.0
	github.com/truvity/sluis/audit/sdk v1.80.3
	github.com/truvity/sluis/storage v1.80.3
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.72.0
	go.opentelemetry.io/otel v1.47.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.47.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.47.0
	go.opentelemetry.io/otel/metric v1.47.0
	go.opentelemetry.io/otel/sdk v1.47.0
	go.opentelemetry.io/otel/sdk/metric v1.47.0
	go.opentelemetry.io/otel/trace v1.47.0
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/sync v0.24.0
	google.golang.org/protobuf v1.36.12
	sigs.k8s.io/yaml v1.6.0
)

require (
	connectrpc.com/connect v1.21.1 // indirect
	connectrpc.com/otelconnect v0.12.0 // indirect
	github.com/antithesishq/antithesis-sdk-go v0.8.0-default-no-op // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.22 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/ecr v1.66.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.4 // indirect
	github.com/aws/smithy-go/metrics/smithyotelmetrics v1.0.33 // indirect
	github.com/aws/smithy-go/tracing/smithyoteltracing v1.0.33 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.31.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/option/v3 v3.0.0-alpha1 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/nats-io/jwt/v2 v2.8.2 // indirect
	github.com/nats-io/nkeys v0.4.16 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/truvity/ocictl v0.12.0 // indirect
	github.com/urfave/cli/v3 v3.14.0 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.1 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261019180522-ce908d29299b // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261019180522-ce908d29299b // indirect
	google.golang.org/grpc v1.84.0 // indirect
	oras.land/oras-go/v2 v2.6.2 // indirect
)

tool (
	connectrpc.com/connect/v2/cmd/protoc-gen-connect-go
	github.com/truvity/ocictl/cmd/helmctl
)

// The SDK is a module of its own, in this checkout beside the root: the
// emitter packages an application imports must not drag the writer's
// dependencies in with them (just audit-sdk-closure holds that). A consumer of
// this module does not get the replace, so the require above is what they build
// against; the release workflow pins it to the release being cut and it is never
// bumped by hand.
replace github.com/truvity/sluis/audit/sdk => ./sdk

// The storage port (state and keys by purpose) is a module of its own, beside
// this one in the checkout, and imports nothing of sluis (internal/independence
// holds that). The same holds for it: a consumer's build uses the require above,
// which the release workflow pins to the release being cut.
replace github.com/truvity/sluis/storage => ../storage
