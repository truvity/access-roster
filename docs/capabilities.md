# Capabilities

What runs where, and how far each piece has got. The target shape is decided in
[decisions/0026](decisions/0026-two-platforms-permanently-kubernetes-and-aws-lambda.md)
to
[0032](decisions/0032-one-configuration-file-one-binary-one-chart.md) and
specified in [design/ports.md](design/ports.md); this page is the status of each
part against it, and is updated in the change that moves a cell.

| Mark | Meaning |
|---|---|
| 📄 | designed: a record or a specification exists, nothing is built |
| 🧪 | built: code exists and is tested, but is not yet released as a supported way to run |
| ✅ | supported: released, documented, and covered by CI |
| — | not applicable on this platform |

Two platforms are supported permanently, so a blank is a gap and not a choice.
A cell reads for the **installation as shipped today**; "today" is the 1.52
series.

## Ports and adapters

| Piece | Kubernetes | AWS Lambda |
|---|---|---|
| State: in-memory (tests, one local process) | ✅ | — |
| State: Kubernetes objects and Valkey (the current store) | ✅ | — |
| State: NATS JetStream KV | 📄 | — |
| State: DynamoDB | — | 📄 |
| Blob: S3 (reports, snapshots) | 📄 | 📄 |
| Trigger: KV watch | 📄 | — |
| Trigger: asynchronous invoke | — | 📄 |
| Sealing: KMS | 📄 | 📄 |
| Sealing: OpenBao Transit | 📄 | — |
| Sealing: mounted key | 📄 | — |
| Inputs: mounted ConfigMaps and Secrets | ✅ | — |
| Inputs: file in the image or a parameter store | — | 📄 |
| Audit sink: `http` | ✅ | — |
| Audit sink: `nats` | 📄 | — |
| Audit sink: `sqs` | — | 📄 |
| Port conformance suite (in-memory, NATS, DynamoDB) | 📄 | 📄 |

## Runtime

| Piece | Kubernetes | AWS Lambda |
|---|---|---|
| Issuer, console and directory hub | ✅ | 📄 |
| GitHub reconciler | ✅ (one replica, no lease) | 📄 |
| Slack reconciler | ✅ (one replica, no lease) | 📄 |
| `Tick(target)` with a lease per target | 📄 | 📄 |
| Two replicas of a reconciler | 📄 | — |
| Slack Connect handoff by pending-share record | 📄 | 📄 |
| HTTP function behind the Lambda Web Adapter and an API Gateway HTTP API | — | 📄 |
| Tick function on EventBridge Scheduler | — | 📄 |
| One binary `access-roster` (`serve`, `tick`, `migrate`) | 📄 | 📄 |
| One chart `access-roster` | 📄 | — |
| One configuration file validated against a schema | 🧪 | 📄 |

## Identity

| Mechanism | Kubernetes | AWS Lambda |
|---|---|---|
| Verify a ServiceAccount token (a cluster declared in the installation) | ✅ | 📄 |
| Verify an AWS outbound-federation token (`sts:GetWebIdentityToken`) | ✅ | ✅ |
| Give the service an AWS identity (annotation or Pod Identity on the ServiceAccount) | ✅ | — |
| The function role's identity to an OTLP endpoint (the extension layer) | — | ✅ |

The federation verifier is the same code on both platforms, so its Lambda cell
is the part of the runtime that is built; the Lambda runtime itself is not.

## Migration and operations

| Piece | Kubernetes | AWS Lambda |
|---|---|---|
| `access-roster migrate --from <adapter> --to <adapter>` | 📄 | 📄 |
| Backup and export through the same command | 📄 | 📄 |
| Copy of Valkey sessions and refresh tokens into the new store | 📄 | — |
| Existing backup: a copy of named Secrets | ✅ | — |

## Telemetry

| Piece | Kubernetes | AWS Lambda |
|---|---|---|
| Metrics over OTLP, configured by `OTEL_*` | ✅ | ✅ |
| Platform logs over OTLP (the extension layer) | — | ✅ |
| Traces (HTTP and Connect spans, trace context across queues) | 📄 | 📄 |
| Chart modes for alerts and dashboards | 📄 | — |
| No personal data in a span or a label | 📄 | 📄 |

Telemetry is configured by the OpenTelemetry environment variables and nothing
else ([0032](decisions/0032-one-configuration-file-one-binary-one-chart.md)); on
Lambda the extension layer sends it with the function role's identity
([integrations/aws-lambda.md](integrations/aws-lambda.md)).
