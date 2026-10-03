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
A cell reads for the **installation as shipped today**; "today" is the 1.53
series.

## Ports and adapters

| Piece | Kubernetes | AWS Lambda |
|---|---|---|
| State: in-memory (tests, one local process) | ✅ | — |
| State, Blob, Trigger, Sealing, Identity: the ports' in-memory adapter (`internal/port/memory`) | 🧪 | — |
| State: Kubernetes objects and Valkey (the current store) | ✅ | — |
| State: the ports' `legacy` adapter over that store (temporary, until the migration of [0031](decisions/0031-a-generic-migration-tool.md) has run) | 🧪 | — |
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
| Ports as Go interfaces (`internal/port`) and the apps depending on them | 🧪 | 📄 |
| Port conformance suite: in-memory and legacy | 🧪 | — |
| Port conformance suite: NATS, DynamoDB | 📄 | 📄 |

## Runtime

| Piece | Kubernetes | AWS Lambda |
|---|---|---|
| Issuer, console and directory hub | ✅ | 📄 |
| GitHub reconciler | ✅ (one replica) | 📄 |
| Slack reconciler | ✅ (one replica) | 📄 |
| `Tick(target)` with a lease per target, a report per target, and a trigger that ticks only its target (on the legacy adapter: the lease is exclusive across pods only with a shared State, and a controller has none; the console reaches a controller through the mounted records, polled) | 🧪 | 📄 |
| Two replicas of a reconciler | 📄 (needs the NATS State) | — |
| Slack Connect handoff: the host's tick notifies the guest's; the guest-side probe is the host's tick's | 🧪 | 📄 |
| Slack Connect handoff by pending-share record | 📄 | 📄 |
| HTTP function behind the Lambda Web Adapter and an API Gateway HTTP API | — | 📄 |
| Tick function on EventBridge Scheduler | — | 📄 |
| One binary `access-roster` (`serve`, `controller github`, `controller slack`; `tick <github|slack> <target>` runs one tick once; `migrate` is a stub) | 🧪 | 📄 |
| One chart `access-roster` (`serve`, `controller-github`, `controller-slack`) | 🧪 | — |
| One configuration file validated against a schema (per subcommand) | 🧪 | 📄 |

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
