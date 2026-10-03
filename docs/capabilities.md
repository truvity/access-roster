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
A cell reads for the **installation as shipped today**; "today" is the 1.52.4
release and what has landed since.

## Ports and adapters

| Piece | Kubernetes | AWS Lambda |
|---|---|---|
| State: in-memory (tests, one local process) | ✅ | — |
| State, Blob, Trigger, Sealing, Identity: the ports' in-memory adapter (`internal/port/memory`) | 🧪 | — |
| State: Kubernetes objects and Valkey (the current store) | ✅ | — |
| State: the ports' `legacy` adapter over that store (temporary, until the migration of [0031](decisions/0031-a-generic-migration-tool.md) has run) | 🧪 | — |
| State, session index and Trigger: NATS JetStream KV (`internal/port/nats`, `ports.adapter: nats`; per-key TTL needs nats-server 2.11 or later) | 🧪 | — |
| Domain stores on the ports: workspaces and credentials, GitHub organisations and Apps, a person's GitHub link (one item, token pair sealed, compare-and-swap refresh), runner and catalogue Apps, the Slack records, the console's session key (`internal/portstore`; any `ports.adapter` but `legacy`, which needs a Sealer) | 🧪 | 📄 |
| State: DynamoDB | — | 📄 |
| Blob: S3 (reports, snapshots; `internal/port/s3blob`, `ports.blob`) | 🧪 | 🧪 |
| Trigger: KV watch (across processes) | 🧪 | — |
| Trigger: asynchronous invoke | — | 📄 |
| Sealing: KMS (`internal/port/kmsseal`, `ports.sealer`) | 🧪 | 🧪 |
| Sealing: OpenBao Transit | 📄 | — |
| Sealing: mounted key | 📄 | — |
| Inputs: mounted ConfigMaps and Secrets | ✅ | — |
| Inputs: file in the image or a parameter store | — | 📄 |
| Audit sink: `http` | ✅ | — |
| Audit sink: `nats` | 📄 | — |
| Audit sink: `sqs` | — | 📄 |
| Ports as Go interfaces (`internal/port`) and the apps depending on them | 🧪 | 📄 |
| Port conformance suite: in-memory and legacy | 🧪 | — |
| Port conformance suite: NATS (embedded nats-server, one node and a three-node cluster) | 🧪 | — |
| Port conformance suite: DynamoDB | — | 📄 |

## Runtime

| Piece | Kubernetes | AWS Lambda |
|---|---|---|
| Issuer, console and directory hub | ✅ | 📄 |
| GitHub reconciler | ✅ (one replica) | 📄 |
| Slack reconciler | ✅ (one replica) | 📄 |
| `Tick(target)` with a lease per target, a report per target, and a trigger that ticks only its target (on the legacy adapter: the lease is exclusive across pods only with a shared State, and a controller has none; the console reaches a controller through the mounted records, polled) | 🧪 | 📄 |
| Two replicas of a reconciler | 📄 (needs the NATS State) | — |
| Slack Connect handoff: the host's tick notifies the guest's; the guest-side probe is the host's tick's | 🧪 | 📄 |
| Slack Connect handoff by pending-share record (`share.<host>.<channel>`: 14 days while pending, 7 days once accepted; needs a State both runners share) | 🧪 | 📄 |
| Slack `users.info` cache on the State (`cache.slack.user.<workspace>.<id>`, 24 h; `slack_roster.user_cache` counts hits and misses) | 🧪 | 📄 |
| Shared inputs of the Slack controller in the State (`cache.<digest>.<name>`) | 📄 (stays in memory) | 📄 |
| Controllers reading the console's records from the State instead of mounted files (`ports.adapter` other than `legacy`) | 🧪 | 📄 |
| HTTP function behind the Lambda Web Adapter and an API Gateway HTTP API | — | 📄 |
| Tick function on EventBridge Scheduler | — | 📄 |
| One binary `access-roster` (`serve`, `controller github`, `controller slack`; `tick <github|slack> <target>` runs one tick once; `migrate --from <config> --to <config>` copies the State between storages) | 🧪 | 📄 |
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
| `access-roster migrate --from <config> --to <config>`: every domain store through its business interface, with `--dry-run`, create-if-absent and `--overwrite`, a plan before any write, and a read-back verification reported as JSON ([operations/migrate.md](operations/migrate.md)) | 🧪 | 📄 |
| Backup and export through the same command (a file as one end) | 📄 (a follow-up: there is no file adapter yet) | 📄 |
| Copy of Valkey sessions, refresh tokens and the keyring schedule into the new store, each with its remaining lifetime | 🧪 | — |
| Rollback by the same command in the other direction (`--from nats --to legacy`) | 🧪 | — |
| Existing backup: a copy of named Secrets | ✅ | — |

## Telemetry

| Piece | Kubernetes | AWS Lambda |
|---|---|---|
| Metrics over OTLP, configured by `OTEL_*` | ✅ | ✅ |
| Platform logs over OTLP (the extension layer) | — | ✅ |
| Traces: HTTP and Connect spans, a span per tick and per port call, the trace continued into the console (trace context across queues waits for the queues) | 🧪 | 📄 |
| Metrics: the issuer's requests, tokens, sign-ins and keys; ticks and leases; port calls; rate limits ([operations/telemetry.md](operations/telemetry.md)) | 🧪 | 📄 |
| Chart modes `renders: alerts` and `renders: dashboards`: ten rules, unit-tested with `vmalert-tool`, and a dashboard held to `dashboardlint` | 🧪 | — |
| No personal data in a span: an allowlist exporter, tested by planting markers; no person or group in a label | 🧪 | 📄 |

Telemetry is configured by the OpenTelemetry environment variables and nothing
else ([0032](decisions/0032-one-configuration-file-one-binary-one-chart.md)); the
signals, the alerts and how to install them are in
[operations/telemetry.md](operations/telemetry.md). On
Lambda the extension layer sends it with the function role's identity
([integrations/aws-lambda.md](integrations/aws-lambda.md)).
