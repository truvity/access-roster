# 0016 — Telemetry is OpenTelemetry used directly, with one log format, W3C trace context, fixed span and metric names, and a generated attribute allowlist

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #1003](https://github.com/truvity/sluis/issues/1003).

## Context

Telemetry is configured only by the standard `OTEL_*` environment variables and exported as OTLP over HTTP with protobuf; the install file has no telemetry keys, and a span or a metric never carries a personal, secret or free-text value ([0004](/decisions/0004-the-data-model/#sensitivities)). An audit record may point at a trace, and the trace never carries what the record says ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format)). Rust actors use a Connect instrumentation crate of sluis's own and OTLP over HTTP/protobuf, with traces still Beta in Rust (spike S6, [0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table)). The prototype of that crate is about 500 lines, against 250 estimated on 2026-10-31, next to a Go kit of about 210 (MEASURED 2026-11-02, spike S6).

What is left is what a developer needs before writing the first actor: whether telemetry goes through a port, what a log line looks like, which spans and metrics every actor and driver emits and under which names, how trace context crosses Unix sockets, and how the allowlist is enforced. Thirty executables in two languages drift apart quickly unless the names are fixed once. v1 emitted OTLP metrics, traces without personal data and logs, with alert rules and a dashboard ([#836](https://github.com/truvity/sluis/issues/836)).

## Decision

### No port

- **Every executable uses the OpenTelemetry SDK of its language directly,** through its kit ([0012](/decisions/0012-the-language-follows-the-executable/#the-rules), R9). Telemetry is not a port and has no driver: an exporter choice is an `OTEL_*` setting, and the collector is the operator's.
- **Telemetry is best effort.** A failed export never fails a request, never blocks the request path and is never the audit channel (REQ-OBS-006). On serverless the kit flushes within a bounded deadline before the runtime freezes (REQ-OBS-004).

### Logs

- **A log line is one JSON object on stderr,** with the field names of the OpenTelemetry log data model: `timestamp`, `severity_text`, `severity_number`, `body`, `attributes`, and `trace_id` and `span_id` when a span is active (REQ-OBS-007). The runtime collects stderr; the OTLP log exporter is optional, set by `OTEL_LOGS_EXPORTER`.
- **`body` is a fixed message chosen in code,** never a formatted value. Values go into `attributes`, and only allowlisted ones.

### Traces

- **W3C Trace Context (`traceparent`, `tracestate`) is the only propagation format,** on every hop: Connect over Unix sockets, Lambda invokes, HTTPS with mutual TLS between nodes and installations (REQ-OBS-002). Baggage is not propagated (MEASURED 2026-11-02, spike S6, Go and Rust in both directions: a `baggage` header sent to the first hop reaches that hop and no further, and `tracestate` still travels).
- **Only internal actors trust a remote parent.** `entry` and every integration that receives a vendor's webhook start a new trace for each request and keep a caller's `traceparent`, if any, as a span link. Internal Go actors use the remote parent; Rust actors do the same through the kit. At an entry, in both languages, the server span has no parent, a new trace id and exactly one link to the caller's client span, and everything behind it is in the new trace (MEASURED 2026-11-02, spike S6).
- **Spans have fixed names:** one server span per RPC, named by the OpenTelemetry RPC conventions (`<package>.<Service>/<Method>`); one client span per call to another actor; one span per driver call, named `<port>.<operation>` (for example `state.cas`, `keys.sign`), with `sluis.driver` naming the driver. A key operation's span records the purpose and the outcome, never the input.
- **Sampling is the operator's,** through `OTEL_TRACES_SAMPLER`. The default is parent-based, always on.

### Metrics

- **Metric names are `sluis.<area>.<thing>`, with units in UCUM as the semantic conventions say,** and the RPC and HTTP metrics take the names of the OpenTelemetry semantic conventions of the pinned SDK version instead, wherever one exists. Every RPC and every driver call has a duration histogram and an outcome count.
- **Named metrics that other records rely on:** `sluis.key.expiry` (seconds until a key's certificate or binding expires, attributes `purpose` and `boundary`; the expiry warnings of [0024](/decisions/0024-root-custody-and-the-signing-api/#lifetimes-and-the-warning)), `sluis.audit.spool.depth` (records waiting in a local spool), and `sluis.directory.staleness` (seconds since the last good read of each upstream directory, [0017](/decisions/0017-identity-and-sign-in/#directory-outages)).
- **Every executable sets the resource attributes** `service.name` (the executable), `service.instance.id` (`<actor>@<boundary>`, [Names](/decisions/0041-core-actors-with-one-responsibility-each/#names)), `service.version` (the release) and `deployment.environment.name` (the environment).

### The allowlist

- **An attribute leaves a process only if it is on the allowlist.** The kit drops every other attribute before export, in spans, metrics and logs alike (REQ-OBS-003).
- **The allowlist is generated** from the sensitivity annotations of the configuration and record schemas, plus the conventions' own attribute names: public and internal identifiers of bounded cardinality may go in, personal, secret and free-text values never (REQ-OBS-008, REQ-OBS-010, REQ-OBS-011).
- **A metric attribute must have bounded cardinality.** A client id or a boundary may label a metric; a subject, a request id or a serial may not, even where a span may carry it.

### Pointing from audit to a trace

- **An audit record carries the W3C trace id in OCSF's `metadata.correlation_uid`,** and nothing from the trace. A trace carries the audit record's `metadata.uid` as `sluis.audit.uid`, so the two can be joined by someone who may read both, and neither repeats the other.

## Consequences

- One log format and fixed names let a dashboard, an alert rule and a support question work on every executable in both languages. The Rust kit carries the conventions in sluis's own instrumentation crate, which must keep pace with the Go SDK; the conformance suite checks both against the same expected spans and metrics.
- **The Rust kit costs more than estimated** (MEASURED 2026-11-02, spike S6; an x86_64 workstation and not a board, one hop pinned to 2 CPUs, 10,000 calls per repetition, median of 5 repetitions, server CPU summed over all threads including the exporters). The server and client spans with the RPC histograms ("RPC only") add **15.0 µs of CPU per call** to a Rust leaf, against the 5.1 µs estimated on 2026-10-31, and the full build of this record (allowlist, log line and OTLP log record, driver span and metrics, gauges) adds **21.8 µs** (10.9 µs without telemetry, 32.7 µs with it). The Go kit adds 10.1 and 16.8 µs on a base of 35.7 µs. Rust with the full build still uses less CPU at a leaf than Go with none. The prototype behind the estimate had no allowlist, no log layer and no driver span, and exported over gRPC. In an ablation (MEASURED, 4 repetitions) about 10 of the 15 µs remain with no OpenTelemetry layer and no metrics; the cause was not profiled and is UNVERIFIED.
- Starting a new trace at `entry` means an outside caller's trace stops at sluis's edge and continues as a link; the operator still sees the whole request inside sluis, and a caller cannot plant trace ids or flood the sampler.
- The allowlist is enforced in the exporter path, so a developer who adds an attribute that is not allowlisted sees it dropped in tests, not leaked in production. The cost is one generated list kept in step with the schemas, which CI checks.
- Bounded metric attributes keep the collector's cost predictable; per-subject or per-request analysis needs traces or the audit log.
- The audit-to-trace join is a correlation id only; deleting traces never weakens the audit log.
- The alert rules and the dashboard of v1 are rebuilt on these names in the parity milestone ([#836](https://github.com/truvity/sluis/issues/836)).
- Requirements: REQ-OBS-001 to REQ-OBS-011 apply as written; [REQ-OBS-012](/requirements/obs/#REQ-OBS-012) to [REQ-OBS-015](/requirements/obs/#REQ-OBS-015) are added.

## Roads not taken

- **A telemetry port with drivers.** It would wrap an SDK that is already pluggable by `OTEL_*`, and add a hop to every span.
- **Plain-text logs, or a log format of sluis's own.** Every collector would need a parser, and the trace id would be in a different place in each executable.
- **Trusting a remote parent at `entry`.** An outside caller could choose trace ids and force sampling on every request it sends.
- **B3 or vendor propagation formats beside W3C Trace Context.** Two formats on one hop double the parsing and the tests; every current SDK speaks W3C.
- **A hand-written allowlist.** It drifts from the schemas the first time a field is added.
- **The audit record id as the trace id, or the trace inside the audit record.** Either makes one store depend on the other's retention and lets a trace say what the audit record says.

## Follow-ups

- Telemetry, health probes, the alert rules and the dashboard for parity: [#836](https://github.com/truvity/sluis/issues/836).
- The expiry warning that uses `sluis.key.expiry`: [#1068](https://github.com/truvity/sluis/issues/1068).
- The Rust kit: where the 15 µs go, a client wrapper or transport that always injects `traceparent` (connect-rust has no client interceptor), OTLP over TLS, and the value of `server.address`: [#861](https://github.com/truvity/sluis/issues/861).
