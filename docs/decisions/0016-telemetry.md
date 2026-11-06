# 0016 — Telemetry is OpenTelemetry with fixed conventions, and a log level is raised at run time only with an expiry

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #1003](https://github.com/truvity/sluis/issues/1003).

## Context

Exporters, endpoints and resources are configured only by the standard `OTEL_*` environment variables and exported as OTLP over HTTP with protobuf; the bootstrap file has no telemetry keys. The log level and the trace sampling of an actor are the one setting that sluis holds for telemetry, and they are a layered kind. A span or a metric never carries a personal, secret or free-text value: the kind registry's treatment decides what may leave ([0004](/decisions/0004-the-data-model/#treatment)). An audit record may point at a trace, and the trace never carries what the record says ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format)). Rust actors use a Connect instrumentation crate of sluis's own and OTLP over HTTP/protobuf, with traces still Beta in Rust (spike S6, [0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table)). The prototype of that crate is about 500 lines, against 250 estimated on 2026-10-31, next to a Go kit of about 210 (MEASURED 2026-11-02, spike S6).

What is left is what a developer needs before writing the first actor: whether telemetry goes through a port, what a log line looks like, which spans and metrics every actor and driver emits and under which names, how trace context crosses Unix sockets, how a log level is raised for a while, and how the allowlist is enforced. Thirty executables in two languages drift apart quickly unless the names are fixed once. v1 emitted OTLP metrics, traces without personal data and logs, with alert rules and a dashboard ([#836](https://github.com/truvity/sluis/issues/836)).

## Decision

### No port

- **Every executable uses the OpenTelemetry SDK of its language directly,** through its kit ([0012](/decisions/0012-the-language-follows-the-executable/#the-rules), R9). Telemetry is not a port and has no driver: an exporter choice is an `OTEL_*` setting, and the collector is the operator's. An actor's audit emit port carries audit facts, never telemetry ([0002](/decisions/0002-families-of-actors/#ports-of-a-work-actor)).
- **Telemetry is best effort.** A failed export never fails a request, never blocks the request path and is never the audit channel (REQ-OBS-006). On serverless the kit flushes within a bounded deadline before the runtime freezes (REQ-OBS-004).

### Logs

- **A log line is one JSON object on stderr,** with the field names of the OpenTelemetry log data model: `timestamp`, `severity_text`, `severity_number`, `body`, `attributes`, and `trace_id` and `span_id` when a span is active (REQ-OBS-007). The runtime collects stderr; the OTLP log exporter is optional, set by `OTEL_LOGS_EXPORTER`.
- **`body` is a fixed message chosen in code,** never a formatted value. Values go into `attributes`, and only allowlisted ones.
- **A string that a caller supplied is logged only after the kit's helper has cleaned it:** one line, no control character and no bidirectional control, at most 256 characters ([REQ-OBS-019](/requirements/obs/#REQ-OBS-019)). A refusal at the authorization or token endpoint logs the error code, a closed reason and the declared client id, never the query, the state, a challenge, a code or a token, and a caller's own mistake is logged below error level ([REQ-OBS-020](/requirements/obs/#REQ-OBS-020), [REQ-OBS-021](/requirements/obs/#REQ-OBS-021), [REQ-OBS-022](/requirements/obs/#REQ-OBS-022)).

### Log levels

- **The log level and the trace sampling of an actor are the layered kind `LogSettings`.** It is a config kind of the boundary, with an id of the form `<actor>[/<module>]`, so a level can be set for one actor and for one module of it. Built-in defaults sit below it. It is never per tenant ([0004](/decisions/0004-the-data-model/#layers-and-the-direction-rule)).
- **A level raised at run time is `LogLevelOverride`,** a temp kind in the operator layer. The console writes it itself ([0002](/decisions/0002-families-of-actors/#the-console)): no actor has domain logic for it, so the store checks its schema and bounds ([0027](/decisions/0027-the-console/#writes)). Raising a level makes the log more permissive than config grants, so the override carries an expiry: 1 hour by default and at most 24 hours ([principle 12](/principles/#12-a-loosening-is-temporary-a-tightening-is-durable)).
- **The unexpired override wins; when it expires the level returns to config,** with no write. Making a level permanent is a change of config, reviewed and signed ([0005](/decisions/0005-the-store/#configuration-loading)).
- **An actor reads and watches its own ids only** ([0005](/decisions/0005-the-store/#rules)). On Lambda nothing is pushed, so a function re-reads with an ETag ([0005](/decisions/0005-the-store/#watch-and-the-resume-point)).
- **Every raise is authorised for a named person and audited** ([0002](/decisions/0002-families-of-actors/#the-console)).

### Traces

- **W3C Trace Context (`traceparent`, `tracestate`) is the only propagation format,** on every hop: Connect over Unix sockets, Lambda invokes, in-cluster calls, HTTPS with mutual TLS between nodes and installations (REQ-OBS-002). Baggage is not propagated (MEASURED 2026-11-02, spike S6, Go and Rust in both directions: a `baggage` header sent to the first hop reaches that hop and no further, and `tracestate` still travels).
- **Only internal actors trust a remote parent.** `entry` starts a new trace for each request, a vendor's webhook to an adapter included, and keeps a caller's `traceparent`, if any, as a span link. Internal Go actors use the remote parent; Rust actors do the same through the kit. At `entry`, in both languages, the server span has no parent, a new trace id and exactly one link to the caller's client span, and everything behind it is in the new trace (MEASURED 2026-11-02, spike S6).
- **Spans have fixed names:** one server span per RPC, named by the OpenTelemetry RPC conventions (`<package>.<Service>/<Method>`); one client span per call to another actor; one span per call through a port, named `<port>.<operation>` (for example `data.write` on a work actor's data port, `keys.seal` on its keys port, `durable.transact` on store@'s port to its engine), with `sluis.driver` naming the driver when the call goes to one. A key operation's span records the purpose and the outcome, never the input.
- **Sampling is parent-based and always on by default,** and the ratio for an actor or a module comes from `LogSettings`.

### Metrics

- **Metric names are `sluis.<area>.<thing>`, with units in UCUM as the semantic conventions say,** and the RPC and HTTP metrics take the names of the OpenTelemetry semantic conventions of the pinned SDK version instead, wherever one exists. Every RPC and every call through a port has a duration histogram and an outcome count.
- **Named metrics that other records rely on:** `sluis.key.expiry` (seconds until a key's certificate or binding expires, attributes `purpose` and `boundary`; the expiry warnings of [0024](/decisions/0024-root-custody-and-the-signing-api/#lifetimes-and-the-warning)), `sluis.audit.spool.depth` (records waiting in a local spool), and `sluis.directory.staleness` (seconds since the last good read of each upstream directory, [0017](/decisions/0017-identity-and-sign-in/#directory-outages)).
- **Every executable sets the resource attributes** `service.name` (the executable), `service.instance.id` (`<actor>@<boundary>`, [Names](/decisions/0002-families-of-actors/#names)), `service.version` (the release) and `deployment.environment.name` (the environment).

### Gauges, counters and the alerts that read them

These rules come from v1, whose alert rules paged falsely for a day at a time until each of them was learned (v1 on `master`, 2026-10-25 to 2026-11-04). No metric is emitted yet, so they are decided before the first one is.

- **An instance is not a process.** `service.instance.id` is `<actor>@<boundary>`, so on serverless every warm environment of a function exports a gauge with identical attributes, and the backend shows the series of whichever environment reported last. No alert reads the last value of a gauge that several instances export ([REQ-OBS-025](/requirements/obs/#REQ-OBS-025)).
- **Each named gauge says how its series combine.** `sluis.key.expiry` is read as the minimum over instances, the soonest expiry. `sluis.audit.spool.depth` is the sum for the total waiting, and an alert on a single spool reads the maximum. `sluis.directory.staleness` is shown as the maximum and drives no alert: its alert reads the counter below.
- **The freshness of a periodic job comes from a counter.** Every periodic job (a reconciler target, a directory refresh, a sweep) adds to the counter `sluis.job.ticks` for each pass, with the attributes `job` (bounded) and `outcome` (`ok` or `failed`). The age of a job is the time since the last increase with `outcome=ok`. Counters from many instances add up and none overwrites another.
- **A counter that an alert reads exists at zero before its first event.** The kit adds zero to a counter when its scope first exists, for a new kind, target or vendor, because a series that starts at its first event makes `increase` miss that event and leaves a panel with no data ([REQ-OBS-024](/requirements/obs/#REQ-OBS-024)).
- **A stall and a stopped series are two alerts.** A job is live while a sample of its series arrived within the live window. A live job with no `ok` increase for `maxAge` is a critical alert ([REQ-OBS-027](/requirements/obs/#REQ-OBS-027)). A series seen within the look-back and silent for the live window is a warning that clears when the look-back passes, so a renamed or removed job does not page for a day ([REQ-OBS-028](/requirements/obs/#REQ-OBS-028)). A job that is gone for good leaves only silence, which an `absent` rule sees ([REQ-OBS-029](/requirements/obs/#REQ-OBS-029)). The starting values are v1's: a live window of 15 minutes, `maxAge` of four default intervals (1 hour) and a look-back of 2 hours. They are design figures taken from v1, not measured on v2.
- **A failure alert counts failures only.** The outcome of a port call is one of `ok`, `conflict`, `not_found` or `error`; the first three are ordinary and the failure share counts `error` alone ([REQ-OBS-026](/requirements/obs/#REQ-OBS-026)).
- **A label is for operators.** No behaviour, such as a maintenance freeze or an authorization, depends on a route name or any other metric label. v1 had a freeze keyed on a route name that the code named differently from its alert.
- **Vendor calls have their own spans and their own latency class.** An adapter or driver that calls a vendor records a span for each API method and a child span for each attempt, with no account, token or URL in it ([REQ-OBS-032](/requirements/obs/#REQ-OBS-032), [REQ-OBS-033](/requirements/obs/#REQ-OBS-033)). An exchange that mints at a vendor waits for seconds, so it has an alert of its own and the token endpoint alert leaves it out ([REQ-OBS-034](/requirements/obs/#REQ-OBS-034)); a duration histogram has a bucket above the longest vendor call it waits for ([REQ-OBS-035](/requirements/obs/#REQ-OBS-035)).
- **Rules are tested like code.** Each alert rule has rule tests for a firing case, a quiet case and the regression of its last change, and every label value a rule selects is one the code emits ([REQ-OBS-030](/requirements/obs/#REQ-OBS-030), [REQ-OBS-023](/requirements/obs/#REQ-OBS-023)).

### The allowlist

- **An attribute leaves a process only if it is on the allowlist.** The kit drops every other attribute before export, in spans, metrics and logs alike (REQ-OBS-003).
- **The allowlist is generated** from the kind registry and the contracts, plus the conventions' own attribute names: a field of bounded cardinality that is neither secret nor personal may go in; a sealed or hashed value, a personal value and free text never (REQ-OBS-008, REQ-OBS-010, REQ-OBS-011).
- **A metric attribute must have bounded cardinality.** A client id or a boundary may label a metric; a subject, a request id or a serial may not, even where a span may carry it.

### Pointing from audit to a trace

- **An audit record carries the W3C trace id in OCSF's `metadata.correlation_uid`,** and nothing from the trace. A trace carries the audit record's `metadata.uid` as `sluis.audit.uid`, so the two can be joined by someone who may read both, and neither repeats the other.

## Consequences

- One log format and fixed names let a dashboard, an alert rule and a support question work on every executable in both languages. The Rust kit carries the conventions in sluis's own instrumentation crate, which must keep pace with the Go SDK; the conformance suite checks both against the same expected spans and metrics.
- **The Rust kit costs more than estimated** (MEASURED 2026-11-02, spike S6; an x86_64 workstation and not a board, one hop pinned to 2 CPUs, 10,000 calls per repetition, median of 5 repetitions, server CPU summed over all threads including the exporters). The server and client spans with the RPC histograms ("RPC only") add **15.0 µs of CPU per call** to a Rust leaf, against the 5.1 µs estimated on 2026-10-31, and the full build of this record (allowlist, log line and OTLP log record, port span and metrics, gauges) adds **21.8 µs** (10.9 µs without telemetry, 32.7 µs with it). The Go kit adds 10.1 and 16.8 µs on a base of 35.7 µs. Rust with the full build still uses less CPU at a leaf than Go with none. The prototype behind the estimate had no allowlist, no log layer and no port span, and exported over gRPC. In an ablation (MEASURED, 4 repetitions) about 10 of the 15 µs remain with no OpenTelemetry layer and no metrics; the cause was not profiled and is UNVERIFIED.
- Every data access crosses store@ and every seal or open crosses key@, so a request has a span for each hop. The two holders are the first place to look when a request is slow, and their histograms are the input to the capacity measurements ([0037](/decisions/0037-capacity-is-measured-before-it-is-promised/)).
- Starting a new trace at `entry` means an outside caller's trace stops at sluis's edge and continues as a link; the operator still sees the whole request inside sluis, and a caller cannot plant trace ids or flood the sampler.
- A raised log level costs log volume for at most a day and then ends by itself. An operator who forgets to lower it does not leave debug logging, which can carry more detail than normal, running.
- The allowlist is enforced in the exporter path, so a developer who adds an attribute that is not allowlisted sees it dropped in tests, not leaked in production. The cost is one generated list kept in step with the registry, which CI checks.
- Bounded metric attributes keep the collector's cost predictable; per-subject or per-request analysis needs traces or the audit log.
- The audit-to-trace join is a correlation id only; deleting traces never weakens the audit log.
- The alert rules and the dashboard of v1 are rebuilt on these names in the parity milestone ([#836](https://github.com/truvity/sluis/issues/836)), with the rules above as their shape.
- A job's age needs a counter and a gauge is only shown, so each periodic job adds one counter series per outcome. The cost is bounded by the number of jobs.
- The dashboards show cold starts and the initialisation time of each function from the platform's report events, because no metric carries them ([REQ-OBS-031](/requirements/obs/#REQ-OBS-031)).
- Requirements: REQ-OBS-001 to REQ-OBS-011 apply as written; [REQ-OBS-012](/requirements/obs/#REQ-OBS-012) to [REQ-OBS-015](/requirements/obs/#REQ-OBS-015) are added, and [REQ-OBS-019](/requirements/obs/#REQ-OBS-019) to [REQ-OBS-035](/requirements/obs/#REQ-OBS-035) carry the log hygiene, the alert rules and the vendor-call rules above.

## Roads not taken

- **A telemetry port with drivers.** It would wrap an SDK that is already pluggable by `OTEL_*`, and add a hop to every span.
- **Plain-text logs, or a log format of sluis's own.** Every collector would need a parser, and the trace id would be in a different place in each executable.
- **Trusting a remote parent at `entry`.** An outside caller could choose trace ids and force sampling on every request it sends.
- **B3 or vendor propagation formats beside W3C Trace Context.** Two formats on one hop double the parsing and the tests; every current SDK speaks W3C.
- **A hand-written allowlist.** It drifts from the registry the first time a field is added.
- **The audit record id as the trace id, or the trace inside the audit record.** Either makes one store depend on the other's retention and lets a trace say what the audit record says.
- **A log level raised with no expiry.** A forgotten debug level would stay on, and nothing would tell an operator that the log is more detailed than config says.
- **Alert on the age of a gauge that every instance exports.** It is v1's first shape: on serverless the series flips between instances, and a healthy job paged because one old environment reported last.
- **Create a counter at its first event.** `increase` over a series that starts at 1 misses the first event, and a panel reads no data until it happens.
- **Look back a day for a stopped series, and page critical for it.** A renamed or removed target then paged for up to a day; a stall and a stopped series are two alerts.
- **A log level per tenant.** The layers of the Logging group are built-in, config and the operator's override, set per boundary, actor and module; none carries a tenant ([0004](/decisions/0004-the-data-model/#layers-and-the-direction-rule)).

## Follow-ups

- Telemetry, health probes, the alert rules and the dashboard for parity: [#836](https://github.com/truvity/sluis/issues/836).
- The expiry warning that uses `sluis.key.expiry`: [#1068](https://github.com/truvity/sluis/issues/1068).
- The Rust kit: where the 15 µs go, a client wrapper or transport that always injects `traceparent` (connect-rust has no client interceptor), OTLP over TLS, and the value of `server.address`: [#861](https://github.com/truvity/sluis/issues/861).
