# Telemetry

What access-roster publishes, what it never publishes, the alerts and the
dashboard that read it, and how to install them. The contract it follows is
[0026](../decisions/0026-two-platforms-permanently-kubernetes-and-aws-lambda.md)
to
[0032](../decisions/0032-one-configuration-file-one-binary-one-chart.md) and
[design/ports.md](../design/ports.md): telemetry is the OpenTelemetry
environment and nothing else, it is exported only when a collector is named, and
it carries no personal data.

## Configuration

There is none in the configuration file. The platform sets the OpenTelemetry
variables on the pods and the SDK reads them:

| Variable | Effect |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Names a collector for metrics and traces. Unset (and neither signal's own variable below set), nothing is exported and every instrument records into a no-op. |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | The same, for one signal. |
| `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_METRIC_EXPORT_INTERVAL`, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` | The SDK's own. The service names itself `access-issuer`, `github-roster` or `slack-roster` when `OTEL_SERVICE_NAME` is unset, so a dashboard that selected on those still finds the process. |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | The sampler. **Unset, it is parent based with `always_on`**: a caller's decision wins and every root trace is kept. |

**The sampler default is provisional.** truvity/audit keeps a tenth of root
traces (`parentbased_traceidratio` at 0.1) because its write path is frequent and
repetitive. This service's traffic is a sign-in and a tick per interval, which a
trace store can hold whole, so the default here is `always_on`. Which of the two
this service should ship is not decided. It is one function
(`defaultSampler` in `internal/telemetry/telemetry.go`), and
`OTEL_TRACES_SAMPLER=parentbased_traceidratio` with `OTEL_TRACES_SAMPLER_ARG=0.1`
on the pods gives audit's behaviour without a release.

## Wiring it with the chart

The chart sets those variables on every pod of `renders: app` from one value
block, so an installation does not hand-write them into each Deployment:

```yaml
telemetry:
  otlp:
    endpoint: http://<gateway>.<namespace>.svc:4318   # empty: no export, nothing rendered
    protocol: http/protobuf                            # the default
    extraEnv: {}                                       # any other OTEL_* variable
```

With `endpoint` set, the service and each controller get
`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL`, an
`OTEL_SERVICE_NAME` of their own, and the `extraEnv` entries:

| Pod | `OTEL_SERVICE_NAME` |
|---|---|
| `serve` | `access-issuer` |
| `controller github` | `github-roster` |
| `controller slack` | `slack-roster` |

These are the names the binary uses when the variable is unset, so a dashboard
or alert that selects on them keeps finding the process. With `endpoint` empty
the chart renders nothing and the pods export nothing
([policy ADR 0006](https://github.com/truvity/policy/blob/master/docs/decisions/0006-telemetry-is-the-sdk-environment.md)).

An installation on a cluster with the estate's metrics gateway, and a trace
sampler of a tenth of root traces:

```yaml
telemetry:
  otlp:
    endpoint: http://otlp-gateway.observability.svc:4318
    extraEnv:
      OTEL_TRACES_SAMPLER: parentbased_traceidratio
      OTEL_TRACES_SAMPLER_ARG: "0.1"
```

The estate's convention is `http://<gateway>:4318` over `http/protobuf`; the
cluster, namespace and tier become labels at the gateway, so none is set here
(see truvity/observability `docs/emitting.md`). The chart refuses an endpoint
that is not an http(s) URL, an `extraEnv` name that does not start with `OTEL_`,
and `OTEL_EXPORTER_OTLP_ENDPOINT` in `extraEnv`, which belongs in `endpoint`.
Anything secret (`OTEL_EXPORTER_OTLP_HEADERS` with a token) is not for
`extraEnv`, which is rendered as plain values: put it in a Secret and reach the
pod through `secretEnv`. The `renders: alerts` and `renders: dashboards` modes
ignore the block.

## Traces

A tracer exists only when a collector is named for traces.

| Where | Span |
|---|---|
| The issuer's listener (everything on the public port, the console included) | A server span per request, **named for the route** (`POST token`, `GET login_callback`) and never for the path. The route is one of a fixed set (`issuer.Route`): `discovery`, `jwks`, `authorize`, `authorize_callback`, `token`, `userinfo`, `introspect`, `revoke`, `end_session`, `device_authorization`, `login_chooser`, `login_start`, `login_callback`, `login_recovery`, `logout`, `signed_out`, `account`, `grants`, `sessions_rpc`, `connect_callback`, `console_assets`, `console_rpc`, `console`, `other`. The caller's `traceparent` is continued. |
| The console's and the session service's Connect handlers | A server span per call (`rpc.method`). |
| The controllers' clients of the console | A client span per call, and the `traceparent` carried to the console, so a tick's trace continues into the console's own spans. |
| A tick | `tick <kind>`, with the target kind, the target and the outcome (`ok` or `failed`). The kinds are `github-tick`, `github-links` and `slack-tick`. |
| A storage port call | `port <port> <operation>`, with the port, the operation and the outcome. Only inside a trace that is already being recorded, so a loop that started none makes no root span per call. |

### What leaves the process

Spans are read by everyone with a grant on the trace store, so the rule that
they hold no personal data is a property of the exporter and not a promise by
each call site. Every span leaves through an allowlist exporter
(`telemetry.FilterExporter`, the one truvity/audit uses):

- **Attributes.** Only the names in `telemetry.SpanAttributeAllowlist` survive:
  `access_roster.target.kind`, `access_roster.target.id`, `access_roster.outcome`,
  `access_roster.port`, `access_roster.operation`, `rpc.system.name`,
  `rpc.method`, `rpc.response.status_code`, `error.type`,
  `http.request.method`, `http.response.status_code` and `http.route`. The HTTP
  and RPC instrumentation record the client's address, the user agent, the raw
  URL path and the peer; they are dropped, whoever set them.
- **Events, links' attributes and the status text** are removed outright: a
  recorded error's message is free text and may quote an address or a group.
- **The key of a port call is never an attribute or a label.** A key names a
  person (`ses.<person>.`) or a target.

The one identifier a span may carry is the target's own name, a GitHub
organisation or a Slack workspace the policy declares. Never an email, a
subject, a group name, a token or its hash, or an address.

`internal/telemetry` has a test that plants those markers in attributes, events,
errors, status text and links, and in a real HTTP request and a real Connect
call, and asserts that none of them reaches the next exporter.

## Metrics

The names below are the OpenTelemetry names; the Prometheus names are what the
metrics gateway makes of them: dots to underscores, `_total` on a counter, the
unit as a suffix (`access_issuer.http.requests` is
`access_issuer_http_requests_total`). Only the cluster, the namespace and the
tier become labels from the resource; every label below is a metric attribute.

### The issuer

| Metric | Type | Labels | What it says |
|---|---|---|---|
| `access_issuer.http.requests` | counter | `route`, `status_class` | Requests the listener answered. `status_class` is `2xx` to `5xx`. |
| `access_issuer.http.request.duration` | histogram, `s` | `route`, `status_class` | Time from a request's arrival to the handler returning. |
| `access_issuer.tokens.issued` | counter | `client_id`, `grant_type` | Access tokens signed. `grant_type` is `authorization_code`, `refresh_token`, `token_exchange`, `client_credentials` or `console_mint`. |
| `access_issuer.login.failures` | counter | `reason` | Sign-ins that did not complete. |
| `access_issuer.login.successes` | counter | `method` | Sign-ins that completed: a directory's kind, `recovery` or `browser_session`. |
| `access_issuer.reuse_detected` | counter | `kind` | A spent credential presented again: `authorization_code` or `refresh_token`. |
| `access_issuer.signing_keys_published` | gauge | `algorithm` | Keys in the JWKS, per algorithm. Healthy is at least one. |
| `access_issuer.signing_key.active_since_timestamp` | gauge, `s` | `algorithm` | When the active key became active (Unix seconds). |
| `access_issuer.signing_key_transitions` | counter | `event`, `algorithm` | Keys seen, activated, retired. |

**Why `client_id` is a safe label.** The policy declares every client, so an
installation has tens, not thousands, and the label cannot grow with its users.
The code holds that bound itself: an id the policy does not declare is `other`,
and a request with no client (a workload's exchange) is `none`, so a request
naming a client nobody declared cannot mint a series.

**The `login.failures` reasons** are a fixed set: `bad_state` (a callback or
a form whose state is missing, expired, forged or not from this browser),
`unknown_provider`, `provider_failed` (the directory's own exchange),
`directory_refused`, `directory_unreachable`, `not_entitled` (signed in, but not
in a group the application requires), `recovery_refused`, `unaudited` (the audit
trail could not be written), `not_waiting` (the authorization request is gone)
and `bad_request`.

**`reuse_detected` has two kinds with two meanings.** An authorization code
presented twice is a certain reuse, and the session it opened is ended. A
refresh token that is neither live nor inside the grace window is spent *or
unknown*: a spent token is not kept past the window, so the two are not told
apart. A burst of either is a client bug or a stolen credential; one is noise.

### The controllers and the rails

| Metric | Type | Labels | What it says |
|---|---|---|---|
| `access_roster.ticks` | counter | `kind`, `target`, `outcome` | Ticks. `outcome` is `ok` (the tick ran to its report, whatever the report says about the target) or `failed`. |
| `access_roster.tick.duration` | histogram, `s` | `kind`, `outcome` | How long a tick took. |
| `access_roster.tick.last_success_timestamp` | gauge, `s` | `kind`, `target` | When a target's last ok tick ended (Unix seconds). |
| `access_roster.leases.acquired` | counter | `kind` | Leases taken by this runner. |
| `access_roster.leases.contended` | counter | `kind` | Leases asked for and held by another runner. |
| `access_roster.leases.lost` | counter | `kind` | Leases held and lost: taken over, or not renewable for a whole lifetime. The tick stopped before its next write. |
| `access_roster.leases.held` | up-down counter | `kind` | Leases this runner holds now. |

The controllers' own metrics are the existing ones: `github_roster.passes`,
`.changes`, `.link_changes`, `.breaker_trips`, `.rows`, `.seats_free`,
`.seats_short`, `.links`, and the rate-limit pair `github_roster.rate_limited`
(waits, by `kind`) and `github_roster.rate_limit_remaining` (the budget left, by
`resource`), and the Slack equivalents `slack_roster.*`. The audit emitter's
`audit.emit.*` instruments are the audit component's, and its own alerts read
them.

### The ports

| Metric | Type | Labels | What it says |
|---|---|---|---|
| `access_roster.port.operation.duration` | histogram, `s` | `port`, `operation`, `outcome` | One storage port call. |

`port` is `state`, `index` or `blob`. `operation` is the call (`get`, `put`,
`create`, `update`, `delete`, `delete_if_revision`, `list`, `add`, `remove`,
`members`, `read`, `write`, `write_if_version`, `replace`, `read_all`).
`outcome` is `ok`, `not_found`, `exists`, `conflict`, `unavailable` (the store
is down), `canceled` (the caller gave up) or `error`. The histogram's count by
outcome is the call rate, the error rate and the **compare-and-swap conflicts**
(`outcome="conflict"`): a lost conflict is a lease or a session rotation
working, and is not an error.

### No workspace or organisation label on the issuer's series

Nothing on the issuer's or the ports' series is labelled by workspace,
organisation, person or group. The controllers' series carry the target
(`target`, `org`, `workspace`) for one reason: an alert on "this organisation
has stopped" has to say which. A target is a GitHub organisation or a Slack
workspace the policy declares (`acts_in`), so the label is bounded by the
installation's own declaration, a handful, and does not grow with its people.
Nothing a person controls becomes a label.

## Alerts

Ten rules, in one group, rendered by the chart with `renders: alerts`. Every
threshold is a value (`alerts.rules.<rule>`) and its reason is in the comment
above the rule in `charts/access-roster/templates/alerts.yaml`. Every
aggregation keeps the cluster label, since one store holds many clusters.

| Alert | Severity | Fires when | Default threshold |
|---|---|---|---|
| `AccessRosterNoSigningKeyPublished` | critical | An algorithm has no published key. | `< 1` for 5m |
| `AccessRosterSigningKeyRotationStalled` | warning | The active key is older than a certificate's life less its renewal. | 350 days (30240000s) for 1h |
| `AccessRosterIssuer5xx` | critical | A share of the listener's requests is answered 5xx. | over 5% and at least 5 errors, over 10m, for 10m |
| `AccessRosterTokenEndpointSlow` | warning | The token endpoint's p99 is high. | over 2s, over 10m, for 15m |
| `AccessRosterTickFailing` | warning | One target's ticks keep failing. | 3 in 45m |
| `AccessRosterTickStale` | critical | A target has had no ok tick for a long while (absence). | 3600s (four default intervals), for 10m |
| `AccessRosterLeaseLost` | warning | Leases of one kind are lost repeatedly. | 3 in 1h |
| `AccessRosterGitHubRateLimitLow` | warning | GitHub's budget is nearly spent, for long. | under 100 for 30m |
| `AccessRosterSeatsShort` | warning | An organisation lacks the seats to invite. | `> 0` for 30m |
| `AccessRosterPortErrors` | critical | Storage port calls are failing. | over 5% and at least 5 errors, over 5m, for 10m |

A rule whose series is absent does not fire: whether the issuer or the
controller is running at all is the platform's alert on its own scrape, not
this chart's.

### Runbook

#### AccessRosterNoSigningKeyPublished

The issuer's key ring holds no key to publish for an algorithm, so its JWKS is
empty: no relying party can verify a token, and a new one cannot be signed. Look
at the Secret the chart mounts at `config.signingKey.file` (cert-manager's
Certificate, or `signingKey.existingSecret`) and the issuer's log for why the
file was not read ("the active signing key changed" and "a signing key was seen"
are the lines that say a key arrived). A rollout shows a zero for seconds; five
minutes is not a rollout.

#### AccessRosterSigningKeyRotationStalled

The active key has not been replaced. cert-manager replaces the certificate
`signingKey.certificate.renewBefore` ahead of its end (720h before 8760h by
default), so a key is at most about 335 days old and the rule fires at 350. Look
at the Certificate (`kubectl describe certificate`), its issuer, and whether the
issuer is reading the mounted file (`config.signingKey.pollInterval`). The day
the certificate expires every token stops verifying. If you changed `duration`
or `renewBefore`, set `maxAgeSeconds` to their difference plus two weeks; if the
key is rotated by hand (`signingKey.existingSecret`), turn the rule off or set it
to your cadence.

#### AccessRosterIssuer5xx

The listener answers server errors. The dashboard's 5xx panel names the route,
the issuer's log has the error. If `AccessRosterPortErrors` is also firing, the
store is the cause: look there first. Otherwise a directory that cannot be
reached (`directory_unreachable` in the sign-in failures) or a policy that does
not load are the usual causes.

#### AccessRosterTokenEndpointSlow

Token requests are slow at the 99th percentile. A token is signed in memory and
costs one store write, so look at the port latency panel (a slow Valkey, or a
slow API server on the namespace's objects), then the size of the policy.

#### AccessRosterTickFailing

A controller's ticks of one target failed three times in 45 minutes. The
controller's page in the console shows the report and the error; in the log it
is "a pass over an organisation failed" (GitHub) or the Slack equivalent. An
uninstalled App, a revoked credential and GitHub being down are the causes. The
console answering under another policy during a rollout is retried within
seconds and does not reach this rule.

#### AccessRosterTickStale

A target has completed no tick for an hour. This is the absence rule: it fires
when the controller is not running, when nobody can take the lease, and when the
loop hangs. Check the controller's Deployment, whether a lease is held by a
runner that is gone (it expires on its own after its lifetime), and the log. A
target the policy no longer declares fires for at most a day and then leaves,
because the last value is looked back over a day; remove it from the policy
first.

#### AccessRosterLeaseLost

A lease is lost when another runner takes it over, or it could not be renewed
for a whole lifetime. One loss is the design working: the tick stopped before its
next write. Repeated losses are two runners on one target (a `tick` Job beside
the Deployment, or more than one replica where the State is not shared, see
[high-availability.md](high-availability.md)) or a State that cannot be reached
to renew: see `AccessRosterPortErrors`.

#### AccessRosterGitHubRateLimitLow

GitHub's budget for a resource has been under 100 requests for half an hour.
`github_roster_rate_limited_total` says how often a call already waited. Lengthen
the controller's `interval`, or look for something else spending the App's budget.

#### AccessRosterSeatsShort

An organisation has fewer free seats than the invitations the policy admits. The
controller is healthy; buy a seat or remove a member who no longer belongs and
the next pass sends the invitations.

#### AccessRosterPortErrors

More than 5% of the calls to a storage port failed. State and index are Valkey or
the namespace's ConfigMaps and Secrets; blobs are the reports' ConfigMaps.
`unavailable` is the store being down (check its own health and the
NetworkPolicy to it); `error` is anything else, and the log line beside it names
the call. Lost conflicts and missing keys are not counted.

## Installing the modes

The chart's `renders` value chooses what a release is. The default, `app`, is the
service and the controllers exactly as before. The other two render **only** the
named objects and validate nothing else, so a second release can carry them
where the metrics store and Grafana look for them:

```yaml
# alerts: a VMRule (or alerts.format: prometheusrule) for the ruler
renders: alerts
alerts:
  namespace: access-roster        # where the service runs; its series are selected by it
  ruleLabels:
    k8s_cluster_name: prod        # for the Alertmanager routing tree
```

```yaml
# dashboards: ConfigMaps for Grafana's sidecar, installed on the cluster Grafana runs on
renders: dashboards
dashboards:
  namespace: monitoring
```

```sh
helm install access-roster-alerts oci://ghcr.io/truvity/charts/access-roster \
  -n monitoring -f alerts.yaml
```

`alerts.ruleLabels` is added to every rule beside its `severity`, and
`alerts.rules.<rule>.labels` to one rule. `alerts.runbookBaseUrl` is where the
anchors above are (empty renders no link).

### The dashboard

`access-roster overview - $cluster` holds to truvity/observability's dashboard
contract: a `datasource` variable that every panel uses, a `cluster` variable
filled by `label_values()`, a `namespace` variable, `$cluster` in the title and
in every query, and no datasource UID written into it. Its rows: is it healthy;
the issuer's requests, errors and latency by route; tokens, sign-ins and keys;
the controllers' ticks and leases; the storage ports; GitHub rate limits and
seats.

## How it is held

`just telemetry` (its own CI job, and part of `check`):

- regenerates the dashboard from `hack/dashboards/access-roster-overview.py` and
  fails on a difference from the committed JSON;
- runs `dashboardlint` from truvity/observability at a pinned version over it, and
  proves the lint is real by feeding it the same dashboard with a literal
  datasource, which must fail;
- unit-tests every rule with `vmalert-tool` (a pinned, checksum-verified
  VictoriaMetrics release, the engine of the estate's own ruler) against
  `tests/rules/access-roster-alerts.test.yaml`. Every rule has a case that fires
  it, with its labels and text, and at least one that must not, and
  `tests/chart/alerts_test.go` refuses a rule without both.

`just chart-lint` holds the goldens for both modes
(`tests/golden/access-roster/alerts.yaml`, `dashboards.yaml`) and that the
default render did not change.
