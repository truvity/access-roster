#!/usr/bin/env python3
"""The access-roster overview dashboard, generated.

Written as code so that units, thresholds and descriptions are decisions made
once. `python3 hack/dashboards/access-roster-overview.py >
charts/access-roster/dashboards/access-roster-overview.json` regenerates it;
`just telemetry` fails when the committed file differs.

It holds to the contract of truvity/observability's docs/dashboards.md, which
its `dashboardlint` enforces: a `datasource` variable that every panel uses, a
`cluster` variable chained off it and populated by label_values(), a
`namespace` variable chained off `cluster`, `$cluster` in the title, and
`$cluster` in every query.

Series are the ones the service and the controllers publish over OTLP, as the
metrics gateway names them (dots to underscores, `_total` on counters, the unit
as a suffix). Only the cluster, namespace and tier become labels from the
resource, so every dimension used below (route, kind, target, port, outcome,
reason) is a metric attribute. Nothing is labelled by person, group or address:
a target is a GitHub organisation or a Slack workspace the policy declares, a
client id is one the policy declares, and both are bounded by that
declaration.
"""
import json

DS = {"type": "prometheus", "uid": "${datasource}"}
K = 'k8s_cluster_name=~"$cluster"'
W = '%s,namespace=~"$namespace"' % K
GREEN, RED, ORANGE = "green", "red", "orange"

panels = []
_id = [0]


def nid():
    _id[0] += 1
    return _id[0]


def target(expr, legend="", ref="A", instant=False):
    return {"datasource": DS, "editorMode": "code", "expr": expr, "legendFormat": legend,
            "range": not instant, "instant": instant, "refId": ref}


def row(title, y):
    panels.append({"id": nid(), "type": "row", "title": title, "collapsed": False,
                   "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": []})


def stat(title, desc, expr, x, y, unit="short", w=4, steps=None, no_value="no data", decimals=0):
    steps = steps or [(None, GREEN), (1, RED)]
    panels.append({
        "id": nid(), "type": "stat", "title": title, "description": desc, "datasource": DS,
        "gridPos": {"h": 4, "w": w, "x": x, "y": y},
        "targets": [target(expr, instant=True)],
        "fieldConfig": {"defaults": {
            "unit": unit, "noValue": no_value, "decimals": decimals, "mappings": [],
            "thresholds": {"mode": "absolute", "steps": [{"color": c, "value": v} for v, c in steps]}},
            "overrides": []},
        "options": {"colorMode": "background", "graphMode": "none", "justifyMode": "center",
                    "textMode": "value", "orientation": "auto",
                    "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
    })


def series(title, desc, targets, x, y, w, unit, h=8, stack=False):
    panels.append({
        "id": nid(), "type": "timeseries", "title": title, "description": desc, "datasource": DS,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "targets": [target(e, legend=l, ref=chr(65 + i)) for i, (e, l) in enumerate(targets)],
        "fieldConfig": {"defaults": {
            "unit": unit, "noValue": "no data",
            "custom": {"drawStyle": "line", "lineWidth": 1, "fillOpacity": 25 if stack else 10,
                       "showPoints": "never", "spanNulls": False,
                       "stacking": {"mode": "normal" if stack else "none", "group": "A"}},
            "thresholds": {"mode": "absolute", "steps": [{"color": GREEN, "value": None}]}},
            "overrides": []},
        "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    })


R = "$__rate_interval"
y = 0
row("Is it healthy?", y)
y += 1
stat("Signing keys published",
     "Keys in the JWKS, the lowest across algorithms and replicas. Healthy is at least one. Zero is an issuer nobody can verify a token "
     "against: see AccessRosterNoSigningKeyPublished in the telemetry runbook.",
     "min(access_issuer_signing_keys_published{%s})" % W, 0, y,
     steps=[(None, RED), (1, GREEN)])
stat("5xx share (1h)",
     "The share of the issuer's requests answered 5xx. Healthy is zero: its refusals are 4xx. The request panels below name the route.",
     "sum(increase(access_issuer_http_requests_total{%s,status_class=\"5xx\"}[1h])) / sum(increase(access_issuer_http_requests_total{%s}[1h]))" % (W, W),
     4, y, unit="percentunit", steps=[(None, GREEN), (0.0001, ORANGE), (0.05, RED)], decimals=1)
stat("Sign-in failures (1h)",
     "Sign-ins that did not complete. A few are people closing a tab; a climb in one reason is the signal. The reasons are in the sign-in panel below.",
     "sum(increase(access_issuer_login_failures_total{%s}[1h]))" % W, 8, y, steps=[(None, GREEN), (10, ORANGE), (100, RED)])
stat("Reuse detected (1h)",
     "A spent authorization code or refresh token presented again. A code reuse also ends the session it opened. A refresh token outside the grace "
     "window is spent or unknown (the two are not told apart). A burst is a client bug or a stolen credential.",
     "sum(increase(access_issuer_reuse_detected_total{%s}[1h]))" % W, 12, y, steps=[(None, GREEN), (1, ORANGE), (20, RED)])
stat("Targets not ticking",
     "Targets (GitHub organisations, Slack workspaces) with no ok tick for over an hour, four default intervals. See AccessRosterTickStale.",
     "count(time() - max by (k8s_cluster_name, namespace, kind, target) (last_over_time(access_roster_tick_last_success_timestamp_seconds{%s}[1d])) > 3600) or vector(0)" % W,
     16, y)
stat("Port errors (1h)",
     "Storage port calls that ended unavailable or error. Not counted: a lost compare-and-swap, a create over a live key, a missing key. Healthy is zero.",
     "sum(increase(access_roster_port_operation_duration_seconds_count{%s,outcome=~\"unavailable|error\"}[1h]))" % W, 20, y)
y += 4

row("Issuer: requests, errors, latency", y)
y += 1
series("Requests per second, by route",
       "What the issuer's listener answers, by route (a fixed set of names, never the raw path). token and authorize are the protocol; "
       "login_* the sign-in pages; console_* the console.",
       [('sum by (route) (rate(access_issuer_http_requests_total{%s}[%s]))' % (W, R), "{{route}}")],
       0, y, 12, "reqps", stack=True)
series("5xx per second, by route",
       "Requests answered with a server error. Should be a flat zero; compare with the request rate above.",
       [('sum by (route) (rate(access_issuer_http_requests_total{%s,status_class="5xx"}[%s]))' % (W, R), "{{route}}")],
       12, y, 12, "reqps")
y += 8
series("Latency p99, by route",
       "The 99th-percentile time the listener took, by route. The token endpoint is one store write and a signature: milliseconds.",
       [('histogram_quantile(0.99, sum by (le, route) (rate(access_issuer_http_request_duration_seconds_bucket{%s}[%s])))' % (W, R), "{{route}}")],
       0, y, 12, "s")
series("Token endpoint latency, p50 and p99",
       "The token endpoint on its own, the one clients wait on. AccessRosterTokenEndpointSlow fires on its p99.",
       [('histogram_quantile(0.5, sum by (le) (rate(access_issuer_http_request_duration_seconds_bucket{%s,route="token"}[%s])))' % (W, R), "p50"),
        ('histogram_quantile(0.99, sum by (le) (rate(access_issuer_http_request_duration_seconds_bucket{%s,route="token"}[%s])))' % (W, R), "p99")],
       12, y, 12, "s")
y += 8

row("Tokens, sign-ins and keys", y)
y += 1
series("Tokens issued per second, by client",
       "Access tokens signed, by the client id the policy declares (anything it does not declare is `other`, a workload's exchange is `none`).",
       [('sum by (client_id) (rate(access_issuer_tokens_issued_total{%s}[%s]))' % (W, R), "{{client_id}}")],
       0, y, 12, "ops", stack=True)
series("Tokens issued per second, by grant",
       "The same tokens by grant type: authorization_code (a sign-in), refresh_token, token_exchange (a workload or a person trading a token), "
       "client_credentials, console_mint (the console reading another service as the person).",
       [('sum by (grant_type) (rate(access_issuer_tokens_issued_total{%s}[%s]))' % (W, R), "{{grant_type}}")],
       12, y, 12, "ops", stack=True)
y += 8
series("Sign-in failures per second, by reason",
       "Why sign-ins did not complete: bad_state (a stale or foreign callback), provider_failed (the directory's own exchange), "
       "directory_refused, directory_unreachable, not_entitled, recovery_refused, unaudited, not_waiting, unknown_provider, bad_request.",
       [('sum by (reason) (rate(access_issuer_login_failures_total{%s}[%s]))' % (W, R), "{{reason}}")],
       0, y, 12, "ops", stack=True)
series("Sign-ins completed per second, by method",
       "Sign-ins that completed, by how the person was proved: a directory's kind, recovery, or an existing browser session.",
       [('sum by (method) (rate(access_issuer_login_successes_total{%s}[%s]))' % (W, R), "{{method}}")],
       12, y, 12, "ops", stack=True)
y += 8
series("Reuse detected, by kind",
       "A spent authorization code or refresh token presented again. Should be a flat zero.",
       [('sum by (kind) (increase(access_issuer_reuse_detected_total{%s}[%s]))' % (W, R), "{{kind}}")],
       0, y, 12, "short")
series("Signing keys: published and age of the active key",
       "Keys in the JWKS by algorithm (left) and the age of the active key (the second series, in seconds). A healthy key is at most about "
       "335 days old with the chart's defaults; AccessRosterSigningKeyRotationStalled fires past 350.",
       [('min by (algorithm) (access_issuer_signing_keys_published{%s})' % W, "published {{algorithm}}"),
        ('time() - max by (algorithm) (access_issuer_signing_key_active_since_timestamp_seconds{%s})' % W, "age {{algorithm}}")],
       12, y, 12, "short")
y += 8

row("Controllers: ticks and leases", y)
y += 1
series("Ticks per second, by kind and outcome",
       "Ticks of the GitHub and Slack controllers. failed is a report that says failed or a tick that returned an error; ok includes in-sync, "
       "applied, held and dry-run.",
       [('sum by (kind, outcome) (rate(access_roster_ticks_total{%s}[%s]))' % (W, R), "{{kind}} {{outcome}}")],
       0, y, 12, "ops", stack=True)
series("Tick duration p99, by kind",
       "How long a tick of a target takes. A climb is a slow GitHub or Slack, a console under load, or a large organisation.",
       [('histogram_quantile(0.99, sum by (le, kind) (rate(access_roster_tick_duration_seconds_bucket{%s}[%s])))' % (W, R), "{{kind}}")],
       12, y, 12, "s")
y += 8
series("Seconds since the last ok tick, by target",
       "For every target, how long since its last ok tick. A line that climbs past an hour (four default intervals) is a target nobody is "
       "reconciling: AccessRosterTickStale.",
       [('time() - max by (kind, target) (last_over_time(access_roster_tick_last_success_timestamp_seconds{%s}[1d]))' % W, "{{kind}} {{target}}")],
       0, y, 12, "s")
series("Failed ticks, by target",
       "Failed ticks per target over the interval. AccessRosterTickFailing fires on three in 45 minutes.",
       [('sum by (kind, target) (increase(access_roster_ticks_total{%s,outcome="failed"}[%s]))' % (W, R), "{{kind}} {{target}}")],
       12, y, 12, "short")
y += 8
series("Leases held, by kind",
       "Tick leases this runner holds now. One per target being ticked; a controller with several replicas shows each replica's own.",
       [('sum by (kind) (access_roster_leases_held{%s})' % W, "{{kind}}")],
       0, y, 12, "short")
series("Leases acquired, contended and lost, per second",
       "Acquired: taken. Contended: asked for and another runner held it (the normal answer of the replica that did not win). Lost: held and "
       "then taken over or not renewable; repeated is AccessRosterLeaseLost.",
       [('sum by (kind) (rate(access_roster_leases_acquired_total{%s}[%s]))' % (W, R), "acquired {{kind}}"),
        ('sum by (kind) (rate(access_roster_leases_contended_total{%s}[%s]))' % (W, R), "contended {{kind}}"),
        ('sum by (kind) (rate(access_roster_leases_lost_total{%s}[%s]))' % (W, R), "lost {{kind}}")],
       12, y, 12, "ops")
y += 8

row("Storage ports", y)
y += 1
series("Port calls per second, by port and outcome",
       "Calls to the state, index and blob ports. conflict is a lost compare-and-swap (a lease or a session rotation working), exists a create "
       "over a live key, not_found a missing key; unavailable and error are the store failing.",
       [('sum by (port, outcome) (rate(access_roster_port_operation_duration_seconds_count{%s}[%s]))' % (W, R), "{{port}} {{outcome}}")],
       0, y, 12, "ops", stack=True)
series("Port failures, share of calls by port",
       "The share of calls that ended unavailable or error. AccessRosterPortErrors fires on 5% over five minutes.",
       [('sum by (port) (rate(access_roster_port_operation_duration_seconds_count{%s,outcome=~"unavailable|error"}[%s])) / sum by (port) (rate(access_roster_port_operation_duration_seconds_count{%s}[%s]))' % (W, R, W, R), "{{port}}")],
       12, y, 12, "percentunit")
y += 8
series("Port latency p99, by port and operation",
       "The 99th-percentile time of a port call. The legacy adapter is Valkey and the namespace's ConfigMaps and Secrets: a blob write is an "
       "API server round trip, a state call one Valkey command.",
       [('histogram_quantile(0.99, sum by (le, port, operation) (rate(access_roster_port_operation_duration_seconds_bucket{%s}[%s])))' % (W, R), "{{port}} {{operation}}")],
       0, y, 12, "s")
series("Compare-and-swap conflicts per second, by operation",
       "Writes that lost a race: update, delete_if_revision and write_if_version answering conflict. A trickle is replicas sharing a lease or "
       "rotating a session; a sustained rate is two things fighting.",
       [('sum by (operation) (rate(access_roster_port_operation_duration_seconds_count{%s,outcome="conflict"}[%s]))' % (W, R), "{{operation}}")],
       12, y, 12, "ops")
y += 8

row("GitHub rate limits and seats", y)
y += 1
series("Rate limit remaining, by resource",
       "Requests left in GitHub's budget as last reported on a response. AccessRosterGitHubRateLimitLow fires under 100 for 30 minutes.",
       [('min by (resource) (github_roster_rate_limit_remaining{%s})' % W, "{{resource}}")],
       0, y, 12, "short")
series("Rate-limit waits per second, by kind",
       "Calls that waited out a GitHub rate limit, by kind of limit (primary or secondary).",
       [('sum by (kind) (rate(github_roster_rate_limited_total{%s}[%s]))' % (W, R), "{{kind}}")],
       12, y, 12, "ops")
y += 8
series("Seats short, by organisation",
       "Invitations the last pass could not send for want of a free seat. Healthy is zero: AccessRosterSeatsShort.",
       [('max by (org) (github_roster_seats_short{%s})' % W, "{{org}}")],
       0, y, 12, "short")
series("Seats free, by organisation",
       "Free seats as last read; absent while the seats cannot be read.",
       [('max by (org) (github_roster_seats_free{%s})' % W, "{{org}}")],
       12, y, 12, "short")


def var_ds():
    return {"name": "datasource", "label": "datasource", "type": "datasource", "query": "prometheus",
            "current": {}, "hide": 0, "includeAll": False, "multi": False, "options": [],
            "refresh": 1, "regex": "", "skipUrlSync": False}


def var_cluster():
    q = "label_values(access_issuer_http_requests_total, k8s_cluster_name)"
    return {"name": "cluster", "label": "cluster", "type": "query", "datasource": DS, "definition": q,
            "query": {"query": q, "refId": "cluster-Variable-Query"}, "current": {}, "hide": 0,
            "includeAll": False, "multi": False, "options": [], "refresh": 2, "regex": "",
            "skipUrlSync": False, "sort": 1}


def var_namespace():
    q = "label_values(access_issuer_http_requests_total{%s}, namespace)" % K
    return {"name": "namespace", "label": "access-roster namespace", "type": "query", "datasource": DS,
            "definition": q, "query": {"query": q, "refId": "namespace-Variable-Query"}, "current": {},
            "hide": 0, "includeAll": True, "allValue": ".*", "multi": True, "options": [],
            "refresh": 2, "regex": "", "skipUrlSync": False, "sort": 1}


dashboard = {
    "uid": "access-roster-overview",
    "title": "access-roster overview - $cluster",
    "description": "The token service and its controllers: the issuer's requests, errors and latency, tokens and sign-ins, signing keys, "
                   "the controllers' ticks and leases, the storage ports, and GitHub rate limits and seats.",
    "editable": False, "graphTooltip": 1, "refresh": "1m", "schemaVersion": 39,
    "time": {"from": "now-6h", "to": "now"}, "timezone": "", "annotations": {"list": []},
    "links": [], "tags": ["access-roster"],
    "templating": {"list": [var_ds(), var_cluster(), var_namespace()]},
    "panels": panels,
}

print(json.dumps(dashboard, indent=2))
