# Runbook

Day-two operations. Everything here is visible in the console; a shell is
needed for the export, a restore, and reading the audit trail's bucket
directly.

## Day one

**A deployment that declares its own way in has no day one.** Values that
carry a workspace and a non-empty operators group are signed into through
the directory from the first boot. Nothing below applies; go to
[the connect runbook](connect-runbook.md) when you add the next tenant.

**A standalone installation configures itself through the console**, and
the console leads it. Overview shows what is left to do until nothing is,
with this installation's own values to copy rather than a placeholder to
translate — the redirect URI is its hostname, and that is where a day-one
setup goes wrong.

1. Install. The service generates `Secret <release>-session-key` and creates
   the ServiceAccount `<release>-recovery`. There is no password anywhere.
2. Mint a recovery token — a cluster administrator already has the RBAC
   for this, and granting `create` on `serviceaccounts/token` for that
   account is how you give it to somebody else:

   ```sh
   kubectl -n access-issuer create token <release>-recovery \
     --audience <release>-recovery --duration 10m
   ```

3. Port-forward the service's port (or go through the gateway), open
   `/login`, expand **Recovery sign-in** and paste the token.
4. Follow Overview. It walks the four steps: register an OAuth client with
   the directory, give it to the service, connect the first directory, and
   attach a directory group to the operators group. Each disappears as it
   completes.
5. Sign out; sign in with the directory as yourself. Search for yourself:
   your page shows operator and the membership that granted it.

Outside a cluster there is nothing to prove access to, so the service prints a
generated recovery password once at start and step 2 is reading it off the
log. That installation gets a fifth setup step — turn the password off —
because a stored password *is* a standing credential, which the token is
not.

Step 4's first item is the only one that leaves the console:
[the connect runbook](connect-runbook.md) has the full walk-through of the
cloud-console visit, and Overview has the two values to paste into it.

The console signs people in as a client of the issuer it shares an
origin with, so steps 3 and 5 are the issuer's own sign-in page, and
recovery stays reachable by port-forward.

## Lost operator access

Nobody is in the operators group, or the group was renamed, or the directory
sign-in is what is broken:

- **recovery enabled (the default):** mint a token as in day one, sign in
  at `/login` under *Recovery sign-in*, fix the membership. Who did it is
  in the service's log and in the cluster's audit log, by name.
- **recovery disabled:** set `recovery.enabled: true` in the values,
  roll the deployment, then as above. There is no password to recover,
  only RBAC to hold.
- **`503 recovery could not be checked`:** the check did not run — the API
  server is unreachable, or the service may not create TokenReviews (the
  ClusterRole `<release>-<namespace>-tokenreview`). It is not a wrong
  token; do not go looking for one.
- **`401 that proof was not accepted`:** the token expired (they are
  minted for minutes), was minted for another audience, or belongs to an
  account that may not recover. Mint another with both flags.
- **outside a cluster, `429 too many attempts`:** ten wrong passwords stop
  the password answering for a minute — the correct one included, so that
  the limit is not a hint about which guess was close. Wait, then try
  once.

Sessions are stateless signed cookies. To log everyone out at once,
delete `Secret <release>-session-key`; the service generates a new one on restart.

The console's own sign-out is the issuer's `/logout`, which ends the
sign-in and every session under it. A console behind `access-proxy`
has a cookie of the proxy's instead, and its sign-out has to run the
whole chain — the proxy's `/oauth2/sign_out`, then the issuer's
`end_session` with that console's client id, then back to its front
page; the proxy chart builds it. With only the proxy's half, the issuer
keeps the session and the next click at any console signs them straight
back in, which looks exactly like success. The issuer's client must
list the console's front page in `signed_out`, or the person lands on
the issuer's own page instead.

Recovery, for the record, is the **cluster anchor used as the floor**
([../design/trust.md](../design/trust.md)): the issuer depends on the
directory, the directory is what this section assumes is broken, so the
only thing left to trust is the API server.

## What "unhealthy" means and what to do

| Symptom (console) | Cause | Action |
|---|---|---|
| Health: error, domains *provisional — probe failed* | token revoked, admin suspended, tenant policy changed, scopes withdrawn | **Reconnect** (consent) or upload a new key. Nothing is lost meanwhile: the last snapshot is served, non-authoritative |
| Health ok, domains *provisional — snapshot stale* | refresher cannot complete a full read (a page fails, quota, timeouts) | check the service logs for the failing page; **Refresh** to retry now; the snapshot recovers on the next successful pass |
| Health ok, domains *provisional — first snapshot pending* | the workspace was connected moments ago, or its served list was just changed; the first snapshot runs detached | wait — seconds for a small tenant, a minute or two for a large one. Longer than a refresh interval: read the log for the failing page |
| One replica answers *workspace not found* for a directory the other serves | before 0.8 the reader map was filled only at start, so a workspace connected on one replica was unknown to the other | restart the replica; from 0.8 a missing reader is opened from the stored credential on first use |
| The consent callback shows the CDN's own *Bad gateway* page | the service answered 5xx and the CDN replaced it — since 0.7.2 the callback never answers 5xx, so the request did not reach the service | the gateway, the route, or the egress policy; the service's log has nothing because nothing arrived |
| One domain not authoritative on two workspaces, marked *conflict* | both tenants list the domain **and both serve it** — a move in progress, or a misconfiguration | wait for the move to complete, or narrow one of them: *Choose which to serve* on the directory's page, leaving the domain out of the tenant that should not answer for it |
| A domain shows *not served* | this service was narrowed to a subset of the tenant's domains, so nothing routes to it and its accounts are not cached | intended in most cases; *Choose which to serve* changes it. A declared workspace says so in the values (`directory.workspaces[].serve`) |
| A domain shows *no longer owned* | the served list names a domain the directory no longer lists — it has moved to another tenant | the hand-over already happened: the other workspace serves it as soon as its own discovery returns it. Drop the entry here so the list matches reality |
| Every domain non-authoritative at once | Valkey unreachable | restore Valkey; the service refills it within one refresh interval |
| A workspace shows *declared* and no Reconnect/Disconnect | it comes from the chart's overlay | change the deployment's values, not the console |
| After a restart, a workspace is unhealthy with "no backend: the credential is not loaded" | its entry in `Secret <release>-workspace-credentials` is gone or unreadable — restored namespace without that Secret, hand-edited object, an entry deleted by hand | put the Secret back from a backup, or **Reconnect** (consent) or upload the key again. The record, its served domains and its memberships are intact; only the credential is missing. The service logs the workspace id at start |

The rule consumers follow makes every row above safe: **a
non-authoritative answer holds, it never removes.**

## Backing up, and restoring, what the console holds

Everything a console added that cannot be minted again is in four
Secrets in the service's namespace, each under a name a deployment
knows in advance:

| Secret | Holds |
|---|---|
| `<release>-workspace-credentials` | every console-connected workspace's credential, one key per workspace, with a copy of its record |
| `<release>-github-apps` | every connected organisation's App key and the link App's client, each with a copy of its record |
| `<release>-github-links` | people's GitHub links, tokens included |
| `<release>-github-runner-apps` | every runner App, its record beside its keys |

**Back them up** by copying the four objects, for example with an
External Secrets `PushSecret` each into a secret manager that travels
with your backups. Nothing in the service depends on the copy.

**Restore** by putting the four Secrets back into the namespace, with
the labels they carried, before the service starts or before restarting
it. At start it rebuilds every workspace ConfigMap and every GitHub
record that is missing beside a credential, then reopens the
workspaces. A restored workspace shows as never probed until its first
probe; a link token that rotated since the copy means that person links
again; a declared Secret is re-delivered by whatever declared it.

**Without a copy**, a lost workspace credential is recovered by pressing
**Connect** again as the same admin role account — the tenant id matches
and the domains return authoritative after the first snapshot — and a
lost App by *Disconnect* then *Create* on the GitHub page's Apps tab.

A namespace that ran a release before 1.7 still holds one
`<release>-credential-<tenant>` Secret per workspace beside the new one:
start-up copied each in by name and left the old object for a rollback,
and reconnecting or disconnecting that workspace removes it.

## Rotating

- **Consent credential:** Reconnect. The old refresh token is revoked at
  Google as part of it.
- **Service-account key, connected through the console:** Upload key
  again with the new JSON; the old one is replaced.
- **Service-account key, declared:** replace the named Secret; the service
  picks up the mounted file within a minute. Delete the old key in
  Google Cloud afterwards.
- **OAuth client secret:** Settings → set the new secret (or update the
  declared Secret). Existing refresh tokens keep working; the secret is
  used only to exchange and refresh.

## Export

```sh
kubectl -n access-issuer get secret,configmap \
  -l app.kubernetes.io/managed-by=directory-roster -o yaml > access-roster-export.yaml
```

The export contains credentials. Treat it as one.

## Scaling and cache

Two replicas are the default; the shared Valkey makes them answer from
the same snapshot and lets one refresher run for both. A single replica
may run without Valkey (`valkey.address` empty), at the cost of a cold
cache on every restart. Memory in Valkey is the size of the directories.
Every replica serves every workspace: one connected through the console
on the other replica is opened from its stored credential on first use
*(0.8; before that, only a restart taught a replica about it)*.

## Logs

Structured JSON on stdout. The service never logs a credential, a token or a
key file, and never logs the members of a group; it logs workspace ids,
domains, counts, durations and errors.

## Enabling a GitHub organisation

1. The organisation is bound in the policy, **connected** on the GitHub
   page, and the controller runs with the organisation *not* in
   `githubRoster.actsIn`. The **link App** is created, and the people
   who belong in it have linked their accounts — send them the link page
   the GitHub page shows. Until somebody links, their rows say
   `not linked` and their accounts are left alone.
2. Read its section on the GitHub page after a pass. *Controller* says
   `dry run`; the table of people not synced is exactly what enabling it
   would do. Look for anybody you did not expect to be removed, and for
   held rows: each carries its reason. *Controller* says `waiting on
   links` when the only thing left is people who have not linked — that
   is not in sync, and enabling changes nothing for them.
3. Add the login to `githubRoster.actsIn` and roll out. The next pass
   acts; its changes appear in the audit trail as `github.member.*`.
4. To stop acting in it, remove the login again. Nothing is undone: the
   organisation is simply left as it is.

If a pass fails, the section says why — an organisation not connected,
an App GitHub refuses, a console that did not answer. A failed pass
changes nothing, and is reported over the last report that had rows, so
the page does not blank while passes fail. A console that answers under
a different policy than the controller loaded — the two restart at
different moments during a rollout — is the same: the pass changes
nothing and is retried next interval.

**Needs you on a GitHub organisation:**

- *Not enough seats* — buy the seats the banner names in the organisation's
  billing on GitHub. Nobody is invited past the last free seat.
- *Seats cannot be counted* — the organisation's App lacks organisation
  administration (read). An owner adds it in the App's settings on GitHub
  and accepts it for the installation. An App created from 1.5.0 on asks
  for it already.
- *Removals held* — more than half the organisation would leave in one
  pass. Read the removals; if they are right, press **Confirm**
  (`github.removals.confirmed` in the audit trail). If they are a policy
  mistake, fix the policy: the set changes and the confirmation would not
  cover it anyway.

**Importing github-roster 0.x pairings.** Once, from a machine that can
read `/roster/people/*` in SSM: build `records[]{login, emails[],
approved_by, approved_at}` and call `ImportGitHubLinks` with `origin:
"github-roster 0.x"` as an operator. Every skipped record comes back with
its reason; imported ones show as *imported* on the GitHub page.

**A link that is `unverifiable`** can no longer be checked and was not
said by GitHub to be gone: its token pair was lost in an interrupted
renewal, or the link App was replaced. It adds and removes nobody. Ask
the person to open the link page and link again.

**A link that is `lost`** was withdrawn on GitHub — the work address
removed or unverified, or the authorization revoked — and its account
left the organisation (`github.link.lost`, then `github.member.remove`
in the audit trail). Linking again brings it back in on the next pass.

## Runner Apps

The chart declares the tiers (`githubRunnerApps.tiers: [preview, stable]`)
and the GitHub page's Apps tab then shows a row per bound organisation
per tier. *Create* is the same two clicks as an organisation's App:
GitHub's create page, then its install page, by an owner of the
organisation. The App lands in `Secret <release>-github-runner-apps` as
`<tier>.<org>.github_app_id`, `.github_app_installation_id` and
`.github_app_private_key` — the keys a gha-runner-scale-set
`githubConfigSecret` reads — and a deployment copies those three to its
runners, for example with a `PushSecret`. Until the App is installed the
key sits under `<tier>.<org>.pending_private_key`, so a copy taken in
between never replaces working runners with an App they cannot register
with.

| Symptom | Means | Do |
|---|---|---|
| a row reads *created, not installed* | the owner stopped after Create | *Finish installing* on the row |
| runners stop taking jobs after a Disconnect | the App was uninstalled and its keys forgotten, as Disconnect does | create a new App for that tier and hand its keys to the runners |
| the runners' copy is empty | the App is not installed yet, or the copy runs before the keys exist | install it; the three keys appear only then |

## Audit: what happened lately

The console's **Audit** page (operators only) is one stream for the whole
service, newest first: sign-ins and their refusals — at the issuer and at
the console's own door, recovery marked as its own kind — refused
refreshes, token exchanges by proof kind, revokes and sign-outs, provider
connects, disconnects and domain or group changes, GitHub Apps created,
organisations connected and disconnected, and whatever a reporting
component such as the GitHub controller did, shown with the identity it
proved. A refused event carries its reason.

**The trail is kept in S3** (`audit.s3.bucket`), one JSON-lines object per
batch under `<prefix>YYYY/MM/DD/HH/`, written at most `audit.s3.flushInterval`
after the event. That bucket is the record: read it directly for anything
older than the console pages through, or to hand an auditor an hour:

```sh
hour=s3://<bucket>/events/2026/09/13/16/
for key in $(aws s3 ls "$hour" | awk '{print $4}'); do aws s3 cp "$hour$key" -; done > hour.jsonl
```

**Each line is an Elastic Common Schema document**, nested as ECS nests
it; fields with no value are left out:

```json
{"@timestamp":"2026-09-13T16:58:01.123456789Z","access_roster":{"attributes":{"how":"google"},"outcome":"refused","target":"console"},"client":{"address":"203.0.113.7"},"ecs":{"version":"8.11.0"},"event":{"action":"sign-in.refused","category":["authentication"],"dataset":"access_roster.audit","id":"1789318681123456789-access-issuer-7d9f8c6b5-x2x4q-1","kind":"event","outcome":"failure","provider":"console","reason":"the directory says this account is not live","type":["denied"]},"http":{"request":{"id":"5f0c1a9e-6b1d-4c1e-9a0b-2d3e4f5a6b7c"}},"service":{"target":{"name":"console"}},"user":{"name":"ada@north.example","target":{"name":"ada@north.example"}},"user_agent":{"original":"Mozilla/5.0 (X11; Linux x86_64)"}}
```

`event.action` is the kind (`sign-in`, `token.exchanged`,
`github.member.invite`…), `event.provider` the source, `user.name` who did
it, `user.target.name` who it concerns, `observer.name` the verified
reporter of a reported event, and `event.outcome` is `success`, `failure`
or `unknown`. ECS cannot tell refused from failed, nor say `held`, so the
native outcome is `access_roster.outcome`, beside `access_roster.target`
and `access_roster.attributes`. `event.category` and `event.type` are
ECS's own values, decided per kind in `internal/audit/ecs.go`.

Objects written by 1.6.2 hold its own lines instead (`id`, `at`, `kind`,
`actor`, … at the top level); the console reads both, and so can `jq`:

```sh
# recovery sign-ins in the hour, newest format only
jq -c 'select(.event.action == "recovery.sign-in") | {at: ."@timestamp", who: .user.name, from: .client.address, outcome: .access_roster.outcome}' hour.jsonl
# every event in either format, as one shape
jq -c 'if .event then {id: .event.id, kind: .event.action, subject: .user.target.name, outcome: .access_roster.outcome}
       else {id, kind, subject, outcome} end' hour.jsonl
```

**Every event is also one log line** with `"audit":true`, carrying the
same fields under their dotted names, flat — `event.action`, `user.name`,
`client.address`, and each attribute as `access_roster.attributes.<name>`
— with the line's own `time` as the timestamp. `event.id` is the same id
as the kept record's, so a line finds its record and back. The lines are
all that remains of a queue a replica could not write before it stopped:

```sh
kubectl -n access-issuer logs deploy/access-issuer --since=24h | jq 'select(.audit == true)'
kubectl -n access-issuer logs deploy/access-issuer --since=24h \
  | jq -c 'select(.audit == true and ."event.action" == "sign-in.refused") | {time, who: ."user.name", from: ."client.address", why: ."event.reason"}'
```

In Loki, whose `json` stage turns dots into underscores, the trail is
`{app="access-issuer"} | json | event_dataset="access_roster.audit"`.

**Three fields say where an event came from**, for an event a request
caused: `client.address`, `user_agent.original`, and `http.request.id` —
the gateway's `X-Request-Id`, which finds the same request in the
gateway's access log. The address is the connection's peer unless
`audit.forwardedForTrustedHops` is set, and then the `X-Forwarded-For`
entry just left of that many of the deployment's own proxies, read from
the right. Count the proxies that append: behind an edge that appends
the client and a gateway that appends the edge's connector, it is 1. The
gateway's access log shows the header as it arrives, which is how to
count them. Background work leaves all three
empty, and a reporter supplies its own.

Without a bucket the trail is one replica's memory, capped by
`audit.maxEvents` and gone on restart — right for a laptop, and warned
about at start anywhere else.

**A component reports** by calling `AuditService.RecordAuditEvents` with
its own ServiceAccount token. The policy has to put it in
`all:access-roster:reporter` through a `service_account` matcher; nothing
else — no person, no other workload — may report, and a report naming
`issuer`, `directory` or `console` as its source is refused.

### When the audit trail cannot be written

**Nothing but a recovery sign-in waits for S3.** Every event is a log line
first. An ordinary event is then queued in the replica that recorded it,
listed from there, and written when S3 answers; the writer tries again
every `audit.s3.flushInterval`. Past 50 000 unwritten events in one
replica the oldest are dropped, and their log lines are then the only
copy. A replica that stops while S3 refuses keeps nothing but those lines.
This is fail-open by decision: an audit outage must not become an access
outage.

**A recovery sign-in fails closed.** Its record is put in S3 before the
sign-in succeeds, and when the put fails the sign-in is refused — a page
at the issuer, a 503 at the console's own door, both saying the audit
trail could not be written — and the refusal is recorded the ordinary way,
as `recovery.sign-in` with outcome `refused`. The proof was good; fix the
write and recover again. That write depends on S3 and the pod's AWS
identity only, so check those: the bucket, `s3:PutObject` under the
prefix, the bucket key's `kms:GenerateDataKey`, and the pod's egress to
S3. A recovery sign-in waits for the trail: there is no override.

**The signals**, in the log:

| Line | Means |
|---|---|
| `the audit trail could not be written to S3; tried again next interval` (Warn) | a queued batch was refused; it is retried |
| `an audit event was logged and not stored` (Warn) | the writer would not even accept an event, as a replica shutting down does; the log line is its only copy |
| `the audit trail cannot be written and is full; the oldest unwritten events are dropped (their log lines remain)` (Warn) | events have been lost from the trail, with `dropped` counting them |
| `an audit event was logged and could not be written durably` (Warn) and `recovery refused: the audit trail could not be written` (Error) | a recovery sign-in was refused |
| `the audit trail could not be written before shutdown; those events are in the log only` (Error) | a replica stopped with events unwritten |

and as metrics, pushed over OTLP when `telemetry.otlpEndpoint` is set:

| Metric | Kind | Attributes |
|---|---|---|
| `access_roster.audit.writes` | counter: objects put | `outcome` (`ok`, `failed`), `durable` |
| `access_roster.audit.dropped` | counter: events dropped unwritten | |
| `access_roster.audit.queue` | gauge: events accepted and not yet written | |

No collector is deployed for these yet. When one is, these are the rules,
in Prometheus form (an OTLP counter arrives as `…_total`, dots as
underscores):

```yaml
groups:
  - name: access-roster-audit
    rules:
      - alert: AccessRosterAuditUnwritable
        expr: sum(increase(access_roster_audit_writes_total{outcome="failed"}[10m])) > 0
        for: 10m
        annotations:
          summary: the audit trail has not been written to S3 for 10 minutes; recovery sign-ins are refused
      - alert: AccessRosterAuditDropping
        expr: sum(increase(access_roster_audit_dropped_total[5m])) > 0
        annotations:
          summary: audit events were dropped unwritten; their log lines are the only copy
      - alert: AccessRosterAuditQueueGrowing
        expr: max(access_roster_audit_queue) > 5000
        for: 15m
        annotations:
          summary: a replica holds thousands of audit events it has not written
```

and the same without metrics, over the log lines in Loki:

```logql
sum(count_over_time({app="access-issuer"} |= "the audit trail could not be written" [10m])) > 0
```
