# Runbook

Day-two operations. Everything here is visible in the console; a shell is
needed for the export, a restore, and reading the log lines of an
installation with no audit trail connected.

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
| After a restart, a workspace is unhealthy with "no backend: the credential is not loaded" | its entry in `Secret <release>-workspace-credentials` is gone or unreadable — restored namespace without that Secret, hand-edited object, an entry deleted by hand | put the Secret back from a backup — then **restart**, because the credential is read once ([Rotating](#rotating)) — or **Reconnect** (consent) or upload the key again. The record, its served domains and its synced groups are intact; only the credential is missing. The service logs the workspace id at start |

The rule consumers follow makes every row above safe: **a
non-authoritative answer holds, it never removes.**

## Backing up, and restoring, what the console holds

Everything a console added that cannot be minted again is in five
Secrets in the service's namespace, each under a name a deployment
knows in advance:

| Secret | Holds |
|---|---|
| `<release>-workspace-credentials` | every console-connected workspace's credential, one key per workspace, with a copy of its record |
| `<release>-github-apps` | every connected organisation's App key and the link App's client, each with a copy of its record |
| `<release>-github-links` | people's GitHub links, tokens included |
| `<release>-github-runner-apps` | every runner App, its record beside its keys |
| `<release>-github-catalogue-apps` | every catalogue App, its record beside its keys |

**Back them up** by copying the five objects into a secret manager that
travels with your backups. The chart renders the copy for the two that
nothing upstream can re-deliver: `directory.push` writes the whole of
`<release>-workspace-credentials` and `githubApps.push` the whole of
`<release>-github-apps`, each an External Secrets `PushSecret` of the
entire Secret under one remote key, off until written
([values](../reference/configuration.md#values)). The other three are a
`PushSecret` of your own. Nothing in the service depends on the copy,
and what lands in the store **is** the credential — name a store the
installation already trusts with material of that weight.

**Restore** by putting the five Secrets back into the namespace, with
the labels they carried, before the service starts or before restarting
it. At start it rebuilds every workspace ConfigMap and every GitHub
record that is missing beside a credential, then reopens the
workspaces. A restored workspace shows as never probed until its first
probe; a link token that rotated since the copy means that person links
again; a declared Secret is re-delivered by whatever declared it.
**Restoring from a backup is a rotation** and needs the same restart
([Rotating](#rotating)): writing the good value back is not enough on
its own.

**Without a copy**, a lost workspace credential is recovered by pressing
**Connect** again as the same admin role account — the tenant id matches
and the domains return authoritative after the first snapshot — and a
lost App by *Disconnect* then *Create* on the GitHub page's Apps tab.

A namespace that ran a release before 1.7 still holds one
`<release>-credential-<tenant>` Secret per workspace beside the new one:
start-up copied each in by name and left the old object for a rollback,
and reconnecting or disconnecting that workspace removes it.

## Rotating

**The Secrets and ConfigMaps are a projection, not a live source.**
Nothing in the service watches them: writing a new value into one
rotates nothing on a running pod. Which ones need a restart differs, so
the rule is per object, as `charts/access-issuer/values.yaml` states it:

> `workspace-credentials` — RESTART. The credential is read once, when
> a replica first opens that workspace — at start, or at the console's
> connect ceremony. After that the open reader is held in memory and
> the Secret is never read again. The only thing that drops a reader is
> DISCONNECTING the workspace, which also revokes the credential and
> deletes the snapshot: that is removal, not rotation.
>
> `session-key` — RESTART. Read once while the stores are wired.
> Deleting it is the documented "sign everyone out" lever, and it takes
> effect on the restart, not on the delete.
>
> `github-links` (App) — NO RESTART. The record and its credential are
> read from the API on every use, so a rotated value is picked up by
> the next request.
>
> The silence is the hazard: a rotation that has not taken effect looks
> exactly like one that has, until a restart hours or weeks later picks
> up the new value — or, if the written value was wrong, takes the
> directory down at a moment nobody connects to the change. Measured on
> 2026-09-21: a deliberately corrupted credential went unnoticed for 14
> minutes of normal operation, probes and a successful directory read
> included, and would have gone unnoticed indefinitely.
>
> TO ROTATE a workspace credential or the session key: write the value,
> then restart the Deployment, then confirm from the logs that the new
> value was read ("opened a workspace this replica had not seen" for a
> workspace). RESTORING FROM A BACKUP IS A ROTATION and needs the same
> restart — writing the good value back is not enough on its own.

Per credential:

- **Consent credential:** Reconnect. The old refresh token is revoked at
  Google as part of it, and the replica that served the click opens the
  new reader; every other replica holds its old one, so restart the
  Deployment and confirm from the log.
- **Service-account key, connected through the console:** Upload key
  again with the new JSON; the old one is replaced. Then the same
  restart, for the same reason.
- **Service-account key, declared:** replace the named Secret and
  restart the Deployment — the mounted file is read once, when the
  workspace is adopted at start, and never re-read. Delete the old key
  in Google Cloud only after the log shows the new one was read.
- **OAuth client secret:** update the declared Secret and restart. The
  console cannot set it — `SettingsService` has `GetSettings` and no
  `SetOAuthClient`, because a credential a console can change is one
  somebody can change from a browser — and the sign-in half reads the
  two mounted files once at start. Existing refresh tokens keep working;
  the secret is used only to exchange and refresh.
- **Session key:** delete `Secret <release>-session-key` and restart;
  the service mints a fresh one, and everyone signs in again. Never copy
  it anywhere: there is no `session.push`, deliberately.

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
   acts; its changes appear in the audit trail as `roster.github_member.*`.
4. To stop acting in it, remove the login again. Nothing is undone: the
   organisation is simply left as it is.

If a pass fails, the section says why — an organisation not connected,
an App GitHub refuses, a console that did not answer. A failed pass
changes nothing, and is reported over the last report that had rows, so
the page does not blank while passes fail. A console that answers under
a different policy than the controller loaded — the two restart at
different moments during a rollout — is the same: the pass changes
nothing. It is tried again within seconds rather than next interval,
because the difference usually lasts only until the last replica on the
previous policy has gone: after 5 seconds, then twice as long each time,
up to a minute, six times. A difference that outlasts those retries is not
a rollout — check that every console replica runs the policy the
controller logged at start (`policy` on "the GitHub controller is
assembled") — and the pass, with its retries, comes round again each
interval.

**Needs you on a GitHub organisation:**

- *Not enough seats* — buy the seats the banner names in the organisation's
  billing on GitHub. Nobody is invited past the last free seat.
- *Seats cannot be counted* — the organisation's App lacks organisation
  administration (read). An owner adds it in the App's settings on GitHub
  and accepts it for the installation. An App created from 1.5.0 on asks
  for it already.
- *Removals held* — more than half the organisation would leave in one
  pass. Read the removals; if they are right, press **Confirm**
  (`roster.github_removals.confirmed` in the audit trail). If they are a policy
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
left the organisation (`roster.github_link.lost`, then
`roster.github_member.removed` in the audit trail). Linking again brings it back in on the next pass.

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

access-roster keeps no audit trail of its own. It records into an **audit
installation** ([truvity/audit](https://github.com/truvity/audit)) of its
own, rendered beside it in the same namespace: `audit.writer` and
`audit.query` in the chart. What it records is its
catalogue, [`internal/audit/catalogue/roster.yaml`](../../internal/audit/catalogue/roster.yaml):
sign-ins and their refusals — at the issuer and at the console's own door,
recovery as its own action — token exchanges and GitHub installation tokens
by the kind of proof, refused refreshes, sign-outs and revokes, directory
connects and changes, GitHub Apps created, installed and disconnected, and
what the GitHub controller did to memberships and links.

The installation locks, indexes and signs; retention is its profile's
(`security`, every action, people in clear), not a setting here. Its own
documentation is where to go for the archive, verification and legal
holds.

**The console's Audit page** is the installation's view, shown when
`audit.query` is set. The console forwards the page's calls to the query
service with a token it mints for the person signed in (audience
`audit.audience`), so what anyone sees is decided by the installation's
grants — with the `access-roster` grants preset, groups named
`<scope>:audit:<role>` — and every read is itself recorded there. The policy
must declare the client `audit.audience` names, requiring those groups;
somebody it does not admit is told the page is not theirs. A recovery
sign-in has no address and cannot read the page.

**Every record is also one log line** with `"audit":true`: `audit.id` (the
record's id, which finds it in the installation), `audit.action`,
`audit.outcome`, `audit.actor.kind`, `audit.actor.id`, `audit.subject.id`,
`audit.targets.N` and `audit.reason`. With no installation connected, the
lines are all there is:

```sh
kubectl -n access-issuer logs deploy/access-issuer --since=24h | jq 'select(.audit == true)'
kubectl -n access-issuer logs deploy/access-issuer --since=24h \
  | jq -c 'select(.audit == true and ."audit.outcome" == "denied") | {time, action: ."audit.action", who: ."audit.actor.id", why: ."audit.reason"}'
```

**Where a record came from**, for one a request caused, is its context: the
client address, the user agent, the gateway's `X-Request-Id` and the trace.
The address is the connection's peer unless `audit.forwardedForTrustedHops`
is set, and then the `X-Forwarded-For` entry just left of that many of the
deployment's own proxies, read from the right. Count the proxies that
append: behind an edge that appends the client and a gateway that appends
the edge's connector, it is 1.

**The GitHub controller records for itself**, with its own service
account's token, and the installation stamps it as those records' observer.
Both service accounts must be mapped to the source `roster` in the
installation's `workloadIdentity.workloads`.

### Connecting an installation

1. Deploy the installation and give it the deployment document its
   profiles come from; see its deploy guide.
2. Map this release's service account, and the controller's when it runs,
   to the source `roster` in its `workloadIdentity.workloads`, with the
   audience `audit.token.audience` (default `audit`).
3. Declare a client for the page in the policy — its id is
   `audit.audience`, default `audit` — requiring the groups that may read
   the trail, and trust this issuer in the query service's grants file
   with that audience.
4. Set `audit.writer` and `audit.query`. At start the service registers
   its catalogue on the writer's own address; `audit installation connected`
   in the log says it did on the first try, `audit catalogue registered`
   that a retry did.

### When the installation cannot be reached

**Nothing but a recovery sign-in waits for it.** Every other record goes on
a bounded queue inside the process and is retried with backoff until the
writer takes it; an outage is a delay, and the queue's depth is the signal.
The queue is in memory, so a pod deleted while the writer is down loses what
it held, and past the queue's bound the oldest are dropped and counted. The
log line every record also is remains either way. This is fail-open by
decision: an audit outage must not become an access outage.

**A recovery sign-in fails closed.** Its catalogue entry says `block`: it is
kept by the installation before the sign-in succeeds, and when it cannot be,
the sign-in is refused — a page at the issuer, a 503 at the console's own
door — and the refusal is recorded the ordinary way. The proof was good;
bring the writer back and recover again. There is no override. With no
installation connected at all, recovery is not refused: a deployment that
keeps no trail has nothing to wait for.

**An installation that cannot be reached at start** does not stop the start:
records wait in the queue, and the catalogue's registration is retried until
it answers. **An installation that refuses the catalogue stops the process**,
whether it refuses at start — the start fails, with the problems it gave —
or first answers after an unreachable start, which ends the process the same
way rather than leaving it running for the life of the pod with records
nobody accepts. `just audit-catalogue` finds most refusals before a release
does. **A token the installation does not trust** is said at Error, naming
the token file, and retried: it is a configuration to fix, and until it is
the queue fills and, past its bound, drops.

**The signals**, in the log:

| Line | Means |
|---|---|
| `audit installation connected` (Info) | the address answered |
| `audit catalogue registered` (Info) | it accepted this service's catalogue; records are kept |
| `the audit installation could not be reached; records wait in the emitter's queue, and registration is retried` (Warn) | started unregistered |
| `the audit installation refused the catalogue; records will not be kept until it is fixed` (Error) | the catalogue and the installation disagree; the process ends |
| `the audit installation does not trust this workload's token; …` (Error) | the writer answered 401 or 403: the token file, its audience, or the installation's `workloadIdentity` |
| `audit records could not be delivered yet` (Warn) | the writer refused or could not be reached; the queue holds them |
| `audit record not kept` (Warn) | one record: a `block` record the writer would not take, and the request it was for was refused |
| `audit record dropped and is not in the trail` (Error) | the queue gave one up; its `audit.id` names the Info line that reads as kept |
| `an audit record does not satisfy the catalogue` (Error) | a bug: the code built a record its catalogue refuses |
| `no audit installation is connected: records are validated and logged, and kept nowhere else` (Warn, at start) | the deployment keeps no trail |

and as metrics, from the emitter, pushed over OTLP when
`telemetry.otlpEndpoint` is set: **`audit.emit.records.dropped` is the one to
alert on** — the queue gave up and those records are gone.
`audit.emit.queue.pending` climbing and not falling is a writer gone too
long; `audit.emit.batches.failed`, `audit.emit.records.refused` (a bug) and
`audit.emit.records.written` are the rest.
