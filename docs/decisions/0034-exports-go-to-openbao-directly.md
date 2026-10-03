# 0034 — Exports: the service copies its secrets into OpenBao itself

**Status:** Accepted; extends [0028](0028-nothing-writes-configmaps-or-secrets.md)
and supersedes the part of truvity/gitops ADR-034 §9 that says the issuer never
calls OpenBao and a PushSecret copies
**Date:** 2026-10-03

## Context

[0028](0028-nothing-writes-configmaps-or-secrets.md) moved every secret the console
writes out of Kubernetes Secrets and into State, sealed. That broke something it
mentioned only in passing ("pushing a catalogue App's token to a secret store for a
consumer is a separate output and is unchanged"): the **copies**.

A program that acts as an App cannot always ask the service for a token when it
runs. Alertmanager posts to Slack as the bot, a runner scale set registers with its
GitHub App, an infrastructure apply reaches for a credential before anything else.
Five more copies are disaster-recovery backups, so that a lost State is not a lost
installation. The estate made all of these with External Secrets `PushSecret`s that
read the Kubernetes Secrets the service wrote and wrote them into OpenBao, where the
consumers read them. gitops' ADR-034 §9 states the rule: the issuer never calls
OpenBao, a PushSecret copies.

With no Secrets written, a PushSecret has nothing to read, and the copies freeze at
the last value the Secrets held. A rotated bot token, a newly installed runner App,
a reconnected workspace never reach OpenBao; the consumers keep working on the old
one until it stops.

## Decision

**The service writes the copies itself, through a new port.** OpenBao stays the place
the copies live; what changes is who writes them.

**The port.** `port.Export` (`internal/port/export.go`) has two calls: `Put(ctx,
target, properties, mode)` and `Delete(ctx, target)`. A target is a path and an
optional store namespace. The mode is **replace** (the key holds exactly the given
properties: a whole-secret copy) or **patch** (the given properties are set and every
other property of the key is left: a per-property copy into a key several writers
share). A `Put` of no properties is refused, so a source that read nothing never
empties a copy. Both modes are idempotent.

**The adapters.** `memory`, for tests and the conformance suite, and `openbao`, a KV
version 2 mount over the HTTP API with no SDK:

- **Replace** is `POST data/<path>`. **Patch** is `PATCH data/<path>` with a JSON
  merge patch, which the server applies atomically, and a `POST` for a key that does
  not exist yet.
- Both **read the key first and write nothing when it already holds what would be
  written**, so the hourly reconcile makes no new KV version and still puts back
  what somebody changed.
- **Login** is `POST auth/<mount>/login {role, jwt}`, inside each namespace written
  to (a login in a namespace opens a token for that namespace alone). Two methods
  share it: `kubernetes`, with the pod's ServiceAccount token, and `jwt`, with a
  token read from a file, afresh on every login: a projected ServiceAccount token on
  Kubernetes, or the web identity token AWS issues a Lambda by outbound federation
  (`sts:GetWebIdentityToken`), whose function runs in the same network and reaches
  OpenBao through the internal load balancer. The adapter also takes a `TokenSource`
  function, which is how a Lambda plugs that token in without a file. The CA bundle
  is configurable. The session token is kept until 80% of its lease has passed, and a
  403 costs one new login before it is believed.
- An error names the method, the path, the status and the server's own error text,
  and never a value or a token.

**The configuration.** `ports.export` names the adapter and the OpenBao to reach.
`exports:` is a list; each entry names what is copied and where:

| `source` | Copies | Written as | Mode |
|---|---|---|---|
| `slack-app` (`app`) | a catalogue Slack App's bot token | `bot_token` | patch |
| `github-app` (`app`) | a catalogue GitHub App | `app_id`, `installation_id`, `private_key` | patch |
| `runner-app` (`tier`, `org`) | a runner App | `github-app-id`, `github-installation-id`, `github-private-key` | patch |
| `bundle` (`bundle`) | one of `workspace-credentials`, `github-apps`, `github-links`, `github-runner-apps`, `github-catalogue-apps`, whole | the Secret's entries, one JSON document each | replace |

The property names are the ones the PushSecrets wrote, so a consumer sees no change.
An optional `properties` map writes only some of an App's properties, under names of
the deployment's choosing. The bundles are what the Kubernetes Secret of that name
held, **byte for byte** (a test builds both from the same data and compares them),
so the restore procedure written for the Secrets restores from them.

The list is validated at start, before anything is served: an unknown source, a field
the source does not take, an App or tier the deployment does not declare, two
exports that would write one key (unless both patch it and share no property), a
name used twice, a path that is not one key. An export whose store this deployment
does not keep (the memory store, a demonstration) is refused.

**The semantics, which are 0028's and ADR-034 §9's intent kept:**

- **A copy is a copy, asynchronous, and never a dependency.** An export runs after
  the State write that changed its source has committed, in its own goroutine, and
  nothing waits for it. Sign-in, a tick and a console action neither wait for it nor
  learn of its failure. An OpenBao that is down, or a login its role refuses, changes
  nothing live: the copy is stale until the next attempt. The service starts with
  OpenBao down: nothing is contacted at start.
- **Retried with backoff, counted, logged.** A failed attempt is retried after 5
  seconds, doubling to 5 minutes, with jitter. Each attempt is counted by export and
  outcome (`ok`, `failed`, `skipped`), the last success is a gauge, and a failure is
  a warning that names the export and the target and never a value.
- **Nothing to copy is not a failure and is not written.** An App that is created and
  not installed has no token and no installation; a bundle with nothing in it is
  empty. The attempt is `skipped`, the key is not touched, and a copy is never
  replaced by the absence of its source.
- **Re-exported on change, at start, and every interval.** Every export is made once
  at start (a reconcile), again when a key under its source's State prefixes changes
  (a watch, settling for two seconds and not more than once in 30 seconds, because a
  link's tokens rotate on every refresh), and again every `interval`, an hour by
  default, as the old refresh was. Where the State cannot be watched, the interval
  alone is the backstop, and the log says so.
- **Exactly one writer.** Each export is made under a lease on the State
  (`lease.export:<name>`, the machinery of [0029](0029-ticks-per-target-under-a-lease.md)),
  so two replicas divide the exports and a second finds the first still at work and
  leaves. Because an identical write changes nothing, two writers on a State that is
  not shared are harmless.
- **Never deleted.** The runner never calls `Delete`. A copy whose source is gone, or
  whose declaration was removed, stays until somebody removes it: a copy that leaves
  with its source is not a backup, and a removed declaration must not break a
  consumer from a distance. The port has `Delete` for a person's tool.

**The chart** renders `config` as it stands, and adds only what is not config: a CA
bundle in a ConfigMap and a projected token, mounted where the config's `caFile` and
`auth.tokenFile` must say (the chart refuses another path), two alert rules and a
dashboard row. Its `push` values (`slackApps[].push`, `directory.push`,
`githubApps.push`, `githubApps.catalogue[].push`, `slackState.push`) are kept for the
`legacy` storage, which is the one that still has Secrets for a PushSecret to read,
and are **deprecated**: they render only with `config.store: kubernetes`, and fail
the render otherwise, so a State-backed deployment could never use them.

**What stays outside.** The Slack state recovery copy (`slackState.push`) has no
export yet: its Secrets are `ws.slack.*` and `rec.slack.*`, and an owner who wants
them copied adds sources the same way.

## Consequences

- **OpenBao policy.** The role the service logs in as needs `read`, `create`,
  `update` and `patch` on `kv/data/<prefix>/*` in each namespace it writes to, and
  nothing else: never `list`, never `delete`. `patch` is the new capability a
  PushSecret's policy did not carry. The `kubernetes` and `jwt` roles are bound to
  the service's ServiceAccount (or, on AWS, to the function's role) alone.
- **Who owns a key.** External Secrets refuses to overwrite a key that does not carry
  its `managed-by` mark, and stamps it on every key it writes. The service writes data
  and not custom metadata, so a key an old PushSecret created keeps its mark and one
  the service creates has none. Delete the PushSecrets in the same change that turns
  the exports on, or in this order: turn the exports on, see them `ok`, delete the
  PushSecrets. Both writing the same bytes is harmless; the two cannot disagree for
  long, and the one that is left is this one.
- **A new place secrets are held in process.** The service already holds each of
  these in memory to act as it. A copy in OpenBao is what it was before: in the blast
  radius of the App, rotated as the App is rotated.
- **The sealed State is still the source of truth.** A copy is a convenience for a
  consumer and a backup for the operator; losing it loses nothing, and the next
  reconcile makes it again.
- **A stale copy is silent without the alerts.** `AccessRosterExportFailing` and
  `AccessRosterExportStale` say it. An export that has never succeeded has no
  last-success series, which is why the failing rule exists.
- **Not covered:** a key written by a PushSecret that is still running at the same
  time is not detected; an OpenBao policy that is wrong shows as a failure and not at
  start (nothing is contacted at start); and the Slack state recovery copy, above.

## Alternatives considered

**Keep the PushSecrets and keep writing Kubernetes Secrets for them.** Rejected:
it is what [0028](0028-nothing-writes-configmaps-or-secrets.md) removed. The RBAC to
write Secrets, the Secret as a second copy of every credential, and no counterpart
on Lambda.

**A second controller that reads State and writes the Secrets, for the PushSecrets
to copy on.** Rejected: it keeps every cost of the Secret (a plaintext copy in
etcd, a hop, a second thing to run) to avoid one HTTP call.

**Write the copies in the same code path as the console action, synchronously.**
Rejected: it puts OpenBao on the console's path and on the sign-in path of anything
that creates an App, which is exactly what [0028](0028-nothing-writes-configmaps-or-secrets.md)
and ADR-034 §9 refused.

**Let the consumer read the sealed State.** Rejected: Alertmanager and ARC would need
the Sealer's key and the State, and the point of the copy is that the consumer holds
one path and one credential.

**Use the OpenBao Go client.** Rejected: five requests do not justify the dependency
and its transitive weight, and the adapter's behaviour (a merge patch, a read before
a write, one login per namespace) is easier to hold to a fake in `go test` than to a
client library's.
