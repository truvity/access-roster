# 0029 — Ticks per target, under a lease

**Status:** Accepted; applies [0024](0024-reconciler-rails-are-shared-pieces-not-a-framework.md)
**Date:** 2026-10-02

## Context

The two reconcilers poll: each pass walks every workspace or organisation, and a
change is noticed by a mounted directory's digest changing. They run as one
replica with a recreate strategy and no lease, because two would write the same
objects. Slack Connect channels are shared by two workspaces, and the host and
guest sides currently learn of each other by both polling. Neither shape fits a
function that lives for one invocation.

## Decision

A reconciler's unit of work is **`Tick(ctx, target)`**: one Slack workspace or
one GitHub organisation. It runs under a **lease** taken from the State port
([0027](0027-the-state-port-nats-jetstream-and-dynamodb.md)), per target, so
that two replicas on Kubernetes divide the targets between them and a second
invocation on Lambda finds the first still running and returns.

A **Trigger port** says that a target has something to do and replaces polling a
mounted directory's digest: a **key-value watch** on Kubernetes, an
**asynchronous `lambda:Invoke`** on AWS. A periodic schedule is still there
(EventBridge Scheduler, or the loop on Kubernetes) as the backstop.

- **Reports are per target.** Each tick publishes its own status report, so no
  tick rewrites another's.
- **Slack Connect is an explicit handoff.** When the host creates or changes a
  shared channel it writes a **pending-share record**, which enqueues the guest's
  tick; the guest accepts on its own tick and records the outcome. Neither side
  calls the other's workspace.
- **Shared inputs are cached by the policy digest**: the answers to "who holds
  this group" and "what is true of this address" are read once per digest and
  reused by every tick that runs under it, in this process or from the store.
- **The guest-side probe moves into the host's tick**
  ([0023](0023-guest-side-probe-only-for-managed-slack-connect-channels.md)
  still decides when it is asked: only for managed Slack Connect channels).

This is **a port, not a framework**, consistent with
[0024](0024-reconciler-rails-are-shared-pieces-not-a-framework.md): it names the
unit of work and the two things around it, a lease and a trigger. It adds no
reconciler interface, no shared pass skeleton and no shared row, action or status
type; the two reconcilers keep their own decisions, audit records and metrics.

## Consequences

Reconciliation latency on a change falls from a polling interval to a watch
event or an invocation, and a reconciler can be scaled by running another
replica. The breaker, the held-once ledger and the last-good report remain per
target and are kept in the State store.

A lease can be lost mid-tick: a tick must be safe to run twice to the point
where it checks it still holds the lease before each external write, and a write
it cannot make idempotent is guarded by the same recovery marker as in 0027.

## Alternatives considered

**Leader election for the whole controller.** Rejected: one replica works while
the other waits, and it has no Lambda counterpart.

**A work-queue framework with typed jobs.** Rejected for the reason in 0024: a
shape guessed from two systems.

**Keep polling directory digests.** Rejected: a Lambda has no mounted directory,
and the digest was a stand-in for a change notification.

## Implementation note (2026-10-03)

**What landed**, on the ports of [0027](0027-the-state-port-nats-jetstream-and-dynamodb.md)
and the legacy adapter, with nothing stored that today's storage cannot hold:

- `Tick(ctx, target)` on each controller: an organisation or a workspace, and
  for GitHub the people's link check as a target of its own, `github:links`. A
  tick publishes its own report only (`rails.Journal.PublishOne`, a one-entry
  write through the Blob port), and a sweep prunes the reports of targets the
  policy no longer has. `access-roster tick <github|slack> <target>` runs one
  tick once.
- A lease per target from the State port (`rails.Leases`): `Create` with a
  lifetime, renewed by `Update` with the revision it holds, released by
  `DeleteIfRevision`; the tick's context ends when the lease is lost or cannot
  be renewed for a lifetime. The keys are `lease.github-tick:<org>`,
  `lease.github-links:all` and `lease.slack-tick:<workspace>`, which the legacy
  adapter maps to the hub's `{target}:lease:<kind>` slot. `controller github|slack`
  is the loop that sweeps the targets under their leases.
- A notification ticks its target: the controller subscribes to the Trigger and
  an operator's request (read from the mounted records) notifies only its target.
  The 30-second look at the mounted records remains the fallback, since the
  legacy trigger is in-process and the console and the controllers are not.
- The shared once-per-pass inputs of the Slack controller are computed in one
  place and cached in memory by the policy digest and what is mounted.
- Slack Connect: the host's tick notifies the guest's when it invited, or sees
  an invitation waiting; `probeGuestSides` is the host's tick's, reading the
  guests' reports from the Blob port and publishing what it finds in the host's
  report (`guest_sides`).

**The one-shot `tick` refuses without a shared State.** With the legacy adapter
the controllers' leases are in the process's own memory, so `access-roster tick`
would not be excluded by the running controller and both could act on one
target. It refuses, saying so, unless `--unsafe-local-lease` is given (for an
operator who has scaled the controller to 0); with a shared State it behaves as
described. It becomes safe by default once the State is shared (B3).

**What waits for B3**, because it needs key families the legacy adapter cannot
hold: the **pending-share record** (`share.`) as the hand-off, so the guest is
notified through the store and not through a process-local notification (until
then the notification is a hint, and the sweep every interval is the backstop);
the **State-backed shared-input cache** (`cache.`) and the breaker and held-once
ledger in the store (`gate.`); a **key-value watch** that replaces the polled
look at the mounted records; and **two replicas**, which need a State both pods
share (a controller has no Valkey to name today, so its leases are held in its
own process and the chart stays at one replica with `Recreate`).

## Implementation note (B3-3)

**The hand-off landed**, with the domain stores on the ports
([ports.md](../design/ports.md#the-domain-stores)), for any adapter but
`legacy`:

- **The pending-share record** `share.<host>.<channel>` is the hand-off. The host's
  tick writes the guest's side `pending` after Slack accepted the invitation, and
  the write asks the guest's runner to tick through the Trigger (on NATS that
  crosses processes); the guest's tick accepts and marks its side `accepted`; the
  host reads it. 14 days while pending, 7 once every guest has accepted. The
  process-local notification stays as the hint and as the fallback when the write
  fails, and the sweep stays the backstop. Tested with the host and the guest as
  separate controllers over separate connections to one NATS bucket.
- **The `users.info` lookup** of `Observe` is cached on the State for 24 hours
  (`cache.slack.user.<workspace>.<id>`), shared by every runner and counted.
  What a decision rests on (who the token is, the account of each address, the
  channels and their members) is still read from Slack every pass.
- **The controllers read the records from the State**, not the mounted files: the
  GitHub controller its organisations' credentials, the link App and the
  operators' requests; the Slack controller its workspaces, shared and console
  channel records, confirmations and requests. A poll of the records' revisions
  replaces the poll of the mounted files' content, so a changed record still runs
  a pass and a request still ticks only its target; a key-value watch is the
  remaining step.
- **A link's refresh is one compare-and-swap of one key.** The marker write
  that precedes the exchange is the claim on the single-use refresh token, so two
  replicas never spend it twice; the loser re-reads and uses the winner's pair.

**Still waiting:** the gates of the breaker and the held-once ledger in the
store (`gate.` is used for confirmations, requests and the link claim's marker,
not yet for the ledgers, which stay in the report), and the **shared inputs
cache** (`cache.<digest>.<name>`), which stays in memory: it is a graph of the
controller's own types that one round of calls to the console rebuilds, and
serialising it is not cheap. Two replicas of a controller now need only the NATS
State, the S3 Blob and the KMS Sealer in `ports`; the chart still ships one.
