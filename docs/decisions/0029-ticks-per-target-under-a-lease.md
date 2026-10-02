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
