# 0027 — The State port: NATS JetStream on Kubernetes, DynamoDB on AWS

**Status:** Accepted; supersedes the store statement in
[design/access-roster.md](../design/access-roster.md#the-store) ("plain
Kubernetes objects … no cloud parameter store, no cache") once the migration
in [0031](0031-a-generic-migration-tool.md) has run
**Date:** 2026-10-02

## Context

State is spread over three places with three failure modes. Records and
credentials are Kubernetes ConfigMaps and Secrets. Sessions, refresh tokens,
codes, the signing-key schedule and the directory snapshots are in Valkey. The
reconcilers' reports and ledgers are ConfigMaps again. None of this runs on
Lambda, and two of the three cannot be shared by two replicas without a lease
nobody wrote.

Valkey is the weak one. Its replication is asynchronous: a primary can
acknowledge a write, fail, and be replaced by a replica that never saw it. For
a cache that is a miss. For sessions and refresh tokens it is a failure with a
name: **everyone is signed out**, and a refresh token that had been rotated
comes back to life or vanishes.

## Decision

Everything that is not a blob goes behind one **State port**, with two adapters:

- **NATS JetStream key-value (replicated three ways)** on Kubernetes.
- **DynamoDB, one table,** on AWS.

An in-memory adapter serves tests and a single local process.

The port works on **one key at a time**: get, put, create-if-absent,
compare-and-swap by revision, delete-if-revision, a lifetime (TTL), listing by
prefix, and watch. It has **no multi-key transactions**; neither engine offers
them under the same terms. A flow that touches several records is written as
idempotent steps with a recovery marker, the way the GitHub refresh already is:
the link records `RefreshingSince` before the token pair is refreshed and clears
it after the new pair is kept, so a crash between reads as "refresh unfinished"
and not as "authorization revoked". A GitHub token pair is one item, so it is
replaced whole.

**Reads always filter on expiry.** DynamoDB removes an expired item lazily,
sometimes a day late, so an adapter that trusted the store to have deleted it
would serve a dead session. The port returns "absent" for an expired record
whatever the engine did.

**Key layouts need no secondary index.** Everything a caller looks up is either
the key itself or a prefix: sessions are `ses.<person>.<sid>` (DynamoDB:
partition `SES#<person>`), and a pointer `sid.<sid>` maps a session id to its
person. The full table is in [design/ports.md](../design/ports.md).

**Blobs go to S3 on both platforms:** the reconcilers' status reports and the
directory snapshots. They are too large for an item and are read whole.

**Valkey is retired.** Its sessions and refresh tokens are copied into the new
store by the migration tool, so nobody has to sign in again.

## Consequences

Two stores replace Valkey and the Kubernetes objects; an installation that runs
neither NATS nor AWS must provide one of them. Durability on Kubernetes is the
JetStream quorum's: the stream's sync interval is part of the installation's
review, because acknowledged writes should not wait on a lazy flush.

Dropping transactions costs design effort at each multi-step flow and nothing
at run time. A step that cannot be made idempotent is not ready to ship.

A later adapter (for example PostgreSQL) must pass the same conformance suite
and nothing else.

## Alternatives considered

**Keep Valkey, add Sentinel or a synchronous wait.** Rejected: `WAIT` narrows
the window and does not close it, and it is a second cluster to run beside the
one that already needs quorum.

**Kubernetes objects as the store.** Rejected: churn on the API server for
session-rate writes, no TTL, and no equivalent on Lambda.

**DynamoDB on both.** Rejected: it forces an AWS dependency on an installation
that has none, and a local emulator is not the engine.

**PostgreSQL on both.** Deferred, not rejected: it fits the port, but nothing
here needs a relational engine, and it is a run-time dependency on Lambda that
needs a connection pool.

**Multi-key transactions in the port.** Rejected: DynamoDB's are bounded and
priced per item, JetStream has none, and a port that promises them would be
satisfied by only one adapter.
