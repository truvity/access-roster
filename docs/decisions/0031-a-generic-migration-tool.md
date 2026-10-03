# 0031 — A generic migration tool, and the order of the move

**Status:** Accepted
**Date:** 2026-10-02

## Context

An existing installation holds its state in Kubernetes objects and Valkey. The
target is a NATS key-value store, and later possibly DynamoDB
([0027](0027-the-state-port-nats-jetstream-and-dynamodb.md)). A one-off
converter for each step would be tested once and then kept for a year. The
move must also be undoable: a change of store and a change of runtime together
cannot be rolled back separately.

## Decision

One command, **`access-roster migrate --from <adapter> --to <adapter>`**, copies
the State store from any adapter to any other through the port, and the same
command with a file as one end is the **backup and export**. It is idempotent
(a re-run copies what is missing, never overwrites a newer record) and verifies
by reading back and comparing. Sealed secrets are copied as ciphertext; moving
them to a new key-encryption key is a separate, explicit rewrap.

For an **existing installation** the order is:

1. Kubernetes objects to NATS (`--from kube --to nats`), with the Valkey
   sessions and refresh tokens copied in the same run, so nobody signs in again.
   Blobs go to S3 here.
2. NATS to DynamoDB (`--from nats --to dynamodb`); S3 is untouched.
3. Only then, and as a separate step, move the runtime (the same pods on the new
   adapter first, then the Lambda platform beside them, then the origin switch).

**Data and runtime never move in the same step.** Each step is released and
proven before the next, and the previous store is left in place until the step
after it has been green for a day.

## Consequences

The tool's correctness is the conformance suite's: each adapter is both a source
and a destination in it. A copy is a snapshot, so the step either stops writes
or runs the copy twice, the second time as a delta, and says which in the
runbook.

A temporary legacy adapter over today's objects exists only until the first
step has run, and is then deleted.

## Alternatives considered

**A converter per step.** Rejected: the same code in different clothes, tested
once.

**Dual-write through both stores for a period.** Rejected: it needs the
multi-key atomicity the port deliberately does not have, and a divergence is
silent.

**Move the data and the runtime together.** Rejected: a failure cannot then be
attributed or reverted separately.

## Implementation note (B3-4)

`access-roster migrate --from <config> --to <config>` is built
([the runbook](../operations/migrate.md)). Where this note and the text above
differ, this is what exists.

- **Each end is a `serve` configuration file**, the one the Deployment reads, not
  an adapter name. `store.Open` builds both port sets, and the domain stores come
  from the switch the service makes (`internal/migrate.OpenDomains`): `legacy`
  keeps the ConfigMap and Secret stores, any other adapter the stores on the
  ports.
- **Domain records are copied through the business interfaces**, so a secret is
  opened with the source's Sealer and sealed again with the destination's, the
  item's own key as the binding. This is not "copied as ciphertext": ciphertext
  bound to one store's key cannot be moved to another's key, and the legacy side
  holds none. A copy between two sealed stores is therefore also the rewrap.
- **The issuer's state is copied with the lifetime each record has left.** The
  port's `Get` does not say it, so State and Index have an optional capability,
  `port.StateExporter` and `port.IndexExporter` (memory, NATS and legacy
  implement them; the observed ports keep them). It is what makes "copy Valkey
  sessions in B3" true: a session expires when it would have.
- **A plan, then the copy, then a verification.** The plan writes nothing and
  fails on any destination value that differs, naming the key, unless
  `--overwrite`; `--dry-run` stops after it. A link is the one record no store
  interface can write as it was (every write moves its revision), so the two link
  stores have a `Restore`, and the console's session key a `PutSessionKey`, which
  only a migration calls.
- **The window is the operator's statement, not a switch.** A run that writes
  needs `--i-have-stopped-writers`; the issuer, the console and both controllers
  are scaled to 0. A maintenance flag would have to stop four writers, one of
  which (the issuer) writes on every sign-in; see the runbook.
- **The way back is the same command** with the files swapped
  (`--from new --to old --overwrite`); the legacy adapter, as a destination,
  creates the objects it needs.
- **Not built:** `--backup <file>` and a file adapter (a backup is a copy to a
  second bucket for now), `--from nats --to dynamodb` (it needs the DynamoDB
  adapter; the command is generic and takes it as it comes), and a delta run: the
  copy is a snapshot taken with the writers stopped, as the Consequences allow.
