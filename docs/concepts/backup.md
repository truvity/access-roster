---
title: Backup and restore
description: "What sluis backs up (authoritative state only), what it does not, how archives are encrypted, and how a restore proves and rebuilds the rest."
status: target
sidebar:
  order: 8
---

A backup exists for the day an installation is lost or hostile, and it is deliberately small. sluis backs up the **authoritative state that nothing else can recreate**, and rebuilds everything else after a restore. What goes in and what a restore does follow from each record kind's [origin](/concepts/data/#origins-and-sensitivity) ([ADR 0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#backup-and-restore-by-origin)).

## What is backed up

The backup is a **logical archive**: the backup side reads records through the ports, never through a database, and the restore writes them back through the same ports. The archive is therefore the same on every driver, and it can be restored onto another driver of the same port (rqlite to DynamoDB, for example). Only authoritative, non-recreatable state goes in:

- **operator-set records**: chat channels managed from the console, runtime switches, console-connected tenants, secrets put at run time;
- **durable issued records**: the issued parts of clients (generated secret versions and their rotation metadata), revocations and revocation state, the issuance log, pins (the workspace at first install, the first subject, an App id), account links, approvals and consents, quota balances and top-ups;
- **vendor-issued secrets**, such as a GitHub App key or a chat bot token, which cannot be fetched again;
- the metadata other records depend on, such as the signing ring's public side and the record of which keys were expected.

Secrets are archived **sealed**: the backup side never reads one. The list of what is backed up is generated from the origin and durability annotations of the configuration schema, not written by hand.

## What is not backed up

| Not backed up | Why |
|---|---|
| **Non-extractable keys** (a KMS key, a key on a card) | They cannot leave their store. Their "backup" is the way they were provisioned: the key policy and the [hand-off that certifies a new key](/concepts/keys/#roots-and-certification). A node whose card is lost gets a new key on a new card and a new certificate; it is not restored. A restore checks that each key purpose can still sign and that the public key matches |
| **Declared configuration** | It lives in version control. The archive keeps the resolved document and its digest as evidence, and the restore starts with `sluis config check` against it |
| **Secrets referenced from declared configuration** | The operator's own store holds them. A secret put at run time is operator-set and *is* backed up, sealed |
| **Learned facts** | Directory snapshots and memberships are pulled again from their sources |
| **Derived data** | The search index, quota meters and hourly aggregates are rebuilt from the log |
| **Sessions and refresh tokens** | On purpose: a restore invalidates every one, so a stolen token does not survive it and everyone signs in again |
| **The transport spool** | It holds records not yet written to the log. Cluster peers and witnesses narrow the window; a backup cannot close it |

## The audit log is handled separately

The [audit log](/concepts/audit/) is not copied into the archive. It is the record, and it is protected by its **lock mode**, by the **witnesses** that cosigned its checkpoints, and by its store, readable by a verifier with no help from sluis ([ADR 0016](/decisions/0016-the-audit-log/#retention)). The **search index** is a rebuildable cache: a snapshot of it may shorten a restore and is never evidence.

The archive records its own existence in the audit log: a `backup.completed` record carries the archive's digest and the fingerprints of its recipients. A restore later uses that record to prove where an archive came from.

## Encryption

The archive is encrypted with a fresh data key, and the data key is wrapped for **at least two recipients held apart**, one of them an **offline operator hardware token** for break-glass ([REQ-BACKUP-001](/requirements/backup/#REQ-BACKUP-001), [REQ-BACKUP-020](/requirements/backup/#REQ-BACKUP-020)). The archive is age-encrypted, a named exception to sluis's algorithm rules ([ADR 0012](/decisions/0012-cryptography-and-authority-keys/#named-exceptions)). The offline recipient is a public key, for example an `age-plugin-yubikey` recipient, whose identity sits on a card that is in no node; it lets an operator open an archive when the installation, the cloud account or the node is gone.

- **The key that wraps a backup archive is not the sealing key** ([ADR 0012](/decisions/0012-cryptography-and-authority-keys/#keys-sign-in-place)). On AWS it may live in another account, and only the restore role may decrypt with it. The archive and its key preferably live in a separate account, because the backup exists for the case where the primary account is lost or hostile.
- **Sealed values stay sealed.** When a data key is sealed, an escrow copy of it is encrypted to the archive's recipients ([ADR 0011](/decisions/0011-state-is-one-port-with-compare-and-set/#sealed-secrets)). Losing the sealing key is a restore from those recipients; it needs no ceremony and copies no key out of its store.
- **An archive holds wrapped data only.** It holds no authority key and no sealing key, and its one escrow copy is of the data keys of sealed secrets, never of a company's audit or usage key, so an archive cannot undo a shred ([ADR 0032](/decisions/0032-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#backups)).
- **The backup side holds public material and a wrap permission only**, so a compromised backup job cannot read earlier archives.
- **An installation declares how long it keeps an archive.** An erasure reaches the copies in archives when they expire, and a restore re-applies every shred and erasure that the audit log records after the archive was taken.

The format of the archive (an age-encrypted tar with a manifest and canonical JSON per record kind), the escrow records, the recipients and the plan and refusals of a restore are fixed by [ADR 0034](/decisions/0034-a-backup-is-an-age-encrypted-tar-of-canonical-json-per-kind-and-restores-onto-any-driver/). A restore onto another driver replaces v1's `sluis migrate`.

## Recovery targets

An installation states how much issued durable data it may lose (the recovery point) and how long recovery takes (the recovery time) for the loss of the state, of a bucket and of the region, and a recovery drill measures both. The targets, the installations they cover and the drill that replaces each with a measured figure are decided in [ADR 0056](/decisions/0056-a-regional-outage-is-accepted-public-keys-outlive-it-and-a-drill-measures-recovery/#recovery); this page does not repeat them. The schedule, the number of archives kept and the rehearsal period are declared per installation and have no default. Installations run in one region for now, and a regional outage stops signing there ([ADR 0030](/decisions/0030-tenancy-and-scale-a-boundary-holds-keys-and-a-tenant-is-a-record/#where-installations-run)).

## Restoring

A restore is started by an operator, never by the console, so that it works when `entry` and `signer` are down. It runs as its own actor with its own identity ([ADR 0034](/decisions/0034-a-backup-is-an-age-encrypted-tar-of-canonical-json-per-kind-and-restores-onto-any-driver/#the-restore)). The order follows [ADR 0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#backup-and-restore-by-origin):

1. **Maintenance mode.** Every actor refuses writes and sign-in stops. A failure at any later step leaves maintenance mode on. The restore preview lists every secret written since the archive was taken, with an alarm: audit never carries secrets, so those cannot be rolled forward and have to be rotated or reconnected.
2. **Provenance check.** The archive is accepted only if the audit log has a `backup.completed` record carrying its digest, under a checkpoint that a witness has cosigned where the installation has one. When the log cannot be reached, the operator can override, and the override is recorded first.
3. **Check the configuration** with `sluis config check` against the archived document.
4. **Decrypt.** The restore actor unwraps the data key, or the operator brings the offline token.
5. **Write the records** through the ports. Every member's digest is checked first, and every record is read back afterwards.
6. **Roll forward from the audit log.** For every record kind marked for it, the restore replays the log from the archive's time to the present: operator-set records, revocations, the issued parts of clients, pins, account links, approvals, quota balances (from the usage log) and the issuance log. Their audit records carry the full value apart from secrets, so a revocation made after the last archive is not lost. Each kind has a merge rule, replace or union; tighten-only switches use union, so a restore never loosens one.
7. **Rebuild derived state and learn again.** The indexer rebuilds the search index (or loads a snapshot), quota meters are rebuilt from the usage log, and learned facts are pulled again.
8. **Lift maintenance** only after the read-back is clean. Sessions and refresh tokens do not exist after a restore, so everyone signs in again.

**A witness is never restored to an older state**, because it would cosign a rolled-back view. A restore re-registers the node with its peers and re-bootstraps the witness ([ADR 0016](/decisions/0016-the-audit-log/#witnesses)).

**Certificate serial numbers are random** 128-bit values, so no record of serials has to be backed up, and a restored CA cannot hand out a serial that collides with one issued after the archive was taken.

**Rehearsal.** A scheduled rehearsal restores the latest archive into an empty scratch installation, compares the per-kind counts and digests with the archive's manifest, and records `restore.rehearsed`. Missing rehearsals alarm, like missing backups.

## On each runtime

| Runtime | Backup runs as | Restore runs as |
|---|---|---|
| [bare-metal](/runtimes/bare-metal/) | A systemd timer; on a cluster the lease picks one node | A CLI on one node with the other actors stopped |
| [serverless](/runtimes/serverless/) | A scheduled function. It spools to `/tmp`, so one invocation bounds the archive size | A separate function, invokable only by an administrator or a break-glass role |
| [kubernetes](/runtimes/kubernetes/) | A CronJob | A Job started by the operator, never a CronJob |

The archive's blob driver declares its own dependencies and lock mode. The boards installation keeps its archive and its audit log on Cloudflare R2, whose lock an account administrator can remove, so it also keeps a second, offline copy of the archive.
