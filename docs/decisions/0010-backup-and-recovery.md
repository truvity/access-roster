# 0010 — A backup is a logical archive of the authoritative kinds through the store; a regional outage is accepted and a drill measures recovery

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #1015](https://github.com/truvity/sluis/issues/1015).

## Context

What a backup holds and what a restore does follow from the storage class of each kind ([0004](/decisions/0004-the-data-model/#storage-classes)): config and secrets are written by IaC and live in git and the secret source, temp data may be lost, and only durable kinds that are the source of truth need an archive. Four things are not yet fixed: what the archive holds, who makes it and with which credential, who may open it, and what a restore does to a system that has moved on since.

The forces:

- **The archive is logical.** The backup reads items through the store ([0005](/decisions/0005-the-store/#the-store-api)), never through an engine, so the same archive exists on every engine and a restore may land on another.
- **An installation is lost on its worst day.** The restore must work when the primary account, the KMS key or the node is gone, with tools that exist outside sluis ([principle 4](/principles/#4-verify-never-trust-a-claim)).
- **Keys never leave their store** ([principle 1](/principles/#1-a-key-is-born-in-its-store-and-never-leaves-it)). A data key is not an authority key: it protects values, and its wrap in the archive is the way to open sealed values after every card or KMS key is lost.
- **The job that makes the archive holds a bucket credential,** so it is a credential holder. It is exporter@, with a write-only credential, and it opens nothing ([0009](/decisions/0009-export/)).
- **Public texts expect the same.** DORA, Article 12, asks for backup, restoration and recovery procedures that are tested periodically, and for a restore on ICT systems physically and logically segregated from the source system (Article 12(2) and (3)). The ECB cloud guide (July 2025, section 2.2.1) recommends that the risk assessment consider storing backups on segregated systems, and counts tests validated for accuracy, completeness and practicality as good practice. DORA binds the regulated customer and the guide guides it; neither binds sluis (read 2026-11-03).
- **There is no number yet.** No page states a recovery time or point, and no restore has been timed ([principle 9](/principles/#9-measure-before-deciding-and-date-the-measurement)).

## Decision

### What the archive holds

- **An archive is a logical copy of the authoritative kinds, read through the store.** A kind is in the archive when the kind registry marks it backed up: durable kinds that are the source of truth. Config, secret and temp kinds are not, and neither is `MaintenanceMode`. A new kind appears in the next archive without a change to the backup job.
- **Sealed values stay sealed and hashed values stay hashes.** The job reads the items as the store holds them. It opens nothing, and the store opens nothing ([principle 18](/principles/#18-plaintext-lives-only-where-it-is-used-behind-two-independent-checks)).
- **DataKeyWrap is included.** The wraps are ciphertext: each data key wrapped for a card or a KMS key, and for the recovery recipient ([0006](/decisions/0006-keys-and-sealing/#datakeywrap)). With the archive, the recovery recipient opens every wrap when all cards and KMS keys are lost. No authority key and no wrapping key is ever in an archive.
- **The archive is one tar, encrypted as a whole with AES-256-GCM under the archive key** ([The archive key](/decisions/0010-backup-and-recovery/#the-archive-key)). Its byte format is specified on a reference page with test vectors, so a tool outside sluis can open it once the archive key is unwrapped. The tar holds a manifest and one file per boundary and kind. The manifest is canonical JSON and names the archive format version, the release that wrote it, the boundary, the time, the digest of the config snapshot in force, the schema version, the count and SHA-384 digest of every kind's file, and the fingerprints of the recipients. A kind's file is one item per line in canonical JSON (RFC 8785), sorted by address, so the same state yields the same bytes.
- **The backup is a job of exporter@** ([0009](/decisions/0009-export/)). It runs on a schedule under a lease ([leases](/decisions/0005-the-store/#leases)), and writes the archive to a bucket destination with a **write-only credential**: it can add an object and cannot read, replace or delete one. The bucket, the schedule, the restore role, the offline recipient and how long an archive is kept are declared in one config kind, `BackupPlan`. The configuration check refuses a production installation that declares no schedule or no retention, because a default would be a number no principle can justify.
- **The audit log is not archived with the state.** It is protected by its lock mode, its witnesses and its own store ([0029](/decisions/0029-the-audit-log/#retention)), and a copy would be a second, unlocked place for evidence.
- **Each archive is announced in the audit log.** The fact `backup.completed` carries the archive's digest and the recipients' fingerprints. A restore uses it to prove provenance.

### The archive key

- **Every archive has its own archive key,** an AES-256-GCM key made for the moment of writing under the key purpose `backup-archive`, which is enabled on use ([key purposes](/decisions/0006-keys-and-sealing/#key-purposes)). exporter@ wraps it and never holds a key that opens an archive.
- **On AWS** key@ calls `GenerateDataKey` for exporter@ under the archive key, a dedicated KMS key enabled on use that may live in another account, and the wrapped copy goes in the archive's header. Only the restore role may unwrap it ([keys on AWS](/decisions/0006-keys-and-sealing/#keys-per-boundary-on-aws)).
- **On boards** key@ gives exporter@ public keys only. The archive key is wrapped by ECDH P-384 for the key-agreement public keys named in the plan, in the scheme of a data key wrap, so the job can wrap the key without being able to unwrap it ([keys per board](/decisions/0006-keys-and-sealing/#keys-per-board)).
- **Every archive is wrapped for the restore role and for an offline recipient.** The offline recipient is the recovery recipient ([0006](/decisions/0006-keys-and-sealing/#the-recovery-recipient)). The two are held apart, and the configuration check refuses a production plan with fewer than two. A board archive restored on AWS needs the recovery recipient's rewrap, because no KMS key can unwrap an archive key that was wrapped for a card.
- **The archive and its recipients live apart from the installation's account where they can.** An archive that lives with the thing it protects is lost with it.

### Restore

- **A restore is started by an operator and by nobody else.** It is the command `sluis restore` of store@, run under its own restore identity, never by the console and never by a work actor, so it works while `entry` and `signer` are down.
- **Maintenance mode comes first.** store@ writes `MaintenanceMode`, which refuses writes and stops sign-in, survives a crash, and is lifted only after a clean read-back, so a failed restore stays in maintenance.
- **The provenance of the archive is checked** against the `backup.completed` fact under a witnessed checkpoint of the audit log: the digest and the recipients' fingerprints must match.
- **A restore has a plan.** Without `--apply` it reads the archive, checks the manifest and the digests, lists the kinds and counts, lists the secrets created since the archive was taken, and writes nothing. With `--apply` it refuses a destination that already holds items of the restored kinds unless `--overwrite` is given. A restore into an empty target is also what a segregated restore needs.
- **The restore writes back through the store and reads back.** It writes through the target's store, so the target may use another engine than the source (rqlite to DynamoDB, a board to a Lambda installation). It is the one named exception to one writer per kind ([One writer per kind](/decisions/0004-the-data-model/#one-writer-per-kind)). The manifest's schema version decides how each kind is read; a kind written by release N is read by N and N+1 ([0015](/decisions/0015-evolution-and-compatibility/#n-and-n-1-inside-a-major-version)), and an older archive is restored in two steps through the release in between. The read-back compares counts and digests with the manifest.
- **Everyone signs in again.** Sessions and codes are temp kinds and are not in the archive.
- **Secrets newer than the archive are listed for rotation.** A secret created after the archive exists at its provider and not in sluis; the plan and the end of the restore list them, from the audit facts, so the operator rotates them.
- **A restore never touches its source.** The old installation stays as it was, so a rollback is pointing back at it. There is no separate migration command: moving state between engines or installations is a backup and a restore.
- **Recovery objectives are in [The drill](/decisions/0010-backup-and-recovery/#the-drill).**

### Roll-forward

- **After the write-back the restore rolls forward from the audit log.** The archive is as old as its time; the audit log is not. The restore reads the audit facts since the archive's time and applies them by the **merge rule of each kind**, declared with the kind in the registry.
- **A tightening is never undone.** A revocation, a switch turned on, a hold, a shorter lifetime and a suspension made after the archive are applied again ([principle 12](/principles/#12-a-loosening-is-temporary-a-tightening-is-durable)). A loosening made after the archive is not applied again; it expired or is made again by its owner.
- **Every shred and erasure recorded since is applied again before maintenance is lifted.** A restore does not bring back an erased person or a shredded tenant ([Tenant lifecycle](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)). An archive taken before a shred holds the tenant's wraps until it expires, so erasure reaches archives by replay and by expiry; the archive retention is the longest time an erased value can exist in a copy.
- **Maintenance is lifted last,** after the replay and the read-back.

### Residency

- **The allowed set of regions is declared, and a region guard refuses a table, a bucket, a queue, an index or a key replica outside it,** at load and at deployment. An installation's set is its declared region and one other region in the same jurisdiction, which holds the replica of the boundary's symmetric key and the copy of the archive.
- **Signing keys are single-region keys.** A multi-Region key copies key material to another region, against [principle 1](/principles/#1-a-key-is-born-in-its-store-and-never-leaves-it); only the symmetric key is replicated, for loss protection ([principle 2](/principles/#2-trust-is-layered-and-redundancy-is-not-a-defence-against-compromise)).

### A regional outage

- **A regional outage stops signing in that region, and this is accepted.** KMS is regional and a software key fallback is refused in production ([floors in code](/decisions/0006-keys-and-sealing/#floors-in-code)). There is no standby region and no failover in the first installation: new sign-ins and signing wait for the region.
- **Public key material outlives the outage.** The discovery document and the key set are public static documents served through a content delivery network with a stale-if-error window ([0009](/decisions/0009-export/#destinations)), so tokens already issued keep verifying while the region is down. They stay valid until they expire. Public material has no residency.
- **A rebuild in a second region needs new intermediates** through the hand-off ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)), so the time to rebuild is not a figure until a drill has measured it.

### The drill

- **An installation publishes its recovery point and recovery time and proves them.** For the loss of the state, of a bucket and of the region it states how much durable data may be lost and how long recovery takes. A recovery drill measures both: at least once a year and after any change to the backup or restore path. The result is published with its date and versions.
- **The drill is a rehearsal restore** into an empty scratch installation, from the archive and the offline recipient alone. It compares counts and digests with the manifest and records the fact `restore.rehearsed`.
- **The targets before the first drill are decided** (2026-11-02). Each is a target and not a measurement, and the first drill replaces it with the measured figure. No page promises a recovery time that no drill has measured. They cover the customer-identity installation and the serverless workforce installation. The boards installation is best effort and states no target until a drill has measured one.

  | Loss of | Recovery point | Recovery time |
  |---|---|---|
  | The state | 5 minutes | 4 hours |
  | A bucket | 24 hours, the interval between archives | 8 hours |
  | The region | no figure until a drill measures it | no figure until a drill measures it |

## Consequences

- One tool covers disaster recovery and a move between engines. A move needs a window with writes stopped, which an online copy would not need; the cost is paid once per move.
- The archive is encrypted in the FIPS-approved set under a key of its own, and a stock `age` no longer opens it; the format has a reference page with test vectors. On AWS the archive key is a seventh KMS key, enabled where backups are taken, and the baseline of 1 + 5 stays.
- The archive is readable by whoever holds the restore role or the recovery recipient, so their custody is as sensitive as the keys themselves. The offline recipient is the way in on the worst day.
- Erasure reaches archives by replay and by expiry, not at the moment of the shred. The archive retention is declared and bounded for that reason.
- A restore needs the audit log to roll forward, so the audit log and the state do not share a single point of loss.
- The canonical form costs a sort and a canonicalisation per item at backup time; it buys a stable digest and archives that compare byte for byte.
- A drill costs a day of work and a restore environment each year, and it is the only way the published figures become true.
- A regional outage is felt as no new sign-ins until the cloud restores the region. The first customers accept that; the day they do not, a second region is a consumer and a new decision.

## Roads not taken

- **A physical backup of each engine (a database file, a table export).** It is tied to one engine and cannot move to another, and a restore would trust the engine's own format.
- **A fifth holder, `backup@`, in the data family.** Least privilege per job, but a fifth unit in every installation for one scheduled job.
- **store@ writes the archive itself.** No new unit, but store@ would get a bucket credential and an outbound path and mix serving with archiving.
- **Backup and restore as work actors.** A work actor would hold a bucket credential and the restore identity, against principle 16.
- **Keep a separate `sluis migrate` command.** Two writers of items through the store would double the tests and the failure modes; the restore already has a plan, a read-back and a refusal to overwrite.
- **`age` for the archive.** Stock tools read it, but X25519 and ChaCha20-Poly1305 are outside the approved set, and the offline recipient is a P-384 key, so a second offline key would be needed.
- **The archive key made under the boundary's symmetric KMS key.** The restore role would become a second principal on the key that only key@ may use, and the key would be lost with the account.
- **Escrow by splitting a key (Shamir shares) or a ceremony.** It moves a key out of its store (principle 1) and needs people in a room (principle 7); a data key wrapped for an offline recipient does neither.
- **One recipient.** One lost token or one compromised account would make the archive unreadable or open.
- **Archive the audit log with the state.** A second, unlocked copy of evidence.
- **A default schedule and retention.** A default would be a number no principle can justify, and a wrong one is found only on the day of a restore.
- **Replay from the audit log alone, with no archive.** Audit facts name changes, not full state, and the log is not a store.
- **A multi-Region signing key for failover.** The key material would live in two regions, against principle 1, and its policy would have to be kept equal in both.
- **A standby region from the start.** Money and operations for an outage no customer has asked to survive.
- **Public documents served only from the region.** Every relying party would fail verification during an outage that tokens already issued could ride out.
- **Recovery figures from the provider's documentation.** The restore time is a property of the size of the state and our order of restore, which only a drill measures.
- **A stated target for the boards installation.** It runs on small computers its operator owns, and a figure would be a promise that nothing measured backs.
- **No stated objectives until a customer asks.** A customer-facing installation has customers on the first day, and an unstated objective is a promise nobody can hold.

## Follow-ups

- The first recovery drill, its published result and the replacement of each target by the measured figure: [#1142](https://github.com/truvity/sluis/issues/1142).
- Build of the backup job and of `sluis restore`: [#834](https://github.com/truvity/sluis/issues/834) and [#835](https://github.com/truvity/sluis/issues/835).
- The region guard: [#1061](https://github.com/truvity/sluis/issues/1061).
