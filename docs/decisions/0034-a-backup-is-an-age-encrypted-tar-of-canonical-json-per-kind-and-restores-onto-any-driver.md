# 0034 — A backup is an age-encrypted tar of canonical JSON per record kind, with two recipients, and a restore writes it onto any driver

**Status:** Accepted
**Date:** 2026-11-02

Proposal: [issue #1015](https://github.com/truvity/sluis/issues/1015).

## Context

What a backup holds and what a restore does follow from the origin of each record kind ([0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#backup-and-restore-by-origin)), and the explanation page [Backup and restore](/concepts/backup/) walks through the steps. Three things are not yet fixed: the format of the archive, how the escrow copies of data keys are made and carried, and what happens when the target of a restore has other drivers than the source. v1 had a separate `sluis migrate` command to copy state between stores, with a plan, a dry run and a read-back check (v1 ADR 0028 and the v1 backup reference, on `master`; parity row [#804](https://github.com/truvity/sluis/issues/804)). It also had a backup module and a restore that worked with the issuer down (parity rows [#834](https://github.com/truvity/sluis/issues/834) and [#835](https://github.com/truvity/sluis/issues/835)).

The forces:

- **The archive is logical.** The backup side reads records through the ports, never through a database ([0011](/decisions/0011-state-is-one-port-with-compare-and-set/)), so the same archive exists on every driver.
- **An installation is lost on its worst day.** The restore must work when the primary account, the cloud key service or the node is gone, with tools that exist outside sluis (principle 4: verify, never trust a claim).
- **Keys never leave their store** (principle 1). A data key is not an authority key: it protects values, and its escrow copy is the only way to open sealed values after the sealing key is lost ([0011](/decisions/0011-state-is-one-port-with-compare-and-set/#sealed-secrets)).
- **Evidence and personal data have separate keys, and a backup must not defeat erasure** ([0032](/decisions/0032-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/)).
- **Two ways to move state would be two things to test.** A copy tool and a restore both write records through the ports.

## Decision

### The archive

- **An archive is one tar file, encrypted as a whole with age** ([0012](/decisions/0012-cryptography-and-authority-keys/#named-exceptions) names age as an exception). Stock `age` and `tar` open it (REQ-BACKUP-006). The age recipients are declared; sluis holds their public keys only.
- **The tar holds a manifest and one file per (boundary, record kind).** The manifest is canonical JSON and names: the archive format version, the release that wrote it, the installation and boundary, the time, the digest of the resolved declared configuration, the schema version and the count and SHA-384 digest of every kind's file, and the fingerprints of the recipients. A kind's file is one record per line, each line the record in RFC 8785 canonical JSON, lines sorted by record key, so the same state yields the same bytes.
- **Which kinds go in is generated from the origin and durability annotations of the schema** ([0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#sensitivities)): operator-set and durable issued kinds. A new kind appears in the next archive without a change to the backup side.
- **A secret is archived sealed.** A sealed value travels as the item the `secrets` port holds ([0035](/decisions/0035-the-secrets-port-has-one-driver-sealed-state-and-the-export-port-publishes-only-kinds-marked-external/)); the backup side never unwraps it.
- **Escrow.** When the port library creates the data key of a sealed secret (`purpose=secret`), it also writes an escrow record of kind `data-key-escrow`: the data key encrypted with age to the installation's archive recipients, bound to the key's boundary, kind and version. The record is issued and durable, so it is in every archive, and the backup side copies it without reading it. What may be escrowed is bounded by [0032](/decisions/0032-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#backups) (REQ-BACKUP-037); no authority key is ever escrowed (principle 1).
- **The recipients are those that 0032 requires,** declared in the install file as `backup.recipients`. `sluis config check` reads the list and refuses a production installation with fewer than two (REQ-BACKUP-007). The data key of the archive is wrapped through the `keys` port (REQ-BACKUP-017), and the archive and its recipients preferably live apart from the installation's account (REQ-BACKUP-022).
- **The schedule and the rehearsal period are declared per installation and have no built-in default.** `sluis config check` refuses a production installation that declares none. How long an archive is kept is declared too (REQ-BACKUP-039). Where the values come from for each installation shape is a product fact that the design cannot set: [#1142](https://github.com/truvity/sluis/issues/1142).
- **Each archive is announced in the audit log.** The record `backup.completed` carries the archive's digest and the recipients' fingerprints. A restore uses it to prove provenance (REQ-BACKUP-009).

### The restore

- **A restore is its own actor with its own identity,** started by an operator and never by the console, so that it works while `entry` and `signer` are down (REQ-BACKUP-024, REQ-BACKUP-025). The steps and their order are on [Backup and restore](/concepts/backup/#restoring); this record does not repeat them.
- **A restore writes through the ports of the target installation,** so the target may use other drivers than the source: rqlite to DynamoDB, a board to a Lambda installation. The manifest's schema version decides how each kind is read; a kind written by release N is read by release N and N+1 under the rules of [0033](/decisions/0033-evolution-and-compatibility-n-and-n-1-inside-a-major-and-parallel-cutover/). An archive older than that is restored in two steps through the release in between.
- **A restore has a plan.** Without `--apply` it reads the archive, checks the manifest and the digests, lists the kinds, counts and secrets written since the archive was taken, and writes nothing. With `--apply` it refuses a destination that already holds records of the restored kinds unless `--overwrite` is given.
- **A restore never touches its source.** The old installation stays as it was, so rollback of a move is pointing back at it.
- **`sluis migrate` does not exist in v2.** Moving state between drivers, or between installations, is a backup and a restore into the new installation. This covers parity row [#804](https://github.com/truvity/sluis/issues/804): the plan, the dry run, the create-if-absent and overwrite choices, the read-back and the rollback are the restore's. The legacy Kubernetes store is not a driver of v2.
- **A rehearsal restore** into an empty scratch installation compares counts and digests with the manifest and records `restore.rehearsed` ([Backup and restore](/concepts/backup/#restoring)).

## Consequences

- One tool covers disaster recovery, a move between drivers and a promotion of a company to its own installation ([0005](/decisions/0005-boundaries-and-the-isolation-ladder/#promotion)). A move needs a window with writes stopped, which v1's online copy did not; the cost is paid once per move.
- The archive is readable by anyone who holds a recipient, so a recipient's identity is as sensitive as the sealing key. The offline token is the break-glass way in.
- The escrow records add one write for every new data key. Rotation of data keys writes new escrow records and leaves the old ones in older archives, which is why archive retention is bounded.
- A restore replays the shreds and erasures recorded after the archive was taken ([0032](/decisions/0032-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#backups), REQ-BACKUP-038), so it lifts maintenance only after that replay; an archive taken before an erasure holds the erased data until it expires.
- The canonical form costs a sort and a canonicalisation per record at backup time; it buys a stable digest and archives that can be compared byte for byte.
- Requirements: REQ-BACKUP-040 to REQ-BACKUP-044 are added; REQ-OPS-005 is withdrawn in favour of REQ-BACKUP-041. The explanation page loses its proposed note about the format.

## Roads not taken

- **A physical backup of each store (a database file, a table export).** It is tied to one driver and cannot move to another, and a restore would trust the engine's own format.
- **Keep `sluis migrate` beside the restore.** Two writers of records through the ports would double the tests and the failure modes, and the restore already has a plan, a read-back and a refusal to overwrite.
- **Escrow by splitting the sealing key (Shamir shares) or a ceremony.** It moves a key out of its store (principle 1) and needs people in a room (principle 7); an age-encrypted copy of a data key does neither.
- **One recipient.** One lost token or one compromised account would make the archive unreadable or open.
- **Archive the audit log with the state.** The log is protected by its lock mode, its witnesses and its store, and a copy would be a second, unlocked place for evidence ([0016](/decisions/0016-the-audit-log/#retention)).
- **A default schedule and retention.** A default would be a number no principle can justify, and a wrong one is found only on the day of a restore.
- **Per-record encryption with a key per company inside the archive.** It would make erasure reach old archives, but needs the company keys at restore time and breaks a restore from the recipients alone.

## Follow-ups

- The first recovery drill and the targets it replaces: [ADR 0056](/decisions/0056-a-regional-outage-is-accepted-public-keys-outlive-it-and-a-drill-measures-recovery/#recovery).
- Build of the backup and restore actors: [#834](https://github.com/truvity/sluis/issues/834), [#835](https://github.com/truvity/sluis/issues/835).
- The `secrets` and `export` ports: [0035](/decisions/0035-the-secrets-port-has-one-driver-sealed-state-and-the-export-port-publishes-only-kinds-marked-external/).
