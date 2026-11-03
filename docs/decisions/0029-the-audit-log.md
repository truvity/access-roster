# 0029 — The audit log is a C2SP tiled log in a blob, sealed in batches by its one writer, with a lock mode, company encryption and a declared retention

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

The log is one of the four audit pieces ([0028](/decisions/0028-audit-pieces/#four-pieces)): a writer, a blob store and an optional witness. This record says how a log is laid out, how its writer seals what it receives, what each blob backend's lock means, how companies are kept apart and how long the log is kept. What an entry holds is [0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format).

v1 wrote records to S3 with Object Lock in compliance mode (v1 ADR 0045, on `master`), and a notary sealed each hour with a JWS over an RFC 6962 Merkle root (v1 ADRs 0050 and 0061). That format was sluis's own. v2 follows published formats and does not carry v1's over.

Four things shape the log:

- **The formats are C2SP's:** `signed-note` (with the P-384 log key), `tlog-checkpoint`, `tlog-tiles`, `tlog-cosignature` (witness keys Ed25519 or ML-DSA-44) and `tlog-witness`. A followed format fixes its own algorithm ([0006](/decisions/0006-keys-and-sealing/#named-exceptions)).
- **The backends lock differently.** AWS S3 has Object Lock in compliance mode, Cloudflare R2 a bucket lock that an account administrator can remove, a local file system none.
- **Each environment boundary owns its audit log, and each company is a reader tenant of it** ([0008](/decisions/0008-boundaries-and-tenants/)). A company that leaves has its slice exported and its data key shredded.
- **A cluster has several nodes, and a log with two writers cannot keep one hash chain.**

The volume used for sizing on 2026-10-31 is about 2.4 records a second at peak and about 75,000 a week. The threats this record answers are T-10, T-12, T-13, T-14 and T-26 of the [threat model](/security/threat-model/).

## Decision

### Tiled log

- **Each log has exactly one writer, and a cluster keeps one log per node.** Each node has its own writer, spool and log key. The local installation has one log of each kind, the lambda installation one of each written by its one writer function, and a Kubernetes installation one of each per writer, with the writer's KMS log key and a lease on the state store ([0005](/decisions/0005-the-store/#leases)).
- **A writer writes two kinds of log, an audit log and a usage log.** What a usage event is, and why it is a stream of its own, is [0030](/decisions/0030-audit-records-and-the-usage-stream/#the-usage-stream). Every rule in this record holds for each log kind separately: its own prefix, checkpoints, retention, lock mode and declared readers. "The log" means one log of one kind.
- **Each log is a `tlog-tiles` log in the blob store.** Entry bundles and hash tiles are static objects that anyone with read access can fetch without a server; the tree hashes follow RFC 6962. A checkpoint is a `signed-note` in the `tlog-checkpoint` shape, signed with the log key, naming the log's origin, size and root hash. Removing, reordering or altering an entry breaks every later checkpoint.
- **One prefix per log, `<kind>/<boundary>/<log>/`,** with the `tlog-tiles` paths below it, where `<kind>` is `audit` or `usage`. An installation may put the usage log in a bucket of its own, for example for another lifecycle. The origin line of a checkpoint is `<installation host>/<kind>/<boundary>/<log>`.
- **Every checkpoint is also written once to `checkpoints/<size>` below the log's prefix.** The `tlog-tiles` `checkpoint` object, the one object the format rewrites, is a convenience pointer, written with a conditional put on its previous version where the store supports it. Verifiers trust the cosigned history, not the pointer.
- **The log holds no catalogue and no schema.** Every record names its release, and the action table is in that release's code ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-action-table-is-code-and-the-release-identifies-it)).
- **One log key per writer signs both of its log kinds,** and each signed batch head names its log. The writer reaches the key through its own `key-holder` socket and only the writer may use it (T-10, [0003](/decisions/0003-units-transports-and-fusion/#key-holder-is-the-one-mediator)); on AWS it is a KMS `ECC_NIST_P384` key whose key policy names only the writer's role. The usage log has no key of its own. **The log key rotates on compromise only:** a log's signatures must verify for the life of the log, so it is the named exception to the rule of [Rotation](/decisions/0006-keys-and-sealing/#rotation). A software key is allowed only where [0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place) allows one.

### Sealing

- **The writer receives messages from the transport, validates them, removes duplicates and seals them in batches.** It checks the audit part and any usage part against the schemas generated from the action table, refuses an unknown action, and appends each part to the current batch of its kind. It stores the bytes it received, unchanged, after checking they are canonical, and stamps the time it recorded the entry and its own instance (`writer@<boundary>`) into the entry's clear envelope, never into the record.
- **A batch is sealed at 256 messages or 5 seconds after its first, whichever comes first,** and one seal seals the audit batch together with the usage batch of the same messages. An empty batch is never sealed, so an idle log signs nothing.
- **Each batch ends with a seal entry** with the batch's record count, the writer instance and the observed clock offset (REQ-AUDIT-017, REQ-AUDIT-036), inside the tree so the witnesses cosign it. It is an entry kind of its own, in RFC 8785 canonical JSON and in clear, because it carries no company data.
- **A batch is sealed when its checkpoint is signed and written.** The writer writes the entry bundles and tiles, asks the keys port to sign the new checkpoint, writes it, and in one atomic state batch registers the sealed batches of both log kinds, records the ids it removed as duplicates and moves its transport cursor ([Data](/concepts/data/#the-atomic-batch)). A crash leaves all of that or none of it, for both kinds at once, so the two logs never disagree about which messages were written.
- **Delivery is at least once, and the writer removes duplicates by record id** (REQ-AUDIT-014, REQ-AUDIT-034): a UUIDv7 (RFC 9562) set by the emitter for the whole message. The writer remembers ids for 14 days, the longest retention of a supported queue; an older record is quarantined and reported, and an operator releases it.
- **A blocking emit waits until the record is durable in the transport:** accepted by the queue, acknowledged by the writer in direct mode, or fsync'd to the local spool. Credential and administrative changes use it, so the change fails when that fails (REQ-AUDIT-015). A durable but invalid record is quarantined and alarmed.
- **On serverless the writer runs with a reserved concurrency of 1 on a standard SQS queue.** The write-once fence is the correctness guarantee; the concurrency limit is an optimisation.

### The write-once fence

- **Every object is written once, and the blob store is the fence.** Entry bundles and tiles, partial tiles included, are created only if absent, so a second writer that believes it owns a log cannot overwrite or fork it (T-12). sluis supports only blob backends with an atomic create-if-absent, and every blob driver refuses to overwrite an existing object on a create-if-absent write (REQ-AUDIT-103):

  | Driver and backend | Atomic create-if-absent |
  |---|---|
  | `s3-compatible` on AWS S3 and Cloudflare R2 | `PutObject` with `If-None-Match: *`: 412 when the key exists, and of concurrent writers to an absent key at most one succeeds (AWS and Cloudflare documentation, checked 2026-10-31). On a versioned bucket a delete marker counts as absent, one more reason no writer holds a delete right |
  | `fs` | Write and fsync a temporary file, then `link()` or `renameat2(RENAME_NOREPLACE)` it to the target, which fail if the target exists, then fsync the directory. Local POSIX filesystems only |

- **Garage is backlog: it ignores conditional writes** ([#982](https://github.com/truvity/sluis/issues/982)). The boards keep their logs on R2.
- **The port conformance suite tests create-if-absent under concurrent writers for every blob driver** (REQ-TEST-009).
- **No actor's credential carries a delete right on the log store,** except an expiry sweeper's right on expired objects.

### Witnesses

- **A witness is optional everywhere, and `sluis config check` warns when there is none.** Witness drivers are `none`, `peer` and `external`; they speak `tlog-witness` and sign `tlog-cosignature` with an Ed25519 or ML-DSA-44 key. On a three-node cluster the other two nodes are each log's peer witnesses, two of three. An `external` witness is a choice of party, not a sluis integration.
- **The writer asks every witness to cosign each new checkpoint of each log kind,** at most one request per witness and log every 5 seconds, so the window in which only the writer vouches for the log is about one seal. When a log is idle the writer asks again for the latest checkpoint every 5 minutes; the cosignature's timestamp lets a reader tell a quiet log from a writer that stopped.
- **Readers merge the logs of a boundary by the time each record was recorded,** keeping each log's own order and breaking ties by log id (REQ-AUDIT-035). The reader shows each log's clock offset and claims no order across logs closer than it.
- **A restore re-registers the node with its peers and never restores a witness to an older state** (REQ-BACKUP-004, REQ-BACKUP-013).
- **The risk is written down.** With no witness, a compromised writer can get a rewritten checkpoint signed; a compliance lock still prevents overwriting stored objects, but not a split view, where different readers are shown different logs.

### Lock modes

- **The log store is a blob with an explicit lock mode,** `none`, `removable` or `compliance` (REQ-AUDIT-008), which the backend sets and `sluis config check` reports (REQ-AUDIT-028):

  | Backend | Lock mode | What it means for the log |
  |---|---|---|
  | AWS S3 | `compliance` | Object Lock in compliance mode: nobody, not even the account's root, can shorten an object's retention or delete it before then |
  | Cloudflare R2 | `removable` | A bucket lock rule that an account administrator can remove |
  | Local file system (`fs`) | `none` | Nothing stops a local administrator; tamper evidence comes from the witnesses |

- **A production log needs a `compliance` lock, or a weaker lock plus a `peer` or `external` witness.** `sluis config check` refuses anything else in a production boundary and warns in development and staging. The boards pass with their peer witnesses; a single-node production installation on `fs` needs an `external` witness.

### Encryption and crypto-shredding

- **Each entry is an envelope in clear plus the record, encrypted with HPKE (RFC 9180) to the company's audit data key.** The record is encrypted with a key per (company, batch), sealed with HPKE to the public part of the company's audit data key, so the writer never holds a key that decrypts what it wrote. A usage entry is encrypted the same way to the company's usage data key, a key of its own with the lifetime of the usage retention, because evidence and personal data never share a key ([0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#two-classes-of-data-two-keys)). The private part is held only wrapped under the boundary's sealing key ([0006](/decisions/0006-keys-and-sealing/#when-keys-are-shared-and-when-separate)): a company has no key of its own in a key store. A machine-plane record, which belongs to no company, is encrypted to the boundary's own audit data key. Records are routed to a company at write time (REQ-AUDIT-020).
- **The envelope uses OCSF field names** (`metadata.uid`, `time`, `metadata.tenant_uid`, `class_uid` and `activity_id`, `status_id`, `actor.user.type_id`) plus the writer's stamps; the boundary is the log's own. Apart from the stamps it is a projection of the record that the writer computes before encrypting, so a reader that decrypts checks that the two agree and catches a writer that lies in the envelope. It leaves out `metadata.event_code`, which says more than the class does. A usage entry has the same form: the id, the time, the company and the event `type` in clear, the event encrypted to the company's usage key.
- **The tree's leaf is the hash of the whole entry, ciphertext included,** and the record's own RFC 8785 hash is inside the ciphertext, so a log verifies after a company is shredded (T-14, T-26).
- **The operator's own view of a company's records is the envelope:** the class, the outcome and rotating pseudonyms (REQ-AUDIT-038).
- **A company that leaves has its slice exported, then its audit data key deleted** (the promotion runbook of [0008](/decisions/0008-boundaries-and-tenants/#promotion)). Its records stay in the log, sealed and verifiable, and nobody can read them again. Its usage data key is kept until the usage retention ends ([0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#two-classes-of-data-two-keys)).

### Pseudonyms

- **A person or external actor is recorded under a keyed pseudonym, never by name, e-mail address or token** (REQ-AUDIT-003, REQ-AUDIT-023, REQ-AUDIT-037). A secret appears as a fingerprint and a revision, and a free-text field is bounded (REQ-AUDIT-046).
- **The keyed function, its key, its monthly rotation and who may reverse a pseudonym are [0044](/decisions/0044-audit-pseudonyms-are-keyed-per-company-and-epoch/).**
- **The mapping from a pseudonym to the person lives outside the log, and erasure of a person deletes it.** There are no per-subject keys in 2.0; the company's data key is the only key that shreds the log, and REQ-AUDIT-018, which asked for a per-subject key, is withdrawn in favour of this.

### Retention

- **Each log declares its retention, and a production log must declare one.** The audit log and the usage log declare theirs separately, so billing data can be kept as long as finance needs without keeping security records as long. There is no built-in default, so the period is chosen consciously and shows in the install file and in `sluis config check`.
- **Each backend enforces retention its own way:** per-object retention on a compliance store, set when the object is written and only ever extended; the bucket lock rule on R2; a lifecycle rule or an expiry sweeper elsewhere, which on `fs` holds a delete right on expired objects only. A trial in governance mode before compliance is recommended in the documentation, not enforced: a wrong period locked in compliance mode cannot be shortened.
- **Legal holds stay outside sluis.** A hold is placed and lifted with the store's own means, under cloud IAM or a break-glass role, and the person who does it records it as an audit record under their own name. The shred procedure of the promotion runbook checks for a standing hold before it deletes a company's key, and on a store with no hold flag (R2, `fs`) the operator suspends expiry for the held range by hand.
- **The log is not part of the ordinary backup.** It is protected by its lock, its witnesses and its store ([Backup](/concepts/backup/#the-audit-log-is-handled-separately)).
- **Break-glass recovery spools its audit record locally and delivers it later,** so a down audit path does not block the emergency way in ([REQ-AUTHN-066](/requirements/authn/#REQ-AUTHN-066) to [REQ-AUTHN-073](/requirements/authn/#REQ-AUTHN-073)).
- **Framework profiles and archive lifecycle tiers are v1 parity.** v1 shipped framework profiles (such as DORA, NEN 7513 and PCI DSS) and an archive bucket with colder-storage transitions; v2 brings them in the parity milestone. Time-stamp anchoring of checkpoints with RFC 3161 (REQ-AUDIT-031), which v1 did not ship, is Later.

## Consequences

- An auditor verifies a log with standard tools: fetch the tiles and checkpoints, check the signature against the published log key and the cosignatures against the witness keys, and recompute the tree.
- One combined message and one atomic registration keep the audit and usage logs consistent by construction. A writer outage stops both together, and a malformed usage part fails its whole message, audit part included. The usage log is a second set of checkpoints to witness and a second retention to declare.
- Every object but the checkpoint pointer is written once, so a compliance lock and create-if-absent together leave no object a writer can change. Each seal writes the checkpoint twice. Backends without an atomic create-if-absent cannot hold a log.
- A seal costs one signature per log kind that has entries, so at most two: at most about 17,000 signatures a day per log when busy, none when idle. On a YubiKey 5 Nano a signature takes about 147 ms, about 7 a second (measured 2026-10-31); on KMS each is a billed request. The index, the witnesses and the quota meters lag the log by a few seconds.
- The seal entry is one more entry kind that the verifier, the indexer and quota must know.
- R2's lock can be removed by an account administrator and `fs` has none, so on the boards the peer witnesses carry the tamper evidence: a compromised writer that also holds a majority of witnesses is not detected. Peer witnesses protect against one compromised node, not a compromised operator. An outage of R2 or the link delays the boards' log.
- One log per node removes failover from the writer: a lost node leaves its log intact up to its last checkpoint. A boundary on the boards has three logs to verify and merge, and events on different nodes within the clock offset may show in either order.
- The envelope leaks metadata by design: who did what kind of thing, when, and with what outcome. A shredded company's ciphertext stays in a locked log for the rest of the retention, still verifiable.
- Pseudonymised records of one person stay linkable to each other after the mapping is deleted, so a contract that demands per-subject shredding cannot be met in 2.0.
- A legal hold works only where the store has one and as far as the operator's procedure goes. A spool that was down for more than 14 days needs an operator to release its quarantine.
- The log key does not rotate on a schedule; it is the exception to the rotation rule of [0006](/decisions/0006-keys-and-sealing/#rotation), and the design principles name it.

## Roads not taken

- **Keep v1's hourly JWS seals over a Merkle root.** A format of sluis's own, signed by a notary v2 no longer has, with no standard witness protocol.
- **A database as the log.** Easy to query, but a row can be changed by whoever administers it and nothing outside proves it was not.
- **Seal every second, or every minute.** Every second is up to 86,400 signatures a day per log; every minute leaves a minute of lag and a larger unwitnessed window.
- **Overwrite the checkpoint and rely on versioning.** The exact `tlog-tiles` behaviour, but `fs` has no versioning, so the history would be lost and the fence broken.
- **The fence as compare-and-set in the state store, or as a signing proxy in front of the blob store.** Either works on any backend, but moves the authority over the log out of the store that holds it, or puts a mediator with a master key on the trusted path; only backends that can fence are supported (decided 2026-10-31).
- **A key per (company, subject).** Millions of keys and a key lookup per record; the pseudonym mapping is deleted instead.
- **Require a compliance lock everywhere, or only warn.** Only AWS S3 offers compliance among the backends, so the boards could never hold a production log; only warning leaves a production log one warning away from no protection.
- **A built-in retention, or keep forever.** A wrong default locked in compliance mode cannot be shortened; keeping forever grows without bound and keeps a shredded company's ciphertext.
- **Legal holds as a sluis record that the writer enforces.** The writer would gain the right to set holds, and the sweeper and the shred would have to check them.
- **A log per company, or one shared log per cluster with a leader as writer.** A writer and key per company and node, with no home for a record that concerns two companies; a leader failover can leave two writers and fork the log.
- **A separate writer for the usage log.** Two writers fed from one emit are a dual write that a crash can split.
- **Time-stamp anchoring (RFC 3161) as the main protection.** It proves when a hash existed, not that every reader saw the same history; witnesses protect against a split view.

## Follow-ups

- Build of the writer, the blob drivers and the witnesses: [#837](https://github.com/truvity/sluis/issues/837), [#838](https://github.com/truvity/sluis/issues/838); the blob conformance suite: [#851](https://github.com/truvity/sluis/issues/851).
- Framework (compliance) profiles, parity milestone: [#1027](https://github.com/truvity/sluis/issues/1027).
- Lifecycle tiers and bucket layout, parity milestone: [#1016](https://github.com/truvity/sluis/issues/1016).
- Backup and restore of a node and its witness state: [#1015](https://github.com/truvity/sluis/issues/1015).
- Garage as a blob backend, backlog: [#982](https://github.com/truvity/sluis/issues/982).
