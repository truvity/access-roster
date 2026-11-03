# 0029 — The audit log is a tiled log in a blob, sealed by its one writer, with pseudonyms, lifecycle tiers and per-tenant keys

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

The log is what the audit pieces write and witness ([0028](/decisions/0028-audit-pieces/#four-pieces)). This record says how a project's logs are laid out in its bucket, how its writer seals what it receives, what each blob backend's lock means, how tenants are kept apart, how people are named in a record, how long a log is kept and when its old objects move to colder storage. What an entry holds is [0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format).

v1 wrote records to S3 with Object Lock in compliance mode (v1 ADR 0045, on `master`), and a notary sealed each hour with a JWS over an RFC 6962 Merkle root (v1 ADRs 0050 and 0061). That format was sluis's own. v2 follows published formats and does not carry v1's over. v1 also had archive tiers and framework profiles, each profile producing a purpose-bound copy of the records in a store of its own (v1 ADRs 0044 and 0056; parity row [#840](https://github.com/truvity/sluis/issues/840)).

Six things shape the log:

- **The formats are C2SP's:** `signed-note` (with the P-384 log key), `tlog-checkpoint`, `tlog-tiles`, `tlog-cosignature` (witness keys Ed25519 or ML-DSA-44) and `tlog-witness`. A followed format fixes its own algorithm ([0006](/decisions/0006-keys-and-sealing/#named-exceptions)).
- **The backends lock differently.** AWS S3 has Object Lock in compliance mode, Cloudflare R2 a bucket lock that an account administrator can remove, a local file system none.
- **Each boundary has one audit, and each emitting unit is a project of it** ([0028](/decisions/0028-audit-pieces/#one-audit-per-boundary)). A tenant may have records in several projects.
- **Evidence and personal data live for different times.** A bill or an audit fact can be disputed after a tenant has left, and finance keeps usage for years, but a tenant's exit must destroy everything personal. Each tenant therefore has an `evidence` key and a `pseudonym` key besides its `data` key ([0006](/decisions/0006-keys-and-sealing/#data-keys)).
- **A cluster has several nodes, and a log with two writers cannot keep one hash chain.**
- **A lock or a retention period is never shortened,** and the numbers a standard sets are facts with a source and a date ([principle 9](/principles/#9-measure-before-deciding-and-date-the-measurement)) that change faster than a record.

The volume used for sizing on 2026-10-31 is about 2.4 records a second at peak and about 75,000 a week. The threats this record answers are T-10, T-12, T-13, T-14 and T-26 of the [threat model](/security/threat-model/).

## Decision

### Projects

- **A project is one emitting unit of a boundary's audit:** `sluis` (the actors of the foundation and of the modules), the infrastructure the installation runs on, and each product. The `AuditLog` config kind declares each project with its bucket, its logs, their lock mode, lifecycle tiers, compliance profiles and retention ([0005](/decisions/0005-the-store/#configuration-loading)).
- **Each project has its own bucket, with one prefix per log kind:** `audit/` for the audit log and `usage/` for the usage log, which the project's writer writes, and `billing/` for the product's billing log, which no audit piece writes ([0039](/decisions/0039-quota-allowance/#the-billing-log-is-outside-sluis)). The `sluis` project also holds the issuance log of `ca`, under `issuance/` ([0023](/decisions/0023-certificate-authorities/#issuance-log-and-revocation)).
- **Each project has its own writer and its own log keys.** A project's writer writes only its own bucket and signs only with its own log key at key@, so a flaw in one project's writer cannot write or sign for another.
- **Who reads a project is a matter of its bindings** ([0028](/decisions/0028-audit-pieces/#access)): its team, its auditor and the boundary auditor.
- **The tenants' keys are the boundary's, whatever the project.** A tenant's records in every project are sealed under its one `evidence` key, and its pseudonyms are made with its one `pseudonym` key. Projects are kept apart by bucket, writer, log key, stream and binding; tenants by their keys and their grants.

### Tiled log

- **Each log has exactly one writer, and a cluster keeps one log per node.** Each node runs its own instance of each project's writer, with its own spool and log key. The local installation has one log of each kind per project; the lambda installation one per project, written by the project's one writer function; a Kubernetes installation one per writer instance, with the writer's KMS log key. The fence of each log is its blob ([The write-once fence](/decisions/0029-the-audit-log/#the-write-once-fence)), not a lease.
- **A project's writer writes two kinds of log, an audit log and a usage log;** in the `sluis` project it also writes the issuance log. What a usage fact is, and why it is a stream of its own, is [0030](/decisions/0030-audit-records-and-the-usage-stream/#the-usage-stream). Every rule in this record holds for each log separately: its own prefix, checkpoints, retention, lock mode, tiers and readers. "The log" means one log of one kind.
- **Each log is a `tlog-tiles` log in its project's bucket.** Entry bundles and hash tiles are static objects that anyone with read access can fetch without a server; the tree hashes follow RFC 6962. A checkpoint is a `signed-note` in the `tlog-checkpoint` shape, signed with the log key, naming the log, its size and its root hash. Removing, reordering or altering an entry breaks every later checkpoint.
- **One prefix per log, `<kind>/<log>/` in the project's bucket,** with the `tlog-tiles` paths below it. The origin line of a checkpoint is `<installation host>/<boundary>/<project>/<kind>/<log>`. <!-- terms-allow: origin (the C2SP checkpoint origin line) -->
- **Every checkpoint is also written once to `checkpoints/<size>` below the log's prefix.** The `tlog-tiles` `checkpoint` object, the one object the format rewrites, is a convenience pointer, written with a conditional put on its previous version where the store supports it. Verifiers trust the cosigned history, not the pointer.
- **The log holds no catalogue and no schema** (REQ-AUDIT-115). Every record names its release, and the catalogue of that release is a config document ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-action-table-is-code-and-the-release-identifies-it)).
- **One log key per writer instance signs its audit and usage logs,** and each signed checkpoint names its log (REQ-AUDIT-126). The issuance log is signed with the issuance-log purpose ([0006](/decisions/0006-keys-and-sealing/#key-purposes)). The writer asks key@ to sign every checkpoint, and key@ lets only that writer use its key (T-10); on AWS it is a KMS `ECC_NIST_P384` key whose key policy names only key@ ([0006](/decisions/0006-keys-and-sealing/#keys-per-boundary-on-aws)). **A log key rotates on compromise only:** a log's signatures must verify for the life of the log, so it is the named exception of [Rotation](/decisions/0006-keys-and-sealing/#rotation).

### Sealing

- **The writer receives messages from its project's stream, validates them, removes duplicates and seals them in batches.** It checks the audit part and any usage part against the project's catalogue ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-action-table-is-code-and-the-release-identifies-it)), refuses an unknown action, and appends each part to the current batch of its kind. It stores the bytes it received, unchanged, after checking they are canonical, and stamps the time it recorded the entry and its own instance into the entry's clear envelope, never into the record.
- **A batch is sealed at 256 messages or 5 seconds after its first, whichever comes first,** and one seal seals the audit batch together with the usage batch of the same messages. An empty batch is never sealed, so an idle log signs nothing.
- **Each batch ends with a seal entry** with the batch's record count, the writer instance and the observed clock offset (REQ-AUDIT-017, REQ-AUDIT-036), inside the tree so the witnesses cosign it. It is an entry kind of its own, in RFC 8785 canonical JSON and in clear, because it carries no tenant data.
- **A batch is sealed when its checkpoint is signed and written.** The writer writes the entry bundles and tiles, asks key@ to sign the new checkpoint, writes it, and in one conditional write of its state in the project's bucket registers the sealed batches of both log kinds, records the ids it removed as duplicates and moves its transport cursor (REQ-AUDIT-094). A crash leaves all of that or none of it, for both kinds at once, so the two logs never disagree about which messages were written. The writer's state lives in the blob and never in the store.
- **Delivery is at least once, and the writer removes duplicates by record id** (REQ-AUDIT-014, REQ-AUDIT-034): a UUIDv7 (RFC 9562) set by the emitter for the whole message. The writer remembers ids for 14 days, the longest retention of a supported queue; an older record is quarantined and reported, and an operator releases it.
- **A blocking emit waits until the record is durable in the transport:** accepted by the queue, acknowledged by the writer in direct mode, or fsync'd to the local spool. Credential and administrative changes use it, so the change fails when that fails (REQ-AUDIT-015). A durable but invalid record is quarantined and alarmed.
- **On serverless each project's writer runs with a reserved concurrency of 1 on a standard SQS queue.** The write-once fence is the correctness guarantee; the concurrency limit is an optimisation.

### The write-once fence

- **Every object is written once, and the blob store is the fence.** Entry bundles and tiles, partial tiles included, are created only if absent, so a second writer that believes it owns a log cannot overwrite or fork it (T-12). sluis supports only blob backends with an atomic create-if-absent, and every blob driver refuses to overwrite an existing object on a create-if-absent write (REQ-AUDIT-103):

  | Driver and backend | Atomic create-if-absent |
  |---|---|
  | `s3-compatible` on AWS S3 and Cloudflare R2 | `PutObject` with `If-None-Match: *`: 412 when the key exists, and of concurrent writers to an absent key at most one succeeds (AWS and Cloudflare documentation, checked 2026-10-31). On a versioned bucket a delete marker counts as absent, one more reason no writer holds a delete right |
  | `fs` | Write and fsync a temporary file, then `link()` or `renameat2(RENAME_NOREPLACE)` it to the target, which fail if the target exists, then fsync the directory. Local POSIX filesystems only |

- **Garage is backlog: it ignores conditional writes** ([#982](https://github.com/truvity/sluis/issues/982)). The boards keep their logs on R2.
- **The port conformance suite tests create-if-absent under concurrent writers for every blob driver** (REQ-TEST-009).
- **No credential carries a delete right on a project's bucket,** except an expiry sweeper's right on expired objects.

### Witnesses

- **A witness is optional everywhere, and `sluis config check` warns when there is none.** Witness drivers are `none`, `peer` and `external`; they speak `tlog-witness` and sign `tlog-cosignature` with an Ed25519 or ML-DSA-44 key, through key@ under the witness purpose ([0006](/decisions/0006-keys-and-sealing/#key-purposes)). On a three-node cluster the other two nodes are each log's peer witnesses, two of three. An `external` witness is a choice of party, not a sluis integration. `AuditWitnesses` declares the witnesses of each log and the cosignatures it requires.
- **The writer asks every witness to cosign each new checkpoint of each log,** at most one request per witness and log every 5 seconds, so the window in which only the writer vouches for the log is about one seal. When a log is idle the writer asks again for the latest checkpoint every 5 minutes; the cosignature's timestamp lets a reader tell a quiet log from a writer that stopped.
- **Readers merge the node logs of a project by the time each record was recorded,** keeping each log's own order and breaking ties by log id (REQ-AUDIT-035). The reader shows each log's clock offset and claims no order across logs closer than it.
- **A restore re-registers the node with its peers and never restores a witness to an older state** (REQ-BACKUP-004, REQ-BACKUP-013).
- **The risk is written down.** With no witness, a compromised writer can get a rewritten checkpoint signed; a compliance lock still prevents overwriting stored objects, but not a split view, where different readers are shown different logs.

### Lock modes

- **A project's bucket is a blob with an explicit lock mode,** `none`, `removable` or `compliance` (REQ-AUDIT-008), which the backend sets and `sluis config check` reports (REQ-AUDIT-028):

  | Backend | Lock mode | What it means for the log |
  |---|---|---|
  | AWS S3 | `compliance` | Object Lock in compliance mode: nobody, not even the account's root, can shorten an object's retention or delete it before then |
  | Cloudflare R2 | `removable` | A bucket lock rule that an account administrator can remove |
  | Local file system (`fs`) | `none` | Nothing stops a local administrator; tamper evidence comes from the witnesses |

- **A production log needs a `compliance` lock, or a weaker lock plus a `peer` or `external` witness.** `sluis config check` refuses anything else in a production boundary and warns in development and staging. The boards pass with their peer witnesses; a single-node production installation on `fs` needs an `external` witness.

### Encryption and crypto-shredding

- **Each entry is an envelope in clear plus the record, sealed by key@ under the tenant's `evidence` key** ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)). The writer asks `policy` for a grant for each batch of one tenant's records, and asks key@ to Seal each record under it, bound as authenticated data to the boundary, the tenant, the project, the log and the record id, so a record copied to another log or tenant does not open. The writer may Seal under `evidence` and never Open, so it holds nothing that decrypts what it wrote; only the indexer and the reader may Open, under a grant (the reader's is the grant of its call; the indexer asks `policy` for one for each pass) ([0028](/decisions/0028-audit-pieces/#access)). Records are routed to a tenant at write time (REQ-AUDIT-020).
- **Evidence and personal data never share a key.** Audit and usage entries are evidence: they name people only by pseudonym ([Pseudonyms](/decisions/0029-the-audit-log/#pseudonyms)) and carry no name, address or token ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format)). The personal data that would make them readable about a person, the person's records and the pseudonym key, lives under the tenant's `data` and `pseudonym` keys.
- **A record that concerns no tenant,** such as a machine-plane record of the foundation or an infrastructure change, belongs to the operator's own tenant and is sealed under its `evidence` key.
- **The envelope uses OCSF field names** (`metadata.uid`, `time`, `metadata.tenant_uid`, `class_uid` and `activity_id`, `status_id`, `actor.user.type_id`) plus the writer's stamps; the boundary and the project are the log's own. Apart from the stamps it is a projection of the record that the writer computes before sealing, so a reader that opens the record checks that the two agree and catches a writer that lies in the envelope. It leaves out `metadata.event_code`, which says more than the class does. A usage entry has the same form: the id, the time, the tenant and the event `type` in clear, the event sealed under the same `evidence` key.
- **The tree's leaf is the hash of the whole entry, ciphertext included,** and the record's own RFC 8785 hash is inside the ciphertext, so a log verifies after its records stop opening (T-14, T-26).
- **A tenant's exit deletes its `data`, `pseudonym` and `pairwise` wraps at once** ([0006](/decisions/0006-keys-and-sealing/#erasing-a-tenant)). Its pseudonyms can no longer be made or reversed, and its people's records are gone, so its records name no one. The records stay in the logs, sealed and verifiable, and readable as evidence.
- **Its `evidence` wrap is deleted when the evidence retention ends,** the latest end of the declared retention of any log of the boundary that holds the tenant's entries ([Retention](/decisions/0029-the-audit-log/#retention)). After that nobody can read the tenant's records again, and the logs still verify.

### Pseudonyms

- **A person or an external actor is recorded under a keyed pseudonym, never by name, e-mail address or token** (REQ-AUDIT-003, REQ-AUDIT-023, REQ-AUDIT-037). A secret appears as a fingerprint and a revision, and a free-text field is bounded (REQ-AUDIT-046).
- **A pseudonym is `p1.<epoch>.<value>`,** where `<epoch>` is the UTC month as `YYYYMM` and `<value>` is the first 128 bits, base64url without padding, of the keyed hash that key@'s `Mac` makes with HMAC-SHA384 under the tenant's `pseudonym` key of that epoch ([0006](/decisions/0006-keys-and-sealing/#sign-and-mac)). The input is domain-separated: the label `sluis-pseudonym-v1`, which key@ binds in, then the boundary, the tenant, the kind of identity and its stable identifier, each length-prefixed. The identifier is the sluis subject for a person; the upstream's issuer and subject for an identity sluis has assigned no subject; the SPIFFE ID or client id for a workload or client; and a product's own stable subject id for a person of a product.
- **An epoch is a generation of the tenant's `pseudonym` key,** made at the start of every UTC month (REQ-AUDIT-129). Within a month the records of one person link to each other; across months they do not, without reversal. A suspected compromise of the key starts a new epoch at once, and past records keep their pseudonyms.
- **The pseudonym is made where the record is made.** The emitter asks key@ for it before the record leaves the process (REQ-AUDIT-128), so a raw subject never reaches a transport, a spool or the writer. key@'s rules let only emitting actors and the reader use the `pseudonym` purpose, and only with `Mac`; the key never leaves key@. A product is not a sluis actor, so its emitter is a declared caller of key@ for `Mac` under the `pseudonym` purpose and nothing else, known by its platform identity (the actor registry lists it among the external callers). A tenant's exit therefore unlinks the product's records too.
- **Only the tenant's own audit role reverses a pseudonym** (REQ-AUDIT-130). The reader answers two questions for a person whose grant carries the tenant's declared reversal grant name: the pseudonyms of a subject the person names, for a range of epochs; and whether a given pseudonym is that of a subject the person names, in its epoch. Each reversal is audited under the asking person's name (REQ-AUDIT-131). The operator of the installation cannot reverse a tenant's pseudonyms.
- **The mapping from a pseudonym to a person lives outside the log, and erasure of a person deletes it.** The pseudonym leads to the subject, and the subject leads to a person only through the person's records, which live outside the log (REQ-AUDIT-057). Once those are erased the person's pseudonyms name no one. There are no per-subject keys; the tenant's `pseudonym` key is the only key that unlinks the log, and REQ-AUDIT-018, which asked for a per-subject key, stays withdrawn.
- **Each epoch's generation is kept for the longest retention of the logs that hold pseudonyms it made,** and is deleted then. Every generation goes at the tenant's exit.

### Retention

- **Each log declares its retention in `AuditLog`, and a production log must declare one.** The audit log and the usage log declare theirs separately, so billing evidence can be kept as long as finance needs without keeping security records as long. There is no built-in default, so the period is chosen consciously and shows in the reviewed document and in `sluis config check`.
- **A tenant's evidence retention is the latest end of the retention of any log of the boundary that holds its entries,** in any project. key@ deletes its `evidence` wrap then ([0008](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)).
- **Each backend enforces retention its own way:** per-object retention on a compliance store, set when the object is written and only ever extended; the bucket lock rule on R2; a lifecycle rule or an expiry sweeper elsewhere, which on `fs` holds a delete right on expired objects only. A trial in governance mode before compliance is recommended in the documentation, not enforced: a wrong period locked in compliance mode cannot be shortened.
- **Legal holds stay outside sluis.** A hold is placed and lifted with the store's own means, under cloud IAM or a break-glass role, and the person who does it records it as an audit record under their own name. Before key@ deletes a tenant's `evidence` wrap, the deletion checks for a standing hold on the logs that hold the tenant's entries; on a store with no hold flag (R2, `fs`) the operator suspends expiry for the held range by hand.
- **The log is not part of the ordinary backup.** It is protected by its lock, its witnesses and its store ([0010](/decisions/0010-backup-and-recovery/#what-the-archive-holds)).
- **Break-glass recovery spools its audit record locally and delivers it later,** so a down audit path does not block the emergency way in ([REQ-AUTHN-066](/requirements/authn/#REQ-AUTHN-066) to [REQ-AUTHN-073](/requirements/authn/#REQ-AUTHN-073)).

### Lifecycle tiers

- **Only cold, immutable objects move.** The entry bundles and the level-0 hash tiles that are complete may move to a colder storage class after a declared age. Partial tiles, hash tiles of higher levels, the checkpoints and the pointer stay in the hot class (REQ-AUDIT-139), so a proof and the newest entries never wait for a retrieval.
- **A tier never touches retention.** A transition leaves the object's lock and retention as they are (REQ-AUDIT-138), and expiry at the end of retention deletes the object from any tier. The conformance suite of each blob driver proves that a transitioned object keeps its lock ([#851](https://github.com/truvity/sluis/issues/851)).
- **Each blob driver declares the tiers it supports,** and `sluis config check` refuses a tier the driver lacks. A driver with none (`fs`) takes none.
- **The ages are declared per log in `AuditLog`,** a list of age and class, so the audit log and the usage log of a project tier separately.
- **sluis renders the lifecycle rule of each bucket and does not apply it.** The rule is a neutral artifact derived from the declaration, applied by the operator's infrastructure code, like the other artifacts of the installation ([0015](/decisions/0015-evolution-and-compatibility/)). The reader learns an object's class from the driver.
- **A read of a cold object is explicit.** The reader returns a `pending` state with a retry time and asks for the retrieval when the grant allows it; it never blocks a request on one (REQ-AUDIT-140). The search index holds the searchable fields, so a query does not touch cold objects; only showing a full record and verifying do. `sluis audit verify` asks for a range in batches.

### Compliance profiles

- **A profile is a floor, not a copy.** It is a data file shipped in the release, one per standard: `profiles/<id>.yaml`. The release ships `dora`, `nen-7513` and `pci-dss`. A file states, for the audit log and the usage log separately, the least retention, the least lock mode (or a witness in its place, as [Lock modes](/decisions/0029-the-audit-log/#lock-modes) allows), whether a witness is required, the least identity treatment (a keyed pseudonym), the record classes that must be emitted and the review cadence. Each value carries the clause of the standard it comes from and the date it was last checked.
- **Each project's logs name the profiles they keep, in `AuditLog`.** The strictest value of each floor applies: the longest retention, the strongest lock, a witness if any requires it.
- **The configuration check enforces the floors.** It refuses, in a production boundary, a declared retention, lock or identity treatment below the floor of a declared profile, naming the profile and the clause (REQ-AUDIT-136, REQ-AUDIT-137). It cannot check that a standard is met, only that the installation is not below the floor the profile file states.
- **The record classes are reported, not refused.** The reader reports, per period and project, a required class with no records, so that an application that stopped emitting is seen.
- **There are no purpose-bound copies.** One log holds the evidence; a second store for a second retention would copy evidence and pseudonyms outside the tenant's keys. A consumer that needs another view reads the log through the reader, or takes the usage log, which has its own retention.
- **Time-stamp anchoring of checkpoints (RFC 3161) is not built.** It proves when a hash existed, not that every reader saw one history; witnesses do that. It stays a planned line, REQ-AUDIT-031.

## Consequences

- An auditor verifies a log with standard tools: fetch the tiles and checkpoints, check the signature against the published log key and the cosignatures against the witness keys, and recompute the tree. Verification needs no key at all and works after a tenant has left.
- A project is a bucket, a writer and a log key per writer instance. A product that joins a boundary adds them and changes no other project; on a board each extra project's log key takes a spare card slot.
- One combined message and one conditional write of the writer's state keep a project's audit and usage logs consistent by construction. A writer outage stops both together, and a malformed usage part fails its whole message, audit part included. The usage log is a second set of checkpoints to witness and a second retention to declare.
- Every object but the checkpoint pointer and the writer's state is written once, so a compliance lock and create-if-absent together leave no log object a writer can change. Each seal writes the checkpoint twice. Backends without an atomic create-if-absent cannot hold a log.
- A seal costs one signature per log kind that has entries: at most about 17,000 signatures a day per log when busy, none when idle. On a YubiKey 5 Nano a signature takes about 147 ms, about 7 a second (measured 2026-10-31); on KMS each is a billed request. Sealing a record is a key@ call per record, batched, served from key@'s cache of opened data keys ([0006](/decisions/0006-keys-and-sealing/#the-cache)). The index and the witnesses lag the log by a few seconds.
- The seal entry is one more entry kind that the verifier, the indexer and the reader must know.
- R2's lock can be removed by an account administrator and `fs` has none, so on the boards the peer witnesses carry the tamper evidence: a compromised writer that also holds a majority of witnesses is not detected. Peer witnesses protect against one compromised node, not a compromised operator. An outage of R2 or the link delays the boards' logs.
- One log per node removes failover from the writer: a lost node leaves its log intact up to its last checkpoint. A project on the boards has three logs to verify and merge, and events on different nodes within the clock offset may show in either order.
- The envelope leaks metadata by design: who did what kind of thing, when, and with what outcome. A departed tenant's records stay readable as evidence for the evidence retention, naming no one, and then stay in a locked log as ciphertext that still verifies.
- A tenant's `evidence` key outlives its personal data by the difference between the longest log retention and the exit. The usage retention has to be declared and at least as long as the longest duty.
- The operator sees a person's activity linked within a month and not beyond. An investigation across months needs the tenant's reversal role, and every reversal is visible in the log. A leaked pseudonym key lets its holder confirm whether a subject they already know appears in that tenant's month; it reveals no subject, because subjects are random, and forges no record.
- Records of one person stay linkable to each other within each month after the mapping is deleted, so a contract that demands per-subject shredding cannot be met.
- A legal hold works only where the store has one and as far as the operator's procedure goes. A spool that was down for more than 14 days needs an operator to release its quarantine.
- The cost of old evidence falls without a change to what can be verified; the price is a delay of minutes to hours when a cold range is read, and a runbook for a verifier that needs one.
- A profile file is data: a standard's change is a reviewed change to one file, dated and sourced, with no record to rewrite. The maintenance cost is the review cadence of three files. An installation that declares no profile is checked only against this record.
- The log key does not rotate on a schedule; it is the exception to the rotation rule of [0006](/decisions/0006-keys-and-sealing/#rotation).

## Roads not taken

- **Keep v1's hourly JWS seals over a Merkle root.** A format of sluis's own, signed by a notary v2 does not have, with no standard witness protocol.
- **A database as the log.** Easy to query, but a row can be changed by whoever administers it and nothing outside proves it was not.
- **The writer's state, or its fence, in the store.** The store would become a second home for evidence and a dependency of every seal; only backends that can fence are supported (decided 2026-10-31).
- **A signing proxy in front of the blob store.** A mediator with a master key on the trusted path.
- **Seal every second, or every minute.** Every second is up to 86,400 signatures a day per log; every minute leaves a minute of lag and a larger unwitnessed window.
- **Overwrite the checkpoint and rely on versioning.** The exact `tlog-tiles` behaviour, but `fs` has no versioning, so the history would be lost and the fence broken.
- **Records sealed by HPKE to a public key per tenant, so the writer encrypts without key@.** A second sealing path beside key@'s, and a private key per tenant to hold somewhere; key@'s Seal-only rule for the writer gives the same property.
- **Records under the tenant's `data` key, with usage under a key of its own.** A tenant's exit would destroy the security evidence at once, and a dispute after the exit could not be answered from the audit log.
- **Delay the shred of personal data until the evidence retention ends.** Personal data would be kept for years after an exit, against any erasure promise.
- **A key per (tenant, subject).** Millions of keys and a key lookup per record; the pseudonym key and the mapping outside the log are deleted instead.
- **A plain hash of the subject.** Anyone with a list of subjects could reverse it without any key.
- **One pseudonym key for the life of the log.** One person could be followed through every record for years by whoever reads the envelopes, against the rotating view REQ-AUDIT-038 asks for.
- **A stored mapping table from pseudonym to person.** A second store of personal data to protect, back up and erase, where the keyed function already gives the mapping on demand.
- **Pseudonymising in the writer.** Every transport and spool would then carry raw subjects.
- **Format-preserving encryption of the subject.** Reversible by whoever holds the key, without the person's record, so erasure could not unlink it.
- **Require a compliance lock everywhere, or only warn.** Only AWS S3 offers compliance among the backends, so the boards could never hold a production log; only warning leaves a production log one warning away from no protection.
- **A built-in retention, or keep forever.** A wrong default locked in compliance mode cannot be shortened; keeping forever grows without bound and keeps every departed tenant's evidence.
- **Legal holds as a sluis kind that the writer enforces.** The writer would gain the right to set holds, and the sweeper and the evidence deletion would have to check them.
- **A log per tenant, or one shared log per cluster with a leader as writer.** A writer and key per tenant and node, with no home for a record that concerns two tenants; a leader failover can leave two writers and fork the log.
- **A separate writer for the usage log.** Two writers fed from one emit are a dual write that a crash can split.
- **A copy of the log per compliance profile, as v1 did.** Several retentions and several stores of the same evidence, each outside the tenant's keys, and a copier to run for each.
- **Tier by moving the object to another bucket, or tier every object.** A new key means a new address, and the checkpoints and tiles name each other by path; tiering higher-level tiles makes every proof wait for a retrieval, for a tiny saving.
- **sluis applies the lifecycle rule itself.** The writer, whose credential has no delete right, would need rights over bucket configuration.
- **Compliance numbers in the record, or a profile that turns on features.** The values are the standards' and change when the standards do; a floor can be checked, while a feature switch would hide which control meets which clause.
- **Time-stamp anchoring (RFC 3161) as the main protection.** It proves when a hash existed, not that every reader saw the same history; witnesses protect against a split view.

## Follow-ups

- Build of the writer, the blob drivers, the tier declaration and the rendered lifecycle rule: [#837](https://github.com/truvity/sluis/issues/837); seals and verification: [#838](https://github.com/truvity/sluis/issues/838); the blob conformance suite: [#851](https://github.com/truvity/sluis/issues/851).
- The emitter's pseudonyms and the reader's reversal: [#841](https://github.com/truvity/sluis/issues/841), [#839](https://github.com/truvity/sluis/issues/839).
- The profile files, the floor check and identity treatment, for parity: [#840](https://github.com/truvity/sluis/issues/840).
- Time-stamp anchoring of checkpoints (REQ-AUDIT-031), later: [#1027](https://github.com/truvity/sluis/issues/1027).
- Backup and restore of a node and its witness state: [#1015](https://github.com/truvity/sluis/issues/1015).
- Garage as a blob backend, backlog: [#982](https://github.com/truvity/sluis/issues/982).
