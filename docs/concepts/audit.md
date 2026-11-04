---
title: Audit
description: "The sluis audit trail: one audit per boundary, a project per emitter, OCSF records and a usage stream, one writer per log, witnesses, access and tenant keys."
status: target
sidebar:
  order: 6
---

sluis writes a tamper-evident audit trail. This page explains the ideas; the records are [ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/), the log [ADR 0029](/decisions/0029-the-audit-log/), and the pieces, transport, search, access and front [ADR 0028](/decisions/0028-audit-pieces/). How a record travels from an actor to the log, with the sockets and the failure cases of each installation, is drawn in the [audit explorer](/architecture/audit-explorer/).

## What is audited

**Every flow is audited, refusals included.** When an actor does something for a caller, such as signing a person in, issuing a token, minting a credential or changing a kind, it appends an audit record, so every actor is an emitter. **What was used goes to a usage log beside it:** an action that uses something, such as a metered call, sends one message with an audit part and a usage part, and the writer puts each part into its own log ([The usage stream](#the-usage-stream)). The facts of the allowance, every admit, refusal and push, are audit facts too ([ADR 0039](/decisions/0039-quota-allowance/#countdown-and-refusal)).

## The four pieces

Audit is the fourth [family](/concepts/families/) of actors and the audit module. It is four pieces fed by an emitter library over a transport ([ADR 0028](/decisions/0028-audit-pieces/#four-pieces)):

| Piece | What it is | What it holds |
|---|---|---|
| **Emitter** | A library inside each emitting process, configured by that process; not a process of its own. From one call it builds one message | Nothing |
| **Writer** | Receives its project's messages, validates and de-duplicates them, seals them in batches and writes the logs | The write credential of its project's bucket |
| **Witness** | Cosigns the writers' checkpoints; optional | The credential for its cosignatures |
| **Indexer and reader** | Search: the indexer builds the index from the log, and the reader serves the audit API | The index credentials: the indexer writes, the reader reads |

- **There is no notary.** The writer asks key@ to sign each checkpoint, the witness asks key@ to sign each cosignature, and key@ lets each use only its own purpose ([Keys](/concepts/keys/)).
- **Audit reads its documents through the data port.** `AuditLog`, `AuditWitnesses` and `AuditCatalogue` are config kinds that store@ loads and verifies like every other config. The blob, the transport and the index are audit's own ports, and the audit pieces write nothing through the store.
- **The search index is derived data,** rebuilt from the log and never evidence.

## One audit per boundary

**Each boundary has one audit:** one set of audit pieces, one search index and one audit front serve every project that emits in the boundary, and no audit spans two boundaries. The boundary is the unit of keys and policy, so the evidence of one boundary is never sealed, indexed or read with another's keys ([ADR 0028](/decisions/0028-audit-pieces/#one-audit-per-boundary)).

Each emitting unit is a **project**: sluis itself, the infrastructure, and each product. A project has ([ADR 0029](/decisions/0029-the-audit-log/#projects)):

- **its own bucket,** with one prefix per log kind: `audit/` for the audit log, `usage/` for the usage log, and `billing/` for the product's billing log, which no audit piece writes. The `sluis` project also holds the issuance log of `ca`;
- **its own writer and its own log keys,** so a flaw in one project's writer cannot write or sign for another;
- **its own stream** in the transport, and its own team and auditor bindings.

The tenants' keys are the boundary's, whatever the project: a tenant's records in every project are sealed under its one `evidence` key. Projects are kept apart by bucket, writer, log key, stream and binding; tenants by their keys and their grants.

## Access

Access to audit is checked **twice, by two independent checks** ([ADR 0028](/decisions/0028-audit-pieces/#access)):

1. **The reader and `policy`.** Cedar decides every call on project, log kind and tenant. The grant that results is a mandatory filter of every query, and a record read from the blob opens at key@ only under a grant that covers its tenant.
2. **The blob store's own access control on the bucket and the prefix:** IAM on AWS, temporary credentials scoped to a bucket and a prefix on Cloudflare R2, file permissions per uid on a local file system.

The bindings are Cedar policies in config:

| Binding | Reads | May change |
|---|---|---|
| **Team** of a project | The project's logs | Ask for operations on them, such as an export or a rebuild of the project's index partitions |
| **Auditor** of a project | The project's logs | Nothing |
| **Boundary auditor** | Every project of the boundary | Nothing |

A binding names log kinds as well as projects, so a finance reader may be granted a project's `usage` without its `audit`. A tenant reads its own records in the projects whose policy allows it. The operator's own view of a tenant's records is the envelope: the class, the outcome and rotating pseudonyms. Every read is itself audited.

## Exactly one writer per log

**Each log has exactly one writer, and a cluster keeps one log per node.** A log is the ordered sequence of entries of one kind written by one writer; the writer's state lives in the project's bucket, written conditionally, not in the store.

- **On a cluster of nodes,** each node runs its own instance of each project's writer, with its own spool and log key. The other nodes are that log's **peer witnesses**, two of three on a three-node cluster. No writer reads another node's spool, so there is nothing to elect and no lease is needed. Readers merge the logs of a project by the time each entry was recorded, keep each log's own order, break ties by log id, and claim no order across logs closer than the clock offsets the seals record.
- **On the local installation** there is one log of each kind per project.
- **On serverless** the project's one writer function runs with a reserved concurrency of 1 on a standard SQS queue. The limit is an optimisation; correctness comes from the write-once fence.
- **On Kubernetes** there is one log of each kind per writer instance, with the writer's KMS log key.

**One log key per writer instance signs both of its log kinds,** and each signed checkpoint names its log. A log key rotates only on compromise, because a log's signatures must verify for the life of the log ([ADR 0029](/decisions/0029-the-audit-log/#tiled-log)).

| Installation | Log key | Witness |
|---|---|---|
| [local](/runtimes/#local) | A software key through key@ | None |
| [boards](/runtimes/#boards) | Each board's own card signs that board's log, through key@ | The other two boards, as `peer` witnesses |
| [lambda](/runtimes/#lambda) | One KMS `ECC_NIST_P384` key per writer, whose key policy names key@ only | Optional: `peer` or `external` |
| [kubernetes](/runtimes/#kubernetes) | One KMS key per writer instance | Optional: `peer` or `external` |

## The write-once fence

**Every object of a log is written once, and the blob store is the fence** ([ADR 0029](/decisions/0029-the-audit-log/#the-write-once-fence)). Entry bundles and tiles, partial tiles included, are created only if absent, so a second writer that believes it owns a log cannot overwrite or fork it: its create fails. sluis supports only blob backends with an atomic create-if-absent (S3 and R2 through `If-None-Match: *`, a local file system through `link()` or `renameat2`), and no credential carries a delete right on a project's bucket, except an expiry sweeper's right on expired objects. Garage ignores conditional writes and is backlog ([#982](https://github.com/truvity/sluis/issues/982)).

## Batches and checkpoints

sluis follows the C2SP specifications and invents no format for the log ([ADR 0029](/decisions/0029-the-audit-log/#tiled-log)):

- **The log** is a `tlog-tiles` log in the project's bucket: entry bundles and hash tiles are static objects that anyone with read access can fetch without a server.
- **Checkpoints** are C2SP `signed-note` documents in the `tlog-checkpoint` shape, signed with the log key (P-256 over SHA-256, the standard C2SP signature), naming the log, its size and its root hash. Removing, reordering or altering an entry breaks every later checkpoint.
- **A witness** signs with `tlog-cosignature`, using an Ed25519 or ML-DSA-44 key, and is asked through the `tlog-witness` protocol.
- **The issuance log** of `ca` records every X.509 certificate it issues in a C2SP `static-ct-api` log, witnessed in the same way.

**The layout.** Each log has one prefix, `<kind>/<log>/`, in its project's bucket, and every checkpoint is also written once to `checkpoints/<size>`, so the full history survives on a store with no versioning.

**Sealing** ([ADR 0029](/decisions/0029-the-audit-log/#sealing)):

- A batch is sealed at **256 messages or 5 seconds** after its first, whichever comes first; one seal covers the audit batch and the usage batch of the same messages, and an empty batch is never sealed.
- Each batch ends with a **seal entry**, in clear, with the record count, the writer instance and the observed clock offset, inside the tree so the witnesses cosign it.
- The writer writes the bundles and tiles, has key@ sign the checkpoint, writes it, and in one conditional write of its state registers the sealed batches of both kinds, the ids it removed as duplicates and its transport cursor. A crash leaves all of it or none, so the two logs never disagree.
- **Delivery is at least once.** Each message carries a UUIDv7 id set by the emitter, and the writer remembers ids for 14 days; an older message is quarantined and reported until an operator releases it.
- **A blocking emit** returns once the record is durable in the transport. Credential and administrative changes use it, so the change fails when the emit fails.

## The transport

The transport joins the emitter to the writer ([ADR 0028](/decisions/0028-audit-pieces/#transport)).

| Mode | Drivers | How the record travels |
|---|---|---|
| **direct** | A Unix socket on the same host, or mutual TLS | The emitter streams the record to the writer |
| **queue** | `spool` (a local fsync'd spool), `sqs`, `nats-jetstream` | The emitter puts the record into a queue; the writer receives and acknowledges it |

**The default follows the runtime:** the spool on bare metal, SQS on serverless, and NATS JetStream on Kubernetes. Direct mode falls back to a local spool when the writer is down and replays when it returns, so it needs a disk and is not available on serverless. An in-memory buffer is not offered, because it would lose records.

**Each project has its own queue or stream,** and the transport authenticates every emitter by its platform identity: the peer uid of a socket, an IAM role for SQS, NATS credentials or a service-account token on Kubernetes. A product's emitter uses the product's own platform identity, so it needs no sluis credential. NATS itself refuses a publish outside the emitter's own subjects ([ADR 0028](/decisions/0028-audit-pieces/#nats-jetstream)).

## Records

**An audit record is an OCSF event of a core class, with no OCSF extension** ([ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format)). Each release pins one OCSF version in `metadata.version`; the first pins **OCSF 1.9.0**, and an upgrade moves one minor release at a time, as a checked pull request. Records are never rewritten. Where OCSF has no activity for an action, the record uses activity 99 (`Other`) with a name.

The sluis action is `metadata.event_code`, the tenant `metadata.tenant_uid`, the record id `metadata.uid`, the release `metadata.product.version`, and the actor `actor.user.uid = <actor>@<boundary>`, where a person or external actor is a keyed pseudonym before the `@`.

**What OCSF has no attribute for goes in one object, `unmapped.sluis`,** and nowhere else in `unmapped`. Its schema is sluis's own, closed and generated in CI ([ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-sluis-fields-unmappedsluis)).

**The action table is code** ([ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-action-table-is-code-and-the-release-identifies-it)). Each action's class and activity, required fields, treatment, declared meters and searchable fields are a table in the emitting product's code. The JSON Schemas of the records are generated from it in CI and published with each release as the config kind `AuditCatalogue`, together with the table, before the release emits. The log holds no catalogue: the product, the release and the event code identify the entry in force. A writer refuses an action its project's catalogue does not declare, so a product's release needs no writer upgrade.

- **The same bytes end to end.** A record is RFC 8785 canonical JSON. The emitter makes the bytes, the transport carries them, the writer checks they are canonical and stores them unchanged, and the reader returns them as they are.
- **A record never carries a secret, an e-mail address, a name or a token;** a secret appears as a fingerprint and a revision.

## The usage stream

**The usage stream holds what was used,** as CloudEvents 1.0 events in structured JSON, canonical by RFC 8785, shaped like OpenMeter's usage events: the `type` selects a meter, the `subject` is the aggregation key, and `data` holds the unit, a signed integer amount and the request id. Its `id` is the audit record's id with the event's position in the message ([ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-usage-stream)).

- **One call, one message, two logs.** The emitter builds the audit record and the usage events from one call and sends one message; the writer splits it and seals both in the same conditional write. There is no dual write and no usage event without its audit record.
- **Each kind is a log of its own:** its own prefix, checkpoints, retention, lock mode, readers and witnesses. Usage entries carry no personal data and are sealed under the tenant's `evidence` key.
- **Only `quota` sends the facts of an allowance.** The usage log has no search index. A product builds its billing from it outside sluis, in the `billing/` prefix of its project; sluis holds no prices ([ADR 0039](/decisions/0039-quota-allowance/#the-billing-log-is-outside-sluis)).
- **A meter has a name, a unit and a kind, and never changes;** only declared outcomes bill ([ADR 0040](/decisions/0040-meters-and-usage-evidence/)).

## The witness is optional

The witness is where an independent party co-signs a checkpoint: `peer` lets the nodes of a cluster witness one another, `external` lets a party outside the installation do it, and `none` is a single signer. **A witness is optional everywhere,** and `sluis config check` warns when an installation has none. In production, a log without a compliance lock needs one ([Lock modes](#lock-modes-retention-and-legal-holds)). `AuditWitnesses` declares the witnesses of each log and the cosignatures it requires.

**The cadence.** The writer asks every witness to cosign each new checkpoint of each log, at most once per witness and log every 5 seconds. When a log is idle it asks again for the latest checkpoint every 5 minutes, so a reader can tell a quiet log from a writer that stopped publishing ([ADR 0029](/decisions/0029-the-audit-log/#witnesses)).

:::caution[The risk of no witness]
With no witness, a compromised writer can get a rewritten checkpoint signed: it asks key@ for a signature over a history it changed, and nobody else has seen the old one. A compliance lock on S3 still prevents overwriting stored objects, but not a **split view**, in which different readers are shown different histories. Only a witness that cosigned the original checkpoint can expose it. On R2 the lock can be removed by an account administrator and on a local file system there is none, so there the witness is the only protection.
:::

## Lock modes, retention and legal holds

The lock mode comes from the blob backend: `compliance` on AWS S3, `removable` on Cloudflare R2, `none` on a local file system. `sluis config check` reports it and applies one rule ([ADR 0029](/decisions/0029-the-audit-log/#lock-modes)):

- **A production log needs a `compliance` lock, or a weaker lock plus a `peer` or `external` witness.** The check refuses anything else in a production boundary and warns in development and staging. The boards, on R2 with peer witnesses, pass; a single-node production installation on a local file system needs an `external` witness.
- **Each log declares its retention in `AuditLog`, and a production log must** ([ADR 0029](/decisions/0029-the-audit-log/#retention)). There is no built-in default, and the audit log and the usage log declare theirs separately. Try a period in governance mode first: a wrong period locked in compliance mode cannot be shortened.
- **Legal holds stay outside sluis.** A hold is placed and lifted with the store's own means, under cloud IAM or a break-glass role, and recorded as an audit record under the name of the person who did it. Before key@ deletes a tenant's `evidence` wrap, it checks for a standing hold.
- **Lifecycle tiers and compliance profiles** are declared in `AuditLog`. Only cold, immutable objects move to colder storage, and never the lock. Compliance profiles are floors that `sluis config check` enforces ([lifecycle tiers](/decisions/0029-the-audit-log/#lifecycle-tiers), [compliance profiles](/decisions/0029-the-audit-log/#compliance-profiles)).

## Tenants, encryption and erasure

Each tenant is a reader of the boundary's audit, and its records are sealed under its own `evidence` key ([ADR 0029](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding)):

- **Each entry is an envelope in clear plus the record,** sealed by key@ under the tenant's `evidence` key and bound to the boundary, tenant, project, log and record id. The writer may Seal and never Open, so it holds nothing that decrypts what it wrote; only the indexer and the reader may Open, under a grant. A record that concerns no tenant belongs to the operator's own tenant.
- **The envelope** (record id, time, tenant, class, outcome and actor type, with OCSF names) is a projection of the record, so a reader that decrypts can catch a writer that lies in it.
- **The tree hashes the whole entry, ciphertext included,** so a log verifies after its records stop opening.
- **Evidence and personal data never share a key.** A tenant's exit deletes its `data`, `pseudonym` and `pairwise` wraps at once, so its pseudonyms can no longer be made or reversed and its records name no one. The records stay in the logs, sealed and verifiable. Its `evidence` wrap is deleted when the evidence retention ends, the latest end of the retention of any log that holds its entries; after that nobody can read the tenant's records again, and the logs still verify ([Keys](/concepts/keys/#erasing-a-tenant)).
- **A person is a keyed pseudonym,** never a name or an e-mail address: `p1.<epoch>.<value>`, made by key@'s `Mac` under the tenant's `pseudonym` key, where an epoch is a UTC month. Within a month one person's records link to each other; across months they do not, without reversal. The emitter makes the pseudonym before the record leaves the process, and only the tenant's own audit role can reverse one ([ADR 0029](/decisions/0029-the-audit-log/#pseudonyms)).

## Search

**Search** is the **indexer**, which builds the search index from the log, the **index**, and the **reader**, which serves queries ([ADR 0028](/decisions/0028-audit-pieces/#search-and-the-index)). The indexer is the only writer of the index; the reader has only a read credential.

- **One index per boundary, partitioned by project and log kind.** Every row carries its project, log kind and tenant, and every query names the partitions it reads. The usage log and the `billing/` prefix are not indexed.
- **The index follows the checkpoints.** The indexer indexes only entries that a signed checkpoint covers, so it lags the log by a few seconds, and it can always be rebuilt from the log. It opens each record at key@ under the record's tenant's `evidence` key, and a tenant's exit purges its rows.
- **The default index** is `sqlite` on local, `rqlite` on the boards, and `postgres` on lambda (Aurora) and Kubernetes (CloudNativePG) ([ADR 0028](/decisions/0028-audit-pieces/#search-and-the-index), [PostgreSQL row-level security](/decisions/0028-audit-pieces/#postgresql-row-level-security)). The index is audit's own and not the store's business.
- **The reader is the audit API:** search, facets, a get that returns a record with its inclusion proof against a cosigned checkpoint, NDJSON exports and a tail. Every call is authorised by a grant from `policy`, which becomes a mandatory filter of the query.

**Verification never trusts the index or the store.** A verifier reads the entries, the checkpoints and the cosignatures from the log store and recomputes the tree itself.

## The audit front

Every audit has a front of its own, also when the audit module runs beside the identity module ([ADR 0028](/decisions/0028-audit-pieces/#the-audit-front)):

- **A slim `entry` of its own, on a sibling host,** `sluis-audit.<env>.example.com` beside `sluis.<env>.example.com`, so it inherits no cookie scope. The reader is the API, and the front runs its own `session` and `console`, the same executables as sluis's.
- **A console bundle of its own** shows search, records with their proofs, exports and the health of each project's logs. Another installation's console reaches the front with an exchanged token (RFC 8693) for the audit client, valid for at most 5 minutes and bound to its X.509-SVID.
- **Without the front,** `sluis audit verify` and `sluis audit read` work from a project's bucket alone with read-only cloud credentials; a payload opens only for a caller that key@ lets open it.

## Audit alone

An installation may run the foundation with the audit module only, to keep the audit of a product that does not use sluis for sign-in ([Families](/concepts/families/#the-foundation-and-the-modules)). key@ signs every checkpoint and seals every record, store@ serves the key wraps, the tenants and audit's documents, and exporter@ backs up the wraps.

- **`policy` authorises every search in this shape too.** The product's issuer is a trusted token source declared in config. The reader verifies the product's token against it, and `policy` decides from the token's claims and seals the grant that key@ checks.
- **The product pushes each tenant before the tenant's first record,** idempotently by request id, like an allowance push. A record for a tenant the boundary does not know is held in the transport and raises an alarm, so a mistyped tenant id never creates a tenant.
- **A product that later adopts sluis for sign-in adds the identity module.** Its project, buckets, logs and keys stay as they are, and nothing is migrated.

## Recovery and backup

Break-glass recovery spools its audit record locally and delivers it later instead of blocking on the audit path, so a down audit cannot shut the emergency way in ([Break-glass recovery](/security/break-glass/)). The log itself is not part of the ordinary backup: it is protected by its lock, its witnesses and its store, and the backup records `backup.completed` in it ([Data](/concepts/data/#backup-and-restore)).
