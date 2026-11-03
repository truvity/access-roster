---
title: Audit
description: "The sluis audit trail: OCSF records and a usage stream, one writer per log, a write-once fence, witnesses, lock modes and company encryption."
status: target
sidebar:
  order: 6
---

sluis writes a tamper-evident audit trail. This page explains the ideas; the records are [ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/), the log [ADR 0029](/decisions/0029-the-audit-log/), and the pieces, transport, search and front [ADR 0028](/decisions/0028-audit-pieces/). How a record travels from an actor to the log, with the sockets and the failure cases of each installation, is drawn in the [audit explorer](/architecture/audit-explorer/).

## What is audited

**Every success is audited.** When an actor does something for a caller, such as signing a person in, issuing a token, minting a credential or changing a record, it appends an audit record, so every actor is a producer. **What was used goes to a usage log beside it**: an action that uses something, such as a metered call or a quota top-up, sends one message with an audit part and a usage part, and the writer puts each part into its own log ([The usage stream](#the-usage-stream)).

## The four pieces

Audit is built from the same [ports and drivers](/concepts/drivers/) as the rest of sluis and adds one port of its own, the witness. It is four separate pieces ([ADR 0028](/decisions/0028-audit-pieces/#four-pieces)):

| Piece | What it is | Ports it uses |
|---|---|---|
| **Emitter** | A library inside each end application, configured by that application; not a process. From one call it builds one message | **transport**, as a producer |
| **Log** | The **writer**, the log store and the **witness**. The writer receives messages, validates and de-duplicates them, seals them in batches and writes two log kinds, the audit log and the usage log | transport (as the receiver), blob, keys, witness, state, lease where needed |
| **Search** | The **indexer**, the index and the **reader** | index, blob |
| **Quota** | The **quota engine** and its state | state, with compare-and-set |

The audit actors are the writer, the witness, the indexer and the reader. The writer asks `key-holder` to sign checkpoints, and `key-holder`'s access list lets only the writer use the log key.

**Each piece can be its own installation, and pieces are separate by default.** Audit is its own installation, connected to sluis through the transport port. When pieces are combined in one installation, even with sluis, they share driver instances; the defence-in-depth layers stay per actor ([Defence in depth](/concepts/drivers/#defence-in-depth)). Where each piece's actors run is derived ([Where an actor runs is derived](/concepts/drivers/#where-an-actor-runs-is-derived)).

## Exactly one writer per log

**Each log has exactly one writer**, and **a cluster keeps one log per node**. A log is the ordered sequence of entries of one kind (audit or usage) written by one writer. The writer declares `instances: exactly 1`.

- **On a cluster of nodes,** each node has its own writer, its own spool and its own log key. The other nodes are that log's **peer witnesses**, two of three on a three-node cluster. No writer reads another node's spool, so there is nothing to elect and no writer lease is needed; when one node is down the others keep writing their own logs. Readers merge the logs of a boundary by the time each entry was recorded, keep each log's own order, break ties by log id, and claim no order across logs closer than the clock offsets the seals record.
- **On the local installation** there is one log of each kind.
- **On serverless** the one writer function runs with a reserved concurrency of 1 on a standard SQS queue; throttled messages return to the queue. The limit is an optimisation; correctness comes from the write-once fence.
- **On Kubernetes** there is one log of each kind per writer, with the writer's KMS log key and a lease on the state store.

**One log key per writer signs both of its log kinds**, and each signed checkpoint names its log. The two kinds have one writer, one audience, one lifetime and one revocation, so they share the key. The log key rotates only on compromise, because a log's signatures must verify for the life of the log ([ADR 0029](/decisions/0029-the-audit-log/#tiled-log)).

| Installation | Log key | Witness |
|---|---|---|
| [local](/runtimes/installations/#local) | A software key through `key-holder` | None |
| [boards](/runtimes/installations/#boards) | Each node's own card signs that node's log, through its `key-holder` | The other two nodes, as `peer` witnesses |
| [lambda](/runtimes/installations/#lambda) | One KMS `ECC_NIST_P384` key whose key policy names the writer function's role only | None by default; `external` is possible |
| [kubernetes](/runtimes/installations/#kubernetes) | One KMS key per writer, named in the writer's ServiceAccount role | None by default; a `peer` witness is not independent within one cluster |

## The write-once fence

**Every object of a log is written once, and the blob store is the fence** ([ADR 0029](/decisions/0029-the-audit-log/#the-write-once-fence)). Entry bundles and tiles, partial tiles included, are created only if absent, so a second writer that believes it owns a log cannot overwrite or fork it: its create fails. sluis supports only blob backends with an atomic create-if-absent ([Create-if-absent](/concepts/drivers/#create-if-absent)), and no actor's credential carries a delete right on the log store, except an expiry sweeper's right on expired objects. Where a lease is needed, it lives on the state store with a fencing token ([Data and secrets](/concepts/data/#leases-and-fencing-tokens)).

## Batches and checkpoints

sluis follows the C2SP specifications and invents no format for the log ([ADR 0029](/decisions/0029-the-audit-log/#tiled-log)):

- **The log** is a `tlog-tiles` log: entry bundles and hash tiles are static objects in the blob store that anyone with read access can fetch without a server.
- **Checkpoints** are C2SP `signed-note` documents in the `tlog-checkpoint` shape, signed with the P-384 log key, naming the log's origin, size and root hash. Removing, reordering or altering an entry breaks every later checkpoint.
- **A witness** signs with `tlog-cosignature`, using an Ed25519 or ML-DSA-44 key, and is asked through the `tlog-witness` protocol.
- **The issuance log** of `ca` records every X.509 certificate it issues in a C2SP `static-ct-api` log, witnessed in the same way.

**The layout.** Each log has one prefix, `<kind>/<boundary>/<log>/` with `<kind>` `audit` or `usage`, and every checkpoint is also written once to `checkpoints/<size>`, so the full history survives on a store with no versioning.

**Sealing** ([ADR 0029](/decisions/0029-the-audit-log/#sealing)):

- A batch is sealed at **256 messages or 5 seconds** after its first, whichever comes first; one seal covers the audit batch and the usage batch of the same messages, and an empty batch is never sealed.
- Each batch ends with a **seal entry**, in clear, with the record count, the writer instance and the observed clock offset, inside the tree so the witnesses cosign it.
- The writer writes the bundles and tiles, has the checkpoint signed, writes it, and in one atomic state batch registers the sealed batches of both kinds, the ids it removed as duplicates and its transport cursor ([The atomic batch](/concepts/data/#the-atomic-batch)). A crash leaves all of it or none, so the two logs never disagree.
- **Delivery is at least once.** Each message carries a UUIDv7 id (RFC 9562) set by the emitter, and the writer remembers ids for 14 days, the longest retention of a supported queue; an older message is quarantined and reported until an operator releases it.
- **A blocking emit** returns once the record is durable in the transport. Credential and administrative changes use it, so the change fails when the emit fails.

## The transport

The transport is a port, not a piece: it joins the emitter to the writer ([ADR 0028](/decisions/0028-audit-pieces/#transport)).

| Mode | Drivers | How the record travels |
|---|---|---|
| **direct** | `direct-unix` (the writer on the same host), `direct-mtls` | The emitter streams the record to the writer |
| **queue** | `spool` (a local fsync'd spool), `sqs`, `nats-jetstream` | The emitter puts the record into a queue; the writer receives and acknowledges it |

**The default follows the runtime:** the spool on bare-metal, SQS on serverless, and NATS JetStream on Kubernetes, which the customer-identity installation on Kubernetes runs as its reference. `direct` is a supported driver with no default. **Direct mode falls back to a local spool** when the writer is down, and replays when it returns, so direct mode needs a disk and is not available on serverless. An in-memory buffer is not offered, because it would lose records.

**The emitter is authenticated by the transport's own layer**, the second layer of [defence in depth](/concepts/drivers/#defence-in-depth):

| Driver | How the producer is authenticated |
|---|---|
| `direct-unix` | The peer uid, read by the writer |
| `direct-mtls` | The SPIFFE ID in the client certificate |
| `spool` | A spool directory per producer uid |
| `sqs` | A queue policy per sender role, and a queue per boundary |
| `nats-jetstream` | NATS accounts and permission templates: an operator per environment, an account per boundary, the company as an account tag, the user `<actor>@<boundary>` |

## Records

**An audit record is an OCSF event of a core class, with no OCSF extension** ([ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format)). Each release pins one OCSF version in `metadata.version`; the first pins **OCSF 1.9.0**, and an upgrade moves one minor release at a time, as a checked pull request. Records are never rewritten. Where OCSF has no activity for an action, the record uses activity 99 (`Other`) with a name. The class of each action is in [ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-class-mapping).

The sluis action is `metadata.event_code`, the company `metadata.tenant_uid`, the environment boundary `metadata.log_name`, the record id `metadata.uid`, the release `metadata.product.version`, and the actor `actor.user.uid = <actor>@<boundary>`, where a person or external actor is a keyed pseudonym before the `@`.

**What OCSF has no attribute for goes in one object, `unmapped.sluis`**, and nowhere else in `unmapped`. Its schema is sluis's own, closed and generated in CI. The first fields are `sender_binding` (a token's DPoP or mTLS thumbprint), `token` (audience and scopes), `assurance` (`acr`, `amr`), `key` (kind, algorithm, store and slot), `attestation`, `config`, `enrolment`, `quota`, `certificate` (an issued or revoked X.509 or SSH certificate), `actor_chain` and `approver`; the generated schema is the exact list ([ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-sluis-fields-unmappedsluis)). An extension comes only if a real consumer needs typed fields.

**The action table is code** ([ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-action-table-is-code-and-the-release-identifies-it)). Each action's class and activity, required fields, sensitivity, declared meters and searchable fields are a table in the emitting product's code. The records' JSON Schemas are generated from it in CI and ship with the release. There is no catalogue document and no catalogue field: the product, the release and the event code identify the entry in force, and an auditor takes the schema from the release a record names.

- **The same bytes end to end.** A record is RFC 8785 canonical JSON. The emitter makes the bytes, the transport carries them, the writer checks they are canonical and stores them unchanged, and the reader returns them as they are. Integers stay within ±(2^53−1); a larger value is a string.
- **The stored record is lean**; an export adds the enum captions, the `observables` and an integrity attestation that points back to the log entry. The writer enforces the generated schema and is authoritative, and Go and Rust emitters validate before they emit.
- **A record never carries a secret, an e-mail address, a name or a token**; a secret appears as a fingerprint and a revision.

## The usage stream

**The usage stream holds what was used**, as CloudEvents 1.0 events in structured JSON, canonical by RFC 8785, shaped like OpenMeter's usage events: the `type` selects a meter, the `subject` is the account, and `data` holds the unit, a signed integer amount, the request id and the subject's pseudonym. Its `id` is the audit record's id with the event's position in the message ([ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-usage-stream)).

- **One call, one message, two logs.** The emitter builds the audit record and the usage events from one call and sends one message; the writer splits it and seals both in the same atomic batch. There is no dual write, no second writer, and no usage event without its audit record.
- **Each kind is a log of its own:** its own prefix or bucket, checkpoints, retention, lock mode, readers and witnesses, signed by the same log key. Usage entries carry no personal data and are encrypted per company to the company's usage key, never its audit key ([ADR 0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/)).
- **Quota and finance read it, and only quota writes balance effects into it.** The usage log has no search index. The finance export is a table derived from it with FinOps FOCUS 1.4 column names; sluis holds no prices.

## The witness is optional

The witness port is where an independent party co-signs a checkpoint: `peer` lets the nodes of a cluster witness one another, `external` lets a party outside the installation do it, and `none` is a single signer. **A witness is optional everywhere**, and `sluis config check` warns when an installation has none. In production, a log without a compliance lock needs one ([Lock modes](#lock-modes-retention-and-legal-holds)).

**The cadence.** The writer asks every witness to cosign each new checkpoint of each log kind, at most once per witness and log every 5 seconds. When a log is idle it asks again for the latest checkpoint every 5 minutes, so a reader can tell a quiet log from a writer that stopped publishing ([ADR 0029](/decisions/0029-the-audit-log/#witnesses)).

:::caution[The risk of no witness]
With no witness, a compromised writer can get a rewritten checkpoint signed: it asks `key-holder` for a signature over a history it changed, and nobody else has seen the old one. A compliance lock on S3 still prevents overwriting stored objects, but not a **split view**, in which different readers are shown different histories. Only a witness that cosigned the original checkpoint can expose it. On R2 the lock can be removed by an account administrator and on `fs` there is none, so there the witness is the only protection.
:::

## Lock modes, retention and legal holds

The lock mode comes from the blob backend: `compliance` on AWS S3, `removable` on Cloudflare R2, `none` on `fs` ([capability flags](/concepts/drivers/#capability-flags)). `sluis config check` reports it and applies one rule ([ADR 0029](/decisions/0029-the-audit-log/#lock-modes)):

- **A production log needs a `compliance` lock, or a weaker lock plus a `peer` or `external` witness.** The check refuses anything else in a production boundary and warns in development and staging. The boards, on R2 with peer witnesses, pass; a single-node production installation on `fs` needs an `external` witness.
- **Each log declares its retention, and a production log must** ([ADR 0029](/decisions/0029-the-audit-log/#retention)). There is no built-in default, and the audit log and the usage log declare theirs separately. S3 applies it as per-object retention, R2 as the bucket lock rule, `fs` through an expiry sweeper that may delete expired objects only. Try a period in governance mode first: a wrong period locked in compliance mode cannot be shortened.
- **Legal holds stay outside sluis.** A hold is placed and lifted with the store's own means, under cloud IAM or a break-glass role, and recorded as an audit record under the name of the person who did it. Nothing in sluis stops a company-key shred during a hold, so the shred procedure checks for a standing hold first, and on a store with no hold flag (R2, `fs`) the operator suspends expiry for the held range by hand.

Compliance profiles (floors that `sluis config check` enforces) and lifecycle tiers (only cold, immutable objects move, and never the lock) are [ADR 0029](/decisions/0029-the-audit-log/).

:::note[Proposed]
Which audit installation receives the audit of the workforce installation is a product fact that the design cannot set. It fixes the queue wiring, the audit data keys and the profiles that apply there, and is tracked in [#1143](https://github.com/truvity/sluis/issues/1143). Until it is decided, the serverless shape is specified up to the queue.
:::

## Companies, encryption and erasure

There is one audit log per environment boundary (per node on a cluster), and each company is a reader tenant of it ([ADR 0029](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding)):

- **Each entry is an envelope in clear plus the record, encrypted with HPKE (RFC 9180) to the company's audit data key.** The record is encrypted with a key per (company, batch), sealed to the public part of that key, so the writer cannot read back what it wrote. The private part is held only wrapped under the boundary's sealing key: a company has no key of its own in a key store ([Keys](/concepts/keys/#aws-kms-layout)). A machine-plane record is encrypted to the boundary's own audit data key, and a usage entry has the same form but is encrypted to the company's usage data key, a key of its own with the lifetime of the usage retention.
- **The envelope** (record id, time, company, class, outcome and actor type, with OCSF names) is a projection of the record, so a reader that decrypts can catch a writer that lies in it. The operator's own view of a company's records is the envelope.
- **The tree hashes the whole entry, ciphertext included.** A company that leaves has its slice exported and its audit data key deleted; its records stay in the log, sealed and verifiable, and nobody can read them again. Its usage data key is kept until the usage retention ends, so billing evidence outlives the personal data ([ADR 0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/)).
- **The erasure of one person is met by the pseudonym.** A person or external actor is a keyed pseudonym, never a name or an e-mail address; the mapping from a pseudonym to the person lives outside the log, and erasure deletes it. There are no per-subject keys in 2.0. Pseudonyms are HMAC-SHA384 of the subject under a data key per company and month, so they rotate monthly, and only the company's own audit role reverses one ([ADR 0029](/decisions/0029-the-audit-log/)).

## Search

**Search** is the **indexer**, which builds the search index from the log, the **index**, and the **reader**, which serves queries ([ADR 0028](/decisions/0028-audit-pieces/#search-and-the-index)). The indexer is the only writer of the index and declares `instances: exactly 1`; the reader has only a read credential.

- **The index follows the checkpoints.** The indexer indexes only entries that a signed checkpoint covers, so it lags the log by a few seconds, and it can always be rebuilt from the log. There is one index per boundary with a company column; the indexer is a declared reader of each company's key, and a shred purges that company's rows.
- **The default index** is `sqlite` on local, `rqlite` on the boards, and `postgres` on lambda (`aurora`) and Kubernetes (`cnpg`) ([The postgres index driver](/concepts/drivers/#the-postgres-index-driver)).
- **The reader is the audit API**: search, facets, a get that returns a record with its inclusion proof against a cosigned checkpoint, NDJSON exports and a tail. Every call is authorised by a grant from `policy`, which becomes a mandatory filter of the query, and every read is itself audited.

**Verification never trusts the index or the state store.** A verifier reads the entries, the checkpoints and the cosignatures from the log store and recomputes the tree itself.

## Quota

**Quota** is the quota engine and its state, and it meters by default and enforces per policy rule, for chosen subjects or audiences ([ADR 0030](/decisions/0039-quota-allowance/#the-allowance)). Enforcement is strict in 2.0, by compare-and-set on the state port; whether to relax it is decided after the load test of the mint path. Its API is `Admit`, `Confirm`, `Cancel`, `TopUp`, `Adjust` and `Balance`: every changing call is idempotent by a `request_id`, amounts are signed 64-bit integers in a declared unit, balance effects live in the usage log and only quota writes them, and an enforcing rule must declare what happens when its balance runs out and when quota is unreachable.

- **Plans are declared and accounts are issued.** A declared client creates an account at run time under a declared plan ([ADR 0039](/decisions/0039-quota-allowance/)).
- **A meter has a name, a unit and a kind, and never changes;** only declared outcomes bill, and an event belongs to the period of its own time within a stated skew ([ADR 0040](/decisions/0040-meters-and-usage-evidence/)).

:::note[Proposed]
These are proposed records. Their open parts are tracked in [#915](https://github.com/truvity/sluis/issues/915) and [#1026](https://github.com/truvity/sluis/issues/1026).

- **Billing pulls a statement** per account and period, closed once and anchored in the usage log ([ADR 0051](/decisions/0051-the-finance-export-is-a-statement-per-account-and-period-closed-once-anchored-in-the-usage-log-and-pulled/)).
- **Services call over mutual TLS with their SVID, and people with exchanged tokens;** a quota installation has no console until a consumer exists ([ADR 0039](/decisions/0039-quota-allowance/)).
- **Consistency and failure are measured per state driver** before enforcement is switched on ([ADR 0039](/decisions/0039-quota-allowance/)).
:::

## The audit front

Every audit installation has a front of its own, also when the audit pieces are combined with sluis ([ADR 0028](/decisions/0028-audit-pieces/#the-audit-front)):

- **A slim `entry` of its own, on a sibling host**, `sluis-audit.<env>.example.com` beside `sluis.<env>.example.com`, so it inherits no cookie scope. The `reader` is the API, and the front runs its own `session` and `console`, the same executables as sluis's; it accepts only the issuer of its environment.
- **A console bundle of its own** shows search, records with their proofs, exports and the log's health. Another installation's console reaches the front with an exchanged token (RFC 8693) for the audit client, valid for at most 5 minutes and bound to its X.509-SVID.
- **Without the front,** `sluis audit verify` and `sluis audit read` work from the bucket alone with read-only cloud credentials; a payload decrypts only for a caller who may unwrap the company's key.

## Recovery and backup

Break-glass recovery spools its audit record locally and delivers it later instead of blocking on the audit path, so a down audit installation cannot shut the emergency way in ([Break-glass recovery](/security/break-glass/)). The log itself is not part of the ordinary backup: it is protected by its lock, its witnesses and its store ([Backup](/concepts/backup/#the-audit-log-is-handled-separately)).
