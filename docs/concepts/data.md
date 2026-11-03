---
title: Data and secrets
description: "Who owns which sluis record and how it is sealed: origins and sensitivities, one writer per kind, encryption, the data ports, secrets and export."
status: target
sidebar:
  order: 7
---

sluis keeps records: sessions, directory facts, operator-set configuration, quota balances, the signing ring's metadata, audit batches. Most of the security of the design rests on who may change which of them and who can read them. Three rules carry it: every record kind has an origin and a sensitivity ([ADR 0004](/decisions/0004-the-data-model/)), every record kind has one writer, and every value is sealed before it reaches a store ([ADR 0005](/decisions/0005-the-store/)). Secrets follow the same rules, behind a port of their own.

## Origins and sensitivity

Every stored **record kind** declares one **origin**, and every field one **sensitivity**, in the configuration schema. Together they decide where a value lives, who may write it, whether it is in a backup, what a restore does with it, whether it may leave sluis, and what an audit record, a log line or a span may say about it. The backup list, the deny matrix, the telemetry allowlist and the audit redaction are generated from them ([ADR 0004](/decisions/0004-the-data-model/#origins)).

To classify a record kind, ask in order; the first "yes" is its origin.

| Origin | The question | Examples | Written by |
|---|---|---|---|
| **declared** | Did an operator write it in a reviewed file, delivered read-only? | the install file, policy, clients, exchange trust, quota limits, export recipients, the card slot map override | Nobody at run time |
| **operator-set** | Did a person choose it at run time, on the console, the CLI or the API, as a lasting intent? | chat channels managed from the console, runtime switches, a console-connected directory tenant, a secret put at run time | The actor that owns the kind |
| **learned** | Can sluis rebuild it without a person from an external system, by pull or by push? | directory users and groups, memberships, discovered channels, a client metadata cache | The integration that observed it |
| **derived** | Can sluis rebuild it from its own records or log? | the search index, quota meters and hourly aggregates | The deriving actor |
| **issued** | Otherwise: sluis created it, or a vendor or a person handed it over once. **Durable** or **ephemeral** | durable: client secret versions, revocations, the issuance log, vendor-issued secrets, pins, account links, approvals, quota balances; ephemeral: sessions, refresh tokens, codes, leases | The issuing actor |

An act, such as an approval or a consent, is an issued record of the act, not configuration. A grant is not a stored record: it is a sealed output of `policy` in flight. The audit log and the non-extractable keys are outside the model.

| Sensitivity | Meaning | Audit record | Telemetry | Logs |
|---|---|---|---|---|
| **public** | Meant to be published (key sets, CA certificates) | yes | only allowlisted | yes |
| **internal** | Not published, personal or secret (client ids, channel names, digests) | yes | allowlisted identifiers only | yes |
| **personal** | About an identifiable person (an e-mail address, a subject, a membership) | pseudonymised | never | redacted by default |
| **secret** | Credential material that is read | a fingerprint and a revision only | never | never |

A field may also carry a **free-text** flag, for text a person typed: it never enters telemetry, and its length in an audit record is bounded.

## One writer per record kind

Every **record kind** has exactly one **record writer**: one actor that may create and change it. Other actors may read it if their manifest says so. The port library scopes every call to `<boundary>/<kind>/…` from the actor's own identity, and the store checks the actor's own credential: a file per actor uid on `embedded`, an `execute` user for the owner and `query`-only users for readers on `rqlite`, a `dynamodb:LeadingKeys` condition per role on DynamoDB ([ADR 0005](/decisions/0005-the-store/#one-writer-per-kind)). There is no state mediator in between.

Examples; the record kinds of the first working version, with their writers, origins and lifetimes, are on [Storage](/reference/storage/#record-kinds-of-the-first-working-version), and the full list is generated from the manifests:

| Record kind | Its single writer | Why only one |
|---|---|---|
| Audit batch sequence | The audit writer of that log | The sequence must have no gaps or forks ([One writer per log](/concepts/audit/#exactly-one-writer-per-log)) |
| Quota balances | `quota` | Balances change only through `quota`; the meters are derived from the usage log |
| Signing ring | `signer` | The ring is the authority for token keys |
| Sessions | `session` | The owner of sessions and the session cookie |
| Directory snapshots | The facts integration that produced them | Another process holds only a cached copy with an expiry |
| Operator-set records of a kind | The actor that owns the kind, on a request routed by `console` | The owner validates the write with its own logic; the manifest says which kinds accept operator-set writes |

When two processes seem to need to write one record, the record is split instead: the learned fields become a kind the integration writes, and the operator-set fields a kind its owning actor writes. The word **writer** by itself means this on this page, not the audit writer actor.

**Trust classes are kept apart.** Operator-set records, learned facts, issued records, sessions and quota state never share a namespace, even when pieces share one driver instance, and they use separate stores where an installation allows. Vendor-issued secrets sit behind the `secrets` port, and authority keys have their own holder.

## Every value is encrypted

**Every state value is encrypted in the port library**, before it reaches any driver, whatever its sensitivity. A store, its replicas and its backups hold ciphertext and record keys only ([ADR 0005](/decisions/0005-the-store/#every-value-is-encrypted)).

- **AES-256-GCM, with a data key per (boundary, record kind).** It is wrapped under the boundary's sealing key through the `keys` port, and a data key is rotated before its AES-GCM usage limit.
- **The sealing key is one per environment boundary**: on AWS a symmetric KMS key with an encryption context per use, on a card the P-384 ECDH key in slot `9d` ([Keys](/concepts/keys/#the-card-slot-map)). Tenants have no key of their own, only data keys wrapped under it; grants and the session cookie key are wrapped under it with their own purpose.
- **Unwrapping is allowed for the kind's writer and its declared readers only**: by the `key-holder` access list, or by the KMS key policy with an encryption-context condition.
- **The additional authenticated data is (boundary, kind, key, version)**, so a value moved to another record, kind, boundary or version fails to decrypt.
- **Record keys never contain personal data.** They stay in the clear so the store can index and list them, so they must not carry an e-mail address or a name.

## Ports

Actors reach their data through five ports. Each has a contract that does not change with the technology behind it; the messages and the on-disk layout of the local drivers are on [Storage](/reference/storage/). The drivers of each installation are on [Installations](/runtimes/installations/).

| Port | What it holds | The contract |
|---|---|---|
| `state` | Records, with revisions | `get`, `put` that creates only if absent, compare-and-set, an atomic batch and expiry. There is no unconditional put: a caller changes a record only against the revision it read |
| `index` | A search index derived from the audit log | Apply a batch, read and set a cursor, query, rebuild from the batches |
| `blob` | Immutable objects, such as audit batches | Put once (an atomic [create-if-absent](/concepts/drivers/#create-if-absent)), get and list by key, with a lock mode of none, removable or compliance |
| `transport` | Messages that must survive a restart, or a stream of them to the writer | Put, receive, acknowledge, return with a delay; or a direct stream |
| `lease` | Named, time-limited ownership | Acquire and renew, with a fencing token; a lease ends when it is not renewed |

A record past its lifetime reads as absent, whatever the engine did with it. There are no interactive transactions: a flow over several records is idempotent steps with a recovery marker.

### The atomic batch

A **write batch** applies several writes together or none of them. The audit writer uses it to register the sealed batches of its audit log and its usage log, record the ids it de-duplicated and move its cursor, so a crash cannot leave one without the others and the two logs never disagree ([ADR 0029](/decisions/0029-the-audit-log/#sealing)). The next number of the sequence is allocated by a compare-and-set inside the same batch.

### Further operations

:::note[Proposed]
Delete, listing by prefix and a feed of changes are further state operations, planned for v1 parity in [#1009](https://github.com/truvity/sluis/issues/1009). A **conditional adjust** is a quota matter: it changes a number by a delta and refuses if the result would cross a floor, as one operation on the store. It is added only if the quota load test shows that compare-and-set on a hot counter contends ([ADR 0053](/decisions/0053-quota-consistency-and-failure-are-measured-per-state-driver-before-enforcement-is-switched-on/#the-load-test), [#1145](https://github.com/truvity/sluis/issues/1145)); until then quota uses compare-and-set.
:::

### Leases and fencing tokens

A lease is **named**: one for each thing that needs a single owner, and many can be held at once by different holders. Acquiring a lease returns a **fencing token**, a number that grows each time the lease changes hands. A holder passes its token with every write it makes under the lease, and the store refuses a token lower than one it has seen, so a holder that was paused, lost its lease and woke up believing it still held it cannot write over the new holder ([ADR 0005](/decisions/0005-the-store/#leases)).

- **Leases live on the state store**, built on compare-and-set with a fencing token, on every state driver, independent of the Raft leader. A named lease `leader` stays available. On a single node a local lock is enough.
- **Where the target store can fence, the fence is in that store.** A Postgres index write checks the token in the same transaction, and audit batches are created only if absent, so a log cannot fork; with one log per node, the boards' audit writers need no lease.
- **External side effects** rely on the lease plus idempotent reconcilers. A database advisory lock is never used alone, because it gives no fencing token.
- On Kubernetes, leases and state are on DynamoDB; there is no Kubernetes Lease driver and no PostgreSQL state driver in 2.0.

## Secrets and export

sluis holds secrets because it has to: a GitHub App key that the vendor issued through a manifest flow, a chat token, a generated client secret. **sluis stores its own secrets and its integrations' secrets, and publishes a small, typed set of values.** It is not a general secrets engine: it offers no arbitrary key-value storage, dynamic secrets, leases or transit to others. Where a caller needs a credential for a vendor, sluis **mints a scoped credential** ([Integrations](/integrations/)) instead of storing the caller's own.

| Port | What it is for |
|---|---|
| `secrets` | Whole values under addresses: sluis's own secrets and the secrets of its integrations. A listing returns names, never values |
| `export` | A small set of typed, versioned documents that something outside sluis may read |

`keys` holds material that never leaves its store; `secrets` holds values that are read. A secret is never a plain record in `state`, and never appears in an audit record (a fingerprint and a revision only), in telemetry or in a log line.

### Where a secret comes from

A secret's origin decides who wrote it and whether it is backed up ([ADR 0004](/decisions/0004-the-data-model/#origins)):

| Origin | Example | Lives in | In a backup |
|---|---|---|---|
| declared, by reference | a vendor root token the operator keeps in their own store | the operator's store, read through a source | no; sluis only names it |
| operator-set | a secret put with `sluis secrets put` or pasted on the console | sluis's own store | yes, sealed |
| issued by a vendor | a GitHub App key from the manifest flow, a chat bot token | sluis's own store | yes, sealed |
| issued by sluis | a generated client secret, a minted credential | sluis's own store, or not stored if short-lived | durable ones yes, sealed |

### Sealed state

A **`sealed-state`** driver is a `secrets` driver that keeps its ciphertext in `state`. Sealed state is allowed on every runtime ([ADR 0005](/decisions/0005-the-store/#sealed-secrets)) and is the one `secrets` store in 2.0 ([ADR 0009](/decisions/0009-export/#one-driver-sealed-state)).

- **A sealed value uses the same envelope as every value**, with `purpose=secret` in the encryption context and the additional authenticated data, so it cannot be read as an ordinary value or the other way round.
- **Each version of a secret is one immutable item**, and the record that names the current version changes by compare-and-set, so a rotated secret can overlap with its predecessor.
- **A re-seal rewraps the data keys** under the new sealing key without decrypting the values.
- **A backup archives sealed values sealed**, with escrow copies of the data keys of sealed secrets encrypted to the archive's recipients; losing the sealing key is a restore from those recipients, not a ceremony ([Backup](/concepts/backup/#encryption)).

Nobody outside sluis can read sealed state, so an exported value goes out through a drop.

### The export port

Exports are **typed and versioned**: a document has a kind, a schema and a version, and a breaking change is a new version written beside the old one for a deprecation window. Whether a value may leave sluis is a property of its kind: a kind marked external is published through `export` ([ADR 0004](/decisions/0004-the-data-model/#backup-and-restore-by-origin)).

| Class | Example | Channel |
|---|---|---|
| Public material | The key set, CA certificates, trust bundles | Static publication; no secret involved |
| Declared data | Rendered policy, the objects an integration needs at its vendor | Rendered files, applied by the operator |
| Learned data | Directory snapshots, group memberships | An authenticated read with a grant |
| Secrets | A generated client secret, an App key, a minted credential | A drop, or a read from a consumer-readable store |

**Copies are not made twice.** An exported value is stored once. The consumer is granted the path on its own side (its role, its policy), and sluis may render that grant for the operator to apply; sluis never holds the consumer's identity. A secret referenced from declared configuration is exported by granting the consumer the operator's own path, not by copying it. A drop is a derived, single-writer artefact of one document, replaced as a whole. sluis never writes Kubernetes objects: it exports, and clusters pull.

### Drops are age-encrypted to the consumer

A **file drop** (a file in a directory that a node-local consumer reads) and a **bucket drop** (an object in a bucket) are **age-encrypted to the consumer's own recipient**, a named exception to sluis's algorithm rules ([ADR 0006](/decisions/0006-keys-and-sealing/#named-exceptions)). The consumer's private key can sit on a hardware token (an `age-plugin-yubikey` recipient); sluis holds only the public recipient. A drop is therefore safe in a bucket others can read, and a stolen copy of sluis's state does not open it.

The operations of the two ports, the writable **stores** against read-only **sources**, the driver flags, and the rule that `sealed-state` is the one `secrets` store and that only a kind marked external is exported are [ADR 0009](/decisions/0009-export/). A drop driver is built when an issue names its consumer; none has one today.

## What is backed up

A backup holds only operator-set records and durable issued records, with secrets archived sealed; a restore invalidates every session ([Backup and restore](/concepts/backup/)).
