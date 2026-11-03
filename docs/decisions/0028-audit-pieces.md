# 0028 — Audit is four pieces joined by a transport port, search is an index fed from the log, and an audit installation has its own front

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #903](https://github.com/truvity/sluis/issues/903).

## Context

Audit was one box: a queue port and an outbox joined the application to the writer, and the log, the search index and quota were tied together. A small installation had to run all of them, and a large one shared their failures. A cluster has several nodes, and a log with two writers cannot keep one hash chain.

Audit uses the same port definitions as sluis ([0002](/decisions/0002-families-of-actors/#ports-of-a-work-actor)): the log store is a `blob` with a lock mode, quota state is `state` with compare-and-set, and search uses `index`. Audit adds only the `witness` port. People have to read the log: auditors, operators, and each company for its own records, so something has to face them.

v1 built the same split for search: the indexer listed the bucket from a cursor (v1 ADR 0062, on `master`), the indexer and the query service were separate processes with separate database roles (v1 ADR 0066), and the query contract was a closed filter grammar with keyset cursors, facets, a get with provenance and an asynchronous export (v1 ADR 0048). v1's standalone audit console was an OpenID Connect relying party with a cookie session (v1 ADR 0049).

The log itself, its layout, sealing, witnesses, lock modes and encryption, is [0029](/decisions/0029-the-audit-log/). What a record holds, the usage stream and quota are [0030](/decisions/0030-audit-records-and-the-usage-stream/). The threats this record answers are T-1 to T-7, T-11, T-13, T-16, T-21 and T-26 of the [threat model](/security/threat-model/).

## Decision

### Four pieces

- **Audit is four separate pieces:**
  - **Emitter:** a library inside each end application, configured by that application; not a process. From one call it builds one message: an OCSF audit record and, for an action that uses something, usage events ([0030](/decisions/0030-audit-records-and-the-usage-stream/#usage-is-derived-from-the-same-event-once)).
  - **Log:** writer, blob store and witness ([0029](/decisions/0029-the-audit-log/)).
  - **Search:** indexer, index and reader (below).
  - **Quota:** quota engine and its state ([0030](/decisions/0030-audit-records-and-the-usage-stream/#quota)).
- **Each piece can be its own installation, and pieces are separate by default.** Audit is its own installation, and sluis emits to it through the transport port.
- **The audit actors are writer, witness, indexer and reader.** There is no notary actor: the writer asks `key-holder` to sign checkpoints, and `key-holder` lets only the writer use the log key ([0006](/decisions/0006-keys-and-sealing/#exclusive-card-access)).
- **Combined pieces share driver instances.** When pieces are combined in one installation, even with sluis, they use the same driver instances. Isolation is had by running them as separate installations.
- **The search index and the quota meters are derived data,** rebuilt from the log and never evidence ([0004](/decisions/0004-the-data-model/#storage-classes)).

### Transport

- **Transport is a port, not a piece.** It joins the emitter to the writer and replaces the old queue port and outbox. It has four drivers in two modes:
  - **direct:** the emitter streams to the writer, over a Unix socket on the same host or over mutual TLS;
  - **queue:** the emitter puts records into a queue and the writer receives them. Queue drivers are **spool**, **SQS** and **NATS JetStream**.
- **The default transport follows the runtime:** spool on bare-metal, SQS on serverless, and NATS JetStream on Kubernetes, which the reference Kubernetes installation, the customer-identity one, runs. Each of the three stays possible on the other runtimes where it fits. Direct is a supported driver with no default. A writer on the same node as sluis is one installation's placement, not part of the model.
- **In direct mode the emitter falls back to a local spool** when the writer is down. Direct mode therefore needs a disk and is not available on serverless.
- **An emitter is authenticated by the transport driver's own layer** ([0007](/decisions/0007-policy-and-sealed-grants/#two-independent-checks)), T-13.

### Search and the index

- **Search is the `indexer`, the `index` and the `reader`.** The indexer is the only writer of the index and declares `instances: exactly 1`, so with more than one node it holds a lease ([0005](/decisions/0005-the-store/#leases)). The reader serves queries with only a read credential on the index. They are separate actors with separate credentials, so a flaw in query parsing is not a flaw in a writer of the index. Their language follows [0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table), and where they run is derived ([0003](/decisions/0003-units-transports-and-fusion/#units)): with `sqlite` on a cluster the reader runs on the indexer's node, with `rqlite` or `postgres` on any node.
- **The indexer follows each audit log of its boundary by checkpoint.** It keeps one cursor per log, checks each new checkpoint's signature and its consistency with the previous one, and only then fetches the entry bundles up to the checkpoint's size. It indexes only entries a signed checkpoint covers. Notifications only wake it.
- **Indexing is idempotent, keyed by the record's hash.** The index can always be rebuilt from the log alone (REQ-AUDIT-016), is not backed up, and verification never trusts it. Rows of records past the log's retention go when the log's objects do.
- **The index port is:** apply a batch, read and set a cursor, query, rebuild from the batches ([Data](/concepts/data/#ports)).
- **The usage log has no search index.** Quota follows it and the finance export is derived from it; the indexer neither follows it nor holds a key for it.
- **What the index stores:** fixed columns for the core fields, mapped from OCSF paths of the record ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format)): time, recorded at (the writer's stamp), log, boundary (`metadata.log_name`), company (`metadata.tenant_uid`), action (`metadata.event_code`, with `class_uid` and `activity_id`), outcome (`status_id`, `status_code`), actor (`actor.user.uid`, `actor.user.type_id`), and the subject, target and request-id paths that the action table entry declares, trace id (`metadata.correlation_uid`) and record id (`metadata.uid`). The column set is the same on every driver. Beside them: a typed attribute table for the properties the action table marks filterable or facetable, keyed by OCSF path (a JSON Pointer); the record itself, once; and one full-text table, external-content, over the fields the action table marks searchable and no other. A personal field is not searchable unless the action table says so.
- **One index per boundary, with a company column.** The indexer is a declared reader of each company's audit data key, so it can decrypt what it indexes ([0029](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding), T-11). The reader filters every query by the caller's grant, and on `postgres` row-level security on the company column adds the database's own check ([0028](/decisions/0028-audit-pieces/)). When a company is shredded its rows are purged, and every later rebuild skips it (T-26).
- **Word search without stemming, the same on every driver:** FTS5 `unicode61` with `remove_diacritics 2`, and Postgres `simple` with `unaccent`. Prefix queries are allowed; there is no substring search.
- **A rebuild builds a new generation beside the serving one, then switches the reader to it atomically.** A failed rebuild leaves the old index serving. A rebuild runs after a restore, a schema or tokenizer change, an action table change that marks a new field, a shred, and on demand (`sluis audit reindex`).
- **Index drivers:**

  | Driver | Where | Layer 2: the backend's own check |
  |---|---|---|
  | `sqlite` | one node; the local installation | a file per indexer uid; the reader opens it read-only |
  | `rqlite` | a cluster of nodes; the boards | an rqlite cluster for the index, the indexer with the `execute` user, the reader with a `query`-only user |
  | `postgres` | any runtime, by provisioning mode | a schema per actor kind, `FORCE ROW LEVEL SECURITY`, actors never own tables, PostgreSQL 15 or newer |

- **`rqlite` is the index of the boards.** Full-text search on rqlite was tested on 2026-10-30 with rqlite 10.6.6 (SQLite 3.53.4), on one node and on a three-node cluster, with the arm64 image under emulation; rqlite itself was measured on a board on 2026-10-31 ([Bare metal](/runtimes/bare-metal/)). Reads go at `none` with a small freshness bound, and at `weak` where a caller must read its own write; writes are batched in one transaction per request. FTS5 on the boards' own hardware and eMMC is not measured yet; if it fails there, the boards fall back to `sqlite` on the indexer's node with the reader beside it, and no new decision is needed.
- **The default index of each tested installation:** local `sqlite`; boards `rqlite`; lambda `postgres` in the `aurora` mode; kubernetes `postgres` in the `cnpg` mode.
- **`sluis audit search` on the CLI builds a local `sqlite` index from the log,** for a small installation or an auditor with read access to the bucket.

### Provisioning modes

- **The `postgres` index is one driver with one provisioning mode per installation:**
  - `rds` or `aurora` on AWS;
  - `cnpg` on Kubernetes, in the same cluster;
  - `external`: a connection string only, and sluis provisions nothing. A database exposed through a load balancer, or a Postgres someone runs on bare metal, is `external`. Its security and availability are the operator's; `sluis config check` probes the connection.
- **A serverless indexer and reader reach Postgres through RDS Proxy with IAM authentication,** with one database role per actor kind ([0023](/decisions/0023-certificate-authorities/#database-client-certificates)). The functions run in the VPC and use endpoints for the other AWS APIs.

### The reader

- **The reader is the audit API.** It authenticates every call itself and serves queries from the index. Its contract is Connect with unary calls only, like every public sluis API, with a TypeScript client from connect-es.
- **It offers:** Search, with a closed filter grammar, keyset cursors whose next page never disappears, and free text `q` over the searchable fields; Facets; Get, which returns a record as the canonical bytes the emitter produced, with its inclusion proof against a cosigned checkpoint; Export, an asynchronous job that writes NDJSON ([0030](/decisions/0030-audit-records-and-the-usage-stream/#export)) and ends in a short-lived signed URL; and a tail, a repeated Search with the cursor. Server streaming may come later, as an option on long-lived hosts.
- **Every call is authorised by `policy`.** The reader asks for a grant: the boundaries, the companies, the operations among search, get, export and tail, a time window, and a full or envelope view. The grant is a mandatory filter of the query (T-16). An operator's grant gives the envelope view (REQ-AUDIT-038). Every read is itself audited, with the rule that granted it.
- **The reader merges the logs of a boundary by recorded time** (REQ-AUDIT-035), by the rule of [0029](/decisions/0029-the-audit-log/#witnesses).

### The audit front

- **Every audit installation runs its own `entry`, also when the audit pieces are combined with sluis.** A combined installation runs two fronts, each with its own `entry` and its own host, so the audit front is the same shape everywhere. It is the same `entry` executable as sluis's, with the route tables of the audit contracts and an instance name of its own, and it is the slim router of [0002](/decisions/0002-families-of-actors/#the-four-families): it parses, validates against closed lists generated from the audit contracts and routes; it holds no key, no secret and no state, and has no outbound network (T-4).
- **It is its front's only edge listener** ([0003](/decisions/0003-units-transports-and-fusion/#listeners)). The edge connector is the runtime's: a tunnel to a Unix-socket origin on bare-metal, the API gateway on serverless, a key-less relay container or `cloudflared` on Kubernetes ([0011](/decisions/0011-runtimes-and-installations/#kubernetes)).
- **The audit front has a sibling host:** `sluis-audit.<env>.example.com` beside `sluis.<env>.example.com`, and `sluis-audit.example.com` beside `sluis.example.com`. A sibling inherits no cookie scope from the boundary host (T-6, T-7). Every passkey verifier's origin allow-list names it ([0017](/decisions/0017-identity-and-sign-in/#passkeys)).
- **The audit installation runs its own `session` and `console`,** the same executables as sluis's. `session` is an OpenID Connect client of the issuer of the environment boundary whose log it holds, seals an HttpOnly cookie with its own key and checks passkeys itself for step-up (T-5); the browser holds no token. The audit console therefore needs no `session` or `console` of sluis beside it, but it does need the boundary's issuer. A token for one environment's log cannot be used for another's (T-3), and a token whose `aud` is not the audit installation's registered client id is refused (T-2).
- **A console of another installation reaches the audit front with an exchanged token:** RFC 8693 at the issuer the audit front accepts, `aud` the audit client id, a lifetime of at most 5 minutes, bound to the console's X.509-SVID by mutual TLS (RFC 8705). The person's identity reaches the reader, which decides with its own policy (T-1, T-21).
- **The audit console is a static bundle of its own,** built from the same source tree on the same release train as the sluis console, served on the same origin as the audit `entry`, with only audit pages and a tighter content security policy. Reads go straight to the reader. Writes, such as an index rebuild, go through the audit `console` actor, which checks the operator's delegation and routes each write to the actor that owns its record kind; the reader stays read-only. The console offers search with facets, records with their proofs and verification status, exports, and the log's health: the age of the latest checkpoint, the witness cosignatures and the index lag. Who sees what follows the reader's grants: a company its own records in full, an operator the envelope, a security reviewer what a declared grant names.
- **Without the front, `sluis audit verify` and `sluis audit read` work from the bucket alone,** with read-only cloud credentials and no `entry`, reader or sign-in. A payload decrypts only where the caller may unwrap the company's key. Auditors and incident responders are never locked out by the front or the issuer.

## Consequences

- A small installation can run the log alone and add Search or Quota later. A failure in one piece does not stop the others; a combined installation shares the failure and the access of its driver instances.
- An emitter has no process to run, but the application owns its transport configuration. Spool as the direct-mode fallback keeps records when the writer is down, at the price of a disk on every emitting node and a spool to drain in order.
- Four transport drivers and three provisioning modes need tests and docs, and one conformance suite covers the index port. Ranking that differs between index drivers is declared.
- A Search installation can be added to a running log and dropped, because everything it holds comes from the log. A rebuild costs time, not data, and needs twice the index's storage. The index lags the log by the seal interval plus the indexer's pass, a few seconds.
- Word search without stemming finds names, ids and codes the same everywhere, but "login" does not find "logged". A newly marked field covers old records only after a rebuild.
- The index holds readable copies of what the log holds encrypted per company, and the indexer can read every company's records; a shred has to reach the index, which the purge does.
- Every lambda installation pays for an Aurora database and an RDS Proxy, and its indexer and reader run in the VPC. The `rqlite` index costs one more small cluster per boundary on the boards, with reads that may lag the leader by tens of milliseconds.
- One policy language serves sluis and audit, and reads are accountable: a read costs a policy call and adds a record to the log. The reader's authentication and grant filter carry the confidentiality of the log and need tests with the other layers switched off.
- A combined installation runs two edge listeners and needs two hosts; on a board that is a second tunnel route, a second certificate name and a second `entry` instance. Splitting audit off later changes no host. Each environment gains a host in DNS, certificates and every passkey verifier's allow-list.
- An audit installation runs a `session` and a `console` of its own: two more actors and one more key (its cookie-sealing key). A second console bundle is built, signed and tested per release.
- Reading the log through the front depends on the issuer; a read from the bucket is the way around it, so bucket read access is granted carefully.

## Roads not taken

- **Separate audit ports.** Audit could change its interfaces freely, but the driver and test matrix doubles; audit shares the sluis ports and adds only `witness`.
- **A fixed audit with log, search and quota in one box.** One thing to install, but a shared blast radius and every installation pays for every part.
- **Fail the operation, or buffer in memory, when the writer is down in direct mode.** Failing stops every audited operation; buffering in memory loses records on a restart, and an audit trail that drops records under failure is not one.
- **Cloudflare Queues as a transport driver.** Another driver to write and test that adds nothing over spool, SQS, NATS JetStream and direct.
- **The writer indexes as it writes, or one process for indexing and queries.** The writer would hold the index credential and stall when the index fails; one process would parse callers' queries while holding the write credential.
- **List the bucket, as v1 did.** A listing shows objects whether or not a checkpoint covers them, and tile names say nothing about time or tenant.
- **An index per company, or an index of the clear envelope only.** Many indexes and a fan-out for cross-company reviews, or no search beyond the envelope; one index with a company column, a grant filter, row-level security and a purge on shred covers it.
- **A scan driver `none` that reads the log for every query.** No consumer: the CLI builds a local `sqlite` index instead, and every tested installation has an index.
- **A search engine of its own (OpenSearch or a log store), or the RDS Data API.** A heavy service to run and secure on boards for a volume SQLite FTS5 and Postgres cover; the Data API is Aurora only, needs a secret per role and is a second SQL path to test.
- **A remote plugin call from the sluis console instead of an audit `entry`, or the reader facing the edge itself.** The actor holding the index credential would parse internet input, and an audit installation would be unreadable without a sluis console.
- **One `entry` for both contract sets in a combined installation.** One listener fewer, but that `entry` parses both contract sets and the audit front would differ between combined and separate installations.

## Follow-ups

- Build of the search piece and its v1 parity: [#839](https://github.com/truvity/sluis/issues/839).
- Build of the audit front: [#985](https://github.com/truvity/sluis/issues/985).
- The quota installation's front: [#1026](https://github.com/truvity/sluis/issues/1026).
