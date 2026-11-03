# 0005 — store@ holds every storage credential: one generic store service, typed clients, drivers private to their owner, and signed configuration loaded as a whole

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

sluis keeps its data as kinds ([0004](/decisions/0004-the-data-model/)). Much of its security rests on who may change which item and on what happens when two callers change one at once. A work actor holds no storage credential at rest (principle 16, [0002](/decisions/0002-families-of-actors/#credential-holders)), so one holder in the data family has to take the engines, the config sources and the secret sources, and every actor reaches data through it.

v1 put everything that is not a blob behind one State contract (v1 ADR 0027, on `master`): one key at a time, compare-and-swap by revision, listing by prefix and a lifetime, with expired items filtered on read. It had two engines, NATS JetStream on Kubernetes and DynamoDB on AWS; the JetStream half was removed on 2026-10-04 because no deployment ran it. Before that port, sessions lived in a cache with asynchronous replication, so a failover could lose an acknowledged write, sign everyone out and bring a rotated refresh token back.

v2 has installations v1 never had: a single machine with no cloud, and three small boards with nothing but each other. They need an engine that is not DynamoDB, survives the loss of one node and runs without an operator. Some actors must run exactly once, which needs a lease that a stale holder cannot use. And config has to be trusted wherever it comes from: a file, a ConfigMap or AWS AppConfig. A service that serves config is not a reason to trust what it serves (principle 4).

Facts about the engines, checked on the dates given. rqlite authorises per endpoint only, with nothing per table, row or database, and a user with `execute` can run `ATTACH` with an arbitrary path (on `query` connections `ATTACH` is refused since v10.6.3; verified on v10.6.6, 2026-10-30). rqlite is light: about 9 MiB per cluster under write load on a board, with the binary's pages paid once per board (measured 2026-10-31, [#943](https://github.com/truvity/sluis/issues/943)). rqlite has no Unix-socket listener (v10.6.6). A conditional update of one hot item on DynamoDB reaches about 1,000 to 1,080 a second, while a transaction per update reaches 91 to 149 (measured 2026-11-02, from a function in one region, 8 to 128 writers). Because store@ is the only client of an engine, an engine that cannot tell callers apart needs no instance per actor.

## Decision

**store@ is the only holder of storage credentials.** It serves one generic store service to work actors on their data port, enforces the kind registry ([0004](/decisions/0004-the-data-model/#kinds)) on every call, and has exactly four ports downward, one per storage class. exporter@ holds the credentials of its export destinations ([0009](/decisions/0009-export/)); a work actor holds none.

### The store API

#### The four ports downward

| Port | Class | Access | Drivers |
|---|---|---|---|
| Config source | config | Read-only | `file` (a directory, a mounted ConfigMap or a Lambda layer), `appconfig` (an AWS AppConfig profile) |
| Secret source | secret | Read-only | A systemd credential (boards and local), AWS SSM |
| Durable | durable | Read-write | `rqlite` (boards and local), `dynamodb` (AWS) |
| Temp | temp | Read-write | `rqlite`, `dynamodb` |

The durable and temp ports may sit on one engine; they are two ports because the classes differ in backup and in TTL. The bootstrap file names one destination per port ([The bootstrap file](/decisions/0005-the-store/#the-bootstrap-file)).

#### The service

- **There is one generic service on the wire,** served as ConnectRPC: `Get`, `List`, `Write` and `Watch`, each carrying a kind name and bytes. The store decodes and validates against the registry and applies the kind's rules. Kinds are not services: a new kind adds no method and no generated code on the wire.
- **There is no query language and no SQL.** `List` lists a tenant's items of a kind, or follows a declared index of the kind. A new question is a new declared index, reviewed with the kind ([0004](/decisions/0004-the-data-model/#kinds)).
- **A sealed kind is opaque to the store.** It keeps the ciphertext the writer sealed and the hash the writer computed; it validates the envelope, never the content. The store never seals or opens a value ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)).
- **Writes that must go together are one batch,** applied all or none, by one actor to its own kinds. There are no interactive transactions: a flow over several items is idempotent steps with a recovery marker.
- **A read of a layered kind returns its provenance:** the effective value, and for each field the layer that set it and the version. A group offers one effective read ([0004](/decisions/0004-the-data-model/#layered-and-linked-kinds)).

The verbs:

| Verb | What it does |
|---|---|
| `get` | Returns one item by address. Linearizable by default; a reader that tolerates lag may ask for a follower read. With an ETag the reply may be "unchanged" |
| `list` | Returns the items of a kind in a tenant, or by a declared index, in pages |
| `create` | Writes an item only if the address is free |
| `update` | Changes an item only at the version the caller read (`if_version`) |
| `delete` | Removes an item, optionally at a version |
| `apply` | Creates the item or sets it to the given value in one call, for a writer that owns the whole item and replays idempotently |
| `watch` | Streams the changes of a kind from a resume point ([Watch and the resume point](/decisions/0005-the-store/#watch-and-the-resume-point)) |

- **An item has a version.** The store sets it: 1 at create, plus 1 at each change. An update names the version it read. For a lease the version is the fencing token ([Leases](/decisions/0005-the-store/#leases)).
- **An item has an expiry** when its kind has a TTL ([Time to live](/decisions/0005-the-store/#time-to-live)).
- **Item keys and the sealed envelope** are on the store API reference page, with the wire contract.

### Typed clients

- **Actors use typed clients, generic on the wire.** In Go the client is `store.Client[T Kind]`. In Rust a kind is a trait, and the client is `Store<K: Kind>`:

```rust
trait Kind {
    type Id;
    type Value: prost::Message;
    const NAME: &'static str;
}
```

- **The client is generated from the kind's Protobuf message** ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf)); it builds the address from the boundary it is connected to, the tenant and id the caller passes, and the kind's name. It cannot choose who the caller is: the store learns that from the transport.
- **There is one client library per language,** not a generated service for each kind.

### Rules

- **A rule is one line of the kind registry:** an actor may use a verb on a kind. The store checks the rule on every call, before it touches data, and denies by default. The rules are generated from the kind registry and the actor registry ([0002](/decisions/0002-families-of-actors/#registries-generate-the-enforcement)); the matrix is the generated page [Rules](/reference/rules/).
- **The store learns the caller from the transport** (a peer uid, a Lambda role, or a projected service-account token, [0003](/decisions/0003-units-transports-and-fusion/#transports)). Fused work actors present one identity, and the store applies the union of their rules ([0003](/decisions/0003-units-transports-and-fusion/#fusion)).
- **A rule may limit an actor to ids under its own name,** as for the tunables, the log settings and a self-scoped kind ([0004](/decisions/0004-the-data-model/#one-writer-per-kind)).
- **The store also checks, on every write:**
  - the schema of the kind, and for a temp kind a TTL within the kind's maximum;
  - the version, for an update;
  - the bounds and the direction rule of a layered kind ([0004](/decisions/0004-the-data-model/#layers-and-the-direction-rule)), reading the config layer from the snapshot;
  - the links that the registry says are checked at write;
  - that the writer is the kind's one writer, or the actor named in the id of a self-scoped kind.
- **Every write to a tenant-scoped kind carries a grant sealed for that tenant.** The store has key@ open it and refuses the write unless it names the address's tenant and allows the verb ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). That is the store's half of the two independent checks; key@'s grant check on every Seal and Open is the other ([0007](/decisions/0007-policy-and-sealed-grants/#two-independent-checks)). key@'s own writes of `DataKeyWrap` carry no grant: key@ is itself the other check, the items are ciphertext, and a rewrap for a new board has no request to carry one.
- **While `MaintenanceMode` is set, the store refuses every write** except those of the restore command, which writes back what it restores ([0010](/decisions/0010-backup-and-recovery/#restore)).
- **exporter@ and the restore command are callers like any other,** with rules of their own. The backup reads authoritative kinds through the store as ciphertext.
- **A refusal returns a code that names the rule, and is an audit fact.**

### Watch and the resume point

- **Watch streams the changes of a kind from a resume point.** The store writes a change-log row in the same transaction as each change of a kind that some actor may watch, so no change to a watched kind is missed or invented; a kind that nobody may watch writes none, and a hot counter such as an allowance stays one conditional update ([Drivers](/decisions/0005-the-store/#drivers)); the resume point is the change-log sequence a watcher hands back after a restart.
- **A resume point that the change log no longer holds** is refused with a distinct error, and the watcher lists the kind again.
- **Config has no change log.** When the store swaps a snapshot, it delivers each changed config kind to the watchers of that kind; a watcher that reconnects reads the kind again.
- **On Lambda nothing is pushed.** A reader re-reads with an ETag, and an unchanged answer costs one small reply.
- **policy recompiles on watch,** and exporter@ watches the exportable kinds ([0009](/decisions/0009-export/#watch-and-reconcile)).

### Drivers

- **A driver is a separate binary behind one port,** private to its owner: store@, key@ or exporter@. key@'s card and KMS driver is private to key@ ([0006](/decisions/0006-keys-and-sealing/#exclusive-card-access)). Only the owner can open a driver's socket, and a work actor never sees one (principle 11).
- **The platform starts a driver; nobody execs it.** On boards it is a systemd service beside its owner's unit, on Lambda an extension of the holder's function, and on Kubernetes a native sidecar container in the holder's pod, with its socket on an emptyDir and the cloud token mounted only into the driver container ([0003](/decisions/0003-units-transports-and-fusion/#units)).
- **Each port has one contract and one CLI:** `serve`, `check`, `version` and `conformance`. `check` verifies the driver's configuration and reach; `conformance` runs the port's suite against the driver. A driver passes the suite or it is not a driver, and the in-memory engine passes it too.
- **A driver sees items only,** and never knows what a kind means. An item is a key, a version, bytes, a TTL and index entries.
- **The item contract of the durable and temp drivers has four calls:** `Get` (an item by key), `Query` (items by key prefix, paged), `Transact` (puts and deletes with conditions, all or none) and `TailLog` (the change log from a sequence). The config source and the secret source have three calls: `Read`, which returns bytes and a version label; `Capabilities`, which says how the driver signals a change (`watch`: `none`, `notify` or `poll`); and `Watch`, a stream that a `notify` driver uses to say that a newer version exists. A config source driver returns bytes and never parses them. The exact messages are on the store API reference page.
- **A `Transact` with one item and one condition is one conditional update,** not a transaction. A counter that many callers change, such as an allowance, depends on it: a conditional update of one hot DynamoDB item reaches about 1,000 a second, about ten times the estimated peak of a busy allowance, and a transaction does not (measured 2026-11-02; [0039](/decisions/0039-quota-allowance/)).
- **Each port has one driver until a second real installation needs another;** that driver arrives with that installation (principle 11). `sluis config check` refuses a driver that does not fit the runtime, such as `rqlite` on serverless.

### Engines

| Engine | Where | Notes |
|---|---|---|
| **DynamoDB** | AWS: serverless and Kubernetes | A table per engine, reachable by store@'s role only; DynamoDB TTL; needs no node or disk |
| **rqlite** | Boards, and the local installation with one node | Replicated SQLite on Raft; data on eMMC; temp data is replicated too, so any board serves any request |
| **In-memory** | Tests only | Passes the conformance suite |

- **An engine serves a boundary at L3 or above.** A boundary below L3 is served under its address prefix by its parent's engine ([0008](/decisions/0008-boundaries-and-tenants/#the-ladder)).
- **Kubernetes uses DynamoDB only** ([0011](/decisions/0011-runtimes-and-installations/#kubernetes)). A PostgreSQL engine is not in 2.0; PostgreSQL may be the audit index, which is not the store's business ([0028](/decisions/0028-audit-pieces/)). Kubernetes in 2.0 means Kubernetes on AWS ([0011](/decisions/0011-runtimes-and-installations/#kubernetes)); the direction for a cluster without AWS is PostgreSQL via CNPG, tracked by [issue #1238](https://github.com/truvity/sluis/issues/1238).
- **rqlite runs beside sluis as its own service,** one cluster of 1, 3 or 5 nodes per engine; an even number adds a node without adding fault tolerance, and 3 or more survive a failure. The engine is a platform piece, not an actor of any family ([0002](/decisions/0002-families-of-actors/#platform-pieces)).
- **Raft is the only port a board opens to another board,** with mutual TLS and a certificate per cluster, so a node of one cluster cannot join another. The certificates come from ritueel's pre-configuration. The firewall admits the Raft port from the cluster's other nodes only ([0003](/decisions/0003-units-transports-and-fusion/#calls-between-nodes)).
- **How the driver reaches rqlite.** rqlite's client API listens on the loopback address only, and the driver is its only client. The driver's unit has `IPAddressDeny=any`, `IPAddressAllow` for that address, and `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, plus a client certificate. It moves to a Unix socket if rqlite adds a socket listener. The rqlite unit is sandboxed by systemd so that it can write only its own data directory, which contains `ATTACH`.
- **Timestamps come from store@,** because rqlite does not rewrite non-deterministic defaults or triggers, and a replica would compute its own.
- **A conditional update is a conditional statement** that checks the version and the number of rows changed; writes go through the Raft log. Authority-relevant reads are linearizable. A local read on a follower can be stale: measured 2026-10-30, it missed a write acknowledged just before every time and caught up within about 50 ms; linearizable and default reads were never stale.
- **Membership is automatic.** A new node joins by discovery, a member unreachable for minutes is reaped, and a node scaled in leaves cleanly where the platform has a scale-in hook. A replacement node enrols as any host ([0022](/decisions/0022-workload-identity-and-host-enrolment/#host-enrolment)) and joins as a new member, not a returning one.
- **A snapshot copy of a database is not the backup.** The backup is a logical archive read through the store, the same on every engine ([0010](/decisions/0010-backup-and-recovery/#what-the-archive-holds)).

### Time to live

- **A temp kind has a mandatory TTL;** a durable kind has one only when it carries an expiry field. The registry gives a default and a maximum ([0004](/decisions/0004-the-data-model/#storage-classes)). A writer may ask for a shorter TTL, and never a longer one than the maximum.
- **A read checks the expiry.** An item past its expiry reads as absent, whatever the engine still holds, and a create may write it again (a `Lease` is taken over by a conditional update instead, [Leases](/decisions/0005-the-store/#leases)).
- **A sweeper removes expired items:** rqlite's leader runs it, and DynamoDB TTL does it on AWS. The sweep only frees space; correctness comes from the read-time check. A `Lease` item is the one exemption ([Leases](/decisions/0005-the-store/#leases)).
- **store@ sets every timestamp,** never the engine.

### Leases

- **A lease is a temp kind,** `Lease`: a conditional create plus a TTL (30 s by default, 10 min at most). Its version is the fencing token: it grows each time the lease changes hands, and the holder passes it with its writes. A lease item is never swept: an expired lease is taken over by a conditional update of the same item, so its version only grows. Its expiry is read-time only (on DynamoDB, a TTL attribute far in the future). A lease needs nothing of its own in the store, and there is no local lock on any installation.
- **Only background jobs take a lease:** a reconciler, a scheduled adapter, the backup job. A lease is self-scoped: its id starts with the name of the actor that takes it ([0004](/decisions/0004-the-data-model/#one-writer-per-kind)).
- **Where the target store can fence, it fences.** An audit batch is created only if absent, so the log cannot fork ([0029](/decisions/0029-the-audit-log/#the-write-once-fence)); that fence is the correctness guarantee, and a concurrency limit on a serverless writer is only an optimisation.
- **External side effects rely on the lease plus idempotent reconcilers** ([0026](/decisions/0026-reconcilers/)). A database session or advisory lock is never used alone, because it gives no fencing token.
- **A lease is not tied to the Raft leader.** It works the same on every engine.

### Configuration loading

#### Signed config documents

- **Config reaches the store as signed config documents,** one per config kind, holding all the items of the kind. A document is a JWS in general JSON serialisation (RFC 7515, section 7.2); its payload is the exact bytes of the reviewed file. The protected header carries the `kid` of the publisher key and a sequence number `seq`. The format and the test vectors are on the signed config reference page.
- **The store verifies the signature before it parses a byte.** It accepts a signature only from a publisher key pinned in the bootstrap file, and refuses any other algorithm than ES384, and any `crit`, `jku`, `x5u` or embedded `jwk`. The signature proves the publisher and the bytes; that the commit was reviewed is the branch protection of the repository.
- **A document may carry several signatures.** A regulated party's policy carries the publisher's and the party's, and the store requires both. Which kinds need a second signature is declared in the bootstrap file, as a `co_signs` list on the pinned key of the party, so that config cannot waive it.
- **The format of a payload depends on the kind.** A policy kind is Cedar text; every other kind is YAML or JSON read under the strict profile of the bootstrap file, with durations written as the grammar of [0004](/decisions/0004-the-data-model/#schemas-are-protobuf) says.
- **The signature rules are fixed.** Every signature of a document must verify under a pinned key, and a signature whose `kid` is not pinned refuses the document. All signatures of one document carry one `seq`. The same `seq` with another digest is refused. An unprotected `header` member, the compact serialisation and the flattened serialisation are refused. The naming of a document and the details of the checks are on the signed config reference page.
- **A sequence number that must grow** stops a running store from taking an older document than the one in force. It protects a running process only ([Freshness at a cold start](/decisions/0005-the-store/#freshness-at-a-cold-start)).
- **Installation-wide documents** have the same content in every boundary's config source; store@ reads its own boundary's source only ([0008](/decisions/0008-boundaries-and-tenants/#installation-wide-settings)).

#### The snapshot

- **The store loads config as a whole.** It fetches every signed document of its boundary, verifies each, validates the whole set, and swaps the **snapshot** atomically. Validation covers each document against its kind's schema, and then the checks that span kinds and layers: links resolve, config bounds sit inside the built-in bounds, and a template that a link names exists. An error names the document and the path, never the value.
- **Only the config kinds that the boundary declares have documents.** The boundary declares the kinds that the modules it runs read, a declared kind with no document is a failure, and a document for a kind that is not declared is refused. There is no empty stand-in document and no default in the place of a missing one.
- **A document is never applied alone.** There is no composition of sources and no order: one signed document per config kind, one snapshot.
- **Audit's documents are config kinds like the rest.** `AuditLog`, `AuditWitnesses` and `AuditCatalogue` are signed config documents of the boundary: the store verifies them, validates them with the whole set and swaps them in the same snapshot. The audit pieces read them through the data port and receive a changed document when the snapshot swaps. The catalogue is one document together with its schemas, so its version moves with them in one swap.
- **Every config change reloads as a whole.** Only the bootstrap file needs a restart.
- **A config source driver signals a change** by `notify` (the `file` driver watches the directory, so the atomic swap of a mounted ConfigMap is seen), by `poll` (the `appconfig` driver asks at the interval the service returns; on Lambda the poll happens at an invocation once the interval has passed) or not at all (`none`: a Lambda layer cannot change under a running function, and a new layer is a new function version).
- **Each start and each reload is an audit fact** that names, for each document, its kind, its `seq` and the SHA-384 of its payload, so a reviewer matches it to `sha384sum` of the file at the commit.
- **`sluis config check` runs the same validation offline,** as CI does before a document is published; `sluis config explain` shows the effective value of a setting with its provenance.

#### A cold start refuses on any failure

- **At a cold start, every failure stops the start.** A config source that is unreachable, a document that is unsigned, badly signed, malformed or invalid, and a snapshot that fails validation: each is an error that names the document, and store@ does not start.
- **Nothing is remembered between starts.** There is no cached copy, no default in place of a missing document and no fallback to a weaker source. A check that cannot run is reported as not run, never as passed (principle 4).

### Freshness at a cold start

- **A store that starts takes the latest validly signed document the source gives it,** whatever its sequence number. The sequence number protects a running store, which never takes a lower one; a store with nothing in force has nothing to compare with (decided 2026-11-02). There is no persisted high-water mark.
- **The audit fact of a start names the `seq` and the SHA-384 of each document,** so a reviewer or a monitor can compare them with the head of the reviewed branch and see a lag.
- **The residual, stated plainly.** If the source answers a cold start with an older document that the publisher key signed, by a rollback in the service, a fault or a replay, the store runs that document until the source serves a newer one and the store reloads it. Nothing in the store detects it; it is found afterwards, in the audit fact. What bounds it: the attacker needs the right to change what the source serves, not the publisher key, so it can roll back and cannot write. A revocation that cannot wait is a tightening in the operator layer, which is durable data, takes effect at once and needs no config ([0004](/decisions/0004-the-data-model/#layers-and-the-direction-rule)).

### A failed reload

- **The snapshot in force stays.** A source that is unreachable is retried with a back-off and reported. A document that fails verification or validation is refused whole, with the rest of the new snapshot, and audited with its digest. An alarm is raised.
- **The new snapshot is all or nothing.** The store never applies the part of a changed snapshot that validates: it would run a document that nobody reviewed or published, with an audited digest that matches no commit.
- **A refusal is reported once per refused digest,** not at every poll.

### The bootstrap file

- **The bootstrap file is the one local file store@ reads at start.** It holds the boundary, one destination per storage class, the driver sockets, and the public keys of the publishers with which the first config is verified, each shown with its SPKI hash, which is the pin, and each with an optional `co_signs` list. On a host there is one file for each boundary, in `/etc/sluis/bootstrap.d/<boundary>.yaml`, and the systemd generator creates the instances from that directory. It is the only setting whose change needs a restart; a change of a publisher key is a restart of store@.
- **It holds no credential.** The credentials of store@ (the engine login, access to the secret source) are platform-provided: a systemd credential, an IAM role or a service account ([0004](/decisions/0004-the-data-model/#what-is-not-data)).
- **It is not a kind,** and its schema is generated from Protobuf like every external config ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf)). Its keys and checks are on the bootstrap file reference page. store@ refuses a file that another uid can write.
- **The pin is the trust anchor of config.** It needs no signed document to verify the first one, so config cannot choose its own publisher.

### Secret sources

- **A secret source is read-only,** a systemd credential on boards and AWS SSM elsewhere, written by IaC. The store serves a secret kind to its listed readers only ([0004](/decisions/0004-the-data-model/#storage-classes)).
- **A secret kind is linked to the config kind it serves** (`UpstreamSecret` to `Upstream`), and config names where the secret is in the source.
- **Values are fetched on first use and held in memory.** Nothing is written to disk, and a secret never appears in an audit fact, a log line or a span.
- **The store sees secret-source values in the clear.** A secret source holds them in the clear for whoever may read it, so they pass through store@ in memory. The design accepts this and the threat model states it: a compromised store@ yields secret-source values, and no sealed data, because the store holds nothing that opens a sealed value.
- **Secret kinds are not backed up.** IaC owns them, so a restore does not carry them.
- **Tightening this on AWS is a follow-up,** not a part of this decision: the actor would open at key@ a value that the store fetched without decrypting it ([#1182](https://github.com/truvity/sluis/issues/1182)).

## Consequences

- A compromised work actor can write only the kinds its rules allow and read only what they list, checked by the store, and it holds no engine credential. The cost is a hop: every data call goes through store@, and a sealed value also goes through key@. On Lambda the hop is an invoke ([0003](/decisions/0003-units-transports-and-fusion/)).
- store@ is the one place that holds the engine credentials and sees secret-source values. It is never fused with a work actor ([0003](/decisions/0003-units-transports-and-fusion/#fusion)). A compromised store@ yields ciphertext, hashes, plain kinds and secret-source values; it can also change or delete items in its engine, and the audit log and the backup are the control against that.
- Replacing an engine is a change of installation, not of code: a driver passes the same conformance suite for the same contract.
- The boards need no external service: three boards, a disk each and the Raft ports. The cost is that a loss of 2 of 3 nodes stops writes until one returns, and that every write on a board is a Raft commit.
- The write budget has headroom: rqlite 10.6.6 commits about 430 times a second on a board, where the CPU and not the eMMC is the first limit (the figures and their dates are on the [bare-metal](/runtimes/bare-metal/) page). Rate windows and sessions are the writers that [0037](/decisions/0037-capacity-is-measured-before-it-is-promised/) re-measures.
- rqlite is a single point of project risk: one main maintainer (2026-10-26), SQLite compiled in through cgo, no embedding as a library, and three security advisories in October 2026, so each release is a rolling upgrade of one cluster. The driver is thin so that a replacement is a driver, and own Raft is the fallback.
- A reap timeout shorter than a planned outage removes a healthy node, so it is set against rolling updates. After a full power loss a cluster returns only with a quorum.
- A cold start needs the config source and every document: an AppConfig outage stops a start, and so does a document that is missing or broken. On Lambda this adds a dependency to the start of store@'s function; the measure of it belongs to that installation's tests.
- An audit piece cannot cold-start without store@, which also loads its documents. It already depends on the store through key@, whose key wraps are kinds, so a loader of its own would buy no independence.
- A signed document is not fresh at a cold start: the residual is stated under [Freshness at a cold start](/decisions/0005-the-store/#freshness-at-a-cold-start).
- A secret-source value is visible to store@: accepted, and stated in the threat model.
- The pages that follow are Store API, Bootstrap file, Signed config and [Data](/concepts/data/).

## Roads not taken

- **Embedded etcd.** A second store with a privileged control plane and no SQL for the declared indexes.
- **Own Raft on `hashicorp/raft`.** We would build snapshots, membership and conditional updates ourselves; it stays the fallback if rqlite's risk grows.
- **A query language or SQL for actors.** Any actor could ask any question, every engine would have to run it, and the rules could not be generated from the registry; a new question is a new declared index.
- **One generated service per kind.** A method and generated code per kind on the wire multiply with the registry; one generic service and typed clients give the same types without it. <!-- terms-allow: service-per-kind -->
- **The store seals and opens.** A key in store@ would let a compromise of the one holder of every engine credential read every sealed value; sealing at key@ keeps plaintext in the actor that uses it (principle 18).
- **An engine and a driver for each actor, each driver holding its actor's credential.** It puts an engine credential in every work actor against principle 16, and an engine that cannot tell callers apart needs a cluster for each owning actor, with its ports, certificates and upgrades on a 2 GB board.
- **NATS JetStream key-value for clusters.** It is replicated with revisions, but v1 removed it from its State contract because no deployment ran it, it is a second service with its own flush interval, and it adds nothing to the declared indexes.
- **A cache with asynchronous replication.** An acknowledged write can be lost on failover, signing everyone out and reviving rotated tokens.
- **Kubernetes objects as the store.** Session-rate writes load the API server, items have no lifetime, and it fits one runtime.
- **DynamoDB everywhere.** Every installation, the local one and the boards included, would need an AWS account; a local emulator is not the engine.
- **PostgreSQL as an engine in 2.0.** Nothing in the store needs a relational engine; it needs a pool on serverless and replication on the boards, and Kubernetes on AWS has DynamoDB. The later direction for a cluster without AWS is PostgreSQL via CNPG as the store engine, tracked by [issue #1238](https://github.com/truvity/sluis/issues/1238); its key source is decided when it has a consumer.
- **The Kubernetes Lease as the lease on Kubernetes.** It needs RBAC for leases, the stores the holder writes do not check its token, and it serves one runtime.
- **A DynamoDB transaction for every update of a hot item.** It measured 91 to 149 updates a second on 2026-11-02, against about 1,000 for a conditional update.
- **Several config sources composed by path ownership, or a later source that overrides an earlier one.** A document in a service could override a reviewed file with no trace in git, and the effective value would depend on the order of a list; one signed document per kind, loaded as a snapshot, has no order.
- **Trusting the config service's own access control for authority.** The right to write to AppConfig would become the right to grant, against principle 4.
- **Publisher keys that are themselves signed by a root, with the roots pinned in the bootstrap file.** Publisher keys would rotate without a restart, but every change would need a root signature, which is a ceremony. It can follow when publisher keys rotate often enough to matter.
- **A signed last known good copy, kept in a layer, on disk or in the store, for a cold start when the source is down.** It is the oldest authority the installation has, a grant revoked since would come back at the moment the operator cannot publish, and it starts the process without the check that failed.
- **A persisted high-water mark, a `min_seq` floor or an expiry in the signed header.** Each is a second home for state that must itself be trusted: a floor that is too high stops every start, a stale one protects nothing, and an expiry stops a quiet installation when its last document runs out.
- **A rule per path for what a reload may change.** Every key would need a reviewed classification, and a snapshot that mixed the two kinds would be refused whole. With one rule, only the bootstrap file needs a restart.
- **Applying the valid part of a changed snapshot.** The process would run a document that nobody reviewed or published, and the next restart would change its behaviour again.

## Follow-ups

- Secret-source values on AWS, tightened: the actor opens at key@ a value that store@ fetched without decrypting it. [#1182](https://github.com/truvity/sluis/issues/1182).
- Delete, list and watch in the store service, and the conformance suite of the drivers: [#1009](https://github.com/truvity/sluis/issues/1009).
- The config loader, the `file` and `appconfig` drivers, the check and the signed-document vectors: [#1157](https://github.com/truvity/sluis/issues/1157).
- Reloading the snapshot of a running store on every runtime: [#977](https://github.com/truvity/sluis/issues/977).
