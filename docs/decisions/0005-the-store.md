# 0005 — State is one port with compare-and-set; one writer owns each record kind, enforced by the backend; every value is encrypted; clusters replicate with rqlite

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

sluis keeps records: sessions, signing metadata, directory facts, operator-set configuration, quota balances and meters. Much of its security rests on who may change which record, and on what happens when two callers change one at once.

v1 put everything that is not a blob behind one State port (v1 ADR 0027, on `master`): one key at a time, compare-and-swap by revision, listing by prefix and a lifetime, with expired records filtered on read. It had two engines, NATS JetStream on Kubernetes and DynamoDB on AWS; the JetStream half was removed on 2026-10-04 because no deployment ran it. Before that port, sessions lived in a cache with asynchronous replication, so a failover could lose an acknowledged write, sign everyone out and bring a rotated refresh token back.

v2 adds installations v1 never had: a single machine with no cloud, and three small boards with nothing but each other. They need a store that is not DynamoDB, survives the loss of one node and runs without an operator. v2 splits the core into actors ([0041](/decisions/0041-core-actors-with-one-responsibility-each/)), and a compromised actor must not rewrite a record it does not own. Some actors must run exactly once, which needs a lease a stale holder cannot use. Each port is protected in three layers ([0003](/decisions/0003-units-transports-and-fusion/#three-layers-per-port)); this record fixes the state port's contract, its layer-2 check per driver and its encryption.

Facts about the backends, checked on the dates given: rqlite authorises per endpoint only, with nothing per table, row or database, and a user with `execute` can run `ATTACH` with an arbitrary path (on `query` connections `ATTACH` is refused since v10.6.3; verified on v10.6.6, 2026-10-30). rqlite is light: about 9 MiB per cluster under write load on a board, with the binary's pages paid once per board (measured 2026-10-31, [#943](https://github.com/truvity/sluis/issues/943)). rqlite has no Unix-socket listener (v10.6.6).

## Decision

### The port

- **`state` is one port.** An actor sees one contract whatever sits behind it ([0002](/decisions/0002-families-of-actors/#ports-and-drivers)).
- **Records carry a revision, and every write has a precondition.** The operations are `get`, `put` (creates only if absent) and `cas` (changes only against the revision the caller read). There is no unconditional overwrite.
- **Writes that must go together are one atomic batch.** There are no interactive transactions; a flow over several records is idempotent steps with a recovery marker.
- **Expiry is part of the contract.** A record past its lifetime reads as absent, whatever the engine did with it.
- **Record keys never contain personal data.** Keys stay in the clear so the store can index and list them.
- **Further operations are out of scope here:** delete, listing by prefix, and watch or a change feed, tracked in [#1009](https://github.com/truvity/sluis/issues/1009) for v1 parity. A conditional adjust of a counter belongs to quota and is added only if the quota load test shows contention ([0053](/decisions/0053-quota-consistency-and-failure-are-measured-per-state-driver-before-enforcement-is-switched-on/#the-load-test)).

### One writer per kind

- **Every record kind has exactly one writer**, the actor that may create and change it. Other actors read it only if their manifest says so. Which kinds exist, their origins and the operator-set routing are [0004](/decisions/0004-the-data-model/#origins).
- **The state backend enforces it, with its own check of the caller.** A rule in each actor's code is a rule a compromised actor can skip, so there is no `state-owner` mediator. Each actor's state driver runs `per-actor` and holds only that actor's credential:
  - **`embedded`:** a SQLite file per actor, owned by that actor's uid.
  - **`rqlite`:** one cluster for each pair of boundary and owning actor. The owner holds the `execute` user; each declared reader holds a `query`-only user.
  - **`dynamodb`:** a table per boundary, an IAM condition on `dynamodb:LeadingKeys` for each actor's role; at L4 the table is in the boundary's own account.
- **The users, roles and policies are generated from the manifests** ([0002](/decisions/0002-families-of-actors/#the-permission-manifest)), and each driver's check has a test with the other layers switched off.
- **The console never writes a record itself**; the backend would refuse it.

### Leases

- **`lease` is a separate port**: `acquire` and `renew` on a named lease. Acquiring returns a fencing token that grows each time the lease changes hands, and the holder passes it with its writes.
- **An actor that declares `instances: exactly 1` needs a lease** when there is more than one node or the nodes are elastic. On a single node a local lock is enough.
- **Leases live on the state store**, as compare-and-set with a fencing token, on every state driver, independent of the Raft leader. The named `leader` lease stays available. On Kubernetes the lease is on `dynamodb`, as on Lambda; a Kubernetes Lease driver is backlog.
- **Where the target store can fence, it fences.** A PostgreSQL index write checks the token in the same transaction. Audit batches are created only if absent, so the log cannot fork ([0029](/decisions/0029-the-audit-log/#the-write-once-fence)); that fence is the correctness guarantee, and a concurrency limit of 1 on a serverless writer is only an optimisation. With one log per node the boards' audit writers need no lease.
- **External side effects rely on the lease plus idempotent reconcilers.** A database session or advisory lock is never used alone, because it gives no fencing token.

### Every value is encrypted

- **Every value of `state` is encrypted in the port library**, whatever its sensitivity. The store sees ciphertext and record keys only.
- **The cipher is AES-256-GCM, with one data key for each pair of boundary and record kind**, wrapped under the boundary's sealing key through the `keys` port (`wrap`, `unwrap`; [0006](/decisions/0006-keys-and-sealing/)). The sealing key is an environment key; tenants have no key of their own, only data keys wrapped under it.
- **The additional authenticated data is (boundary, kind, key, version).** A value copied to another record, kind or boundary does not decrypt.
- **Unwrap is allowed for the kind's writer and its declared readers only.** On `key-holder` this is its access list; on KMS the sealing key is symmetric, so it is the key policy plus a condition on the encryption context.
- **A data key is rotated before its AES-GCM usage limit.** Kinds with a high write rate rotate theirs by count.

### Sealed secrets

- **State may hold a sealed secret on every runtime.** A sealed value uses the same envelope as every value, with `purpose=secret` in the encryption context and the additional authenticated data, so a sealed secret cannot be read as an ordinary value or the other way round. A `sealed-state` driver keeps the ciphertext in `state` and is a `secrets` driver.
- **Each version of a secret is one immutable item**, and the record that names the current version changes by compare-and-set.
- **A re-seal rewraps the data keys** under the new sealing key; the values are not decrypted and written again.
- **A backup archives sealed values sealed.** When a data key is sealed, an escrow copy of it is encrypted to the archive's recipients: at least two held apart, one of them an offline hardware token ([REQ-BACKUP-001](/requirements/backup/#REQ-BACKUP-001), [REQ-BACKUP-020](/requirements/backup/#REQ-BACKUP-020)). The backup side never reads a secret. Losing the sealing key is a restore from those archive recipients; it is not a root ceremony and copies no key out of its store.
- **This supersedes v1's retirement of sealing** (v1 ADR 0028, on `master`, sealed written secrets in state; sealing was retired two days later in favour of a secrets store). The boards have no secrets store, and a vendor-issued secret needs a place.
- **Interface details of the `secrets` and `export` ports are out of scope here**, tracked in [#1014](https://github.com/truvity/sluis/issues/1014); the archive format is [#1015](https://github.com/truvity/sluis/issues/1015).

### Drivers

| Driver | Fits | Notes |
|---|---|---|
| `embedded` | One node: the local installation and a single machine | A SQLite file per actor; not replicated |
| `rqlite` | Bare metal, 1, 3 or 5 nodes | Replicated SQLite on Raft, a cluster per boundary and owning actor; 3 or more to survive a failure; needs a disk; provides the lease |
| `dynamodb` | Anywhere with an AWS account: serverless and Kubernetes | A table per boundary, a leading key per actor role; needs no node or disk; provides the lease |

- **Kubernetes uses `dynamodb` only** for state and leases ([0011](/decisions/0011-runtimes-and-installations/#kubernetes)). A PostgreSQL or CloudNativePG state driver is not in 2.0; `postgres` exists as an index driver ([0028](/decisions/0028-audit-pieces/#search-and-the-index)), isolated as [0003](/decisions/0003-units-transports-and-fusion/#postgresql-row-level-security) says.
- **`sluis config check` refuses a driver that does not fit the runtime**, such as rqlite or `embedded` on serverless, and an actor that needs a lease with no lease driver.

How the rqlite clusters are run:

- **Each cluster runs beside sluis as its own service**, from the systemd template `sluis-rqlite@<boundary>-<actor>`, with a port scheme for its HTTP and Raft ports. A cluster is 1, 3 or 5 nodes: an even number adds a node without adding fault tolerance.
- **A cluster opens two TCP ports on each node, its Raft port and its HTTP port, and nothing else.** Both are among the named flows between nodes of [0003](/decisions/0003-units-transports-and-fusion/#listeners). Node-to-node and client traffic use mutual TLS with a certificate per cluster, so a node of one cluster cannot join another; the firewall admits the Raft port from the cluster's other nodes only, and the HTTP port from the cluster's nodes, where its own drivers run, only.
- **Each rqlite unit is sandboxed by systemd** so that it can write only its own data directory. That contains `ATTACH`.
- **Compare-and-set is a conditional update** that checks the revision and the number of rows changed; writes go through the Raft log as atomic batches.
- **Timestamps come from the application**, because rqlite does not rewrite non-deterministic defaults or triggers and a replica would compute its own.
- **Authority-relevant reads are linearizable.** Reads that tolerate lag may be served by a follower; callers choose the level per read.
- **Membership is automatic.** A new node joins each cluster by discovery; a member unreachable for minutes is reaped; a node scaled in leaves cleanly where the platform has a scale-in hook. A replacement node enrols as any host ([0022](/decisions/0022-workload-identity-and-host-enrolment/#host-enrolment)) and joins as a new member, not a returning one.

### How a per-actor rqlite driver reaches its cluster

- **Through a narrow network rule per unit, not `PrivateNetwork=yes`:** `IPAddressDeny=any`, `IPAddressAllow=` for its own cluster's addresses only, and `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, plus a client certificate for that cluster.
- **It moves to a Unix socket if rqlite adds a socket listener.** Every other driver stays on Unix sockets only ([0003](/decisions/0003-units-transports-and-fusion/#listeners)).

## Consequences

- A compromised actor can write only its own kinds and read only what its manifest lists, checked by the backend itself; no mediator is in the path of a state call.
- Replacing a state driver is a change of installation, not of code: a driver passes the same conformance suite for the contract.
- A store-level reader learns little: a backup, a database administrator or a process that bypasses the port sees ciphertext and record keys, and a moved value does not decrypt. The cost is an unwrap per data key, an AEAD per value, and kinds whose record keys must be designed to carry no personal data.
- The boards need no external service for state: three boards, a disk each and the Raft ports. The cost is that sluis operates many small replicated databases, one per boundary and owning actor, each with its ports, certificates, users file, backups and upgrades; a loss of 2 of 3 nodes stops writes until one returns. rqlite's users file is static, so a change of owners or readers, which comes only with a release, needs a restart.
- The write budget is ample: about 7 commits a second at today's measured peak, against about 430 commits a second measured for rqlite 10.6.6 on a board, where the CPU and not the eMMC is the first limit (57 times headroom; the figures and their dates are on [the bare-metal page](/runtimes/bare-metal/)).
- rqlite is a single point of project risk: one main maintainer (2026-10-26), SQLite compiled in through cgo, no embedding as a library, and three security advisories in October 2026, so each release means a rolling upgrade of every cluster. The driver is kept thin so that a replacement is a driver, and embedded Raft is the fallback.
- A local read on a follower can be stale: measured on 2026-10-30, it missed a write acknowledged just before every time and caught up within about 50 ms; linearizable and default reads were never stale.
- A reap timeout shorter than a planned outage removes a healthy node, so the timeout is set against rolling updates. After a full power loss a cluster returns only with a quorum, and waits for keys that are locked until an operator unlocks them.
- A unit with a `per-actor` rqlite driver has a network stack, limited by its address rule and its per-cluster certificate rather than by a namespace.
- A snapshot copy of a database is not the backup: the backup is a logical archive read through the ports, the same on every driver ([0004](/decisions/0004-the-data-model/#backup-and-restore-by-origin)).
- A lease works the same on every driver and does not move with the Raft leader; a stale holder is refused by its fencing token wherever the target store checks it.

## Roads not taken

- **NATS JetStream key-value for clusters.** It is replicated, with revisions and compare-and-set, and is also a transport driver; but v1 removed it from the State port because no deployment ran it (v1 ADR 0027), it is a second service with its own flush interval to review, and it adds nothing to the index, which wants SQL. NATS JetStream stays a transport driver only.
- **A cache with asynchronous replication.** An acknowledged write can be lost on failover, signing everyone out and reviving rotated tokens; v1 retired it.
- **Kubernetes objects as the store.** Session-rate writes load the API server, records have no lifetime, it fits one runtime, and sluis never writes Kubernetes objects.
- **DynamoDB everywhere.** Every installation, the local one and the boards included, would need an AWS account; a local emulator is not the engine.
- **PostgreSQL as a state driver in 2.0.** Nothing in state needs a relational engine, it needs a pool on serverless and replication on the boards, and Kubernetes has DynamoDB; it can be added later as a driver that passes the suite.
- **Embedded Raft on `hashicorp/raft`, or etcd.** We would build snapshots, membership and compare-and-set ourselves, or run a second store with a privileged control plane and no SQL for the index; embedded Raft stays the fallback if rqlite's risk grows.
- **A `state-owner` mediator, or one rqlite cluster per boundary with an actor column.** Isolation would be the mediator's code and every state call its blast radius, or every `execute` user could rewrite every record and `ATTACH` files; a cluster per owning actor lets the backend check the caller.
- **One writer per kind kept by convention, or only secret and personal values encrypted.** A convention is not checked, and a misclassified field leaks in the clear and a moved value goes undetected.
- **The Kubernetes Lease as the lease on Kubernetes.** It needs RBAC for leases, the stores the holder writes do not check its token, and it serves one runtime.
- **Leaving sealed state out of v2.** The boards would have no place for a vendor-issued secret; v1 retired sealing only where a managed secrets store existed.

## Follow-ups

- Further state operations (delete, list by prefix, watch), v1 parity: [#1009](https://github.com/truvity/sluis/issues/1009).
- A conditional adjust, only if the quota load test shows contention: [#1145](https://github.com/truvity/sluis/issues/1145).
- Interface details of the `secrets` and `export` ports: [#1014](https://github.com/truvity/sluis/issues/1014).
- Backup archive format, escrow copies and restore tooling: [#1015](https://github.com/truvity/sluis/issues/1015).
