---
title: Ports and drivers
description: "Ports and drivers: the port interfaces and capability flags, how drivers are started and reached, key-holder, and what each driver requires."
status: target
sidebar:
  order: 2
---

An [actor](/concepts/actors/) needs things from outside itself: keys to sign with, a place to keep records, a place to put audit archives. It asks for each through a **port**, an abstract interface with capability flags where the technologies behind it differ. The technology that answers it is a **driver**, and a driver declares what it requires: a long-running process, a local disk, a number of nodes, or a **dependency** such as an AWS account ([ADR 0002](/decisions/0002-the-design-model-actors-ports-drivers-and-contracts/#ports-and-drivers)).

An actor sees one contract per port, whatever sits behind it. `signer` calls "sign with the token key" on the keys port; whether that lands on AWS KMS, a YubiKey or a software key is installation configuration, not actor code.

## Port interfaces

| Port | Interface | Capability flags and notes |
|---|---|---|
| `keys` | `sign`, `public-key`, `wrap`, `unwrap` | `wrap` and `unwrap` (or an `ecdh` operation) protect a data key without the key leaving its store. A driver declares the signing algorithms it supports ([Keys](/concepts/keys/#algorithms)) |
| `state` | `get`, `put` (create only if absent), `cas`, an atomic batch, expiry | `cas`: compare-and-set. There is no unconditional put ([Data and secrets](/concepts/data/#ports)) |
| `lease` | `acquire`, `renew` on a named lease | Built on the state store's compare-and-set; every acquire returns a fencing token |
| `blob` | `put-once`, `get`, `list` | A lock mode: `none`, `removable` or `compliance`. `put-once` is an atomic create-if-absent ([Create-if-absent](#create-if-absent)) |
| `transport` | `put`, `receive`, `ack`, or `stream` | How an emitter hands an audit record to the writer, through a queue or directly ([Audit](/concepts/audit/#the-transport)) |
| `index` | apply a batch, cursor, `query`, rebuild | The search index of the audit log |
| `witness` | `cosign` | The one port that audit adds |
| `cloud` | `credentials(cloud, role)` | Short-lived cloud credentials for the calling actor |
| `secrets` | values under addresses | `writable`, `encryption`, `versioned`; interface planned ([Secrets and export](/concepts/data/#secrets-and-export)) |
| `export` | typed documents for outside readers | interface planned ([Secrets and export](/concepts/data/#secrets-and-export)) |
| `config-source` | `read` one document as bytes, with a version label | `watch`: `none`, `notify` or `poll`. Read-only, and the one port with a list of drivers in an installation: the sources are composed by disjoint ownership of paths ([Configuration sources](/reference/config-sources/), [ADR 0057](/decisions/0057-configuration-sources-are-a-port-sources-own-disjoint-paths-authority-is-signed-and-a-failing-source-keeps-the-version-in-force/)) |

## Capability flags

Two ports carry flags that an actor can require, so that "any driver for this port" is not always enough.

**Blob lock mode.** A blob driver declares how strongly an object stays locked once written:

| Backend | Lock mode | What it means |
|---|---|---|
| `fs` | `none` | Nothing stops a local administrator from changing a file; tamper evidence comes only from witnesses |
| `s3-compatible` on Cloudflare R2 | `removable` | A bucket lock rule that an account administrator can remove |
| `s3-compatible` on AWS S3 | `compliance` | Object Lock in compliance mode: not even the account's root can shorten the retention |

An actor states the lock mode it needs; the audit log's rule is on [Audit](/concepts/audit/#lock-modes-retention-and-legal-holds).

**State `cas`.** An actor that changes a record more than one caller can reach requires compare-and-set. Quota's balances are the main case: strict enforcement is compare-and-set on the mint path ([ADR 0017](/decisions/0017-audit-records-the-usage-stream-and-quota/#quota)).

### Create-if-absent

Every blob driver must refuse to overwrite an existing object on a `put-once`, atomically, so that the blob store can be the audit log's [write-once fence](/concepts/audit/#the-write-once-fence). sluis supports only backends that give it:

| Driver | How |
|---|---|
| `s3-compatible` on AWS S3 and Cloudflare R2 | `PutObject` with `If-None-Match: *`: 412 Precondition Failed if the key exists, and of concurrent writers at most one succeeds (both providers' documentation, checked 2026-10-31) |
| `fs` | A temporary file, fsynced, then `link()` or `renameat2(RENAME_NOREPLACE)` to the target name (both fail if it exists), then an fsync of the directory. Local POSIX filesystems only |

The [port conformance suite](https://github.com/truvity/sluis/issues/851) tests it under concurrent writers for every blob driver. Garage is backlog because it ignores conditional writes ([#982](https://github.com/truvity/sluis/issues/982)); the boards keep their blobs on R2.

## Drivers are services, and nobody execs them

A driver is a platform-started service that speaks ConnectRPC over a Unix socket, with the same wire contract for every driver of a port, so a driver may be written in another language than its actor. **No actor starts a driver** ([ADR 0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#drivers-are-platform-started-services)):

| Runtime | The platform starts a driver as |
|---|---|
| Bare-metal | A systemd service and socket; in the local installation, a container that Docker Compose starts |
| Serverless | A Lambda extension |
| Kubernetes | A native sidecar container in the actor's pod, started before the actors that call it. A Unix socket cannot cross a pod boundary, so a driver is never a pod of its own |

The design leans on this:

- An actor's unit may execute only its own binary (on systemd, `NoExecPaths=/` with one `ExecPaths=`), so a compromised actor cannot start a shell, a helper or a driver.
- The platform supervises the driver and orders it before its callers.
- Backends combine at deploy time without a rebuild: add a unit, a layer or a sidecar.

Plugins also run out of process; there are no Go `.so` plugins and no WebAssembly.

Every actor and every driver listens on Unix sockets only, under `/run/sluis/<actor>/`; `entry` is the one actor with a public listener. Where the sockets live and the short list of flows between nodes are on [Deployment](/architecture/deployment/).

## Per-actor and shared instances

Whether the backend can tell callers apart decides how a driver runs. Each driver declares `instance: per-actor | shared`.

| Instance | Use it when | How access is enforced |
|---|---|---|
| `per-actor` (the default) | The backend can tell callers apart: AWS IAM, a database with a role per actor, an rqlite cluster with a user per actor, NATS accounts | The driver runs as the actor's own uid and holds only that actor's credential; the backend checks the caller |
| `shared` | The backend has one credential or one device: a node's YubiKey and its PIN, or a key file in development | One process holds the credential, authenticates every caller and checks an access list generated from the manifest |

A backend that can authorise each caller is used with per-actor credentials and no mediator. sluis brokers **credentials** instead of mediating the data path: `sluis-node` issues a token per uid on a node, the cloud drivers exchange that token for the actor's own cloud role, `ca` issues database client certificates, one identity per actor ([PostgreSQL](/integrations/postgresql/)), and sluis issues NATS credentials per actor.

**The uid rule.** A per-actor driver runs as the actor's own uid, and its socket is owned by that uid. For example, the AWS driver for `signer@prod` runs as the `sluis-signer-prod` user (the paths are illustrative):

```text
/run/sluis/signer/prod.sock        the actor's own API, reachable by its callers
/run/sluis/signer/prod/aws.sock    the signer's AWS driver, mode 0600, owned by the signer's uid
```

Another actor cannot open `aws.sock`, and AWS does the rest: the KMS key policy names the signer's role and no other.

## The mediating driver

A node's card has one PIN and cannot refuse a caller by itself, so **`key-holder`** owns it and every other process goes through it. It is the one `shared` driver ([ADR 0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#key-holder-is-the-one-mediator)):

- **One process, one Unix socket per caller.** Each socket sits in a directory that only its caller can open: systemd `.socket` units with `SocketUser=` and `FileDescriptorName=` on a host, and only that caller's socket mounted into its container.
- **A peer-uid check as a second factor.** `key-holder` reads the caller's uid from the connection (`SO_PEERCRED`) and checks it against the socket it arrived on and an access list of caller, key purpose and operation, generated from the manifests.
- **Content-aware signing per purpose.** The `ca` purpose signs only a TBSCertificate that parses and stays within its constraints, the `ssh-ca` purposes only an OpenSSH certificate body, a token purpose only a JWS signing input, the release-signing purpose only an OpenPGP signature input. A caller that has a socket still cannot get arbitrary bytes signed, and a parser mistake refuses a signature rather than signing the wrong thing.
- **Exclusive card access**, through Go and `piv-go` ([Keys](/concepts/keys/#key-holder)).
- **Hardened.** No network, seccomp, the PIN in locked memory, every signature rate-limited and audited. The access list lets only the audit writer use the log key.

With a cloud key service there is no `key-holder`: the key policy is the whole layer-2 check.

## State clusters

There is no `state-owner` mediator: every state backend checks its callers itself ([ADR 0011](/decisions/0011-state-is-one-port-with-compare-and-set/#one-writer-per-kind)). On bare-metal clusters this means **one rqlite cluster per (boundary, owning actor)**. The owning actor gets an rqlite user with `execute`, and each declared reader a user with `query` only. Each cluster runs as a systemd template instance, `sluis-rqlite@<boundary>-<actor>`, with its own ports from a port scheme, its own certificate, mutual TLS between nodes and to clients, and a sandbox that lets it write only its data directory. What a board can carry is measured in [Board capacity](/runtimes/bare-metal/#board-capacity).

rqlite's client API is a TCP port, so the unit of a per-actor rqlite driver does not run with `PrivateNetwork=yes`. It gets a narrow rule instead: `IPAddressDeny=any`, `IPAddressAllow=` for its own cluster's addresses only, and `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, plus a client certificate per cluster. If rqlite adds a Unix-socket listener, the driver moves to it ([ADR 0011](/decisions/0011-state-is-one-port-with-compare-and-set/#how-a-per-actor-rqlite-driver-reaches-its-cluster)).

## Defence in depth

Every port is protected in **three layers**, all generated from one manifest, and each must hold alone ([ADR 0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#three-layers-per-port)). The threats these layers answer and what is left after each control are on the [threat model](/security/threat-model/); each control's test vectors are in the [isolation requirements](/requirements/iso/).

| Layer | Where | What it does |
|---|---|---|
| **1. The port library in the actor** | Linked into every actor | Scopes every call to `<boundary>/<kind>/…`, taken from the actor's own identity and never from the request. Encrypts every state value ([Data and secrets](/concepts/data/#every-value-is-encrypted)). Names keys by purpose. Writes blobs create-if-absent |
| **2. The driver's or backend's own check** | The backend | Checks the caller's platform identity: the peer uid, the IAM role, the ServiceAccount token or the client certificate |
| **3. Physical separation** | The installation | At [L3 and L4](/concepts/boundaries/): a store, a bucket, a queue, an account or hosts of the boundary's own |

- **One generator** writes the scopes, access lists, IAM and KMS policy documents, units, sockets and ServiceAccounts, and a **drift test** compares them with what is deployed.
- **Isolation is tested per layer, with the other layers switched off**, so that no layer passes only because another caught the case.
- **A driver whose backend cannot check each caller** is allowed only at L3 and above, together with its layer-3 separation.

The layer-2 check of every driver is listed in [ADR 0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#per-driver-checks).

## What each driver requires

Every driver declares what it needs from the installation: a long-running process, a persistent local disk, a number of nodes, and a dependency from outside sluis. A dash means the driver does not need it.

| Driver | Port | Long-running | Disk | Nodes | Dependency |
|---|---|---|---|---|---|
| software | keys | – | – | any | – (refused in production) |
| yubikey-piv | keys | ✓ | – | any | a YubiKey on each node, through `key-holder` |
| aws-kms | keys | – | – | any | AWS |
| embedded | state | ✓ | ✓ | exactly 1 | – |
| rqlite | state, lease, index | ✓ | ✓ | 1, 3 or 5 (3 or more to survive a failure) | – |
| dynamodb | state, lease | – | – | any | AWS |
| local lock | lease | ✓ | – | exactly 1 | – |
| fs | blob | – | ✓ | exactly 1 | – (a local POSIX filesystem) |
| s3-compatible | blob | – | – | any | an S3 API: AWS S3 or Cloudflare R2; credentials from the `cloud` port |
| direct-unix | transport | ✓ receiver | ✓ (spool fallback) | same host | – |
| direct-mtls | transport | ✓ receiver | ✓ (spool fallback) | any | – |
| spool | transport | ✓ | ✓ | any | – |
| sqs | transport | – | – | any | AWS |
| nats-jetstream | transport | ✓ | – | any | a NATS service (3 nodes to replicate) |
| sqlite | index | ✓ | ✓ | one writer | – |
| postgres | index | – | – | any | a Postgres service, by [provisioning mode](#the-postgres-index-driver) |
| none (scan) | index | – | – | any | – |
| none | witness | – | – | any | – |
| peer | witness | ✓ | – | 2 or more | – |
| external | witness | – | – | any | an external witness |
| sealed-state | secrets | – | – | any | a `state` driver and a `keys` driver that can wrap |
| age drop, file or bucket | export | – | file: ✓ | any | the consumer's age recipient (a public key) |
| web identity | cloud | – | – | any | the node agent and a public issuer URL |
| platform role | cloud | – | – | any | a cloud VM, function or pod identity |
| gcp / azure federation | cloud | – | – | any | GCP or Azure |
| cloudflare | cloud | – | – | any | a Cloudflare account and a parent token per boundary, stored sealed |
| file | config-source | – | – | any | – (a path: a file, a Lambda layer, a mounted ConfigMap) |
| appconfig | config-source | – | – | any | AWS: the AppConfig data API, with credentials from the `cloud` port |

Nodes and dependencies belong to an installation, not to a [runtime](/runtimes/), except that serverless always comes with its provider ([ADR 0018](/decisions/0018-runtimes-installations-and-delivery-order/#runtime-kinds)).

Azure App Configuration, Google Cloud Parameter Manager, Consul and etcd are planned `config-source` drivers with no promise and no issue; each arrives with the first installation that needs it ([ADR 0057](/decisions/0057-configuration-sources-are-a-port-sources-own-disjoint-paths-authority-is-signed-and-a-failing-source-keeps-the-version-in-force/#a-port-config-source)).

## Which drivers fit which runtime

Which drivers a runtime can run is **derived** from the table above and from what the runtime provides: a long-running driver is impossible on serverless, a driver that needs a disk works on Kubernetes only with a per-pod volume, and so on. Each runtime page lists its drivers: [bare-metal](/runtimes/bare-metal/), [serverless](/runtimes/serverless/) and [Kubernetes](/runtimes/kubernetes/). The drivers of the four tested installations are on [Installations](/runtimes/installations/) and in [ADR 0018](/decisions/0018-runtimes-installations-and-delivery-order/#installations).

The transport defaults follow the runtime: the spool on bare-metal, SQS on serverless (the workforce installation proves it) and NATS JetStream on Kubernetes (the customer-identity installation proves it); `direct` is supported with no default. A witness is optional everywhere ([Audit](/concepts/audit/#the-witness-is-optional)).

## Blob, index and cloud drivers

### One S3-compatible blob driver

There is **one blob driver for object stores, `s3-compatible`**. It speaks the S3 API and takes its credentials from the **`cloud` port**:

- on AWS, from STS through web identity or the platform role, scoped by IAM prefix conditions;
- on Cloudflare R2, from the **`cloudflare` cloud driver**, which runs as `cloud-cloudflare@<boundary>` and mints R2 **temporary credentials** scoped to the bucket and the prefix, locally, as an HS256 token signed with the parent token's secret. The parent token is per boundary and is stored sealed.

A prefix scope exists only on R2 temporary credentials, and R2 has no OIDC federation (checked 2026-09-26). The `cloudflare` cloud driver is separate from the company integration `cloudflare@<company>`, which mints Cloudflare tokens for people and jobs ([Cloudflare](/integrations/cloudflare/)): they share a library, not a credential.

### The postgres index driver

The `index` port has one Postgres driver, `postgres`, with a **provisioning mode** that says who creates the database; it does not change what the indexer and the reader do ([ADR 0015](/decisions/0015-audit-pieces-transport-search-and-front/#provisioning-modes)):

| Mode | Where | What sluis does |
|---|---|---|
| `rds` or `aurora` | AWS | Provisions the database. Serverless functions reach it through RDS Proxy with IAM authentication, one database role per actor kind |
| `cnpg` | Kubernetes | Provisions a CloudNativePG cluster in the same cluster |
| `external` | Anywhere | Nothing: it takes a connection string only. A database behind a load balancer, or one run on bare metal, is `external` |

Each actor kind has a fixed schema, row-level security separates boundaries and tenants, actors never own tables, and PostgreSQL 15 or newer is required ([ADR 0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#postgresql-row-level-security)). Clients authenticate with certificates from `ca`, or with IAM on RDS and Aurora. `postgres` is an index driver only; there is no Postgres state driver in 2.0.

### The rqlite index driver

`rqlite` is a replicated SQLite, so with it the reader can run on **any node**, which a `sqlite` file on one node cannot offer. It is the index of the boards, with an external-content FTS5 table; if FTS5 fails on the boards' own hardware, they fall back to `sqlite` on the indexer's node ([ADR 0015](/decisions/0015-audit-pieces-transport-search-and-front/#search-and-the-index)).

## How `sluis config check` validates an installation

An installation is a runtime, nodes, dependencies and one driver per port ([Configuration](/concepts/configuration/#what-is-configured-an-installation)). `sluis config check` follows, for each actor, the ports it requires to the driver chosen for each, and refuses a combination that cannot work:

- a port with no driver;
- a driver the runtime cannot run (a long-running driver on serverless, a disk where there is none), including a direct transport, which needs a disk for its spool fallback;
- a node count that does not fit (`embedded` with three nodes, `rqlite` with two);
- a missing dependency (`aws-kms` without an AWS account, `yubikey-piv` on a node with no card);
- a configuration source the installation does not offer (`appconfig` without AWS), a source whose paths overlap another's or the base's, and a source that delivers authority or per-customer defaults without the verification they need ([Configuration sources](/reference/config-sources/#refusals));
- a capability flag too weak, such as a production audit log with neither a `compliance` lock nor a witness;
- an actor with `instances: exactly 1` and no lease on more than one node;
- a software key in production;
- generated parts that disagree with the manifest, or a driver with no per-caller check without its separation at L3 and above.

No witness is a warning, not an error.

Each refusal names the actor, the port, the driver and what is missing. For example (illustrative):

```text
$ sluis config check
error  ports.keys: driver "yubikey-piv" needs a long-running process; runtime "serverless" has none
error  ports.state: driver "embedded" needs exactly 1 node; the installation has 3
error  ports.blob: production audit log store needs lock mode "compliance" or a witness; driver "fs" gives "none" and ports.witness is "none"
```

## Where an actor runs is derived

Where an actor runs is **derived from the port and driver rules**, for every sluis actor and for the audit pieces ([ADR 0002](/decisions/0002-the-design-model-actors-ports-drivers-and-contracts/#placement-is-derived)). There are no per-installation placement decisions: `sluis config check` enforces the rules, and each tested installation only names its default drivers. For example:

- An actor that declares **`instances: exactly 1`**, such as the indexer, runs on one node, and needs the lease port when there is more than one node or the nodes are elastic.
- With a `sqlite` index on a cluster there is one writer, so the reader runs on the indexer's node; with `rqlite` or `postgres` it can run on any node.
- A driver that needs a long-running process or a disk puts its actor where one exists.
- An actor reaches the driver of a port over its socket, so the two share a node, a pod or a function.

The check is the only place where driver and runtime meet, which is why a driver's requirements are declared once, in a table, and not in each installation.

## On-disk layout

Internal programs are not on `PATH`. The only command for humans is `/usr/bin/sluis`. Everything a platform starts lives under `/usr/libexec/sluis/`, one directory per kind:

```text
/usr/bin/sluis                         the only command for humans
/usr/libexec/sluis/
  actors/                              entry, session, console, exchange, signer, policy, ca, ssh-ca, quota, writer, witness, indexer, reader
  drivers/                             one entry per driver
  integrations/                        one per integration
  node/                                sluis-node and other node services
  vendor/                              third-party binaries, such as the state store
```

Short names fit the kernel's 15-character process name; units, users and the CLI keep the `sluis-` prefix.

## Why separate services

Compiled-in drivers would make fat binaries and need a rebuild to add a backend; a self-spawned driver would need exec rights; one AWS driver for all actors would hold every actor's credentials and lose IAM's per-actor enforcement. Separate services cost a socket to protect, contract versioning and some memory, and one Unix-socket hop is a fraction of a millisecond against the milliseconds of a KMS or DynamoDB call.

The language of each driver follows [ADR 0014](/decisions/0014-the-language-follows-the-executable/#per-actor-table): the AWS, GCP and Azure drivers are Rust, and on serverless one Rust `aws` executable implements every AWS port for its function, as one extension; `key-holder` and `cloud-cloudflare` are Go.
