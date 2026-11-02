# 0004 — Drivers are platform-started services on Unix sockets, listeners are few and named, and every port is enforced in three layers

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

Each actor reaches what it needs through a port ([0002](/decisions/0002-the-design-model-actors-ports-drivers-and-contracts/#ports-and-drivers)). The port model does not say how a driver is attached to its actors, which processes may accept a network connection, or where a boundary between actors and boundaries is enforced.

A key-holding process, a state store and a hardware key are the most valuable things in an installation. If one of them listens on a TCP port, anything that can route to the port can try it, and the receiver does not learn who the caller is. If an actor starts its own helper, a compromised actor can start anything. If a plugin loads into the actor's address space, its fault is the actor's fault, with the actor's keys and identity. And a boundary enforced in one place fails as soon as that place has a bug.

Most backends can tell callers apart: a cloud key service checks a role per caller, DynamoDB checks the leading key per role, PostgreSQL has grants and row-level security, NATS has accounts and permission templates, and rqlite has `execute` and `query` users and is light enough to run one cluster per owning actor. rqlite authorises per endpoint only, with nothing per table or row, and an `execute` user can `ATTACH` an arbitrary path (rqlite v10.6.6, checked 2026-10-30). A YubiKey has one PIN, so every process that can talk to the card can use every key on it, and a software key is one file. For those, one process has to own the resource and decide for every caller.

## Decision

### Drivers are platform-started services

- **Plugins run out of process, always.** Locally over a Unix socket with peer credentials, on AWS as a Lambda invoke, and for a remote plugin over HTTPS with mutual TLS. There are no Go `.so` plugins and no WebAssembly.
- **A driver is a service that speaks ConnectRPC over a Unix socket.** The wire contract is the same for every driver of a port, so a driver may be written in another language than its actor.
- **Nobody execs a driver; the platform starts it:** systemd on bare metal (a container service in the local installation), a Lambda extension on serverless, and a native sidecar container on Kubernetes ([0018](/decisions/0018-runtimes-installations-and-delivery-order/#kubernetes)). An actor's unit may execute nothing but its own binary, so a compromised actor cannot start a shell, a helper or a driver.
- **A driver declares its instance mode, `per-actor` or `shared`.**
  - **`per-actor` is the default.** The driver runs as the actor's own uid, in the actor's unit or as its sidecar, its socket is open to that uid only, and it holds only its own actor's credential: a cloud role, a database client certificate, an rqlite user or NATS credentials. The backend checks the caller.
  - **`shared` is only for a backend that cannot tell callers apart.** The one shared driver is `key-holder`. State has no mediator: every state backend checks its callers itself ([0011](/decisions/0011-state-is-one-port-with-compare-and-set/#one-writer-per-kind)).
- **Credentials are brokered instead of mediating the data path:** `sluis-node` issues a token per uid ([0007](/decisions/0007-workload-identity-and-host-enrolment/#proofs-and-the-exchange)), the cloud drivers exchange it for that actor's cloud role, `ca` issues database client certificates, one identity per actor ([0008](/decisions/0008-certificate-authorities-for-x509-ssh-and-databases/#database-client-certificates)), and sluis issues NATS credentials per actor ([0012](/decisions/0012-cryptography-and-authority-keys/#named-exceptions) names their keys).

### Listeners

- **`entry` is the only actor with a public listener, and it authenticates every request itself.**
  - **On bare metal, `entry` listens on a Unix socket only.** Its unit runs with `PrivateNetwork=yes` and `RestrictAddressFamilies=AF_UNIX`, so it has no TCP listener and no outbound network. The edge connector, `cloudflared`, connects outbound only and forwards to `entry` over a Unix-socket origin at `/run/sluis/entry/<boundary>.sock`.
  - **On serverless, `entry` listens on `127.0.0.1` inside the function's sandbox.** The edge connector is the Lambda Web Adapter, pinned and vendored into sluis's own layer, so the loopback port's only client is a component sluis ships.
  - **On Kubernetes, `entry` stays socket-only.** A key-less edge relay container in the pod forwards to its socket ([0018](/decisions/0018-runtimes-installations-and-delivery-order/#kubernetes)).
- **Every other actor and every driver listens on Unix sockets only,** under `/run/sluis/<actor>/`, one socket per instance (`/run/sluis/<actor>/<boundary>.sock`). A key-holding actor and a driver never get a TCP listener.
- **Traffic between nodes and installations is a short, named list,** each flow over mutual TLS with a certificate per peer, each port declared in the manifest and admitted by the firewall from the declared peers only:
  - the state clusters' Raft and HTTP ports ([0011](/decisions/0011-state-is-one-port-with-compare-and-set/#how-a-per-actor-rqlite-driver-reaches-its-cluster));
  - the `peer` witness's co-signature of another node's log checkpoints ([0016](/decisions/0016-the-audit-log/#witnesses));
  - the PIN hand-over from an unlocked peer to a node's `key-holder`, the alternative to `sluis node unlock` on the node itself;
  - the `direct-mtls` and `nats-jetstream` audit transports, from an emitter to a separate audit installation ([0015](/decisions/0015-audit-pieces-transport-search-and-front/#transport));
  - calls between boundaries, which name SPIFFE IDs ([0005](/decisions/0005-boundaries-and-the-isolation-ladder/#federation-between-boundaries)).
- **No actor is otherwise reachable from another node.** An actor asks the driver on its own node. The deny tests check that nothing else binds a TCP address.

### Three layers per port

Every port is protected in three layers, all generated from the one manifest. Each layer must hold alone, so a bug in one is caught by the next.

1. **Layer 1, the port library inside the actor.** The scope `<boundary>/<kind>/…` comes from the actor's own identity, never from the request. State values are encrypted ([0011](/decisions/0011-state-is-one-port-with-compare-and-set/#every-value-is-encrypted)). Keys are addressed by purpose, never by a name the request supplies. Blobs are created only if absent.
2. **Layer 2, the driver's or the backend's own check of the caller,** by its platform identity: a peer uid, an IAM role, a ServiceAccount token or a client certificate. It never relies on what layer 1 claims.
3. **Layer 3, physical separation** at isolation levels L3 and L4: a store, a bucket, a queue, an account or a cluster of its own ([0005](/decisions/0005-boundaries-and-the-isolation-ladder/#the-isolation-ladder)).

- **One generator writes every layer's artefacts:** the library scopes, the access lists, the IAM and KMS policy documents (output for the infrastructure code to apply), the systemd units and sockets, and the Kubernetes ServiceAccounts.
- **A drift test** compares what is deployed with what the generator writes, and `sluis config check` refuses an installation whose layers disagree.
- **Isolation is tested per layer, with the other layers switched off,** with test vectors per layer: `ca@env-a` asking for env-b's key is refused; actor X writing under actor Y's prefix is refused.
- **A driver whose backend has no per-caller check is allowed at L3 and above only,** together with its layer-3 separation; `sluis config check` enforces it.

### key-holder is the one mediator

A node's YubiKey, or a key file in development, is the one backend left that cannot tell callers apart.

- **One `key-holder` process serves one Unix socket per caller.** Each socket sits in a directory only its caller can open (systemd socket units with `SocketUser=` and `FileDescriptorName=`); in a container, only that caller's socket is mounted.
- **It checks the peer uid** (`SO_PEERCRED`) of every connection as a second factor, and an access list generated from the manifest.
- **Signing is content-aware per purpose.** The `ca` purpose signs only a TBSCertificate that parses and stays within its constraints, the `ssh-ca` purpose only an OpenSSH certificate body, a token purpose only a JWS signing input, the release-signing purpose only an OpenPGP signature input. A sign call therefore carries the content, not only its digest. A mistake in a parser refuses a signature rather than signing the wrong thing.
- **It holds the card exclusively.** `key-holder` is written in Go with `piv-go` ([0014](/decisions/0014-the-language-follows-the-executable/#per-actor-table)), runs as a dedicated user, and no other card software runs on the node, so no other process can use or reset the card. It has no network, runs under seccomp, and keeps the PIN in locked memory; the PIN arrives only from an unlocked peer or through `sluis node unlock` ([0012](/decisions/0012-cryptography-and-authority-keys/#touch-and-pin)). Every signature is rate-limited and audited.
- **It makes the OpenPGP back-signature of a node's subkey on the card** ([0013](/decisions/0013-the-hand-off-to-root-custody-and-the-signing-api/#the-hand-off)).
- **More than one card per node is a later option.**
- **With a cloud key service there is no `key-holder`.** A signing key's key policy names one actor and one purpose; `kms:Sign` takes no encryption context, so the key policy is the whole layer-2 check. A symmetric key's policy adds a condition on the encryption context.

### Per-driver checks

| Port | Driver | Layer 2: the backend's own check | Layer 3, and notes |
|---|---|---|---|
| keys | `software` | `key-holder` | Development and test only; refused in production ([0012](/decisions/0012-cryptography-and-authority-keys/#floors-in-code)) |
| keys | `yubikey-piv` | `key-holder`: a socket per caller, peer uid, content-aware signing | |
| keys | `aws-kms` | Key policy per actor and purpose; an encryption-context condition on symmetric keys | |
| keys | `pkcs11` (YubiHSM 2, Nitrokey HSM 2) | `key-holder` plus the HSM's own authentication | Later ([#1029](https://github.com/truvity/sluis/issues/1029)) |
| state | `embedded` | A file per uid, one per actor | |
| state | `rqlite` | A cluster per boundary and owning actor; `execute` user for the owner, `query` users for readers | |
| state | `dynamodb` | IAM `dynamodb:LeadingKeys` per actor role | A table per boundary; at L4 in the boundary's own account |
| lease | all state drivers | On the state store, with a fencing token ([0011](/decisions/0011-state-is-one-port-with-compare-and-set/#leases)) | |
| blob | `fs` | A directory per uid, mode 0700 | |
| blob | `s3-compatible` | IAM prefix conditions on AWS; R2 temporary credentials scoped to a prefix through `cloud-cloudflare` | A bucket per boundary; Object Lock on S3 |
| transport | `direct-unix` | The peer uid, checked by the receiver | |
| transport | `direct-mtls` | The SPIFFE ID in the client certificate | |
| transport | `spool` | A directory per producer uid | |
| transport | `sqs` | Queue policy per sender role | A queue per boundary. Proved by the workforce installation on serverless |
| transport | `nats-jetstream` | NATS accounts plus permission templates | An operator per environment, an account per boundary. Proved by the customer-identity installation on Kubernetes |
| index | `sqlite` | A file per indexer uid; the reader opens it read-only | |
| index | `rqlite` | As for state | |
| index | `postgres` | Grants and row-level security (below) | |
| witness | `peer` | The node's identity, over mutual TLS | |
| witness | `external` | The witness's own key | |
| secrets | `sealed-state` | Inherits from `state` and `keys` | |
| export | `age` | Encrypted to the recipient's key | |
| cloud | web identity | Tokens per uid from `sluis-node`; the trust policy pins `sub` to `<actor>@<boundary>` | |
| cloud | platform role | – | |
| cloud | GCP and Azure federation | – | |
| cloud | `cloud-cloudflare` | R2 temporary credentials | |

A dash means no layer-2 check is named for that driver yet. Each driver is added with the installation that needs it ([principle 10](/principles/#10-one-product-many-shapes)); where the notes name one, it is that driver's reference installation.

- **Blob has one driver for object stores, `s3-compatible`,** with credentials from the `cloud` port: STS through web identity on AWS, and on Cloudflare a `cloud-cloudflare@<boundary>` driver that mints R2 temporary credentials scoped to one bucket and prefix, locally, as an HS256 token signed with the parent token's secret. The parent token is per boundary and stored sealed. `cloud-cloudflare@<boundary>` is separate from the company integration `cloudflare@<company>`: they share a library, not a credential. Garage is backlog ([#982](https://github.com/truvity/sluis/issues/982)): it ignores conditional writes.

### PostgreSQL row-level security

- **Each actor kind has a fixed schema, and grants separate the kinds.**
- **Row-level security separates instances of one kind** (boundaries and tenants) through group-role membership: `pg_has_role(current_user, 'boundary_' || boundary, 'member')`. Tables use `FORCE ROW LEVEL SECURITY`.
- **Actors never own tables;** a migration role owns them.
- **Policies never trust session variables.**
- **Views are `security_invoker`, and there is no `SECURITY DEFINER` function.**
- **The tenant column is part of every unique key.**
- **Each role has its own connection pool.**
- **PostgreSQL 15 or newer** is required.
- **At L3 and above, each boundary has its own database,** and row-level security stays on.
- **Clients authenticate with certificates from `ca`** (the common name is the role) or with IAM on RDS and Aurora ([0008](/decisions/0008-certificate-authorities-for-x509-ssh-and-databases/#database-client-certificates)).

### NATS JetStream

- **Layer 2 of the `nats-jetstream` transport driver is NATS itself:** accounts and permission templates on scoped signing keys. The broker refuses a publish outside the template, so the driver needs no mediator and runs `per-actor`.
- **The mapping:** one operator per environment, an account per boundary, the company as an account tag, the user named `<actor>@<boundary>`, and a scoped signing key per role.
- The key that NATS requires is a named exception in [0012](/decisions/0012-cryptography-and-authority-keys/#named-exceptions).

## Consequences

- A compromised actor cannot start a process, load a plugin or open a port to the world. From outside, it can be reached only through the one authenticated public API and the named flows between nodes, so a node opens no inbound port for sluis beyond those.
- A compromised actor has to defeat three independent mechanisms to reach another boundary's data: its own library, the backend's check of its platform identity, and, at L3 and above, a store it has no route to.
- Drivers can be added, replaced and combined at deploy time without a rebuild. The platform supervises, restarts and orders them; our code does not.
- `key-holder` is the one place where a driver's own code is the boundary. Its socket layout, peer-uid check, content parsers and access list are the code to review hardest and need deny tests. Every `per-actor` driver relies on the backend's check instead, and that check needs a test per driver with the other layers switched off.
- On KMS there is no content-aware signing, so the per-actor, per-purpose key policy carries layer 2 alone.
- Credential brokering puts minting on the start-up path, not on every read: a broker that is down stops new credentials, not existing ones.
- One blob driver serves AWS and Cloudflare; the difference moves to the `cloud` port, where credentials are scoped to a prefix on both, so a bucket can be shared between actors safely.
- The bare-metal, serverless and Kubernetes edges differ (a Unix-socket origin, a loopback port, a relay container), and `entry`'s tests cover each listener.
- ConnectRPC over Unix sockets costs a hop and a serialisation where a library call would be free, and every driver needs its port's Protobuf contract. The cost is accepted for the isolation.
- PostgreSQL needs more set-up: a migration role, a group role per boundary, a pool per role and version 15 or newer.
- Threats addressed: T-8, T-9, T-10, T-11, T-12, T-13, T-14, T-24 and T-25, see the [threat model](/security/threat-model/). The [Listeners](/architecture/deployment/#listeners) and [Ports and drivers](/concepts/drivers/) pages describe this record.

## Roads not taken

- **Plugins in the actor's process (Go `.so`).** A plugin shares the actor's memory, keys and identity, and Go plugins need an identical toolchain; it removes the isolation the rest of the design depends on.
- **Plugins in WebAssembly.** A second runtime to ship and secure, with host bridges for devices, cloud SDKs and sockets, for a boundary an ordinary process gives with tools operators already know.
- **The actor starts its driver.** The actor would need the right to execute programs, so a compromised actor could run a shell; the platform already supervises services.
- **A `state-owner` mediator in front of the state store.** Isolation between actors would be the mediator's code, in every state call's path, with the whole state class as blast radius; a cluster per owning actor lets the backend refuse a wrong writer itself.
- **`entry` on a loopback TCP port on every runtime.** On bare metal `entry` would have to share the host's network namespace, so any local process could open the port; serverless keeps loopback only because the adapter needs it and the sandbox runs sluis alone.
- **Isolation in one layer only.** The single layer becomes the boundary: a library alone does not stop a compromised actor, policy documents alone must be perfect, and physical separation alone leaves L0 to L2 open.
- **`key-holder` with one shared socket and an access list.** Every caller could reach the socket, and a mounted socket would give a container a path to every purpose; a socket per caller adds a filesystem check before `key-holder`'s own.
- **A separate `r2` blob driver beside an S3 driver.** Two drivers for one protocol, and a long-lived R2 token is bucket-wide; prefix-scoped temporary credentials give R2 the same layer 2 as IAM conditions.
- **PostgreSQL isolation through session variables.** A caller that can run SQL can set the variable and a pooled connection can carry another tenant's setting; policy rests on the authenticated role.

## Follow-ups

- More key drivers (PKCS#11 for YubiHSM 2 and Nitrokey HSM 2): [#1029](https://github.com/truvity/sluis/issues/1029), Later.
