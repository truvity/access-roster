---
title: Bare-metal
description: The bare-metal runtime runs sluis as systemd units on physical hosts and virtual machines, or in Docker locally, on one node or N; and the board capacity.
status: target
sidebar:
  order: 2
---

Bare-metal is the runtime where sluis owns its hosts: physical machines (single-board computers, servers), virtual machines (EC2 or any other provider) and local Docker on a workstation. Processes are long-running, the node has a persistent disk, actors and drivers talk over Unix sockets on the node, and systemd, or a container runtime for local Docker, starts everything ([what each runtime provides](/runtimes/#what-each-runtime-provides)).

The node count is an attribute of the installation, not of the runtime: bare-metal runs with one node or with N. The tested installations on bare-metal are [local](/runtimes/installations/#local) and [boards](/runtimes/installations/#boards). Which drivers fit bare-metal is on [Installations](/runtimes/installations/#which-drivers-fit-which-runtime).

## What runs where

- Each [actor](/concepts/actors/) instance, `<actor>@<boundary>`, is its own OS user and its own instance of a systemd template unit. Drivers are systemd units too, started by the platform. Nothing execs a driver.
- **Templates and a generator.** The packages ship template units only: `sluis-<actor>@.service` and `sluis-<actor>@.socket`, with `User=sluis-<actor>-%i`, `RuntimeDirectory=sluis/<actor>/%i`, `LoadCredentialEncrypted=` per instance and `ListenStream=/run/sluis/<actor>/%i.sock`. A **systemd generator** shipped in the package reads `/etc/sluis/install.yaml` and creates the instances and their `sysusers.d` entries, so a second [boundary](/concepts/boundaries/) on the same host is a second set of instances, not a second package.
- The packages, split by function ([Packages](/distribution/packages/)), install under `/usr/libexec/sluis/{actors,drivers,integrations,node,vendor}/<short-name>`.
- The node agent (`sluis-node`) issues each actor a short-lived workload JWT and, on a cloud VM, is the only process that holds the instance role and brokers per-actor credentials.
- The permission manifest generates the units: `User=`, a private state directory, the credentials an actor may read, and socket modes and groups for the callers it allows.
- **Hardening per unit:** `ProtectSystem=strict`, `NoNewPrivileges=`, an empty `CapabilityBoundingSet=` and `SystemCallFilter=@system-service`. Every actor that needs no network, `entry`, `policy` and `signer` among them, gets `PrivateNetwork=yes` and `RestrictAddressFamilies=AF_UNIX`. Integrations reach their providers through the egress proxy.
- `key-holder` fronts the node's YubiKey with one socket per caller, a peer-uid check and content-aware signing ([ADR 0003](/decisions/0003-units-transports-and-fusion/#key-holder-is-the-one-mediator)). State has no mediator: each owning actor has its own rqlite cluster, and the unit of its driver reaches the cluster's TCP client port through a narrow network rule ([ADR 0005](/decisions/0005-the-store/#how-a-per-actor-rqlite-driver-reaches-its-cluster)).
- Integration actors run only when the installation uses them.

## Supported distributions and the systemd floor

The systemd floor is 252. Ubuntu 26.04 LTS, Rocky Linux 10.x and Amazon Linux 2023 meet it, on amd64 and arm64, so the units use `LoadCredentialEncrypted=` where they need it ([Packages](/distribution/packages/)). There are no build profiles: the packaging is the build. One cluster may mix distributions, because the package set is the same, at the price of a wider test surface.

A board image older than the floor is a declared exception until board images for the supported distributions exist ([#881](https://github.com/truvity/sluis/issues/881)). On such an image the generated units use plain `LoadCredential=`, protected by file mode and the dedicated state directory but not encrypted at rest; key material never is on disk, because it stays in the card. `sluis doctor` warns on the randomness checklist when the kernel is older than 5.18, which VM-clone reseeding needs.

## One node

A single node is one failure domain. Losing it stops sign-in until the node is rebuilt and its state restored.

- **State:** the `embedded` single-node store, no Raft, or DynamoDB on an AWS VM.
- **Audit:** records go to a local spool, and the writer seals batches into the blob store and asks `key-holder` to sign checkpoints. Records still in the spool when a node dies are lost, so keep the spool small and drained, and keep the blob store off the node if the audit trail has to outlive it.
- **Index:** `sqlite`. It lags the chain, and verification never trusts it or the state, so a damaged index cannot hide a missing record.
- **Recovery** needs no cloud and no Kubernetes ([Break-glass recovery](/security/break-glass/)).

## N nodes

With three nodes the installation survives the loss of one.

- **State:** rqlite across the nodes, **one cluster per (boundary, owning actor)**, each a template instance `sluis-rqlite@<boundary>-<actor>` with its own port and certificate. The owning actor has the only rqlite user that may `execute`; a declared reader has a `query`-only user. Each cluster's unit writes its data directory only. Each cluster needs a quorum of two of three; a node that is down is replaced or repaired without losing state.
- **Raft over mTLS.** Each cluster's peer traffic uses its own TCP port, with mutual TLS and a certificate per cluster, allowed only between the peers. No actor is called across nodes.
- **Audit:** a local spool on each node, and one log per node with its own writer and log key; the other nodes are its peer witnesses, so one compromised node cannot extend a log alone ([Audit](/concepts/audit/)). Readers merge the logs by time.
- **Identity:** the boundary's issuer issues workload tokens, and its key set holds one key per node card. Per-node issuers, `https://<issuer>/nodes/<node>/`, are optional, for a fleet whose nodes run different actors: there a cloud role trusts only the issuers of the nodes that run it ([ADR 0022](/decisions/0022-workload-identity-and-host-enrolment/)).
- Losing two nodes of three stops writes, and sign-in with them, because sessions and grants need state. Three nodes usually share a site, a network and a power feed, so this is not a multi-site design.

## Board capacity

Measured on 2026-10-31 on one single-board computer (arm64, 4 cores, 2 GB RAM, eMMC, with a YubiKey 5 Nano on firmware 5.8.0), and again on 2026-11-02 on three identical boards on one gigabit switch with real replication between them (4 x Cortex-A55, 1978 MiB usable RAM, 32 GB eMMC, kernel 5.10.160). Each row says which. The language choice that follows from it is [ADR 0012](/decisions/0012-the-language-follows-the-executable/).

| Measure | Figure |
|---|---|
| Memory of a full board: 10 rqlite clusters, 30 actors, two `entry` instances, the card path, `cloudflared` and the board's other services | About 985 MiB with Go actors, about 680 MiB with Rust actors, of 1978 MiB usable, under a ceiling of 1380 MiB (a quarter of the RAM kept for page cache, 100 MiB for slab and bursts) |
| Go actor against Rust actor | MEASURED 2026-11-02, 30 actors under load, one language each: a Rust actor holds about 0.2 MiB of private memory and a Go actor 8.0 to 8.7 MiB, so Go costs 235 to 255 MiB more at 30 actors. The estimate of 2026-10-31 was about 300 MiB. Go does not give the memory back after the load |
| The mix of ADR 0012 next to the rqlite nodes, per board | MEASURED 2026-11-02, 25 Rust actors, 5 Go actors, 2 `entry`, a `session` stand-in and 10 rqlite nodes, light load: 160 to 200 MiB of PSS for the 43 processes, of which rqlite 98 to 134 MiB. The board's own services use about 160 MiB before anything starts, and `MemAvailable` never fell below 1559 of 1978 MiB |
| rqlite | About 9 MiB per cluster under write load, plus about 22 MiB of binary pages once per board |
| State writes | MEASURED 2026-11-02, three boards, 10 clusters of three nodes (one node of each on each board), Raft over plain TCP, the load generator on the boards: 400 commits a second for the installation were delivered in full with a p99 of 118 to 127 ms and 13 to 15 % of the CPU idle; saturated, about 600 a second with the CPU 95 % busy and the eMMC 29 % busy. The budget stays 400. The CPU limits writes before the eMMC does. The single-board figure of 2026-10-31 (about 430 a second) had no replication and is not comparable |
| Latency of a replicated commit | MEASURED 2026-11-02: p50 21 to 41 ms and p99 62 to 123 ms at 7 and at 73 commits a second. Treat 20 to 40 ms as the cost of a replicated commit on this eMMC |
| Swap | MEASURED 2026-11-02: the board image runs a compressed swap (zram, 989 MiB). It was switched off for every memory figure above, so they are resident memory; account for it when sizing memory |
| Signing | About 147 ms per P-384 signature, about 7 a second per card, about 21 a second for three boards |

The totals of 2026-10-31 stand, now with the actor and rqlite rows measured and not estimated. Not measured: `cloudflared` with a live tunnel (29 MiB idle, MEASURED 2026-10-31; 60 MiB with an edge connection is an estimate, UNVERIFIED), the Go actors that were not loaded, and the real actors. The total stays under the ceiling with 50% added to the estimates. Go processes run under a `GOMEMLIMIT` at 2 to 3 times their steady private memory (24 to 32 MiB for rqlite, 24 MiB for an actor), with the default `GOGC`. The write figure was measured with the load generator on the same cores and with a replication round trip (about 1 ms between the boards), but without TLS on Raft, which the design uses and nobody has measured yet (UNVERIFIED), so the estimate below also reads it against a derated 200 commits a second.

**Writes the design needs** (estimated 2026-10-31 from the actor design). Each board is a voter in every cluster, so it applies every commit of the installation. The load of v1 is about 25,000 tokens in seven days, a peak of 0.8 tokens a second, 95% of them token exchanges; the signing ceiling of 21 tokens a second is the most three cards can sign. The commits per action are a reading of the flows, because the session and claims records ([#998](https://github.com/truvity/sluis/issues/998), [#999](https://github.com/truvity/sluis/issues/999)) are not written yet.

| Cluster (owning actor) | Commits per action (assumed) | At 0.8 tokens/s | At 21 tokens/s |
|---|---|---|---|
| `exchange` | 1 replay marker per token exchange | 0.76 | 20.0 |
| `session` | 6 per sign-in (5% of tokens) | 0.24 | 6.3 |
| `quota`, where a rule enforces | 2 per minted token: `Admit` and `Confirm` ([ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/)) | 1.6 | 42.0 |
| Audit `writer`, 3 logs | 1 per sealed batch, at most 0.2 a second per log ([ADR 0029](/decisions/0029-the-audit-log/#sealing)) | 0.6 | 0.6 |
| `witness`, 3 | 2 co-signatures per batch | 1.2 | 1.2 |
| `indexer` | 1 per sealed batch, with the cursor | 0.6 | 0.6 |
| Leases | 4 leases renewed every 5 s | 0.8 | 0.8 |
| `ca`, `ssh-ca`, reconcilers, `console` | A reserve: no rate is documented | 1.2 | 1.2 |
| **Total with `quota` enforcing** | | **7.0** | **72.7** |
| **Total without enforcement** | | **5.4** | **30.7** |

The design needs about 7 commits a second at the measured peak, 57 times below the budget of 400 (29 times below the derated 200), and about 73 at the signing ceiling, 18% of the budget. The cards limit the installation before the state does. Enforced `quota` is the largest writer, 23% of the total at the peak and 58% at the ceiling, so its load test matters most. The estimate reserves what is not yet known: the certificate rate, the size of directory passes, the lease time, the cost of a full-text commit and a slower follower. Re-measure when the actors exist.

## Virtual machines (EC2)

An EC2 instance or an Auto Scaling group is a possible bare-metal installation, with the same units as on a board and the packages from the dnf repository on Amazon Linux 2023. EC2 is not a delivery target and is not tested.

## Local Docker

Docker on a workstation is the development and CI form of bare-metal, one node: the [local](/runtimes/installations/#local) installation ([ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)).

- It runs as **Docker Compose, one container per actor and per driver**, each as its actor's uid, so the call graph and the socket access lists are the ones the other installations enforce.
- Actors and drivers speak ConnectRPC over Unix sockets on shared volumes under `/run/sluis/<actor>/`.
- Keys are **software keys** by default. A dedicated development card is opt-in: only the `key-holder` container reaches it, through the host's smart-card service, and `key-holder` has the card to itself. The code refuses a software key in production.

## Keys

- **YubiKey (PIV):** the key mode on boards. One card per node, so a node's keys are its own. A YubiKey has no symmetric keys, so sealing uses ECDH plus HKDF with the P-384 key in slot `9d`. Each purpose has its own slot ([the card slot map](/concepts/keys/#the-card-slot-map)). Only `key-holder` talks to the card, with exclusive access, and it audits every use. Use firmware 5.7 or newer, which fixes EUCLEAK.
- **AWS KMS:** the key mode on an AWS virtual machine ([Keys](/concepts/keys/#aws-kms-layout)). Each key policy names one actor and denies the instance role.
- **Software key:** development only; the code refuses it in production.

## Identity and edge

- An actor's identity on a node is its uid, read through `SO_PEERCRED` on the Unix socket. On a cloud VM, calls to AWS use the actor's own IAM role, so CloudTrail names the actor and the instance.
- `entry`'s public API is a Unix socket, and `entry` runs with `PrivateNetwork=yes`, seccomp and Landlock, so it has no network at all. Every other actor and every driver listens on a Unix socket under `/run/sluis/<actor>/` ([Deployment](/architecture/deployment/)).
- `cloudflared` is the edge connector on the boards installation. It forwards to `entry`'s Unix socket and connects outbound only, so the node opens no inbound port for sluis; it holds no key and reaches no other socket. Each node runs its own.
- **The console.** `entry` serves the console's single-page application from a directory on the node, on the same origin as its API. The bundle is a separate artifact of the release ([Packages](/distribution/packages/)).

## Limits and residual risk

- The YubiKey is physical. Whoever holds the board and the card, and knows the PIN, can sign. Keep the board in a controlled place.
- eMMC wears under heavy writes. The spool and the state are small, and a blob store off the board keeps the audit chain.
- A root-level compromise of a node defeats host-asserted identities (uid, cgroup). On a cloud VM, KMS key policies and CloudTrail limit and record what the stolen identity can do; the instance role is the instance's blast radius, so keep it small.
- KMS is a regional service. A regional outage stops signing; there is no software fallback key, because the code refuses one in production.
- A burst beyond the signing rate of the cards queues ([Board capacity](#board-capacity)).
