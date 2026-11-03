---
title: Bare-metal
description: "The bare-metal runtime runs sluis as a systemd unit and uid per actor on boards, VMs or local Docker: the call graph, the card and the board capacity."
status: target
sidebar:
  order: 2
---

Bare-metal is the runtime where sluis owns its hosts: physical machines (single-board computers, servers), virtual machines (EC2 or any other provider) and local Docker on a workstation. Processes are long-running, the node has a persistent disk, actors and drivers talk over Unix sockets on the node, and systemd, or a container runtime for local Docker, starts everything ([what each runtime provides](/runtimes/#what-each-runtime-provides)).

The node count is an attribute of the installation, not of the runtime: bare-metal runs with one node or with N. The tested installations on bare-metal are [local](/runtimes/#local) and [boards](/runtimes/#boards). Which drivers fit bare-metal is on [Runtimes](/runtimes/#which-drivers-fit-which-runtime). The design is [0003](/decisions/0003-units-transports-and-fusion/); this page shows what it makes of a three-board installation.

## What runs where

- **One systemd unit and one uid per actor and per boundary.** Each [actor](/concepts/families/) instance, `actor@boundary`, is its own OS user and its own instance of a systemd template unit. The same holds for the holders store@, key@ and exporter@ ([0003](/decisions/0003-units-transports-and-fusion/#units)).
- **Drivers are systemd units too,** started by the platform beside their owner's unit. Nothing execs a driver, and an actor's unit may execute nothing but its own binary. Only the owner can open a driver's socket.
- **Templates and a generator.** The packages ship template units only: `sluis-<actor>@.service` and `sluis-<actor>@.socket`, with `User=sluis-<actor>-%i`, `RuntimeDirectory=sluis/<actor>/%i`, `LoadCredentialEncrypted=` per instance and `ListenStream=/run/sluis/<actor>/%i.sock`. A **systemd generator** shipped in the package reads the bootstrap files in `/etc/sluis/bootstrap.d/`, one for each boundary ([Where it lives](/reference/bootstrap-file/#where-it-lives)), and creates the instances and their `sysusers.d` entries, so a second [boundary](/concepts/boundaries/) on the same host is a second set of instances, not a second package.
- **The units are generated from the registries.** The actor registry gives the uid, the sockets, the callers and the egress of each unit, and the kind registry gives the rules ([0002](/decisions/0002-families-of-actors/#registries-generate-the-enforcement)). The packages, split by holder and module ([Packages](/distribution/packages/)), install under `/usr/libexec/sluis/{actors,drivers,node,vendor}/<short-name>`.
- **The node agent** (`sluis-node`) issues each unit a short-lived workload token and asks key@ to sign it. It holds no key credential ([0022](/decisions/0022-workload-identity-and-host-enrolment/)).
- **Adapters run only when the installation uses them.** Fusion of work actors is an explicit installation choice, and a holder is never fused with a work actor ([0003](/decisions/0003-units-transports-and-fusion/#fusion)).

## Sockets and the call graph

A board has no TCP listener of any actor. The call graph is declared once in the actor registry and enforced twice ([0003](/decisions/0003-units-transports-and-fusion/#the-call-graph)):

- **In logic.** The generated client exists only for the callees an actor may call, and one interceptor in every process refuses a caller that is not listed.
- **In the unit.** The callee's Unix socket is owned by the callee's uid, with a group that holds only the uids of its allowed callers (mode `0660`). Each caller's sandbox makes only its allowed sockets visible (`BindPaths=` and `InaccessiblePaths=`, with `RestrictAddressFamilies=AF_UNIX` and `PrivateNetwork=yes`). The callee reads the caller's uid with `SO_PEERCRED`.

```mermaid
flowchart LR
  cf["cloudflared"] -- "Unix socket" --> entry["entry"]
  entry -- "Unix sockets" --> work["work actors"]
  work -- "data port" --> store["store@"]
  work -- "keys port" --> key["key@"]
  store -- "driver socket" --> eng["rqlite node"]
  key -- "driver socket" --> card["YubiKey"]
  eng -. "Raft, mutual TLS" .-> peers["peer boards"]
```

- **`entry` listens on a Unix socket only,** at `/run/sluis/entry/<boundary>.sock`, and runs with `PrivateNetwork=yes`, seccomp and Landlock, so it has no network at all. `cloudflared` is the edge connector: it connects outbound only, forwards to that socket, holds no key and reaches no other socket. Each board runs its own, so the board opens no inbound port for sluis.
- **Every other actor and every driver listens on a Unix socket** under `/run/sluis/<actor>/`, one socket per boundary. key@ serves each caller on a socket of its own, in a directory only that caller can open ([0006](/decisions/0006-keys-and-sealing/#exclusive-card-access)).
- **The only inbound and inter-node port is rqlite's Raft port,** with mutual TLS, certificates from ritueel's pre-configuration, and a firewall rule that admits it from the declared peers only ([0003](/decisions/0003-units-transports-and-fusion/#calls-between-nodes)). rqlite's client API listens on the loopback address, and store@'s driver is its only client ([0005](/decisions/0005-the-store/#engines)). Witnesses meet through the audit blob, not through a connection between boards.
- **Egress is denied by default** and generated from the registry: nftables per uid. An actor whose registry row lists no outside host, `entry`, `policy` and `signer` among them, also gets `PrivateNetwork=yes`. Adapters reach their providers through the egress rules of their own uids.
- **Hardening per unit:** `ProtectSystem=strict`, `NoNewPrivileges=`, an empty `CapabilityBoundingSet=` and `SystemCallFilter=@system-service`.
- **The deny tests check the result.** They try every pair of actors against both layers, and they check that nothing else binds a TCP address apart from rqlite's client API on the loopback address.

## Supported distributions and the systemd floor

The systemd floor is 252. Ubuntu 26.04 LTS, Rocky Linux 10.x and Amazon Linux 2023 meet it, on amd64 and arm64, so the units use `LoadCredentialEncrypted=` where they need it ([Packages](/distribution/packages/#supported-platforms)). There are no build profiles: the packaging is the build. One cluster may mix distributions, because the package set is the same, at the price of a wider test surface.

A board image older than the floor is a declared exception until board images for the supported distributions exist ([#881](https://github.com/truvity/sluis/issues/881)). On such an image the generated units use plain `LoadCredential=`, protected by file mode and the dedicated state directory but not encrypted at rest; key material never is on disk, because it stays in the card. `sluis doctor` warns on the randomness checklist when the kernel is older than 5.18, which VM-clone reseeding needs.

## One node

A single node is one failure domain. Losing it stops sign-in until the node is rebuilt and its state restored.

- **Engine:** rqlite with one node, a cluster of one, or DynamoDB on an AWS VM. The local installation uses the same rqlite path.
- **Audit:** records go to a local spool, and the writer seals batches into the blob store and asks key@ to sign checkpoints. Records still in the spool when a node dies are lost, so keep the spool small and drained, and keep the blob store off the node if the audit trail has to outlive it.
- **Index:** `sqlite`. It lags the chain, and verification never trusts it or the store, so a damaged index cannot hide a missing record.
- **Recovery** needs no cloud and no Kubernetes ([Break-glass recovery](/security/break-glass/)).

## N nodes

With three nodes the installation survives the loss of one.

- **Engine:** one rqlite cluster over the boards for the boundary. Every board holds the data and the temp data is replicated too, so any board serves any request, and each board's store@ talks to the rqlite node on its own board ([0005](/decisions/0005-the-store/#engines)). A quorum is two of three; a board that is down is replaced or repaired without losing data.
- **Raft over mutual TLS.** The peer traffic uses the Raft port only, with a certificate per cluster, allowed only between the peers. No actor is called across nodes: a work actor asks the holders of its own node.
- **Audit:** a local spool on each board, and one log per board with its own writer and log key; the other boards are its peer witnesses, through the audit blob, so one compromised board cannot extend a log alone ([Audit](/concepts/audit/)). Readers merge the logs by time.
- **Identity:** the boundary's issuer issues workload tokens, and its key set holds one key per board card. Per-node issuers are optional, for a fleet whose nodes run different actors: there a cloud role trusts only the issuers of the nodes that run it ([0022](/decisions/0022-workload-identity-and-host-enrolment/)).
- Losing two boards of three stops writes, and sign-in with them, because sessions and grants need the store. Three boards usually share a site, a network and a power feed, so this is not a multi-site design.

## The card and its slots

A board's key mode is its YubiKey. key@ is the only process that talks to the card, with exclusive access, and every key of the board is born on it ([0006](/decisions/0006-keys-and-sealing/#keys-per-board)). The card runs firmware 5.7 or newer, the floor that fixes EUCLEAK ([0006](/decisions/0006-keys-and-sealing/#touch-and-pin)).

A documented, versioned map says which PIV slot serves which purpose, one slot per purpose and per algorithm ([0006](/decisions/0006-keys-and-sealing/#the-slot-plan)). The three slots of a board that carries sign-in:

| Slot | Purpose |
|---|---|
| `9c` | The board's X.509 intermediate, certified by ritueel's root |
| `9a` | Token signing |
| `9d` | Key agreement (ECDH): unwraps data keys, the boundary's `grant` data key among them |

The map goes on in slots `82` to `86` (the two SSH authorities, the audit log key, the release subkey in the release boundary, the workload issuer), `87` (the PIN release key, the one slot that needs no PIN) and `88` to `95`, which are spare; `9e` is not used. The generated [keys page](/reference/keys/) lists every purpose with its algorithm, its key type on AWS and its slot. Slot `9d` is the only key-agreement slot; grants do not use it directly, because they are sealed under a boundary data key and cost a memory operation, not an ECDH on the card.

### Touch, PIN and the locked board

- **Cards are touch never and PIN once,** so a board signs unattended.
- **A board starts locked.** key@ does not have the PIN when it starts. After a full power loss one person unlocks the first board (`sluis node unlock`, over an SSH certificate from sluis's own CA or the admin API), and that board then unlocks the others.
- **A peer releases the PIN through the store.** For a reboot of one board or a rolling update, the locked key@ writes a `PinReleaseRequest` with an ephemeral public key, signed by a key of its card whose slot needs no PIN. An unlocked peer's key@ watches the kind, verifies the signature and the slot's attestation, and answers with a `PinRelease`: the board's PIN, sealed to that key, which only the locked key@ can open. Both are temp kinds written by key@ alone, with a default of 5 minutes and a maximum of 15 ([0006](/decisions/0006-keys-and-sealing/#touch-and-pin)).
- **The PIN crosses only the Raft port,** inside the store's replication, so the flow adds no listener and no inter-node port. The sealed PIN is ciphertext in an ordinary temp kind, and no archive holds it.
- **key@ never retries a wrong PIN,** because the card blocks after three attempts and then needs the PUK. The PIN lives in key@'s locked memory and reaches the card through key@'s own driver only.

### Other key modes

- **AWS KMS** is the key mode on an AWS virtual machine ([0006](/decisions/0006-keys-and-sealing/#keys-per-boundary-on-aws)). The key policy of every key names key@'s role alone, so no other actor and no instance role reaches KMS.
- **Software key:** development only; the code refuses it in production ([0006](/decisions/0006-keys-and-sealing/#floors-in-code)).

## Board capacity

Measured on 2026-10-31 on one single-board computer (arm64, 4 cores, 2 GB RAM, eMMC, with a YubiKey 5 Nano on firmware 5.8.0), and again on 2026-11-02 on three identical boards on one gigabit switch with real replication between them (4 x Cortex-A55, 1978 MiB usable RAM, 32 GB eMMC, kernel 5.10.160). Each row says which. The language choice that follows from it is [0012](/decisions/0012-the-language-follows-the-executable/).

| Measure | Figure |
|---|---|
| Memory of a full board, as measured: 10 rqlite clusters, 30 actors, two `entry` instances, the card path, `cloudflared` and the board's other services | About 985 MiB with Go actors, about 680 MiB with Rust actors, of 1978 MiB usable, under a ceiling of 1380 MiB (a quarter of the RAM kept for page cache, 100 MiB for slab and bursts) |
| The same board with one rqlite cluster, as an installation has | MEASURED 2026-11-03, three boards, one rqlite cluster over the three, 30 Go stand-ins and `ca` and `ssh-ca` as two units: 1,056 MiB of proportional memory on a typical loaded board (53% of the board) and 1,155 MiB on the worst board measured (58%). No Rust actor was built, so the Rust figure is still the estimate of 0012 ([#1180](https://github.com/truvity/sluis/issues/1180), [0037](/decisions/0037-capacity-is-measured-before-it-is-promised/#board-capacity)) |
| Go actor against Rust actor | MEASURED 2026-11-02, 30 actors under load, one language each: a Rust actor holds about 0.2 MiB of private memory and a Go actor 8.0 to 8.7 MiB, so Go costs 235 to 255 MiB more at 30 actors. The estimate of 2026-10-31 was about 300 MiB. Go does not give the memory back after the load |
| The mix of [0012](/decisions/0012-the-language-follows-the-executable/) next to the rqlite nodes, per board | MEASURED 2026-11-02, 25 Rust actors, 5 Go actors, 2 `entry`, a `session` stand-in and 10 rqlite nodes, light load: 160 to 200 MiB of PSS for the 43 processes, of which rqlite 98 to 134 MiB. The board's own services use about 160 MiB before anything starts, and `MemAvailable` never fell below 1559 of 1978 MiB |
| rqlite | About 9 MiB per cluster under write load, plus about 22 MiB of binary pages once per board |
| State writes | MEASURED 2026-11-02, three boards, 10 clusters of three nodes (one node of each on each board), Raft over plain TCP, the load generator on the boards: 400 commits a second for the installation were delivered in full with a p99 of 118 to 127 ms and 13 to 15 % of the CPU idle; saturated, about 600 a second with the CPU 95 % busy and the eMMC 29 % busy. The budget is not 400: that run used 10 clusters, and an installation has one. The budget is the saturation measured on 2026-11-03 with one rqlite cluster over the three boards, about 275 commits a second with the leader's CPU 85% busy ([0037, Board capacity](/decisions/0037-capacity-is-measured-before-it-is-promised/#board-capacity)). The CPU limits writes before the eMMC does. The single-board figure of 2026-10-31 (about 430 a second) had no replication and is not comparable |
| Latency of a replicated commit | MEASURED 2026-11-02: p50 21 to 41 ms and p99 62 to 123 ms at 7 and at 73 commits a second. Treat 20 to 40 ms as the cost of a replicated commit on this eMMC |
| Swap | MEASURED 2026-11-02: the board image runs a compressed swap (zram, 989 MiB). It was switched off for every memory figure above, so they are resident memory; account for it when sizing memory |
| Signing | About 147 ms per P-384 signature, about 7 a second per card, about 21 a second for three boards (MEASURED 2026-10-31) |
| Opening a data key | An ECDH on the card: median 143 ms, about 7 a second per card (MEASURED 2026-11-03 on two boards' cards). key@ caches the opened key, so a hit costs a memory operation and the hit rate decides how many requests a card supports ([0037](/decisions/0037-capacity-is-measured-before-it-is-promised/#measured-so-far)) |

Not measured: `cloudflared` with a live tunnel (29 MiB idle, MEASURED 2026-10-31; 60 MiB with an edge connection is an estimate, UNVERIFIED), the Go actors that were not loaded, and the real actors. The total stays under the ceiling with 50% added to the estimates. Go processes run under a `GOMEMLIMIT` at 2 to 3 times their steady private memory (24 to 32 MiB for rqlite, 24 MiB for an actor), with the default `GOGC`. The write figure was measured with the load generator on the same cores and with a replication round trip (about 1 ms between the boards), but without TLS on Raft, which the design uses and nobody has measured yet (UNVERIFIED), so the estimate below also reads it against a derated 200 commits a second.

A directory re-sync of 1,000, 10,000 and 100,000 users takes 2.5 s, 26 s and 260 s, and raises the p99 of a sign-in write about fivefold while it runs; a re-sync replaces items and does not clear first ([#1180](https://github.com/truvity/sluis/issues/1180), [0037](/decisions/0037-capacity-is-measured-before-it-is-promised/#board-capacity)).

**Writes the design needs** (estimated 2026-10-31 from the actor design, UNVERIFIED for the current layout). Each board is a voter in the cluster, so it applies every commit of the installation. The load of v1 is about 25,000 tokens in seven days, a peak of 0.8 tokens a second, 95% of them token exchanges; the signing ceiling of 21 tokens a second is the most three cards can sign. The commits per action are a reading of the flows, because the session and claims flows are not written yet.

| Commits from | Commits per action (assumed) | At 0.8 tokens/s | At 21 tokens/s |
|---|---|---|---|
| `exchange` | 1 replay marker per token exchange | 0.76 | 20.0 |
| `session` | 6 per sign-in (5% of tokens) | 0.24 | 6.3 |
| `quota`, where a rule enforces | 2 per admit: the `AdmitRecord` and the conditional update of the allowance ([0039](/decisions/0039-quota-allowance/#countdown-and-refusal)) | 1.6 | 42.0 |
| Audit `writer`, 3 logs | 1 per sealed batch, at most 0.2 a second per log ([0029](/decisions/0029-the-audit-log/#sealing)) | 0.6 | 0.6 |
| `witness`, 3 | 2 co-signatures per batch | 1.2 | 1.2 |
| `indexer` | 1 per sealed batch, with the cursor | 0.6 | 0.6 |
| Leases | 4 leases renewed every 5 s | 0.8 | 0.8 |
| `ca`, `ssh-ca`, reconcilers, `console` | A reserve: no rate is documented | 1.2 | 1.2 |
| **Total with `quota` enforcing** | | **7.0** | **72.7** |
| **Total without enforcement** | | **5.4** | **30.7** |

The three audit rows were counted as commits of the engine when the estimate was made. The writer and the witnesses keep their state in the audit blob and the index is an rqlite cluster of its own, so those rows overstate the load on store@'s engine and count towards the load of the board as a whole.

The design needs about 7 commits a second at the measured peak, 39 times below the budget of about 275 ([measured](/decisions/0037-capacity-is-measured-before-it-is-promised/#board-capacity); 29 times below the derated 200), and about 73 at the signing ceiling, 27% of the budget. The cards limit the installation before the store does, unless a hot quota allowance runs at the target of 100 admits a second, which alone takes about 200 commits a second ([0039](/decisions/0039-quota-allowance/#consistency-under-load)). Enforced `quota` is the largest writer, 23% of the total at the peak and 58% at the ceiling, so its load test matters most. The estimate reserves what is not yet known: the certificate rate, the size of directory passes, the lease time, the cost of a full-text commit and a slower follower. Re-measure when the actors exist.

## Virtual machines (EC2)

An EC2 instance or an Auto Scaling group is a possible bare-metal installation, with the same units as on a board and the packages from the dnf repository on Amazon Linux 2023. EC2 is not a delivery target and is not tested.

## Local Docker

Docker on a workstation is the development and CI form of bare-metal, one node: the [local](/runtimes/#local) installation ([0011](/decisions/0011-runtimes-and-installations/#the-local-installation)).

- It runs as **Docker Compose, one container per actor and per driver**, each as its actor's uid, so the call graph and the socket access lists are the ones the other installations enforce.
- Actors and drivers speak ConnectRPC over Unix sockets on shared volumes under `/run/sluis/<actor>/`.
- Keys are **software keys** by default. A dedicated development card is opt-in: only the key@ container reaches it, through the host's smart-card service, and key@ has the card to itself. The code refuses a software key in production.

## Identity and edge

- An actor's identity on a node is its uid, read through `SO_PEERCRED` on the Unix socket. On a cloud VM, calls to AWS use the actor's own IAM role, so CloudTrail names the actor and the instance.
- `cloudflared` is the edge connector on the boards installation, as described [above](#sockets-and-the-call-graph).
- **The console.** `entry` serves the console's single-page application from a directory on the node, same-origin with its API. The bundle is a separate artifact of the release ([Packages](/distribution/packages/)).

## Limits and residual risk

- The YubiKey is physical. Whoever holds the board and the card, and knows the PIN, can sign. Keep the board in a controlled place. The card's PIN policy limits the exposure of a lost board until it is replaced.
- eMMC wears under heavy writes. The spool and the data are small, and a blob store off the board keeps the audit chain.
- A root-level compromise of a node defeats host-asserted identities (uid, cgroup). On a cloud VM, KMS key policies and CloudTrail limit and record what the stolen identity can do.
- KMS is a regional service. A regional outage stops signing; there is no software fallback key, because the code refuses one in production.
- A burst beyond the signing rate of the cards queues ([Board capacity](#board-capacity)).
