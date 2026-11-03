# 0012 — The language follows the executable: Go by default, Rust at the edge, in the trusted base, in cloud drivers and on the smallest boards

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

sluis v2 is written in two languages. `policy` is Rust because Cedar's engine is a Rust crate ([0007](/decisions/0007-policy-and-sealed-grants/)), and the drivers for AWS are Rust. Two toolchains, a Rust kit for Connect over Unix sockets, schema validation and the conformance suite are a cost already paid, so moving one more component to Rust costs that component's code, not a second toolchain.

The unit of choice is the executable. Every component boundary is a ConnectRPC contract ([0002](/decisions/0002-families-of-actors/#contracts)), every driver is its own binary behind one port of its owner ([0005](/decisions/0005-the-store/#drivers)), and the executable a unit starts is the only code in its process. A driver's language is independent of its caller's, and a wrong choice can be reversed one component at a time. The typed clients of the store exist in both languages ([0005](/decisions/0005-the-store/#typed-clients)), so a work actor's language does not depend on the language of store@.

The research of 2026-10-30 found:

- **Go is memory-safe with exceptions:** data races on multi-word values, `unsafe` and cgo. Since 2024 the Go standard library had 89 advisories and none was memory corruption; Rust's TLS and certificate crates had the same classes (denial of service, panics, logic bugs) in the same period.
- **What Rust buys:** no memory corruption through data races in the most concurrent processes, deterministic destruction and zeroisation of secrets, a smaller footprint and faster cold start (on lambda-perf, 2026-10-30, arm64, 128 MB, hello world: Go 46.6 ms and 17 MB, Rust 18.0 ms and 13.3 MB). It does not buy freedom from parser logic bugs, allocation bombs or panics.
- **The libraries decide many components.** Go clearly leads for an embeddable OpenID Connect provider, the X.509 CA and the static-ct-api issuance log, the C2SP transparency-log tools, PIV attestation, HPKE, Kubernetes controllers and the vendor SDKs.
- **The YubiKey path (spike S4, 2026-10-31, firmware 5.8.0, `cryptoki` 0.12.1 over `ykcs11` 2.7.3 against `piv-go` v2.6.0).** Both worked within 1 to 3 ms of each other; the card is the cost, about 146 ms per P-384 signature. `ykcs11` does not hold the card for itself: when a second client touched it, the holder failed in 3 of 5 runs, once without recovering, because libykpiv reconnects with `SCARD_RESET_CARD`; libykpiv also caches the PIN in its own heap, out of reach of `zeroize`. `piv-go` connects exclusively, queues callers fairly and reaches its first signature in 0.17 s. Its own `piv.Verify` rejects attestations from firmware 5.7 and newer, so sluis supplies Yubico Attestation Root 1 and its intermediates.
- **The small boards (spike S5, re-run MEASURED 2026-11-02 on three arm64 boards with 4 cores, 2 GB RAM and eMMC each, on one gigabit switch, with real replication between them).** The memory fits with Go or with Rust actors. At 30 actors under load a Rust actor holds about 0.2 MiB of private memory and a Go actor 8.0 to 8.7 MiB, so Go costs **235 to 255 MiB more at 30 actors**, the largest single difference in the budget; the estimate of 2026-10-31 was about 300 MiB, the right order and 15 to 20 % high. Go does not give the memory back after the load stops. The write budget holds with the replication round trip: 400 commits a second for the installation were delivered in full with a p99 of 118 to 127 ms and 13 to 15 % of the CPU idle, and about 600 a second when saturated, where the CPU and not the eMMC limits (the eMMC was 29 % busy). The design needs 7 to 73 commits a second (estimated 2026-10-31, [Bare metal](/runtimes/bare-metal/#board-capacity)). The board image's compressed swap (zram, 989 MiB, MEASURED 2026-11-02) must be accounted for when sizing memory: it was switched off for these runs, so every figure is resident memory. The budget and the conditions of the write figures are on [Bare metal](/runtimes/bare-metal/#board-capacity).
- **The budget for one engine cluster and the units of a board (MEASURED 2026-11-03, three boards, [#1180](https://github.com/truvity/sluis/issues/1180)).** The measured full board of S5 ran 10 rqlite clusters, one per owner of state. An installation has one cluster over its boards ([0005](/decisions/0005-the-store/#engines)), which the spike ran with 30 Go units on each board, `ca` and `ssh-ca` as two units and every driver of store@ and key@ as a process of its own: the 30 Go units hold 727 to 836 MiB of resident memory idle and 856 MiB loaded, and a typical loaded board (the rqlite leader at 100 writes a second) uses 1,056 MiB of proportional memory, 53 % of 1,978 MiB, and the worst case measured 1,155 MiB, 58 %, both under the ceiling of 1380 MiB. `ca` and `ssh-ca` together hold 54.6 MiB, so keeping them apart costs about 27 MiB per board, and nothing needs fusing. The figures are for Go stand-ins of every unit, which over-count the 19 Rust actors of the table; no Rust unit was built, and the Rust set is still the estimate of S5. The full measurement is in [0037](/decisions/0037-capacity-is-measured-before-it-is-promised/#board-capacity).
- **The Rust side has known gaps.** Connect for Rust (`connectrpc` 0.9.1) is official but before 1.0, with one named maintainer; OpenTelemetry traces in Rust are Beta; GoReleaser's Rust builder warns that workspaces might not work; spike S10 answered it on 2026-11-01: workspaces work, with one build entry per binary using `--package` and `--bin`.

## Decision

### The rules

- **R1. One executable, one language.** An actor is never split across languages, so its language holds on every runtime. A driver is its own executable and may differ from its caller. The per-actor table records the choice per component.
- **R2. Rust at the unauthenticated edge**, where a process is reachable by unauthenticated network input and needs no protocol library that is mature only in Go: the slim `entry`, and the key-less edge relay on Kubernetes ([0011](/decisions/0011-runtimes-and-installations/#kubernetes)). An edge actor that needs an OpenID Connect provider stays Go until a Rust one exists.
- **R3. Rust for the trusted base:** processes that run as root or hold a PIN, a session or key material in memory and speak a fixed local protocol: `sluis-node`, key@ and `sluis-host`. One named exception: key@ is Go (below).
- **R4. Go where the deciding library is Go-only or best in Go:** the X.509 CA and its issuance log, the C2SP log writer and witness, the OpenID Connect provider and token exchange, PIV attestation, HPKE, TPM, Kubernetes controllers and the cert-manager issuer, and the vendor SDKs.
- **R5. Drivers follow their backend's best SDK, with one language per vendor SDK in the build.** AWS is Rust, so the build has one AWS SDK language. The engine and the local sources have no vendor SDK and follow R11, because they run on the boards. One named exception: `cloud-cloudflare` is Go.
- **R6. Go by default** for business logic, CRUD and integrations, except on the smallest board tier (R11): delivery speed, stable OpenTelemetry and the wider hiring pool.
- **R7. No Rust where the only library for a security function is marked experimental or unaudited.** Use a standard interface such as PKCS#11, or stay in Go. The `yubikey` crate is the case in point.
- **R8. No FIPS build in 2.0.** Rust components use current crates and rustls, with no FIPS pin, and keep to the approved algorithms of [0006](/decisions/0006-keys-and-sealing/#algorithms). A FIPS build of the Rust side would need aws-lc-rs in FIPS mode and an answer for the AWS SDK for Rust, which signs SigV4 requests and S3 checksums with RustCrypto, outside any module (spike S2, 2026-10-30).
- **R9. Both kits pass one conformance suite:** Connect over Unix sockets with peer credentials, the typed store client, configuration from the generated JSON Schema, the CLI conventions, OpenTelemetry. A component may move language only once its language's kit passes the suite.
- **R10. Contracts are on the wire, so a choice is reversible.** A language change replaces one component behind the same contract and suite.
- **R11. Rust on the smallest board tier, unless a serious trade-off is named.** An actor that runs on a tier-0 board (2 GB, as in spike S5) prefers Rust. Go is used there only where the rules name a serious trade-off, such as a required library that exists only in Go. The per-actor table below names the language of every component; a later design that names a serious trade-off changes its row. Building the trusted base in Go first and swapping later is acceptable, under R9.
- **`GOMEMLIMIT` is a ceiling** at 2 to 3 times each process's steady private memory, with the default `GOGC` (24 to 32 MiB for rqlite, 24 MiB for an actor; decided 2026-10-31). A limit of 12 MiB cut throughput by 61 to 81 % through garbage collection.

### Per-actor table

A Rust row holds once its spikes pass ([The spikes are gates](/decisions/0012-the-language-follows-the-executable/#the-spikes-are-gates)). S1 and S10 passed on 2026-11-01, and S3 holds the row for `entry` with the two checks listed under Follow-ups. A gate does not stop work: the component is built against its contract and the conformance suite meanwhile, and a failed gate moves it to the fallback candidate. Go rows have no gate.

| Component | Language | Rule | Gate | First working version |
|---|---|---|---|---|
| `entry` (slim), the Kubernetes edge relay | Rust | R2 | S1, S3, S10 | `entry` |
| `store@` | Rust | R11 | S1, S10 | yes |
| `exporter@` | Rust | R11 | S1, S10 | no |
| `key@` | Go with `piv-go` for YubiKey PIV, in key@ and in its card driver | R4: an exception to R3 | none | yes |
| `sluis-node` | Rust. It verifies OpenPGP signatures on signed configuration and binaries, by a release subkey that a root primary in the keyring has bound; Sigstore provenance is a second signal, not the trust | R3 | S1, S10 | no |
| `sluis-host` | Rust | R3 | S1, S10 | no |
| `policy` | Rust | R4 (`cedar-policy`) | S1, S10 | yes |
| `signer` | Rust: it signs through key@ and needs no Go-only library | R11 | S1, S10 | yes |
| `console` (the actor; the single-page application is TypeScript) | Rust, unless S1 shows that Connect for Rust lacks the server streaming the console needs; then Go | R11 | S1, S10 | yes |
| `indexer`, `reader` | Rust: they read the log's tiles and verify its C2SP checkpoints, which needs no Go-only library | R11 | S1, S10 | yes |
| Drivers of the engine and the local sources: `rqlite`, `file`, the credential source | Rust | R11 | S1, S10 | yes |
| The local drivers of the audit pieces: `spool`, the `fs` blob, the `sqlite` index | Rust | R11 | S1, S10 | yes |
| AWS drivers: `dynamodb`, `appconfig`, SSM, `aws-kms`, `sqs`, the `s3-compatible` blob | Rust | R5 | S1, S10 | no |
| `cloud-cloudflare` | Go, sharing the library of the Cloudflare minter | R4: an exception to R5 | none | no |
| `session` | Go | R4: the embeddable OpenID Connect provider | none | yes |
| `exchange` | Go | R4: the proof verifiers, HPKE and the OpenID Connect provider; its HPKE key and the session cookie-sealing stay behind key@ | none | yes |
| `ca` | Go | R4: the X.509 CA and its issuance log | none | yes |
| `writer`, `witness` | Go | R4: the C2SP log writer and witness | none | `writer` |
| Integrations | Go: the adapters `adapter-github`, `adapter-slack` and `adapter-upstream-oidc`, and every further `adapter-<vendor>`, one executable each | R4: the vendor SDKs, and the OpenID Connect client of `adapter-upstream-oidc` | none | `adapter-upstream-oidc` |
| Other drivers (`nats-jetstream`, the `postgres` index, witness drivers, the OpenBao and Kubernetes destinations of exporter@) | Go | R5, R6 | none | no |
| `ssh-ca`, `quota`, `sluis agent` | Rust | R11 | S1, S10 | no |
| The `sluis` CLI, the cert-manager issuer | Go | R4, R6; not resident on a tier-0 board | none | the CLI |

- **key@ is Go with `piv-go`.** One key@ owns each node's card, and `piv-go` enforces that by construction with its exclusive connection, where `ykcs11` resets the card when another client appears and keeps a PIN copy that cannot be wiped. key@ keeps the PIN in locked memory and zeroes its own copy; Go cannot promise the runtime keeps no other, which the zeroisation review records. PKCS#11 stays only for the later YubiHSM 2 and Nitrokey drivers, whose language is chosen with them.
- **store@ and exporter@ are Rust.** They hold credentials, parse no unauthenticated input and speak the one store contract, so R11 decides. Their code is the code to review hardest ([0002](/decisions/0002-families-of-actors/#credential-holders)).
- **Rust validates with `prost-protovalidate` 0.6.x, pinned.** It is a community crate, because Buf publishes no protovalidate library for Rust, and it is a named risk: it agreed with protovalidate-go on every document of the schema spike ([#1177](https://github.com/truvity/sluis/issues/1177), 2026-11-03), and the shared vectors of R9 must catch it the day it falls behind protovalidate's rules.
- **The typed store clients are part of both kits.** The Go client `store.Client[T Kind]` and the Rust `Store<K: Kind>` are generated from the kind's message and pass the same conformance suite (R9).
- **Attestation verification is Go**, in the CLI at node initialisation and in the `yubikey-attestation` verifier of `exchange` ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)), anchored on Yubico Attestation Root 1 and its intermediates, supplied by sluis.
- **`cloud-cloudflare` is Go:** one vendor library in one language weighs more than one language for every driver. It is a driver private to its owner, and it shares its library with the Cloudflare minter of tenant credentials ([0025](/decisions/0025-integrations/#credential-minters)).
- **The AWS drivers are one group** in Rust. They run as Lambda extensions and as sidecars, where start-up time adds to every cold start.
- **OpenTelemetry from Rust** uses a Connect instrumentation crate of sluis's own, offered upstream, and OTLP over HTTP/protobuf; about 3 to 4 MiB more per Rust actor is accepted (MEASURED 2026-11-02, spike S6: 3.4 MiB at idle and 4.0 MiB after 22,000 calls). The measured CPU and size of the crate are in [0016](/decisions/0016-telemetry/#consequences).

### The spikes are gates

A conditional verdict holds once its spike passes. The table above fixes the languages of the first working version; the gated components are built meanwhile against their contracts, and a spike that fails moves its components to a fallback candidate before their first release.

| Spike | What it shows | Gates |
|---|---|---|
| S1 ([#939](https://github.com/truvity/sluis/issues/939)) | Connect for Rust over Unix sockets: `connectrpc` server and client with a peer-credential extension and the default-deny interceptor, against connect-go both ways; the conformance runner; streaming | R2, R3, R5 |
| S3 ([#941](https://github.com/truvity/sluis/issues/941)) | A slim `entry` prototype in both languages, behind the tunnel client and the Lambda Web Adapter, with limits, timeouts and 24 hours of fuzzing; p99 latency, memory, cold start, binary size | `entry` |
| S10 ([#947](https://github.com/truvity/sluis/issues/947)) | GoReleaser with a Cargo workspace: every Rust binary for two architectures, with SBOM and provenance like the Go artefacts, and Lambda zips within the layer limits | Every Rust component |

Spikes S2 ([#940](https://github.com/truvity/sluis/issues/940)), S4 ([#942](https://github.com/truvity/sluis/issues/942)), S5 ([#943](https://github.com/truvity/sluis/issues/943)), S6 ([#944](https://github.com/truvity/sluis/issues/944)) and S7 ([#945](https://github.com/truvity/sluis/issues/945)) are done (results above). Configuration is settled in [0004](/decisions/0004-the-data-model/#schemas-are-protobuf); its fidelity spike ([#1177](https://github.com/truvity/sluis/issues/1177)) is done too (2026-11-03).

### Fallbacks are candidates

A fallback is not chosen in advance. When a spike fails, the maintainer picks the fallback for that component from its candidates, with the results in hand.

| Component | Candidate fallbacks |
|---|---|
| `entry` | Go first, Rust after the parity milestone |
| AWS-backed drivers | Go |
| `sluis-node`, `sluis-host` | Go |
| Connect for Rust (S1) | The gRPC protocol through tonic, or a hand-written unary codec |

## Consequences

- More of sluis moves to Rust on the boards. Reviewers read more Rust, and the Rust gates cover more components; each move waits for the Rust kit to pass the suite.
- The public edge and the trusted base, apart from key@, are memory-safe without a garbage collector and can zeroise what they hold. store@ and exporter@ are among them. The cost is two languages on the request path and at the trust boundaries.
- Most of sluis stays Go where its deciding libraries are: the OpenID Connect provider, the CA, the transparency logs, the vendor SDKs and Kubernetes.
- One AWS SDK language: the AWS drivers share a toolchain and a release path.
- `piv-go` reaches pcsc-lite through cgo on Linux, so key@ keeps a per-architecture native build ([0013](/decisions/0013-release-train-packaging-and-distribution/#one-version)).
- key@ is the one trusted-base process in Go: its PIN sits in a garbage-collected process and it uses a few megabytes more than a Rust holder, but the card has exactly one owner, enforced by the library.
- A board runs one engine cluster, not one per owner of state, so the memory budget has more room than the measured full board; the units of a whole board, with the drivers of the holders and `ca` and `ssh-ca` as processes of their own, were measured on 2026-11-03 and fit with room to spare.
- The Rust components build like any other Rust code, with cargo-zigbuild and no CMake, Perl or pinned clang.
- The spikes S1, S3 and S10 are on the critical path of the first working version, and the Rust validator is a community crate that the conformance vectors watch. If Connect for Rust stalls, a fallback candidate carries the Rust components; tonic is in maintenance only, so the hand-written codec is the longer-lived one.
- Two OpenTelemetry stacks, with Rust traces in Beta.
- The `sluis` CLI stays the only executable people run, and it is Go. The source-layout page follows this record.

## Roads not taken

- **Go for everything except `policy` and the cloud drivers.** It leaves the public edge with net/http's advisory stream and Go's data-race class, keeps root-run secrets in a garbage-collected heap, and splits the AWS SDK across two languages.
- **Rust for everything, or for every actor on a tier-0 board.** Rust has no embeddable OpenID Connect provider, no maintained static-ct-api log or C2SP witness, no PIV-attestation library and no maintained vendor clients; each would be written in-house.
- **Group by piece (core, audit, platform in one language each).** It overrides the library-driven choices, while the contracts already make each executable independent.
- **`exchange` in Rust, or `session` and `exchange` together.** Three of the six proof verifiers and RFC 8693 would be written in-house, and the HPKE crate is unaudited; the secrets leave the process through the keys port instead.
- **key@ on the `yubikey` crate.** Its own notice says it is unaudited and experimental (R7).
- **key@ in Rust through PKCS#11 (`cryptoki` with `ykcs11`).** Spike S4 found that `ykcs11` resets the card for every client when a second one appears and keeps a PIN copy Rust cannot wipe; `piv-go`'s exclusive connection is what one holder per node needs.
- **store@ in Go for the vendor SDKs.** The store speaks to its engines through drivers that follow R5, so the SDKs are in the drivers and not in store@; a Go store@ would cost about 8 MiB of private memory on a 2 GB board for no library it needs.
- **`cloud-cloudflare` in Rust.** The Cloudflare library would exist twice, and its maintained SDK is Go.
- **Go by default on a tier-0 board.** About 250 MiB more private memory at 30 actors on a 2 GB board (235 to 255 MiB, spike S5, MEASURED 2026-11-02), where Rust costs no serious trade-off.

## Follow-ups

- The zeroisation review of the key@ PIN paths, and the release-subkey slot on a real card: [#942](https://github.com/truvity/sluis/issues/942).
- Spikes S1 ([#939](https://github.com/truvity/sluis/issues/939)) and S10 ([#947](https://github.com/truvity/sluis/issues/947)) pass (2026-11-01); results are on the issues. S3 ([#941](https://github.com/truvity/sluis/issues/941)) holds the Rust row for the slim `entry` on memory, size and threads (latency is parity); two checks remain: the real tunnel client (edge relay tests) and 24-hour fuzz campaigns (CI, [#796](https://github.com/truvity/sluis/issues/796)).
