---
title: Approved libraries
description: "The cryptography and parser libraries sluis may use in Go, Rust and TypeScript, the ones it refuses, and how a library is added."
status: target
sidebar:
  order: 6
---

sluis implements no cryptographic primitive and no protocol parser of its own ([REQ-SEC-018](/requirements/sec/#REQ-SEC-018)): they come from approved, maintained libraries ([REQ-SEC-008](/requirements/sec/#REQ-SEC-008)). This page is the list, per language, with the record that needs each capability; a library is approved by the review of the pull request that lists it. The list itself is data, [`docs/reference/approved-libraries.yaml`](https://github.com/truvity/sluis/blob/main/docs/reference/approved-libraries.yaml), so that a CI check can compare it with the dependencies once there is code ([#1039](https://github.com/truvity/sluis/issues/1039)).

The rules behind it are in [ADR 0006](/decisions/0006-keys-and-sealing/#algorithms) and [ADR 0012](/decisions/0012-the-language-follows-the-executable/#the-rules): only the approved algorithms, a nonce from the library and never from the caller, the operating system's random generator only, no library marked experimental or unaudited for a security function, and no FIPS build in 2.0.

## Go

| Library | For | Needed by |
|---|---|---|
| `crypto/...` (standard library) | ECDSA P-384, AES-256-GCM, SHA-2, HKDF, HMAC, X.509, TLS, and `crypto/rand` | [ADR 0006](/decisions/0006-keys-and-sealing/#algorithms) |
| `golang.org/x/crypto/ssh` | OpenSSH keys and certificates in Go components and the CLI | [ADR 0023](/decisions/0023-certificate-authorities/#ssh) |
| `github.com/go-piv/piv-go/v2` | YubiKey PIV in key@ and in its card driver; attestation verification | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table) |
| `github.com/ProtonMail/go-crypto` | OpenPGP packets: the subkey request, the back-signature, detached signatures | [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off) |
| `github.com/santhosh-tekuri/jsonschema/v6` | The generated JSON Schema, applied to a configuration document before it is decoded | [ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf) |
| `buf.build/go/protovalidate` (protovalidate-go) | The protovalidate rules of every Protobuf message, after decoding: the authority in code; see [protovalidate](#protovalidate) | [ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf) |
| `connectrpc.com/connect`, `google.golang.org/protobuf` | The Connect protocol and Protobuf | [ADR 0002](/decisions/0002-families-of-actors/#contracts) |
| `github.com/go-jose/go-jose/v4` | JWS, JWK and JWT: verifying tokens and client assertions, reading and writing key sets; never JWE | [ADR 0017](/decisions/0017-identity-and-sign-in/#context) |
| `github.com/go-jose/go-jose/v4/cipher` (the key-wrap function only) | AES key wrap (RFC 3394) of a data key for the key-agreement key of a board's card. Scope: key@ only, AES-KW only; no JWE and no other function of the module in key@ | [ADR 0006](/decisions/0006-keys-and-sealing/#datakeywrap) |
| `github.com/zitadel/oidc/v3` | The OpenID Provider of `session` and `exchange` (`pkg/op`) and the relying party of the `oidc` upstream (`pkg/client/rp`) | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table) |
| `golang.org/x/oauth2` | The OAuth 2.0 client under the relying party of the `oidc` upstream | [ADR 0017](/decisions/0017-identity-and-sign-in/#optional-openid-flows) |
| `golang.org/x/mod/sumdb/note`, `golang.org/x/mod/sumdb/tlog` | C2SP signed notes, and the hashes and tiles of a tiled log, in `writer` and `witness` | [ADR 0029](/decisions/0029-the-audit-log/#tiled-log) |
| `filippo.io/torchwood` | C2SP checkpoints, cosignatures and tiles, and the tile client, in `writer` and `witness` | [ADR 0029](/decisions/0029-the-audit-log/#witnesses) |
| `filippo.io/sunlight` | C2SP `static-ct-api` entries and checkpoints, in the issuance log of `ca` | [ADR 0023](/decisions/0023-certificate-authorities/#issuance-log-and-revocation) |
| `go.yaml.in/yaml/v3` | Reading the bootstrap file and the YAML config documents, through the strict profile of [the bootstrap file](/reference/bootstrap-file/#format) | [ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf) |

Go keeps the standard library's defaults: `GOFIPS140` and `fips140` are unset ([ADR 0006](/decisions/0006-keys-and-sealing/#algorithms)).

## Rust

| Library | For | Needed by |
|---|---|---|
| `aws-lc-rs` | AES-256-GCM with `RandomizedNonceKey`, ECDSA P-384, HKDF, SHA-2, and its random generator | [ADR 0006](/decisions/0006-keys-and-sealing/#algorithms) |
| `rustls` | TLS, with the `aws-lc-rs` provider and no FIPS pin | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#the-rules) |
| `cedar-policy` | Cedar policy in `policy` | [ADR 0007](/decisions/0007-policy-and-sealed-grants/) |
| `jsonschema` | The generated JSON Schema, applied to a configuration document before it is decoded | [ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf) |
| `prost-protovalidate`, 0.6.x, pinned | The protovalidate rules of every Protobuf message, after decoding, in the Rust binaries. A community crate and a named risk; see [protovalidate](#protovalidate) | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table) |
| `connectrpc` | The Connect protocol over Unix sockets (spike S1 passed on 2026-11-01) | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#the-spikes-are-gates) |
| `zeroize` | Wiping secrets from memory | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#context) |
| `jsonwebtoken`, with its `aws_lc_rs` feature | Verifying JWS and JWT, with an explicit algorithm list | [ADR 0017](/decisions/0017-identity-and-sign-in/#context) |
| `signed_note`, `tlog_tiles` | C2SP signed notes, checkpoints and tiles in `indexer` and `reader`; the P-384 verifier of the log key is a `NoteVerifier` on `aws-lc-rs` | [ADR 0029](/decisions/0029-the-audit-log/#tiled-log) |
| `saphyr-parser` | Reading the bootstrap file and the YAML config documents, through the strict profile of [the bootstrap file](/reference/bootstrap-file/#format) | [ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf) |
| `ssh-key` | OpenSSH keys and certificates in `ssh-ca`, with a signing key that signs through the `keys` port; chosen with a condition, see [below](#rust-openssh-certificates) | [ADR 0023](/decisions/0023-certificate-authorities/#ssh) |
| The AWS SDK for Rust | AWS calls from the AWS-backed drivers; its SigV4 and checksums are outside any FIPS module | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#the-rules) |

## TypeScript

| Library | For | Needed by |
|---|---|---|
| `ajv`, its draft 2020-12 build | Configuration against the generated JSON Schema | [ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf) |
| WebCrypto and WebAuthn, the browser's | Cryptography and passkeys in the console's single-page application | [ADR 0017](/decisions/0017-identity-and-sign-in/#passkeys) |
| `@connectrpc/connect` (connect-es) | The Connect client of the audit reader's API | [ADR 0028](/decisions/0028-audit-pieces/#the-reader) |
| `jose` | Verifying tokens in the console's single-page application and in the verification demo | [ADR 0017](/decisions/0017-identity-and-sign-in/#context) |

## Refused

| Library | Why | Decided by |
|---|---|---|
| The `yubikey` crate | Its own notice says it is unaudited and experimental (rule R7) | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#roads-not-taken) |
| `ykcs11` through `cryptoki`, for key@ | It resets the card for every client when a second one appears, and keeps a PIN copy that cannot be wiped | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#roads-not-taken) |
| `gpg` on a node | sluis builds the OpenPGP packets itself and the card signs | [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off) |
| A Go plugin or a WebAssembly module in an actor | Plugins run out of process, always | [ADR 0003](/decisions/0003-units-transports-and-fusion/#consequences) |

## Adding a library

A dependency that provides a cryptographic primitive, or parses a protocol or a format that crosses a trust boundary, must be on this list under the language of the executable that links it. To add one:

1. Open a pull request that adds an entry to the data file and a row here: the name, what it is for, and why this library and not one already listed.
2. Say whether it is maintained (releases in the last year, a security policy), whether it has had an audit, and whether it is marked experimental; an experimental library is refused for a security function.
3. Add a security note, as for any change that touches keys or signing ([Review](/contributing/workflow/#review)).

The lockfiles pin versions. A choice names the version it was evaluated at and the date, so that the next reader can judge how far the library has moved ([principle 9](/principles/#9-measure-before-deciding-and-date-the-measurement)); a security fix can set a floor.

## Choices made on 2026-11-01

Each row is a question that stood open until then. The versions are the latest releases on 2026-11-01; the release date follows each version. Where a library is refused, the reason is in the last column.

| Question | Chosen | Evaluated at | Not chosen, and why |
|---|---|---|---|
| [JOSE](#jose) in Go | `go-jose/v4` | v4.1.7, 2026-10-30; floor v4.1.7 | `lestrrat-go/jwx` v3.4.0 (2026-10-23): a second JOSE library beside the one the provider already needs. `golang-jwt/jwt` v5.3.1 (2026-01-28): JWT only, no JWK or key sets |
| [JOSE](#jose) in Rust and TypeScript | `jsonwebtoken` (Rust), `jose` (TypeScript) | 11.1.0, 2026-09-16; 6.2.14, 2026-10-29 | `josekit` 0.10.3 (2025-05-20): OpenSSL, not `aws-lc-rs`, and not released for 17 months |
| [OpenID Connect provider](#openid-connect-provider) | `zitadel/oidc/v3` | v3.51.16, 2026-10-15; floor v3.47.0 | `ory/fosite` v0.49.0 (2024-12-12): its own OAuth 2.0 and no release for ten months. Dex: a server with its own storage, not a library. `coreos/go-oidc` v3.21.0 (2026-09-01): relying party only |
| [C2SP libraries](#c2sp-transparency-logs) | `x/mod` `note` and `tlog`, `torchwood`, `sunlight` in Go; `signed_note` and `tlog_tiles` in Rust | v0.42.0, 2026-10-09; v0.10.0, 2026-09-24; v0.10.2, 2026-10-26; 0.2.0, 2025-04-18 | Tessera v1.0.4 (2026-07-16) as the writer's engine: it sequences and publishes checkpoints itself |
| [YAML reader](#yaml-reader) | `go.yaml.in/yaml/v3` (Go), `saphyr-parser` (Rust), each behind one strict profile | v3.0.6, 2026-10-13; 0.3.3, 2026-10-27 | `serde_yaml` (deprecated), `serde-saphyr` 2.0.0 and `goccy/go-yaml` v1.19.2: they read a different document than the other language, or print the source in an error |
| [OpenSSH certificates in Rust](#rust-openssh-certificates) | `ssh-key`, once it is released as 0.7 | 0.6.7, 2024-10-15; 0.7.0-rc.11, 2026-06-29 | `russh` 0.65.0 (2026-10-25): an SSH transport, which `ssh-ca` does not speak |

### JOSE

- **Go: `go-jose/v4`.** The OpenID Connect provider below already depends on it (`zitadel/oidc` v3.51.16 requires v4.1.4), so one JOSE library serves the provider, the relying party and sluis's own code. It parses a signed token only against an algorithm list the caller passes, which makes "the token chooses its algorithm" impossible by construction, and it supports ES384, the algorithm of the token-signing keys ([ADR 0006](/decisions/0006-keys-and-sealing/#algorithms)). **The floor is v4.1.7:** five advisories were published against v4.1.6 and earlier on 2026-10-30, all fixed in v4.1.7, so the version `zitadel/oidc` asks for is too old, and the sluis module requires v4.1.7 or newer. sluis uses JWS, JWK and JWT only; a call into the JWE half of the library needs a pull request to this list. Its key-wrap function, and that function alone, is also approved for key@: Go's standard library has no AES key wrap, which key@ needs to wrap a data key for a board's card ([ADR 0006](/decisions/0006-keys-and-sealing/#datakeywrap)).
- **Rust: `jsonwebtoken` with the `aws_lc_rs` backend,** for verification (the console checks an operator's token). It requires the caller to name the algorithms, and its backend is the library already on this list. `signer` signs through the `keys` port, so the key never reaches a JOSE library; the library's crypto-provider hook, or the base64url encoding of the signing input by `signer` itself, which is encoding and not cryptography, is the pull request of `signer` to choose.
- **TypeScript: `jose`.** The single-page application and the verification demo verify against the key set with WebCrypto underneath.
- **The verification demos** of the integration guides use the library of their language: `go-jose`, `jsonwebtoken` and `jose`. A relying party in any other language uses its own platform's library: sluis tells it what to pin (`iss`, `aud`, the algorithm), not which library to use ([principle 5](/principles/#5-open-standards-as-their-consumers-implement-them)).

### OpenID Connect provider

- **`zitadel/oidc/v3` for the provider of `session` and `exchange`, and its `rp` package for the `oidc` upstream.** Go is the language of both actors because this is the only maintained Go library that is an OpenID Provider and a relying party in one module ([ADR 0012](/decisions/0012-the-language-follows-the-executable/#the-rules), rule R4). Read on 2026-11-01: v3.51.16 was released on 2026-10-15, the repository was pushed on 2026-10-30, one advisory was published (2026-08-24, fixed in v3.47.0, the floor), the licence is Apache-2.0. It implements the code flow with PKCE, refresh, discovery, token exchange (RFC 8693), device authorization and back-channel logout on the provider side, and its source handles `form_post`, `acr_values` and `max_age` in the authorization request.
- **It is not certified as a provider.** Its README names certifying the provider as a goal and lists the relying party as certified for the basic and config profiles. sluis claims a conformance plan only when it passes ([ADR 0017](/decisions/0017-identity-and-sign-in/#optional-openid-flows)), so the conformance run of sluis's own `session` is the evidence, and the library gives no shortcut to a claim.
- **Its maintainers say they have limited availability for feature reviews** (the repository's README, 2026-11-01). A gap that sluis needs is therefore carried as a patch and offered upstream; if a patch cannot be carried, the answer is a pull request to this list that vendors or replaces the library, not a private fork. A version change runs the conformance cases first, as for Cedar ([ADR 0007](/decisions/0007-policy-and-sealed-grants/#consequences)).
- **Not chosen.** `ory/fosite`: an OAuth 2.0 framework with its own OAuth implementation; its latest release is v0.49.0 of 2024-12-12, though the repository was pushed on 2025-11-20. Dex: a complete server with its own storage and connectors, which sluis would have to embed with its state model. `coreos/go-oidc`: verifies ID tokens as a relying party and is not a provider; sluis would write the flow, `state` and `nonce` handling itself.

### C2SP transparency logs

- **Go, for `writer`, `witness` and the issuance log of `ca`.** `golang.org/x/mod/sumdb/note` and `tlog` (module v0.42.0, 2026-10-09) are the Go team's signed-note and tile-hash code. Their signer and verifier are interfaces, so the P-384 log key signs through the `keys` port. `filippo.io/torchwood` (v0.10.0, 2026-09-24, BSD-3-Clause, before 1.0) adds the C2SP checkpoint, cosignature and tile functions and a tile client on top of them. `filippo.io/sunlight` (v0.10.2, 2026-10-26, ISC) holds the `static-ct-api` entry and checkpoint code for `ca`'s issuance log.
- **Rust, for `indexer` and `reader`.** `signed_note` and `tlog_tiles` from Cloudflare's `azul` repository (BSD-3-Clause). The released 0.2.0 dates from 2025-04-18, while the repository was changed on 2026-10-27, so the pull request that builds the reader chooses between the release and a pinned revision, and a pinned revision is a pull request to this list. `signed_note` ships only an Ed25519 verifier, with a `NoteVerifier` trait for others: the P-384 verifier of the log key is a few lines on `aws-lc-rs`, and the cosignatures of witnesses are Ed25519 or ML-DSA-44 ([ADR 0029](/decisions/0029-the-audit-log/#witnesses)).
- **Not chosen: Tessera as the writer's engine** (v1.0.4, 2026-07-16). It sequences entries and publishes checkpoints itself, while [ADR 0029](/decisions/0029-the-audit-log/#the-write-once-fence) puts the batch, the seal entry and the create-if-absent fence in sluis's one writer. This was judged from its documentation on 2026-11-01 and not measured; it comes back if the writer's own tile code turns out to be larger than the engine it replaces.

### YAML reader

Both readers were run on 2026-11-01 and again on 2026-11-02 (`go.yaml.in/yaml/v3` v3.0.6 and `saphyr-parser` 0.3.3): the readers as they come on a dozen documents, and the two behind the strict profile of [the bootstrap file](/reference/bootstrap-file/#format) on the 15 documents of its vector table of 2026-11-01 (14 rows, one of which holds two documents), and on 2026-11-02 on 105 profile vectors, those 15 and 90 edge cases.

- **As they come, no reader refuses what the profile refuses.** `go.yaml.in/yaml/v3` and `goccy/go-yaml` v1.19.2 accept anchors, aliases, merge keys, tags and a second document, and read `010` as the number 8. `serde-saphyr` 2.0.0 reads the plain words `y` and `yes` as `true` and `010` as a float; `saphyr` reads `yes` as a string. Only a duplicate key is refused by every reader. `goccy/go-yaml` and `serde-saphyr` print the offending source line in their errors, which breaks the rule that an error never shows a value ([ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf)).
- **Behind the profile, the two give the same verdict on all 15 documents and on all 105 profile vectors (MEASURED 2026-11-02).** Finding the edge cases added six cases to the first five rules of the profile, each by a disagreement of the two readers, and the bootstrap-file page now carries them. The profile is a walk over the nodes of the reader, about 75 lines in Go and 90 in Rust: Go uses the `Node` tree of `go.yaml.in/yaml/v3`, and Rust uses the event stream of `saphyr-parser`, which exposes anchors, aliases and tags that a typed reader hides. [P6](/principles/#6-generic-products-joined-by-a-contract) applies: the contract is the profile and its vectors, not shared code.
- **`go.yaml.in/yaml/v3` and `saphyr-parser` because** they are the parsers the maintained readers sit on: `go.yaml.in/yaml/v3` is maintained by the YAML organisation at `github.com/yaml/go-yaml` (v3.0.6, 2026-10-13, and already in the dependencies of the OpenID Connect library above), and `saphyr-parser` 0.3.3 (2026-10-27) is a YAML 1.2 event parser. `serde_yaml` is deprecated and `serde_yml` is marked unmaintained.

### Rust OpenSSH certificates

- **`ssh-key`** (RustCrypto, Apache-2.0 or MIT) reads and writes OpenSSH keys and certificates, and builds a certificate with `Builder::sign` over any type that implements its `SigningKey` trait, so `ssh-ca` can sign through the `keys` port. It supports `ecdsa-sha2-nistp384`. It carries no experimental or unaudited notice; no audit of it is published as far as the evaluation of 2026-11-01 found, and RustSec lists no advisory against it. The repository was changed on 2026-10-26.
- **The condition.** The last stable release is 0.6.7 of 2024-10-15, and 0.7.0 has been a release candidate since 2025-06-01, the latest being 0.7.0-rc.11 of 2026-06-29. The pull request that builds `ssh-ca` uses a stable 0.7 or, if there is none by then, 0.6.7 with the certificate tests below, or moves `ssh-ca` to Go with `golang.org/x/crypto/ssh` under the serious-trade-off clause of [rule R11](/decisions/0012-the-language-follows-the-executable/#the-rules). `ssh-ca` is not in the first working version.
- **The interop test is the standard** ([principle 5](/principles/#5-open-standards-as-their-consumers-implement-them)): a certificate that `ssh-keygen -L` reads and an `sshd` accepts, with the principals, validity and critical options of [ADR 0023](/decisions/0023-certificate-authorities/#ssh).
- **Not chosen: `russh`** (0.65.0, 2026-10-25) is an SSH client and server; `ssh-ca` issues certificates and speaks no SSH.

## Choices made on 2026-11-03

| Question | Chosen | Evaluated at | Not chosen, and why |
|---|---|---|---|
| [Protovalidate](#protovalidate) | `buf.build/go/protovalidate` in Go; `prost-protovalidate` 0.6.x in Rust, pinned | The schema spike ([#1177](https://github.com/truvity/sluis/issues/1177)), 2026-11-03 | A rule checker of our own per language: two implementations of the same constraints would drift |

### Protovalidate

- **Protobuf with protovalidate is the authority in code.** The generated JSON Schema is a derived subset for editors and `helm lint`; cross-field rules, duration and timestamp ranges, exact byte lengths and the strictness of `uri` are enforced by protovalidate only ([ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf)). Every binary validates a document against the embedded JSON Schema before it decodes, and the decoded message against its protovalidate rules.
- **Go uses protovalidate-go,** the library that Buf publishes. It is the reference: the rules mean what it says they mean.
- **Rust uses `prost-protovalidate` 0.6.x, pinned.** It is a community crate, because Buf publishes no protovalidate library for Rust, and it is a named risk ([ADR 0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table)). It agreed with protovalidate-go on every document of the schema spike (2026-11-03). Two things bound the risk. The version is pinned, so a release that changes a rule cannot arrive through a lockfile update. And the shared conformance vectors of rule R9 run the same documents through both kits, so the day the crate falls behind protovalidate's rules, a vector fails ([ADR 0012](/decisions/0012-the-language-follows-the-executable/#the-rules)).
- **Not recorded here:** the crate's release date, its maintainers and whether it has been audited. The pull request that pins the exact version states them, as [Adding a library](#adding-a-library) asks, and a crate that is marked experimental or unaudited for a security function is refused (rule R7).

## Still to build

**The CI check against home-made primitives and unlisted libraries** is built with the first code ([#1039](https://github.com/truvity/sluis/issues/1039)); it reads the data file beside this page, `approved-libraries.yaml`. Until then the review of each pull request is the check.
