---
title: Approved libraries
description: "The cryptography and parser libraries sluis may use in Go, Rust and TypeScript, the ones it refuses, the licence rule, and how a library is added."
status: target
sidebar:
  order: 6
---

sluis writes no code of its own for a cryptographic primitive or an external protocol standard when a vetted library exists ([REQ-SEC-018](/requirements/sec/#REQ-SEC-018)): they come from approved, maintained libraries ([REQ-SEC-008](/requirements/sec/#REQ-SEC-008)). A format of sluis's own is allowed when it has a written specification, length limits and fuzz tests. This page is the list, per language, with the record that needs each capability; a library is approved by the review of the pull request that lists it. The list itself is data, [`docs/reference/approved-libraries.yaml`](https://github.com/truvity/sluis/blob/main/docs/reference/approved-libraries.yaml), so that a CI check can compare it with the dependencies once there is code ([#1039](https://github.com/truvity/sluis/issues/1039)).

The rules behind it are in [ADR 0006](/decisions/0006-keys-and-sealing/#algorithms) and [ADR 0012](/decisions/0012-the-language-follows-the-executable/#the-rules): only the approved algorithms, a nonce from the library and never from the caller, the operating system's random generator only, no library marked experimental or unaudited for a security function, and no FIPS build in 2.0.

## Go

| Library | For | Needed by |
|---|---|---|
| `crypto/...` (standard library) | ECDSA P-384, AES-256-GCM, SHA-2, HKDF, HMAC, X.509, TLS, and `crypto/rand` | [ADR 0006](/decisions/0006-keys-and-sealing/#algorithms) |
| `golang.org/x/crypto/ssh` | OpenSSH keys and certificates in Go components and the CLI | [ADR 0023](/decisions/0023-certificate-authorities/#ssh) |
| `github.com/go-piv/piv-go/v2` | YubiKey PIV in key@ and in its card driver; attestation verification | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table) |
| `github.com/ProtonMail/go-crypto` | OpenPGP packets: the subkey request, the back-signature, detached signatures | [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off) |
| `github.com/santhosh-tekuri/jsonschema/v6` | The generated JSON Schema, applied to a configuration document before it is decoded, and to each audit record by the emitter (`kits/go/audit`) before it is emitted | [ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf), [ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format) |
| `buf.build/go/protovalidate` (protovalidate-go) | The protovalidate rules of every Protobuf message, after decoding: the authority in code; see [protovalidate](#protovalidate) | [ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf) |
| `connectrpc.com/connect`, `google.golang.org/protobuf` | The Connect protocol and Protobuf | [ADR 0002](/decisions/0002-families-of-actors/#contracts) |
| `github.com/go-jose/go-jose/v4` | JWS, JWK and JWT: verifying tokens and client assertions, verifying signed config documents (`kits/go/signedconfig`), reading and writing key sets; never JWE | [ADR 0017](/decisions/0017-identity-and-sign-in/#context) |
| `github.com/go-jose/go-jose/v4/cipher` (the key-wrap function only) | AES key wrap (RFC 3394) of a data key for the key-agreement key of a board's card. Scope: key@ only, AES-KW only; no JWE and no other function of the module in key@ | [ADR 0006](/decisions/0006-keys-and-sealing/#datakeywrap) |
| `github.com/zitadel/oidc/v3` | The OpenID Provider of `session` and `exchange` (`pkg/op`) and the relying party of the `oidc` upstream (`pkg/client/rp`) | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table) |
| `golang.org/x/oauth2` | The OAuth 2.0 client under the relying party of the `oidc` upstream | [ADR 0017](/decisions/0017-identity-and-sign-in/#optional-openid-flows) |
| `golang.org/x/mod/sumdb/note`, `golang.org/x/mod/sumdb/tlog` | C2SP signed notes, and the hashes and tiles of a tiled log, in `writer`, `witness` and the CLI's `audit verify` | [ADR 0029](/decisions/0029-the-audit-log/#tiled-log) |
| `filippo.io/torchwood` | C2SP checkpoints, cosignatures and tiles, and the tile client, in `writer` and `witness`, and the checkpoint and tile code of the CLI's `audit verify` | [ADR 0029](/decisions/0029-the-audit-log/#witnesses) |
| `github.com/transparency-dev/formats` | The reference verifier of C2SP signed-note type 0x02 and the reference checkpoint parser, as the independent oracle of the checkpoint tests. Scope: tests only; linked into no executable | [ADR 0029](/decisions/0029-the-audit-log/#tiled-log) |
| `filippo.io/sunlight` | C2SP `static-ct-api` entries and checkpoints, in the issuance log of `ca` | [ADR 0023](/decisions/0023-certificate-authorities/#issuance-log-and-revocation) |
| `github.com/gowebpki/jcs` | RFC 8785 canonical JSON of the audit records: the order of members, the escapes and the text of numbers; the sluis profile (integers within ±(2^53−1), no floats, depth, UTF-8) is checked before it | [ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format) |
| `go.yaml.in/yaml/v3` | Reading the bootstrap file and the YAML config documents, through the strict profile of [the bootstrap file](/reference/bootstrap-file/#format) | [ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf) |

Go keeps the standard library's defaults: `GOFIPS140` and `fips140` are unset ([ADR 0006](/decisions/0006-keys-and-sealing/#algorithms)).

## Rust

| Library | For | Needed by |
|---|---|---|
| `aws-lc-rs` | AES-256-GCM with `RandomizedNonceKey`, ECDSA P-384 (and P-256 for the audit log key), HKDF, SHA-2, and its random generator | [ADR 0006](/decisions/0006-keys-and-sealing/#algorithms) |
| `rustls` | TLS, with the `aws-lc-rs` provider and no FIPS pin | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#the-rules) |
| `cedar-policy` | Cedar policy in `policy` | [ADR 0007](/decisions/0007-policy-and-sealed-grants/) |
| `jsonschema`, no default features | The generated JSON Schema, applied to a configuration document before it is decoded, and to each audit record by the emitter (`sluis-audit`) before it is emitted | [ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf), [ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format) |
| `buffa`, `buffa-types`, 0.9.2, pinned | The Protobuf runtime of every Rust component, and its well-known types; the kit validates decoded messages by hand until a protovalidate bridge exists; see [protovalidate](#protovalidate) | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table) |
| `connectrpc` | The Connect protocol over Unix sockets (spike S1 passed on 2026-11-01) | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#the-spikes-are-gates) |
| `zeroize` | Wiping secrets from memory | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#context) |
| `jsonwebtoken`, with its `aws_lc_rs` feature | Verifying JWS and JWT, with an explicit algorithm list | [ADR 0017](/decisions/0017-identity-and-sign-in/#context) |
| `signed_note`, `tlog_checkpoint`, `tlog_core`, `tlog_tiles` | C2SP signed notes, checkpoints, RFC 6962 hashes and tiles in `indexer` and `reader`; the verifier of the log key (P-256 for an audit log, P-384 for the issuance log) is a `NoteVerifier` on `aws-lc-rs` | [ADR 0029](/decisions/0029-the-audit-log/#tiled-log) |
| `pgp` (rPGP), 0.21.0, pinned, no default features | OpenPGP packets in `signer`: the detached release signature, with the signing step handed to key@; see [OpenPGP in Rust](#openpgp-in-rust) | [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-signature) |
| `saphyr-parser` | Reading the bootstrap file and the YAML config documents, through the strict profile of [the bootstrap file](/reference/bootstrap-file/#format) | [ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf) |
| `hyper`, `hyper-util` | The HTTP/1.1 and HTTP/2 server of `entry` and of the Rust kit: parsing the request head and framing the body | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#the-rules) |
| `serde_json` | JSON of the audit records, in the emitter and in `indexer`, and the error bodies of `entry` | [ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format) |
| `serde_json_canonicalizer` | RFC 8785 canonical JSON of the audit records, in the emitter: the order of members, the escapes and the text of numbers; the sluis profile is checked before it | [ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format) |
| `ssh-key` | OpenSSH keys and certificates in `ssh-ca`, with a signing key that signs through the `keys` port; chosen with a condition, see [below](#rust-openssh-certificates) | [ADR 0023](/decisions/0023-certificate-authorities/#ssh) |
| The AWS SDK for Rust | AWS calls from the AWS-backed drivers; its SigV4 and checksums are outside any FIPS module | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#the-rules) |

## TypeScript

| Library | For | Needed by |
|---|---|---|
| `ajv`, its draft 2020-12 build | Configuration against the generated JSON Schema | [ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf) |
| WebCrypto and WebAuthn, the browser's | Cryptography and passkeys in the console's single-page application | [ADR 0017](/decisions/0017-identity-and-sign-in/#passkeys) |
| `@connectrpc/connect` (connect-es) | The Connect client of the audit reader's API | [ADR 0028](/decisions/0028-audit-pieces/#the-reader) |
| `jose` | Verifying tokens in the console's single-page application and in the verification demo | [ADR 0017](/decisions/0017-identity-and-sign-in/#context) |

## Tools that run in CI

These run in CI and on a workstation, and are linked into no sluis artifact, so the [licence rule](#licences) does not reach them. Each is pinned by version and digest, and installed below `.cache/` by a `just` recipe, never globally.

| Tool | For | Pin |
|---|---|---|
| `ocsf-schema-compiler` 1.1.1 (Python, Apache-2.0, no dependencies), `ocsf-toolkit` v0.9.0 (Go, Apache-2.0) and the OCSF schema 1.9.0 (Apache-2.0) | `just ocsf-check`: the example record of every audit action through the OCSF toolkit, against the pinned OCSF schema ([ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format), REQ-AUDIT-100) | `tools/ocsf/requirements.txt` (pip `--require-hashes`), `tools/ocsf/pins.env` (the schema commit and the toolkit sha256 for amd64 and arm64). The owner allowed the pinned virtualenv on 2026-11-07. The toolkit is pre-1.0, so it gates CI and never the writer. |

## Refused

| Library | Why | Decided by |
|---|---|---|
| The `yubikey` crate | Its own notice says it is unaudited and experimental (rule R7) | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#roads-not-taken) |
| `ykcs11` through `cryptoki`, for key@ | It resets the card for every client when a second one appears, and keeps a PIN copy that cannot be wiped | [ADR 0012](/decisions/0012-the-language-follows-the-executable/#roads-not-taken) |
| `sequoia-openpgp` (Rust) | LGPL-2.0-or-later: copyleft in a library that would be linked into `signer`, which the [licence rule](#licences) refuses. `sq` and `sqv` stay allowed as external tools in CI | [Licences](#licences), 2026-11-06 |
| `gpg` on a node | An approved library writes the OpenPGP packets and the card signs; the `gpg` tool is never used, and none runs on a board | [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off) |
| A Go plugin or a WebAssembly module in an actor | Plugins run out of process, always | [ADR 0003](/decisions/0003-units-transports-and-fusion/#consequences) |

## Licences

Only permissive licences (MIT, BSD, Apache-2.0, and also ISC, Zlib, Unicode-3.0, the LLVM exception to Apache-2.0 and MIT-0, as decided below) are allowed for anything that is linked into a sluis artifact ([REQ-SUPPLY-045](/requirements/supply/#REQ-SUPPLY-045), decided 2026-11-06). Copyleft is allowed only for external tools, such as `gpgv` and `sq` in CI: they run beside sluis, are neither linked into a binary nor shipped in a package, and so their licence does not reach a sluis artifact.

- **Scope.** Every Go module, Rust crate and TypeScript package that a sluis binary or the console links, direct or indirect, in the builds CI makes (the Go build with and without the tag `sluis_card`), and the C libraries a driver links. The documentation site is not an artifact; it is outside the rule.
- **Dual licences.** An `OR` expression counts under its permissive choice: `r-efi` is `MIT OR Apache-2.0 OR LGPL-2.1-or-later` and is taken as MIT. An `AND` expression needs every part to be permissive.
- **The list.** MIT, BSD-2-Clause, BSD-3-Clause and Apache-2.0 are the first decision. The tree of 2026-11-06 also needs four more licences, and on 2026-11-06 the owner added them to the allowed licences: **ISC, Zlib, Unicode-3.0 and `Apache-2.0 WITH LLVM-exception`**. On 2026-11-07 the owner added a fifth, **MIT-0** (MIT No Attribution, which asks for less than MIT): the approved `jsonschema` crate, which the audit emitter of the Rust actors uses to apply the record schemas, depends on `borrow-or-share` (through `fluent-uri`), and that crate is `MIT-0`. Any other licence needs a decision of the same kind.

### What the tree holds, measured 2026-11-06

Source: `cargo metadata --locked` over `Cargo.lock` (281 packages: 21 workspace crates, all `MIT`, and 260 external), the `LICENSE` file of every module that `go list -m` resolves for `go.mod` (the tree of `origin/main` at `a01e20863`), and the Debian copyright file of `libpcsclite1`. No dependency is under a copyleft licence as its licence field or licence text states it.

| Ecosystem | Licence expression, as the package states it | External packages | Allowed |
|---|---|---|---|
| Rust | `MIT OR Apache-2.0` (also written `Apache-2.0 OR MIT`, `MIT/Apache-2.0`) | 170 | yes |
| Rust | `MIT` | 50 | yes |
| Rust | `Apache-2.0` | 15 | yes |
| Rust | `Unlicense OR MIT` | 10 | yes, by the MIT choice |
| Rust | `Apache-2.0 WITH LLVM-exception OR MIT OR Apache-2.0` (`linux-raw-sys`, `rustix`, `wasi`), `CC0-1.0 OR MIT-0 OR Apache-2.0` (`dunce`), `Zlib OR MIT OR Apache-2.0` (`tinyvec`), `MIT OR Apache-2.0 OR LGPL-2.1-or-later` (`r-efi`) | 6 | yes, by the MIT or Apache choice; `r-efi` is taken as MIT |
| Rust | `Zlib` (`foldhash` twice, `zlib-rs`) | 3 | yes (Zlib) |
| Rust | `(MIT OR Apache-2.0) AND Unicode-3.0` (`unicode-ident`, `unicode-normalization`) | 2 | yes (Unicode-3.0) |
| Rust | `ISC AND (Apache-2.0 OR ISC)` (`aws-lc-rs`), `ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND ...` (`aws-lc-sys`), `ISC` (`untrusted`) | 3 | yes (ISC) |
| Rust | `Apache-2.0 WITH LLVM-exception` (`ar_archive_writer`) | 1 | yes (LLVM exception) |
| Go | Apache-2.0: `connectrpc.com/connect`, `go-jose/v4`, `go-piv/piv-go/v2` | 3 | yes |
| Go | BSD-3-Clause: `golang.org/x/crypto`, `golang.org/x/mod`, `google.golang.org/protobuf`, and `google/go-cmp` (tests only) | 4 | yes |
| Go | MIT and Apache-2.0, per file, as its `NOTICE` says: `go.yaml.in/yaml/v3` | 1 | yes |
| C (cgo, the card driver only) | BSD-3-Clause: `libpcsclite`; the GPL-3+ files of the Debian package are `src/spy/*` and `debian/*`, which the driver does not link | 1 | yes |

Nine Rust crates are under the four licences that the owner added: the cryptographic backend (`aws-lc-rs`, `aws-lc-sys`, `untrusted`), the hash and compression crates (`foldhash`, `zlib-rs`), the Unicode tables (`unicode-ident`, `unicode-normalization`) and a build helper (`ar_archive_writer`). With them the tree has no licence outside the allowed ones. Unlicense, CC0-1.0, MIT-0 and BSD-1-Clause appear only as one choice of an `OR` and are not needed. The documentation site is outside the rule, and the console, which will have a TypeScript tree, does not exist yet.

### The check

The requirement stays `planned`: the check runs for Rust and not yet for Go. The Rust step (1 below) runs in the `advisories` job of the CI workflow as `just check-licenses`; the Go lister (2) and the test (3) are the follow-up on [#1039](https://github.com/truvity/sluis/issues/1039).

1. **Rust: `cargo deny check licenses`** with a `deny.toml` that holds the allow list (it runs as `just check-licenses`). Measured 2026-11-06 with cargo-deny 0.20.2 offline over this `Cargo.lock`: 0.4 seconds. The first four licences alone fail with nine errors (the crates above); the four added on 2026-11-06 make it pass (`licenses ok`), and they are the `allow` list of `deny.toml`. A probe project that depends on `sequoia-openpgp` 2.4.2 fails on `LGPL-2.0-or-later`, so the check does catch the case the rule is for.
2. **Go: a lister over `go.mod`,** run with and without the tag `sluis_card`. `github.com/google/go-licenses/v2` (`@latest`, 2026-11-06) does not work: on Go 1.27.3 it stops with "Package ... does not have module info" for every standard-library package. The alternative is about fifty lines of our own in `tools/`: `go list -deps -json`, the `LICENSE` file of each module, and a classifier. The classifier is a parser of a format, so it would use a library, not a regular expression.
3. **A test of each:** a fixture with a copyleft crate and module, which the check must fail on.

## Adding a library

A dependency that provides a cryptographic primitive, or parses a protocol or a format that crosses a trust boundary, must be on this list under the language of the executable that links it. To add one:

1. Open a pull request that adds an entry to the data file and a row here: the name, what it is for, and why this library and not one already listed.
2. Say whether it is maintained (releases in the last year, a security policy), whether it has had an audit, and whether it is marked experimental; an experimental library is refused for a security function.
3. Add a security note, as for any change that touches keys or signing ([Review](/contributing/workflow/#review)).
4. Name its licence, and the licences of its dependencies that a build links. It must pass the [licence rule](#licences); a copyleft library is refused whatever its quality.

The lockfiles pin versions. A choice names the version it was evaluated at and the date, so that the next reader can judge how far the library has moved ([principle 9](/principles/#9-measure-before-deciding-and-date-the-measurement)); a security fix can set a floor. The floor is enforced, not only written here: the `advisories` job of CI ([REQ-SUPPLY-030](/requirements/supply/#REQ-SUPPLY-030)) runs `govulncheck`, `cargo audit` and `osv-scanner` over the lock files and fails on a known advisory that affects a function sluis calls, so a lock file that falls below a floor set by an advisory turns CI red. The job cannot see a floor that is set by a choice and no advisory, and a vulnerability in code that sluis never calls (the JWE half of `go-jose`, say) does not fail it; the floor on this page still holds for both. An exception goes into `tools/advisories/ignore.yaml` with a reason and an expiry date, and never into this page.

## Choices made on 2026-11-01

Each row is a question that stood open until then. The versions are the latest releases on 2026-11-01; the release date follows each version. Where a library is refused, the reason is in the last column.

| Question | Chosen | Evaluated at | Not chosen, and why |
|---|---|---|---|
| [JOSE](#jose) in Go | `go-jose/v4` | v4.1.7, 2026-10-30; floor v4.1.7 | `lestrrat-go/jwx` v3.4.0 (2026-10-23): a second JOSE library beside the one the provider already needs. `golang-jwt/jwt` v5.3.1 (2026-01-28): JWT only, no JWK or key sets |
| [JOSE](#jose) in Rust and TypeScript | `jsonwebtoken` (Rust), `jose` (TypeScript) | 11.1.0, 2026-09-16; 6.2.14, 2026-10-29 | `josekit` 0.10.3 (2025-05-20): OpenSSL, not `aws-lc-rs`, and not released for 17 months |
| [OpenID Connect provider](#openid-connect-provider) | `zitadel/oidc/v3` | v3.51.16, 2026-10-15; floor v3.47.0 | `ory/fosite` v0.49.0 (2024-12-12): its own OAuth 2.0 and no release for ten months. Dex: a server with its own storage, not a library. `coreos/go-oidc` v3.21.0 (2026-09-01): relying party only |
| [C2SP libraries](#c2sp-transparency-logs) | `x/mod` `note` and `tlog`, `torchwood`, `sunlight` in Go; `signed_note`, `tlog_checkpoint`, `tlog_core` and `tlog_tiles` in Rust | v0.42.0, 2026-10-09; v0.10.0, 2026-09-24; v0.10.2, 2026-10-26; 0.3.0 (tag v0.3.0), 2026-10-15 | Tessera v1.0.4 (2026-07-16) as the writer's engine: it sequences and publishes checkpoints itself |
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
- **Three conditions before `pkg/op` is imported by `session` or `exchange`.** v1 uses this library and had to patch three behaviours in October 2026 (the security release v1.79.2 and the log change after it). sluis adopts the provider package only with a test in CI for each, and a patch carried or offered upstream where the test fails:
  1. **The audience of an ID token is the client alone.** The library puts the resource of the request into the audience; [REQ-TOKEN-004](/requirements/token/#REQ-TOKEN-004) and [REQ-TOKEN-005](/requirements/token/#REQ-TOKEN-005) are the proof.
  2. **A public client that presents a secret is refused with `invalid_client`.** The library ignores the secret without a word; [REQ-CLIENT-001](/requirements/client/#REQ-CLIENT-001) is the proof.
  3. **The log line of a refused authorization request carries the error code, a closed reason, the client id and the path, and never the state or raw caller text.** The library logs the request's state and the caller's own description; [REQ-OBS-019](/requirements/obs/#REQ-OBS-019) to [REQ-OBS-022](/requirements/obs/#REQ-OBS-022) are the proof.
- **Not chosen.** `ory/fosite`: an OAuth 2.0 framework with its own OAuth implementation; its latest release is v0.49.0 of 2024-12-12, though the repository was pushed on 2025-11-20. Dex: a complete server with its own storage and connectors, which sluis would have to embed with its state model. `coreos/go-oidc`: verifies ID tokens as a relying party and is not a provider; sluis would write the flow, `state` and `nonce` handling itself.

### C2SP transparency logs

- **Go, for `writer`, `witness` and the issuance log of `ca`.** `golang.org/x/mod/sumdb/note` and `tlog` (module v0.42.0, 2026-10-09) are the Go team's signed-note and tile-hash code; the CLI's `audit verify` uses them too, to check a log the way the writer made it. Their signer and verifier are interfaces, so the log key signs through the `keys` port. `filippo.io/torchwood` (v0.10.0, 2026-09-24, BSD-3-Clause, before 1.0) adds the C2SP checkpoint, cosignature and tile functions and a tile client on top of them; the `writer` and the CLI's `audit verify` take the checkpoint body, the tile paths and the tile entries from it, and keep only the type 0x02 key and the adapter that has key@ sign (REQ-SEC-018, decided 2026-11-06). Neither library has the ECDSA signature type 0x02, so its key, key ID and verifier are a few lines of sluis code, and `github.com/transparency-dev/formats` (v0.1.1, 2026-06-02, Apache-2.0, before 1.0), the reference that the standard names for that type, checks every checkpoint in the tests of `writer` and the CLI (tests only; it is in no executable). Our own format is the `checkpoints/<size>` history, specified on [Checkpoint history](/reference/checkpoint-history/). `filippo.io/sunlight` (v0.10.2, 2026-10-26, ISC) holds the `static-ct-api` entry and checkpoint code for `ca`'s issuance log.
- **Rust, for `indexer` and `reader`.** `signed_note`, `tlog_checkpoint` and `tlog_core` from Cloudflare's `azul` repository (BSD-3-Clause), pinned to revision `662c80c05a5969a2c5eb4e75a48e3cf50dba5790`, the tag `v0.3.0` of 2026-10-15 (version 0.3.0). The release on crates.io is 0.2.0 of 2025-04-18, older than a year, and has a `Verifier` trait where 0.3.0 has `NoteVerifier`, so the tag is the better of the two; it is not published on crates.io, which is why the dependency is a pinned revision. `indexer` links them: `signed_note` splits and verifies the note (size, control characters and signature-count limits included), `tlog_checkpoint` reads the checkpoint text, and `tlog_core` has the RFC 6962 leaf and node hashes and serves as the oracle of the tests of the compact range. `signed_note` ships only an Ed25519 verifier, with a `NoteVerifier` trait for others: the P-256 verifier of the log key (signature type 0x02) is a few lines on `aws-lc-rs`, and the cosignatures of witnesses are Ed25519 or ML-DSA-44 ([ADR 0029](/decisions/0029-the-audit-log/#witnesses)). What `indexer` still holds is the compact range of the tree (`merkle.rs`), because no library keeps a tree as one hash per set bit of its size; the Go writer's fixtures, the Certificate Transparency reference tree and `tlog_core::tree_hash` check it. `tlog_tiles` is not linked yet. **The git pin has no RustSec advisory coverage and no automatic bump**, since the crates are not on crates.io: re-check the pin on each azul release.
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
| [Protovalidate](#protovalidate) | `buf.build/go/protovalidate` in Go; hand-written checks in the Rust kit, on `buffa` messages | `connectrpc` 0.9.1 generates only `buffa` types, which `prost-protovalidate` cannot validate (2026-11-04) | `prost-protovalidate` 0.6.x: it validates `prost` messages only, and a second Protobuf runtime in the tree would serve one crate |

### Protovalidate

- **Protobuf with protovalidate is the authority in code.** The generated JSON Schema is a derived subset for editors and `helm lint`; cross-field rules, duration and timestamp ranges, exact byte lengths and the strictness of `uri` are enforced by protovalidate only ([ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf)). Every binary validates a document against the embedded JSON Schema before it decodes, and the decoded message against its protovalidate rules.
- **The options file is vendored.** `buf/validate/validate.proto` of protovalidate (Apache-2.0) is in `third_party/protovalidate`, unchanged, with the registry commit it came from, so that no build reaches an outside service. The messages import it for their rules, and the generated Go of it is `gen/go/buf/validate`.
- **Go uses protovalidate-go,** the library that Buf publishes. It is the reference: the rules mean what it says they mean.
- **Rust uses `buffa` messages and hand-written checks** ([ADR 0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table)). The protovalidate annotations stay in the `.proto` files as the documentation of the rules, and the kit checks a decoded message by hand against them. The shared conformance vectors of rule R9 run the same documents through both kits, so a rule that Go enforces and the Rust checks miss fails a vector. A validation bridge replaces the hand-written checks later.
- **Not recorded here:** the release date of a crate, its maintainers and whether it has been audited. The pull request that pins the exact version states them, as [Adding a library](#adding-a-library) asks, and a crate that is marked experimental or unaudited for a security function is refused (rule R7).

## Choices made on 2026-11-06

| Question | Chosen | Evaluated at | Not chosen, and why |
|---|---|---|---|
| [OpenPGP in Rust](#openpgp-in-rust) | `pgp` (rPGP), pinned, `default-features = false` | 0.21.0, 2026-10-03 | `sequoia-openpgp` 2.4.2 (2026-10-14): LGPL-2.0-or-later, refused by the [licence rule](#licences). RNP: C++ behind a C API, so cgo or a `-sys` crate with `unsafe` |

### OpenPGP in Rust

- **Verdict: `pgp` passes, and is approved for `signer`.** Decided on 2026-11-06 on the condition that it supports an external signer; the check below found that it does, for ECDSA P-384 and for EdDSA. No Go helper is needed for the signature, and `go-crypto` stays the Go library for the parts that are in Go.
- **The interface.** The trait `pgp::types::SigningKey` has `sign(&self, key_pw, hash: HashAlgorithm, data: &[u8]) -> Result<SignatureBytes>` and `hash_alg()`; `SignatureConfig::v4(typ, pub_alg, hash_alg)` has public `hashed_subpackets` and `unhashed_subpackets` fields; `SignatureConfig::sign(self, &impl SigningKey, &Password, impl Read)` hashes the content, the hashed fields and the trailer, and calls `sign` with the **final digest**. The library never needs a private key: a type that holds the public key packet and a socket to key@ implements `SigningKey`, and returns `SignatureBytes::Mpis` with R and S (ECDSA) or the two 32-byte halves (EdDSA legacy). The crate's own test `tests/hsm-test.rs` (a fake HSM) and its `adapter::EcdsaSigner` do the same for a local key.
- **Measured 2026-11-06, `pgp` 0.21.0, `p384` 0.13.1, `ed25519-dalek` 2.2.0, Rust 1.99.1, `gpgv` 2.4.8.** A prototype outside the repository gave key@ a Unix socket pair, with the private key in the thread at the other end and none in the type that `pgp` sees. Three tests passed.
  - **ECDSA P-384, SHA-384:** the callback received a 48-byte digest, twice (one self-certification and one detached signature); the remote answered with an ASN.1 DER signature, as key@ does, and the adapter turned it into R and S. `gpgv` printed `Good signature` for the detached signature against the exported public key, and `BAD signature` after one byte was appended to the data. `gpg --list-packets` shows exactly the packet that [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-signature) fixes: version 4, class `0x00`, algorithm 19, digest algorithm 9, two hashed subpackets (2 and 33) and one unhashed subpacket (16).
  - **EdDSA (legacy, algorithm 22), SHA-256:** the same, with a 32-byte digest and a 64-byte answer; `gpgv` says `Good signature`.
  - **Signature input to key@:** [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-signature) says key@ receives the signature input (the content, the hashed fields, the trailer) and parses it before it signs, while the library's callback receives only the digest. The input is reachable from the public API: `SignatureConfig::hash_signature_data` writes the hashed fields into a hasher (a recording `DynDigest` captures the bytes) and `trailer(len)` returns the trailer. The prototype sent that input, 64 bytes for a 23-byte file, to the remote, and the signing type asserted that SHA-384 of it equals the digest `pgp` computed, so the two cannot diverge. `gpgv` accepted the result.
- **What to watch.**
  - **The crate is 0.x.** Releases came on 2025-09-25, 2025-11-16, 2026-02-02, 2026-06-23 and 2026-10-03, and a 0.x release may break the API. The version is pinned, and the prototype becomes the test that a bump must pass.
  - **Default features off, and the licence.** The default feature `bzip2` links `libbz2-rs-sys` (licence `bzip2-1.0.6`, permissive and not on the list) and nothing in a detached signature needs compression. The prototype builds and passes with `default-features = false`. `pgp` alone then has 152 crates (154 with the defaults); `cargo deny` with the allow list of [Licences](#licences) accepts all of them, and the first four licences alone refuse two (`Zlib` and `Unicode-3.0`), both already in the tree. `cargo check --target x86_64-unknown-linux-musl` passes; the `aarch64` musl target was not checked.
  - **`sign` is synchronous.** A call to key@ inside it blocks the thread; `signer` runs it on a blocking thread.
  - **Audit state.** `docs/SECURITY_STATUS.md` of 0.21.0 names an audit by Radically Open Security (2024-12, two advisories, fixed), an analysis by ETH researchers (2024-03) and an audit of 2019; its `SECURITY.md` takes private reports, with 90 days to fix. It does not mark the crate experimental. It lists the Marvin attack on the `rsa` crate as known, which does not touch ECDSA or EdDSA. SHA-1 is handled by `sha1-checked`; sluis writes only SHA-384.
  - **`sq` was not run:** it is not installed here. `gpgv` is the only external verifier of this check; the CI check of [REQ-SEC-018](/requirements/sec/#REQ-SEC-018) should add `sqv`.
- **The Go fallback, measured and not needed.** `github.com/ProtonMail/go-crypto` v1.5.2 (2026-09-25, BSD-3-Clause, with `cloudflare/circl`, BSD-3-Clause) does take a custom `crypto.Signer`, with limits. For ECDSA, `Signature.Sign` calls `PrivateKey.(crypto.Signer).Sign(rand, digest, hash)` and reads an ASN.1 signature; EdDSA needs its own concrete `*eddsa.PrivateKey` and takes no custom signer. `packet.NewSignerPrivateKey` type-switches on concrete key types and panics on any other, so the key is built by setting the exported field `PrivateKey.PrivateKey` to the signer, and the public key has to come from a parsed key packet because its curve type is internal. A prototype did this for P-384, and `gpgv` said `Good signature`. The subpackets do not match [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-signature): the issuer key id is written in the **hashed** area, the creation time is critical by default, and a random-salt notation is added unless `NonDeterministicSignaturesViaNotation` is switched off. If `pgp` fails a later check, the Go helper is therefore not a drop-in: it needs a patch or a small own packet writer for the signature, which [REQ-SEC-018](/requirements/sec/#REQ-SEC-018) would have to allow as a spec'd and fuzzed exception.

## Still to build

**The CI check against home-made primitives and unlisted libraries** is built with the first code ([#1039](https://github.com/truvity/sluis/issues/1039)); it reads the data file beside this page, `approved-libraries.yaml`. Until then the review of each pull request is the check.

**The licence check** ([REQ-SUPPLY-045](/requirements/supply/#REQ-SUPPLY-045)) is the second job of the same lint; see [the check](#the-check).
