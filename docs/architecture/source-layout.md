---
title: Source layout
description: Which language each sluis component is written in, the shared kits every language implements, and the layout of the repository tree.
status: target
sidebar:
  order: 4
---

## Languages

**One executable, one language.** Go is the default; Rust is used at the unauthenticated edge, in the trusted base, in the cloud drivers and on the smallest boards. The rules and the reasoning are in [ADR 0012](/decisions/0012-the-language-follows-the-executable/); this table follows its [per-actor table](/decisions/0012-the-language-follows-the-executable/#per-actor-table).

| Component | Language | Why |
|---|---|---|
| `entry` (slim), the Kubernetes edge relay | Rust | The unauthenticated edge |
| `sluis-node`, `sluis-host` | Rust | The trusted base |
| `key-holder` | Go with `piv-go` | The one exception in the trusted base: `piv-go` holds the card exclusively |
| `policy` | Rust | Cedar's engine is the `cedar-policy` crate |
| The `cloud` port drivers (web identity, platform role, GCP and Azure federation) and the AWS-backed drivers (`aws-kms`, `dynamodb`, `sqs`, `s3-compatible`) | Rust | One AWS SDK language |
| `cloud-cloudflare` | Go | Shares the library of the `cloudflare@<company>` integration |
| `session`, `exchange` | Go | The embeddable OpenID Connect provider, the proof verifiers and HPKE |
| `ca` | Go | The X.509 CA and its issuance log |
| `writer`, `witness` | Go | The C2SP log writer and witness |
| Integrations, among them the generic OpenID Connect upstream `oidc@<name>` | Go | The vendor SDKs and the OpenID Connect client |
| Other drivers (`nats-jetstream`, the `postgres` index, witness drivers, `age` export) | Go | The default, and age with post-quantum recipients |
| `signer`, `console` (the actor), `indexer`, `reader`, the local drivers (`embedded` state and its local lock, the spool, the `fs` blob, the `sqlite` index), the rqlite drivers, `ssh-ca`, `quota`, `sluis agent` | Rust | They run on the smallest boards and need no Go-only library; `console` moves to Go if spike S1 shows that Connect for Rust lacks the server streaming it needs |
| The `sluis` CLI, the cert-manager issuer | Go | Not resident on a board |
| The console's single-page application | TypeScript | |

PKCS#11 is used only by the later YubiHSM 2 and Nitrokey drivers, whose language is chosen with them. Every Rust choice is [gated by its spike](/decisions/0012-the-language-follows-the-executable/#the-spikes-are-gates): S1 and S10 for every Rust component, and S3 for `entry` as well. A gate does not stop work: the component is built against its contract meanwhile, and when a spike fails, the fallback for that component is chosen from the candidates in ADR 0012.

Tokens are standard JWS and JWT, so any language verifies them against the published key set. An actor can move between languages because every contract is ConnectRPC and every integration and driver is out of process: the language is chosen per executable, and the contracts do not change.

The command-line tool is one Go `sluis` binary with subcommands for operators and for users, including `sluis key request`, `install` and `status`.

## Shared kits

Parallel implementations of the same small kits, one per language, keep the languages interchangeable. Each is checked by the same conformance suite.

| Kit | What it is |
| --- | ---------- |
| ConnectRPC over Unix sockets | A server and client that read peer credentials (`SO_PEERCRED`) on every call and expose them to the call-graph interceptor |
| Config loader and validator | Loads the layered configuration and validates it against the generated JSON Schema, with strict unknown-field handling |
| CLI conventions | `config check`, `config explain`, `doctor`, and a uniform `--help` |
| Conformance suite | Shared vectors and behavioural tests that every kit and driver must pass, whatever its language |

Configuration validation uses `santhosh-tekuri/jsonschema/v6` in Go, the `jsonschema` crate in Rust and `ajv` in TypeScript, with one shared set of conformance vectors. The schema is generated from the Pkl sources at build time; there is no Pkl at run time.

## The repository tree

```text
proto/          ConnectRPC contracts
schema/         Pkl sources and the generated JSON Schema
kits/
  go/  rust/  ts/  conformance/
actors/<actor>/
drivers/<driver>/
integrations/<integration>/
node/agent/
cli/sluis/
host/sluis-host/
console/
manifest/       permission manifests, one per actor
deploy/
  packages/  helm/  lambda/  iac/
tests/
  installations/  tutorials/
docs/  site/
```

| Directory | Holds |
| --------- | ----- |
| `proto/` | The contracts every other directory implements or calls. A contract change is reviewed here first |
| `schema/` | The Pkl sources that define the configuration shape, and the JSON Schema (draft 2020-12) generated from them. The schema is part of the public API |
| `kits/` | The shared kits above, one directory per language, plus the conformance suite |
| `actors/`, `drivers/`, `integrations/` | One directory per component, matching the layout under `/usr/libexec/sluis/` that the [packages](/architecture/components/#packaging) install |
| `node/agent/` | The node agent (`sluis-node`) |
| `cli/sluis/` | The one `sluis` binary |
| `host/sluis-host/` | The SSH host service ([SSH](/integrations/ssh/)) |
| `console/` | The TypeScript console |
| `manifest/` | The permission manifests, one per actor, which generate the enforcement ([Architecture](/architecture/#the-permission-manifest-is-the-spine)) |
| `deploy/` | Packaging for each artifact: `.deb` and `.rpm` packages, Helm charts, Lambda archives, infrastructure as code |
| `tests/installations/`, `tests/tutorials/` | Integration tests on the four tested installations, and the tutorials as tests |
| `docs/`, `site/` | This documentation and the site that builds it |

One version covers the whole repository. See [Distribution](/distribution/) for what is built from the tree.

## Board OS images live elsewhere

Operating system images for the single-board computers are built in a separate public repository, not here ([#881](https://github.com/truvity/sluis/issues/881)). The supported distributions are on [Packages](/distribution/packages/).

Next: [Architecture](/architecture/) lists the pages, and [Runtimes](/runtimes/) shows where each binary runs.
