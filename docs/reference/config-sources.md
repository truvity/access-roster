---
title: Configuration sources
description: "The config-source port in detail: the sources list, the composition rule with its refusals and vectors, the signed document, and what a driver returns."
status: target
sidebar:
  order: 9
---

The install file can name more sources of declared configuration than itself: a second file, a Lambda layer, a mounted ConfigMap, AWS AppConfig. This page fixes how they are written, put together and trusted. The reasons, the principles and the roads not taken are [ADR 0057](/decisions/0057-configuration-sources-are-a-port-sources-own-disjoint-paths-authority-is-signed-and-a-failing-source-keeps-the-version-in-force/); the layers, origins and reload they sit inside are [ADR 0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/) and [Configuration](/concepts/configuration/).

Schema v1 of the [install file](/reference/install-file/) has no `sources` key: the first working version reads one file ([principle 8](/principles/#8-nothing-without-a-consumer)). The key joins the schema with the pull request that reads it, for the lambda installation ([#1157](https://github.com/truvity/sluis/issues/1157)). Until then the rules below are the design that pull request is built and tested against.

## The sources list

`sources` is an optional top-level key of the install file: an ordered list, one entry per source.

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | A lower-case kebab-case name, 1 to 32 characters, unique in the list. It appears in errors, in `sluis config explain` and in audit records |
| `driver` | yes | `file` or `appconfig` |
| `owns` | yes | One or more JSON Pointers (RFC 6901) to the subtrees this source sets, for example `/policy` or `/boundaries/dev/clients` |
| `verify` | `appconfig`; `file` defaults to `host` | `host`, `signed` or `service`, below |
| `keys` | `signed` | A mapping from a publisher `kid` to the path of its public key, a JWK for an EC P-384 key |
| `path` | `file` | The file, relative to the directory of the install file |
| `application`, `environment`, `profile` | `appconfig` | The AppConfig application, environment and configuration profile, by name or id |

```yaml
sources:
  - name: authority
    driver: appconfig
    owns: [/policy, /clients, /boundaries/dev/clients]
    verify: signed
    keys: { release-2026: publishers/release-2026.jwk }
    application: sluis
    environment: production
    profile: authority
  - name: local-extra
    driver: file
    owns: [/upstreams]
    path: sources/upstreams.yaml
```

- **The install file is the base.** It is read first, from a file, and is not an entry of the list. It owns every path that no source owns.
- **The base keys cannot be owned:** `$schema`, `runtime`, `environment`, `nodes`, `drivers`, `sources` and `trust`. A pointer to one of them, or to a path that contains one, is refused.
- **`verify`.** `host` trusts the platform's access rules over the file, as for the install file itself. `signed` requires a signed document ([below](#the-signed-document)). `service` trusts the identity and change history of the configuration service, and is allowed only for paths that hold no authority.
- **Which paths may carry which `verify`.** A path that holds a field marked `x-sluis-authority` needs `host` or `signed`. A field marked `x-sluis-defaults`, the per-customer defaults of [ADR 0031](/decisions/0031-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/#customer-identity-installations), is accepted only from a `service` source, so never from git. Operator-set, learned and issued kinds are accepted from no source.

## Composition

Composition builds the install layer: the base and each source's document give one document, and the defaults, runtime and environment overrides of [Layers](/concepts/configuration/#layers) apply to it afterwards. The rule has no precedence:

1. Every source owns the subtrees its `owns` names, and the base owns the rest.
2. A source's document is a mapping that holds exactly its owned subtrees, written under their full paths: a source that owns `/policy` has the document `policy: {...}`.
3. The merged document is the union of those subtrees. No key is set by two owners, so nothing overrides anything.
4. A sequence is one value. It is never joined to another and never extended. `null` is one value, not a deletion.
5. The order of the list is the order of reading, of errors and of the audit record. The merged document is the same in whatever order the sources are listed.

### Refusals

`sluis config check` makes the refusals that need no document (the first four rows, a `verify` that is not allowed and a driver the installation does not offer) before any source is read. The loader makes the rest when it reads, naming the source and the path and never the value.

| Refused | Because |
|---|---|
| Two sources with one name | A name must identify one source in an error |
| Two sources whose pointers are equal, or one inside the other | Two owners of one key |
| A pointer to a base key, or empty, or `/` | A source cannot choose the list of sources or the roots |
| A pointer through a sequence (`/a/0`) | A sequence is one value; there is no element ownership |
| The base holds a key under a path a source owns, even with the same value | Two owners of one key; a copy in the base would hide a source that fails |
| A document with a key outside the paths its source owns | A publisher writes only its own scope ([ADR 0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#origins)) |
| A document without one of its owned paths | Absent and empty would mean the same, and the schema default would answer silently |
| A document that the strict YAML profile refuses | The profile of the [install file](/reference/install-file/#format) holds for every source |
| A document whose owned subtree the schema refuses | Each subtree is checked against the schema at its pointer before merging |
| A merged document that the schema or a cross-key check refuses | Checked once, after composition, as `sluis config check` checks a single file |
| A source whose `verify` is not allowed for its paths | See above |

### Vectors

The vectors are a document set beside the profile vectors of the [install file](/reference/install-file/#format), in the conformance kit, and the Go and Rust loaders must give the same verdict on each. This is the design of the set, not a measurement: the loaders do not exist yet, and the figure of the strict loader (every vector of spike S7, [#945](https://github.com/truvity/sluis/issues/945)) says nothing about these rows. Each row adds files to the vector directory; "base" is the install file.

| Base and sources | Verdict |
|---|---|
| Base sets `front`; source `a` owns `/policy` and holds `policy: {...}` | Read: the union |
| The same, with the two sources listed in the other order | Read: the same merged document and the same digest |
| Source `a` owns `/policy`; source `b` owns `/policy` | Refused by `check`: equal pointers |
| Source `a` owns `/boundaries`; source `b` owns `/boundaries/dev/clients` | Refused by `check`: one pointer inside the other |
| Source `a` owns `/policy`; the base also has `policy` | Refused: the base holds an owned key, with a different value and with the same value |
| Source `a` owns `/policy`; its document also has `clients` | Refused: a key outside its paths |
| Source `a` owns `/policy` and `/clients`; its document has only `policy` | Refused: an owned path is missing |
| Source `a` owns `/drivers`, or `/sources`, or `/trust/root_list` | Refused by `check`: a base key |
| Source `a` owns `/boundaries/dev/clients/0` | Refused by `check`: a pointer through a sequence |
| Source `a` owns `/policy`, and its `policy` holds a `files` sequence; the base also lists files under `/actors` | Read: each sequence belongs to its owner and none is joined |
| Source `a` has `policy: ~` for an owned path | Read as `null`; the schema then decides (a required object refuses it) |
| A source document with a duplicate key, an anchor or a merge key | Refused by the strict profile, before any merge |
| A source document with a tab, a directive or two documents | Refused by the strict profile |
| Each document valid; an upstream in one names an `org` that no other document declares | Refused: the merged check, naming the field and both sources |
| A `signed` source whose document is unsigned, signed by another key, or signed with `alg` other than ES384 | Refused before the payload is parsed |
| A `signed` source whose header has `crit`, `jku`, `x5u` or `jwk` | Refused |
| A `signed` document with a `seq` lower than the one in force | Refused on reload |
| A `signed` document with a `seq` lower than the newest published, read by a process that is starting | Read: nothing is in force to compare with; the audit record carries the digest and `seq` |
| A `service` source that owns a field marked `x-sluis-authority` | Refused by `check` |
| A `file` or `signed` source that owns a field marked `x-sluis-defaults` | Refused by `check` |
| An `appconfig` source on an installation that has no AWS | Refused by `check`: the driver is not offered |
| The install file is missing, unreadable or invalid at start | Refused: the process does not start |
| A `file` source whose file is missing, unreadable or invalid at start | Refused: the process does not start |
| An `appconfig` source that cannot be reached at start | Refused: the process does not start |
| A reload whose snapshot changes a `restart` path and a `live` path | Refused as a whole: the version in force stays, the `live` change is not applied |
| A reload whose snapshot changes only `live` paths | Read: the whole composition is swapped |
| A source that owns a `restart` path | Read at start; `check` warns, and a reload that changes the path is refused |

## The signed document

A `signed` source holds a compact JWS (RFC 7515, RFC 7518) whose payload is the document, byte for byte as the reviewed file.

- **Header.** `alg` is `ES384`. `kid` names a key of the source's `keys`. `seq` is a positive integer that the publishing pipeline increases with every document. Any other `alg`, and a `crit`, `jku`, `x5u` or `jwk` header, are refused.
- **Order.** The signature is verified over the received bytes first; only then is the payload parsed. A document that fails verification is reported as refused and is never read.
- **Digest.** The audit record of a start or reload carries the SHA-384 of the payload and the `seq` for each source, and the SHA-384 of the merged document. A reviewer matches a source's digest to `sha384sum` of the file at the commit. The signature proves who published these bytes; that the commit was reviewed is the branch protection of the repository.
- **Freshness.** `seq` stops a running process from accepting an older document than the one in force. It protects a running process only: a process that starts takes the latest signed document the source gives it, whatever its `seq`. A service that serves an older signed version at a cold start is not detected by the process; the digest and `seq` in the audit record are how it is found afterwards, by comparing them with the head of the reviewed branch. A floor (`min_seq`) and an expiry (`not_after`) were weighed and not taken ([ADR 0057](/decisions/0057-configuration-sources-are-a-port-sources-own-disjoint-paths-authority-is-signed-and-a-failing-source-keeps-the-version-in-force/#roads-not-taken)). The residual is stated in [ADR 0057](/decisions/0057-configuration-sources-are-a-port-sources-own-disjoint-paths-authority-is-signed-and-a-failing-source-keeps-the-version-in-force/#freshness-at-a-cold-start).
- **Size.** The payload is encoded in base64url, a third larger than the file. A service has a size limit of its own; the figure for AppConfig hosted configurations (2 MiB) is UNVERIFIED and is confirmed with the driver ([#1157](https://github.com/truvity/sluis/issues/1157)).

## What a driver returns

`read` returns the bytes of one document and a version label, and never parses them. `watch` is the way the driver reports that a newer version exists.

| Driver | `watch` | How it reads | Needs |
|---|---|---|---|
| `file` | `notify`; `none` for a Lambda layer | Opens the path; the loader watches its directory, so a replaced file or the swap of a mounted ConfigMap is seen | Nothing |
| `appconfig` | `poll` | Starts a session on the profile, then asks for the latest configuration at the interval the service returns | AWS credentials from the `cloud` port; the AppConfig data API |

AppConfig facts, READ 2026-11-02 from the AWS API reference of `GetLatestConfiguration`: each call returns a token for the next call, a token is valid for one call and for up to 24 hours, the configuration is empty when the caller already has the latest version, and the answer carries the interval to wait before the next poll. A request may set a required minimum poll interval. The driver uses the data API and not the AppConfig agent ([Serverless](/runtimes/serverless/)).

## Start, reload and failure

- **At start, every source stops the start when it is unavailable or broken, and so does the base.** The install file and each source, `file` or `appconfig`, must be reachable, readable, signed where `verify` says so and valid. A file that is missing, unreadable or invalid, a service that cannot be reached, an unsigned or invalid document: each is an error that names the source, and the process does not start. There is no cached copy, no signed last-known-good copy in a layer, no default in place of a missing document and no fallback to a weaker source ([ADR 0057](/decisions/0057-configuration-sources-are-a-port-sources-own-disjoint-paths-authority-is-signed-and-a-failing-source-keeps-the-version-in-force/#failure)).
- **At reload**, all sources are read again, composed and validated, and the result replaces the version in force as a whole, or not at all. An unreachable source is retried with a back-off and reported, and the version in force stays. A refused document is audited with its digest.
- **A reload changes `live` paths only.** Every path is `live` or `restart` ([the classes](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#reload-classes), [by area](/reference/install-file/#which-keys-reload)). A snapshot that changes a `restart` path is refused as a whole: the version in force stays, no `live` change in it is applied, and the audit record names the digest and the paths, never their values. A restart applies it. `sluis config check --against` lists these paths before the document is published.
- **Live configuration on Lambda comes from `appconfig`.** A layer is a file that cannot change under a running function (`watch` is `none`), so the install file in the layer is `restart`. Policy and clients change without a new function version when an `appconfig` source owns them, for example `owns: [/policy, /clients, /boundaries/dev/clients]` with `verify: signed`; each function polls at the first invocation after the interval the service returned. The `file` driver on bare-metal, in Compose and on Kubernetes signals by notify, so a replaced file or a swapped ConfigMap reloads without a poll.
- **`sluis config explain`** names the source of each field in its layer column, for example `install   source authority`, and `check` lists each source with its verdict.
