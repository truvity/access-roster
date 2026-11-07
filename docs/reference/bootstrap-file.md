---
title: Bootstrap file
description: "The bootstrap file of store@: where it lives, its strict YAML profile, every key, the checks on it, why a change needs a restart, and the example for local."
status: target
sidebar:
  order: 3
---

The bootstrap file is the one local file store@ reads at start. It says where things are: the boundary, one driver socket for each of store@'s four ports, and the public keys of the publishers that sign config. Everything else is a signed config document ([Signed config](/reference/signed-config/)). The reasons and the roads not taken are in [0005](/decisions/0005-the-store/#the-bootstrap-file); this page fixes the shape of the file, schema v1.

Schema v1 has only the keys that code of the first working version reads ([principle 8](/principles/#8-nothing-without-a-consumer)). A key joins the schema with the pull request that reads it. Adding a key or a value is compatible; removing or changing one is a new schema version beside v1 ([0013](/decisions/0013-release-train-packaging-and-distribution/#compatibility-between-releases)).

## Where it lives

- **`--bootstrap FILE` points store@ at the file.** The platform provides it: a file of root's in `/etc/sluis/bootstrap.d/` on a board or in the local installation (below), a mounted ConfigMap in a pod, a file in the function's package or layer on Lambda. The registries render its fragments, and IaC places them ([0015](/decisions/0015-evolution-and-compatibility/)).
- **A host has one file for each boundary, in `/etc/sluis/bootstrap.d/<boundary>.yaml`.** The name is the boundary's ([Names](#schema-and-validation)). The file holds one `boundary`, so a second boundary on the host is a second file, and the systemd generator reads the directory and creates one set of instances for each file ([Bare-metal](/runtimes/bare-metal/#what-runs-where)). On Kubernetes and Lambda the platform mounts or packages the one file of the boundary the pod or function serves.
- **store@ reads all of it; key@ decodes the `publishers` block and nothing else, but checks the whole file against the schema first,** as store@ does, and so does the card driver of key@ (below, [Schema and validation](#schema-and-validation)). key@ verifies the `KeyPlan` itself, under these keys, instead of taking it from store@ ([0006](/decisions/0006-keys-and-sealing/#who-may-receive-a-wrap)). The block holds public keys only, so the file stays readable by root's group and others, and key@ gets it read-only (`--bootstrap`). No other actor reads it, and it is not a kind ([0004](/decisions/0004-the-data-model/#what-is-not-data)).
- **store@ refuses a file that another uid can write.** The owner must be root or store@'s own uid, and the mode must not allow a write by group or others.
- **It holds no credential.** The engine login and the access to the secret source are platform-provided: a systemd credential, an IAM role or a service account ([0004](/decisions/0004-the-data-model/#what-is-not-data)). A driver's own settings (the rqlite address, a DynamoDB table, an AppConfig profile, a parameter prefix, the directory of the `file` driver) belong to the driver and its unit, not to this file, because only the owner opens a driver ([0005](/decisions/0005-the-store/#drivers)).
- **It holds no telemetry setting.** Telemetry is the standard `OTEL_*` environment variables ([0016](/decisions/0016-telemetry/)).

## Format

- **YAML that is plain JSON data, read by one strict profile.** Go and Rust read YAML with different parsers ([Approved libraries](/reference/approved-libraries/#yaml-reader)), and a YAML parser as it comes does not give the same document in both: `010` is the number 8 in one and 10 in another, `yes` is a string or a boolean, an alias is expanded or kept. The profile removes the choice, and the readers give the same verdict on every document below. The profile holds for the bootstrap file and for every config document that is YAML ([Signed config](/reference/signed-config/#the-payload)):
  1. **One document.** A second document is refused.
  2. **No anchors, aliases, merge keys (`<<`), tags or duplicate keys; both readers refuse each.** Every tag is refused: `!!str`, `!foo` and the non-specific tag `!` alike, so `a: ! 12` is refused and not read as the number 12 (a node tree of the Go reader does not show `!`, so it is found in the text). A merge key is refused whatever its quoting.
  3. **Every mapping key is a string,** written plain or quoted; a key that is a mapping or a sequence is refused, and so is an empty plain key (`: 1`).
  4. **A plain scalar is `null` (`null`, `~` or empty), a boolean (`true`, `false`) or a number that matches the JSON grammar, and any other plain scalar is a string.** So `yes`, `y`, `010`, `0x1F`, `+1`, `.inf`, `1_000` and `2026-11-01` are strings, and a field that wants a number refuses them with a type error. A quoted or block scalar is always a string.
  5. **No directive.** A `%YAML`, `%TAG` or any other `%` line before the content is refused.
  6. **No tab character.** A tab anywhere is refused, so write `\t` inside a double-quoted string.
  7. **Flow collections (`[...]` and `{...}`) nest at most 64 levels deep.** The Rust reader stops at about 250 levels and the Go reader at 10,000, so the profile sets the limit.
  8. **An error names the path or the line and column, never the value.** The reader's own messages are not shown, because some print the source line. A syntax error names its kind only, because the two readers place it differently; every other error of the profile has the same line and column in both.
- **The profile's vectors** (measured 2026-11-01 and again 2026-11-02 with `go.yaml.in/yaml/v3` v3.0.6 and `saphyr-parser` 0.3.3; the conformance kit starts from them):

  | Document | Verdict |
  |---|---|
  | `a: 1`, `b: [x, y]`, `c: {d: true}` | read: `{"a":1,"b":["x","y"],"c":{"d":true}}` |
  | `a: 1` twice | refused: duplicate key |
  | `a: &x [1,2]` and `b: *x` | refused: anchor |
  | a key `<<` | refused: merge key |
  | `a: !foo bar`, `a: !!str 12`, `a: ! 12` | refused: tag |
  | `a: yes`, `b: 0o17`, `c: 010`, `d: y` | read, all four strings |
  | a byte order mark at the start | read; one anywhere else is refused: byte order mark |
  | `a: Null`, `b: NULL`, `c: True`, `d: TRUE`, `e: False`, `f: FALSE` | read, all six strings: only `null`, `~`, an empty value, `true` and `false` are null and booleans (a YAML 1.1 reader reads the others as null and booleans, and the Go reader of key@ is held to this) |
  | `a: ~`, `c: 0x1F`, `d:` | read: `null`, the string `"0x1F"`, `null` |
  | `a: 1.5e3`, `b: .inf`, `c: +1`, `d: -0`, `e: 1_000` | read: the numbers `1.5e3` and `-0`, the strings `".inf"`, `"+1"` and `"1_000"` |
  | `a: "12"`, `b: 'true'`, `c: "null"` | read: three strings |
  | `1: a` | read: the key is the string `"1"` |
  | `a: 2026-11-01` | read: the string `"2026-11-01"` |
  | two documents separated by `---` | refused: more than one document |
  | `? [a, b]` as a key | refused: key is not a scalar |
  | `a: [1,` | refused: syntax error |
  | `%YAML 1.2` before the content | refused: directive |
  | `a:`, a tab, then `1` | refused: tab |
  | `: 1` | refused: empty key |
  | 65 levels of `[` | refused: too deep |

- **A hash is written as a quoted string.** A pin made of hex digits could read as a number under rule 4 in the rare case that it holds no letter but one `e`; the quotes remove the doubt.

### Durations

- **A duration is written with a unit:** one whole number followed by one unit, `s`, `m`, `h` or `d`, such as `30s`, `900s`, `15m`, `12h` or `30d`, in this file and in every config document ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf)). There are no fractions and no compounds such as `1h30m`. The loader converts it to a Protobuf `Duration`, and the generated JSON Schema checks the pattern `^[0-9]+(s|m|h|d)$`. Write the unit that reads best: `12h`, not `43200s`. An ISO 8601 string is refused.
- **Bounds are not in the format.** The range of a duration, such as the one hour of a token lifetime, is a protovalidate rule and is checked at load, not by the JSON Schema ([Schema and validation](#schema-and-validation)).
- **The vectors** follow the pattern, and the shared conformance vectors confirm them in Go and Rust once the kits exist:

  | Value | Verdict |
  |---|---|
  | `30s`, `900s`, `15m`, `12h`, `30d` | read |
  | `30`, `30 s`, `30S`, `15M` | refused: not a duration string |
  | `PT30S`, `P1D` | refused: ISO 8601 |
  | `1.5s`, `1h30m`, `2w` | refused: one whole number and one unit of `s`, `m`, `h` or `d` |
  | `-1s` | refused: not a duration string |

## Schema and validation

- **The schema is the JSON Schema generated from the Protobuf message of the file,** draft 2020-12, with the `$id` `https://sluis.id/schema/bootstrap/v1/bootstrap.schema.json`. The message is `Bootstrap` in [`proto/sluis/config/v2alpha1/bootstrap.proto`](https://github.com/truvity/sluis/blob/main/proto/sluis/config/v2alpha1/bootstrap.proto), its rules are protovalidate rules, and `tools/gen/configschema` makes the schema from them. The schema is committed as the golden file [`schema/bootstrap/v1/bootstrap.schema.json`](https://github.com/truvity/sluis/blob/main/schema/bootstrap/v1/bootstrap.schema.json), which CI compares with what the message makes (`just config-schema-check`) ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf)). `unevaluatedProperties: false` is on every object, so an unknown key is an error that names its path, and an error never shows a value.
- **The order of validation is fixed.** The reader applies the strict profile, the binary validates the document against the embedded JSON Schema, decodes it, and then checks the decoded document against the rules of the message. The binaries that read the file are store@, key@ and the card driver of key@; each embeds the schema and applies it to the whole file before it decodes anything, so a file that one refuses at the schema, all refuse. In the first working version the decoder of store@ is hand-written and checks the rules of the message by hand ([Approved libraries](/reference/approved-libraries/#protovalidate)), and it is never looser than the schema. The JSON Schema is a derived subset: cross-field rules, duration ranges, exact byte lengths and the strictness of a URI are enforced by protovalidate only, so a file that the schema accepts can still be refused at load ([#1177](https://github.com/truvity/sluis/issues/1177), measured 2026-11-03).
- **An error names a path and a rule, and never a value.** The path is made of the keys of this page and the positions of list items (`publishers[0].kid`), and a key that the page does not list is shown as `<key>`, because it is the file's own text. When a file has several faults the error names the first by path, then by rule, the same one in every binary. The rules, in the words of the error:

  | Failure of the schema | The error says |
  |---|---|
  | a key the schema requires is missing | `required` |
  | a key the schema does not list, at any level | `unknown key` |
  | a value of another type | `must be a string`, `a mapping`, `a list`, `a boolean` or `a number` |
  | a string that does not match the pattern of its key | `not in the form the schema requires` |
  | a string shorter or longer than the schema allows | `too short`, `too long` |
  | a list with too few or too many items | `too few items`, `too many items` |
  | a value other than the one the schema fixes (`$schema`) | `not the value the schema requires` |
  | a key the schema retired | `retired key` |

- **The vectors** are [`kits/conformance/config/schema-vectors.json`](https://github.com/truvity/sluis/blob/main/kits/conformance/config/schema-vectors.json): one document of the example for local, changed by one fault at a time, with the verdict and the words. The Go package `kits/go/configschema` and the Rust crate `sluis-schema` run the same file, so the two libraries that apply the schema cannot differ on a document of it ([REQ-DATA-038](/requirements/data/#REQ-DATA-038)).
- **`$schema`** may name the `$id` above, for editors. A file that names another `$id` is refused.
- **The identifier never changes, and CI judges it.** `just config-schema-compat` compares the committed schemas with the `schema/` directory of the newest release tag `v2.*`: every schema is still there, at the same path and with the same `$id`, and accepts whatever the release's accepted. A key may be added and a bound may be looser; a key that goes, a type or a pattern that changes, a key that becomes required and a bound that is tighter each fail the check, and the way out is a new version under a new path, beside the old one ([0013](/decisions/0013-release-train-packaging-and-distribution/#compatibility-between-releases)). The judge knows the keywords the generator writes and fails on any other. With no release tag yet the recipe prints `NOT RUN` and passes, as `audit-compat` does: a check that cannot run is reported as not run ([REQ-DATA-040](/requirements/data/#REQ-DATA-040)).
- **Names** of a boundary and of a `kid` are lower-case kebab-case, 1 to 32 characters, starting with a letter: a boundary name appears in unit names, sockets and addresses (`store@<boundary>`).

## Keys

| Key | Required | Read by | What it says |
|---|---|---|---|
| `$schema` | no | every binary that reads it | The schema `$id`, for editors |
| `boundary` | yes | store@ | The boundary this store@ serves. Every address it handles begins with it ([0004](/decisions/0004-the-data-model/#the-address)) |
| `start_timeout` | no | store@ | How long store@ waits at start for each driver to pass its `check` and for the config source to answer, a duration. Default `30s`. When it passes, store@ does not start ([0005](/decisions/0005-the-store/#a-cold-start-refuses-on-any-failure)) |
| `config_source` | yes | store@ | The destination of the config class ([below](#the-four-destinations)) |
| `secret_source` | yes | store@ | The destination of the secret class |
| `durable` | yes | store@ | The destination of the durable class |
| `temp` | yes | store@ | The destination of the temp class |
| `publishers` | yes | store@ | The pinned public keys that sign config ([below](#publishers)) |

### The four destinations

A destination names the driver behind one of store@'s four ports and the Unix socket where store@ reaches it ([0005](/decisions/0005-the-store/#the-four-ports-downward)). The durable and temp destinations may name one engine, and they stay two keys because the classes differ in backup and in time to live.

| Field | Required | Meaning |
|---|---|---|
| `driver` | yes | The driver of the port. The values are those of the installation ([below](#drivers)) |
| `socket` | yes | The absolute path of the driver's Unix socket, under `/run/sluis/store/<boundary>/` on a host. On Kubernetes it is the path on the `emptyDir` that store@ and its driver share |

#### Drivers

Each port has one driver until a second real installation needs another ([0005](/decisions/0005-the-store/#drivers)). The values the first working version accepts are the local installation's and the boards'; the drivers of the other tested installations are added with them ([0011](/decisions/0011-runtimes-and-installations/#installations)).

| Key | Values in v1 | Added with |
|---|---|---|
| `config_source` | `file` | `appconfig`, with the serverless installation |
| `secret_source` | `credential` | `ssm`, with the serverless and Kubernetes installations |
| `durable`, `temp` | `rqlite` | `dynamodb`, with the serverless and Kubernetes installations |

`sluis config check --runtime serverless` refuses a driver that does not fit the runtime, such as `rqlite` ([0005](/decisions/0005-the-store/#drivers)). An in-memory engine exists for tests only and is not a value of this file in a release.

### Publishers

A publisher key is a public key that may sign config documents. The list is the trust anchor of config: it needs no signed document to verify the first one, so config cannot choose its own publisher ([0005](/decisions/0005-the-store/#the-bootstrap-file)).

| Field | Required | Meaning |
|---|---|---|
| `kid` | yes | The key's name, unique in the list. A document's signature names its key by this `kid` ([Signed config](/reference/signed-config/#the-document)) |
| `public_key` | yes | The key as a PEM `PUBLIC KEY` (SubjectPublicKeyInfo), an EC P-384 key |
| `spki_sha384` | yes | The pin: the SHA-384 of the DER SubjectPublicKeyInfo, in lower-case hex. It is shown beside the key so that a reviewer compares it with the pin the publisher announced, and the check refuses a pin that does not match the key |
| `co_signs` | no | A list of kind names. A document of one of these kinds must carry a valid signature of this key as well as one of a publisher key that has no `co_signs`. It is how a regulated party's policy needs the party's signature as well as the publisher's ([0007](/decisions/0007-policy-and-sealed-grants/#a-regulated-partys-policy)) |

- **A change of a publisher key is a restart of store@ and of key@.** To rotate one, add the new key beside the old, restart, publish under the new key, remove the old key, and restart again. A key is never added by a config document.
- **A key that is not in the list verifies nothing.** store@ refuses a document that carries a signature of any other key, and a document that no listed publisher key has signed ([Signed config](/reference/signed-config/#verifying-a-document)).

## What `sluis config check` checks

Beyond the schema and protovalidate, `sluis config check` runs these on the file ([Commands](/reference/cli/#sluis-config-check-and-explain)). store@ makes the same checks at start, except the one on the drivers below, and does not start on a failure.

- no two destinations share a socket path;
- every `public_key` parses as an EC P-384 key, and its `spki_sha384` matches it;
- every `kid` is unique, and every kind in a `co_signs` is a config kind of the kind registry ([Kinds](/reference/kinds/));
- the file's mode allows no write by group or others, as in [Where it lives](#where-it-lives).

`sluis config check` also checks every `driver` against the runtime that the caller names with `--runtime` ([The installation](/reference/cli/#sluis-config-check-and-explain)). store@ does not know the runtime and does not make this check at start. That is the safe direction: the check is stricter than store@, so it can refuse a set that store@ would load, and it cannot pass a set that store@ refuses ([REQ-DATA-090](/requirements/data/#REQ-DATA-090), [0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table)). The node count joins when a driver first depends on it.

`sluis config check` does not check the file's owner. It often runs on a CI runner or a workstation, where the file belongs to whoever checked it out, so the owner is a check of the installation, not of the file ([#1419](https://github.com/truvity/sluis/issues/1419)). store@ still refuses, at start, a file whose owner is neither root nor its own uid.

## A change needs a restart

The bootstrap file is the only setting whose change needs a restart ([0005](/decisions/0005-the-store/#configuration-loading)). It names the processes store@ talks to and the keys that anchor trust, and neither can change under a running store. Every other change, a new policy or a new client, is a signed config document and reloads as a whole snapshot ([Signed config](/reference/signed-config/#the-snapshot)).

## The example for local

The local installation ships an example bootstrap file, [`tests/installations/local/bootstrap.yaml`](https://github.com/truvity/sluis/blob/main/tests/installations/local/bootstrap.yaml). It serves the boundary `dev` with one rqlite node behind both engine ports ([0011](/decisions/0011-runtimes-and-installations/#the-local-installation)) and pins the test key of the vectors on the signed config page. This copy is checked against that file (`just check-examples`).

<!-- example: tests/installations/local/bootstrap.yaml -->
```yaml
# The bootstrap file of store@ on the local installation (ADR 0011): the boundary `dev`, a
# directory of signed config documents, and one rqlite node behind both engine ports.
# Schema v1: https://sluis.id/reference/bootstrap-file/
$schema: https://sluis.id/schema/bootstrap/v1/bootstrap.schema.json
boundary: dev
start_timeout: 30s

config_source: { driver: file, socket: /run/sluis/store/dev/config-source.sock }
secret_source: { driver: credential, socket: /run/sluis/store/dev/secret-source.sock }
durable: { driver: rqlite, socket: /run/sluis/store/dev/durable.sock }
temp: { driver: rqlite, socket: /run/sluis/store/dev/temp.sock }

# The pin of the key that signs the local config documents. The key is the test key of the
# vectors on the signed config page; it guards nothing.
publishers:
  - kid: publisher-1
    public_key: |
      -----BEGIN PUBLIC KEY-----
      MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEEUKd6CE58PyZQlFf8Lr7OWUalh4lNPvr
      rA7mNmdNt8fOYSPky3w9E9KZmFNWOE+0TJJXt1i3+P5C4nYax8bkHrnS8/lGRv18
      eizHflv/jwhvtlX6XUZQsM7aMGQp7ZCQ
      -----END PUBLIC KEY-----
    spki_sha384: "d4c36e17a4d13238c8131db63e69bc2a70bd8797357fd39fea5b0d7e9e5d1919163152a3292201de5362906ad9afcbb4"
```
