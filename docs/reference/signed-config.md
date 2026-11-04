---
title: Signed config
description: "The signed config document: JWS signatures, the payload, the growing sequence, the snapshot rules, the config source drivers, and test vectors with a key pair."
status: target
sidebar:
  order: 8
---

Config reaches store@ as signed config documents: one per config kind, signed by a publisher, read from a config source and loaded as a whole ([0005](/decisions/0005-the-store/#configuration-loading)). This page fixes the format of a document, the order in which store@ checks it, the rule for the sequence number, what a config source driver returns, and the vectors every implementation must pass. The reasons and the roads not taken are in [0005](/decisions/0005-the-store/); the keys that anchor trust are in the [bootstrap file](/reference/bootstrap-file/#publishers).

## The document

A signed config document is a JWS in the general JSON serialisation (RFC 7515, section 7.2) with these members:

| Member | Meaning |
|---|---|
| `payload` | The bytes of the reviewed file, in base64url without padding |
| `signatures` | A list of one or more signatures. Each has `protected` (the protected header in base64url) and `signature` (base64url) |

The protected header of every signature is a JSON object with exactly these members:

| Header | Value |
|---|---|
| `alg` | `ES384`, and nothing else |
| `kid` | The `kid` of a publisher key in the [bootstrap file](/reference/bootstrap-file/#publishers) |
| `seq` | A positive integer, below 2^53, that the publishing pipeline increases with every document of the kind. Every signature of one document carries the same value |
| `kind` | The registry name of the config kind, such as `KeyPlan` ([Kinds](/reference/kinds/)). The verifier requires it to equal the kind it asked for, so a document signed for one kind cannot be served as another's |

- **The signature input** is `ASCII(protected) "." payload`, as in RFC 7515. The signature is ECDSA with P-384 and SHA-384, 96 bytes, `r` then `s`, 48 bytes each (RFC 7518, section 3.4).
- **One document holds one config kind,** for one boundary, with all the items of the kind. The driver is asked for it by the kind's kebab-case name (`front-host`): the `file` driver reads `front-host.jws` from its directory, which on a host and in the local installation is `/etc/sluis/config/<boundary>/`, and the `appconfig` driver reads the hosted configuration of the profile with that name.
- **A document may carry several signatures.** A regulated party's policy carries the publisher's and the party's: the pipeline adds the party's signature over the same payload and the same `seq`, and store@ requires both ([0007](/decisions/0007-policy-and-sealed-grants/#a-regulated-partys-policy)). Which kinds need a second signature is the `co_signs` list of the party's key in the bootstrap file, so that config cannot waive it ([0005](/decisions/0005-the-store/#signed-config-documents)). Neither party can change the document alone.
- **Only the protected header is read.** A signature with an unprotected `header` member is refused, and so is the compact serialisation and the flattened JSON serialisation ([0005](/decisions/0005-the-store/#signed-config-documents) states the signature rules).
- **The signature proves who published these bytes.** That the commit was reviewed is the branch protection of the repository ([0005](/decisions/0005-the-store/#signed-config-documents)).

## The payload

- **The payload is the file as it was reviewed, byte for byte.** A reviewer matches it to `sha384sum` of the file at the commit.
- **The format depends on the kind.** A policy kind (`Policy`, `RegulatedPartyPolicy`) is Cedar text. Every other kind is YAML or JSON, read by the [strict profile](/reference/bootstrap-file/#format) into the kind's Protobuf message, with durations written with a unit ([Durations](/reference/bootstrap-file/#durations)). The record states the format ([0005](/decisions/0005-the-store/#signed-config-documents)).
- **The payload of a YAML or JSON kind is a mapping from item id to item** (decided 2026-11-04). The key is the item's id and the value is the item, read into the kind's message. A **singleton kind** has one item, with the id `default`: `Boundary`, `KeyPlan`, `TokenLifetime`, `AuditLog`, `AuditCatalogue`, `ExchangeTrust` and `Policy`. A **keyed kind** uses the name of each item as its id, for example `workforce` for an `Upstream` and `sluis-cli` for an `InstallationClient`.
- **Two kinds are not mappings.** `GrantVocabulary` is the exception: its payload is the vocabulary file itself, which `policy` parses, so it is one document and not a map. `Policy` is Cedar text, one file, and that file is its one item `default`; its grammar and schema are checked by `policy`.
- **The message is the schema** ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf)). store@ validates the payload against the generated JSON Schema, decodes it, and validates the message with protovalidate. An unknown key is an error that names its path, a retired field in a signed document is refused, and an error never shows a value.
- **A document that is large is still one document.** The payload is a third larger in base64url than the file. **A signed document is at most 3 MiB** (2 MiB of file, a third more in base64url, and the signatures): store@ refuses a larger one at step 1, and the Go verifier, with the message bound of the clients, refuses to buffer more, because the reader that verifies for itself reads from a store@ that it does not trust. A config service has a size limit of its own; the figure for AWS AppConfig hosted configurations (2 MiB) is UNVERIFIED and is confirmed with the driver ([#1157](https://github.com/truvity/sluis/issues/1157)).

## Verifying a document

store@ takes these steps in this order and stops at the first failure. Nothing before step 5 reads the payload.

1. **Structure.** The document is a JSON object in the general serialisation, with a `payload` and at least one signature, and no other member.
2. **Headers.** Each protected header is a JSON object with `alg` `ES384`, a `kid`, a `seq` and a `kind`, and no other member. The `kind` must be the kind the verifier asked for. A `crit`, `jku`, `x5u`, `x5c` or `jwk` header is refused, and so is any other algorithm, `none` included. All signatures carry one `seq`. Every part that is base64url (the protected header, the payload, the signature) holds the characters `A-Z a-z 0-9 - _` and nothing else: a line feed, a space or a padding `=` is refused, and so is a last character that carries bits the bytes do not.
3. **Keys.** Each `kid` names a key in the bootstrap file, and no `kid` is used twice.
4. **Signatures.** Every signature verifies over the bytes as they were received. The document needs a signature of at least one publisher key (one without `co_signs`), and of every key whose `co_signs` names the document's kind. A signature that does not verify, or a key that is not in the list, refuses the document.
5. **The sequence number** ([below](#the-sequence-number)).
6. **The payload.** It is parsed under the strict profile or the Cedar grammar, then validated against the schema and with protovalidate.

A failure names the document by its kind, never the value. A document that is refused is never read.

**A second verifier checks the same steps in Go.** A caller that must not rely on store@ for what a document says reads the signed bytes through [`GetSignedConfig`](/reference/store-api/#getsignedconfig) and takes steps 1 to 5 itself (`kits/go/signedconfig`). key@ does so for the `KeyPlan` and the `Boundary`, under the `publishers` block of its own copy of the bootstrap file, so a compromised store@ cannot choose who receives a data key ([0006](/decisions/0006-keys-and-sealing/#who-may-receive-a-wrap)). The two verifiers are one contract and not shared code, and the [vectors](#test-vectors) hold them to it.

## The sequence number

- **A running store takes only a growing sequence.** For a kind, a document with a higher `seq` than the one in force replaces it. A document with the same `seq` and the same digest changes nothing. A document with the same `seq` and another digest, or with a lower `seq`, is refused: two documents must not share a number, and an older one must not come back.
- **A store that starts takes the latest validly signed document the source gives it,** whatever its `seq` (decided 2026-11-02). It has nothing in force to compare with, and nothing is persisted between starts: no high-water mark, no `min_seq` floor and no expiry in the header ([0005](/decisions/0005-the-store/#freshness-at-a-cold-start)).
- **The audit fact of every start and reload** names, for each document, its kind, its `seq` and the SHA-384 of its payload ([0030](/decisions/0030-audit-records-and-the-usage-stream/)). A monitor compares them with the head of the reviewed branch and sees a lag. The residual, if a source serves an older signed document at a cold start, is stated once in [0005](/decisions/0005-the-store/#freshness-at-a-cold-start).

## The snapshot

store@ loads the documents of its boundary as one set ([0005](/decisions/0005-the-store/#the-snapshot)):

1. **Read every document** of the boundary from the config source, one for each config kind the boundary declares ([0005](/decisions/0005-the-store/#the-snapshot)). A declared kind with no document is a failure; there is no default and no empty stand-in in its place. A document for a kind that is not declared is refused ([0005](/decisions/0005-the-store/#the-snapshot)). Planned: store@ cannot detect an undeclared document yet, because the config-source contract has no call that lists the documents of a source, so for now such a document is never read.
2. **Verify each one** as above.
3. **Validate the set.** Each document is checked against its kind's schema; then the checks that span kinds and layers run: links resolve, the config bounds sit inside the built-in bounds, a template that a link names exists, and every grant name is in the vocabulary ([Policy](/reference/policy/#the-grant-vocabulary)). An error names the document and the path.
4. **Swap atomically.** The snapshot replaces the one in force, and each changed kind is delivered to its watchers.

- **A cold start refuses on any failure.** A source that is unreachable, a document that is unsigned, badly signed, malformed or invalid, and a set that fails validation each stop the start. There is no cached copy, no default and no fallback to a weaker source.
- **A failed reload keeps the snapshot in force** and raises an alarm. The new set is all or nothing: the valid part of a changed set is never applied. A refusal is reported once per refused digest, not at every poll ([0005](/decisions/0005-the-store/#a-failed-reload)).
- **An installation-wide document** has the same content in every boundary's config source, and store@ reads only its own boundary's ([0008](/decisions/0008-boundaries-and-tenants/#installation-wide-settings)).
- **`sluis config check` runs step 6 and the validation of the set offline,** as CI does before a document is published, and `sluis config explain` shows the effective value of a setting with its provenance ([Commands](/reference/cli/#sluis-config-check-and-explain)).

## What a config source driver returns

`Read` returns the bytes of one document and a version label, and never parses them; the contract is on [Store API](/reference/store-api/#the-source-contract). The driver reports a newer version in one of three ways.

| Driver | Signal | How it reads | Needs |
|---|---|---|---|
| `file` | `notify`; `none` for a Lambda layer | Opens the path; the driver watches its directory, so a replaced file or the swap of a mounted ConfigMap is seen | Nothing |
| `appconfig` | `poll` | Starts a session on the profile, then asks for the latest configuration at the interval the service returns | AWS credentials of the driver's role; the AppConfig data API |

AppConfig facts, READ 2026-11-02 from the AWS API reference of `GetLatestConfiguration`: each call returns a token for the next call, a token is valid for one call and for up to 24 hours, the configuration is empty when the caller already has the latest version, and the answer carries the interval to wait before the next poll. A request may set a required minimum poll interval. On Lambda the poll happens at an invocation once the interval has passed. A Lambda layer cannot change under a running function, so a new layer is a new function version ([Serverless](/runtimes/serverless/)).

## Declarations

A declaration is a signed document in the same format that is not config: an operator's act that one actor takes once, and not a state that store@ loads. There is one kind, `KeyRevocationDeclaration`, with which an operator revokes keys ([0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#the-declaration)).

- **The format, the header and steps 1 to 4 are a config document's.** The header has `alg`, `kid`, `seq` and `kind`, the signature is a publisher key's of the bootstrap file, and the `co_signs` rules apply. The `kind` names the declaration, which is not a kind of the registry, so store@ refuses it as config and a config document is never taken as a declaration (`VerifyDeclaration` in `kits/go/signedconfig`).
- **The sequence admits a retry and nothing older.** key@ takes a declaration with a `seq` above the highest it took, and keeps that `seq` and the digest of the payload in a mark of its own state directory, `keyrevocation.mark`. The same `seq` with the same payload is a retry of the last declaration, which completes it; the same `seq` with another payload, and a lower one, are refused.
- **The payload is YAML under the strict profile,** read into the message `sluis.key.v2alpha1.KeyRevocationDeclaration`: the members `boundary`, `kids` and `reason`, and `allow_unknown` when it is needed. `boundary` is the boundary the declaration is for; `kids` lists 1 to 64 RFC 7638 thumbprints, each once; `reason` is `compromise`, `suspicion`, `lost-board` or `drill`; `allow_unknown: true` revokes keys that key@ does not know. `sluis key revoke` writes it:

  ```yaml
  boundary: dev
  kids:
    - NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
  reason: compromise
  ```

- **key@ refuses a declaration that does not verify (`declaration`), an old `seq` or another payload under the last one (`seq`), a payload that is not one (`schema`, with the path), another boundary (`other-boundary`) and, without `allow_unknown`, a key it does not know (`unknown-kid`, with the path of the key).** It knows a signing key it holds, a token key that `SigningRing` lists for any node, and a key that a `KeyCertificate` of a signing purpose certifies. A refused declaration writes nothing and does not move the mark. A declaration that a store@ failure stopped half way is refused as `partial` (unavailable), with the keys in the detail, and the same declaration completes it.

## Test vectors

The vectors use two test key pairs. Their private halves were discarded after signing, so the keys guard nothing. The bootstrap file that pins the first one is the [local example](/reference/bootstrap-file/#the-example-for-local).

| Key | `kid` | `spki_sha384` | `co_signs` |
|---|---|---|---|
| Publisher | `publisher-1` | `d4c36e17a4d13238c8131db63e69bc2a70bd8797357fd39fea5b0d7e9e5d1919163152a3292201de5362906ad9afcbb4` | none |
| Regulated party | `party-1` | `788ce45e1127152dd8ca7bb5d2f2a1bcd9fc208d1bcffd629672c57224827d626b7d863891238bfd67c969e079a6469f` | the kind of the vectors |

```text
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEEUKd6CE58PyZQlFf8Lr7OWUalh4lNPvr
rA7mNmdNt8fOYSPky3w9E9KZmFNWOE+0TJJXt1i3+P5C4nYax8bkHrnS8/lGRv18
eizHflv/jwhvtlX6XUZQsM7aMGQp7ZCQ
-----END PUBLIC KEY-----
```

```text
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAENcY8rxK8EKeYUMn0cewM5s+NePDm4Ud/
sHupp7zMuXn59VOyZLHsa/gkMqTwfoXh1TuHkYKdDLGSmWGf5YhED3sVqqfD7cqU
gRKwViO6TrYXCCq+TZVFl0XZTamJNr0E
-----END PUBLIC KEY-----
```

**Vector 1** is signed by the publisher alone, with `seq` 1. Its payload is `vector: 1` and a line feed (10 bytes), and the SHA-384 of the payload is `956168af938823b9fd7adf5d32a50101eb661ae94b14a6575470b29e27f4f7ac666fd14466d508eb475fa99036276db0`.

```json
{
  "payload": "dmVjdG9yOiAxCg",
  "signatures": [
    {
      "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6InB1Ymxpc2hlci0xIiwic2VxIjoxLCJraW5kIjoiQm91bmRhcnkifQ",
      "signature": "XZnPZpoRaLG7Ngq0DsY62EkyOh6gKstlbxkZjpHw90MqDNzXYMxxmhAjk5mhCuAskOqDWa6hCZQApDAo34HOSL98hFkKsOCT_r2Hm6qRiOKJ2Ilu5bkQhed16aPDF5oO"
    }
  ]
}
```

**Vector 2** is signed by the publisher and by the party, with `seq` 2. Its payload is `vector: 2` and a line feed (10 bytes), and the SHA-384 of the payload is `a9a502900b44f260cc6330a43a76b53f6ddb40acb16c7ae9569afeef3080481827219faa7effa42a336265c73b39032e`.

```json
{
  "payload": "dmVjdG9yOiAyCg",
  "signatures": [
    {
      "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6InB1Ymxpc2hlci0xIiwic2VxIjoyLCJraW5kIjoiQm91bmRhcnkifQ",
      "signature": "pyn38__B7njhEtDvE1CMAXlKnr0-oeuhkaIxPbZjmksasy823KZftzegAljIRfDWcIJ6W_g4sjDLqlnt8DbVvrfluvPEfniyagd9Pu9gFBT8yHdv3tTHq_r8yJ9DoUsG"
    },
    {
      "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6InBhcnR5LTEiLCJzZXEiOjIsImtpbmQiOiJCb3VuZGFyeSJ9",
      "signature": "cVFQNr-RN24LgIQM75z46PlvpXuq5d4c4NZ8HVK4WynFqz5hS6-FWvBEdaiNda-8pe8Y_oB6IQAa7XLaZya93FMbyIzcQDT8kwsE9NeLgZXyaTlKlkc-9i3Ke8zDq6PA"
    }
  ]
}
```

The vectors are committed as data in [`tests/testdata/signed-config/vectors.json`](https://github.com/truvity/sluis/blob/main/tests/testdata/signed-config/vectors.json), with the two vectors above, about forty refused variants and the sequence cases. store@ (Rust) and `kits/go/signedconfig` (Go) run the same file and must give the same verdict, step for step. [`keyplan-payloads.json`](https://github.com/truvity/sluis/blob/main/tests/testdata/signed-config/keyplan-payloads.json) and [`boundary-payloads.json`](https://github.com/truvity/sluis/blob/main/tests/testdata/signed-config/boundary-payloads.json) do the same for the payloads of a `KeyPlan` and a `Boundary`, which key@ reads from the bytes it verifies.

The payload of a vector is a stand-in: the signature layer does not look into it. Both vectors name the kind `Boundary`, and the page's keys were made on 2026-11-04 for the header that names a kind. Both vectors verify (checked 2026-11-04 with the Go verifier and the Rust verifier of sluis, which are the two implementations this page binds). The verdicts every implementation, Go and Rust, must give, with the bootstrap file listing both keys and the kind of the vectors under the party's `co_signs`:

| Case | Verdict |
|---|---|
| Vector 2, nothing in force | Read: `seq` 2, both signatures verify |
| Vector 1 with the party's `co_signs` naming its kind | Refused at step 4: the party's signature is missing |
| Vector 1 where the kind has no `co_signs` | Read: `seq` 1 |
| Vector 2 with the party's signature removed | Refused at step 4 |
| Vector 2 with the party's `kid` not in the bootstrap file | Refused at step 3 |
| Any vector with one character of the payload changed | Refused at step 4, before the payload is parsed |
| Any vector with one character of the protected header changed | Refused: the signature does not verify |
| `alg` `ES256`, `ES512`, `HS384`, `PS384` or `none` | Refused at step 2 |
| A protected header with `crit`, `jku`, `x5u`, `x5c` or `jwk` | Refused at step 2 |
| A protected header with an extra member | Refused at step 2 |
| `kind` missing from the protected header, or not a string | Refused at step 2 |
| A valid signature over a header that names another kind | Refused at step 2: the document is not the kind asked for |
| A line feed or carriage return inside the protected header, the payload or the signature | Refused (step 2 for the header, step 4 for the others) |
| A last base64url character that carries bits the bytes do not | Refused |
| A `kid` with a lone surrogate escape, or protected-header bytes that are not UTF-8 | Refused at step 2 |
| A document that is not UTF-8 | Refused at step 1 |
| The two signatures of vector 2 with different `seq` | Refused at step 2 |
| A signature with an unprotected `header` member | Refused at step 1 |
| The same document in the compact or the flattened serialisation | Refused at step 1 |
| Two signatures with one `kid` | Refused at step 3 |
| A DER-encoded ECDSA signature in place of `r` then `s` | Refused at step 4 |
| Vector 1 in force, then vector 2 on reload | Read: `seq` 2 replaces `seq` 1 |
| Vector 2 in force, then vector 1 on reload | Refused at step 5: lower `seq`; the snapshot in force stays and an alarm is raised |
| Vector 2 in force, then vector 2 again | No change |
| Vector 2 in force, then a document with `seq` 2 and another payload | Refused at step 5 |
| Vector 1 as the only document at a cold start, though `seq` 2 was published before | Read: nothing is in force to compare with |
| A valid signature over a payload that is not valid for the kind | Refused at step 6, naming the path |
| One document of the set invalid, the other documents valid | The whole set is refused; the snapshot in force stays |
| Every document valid, one declared kind missing from the source | Refused at a cold start and on a reload |
| A document for a config kind that the boundary does not declare | Refused at a cold start and on a reload (planned: store@ cannot list a source's documents yet, so the document is not read) |
