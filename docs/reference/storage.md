---
title: Storage
description: "The port contracts on the wire, record keys and kinds, the state envelope and data-key rotation, and the on-disk layout of the local drivers."
status: target
sidebar:
  order: 5
---

An actor reaches its keys and data through ports, and the driver behind each port is a service on a Unix socket ([ADR 0002](/decisions/0002-families-of-actors/#ports-of-a-work-actor), [ADR 0005](/decisions/0005-the-store/#drivers)). This page fixes what goes over those sockets, how a record is named and sealed, which record kinds the first working version has, and how the drivers of the local installation lay their data out on disk. Who may write which kind, and why every value is encrypted, are on [Data and secrets](/concepts/data/).

## Port contracts

Each port is one Connect service under `proto/sluis/port/<port>/v2alpha1/` ([Contracts and errors](/reference/contracts/#packages-and-files)). The port library inside the actor is the only client: it adds the scope from the actor's own identity, seals values, and never lets a request choose a scope, a key or a path ([Three layers per port](/decisions/0007-policy-and-sealed-grants/#two-independent-checks)). The driver checks the caller again by its peer uid.

### state

```proto
service StateService {
  rpc Get(GetRequest) returns (GetResponse);       // key -> value, revision, expires_at; not_found if absent or expired
  rpc Put(PutRequest) returns (PutResponse);       // create only if absent: already_exists otherwise
  rpc Cas(CasRequest) returns (CasResponse);       // change only at the revision read: aborted otherwise
  rpc Batch(BatchRequest) returns (BatchResponse); // puts and cas together, all or none
}
```

- **A record is a key, a revision, an optional expiry and a sealed value.** A revision is a 64-bit integer that the driver sets: 1 at creation, plus 1 at each change. An expiry is milliseconds since the Unix epoch, set by the application, never by the store ([ADR 0005](/decisions/0005-the-store/#drivers)).
- **A record past its expiry reads as absent**, whatever the engine still holds, and a `Put` may create it again.
- **`Batch` holds at most 64 writes** to records of the calling actor and is applied atomically, or refused whole with the code of the first write that failed and its index.
- **Delete, listing by prefix and watch are not in the first working version.** Nothing in it needs them; session listing does, at parity ([#1009](https://github.com/truvity/sluis/issues/1009)). A conditional adjust of a counter is not part of that issue: it belongs to quota and is added only if the quota load test shows contention ([ADR 0053](/decisions/0053-quota-consistency-and-failure-are-measured-per-state-driver-before-enforcement-is-switched-on/#the-load-test)).

### lease

```proto
service LeaseService {
  rpc Acquire(AcquireRequest) returns (AcquireResponse); // name, ttl -> fencing_token, expires_at; aborted while held
  rpc Renew(RenewRequest) returns (RenewResponse);       // name, fencing_token, ttl -> expires_at; aborted if lost
}
```

A lease ends when it is not renewed. The fencing token grows each time the lease changes hands, and the holder passes it with every write it makes under the lease ([Leases](/decisions/0005-the-store/#leases)). On a single node the `local-lock` driver serves the same contract.

### keys

```proto
service KeysService {
  rpc Sign(SignRequest) returns (SignResponse);                // purpose, content -> signature
  rpc PublicKey(PublicKeyRequest) returns (PublicKeyResponse); // purpose -> SPKI (DER), key id, certificate chain
  rpc Wrap(WrapRequest) returns (WrapResponse);                // purpose, context, plaintext -> wrapped
  rpc Unwrap(UnwrapRequest) returns (UnwrapResponse);          // purpose, context, wrapped -> plaintext
}
```

- **A key is addressed by its purpose**, never by a slot, an ARN or a file: `token-signing`, `x509-intermediate`, `sealing`, `log`, `ssh-user`, `ssh-host`, `enrolment`, `issuance-log`, `release-signing` ([ADR 0006](/decisions/0006-keys-and-sealing/#the-slot-plan)). The driver maps it to its slot or key.
- **`Sign` carries the content, not only a digest,** for the purposes whose content `key-holder` parses before signing: a TBSCertificate for `x509-intermediate`, an OpenSSH certificate body for the SSH purposes, a JWS signing input for `token-signing`, an OpenPGP signature input for `release-signing` ([key-holder is the one mediator](/decisions/0006-keys-and-sealing/#exclusive-card-access)). Content that does not parse, or falls outside the purpose's constraints, is `permission_denied`, and nothing is signed.
- **`context` is the encryption context of a wrap,** a list of name and value pairs that must match on unwrap: `purpose=cookie`, `purpose=grant`, `purpose=secret`, or the (boundary, kind) of a data key.
- **The access list** of `key-holder` names, for each caller actor, the purposes and operations it may use; it is generated from the manifests ([Permission manifest](/architecture/manifest/)).

### blob, transport and index

| Port | Methods | Notes |
|---|---|---|
| blob | `PutOnce(key, bytes)`, `Get(key)`, `List(prefix, page)` | `PutOnce` is create-if-absent: `already_exists` when the key is taken. It is what fences the audit writer ([ADR 0029](/decisions/0029-the-audit-log/#the-write-once-fence)). The lock mode is a capability flag of the driver: `fs` has `none` |
| transport | `Put(record)`, `Receive(max)`, `Ack(ids)` | At least once: the writer de-duplicates by record id ([ADR 0028](/decisions/0028-audit-pieces/#transport)) |
| index | `Write(batch)`, `Query(query, page)` | The search index of the audit trail ([ADR 0028](/decisions/0028-audit-pieces/#search-and-the-index)) |

## Record keys

A record key is `<boundary>/<kind>/<id>`, in the clear, so the store can index it ([ADR 0005](/decisions/0005-the-store/#the-store-api)).

- **`<boundary>` and `<kind>` come from the library**, from the actor's own identity and the kinds its manifest names; the caller passes only `<id>`.
- **Each segment is ASCII:** lower-case letters, digits, `-`, `_` and `.`, at most 128 characters, and the whole key at most 300.
- **`<id>` never holds personal data:** no e-mail address, name or directory account. It is a random id (128 bits, base32 without padding) or a keyed hash of a natural key. A person's record is found by the opaque subject, never by the address, and an upstream account's link by a keyed hash of the issuer and the subject claim ([ADR 0019](/decisions/0019-person-and-upstream-link/#the-records)).
- **A kind name is singular kebab-case** (`auth-code`, not `auth_codes`) and unique within a boundary across all actors; the manifest generator refuses a kind two actors write ([One writer per kind](/decisions/0004-the-data-model/#one-writer-per-kind)).

## Record kinds of the first working version

The kinds that the actors of the first working version write. Each has one writer; declared configuration (clients, policy, exchange trust) is not stored here, it is the install file ([Install file](/reference/install-file/)). The full list is generated from the manifests once they exist.

| Kind | Writer | Origin | Expires | Roll-forward | Holds |
|---|---|---|---|---|---|
| `pending-signin` | `session` | issued, ephemeral | when the sign-in times out | no | The state of a sign-in between the authorize request and the upstream callback |
| `auth-code` | `session` | issued, ephemeral | at most 10 minutes (RFC 6749, section 4.1.2) | no | An authorization code with its PKCE challenge; spent by compare-and-set, so it works once |
| `session` | `session` | issued, ephemeral | the session's absolute limit ([ADR 0018](/decisions/0018-sessions/)) | no | A session, its subject, and the freshness of its authentication per boundary |
| `refresh-token` | `session` | issued, ephemeral | the refresh token's lifetime | no | The hash of a refresh token, its chain and its spent marker |
| `webauthn-challenge` | `session` | issued, ephemeral | the ceremony's timeout | no | A passkey challenge; spent once |
| `passkey` | `session` | issued, durable | none | yes | A person's passkey: its public key, credential id hash and sign count |
| `person` | `session` | issued, durable | none | yes | The subject (128 random bits, lower-case base32, also the key), the WebAuthn user handle (32 random bytes) and the time created ([ADR 0019](/decisions/0019-person-and-upstream-link/#the-records)) |
| `upstream-link` | `session` | issued, durable | none | yes | The subject of the person, the issuer and the subject-claim name; the key is the keyed hash of the issuer and the claim value |
| `upstream-pin` | `session` | issued, durable | none | yes | The subject claim first used for an issuer; a later contradiction is refused |
| `link-key` | `session` | issued, durable | none | no | The 32 random bytes that key the two hashes; a sealed secret, made once by a create-only `Put`, never rotated, held by every archive after the first start |
| `person-hold` | `session` | operator-set | none | yes | That an operator holds a person: who, when and why; set and lifted on the console |
| `signing-ring` | `signer` | issued, durable | none | yes | The token keys the key set publishes, each with its `x5c` chain |
| `issued-certificate` | `ca` | issued, durable | the certificate's expiry | yes | The serial, profile, requester, validity and public-key hash of a certificate |
| `openpgp-binding` | `signer` | issued, durable | none | yes | The primary's certification of the release subkey that `sluis key install` stored, with its expiry; the signing API refuses when it is absent or expired ([ADR 0045](/decisions/0045-the-signing-api-signs-sent-content-for-an-authorised-proof-and-returns-an-armoured-detached-signature/#when-the-api-refuses-to-sign)) |
| `data-key` | the writer of the kind it serves | issued, durable | none | yes | A data key of one (boundary, kind), wrapped under the sealing key, with its encryption count |
| `policy-link-set` | `session` | operator-set, durable | none | no | The template links of the boundary, as one set under the fixed id `links`, changed by compare-and-set; `exchange` reads it ([Policy](/reference/policy/#template-links)) |

The short lifetimes are defaults in code, written with the actor that owns the kind; token lifetimes have the defaults and caps of [ADR 0020](/decisions/0020-grant-vocabulary-and-token-claims/#lifetimes), and session limits are per class ([ADR 0018](/decisions/0018-sessions/)). `entry`, `console` and `policy` write no record.

## The state envelope

Every value is sealed in the port library before it reaches a driver ([Every value is encrypted](/decisions/0006-keys-and-sealing/#seal-and-open)).

```text
envelope = version (1 byte, 0x01)
         | data-key id (16 bytes)
         | nonce (12 bytes, from the library)
         | ciphertext (AES-256-GCM)
         | tag (16 bytes)

aad      = "sluis-state-v1"
         | u16 length | boundary
         | u16 length | kind
         | u16 length | key
         | u64 revision
```

- **AES-256-GCM, with a data key per (boundary, kind).** The nonce comes from the cryptographic library, never from the caller: `crypto/cipher` with a random nonce in Go, `RandomizedNonceKey` of `aws-lc-rs` in Rust ([ADR 0006](/decisions/0006-keys-and-sealing/#algorithms)). Lengths are big-endian.
- **The additional authenticated data binds the value to its place**: a value copied to another boundary, kind, key or revision fails to decrypt. The label carries the envelope's version and the revision the record's, so both readings of "version" in ADR 0005 hold. The revision is the one the write creates: a `Put` seals at revision 1, a `Cas` at the read revision plus 1.
- **A sealed secret** uses the same envelope with `purpose=secret` in the data key's context and `"sluis-secret-v1"` as the first part of the additional data, so it is never read as an ordinary value or the other way round ([Sealed secrets](/decisions/0004-the-data-model/#treatment)).

### Data keys

- **A data key is a `data-key` record** of the kind's writer: 32 random bytes from the operating system's generator, wrapped through the keys port under the boundary's sealing key, with the context (boundary, kind). The writer and the kind's declared readers may unwrap it; no one else can ([ADR 0006](/decisions/0006-keys-and-sealing/#seal-and-open)).
- **A data key is rotated after 2^30 encryptions or one year, whichever comes first.** AES-GCM with random 96-bit nonces stays within its bound on nonce collisions up to 2^32 encryptions under one key (NIST SP 800-38D, section 8.3, checked 2026-11-01); 2^30 keeps a margin of four for counting gaps.
- **Encryptions are counted in blocks.** A process reserves 65,536 encryptions at a time with a compare-and-set on the `data-key` record, so a crash loses at most its unused block and never under-counts. When the reserved total reaches the limit, the writer makes a new data key and uses it for every new write.
- **An old data key stays readable** until no value refers to it. A re-seal rewraps the data keys under a new sealing key without decrypting a value.

## The local drivers on disk

The local installation runs one container per actor and per driver, with the same socket layout and identities as a host ([ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)). Each driver keeps its data under `/var/lib/sluis/` on a named volume, in a directory owned by the uid that may write it; the same paths are used on a bare-metal host.

| Driver | Path | Owner and mode |
|---|---|---|
| `software` keys | `/var/lib/sluis/keys/<boundary>/<purpose>.key` | `key-holder`, `0600` in a `0700` directory |
| `embedded` state | `/var/lib/sluis/state/<actor>@<boundary>/state.db` | the actor's uid, `0600` in a `0700` directory |
| `local-lock` lease | `/var/lib/sluis/state/<actor>@<boundary>/leases.db` | the actor's uid, as above |
| `fs` blob | `/var/lib/sluis/blob/<actor>@<boundary>/<key>` | the writing actor's uid, `0750`; its declared readers are in its read group |
| `spool` transport | `/var/lib/sluis/spool/<producer>@<boundary>/` | the producing actor's uid, `0750`; the audit writer is in its read group |
| `sqlite` index | `/var/lib/sluis/index/<boundary>/index.db` | the indexer's uid, `0640`; the reader opens it read-only |

- **The read groups are generated from the manifests**, one per writing actor, holding only its declared readers' uids.
- **A software key file** holds one key, a PKCS#8 private key, PEM-armoured, made by the driver; the driver refuses to start when the environment is production ([ADR 0006](/decisions/0006-keys-and-sealing/#floors-in-code)). Anyone who can read the volume can read the key, so software keys guard development data only.

### `embedded`

One SQLite file per actor instance, opened only by that actor's driver:

```sql
CREATE TABLE records (
  key        TEXT    PRIMARY KEY,
  revision   INTEGER NOT NULL,
  expires_at INTEGER,          -- milliseconds since the Unix epoch, or NULL
  value      BLOB    NOT NULL  -- the envelope
) STRICT, WITHOUT ROWID;
CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;  -- schema_version = 1
```

- **The journal is WAL with `synchronous=FULL`**, so a write that returned survives a power cut.
- **`Put`** inserts the row, or replaces a row whose `expires_at` has passed, in one statement, and reports `already_exists` when no row changed. **`Cas`** is `UPDATE … WHERE key = ? AND revision = ?` and reports `aborted` when no row changed. **`Batch`** runs in one `BEGIN IMMEDIATE` transaction.
- **Expired rows are deleted by the driver** in the background. That is housekeeping, not a port operation: a reader never sees an expired record either way.

### `fs`

- **A blob key maps to a path** under the writer's directory, one directory per `/`-separated segment, with the same character rules as record keys.
- **Create-if-absent:** the driver writes a temporary file in the target directory, fsyncs it, then `link()`s it to the target name (or `renameat2` with `RENAME_NOREPLACE`), which fails if the name exists, removes the temporary name and fsyncs the directory ([Ports and drivers](/concepts/drivers/#create-if-absent)). Local POSIX filesystems only.
- **The lock mode is `none`**: a local administrator can change a file, so tamper evidence comes from verification and a witness ([ADR 0029](/decisions/0029-the-audit-log/#lock-modes)).
- **The issuer documents** (discovery and the key set) are blobs of `signer` under `/var/lib/sluis/blob/signer@<boundary>/issuer/`.

### `spool` and `sqlite`

**These two drivers serve the audit log,** which is in the first working version ([ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)).

- **The spool is a directory per producer of append-only segment files.** Each record is a 4-byte big-endian length, the sealed record and a CRC-32C. A segment is fsynced after each record and closed at 4 MiB or one minute. The writer's cursor per producer moves in its atomic batch ([ADR 0029](/decisions/0029-the-audit-log/#sealing)).

:::note[Proposed]
**The `sqlite` index schema** follows the query contract of Search and is written with it. Tracked in [#1122](https://github.com/truvity/sluis/issues/1122).
:::

## Open items

None on this page that is not marked above. People's records are [ADR 0019](/decisions/0019-person-and-upstream-link/#the-records); what a directory adds at the parity milestone is in the same record.
