# Ports

The target shape of access-roster's storage, signalling and identity edges, and
the contract each adapter must meet. The reasoning is in the records
[0026](../decisions/0026-two-platforms-permanently-kubernetes-and-aws-lambda.md)
to [0032](../decisions/0032-one-configuration-file-one-binary-one-chart.md); this
page is the specification. Which adapter exists today is in
[../capabilities.md](../capabilities.md).

**Status: the ports and five adapters are built; DynamoDB is designed.** The
interfaces, an in-memory adapter, a temporary `legacy` adapter, a NATS JetStream
adapter for State, Index and Trigger, an S3 Blob and a KMS Sealer exist
([Implementation status](#implementation-status)); DynamoDB does not, and
nothing runs on the NATS adapter yet. The running service still keeps its state as
described in [access-roster.md](access-roster.md#the-store) and
[../operations/high-availability.md](../operations/high-availability.md). This
page is what an adapter is built and tested against; the current layout stays
true until the migration in
[0031](../decisions/0031-a-generic-migration-tool.md) has run.

A port is a small Go interface in the service, a set of semantics every adapter
shares, and a conformance suite. It is **not a framework**
([0024](../decisions/0024-reconciler-rails-are-shared-pieces-not-a-framework.md)):
business code names a port and never an adapter, and an adapter contains no
business rule.

| Port | What it is for | Kubernetes | AWS Lambda |
|---|---|---|---|
| [State](#state) | records, sealed secrets, sessions, tokens, leases, gates, caches, counters | NATS JetStream KV | DynamoDB |
| [Blob](#blob) | status reports, directory snapshots | S3 | S3 |
| [Trigger](#trigger) | a change becomes a tick | KV watch | asynchronous `lambda:Invoke` |
| [Sealing](#sealing) | wraps the data key of a sealed secret | KMS, OpenBao Transit, or a mounted key | KMS |
| [Inputs](#inputs) | policy, configuration, operator-managed secrets | mounted ConfigMaps and Secrets | file in the image, or a parameter store |
| [Identity](#identity) | proves a workload to the issuer, and the service to the cloud | ServiceAccount token, AWS federation | the same |
| [Audit sink](#audit-sink) | records what the service did | `http`, `nats` | `sqs` |

## State

A key-value store with a lifetime on every record, a revision on every write,
and no relations. Keys are strings of the form `a.b.c`; a prefix ends at a `.`.
A value is an opaque byte string up to 256 KiB (the smaller of the two engines'
limits, with headroom); larger content is a [blob](#blob).

### Operations

| Operation | Meaning | Errors |
|---|---|---|
| `Get(key)` | the value and its revision | `ErrNotFound` if absent **or expired** |
| `Put(key, value, ttl)` | write unconditionally; returns the new revision | `ErrTooLarge` |
| `Create(key, value, ttl)` | write only if absent (an expired record is absent) | `ErrExists` |
| `Update(key, value, ttl, rev)` | compare-and-swap: write only if the revision is still `rev` | `ErrConflict` if it moved, `ErrNotFound` if it is gone |
| `Delete(key)` | remove, no error if absent | |
| `DeleteIfRevision(key, rev)` | remove only if the revision is still `rev` | `ErrConflict`, `ErrNotFound` |
| `List(prefix, page)` | live records under a prefix, in key order, paged | `ErrBadPage` for a token from another prefix |
| `Watch(prefix)` | a stream of changes (put, delete, expiry) under a prefix, from now | the stream ends with the adapter's error; the caller resubscribes |

Semantics every adapter shares:

- **Single key only.** An operation touches one key. There are no multi-key
  transactions and no secondary indexes. A flow that needs several keys is a
  sequence of idempotent steps with a recovery marker.
- **A TTL is mandatory** on `Put`, `Create` and `Update`, except for records the
  [layout](#key-layout) marks as permanent (`0`). A call with no lifetime that
  the layout does not allow is refused up front, as the current store refuses it.
- **A revision is opaque and strictly changes on every write.** Callers compare
  it for equality and never order it.
- **Reads filter on expiry.** `Get` and `List` return a record only if its
  expiry is in the future by the caller's clock, whether or not the engine has
  already removed it. DynamoDB removes expired items lazily and later; JetStream
  removes them at the stream's maximum age. Neither is relied on.
- **Create-if-absent sees an expired record as absent**, so a lease or a
  one-time code whose predecessor expired can be taken at once.
- **Paging is stable.** A page token continues from a key; a record written
  while paging may or may not appear, and none appears twice.
- **Watch is at-least-once and unordered across keys.** It carries the key and
  the new revision; a watcher that needs the value reads it. A watcher that falls
  behind or reconnects performs a `List` and reconciles; it never assumes it saw
  every event.

### Leases

A lease is a `Create` of `lease.<target>` with the holder's id and a short TTL,
renewed by `Update` with the revision it holds, and released by
`DeleteIfRevision`. Takeover is a `Create` after expiry. A holder that fails to
renew treats the lease as lost and stops before its next external write. Clock
skew is bounded by the TTL being many times the renewal interval.

### Error mapping

An adapter maps its engine's errors to the six above. Everything else is an
`ErrUnavailable`, which the caller treats as "the store is down" and, on the
sign-in path, **refuses** the request rather than degrading, exactly as the
current store does.

## Key layout

One layout, two renderings. NATS uses the dotted key as written, in a bucket
`access-roster`. DynamoDB uses one table with a partition key `pk` and a sort
key `sk`; the dotted key is split at the first `.` into a partition and a sort
value so that a prefix listing is a `Query` on one partition, with the first
segment's upper-case form (`SES`, `SID`) written as `<KIND>#<value>`. An
`expires` attribute (epoch seconds) holds the expiry, the table's TTL attribute
points at it, and a revision attribute `rev` is a counter that conditional writes
compare.

No access pattern needs a secondary index: everything a caller looks up is a key
or a prefix. Sessions are listed per person under `ses.<person>.`, a session id
is resolved to its person through the pointer `sid.<sid>`, and "every session"
is a listing over all `ses.` partitions, which is an operator action and not a
hot path.

| Prefix (NATS key) | DynamoDB `pk` / `sk` | Content | Writer | TTL |
|---|---|---|---|---|
| `req.<id>` | `REQ#<id>` | a pending authorization request, also backing a device-code poll | issuer | 30 min |
| `code.<id>` | `CODE#<id>` | an authorization code | issuer | 5 min |
| `codesess.<id>` | `CODESESS#<id>` | the session a redeemed code opened, for a replayed redemption | issuer | 5 min |
| `ses.<person>.<sid>` | `SES#<person>` / `<sid>` | a per-client session: identity, client, how it began, scopes, SSO session, refresh token (hashed), authentication time | issuer | the session lifetime |
| `sid.<sid>` | `SID#<sid>` | pointer from a session id to `<person>`; written with the session, deleted with it | issuer | the session lifetime |
| `rt.<hash>` | `RT#<hash>` | live refresh token to `<person>.<sid>` | issuer | the session lifetime |
| `rtrot.<hash>` | `RTROT#<hash>` | a spent refresh token's successor, for the 30-second retry grace | issuer | 30 s |
| `sso.<id>` | `SSO#<id>` | the browser-wide SSO session and the clients it covers | issuer | the session lifetime |
| `tok.<jti>` | `TOK#<jti>` | a minted token's own record, for userinfo and revocation | issuer | until the token expires |
| `keyring.<kid>` | `KEYRING#<kid>` | a signing key's schedule: first seen, activation | issuer replicas | 30 days, renewed on each poll |
| `ws.<id>` | `WS#<id>` | a connected Slack workspace or directory record, with its sealed credential | console | permanent |
| `gh.org.<id>` | `GHORG#<id>` | a connected GitHub organisation record, with its sealed App key | console | permanent |
| `gh.link.<person>` | `GHLINK#<person>` | a person's GitHub link and its token pair, **one item**, including `RefreshingSince` | link flow, GitHub tick | until refresh expiry |
| `app.<id>` | `APP#<id>` | a catalogue App's record and sealed token | console | permanent |
| `lease.<target>` | `LEASE#<target>` | the holder of a target's tick, by id | ticks | seconds, renewed |
| `gate.<target>.<name>` | `GATE#<target>` / `<name>` | a held-once ledger entry, a breaker, a fingerprint | ticks | by gate |
| `share.<host>.<channel>` | `SHARE#<host>` / `<channel>` | a pending Slack Connect share, written by the host's tick; its write enqueues the guest's tick | host tick | until accepted, then 7 days |
| `cache.<digest>.<name>` | `CACHE#<digest>` / `<name>` | a shared input (a group's holders, an address's state), keyed by the policy digest | ticks | the digest's lifetime |
| `dedupe.<id>` | `DEDUPE#<id>` | an idempotency marker for an external write | ticks | by use |

The records marked permanent are the only ones with no TTL. A key that no
longer appears in this table is not written by the service.

Secrets in a record are **sealed** before they reach the port
([Sealing](#sealing)); the State store never sees a plaintext credential.

## Blob

Whole-object storage for content too large for an item and read whole: a target's
status report (one per target, replaced on every tick) and the directory
snapshots the hub serves from.

| Operation | Meaning | Errors |
|---|---|---|
| `Read(name)` | the object and its version | `ErrNotFound` |
| `Write(name, body)` | replace the object; returns the version | `ErrUnavailable` |
| `WriteIfVersion(name, body, version)` | replace only if it is unchanged | `ErrConflict` |

Both platforms use S3: a bucket the installation names, a prefix per kind
(`reports/<target>`, `snapshots/<directory>`), server-side encryption on, and no
public access. A blob holds no credential and no personal data beyond what the
console already shows. A reader treats a missing blob as "not yet written" and a
stale one as stale, never as an error in the access decision.

## Trigger

Turns "this target has work" into a tick without a poll.

| Operation | Meaning |
|---|---|
| `Notify(target)` | ask for a tick of the target; coalesces with one already waiting |
| `Subscribe(handler)` | run `handler(target)` for every notification delivered to this process |

On Kubernetes, `Notify` is a `Put` of a `notify.<target>` key and `Subscribe` is
a watch on that prefix, with a periodic full listing as the backstop. On AWS,
`Notify` is an asynchronous `lambda:Invoke` of the tick function with the target
in the payload, and the invocation **is** the delivery: the function's handler
is the subscriber. EventBridge Scheduler invokes the same function for every
target on a period as the backstop.

A notification is a hint and may be duplicated or lost; the lease and the
backstop make both harmless. Writing a `share.` record **is** a notification of
the guest's tick.

## Sealing

Wraps and unwraps the data key of a sealed secret.

| Operation | Meaning | Errors |
|---|---|---|
| `Wrap(plaintext key, context)` | returns the key wrapped by the key-encryption key, with the key's id | `ErrUnavailable` |
| `Unwrap(wrapped, context)` | returns the data key | `ErrUnwrap` for a key not wrapped by this key, a wrong context, or a revoked key |

A secret is sealed with AES-GCM under a fresh data key; the envelope holds the
nonce, the ciphertext, the wrapped data key and the key id. The **context** (the
record's key and kind) is authenticated additional data, so a sealed value copied
under another key does not open. Rotation of the key-encryption key is a rewrap
of the envelopes' data keys and never touches the ciphertext.

Adapters: **KMS** (AWS; on Kubernetes through Pod Identity), **OpenBao Transit**,
and a **mounted key** (a file, for an installation with neither). The signing-key
schedule's private material is not stored by this port: the signing key stays a
mounted file ([access-roster.md](access-roster.md#the-store)).

## Inputs

Read-only. The policy, the configuration file
([0032](../decisions/0032-one-configuration-file-one-binary-one-chart.md)) and
the secrets an operator manages. On Kubernetes they are mounted ConfigMaps and
Secrets, polled for change; on Lambda they are a file in the image, or read from
a parameter store at start. The service **never writes** an input and holds no
permission to.

## Identity

Two directions. **Inbound**, a workload proves itself to the issuer with a
ServiceAccount token or an AWS federation token
([../connect/aws-workloads.md](../connect/aws-workloads.md)); the verifier is
platform-independent, and the installation declares the clusters and accounts it
trusts ([0030](../decisions/0030-workload-identity-on-both-platforms.md)).
**Outbound**, the service takes its own identity from the platform (a projected
token or a role) and hands it to the adapters that need one; no adapter reads a
credential from anywhere else.

## Audit sink

Records the service's own actions in an audit installation. Transports: `http`
and `nats` on Kubernetes, `sqs` on AWS. A record that cannot be written durably
refuses the action it describes where the action is a sign-in, as today
([access-roster.md](access-roster.md#audit)).

## Conformance

One suite, written once against the port, runs against every adapter: **the
in-memory one, NATS JetStream and DynamoDB** (a local emulator is not enough:
the suite also runs against the real engine in CI for the adapter that has one
available, and the emulator-only case is named as such). It is the gate for
adding or changing an adapter, and for the migration tool, where each adapter is
a source and a destination.

The suite asserts, at least:

- **CAS races.** N concurrent `Update` calls with the same revision: exactly one
  succeeds, the rest return `ErrConflict`; N concurrent `Create` of one key:
  exactly one succeeds. `DeleteIfRevision` loses to a newer write.
- **TTL visibility.** A record is returned until its expiry and never after, on
  the caller's clock, **including after the engine's own sweep has not yet run**;
  `Create` succeeds over an expired record; `List` omits it.
- **Lease takeover.** A held lease cannot be taken; an expired one can, by
  exactly one of several racing takers; a renewal after takeover fails with
  `ErrConflict`.
- **Prefix paging.** A listing of more records than a page returns every live
  record once, in key order, across a page boundary and across a concurrent write;
  a page token from another prefix is refused.
- **Revisions.** A revision changes on every write and an `Update` with a stale
  one fails.
- **Watch.** A put, a delete and an expiry under a prefix are observed; a
  watcher that reconnects can recover by listing.
- **Limits.** A value over the size limit is refused with `ErrTooLarge`, on every
  adapter alike.
- **Sealing and blobs.** A sealed value does not open under another context;
  `WriteIfVersion` loses to a newer write.

An adapter that cannot pass an assertion for a stated engine reason documents the
reason in its own page and the suite names the exception; a silent skip fails the
suite.

## Implementation status

Business code uses the lease and the trigger as `rails.Leases` (`Acquire`,
`Renew`, `Release`, and `Do`, which runs a tick under a lease and cancels it if
the lease is lost) and `port.Trigger`; a report of a target is one blob written
alone (`rails.BlobReports.Put`).

The Go interfaces are in `internal/port` (`State`, `Index`, `Blob`, `Trigger`, `Sealer`,
`Identity`; the audit sink is `audit.Recorder`, unchanged), the conformance
suite is `internal/port/porttest`, and `internal/store` builds one set of ports
from the `ports.adapter` key of the configuration file and hands it to the
apps. Business packages depend on the interfaces only; a test
(`internal/port/guard_test.go`) fails if one imports `internal/kube`,
`internal/valkey` or the legacy adapter. The interfaces differ from the tables
above in three ways, all small:

- `Blob` also has `Delete` and `List(prefix)`, because a report family is
  replaced as a whole and a snapshot is deleted with its workspace, and two
  optional capabilities, `Replacer` (replace every object under a prefix in one
  write) and `ReaderAll` (read them in one request).
- `State` is accompanied by `Index`, an unordered set with an expiry refreshed
  on `Add`. It is **transitional**: the issuer's session index is a Valkey set
  today, the layout replaces it with a prefix listing, and until the migration
  has run the legacy adapter has to keep writing sets. A new feature does not use
  it.
- `Identity` is `Verify(token, audiences) (subject, error)`, the seam over the
  existing verifiers; the legacy adapter is the cluster's `TokenReview`.

### The S3 Blob and the KMS Sealer

Two adapters of one port each, in `internal/port/s3blob` and
`internal/port/kmsseal`. They are chosen by `ports.blob` and `ports.sealer`,
which replace the Blob and the Sealer of whatever `ports.adapter` brings, so
State `legacy` with Blob `s3` is a valid pair and so is, later, State NATS with
Blob S3 and Sealer KMS. Both take their credentials from the platform (Pod
Identity, IRSA, a Lambda role): no key is configured. They are marked 🧪 in
[../capabilities.md](../capabilities.md): they pass the conformance suite on
LocalStack, and have not yet run against AWS.

**S3 Blob.** One bucket and one key prefix; a name `reports/<target>` is the
object `<prefix>/reports/<target>`.

| Port operation | S3 | Maps to |
|---|---|---|
| `Read` | `GetObject`; the version is the ETag | `ErrNotFound` for `NoSuchKey`; a missing bucket is **not** `ErrNotFound` but `ErrUnavailable` |
| `Write` | `PutObject`; the version is the new ETag | |
| `WriteIfVersion` | `PutObject` with `If-Match: "<etag>"`, atomic in S3 | 412 (the ETag moved) and 409 (`ConditionalRequestConflict`, a concurrent conditional write) are `ErrConflict`; an absent object is `ErrNotFound` (a store that answers 412 for an absent key is told apart by a `HeadObject`) |
| `Delete` | `DeleteObject`, which succeeds for an absent key | |
| `List` | `ListObjectsV2` under the prefix, every page, sorted | |

Without SSE-KMS an ETag is the MD5 of the body, so rewriting identical bytes
keeps the version; as with the legacy adapter, a compare-and-swap cannot tell
A, B, A from a blob that never moved, and nothing depends on it. `Replacer` is
**not implemented**: S3 has no multi-object write, so replacing a family is not
atomic, and the port's fallback (`Write` and `Delete`) is what a caller uses.
`ReaderAll` is not implemented either: on S3 it is a listing and a `GET` per
object, no cheaper than the caller doing it. The port has no create-if-absent
for a blob, so `If-None-Match: *` is not used. `ports.blob.s3.kmsKey` asks for
SSE-KMS on every write; the request checksum is sent only where an operation
requires it, which keeps S3-compatible stores working.

**KMS Sealer.** `port.Seal` generates the 32-byte data key itself and hands it to
the Sealer, so the adapter uses `Encrypt`, not `GenerateDataKey`.

- `Wrap(dataKey, binding)` is `kms:Encrypt` under the configured key with the
  `EncryptionContext` `{"access-roster:binding": <binding>}`; `Wrapped.KeyID` is
  the key ARN KMS reports and `Wrapped.Blob` the ciphertext.
- `Unwrap` is `kms:Decrypt` with the same context and the configured key as
  `KeyId`. A different binding, a ciphertext another key made, a disabled,
  deleted-pending or unknown key, and an envelope whose key id is not the key
  KMS used are `ErrUnwrap`; throttling, a missing permission and the network are
  `ErrUnavailable`.
- **There is no cache of unwrapped keys.** Every `Unwrap` is one `kms:Decrypt`
  in CloudTrail, which is the audit of who opened which secret, and the port
  allows no data key to outlive the call. A path that reads a sealed value per
  request pays a KMS call for it.
- Rotation of the key's material is KMS's own and transparent. Moving to another
  key is a rewrap with the old key to read and the new to write, which this
  adapter, holding one key, does not do on its own.

**Conformance.** `porttest.RunGroups` runs the `blob/` and `sealing/` groups
against each adapter: against a fake in `go test ./...`, and against LocalStack
(S3, KMS) when `ACCESS_ROSTER_S3_URL` is set. `just test-s3` starts the pinned
LocalStack with `docker run`; CI runs the same script
(`hack/s3-conformance.sh`) as the `s3` job, which **fails if a test skipped or
did not run**. It also runs the Blob suite with SSE-KMS on, and checks that KMS
itself refuses a wrong binding and a foreign key.

### The in-memory adapter

`internal/port/memory` implements every port in process memory, with the
semantics above (revisions are a counter, expiry is judged by an injectable
clock, `Watch` delivers put, delete and expiry, `Trigger` coalesces, `Sealer` is
AES-GCM under a key that lives and dies with the store). It is what tests and the
demonstration use, and what `ports.adapter: memory` selects.

### The NATS adapter

`internal/port/nats` implements State, the transitional Index and Trigger over
one JetStream KV bucket (`ports.adapter: nats`, `ports.nats`:
[configuration](../reference/configuration.md)). Blob, Sealer and Identity
are not NATS's: with this adapter `internal/store` takes them from the legacy
adapter, unless `ports.blob` and `ports.sealer` name the S3 and KMS adapters
(which compose with any State). The package documentation holds the whole
mapping; in short:

| Operation | JetStream |
|---|---|
| `Get` | `kv.Get` |
| `Create` | `kv.Create` (with the per-key TTL); over an expired record that the server has not reaped, a publish against its revision, so exactly one taker wins |
| `Put`, `Update(rev)` | a publish to the key's subject with the expected-last-sequence header (what `kv.Put` and `kv.Update` send, with the TTL they cannot carry) |
| `DeleteIfRevision` | `kv.Delete` with `LastRevision` (`kv.Purge` with a marker TTL when the bucket has limit markers) |
| `List` | the stream's own subject listing under the prefix, sorted, a page token naming the last key, then a `kv.Get` per key |
| `Watch` | a KV watch on the prefix, from now |
| Index `Add`/`Remove`/`Members` | the key `idx.<set>.<member>` with an empty value and the lifetime; `Members` is a prefix listing |
| Trigger `Notify`/`Subscribe` | `notify.<target>` written with a one-minute lifetime; `Subscribe` watches the prefix, so a notification crosses processes |

- **Revisions are the stream sequence.** A rewrite of identical bytes changes
  it, and a record that went A, B, A is not mistaken for one that never moved:
  the legacy adapter's two skips do not apply, and no assertion is skipped for
  State, Index or Trigger.
- **Expiry is in the value and judged by the reader's clock**, nine bytes in front
  of it, so `Get` and `List` never return an expired record whether or not the
  server has reaped it, `Create` succeeds over one and `Update` finds it gone.
  **On nats-server 2.11 or later** (JetStream API level 1) the bucket is also
  created with message TTLs and limit markers, each write carries its TTL
  (rounded up to the second) and the server reaps the record and a watcher sees
  the expiry. **On an older server** the bucket is created without them, nothing
  is reaped (a record is filtered, not removed, until it is written or deleted),
  and a `Watch` reports an expiry from its own clock for records it saw written.
- **Reads are the leader's.** A KV bucket answers `Get` from any replica by
  default, which can be behind a write the caller was just acknowledged for; the
  adapter turns direct gets off on its bucket, so a revoked session reads as
  revoked, and lists from the stream's state, which the leader answers.
- **A key is a subject.** Bytes a subject or the KV client does not allow (a `:`
  of the legacy names) are written as `=XX`; the dots stay, so the layout is the
  subject hierarchy.
- **`List` scans the prefix's subjects on every page**: it is for the operator,
  the watcher and the small per-person prefixes, not for a request over a large
  one.
- **The Index's expiry is per member.** An `Add` gives its member the lifetime
  and does not extend the others'; the layout's `ses.<person>.` listing replaces
  the Index.
- **Credentials** are the pod's projected ServiceAccount token, presented as the
  NATS token for the auth callout to validate (`ports.nats.tokenFile`, read afresh
  on every connect), or a credentials file; never a value in the file.
- **Conformance** runs against an embedded nats-server (a single node, a
  single node without per-message TTL, and a three-node cluster with a
  replicated bucket), with no container; State, Index and Trigger pass every
  assertion. The Blob, Sealer and Identity assertions are skipped by name, as they
  are other adapters' ports. A test with the real clock covers the server's own
  TTL reaping.

### The legacy adapter

`internal/port/legacy` is temporary: it implements the ports over today's
ConfigMaps, Secrets and Valkey, writing exactly the bytes the domain stores
write, and is deleted when the migration of
[0031](../decisions/0031-a-generic-migration-tool.md) has run. Its package
documentation holds the whole mapping; in short:

| Port key or name | Where it lives today |
|---|---|
| `req.<id>`, `code.<id>`, `codesess.<id>`, `tok.<jti>`, `sso.<id>`, `rt.<hash>`, `rtrot.<hash>`, `keyring.<alg>:<kid>` | the Valkey key the issuer writes (`issuer:request:<id>`, `issuer:code:<id>`, ...), under the installation's prefix |
| `lease.<kind>:<workspace>` | `{<workspace>}:lease:<kind>`, the hub's refresh lease; `lease.<name>` is `lease:<name>`. The controllers' tick leases are `lease.github-tick:<org>`, `lease.github-links:all` and `lease.slack-tick:<workspace>` (0029) |
| a key containing `:` | itself: the legacy namespace the issuer's own state is written in |
| `gh.org.<org>` | the `<org>.json` entry of the `<release>-github-orgs` ConfigMap (the record; the credential is a separate Secret) |
| `snapshots/<workspace>` | `{<workspace>}:snapshot`, the same gzip bytes, for the cache's lifetime |
| `reports/github/<key>`, `reports/slack/<key>` | an entry of `<release>-github-status`, `<release>-slack-status` |

Every other key of the layout (`ses.`, `sid.`, `ws.`, `gh.link.`, `app.`,
`gate.`, `share.`, `cache.`, `dedupe.`, `notify.`) has no object of its own
today, and is `ErrUnsupported` (which is why the pending-share hand-off, the
State-backed input cache and the gates of 0029 wait for an adapter that can hold
them; the controllers keep the first as a notification between ticks, the
second in memory and the third in the report): a session is one Valkey value that does not carry
its person, a link is a Secret entry keyed by account id, and presenting either
under the layout's key would write different bytes.

Where a port operation cannot be met exactly, the adapter does the closest safe
thing, and the conformance suite names the exception:

- **Revisions are the SHA-1 of the stored bytes.** Neither Valkey nor a
  ConfigMap entry has a per-key version, and adding one would change what is
  written. A rewrite of identical bytes keeps its revision
  (`revisions/change-on-identical-rewrite` is skipped), and a compare-and-swap
  cannot tell a record that went A, B, A from one that never moved. The swap is
  atomic: a Lua script in Valkey, the ConfigMap's own `resourceVersion` for an
  entry.
- **`Watch` polls** the prefix by listing it (every two seconds by default) and
  reports differences; an expiry is seen as a delete when a poll finds the record
  gone.
- **A ConfigMap entry has no lifetime**, so `gh.org.` accepts only the permanent
  writes the layout allows. Report entries are text: a blob of invalid UTF-8 under
  `reports/` is `ErrUnsupported`.
- **`Trigger` is in-process.** A notification reaches this process's
  subscribers. A controller subscribes and ticks the target it names, but the
  console that calls `Notify` is another process, so a controller still learns
  of a console write from the records it mounts, looked at every 30 seconds (an
  operator's request for a pass names its target and ticks only it; any other
  change runs a sweep), and its sweep is still its interval. The key-value watch
  of the layout replaces the poll.
- **Tick leases are exclusive across processes only with a Valkey.** The
  controllers are configured with none, so with this adapter a controller's
  leases are held in its own memory and the chart keeps one replica.
- **`Sealer` is `ErrUnsupported`** (`sealing/context` is skipped): nothing is
  sealed today, and a process-local key would produce envelopes no restart could
  open.
- **Listing is a scan** (`SCAN` of every primary, or one `GET` of the ConfigMap),
  for an operator or a watcher and not a request path.

What does not go through the ports yet: the ConfigMap and Secret domain stores
of a connected workspace and its credential, an organisation's credential, a
person's GitHub link, the catalogue Apps, the OAuth client and memberships, and
the Slack records with their recovery mirror. They stay behind their own
interfaces and are written by `internal/kube`, which only `internal/app`,
`internal/githubroster/app` and the legacy adapter import. Each moves when its
key family of the layout has an adapter that can hold it.
