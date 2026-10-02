# Ports

The target shape of access-roster's storage, signalling and identity edges, and
the contract each adapter must meet. The reasoning is in the records
[0026](../decisions/0026-two-platforms-permanently-kubernetes-and-aws-lambda.md)
to [0032](../decisions/0032-one-configuration-file-one-binary-one-chart.md); this
page is the specification. Which adapter exists today is in
[../capabilities.md](../capabilities.md).

**Status: designed, not shipped.** The running service still keeps its state as
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
