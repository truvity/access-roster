---
title: Store API
description: "The store service on the wire, address encoding, the item, source and blob contracts of drivers, the conformance suite and the sealed envelope layout."
status: target
sidebar:
  order: 5
---

Every data call of a work actor goes to store@ over one generic service, and store@ reaches its engines and sources through drivers ([0005](/decisions/0005-the-store/)). This page fixes what goes over those sockets: the service, how an address is encoded, the contract of the drivers, and the byte layout of a sealed value. It is the one place that states these rules; the records link here. Who may write which kind is the generated [Rules](/reference/rules/) page, and the kinds themselves are on [Kinds](/reference/kinds/).

## The store service

The service is `sluis.store.v2alpha1.StoreService` ([Contracts and errors](/reference/contracts/#packages-and-files)), served by store@ on a Unix socket, an invoke or a pod address, depending on the runtime ([0003](/decisions/0003-units-transports-and-fusion/#transports)). A typed client is the only caller in practice: it builds the address from the boundary it is connected to, the tenant and the id the caller passes, and the kind's name ([Typed clients](#typed-clients)).

```proto
service StoreService {
  rpc Get(GetRequest) returns (GetResponse);               // one item by address
  rpc List(ListRequest) returns (ListResponse);            // the items of a kind in a tenant, or by a declared index
  rpc Write(WriteRequest) returns (WriteResponse);         // create, update, delete or apply, all or none
  rpc Watch(WatchRequest) returns (stream WatchResponse);  // the changes of a kind from a resume point
  rpc GetSignedConfig(GetSignedConfigRequest) returns (GetSignedConfigResponse);  // the signed document of a config kind, as the source holds it
}

message Address {
  string kind = 1;    // the kebab-case segment of the kind's name
  string tenant = 2;  // empty for a kind with no tenant; the address then carries "-"
  string id = 3;      // one or more parts, separated by "/"
}

message Item {
  Address address = 1;
  uint64 version = 2;                         // 1 at create, plus 1 at each change; set by store@; a re-created item starts at 1 again (0005, Time to live)
  bytes value = 3;                            // the kind's Protobuf message; for a sealed kind, the envelope
  google.protobuf.Timestamp expires_at = 4;   // set by store@ when the kind has a TTL
  repeated IndexEntry indexes = 5;            // the declared indexes, computed by the writer
}

message IndexEntry { string name = 1; bytes value = 2; }
```

- **The caller is learned from the transport,** never from a field: a peer uid, a Lambda role, a service-account token or a SPIFFE identity ([0005](/decisions/0005-the-store/#rules)). The boundary is the store@ the client is connected to, so a request names none.
- **A kind is named, never a method.** A new kind adds no method and no generated code on the wire, and the client library is one per language.
- **A sealed kind's `value` is the envelope.** store@ validates the envelope's header and size and never opens it ([The sealed envelope](#the-sealed-envelope)). The index entries of a sealed kind are keyed hashes or dates that the writer computes, because store@ cannot read the value.
- **Every call carries a deadline and a correlation id,** as every contract does ([Contracts and errors](/reference/contracts/#every-call)).

### Get and List

```proto
message GetRequest {
  Address address = 1;
  Consistency consistency = 2;  // LINEARIZABLE (the default) or FOLLOWER
  uint64 if_none_match = 3;     // a version the caller holds; the reply may be "unchanged"
}
message GetResponse {
  bool unchanged = 1;                 // true when the item is still at if_none_match; item is then empty
  Item item = 2;
  repeated Provenance provenance = 3; // for a layered kind only
}
message Provenance { string field_path = 1; Layer layer = 2; uint64 version = 3; }
enum Layer { LAYER_UNSPECIFIED = 0; BUILT_IN = 1; CONFIG = 2; OPERATOR = 3; TENANT = 4; }

message ListRequest {
  string kind = 1;
  string tenant = 2;
  string index = 3;         // a declared index of the kind, or empty to list the tenant's items
  bytes index_value = 4;    // the value to match under that index
  int32 page_size = 5;
  string page_token = 6;
  Consistency consistency = 7;  // unset or FOLLOWER: the leader's read, as before; LINEARIZABLE: see below
}
message ListResponse { repeated Item items = 1; string next_page_token = 2; uint64 resume_point = 3; uint64 log_epoch = 4; }  // the log position to watch from, and the epoch of the log it is in ([Watch](#watch))
```

- **`Get` is linearizable by default.** A reader that tolerates lag may ask for a follower read. A read that carries `if_none_match` and finds the same version answers `unchanged`; on Lambda, where nothing is pushed, that is how a reader re-reads cheaply ([0005](/decisions/0005-the-store/#watch-and-the-resume-point)).
- **`List` is not linearizable unless it asks, which is the opposite of `Get`.** Left unset (or `FOLLOWER`) a listing is read by the leader without confirming that it still leads, so a leader that was deposed a moment ago can answer from stale state for under a second; that is the read every listing had before the field, and asking for more costs a confirmation with a quorum, so the default stays. `LINEARIZABLE` sees every write that was acknowledged before it. A reader that decides on what it lists asks for it: key@ does for `KeyRevocation`, in the check of every `Sign` and of every PIN release (REQ-KEYS-233), because a revocation missed by a stale read is a downgrade ([0005](/decisions/0005-the-store/#engines): authority-relevant reads are linearizable). A store that cannot provide the level it was asked for refuses the call, as `unavailable`, and never answers a weaker one. A config kind is served from the signed documents store@ holds, and the field does not change it. A value of the field that this build does not know is `invalid_argument` with the reason `schema`. **Deploy store@ and the driver before key@:** protobuf drops a field it does not know, so a key@ that asks for `LINEARIZABLE` of a store@ or a driver from before the field gets the weak read and no error. There is no capability check, because the units of a board are deployed together and a rolling update replaces store@ and the driver first; if a driver ever runs apart from store@, the check has to come first. The item suite cannot catch a driver that ignores the flag (a one-node cluster answers the same at both levels), so the `rqlite` driver's test that records the level of each query is what pins it.
- **A read of a layered kind returns its provenance:** the effective value and, for each field, the layer that set it and the version. The effective read of a whole group, such as `EffectivePolicySet` for policies, is a `Get` of the group's effective answer ([0004](/decisions/0004-the-data-model/#layered-and-linked-kinds)).
- **An item past its expiry reads as absent,** whatever the engine still holds ([0005](/decisions/0005-the-store/#time-to-live)).
- **`List` has no query language.** It lists a tenant's items of a kind, or follows a declared index; a new question is a new declared index ([0005](/decisions/0005-the-store/#the-store-api)). The page size is at most the maximum the contract declares, and a page token is opaque, bound to the query and the caller ([Contracts and errors](/reference/contracts/#every-call)).

### Write

```proto
message WriteRequest {
  repeated Operation operations = 1;  // at most 64, applied all or none, to kinds of the calling actor
  bytes grant = 2;                    // the sealed grant; required when an address is tenant-scoped (not for key@'s DataKeyWrap and KeyRevocation)
}
message Operation {
  Verb verb = 1;                      // CREATE, UPDATE, DELETE or APPLY
  Address address = 2;
  bytes value = 3;
  uint64 if_version = 4;              // UPDATE: the version read; DELETE: optional
  google.protobuf.Duration ttl = 5;   // optional: shorter than the kind's maximum; absent, the kind's default
  repeated IndexEntry indexes = 6;
}
enum Verb { VERB_UNSPECIFIED = 0; CREATE = 1; UPDATE = 2; DELETE = 3; APPLY = 4; }
message WriteResponse { repeated Item items = 1; }  // the items as written, with their versions
```

| Verb | Writes | Refused when |
|---|---|---|
| `CREATE` | The item, only if the address is free | The address is taken: `already_exists` |
| `UPDATE` | The item, only at `if_version` | The version has moved: `aborted` |
| `DELETE` | Removes the item, at `if_version` when given | The version has moved: `aborted` |
| `APPLY` | Creates the item or sets it to the value, for a writer that owns the whole item and replays idempotently | Never for a version |

- **A batch is all or none,** by one actor to its own kinds. There are no interactive transactions: a flow over several items is idempotent steps with a recovery marker. A batch of more than 64 operations is refused.
- **store@ checks, on every operation,** the rule of the actor, the kind and the verb; the schema of the kind; a TTL within the kind's maximum; the version; the bounds and the direction rule of a layered kind; the links the registry says are checked at write; and that the caller is the kind's one writer ([0005](/decisions/0005-the-store/#rules)). On a write to a tenant-scoped address, except key@'s own writes of `DataKeyWrap` and `KeyRevocation` ([0005](/decisions/0005-the-store/#rules)), it has key@ open the grant, and refuses the write unless the grant names the address's tenant and allows the verb ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)).
- **While `MaintenanceMode` is set,** every write except those of the restore command is refused ([0010](/decisions/0010-backup-and-recovery/#restore)).
- **A write that changes a watched kind** also writes its change-log row in the same transaction. A kind that nobody watches writes none, and a hot counter is one conditional update ([Item contract](#the-item-contract)).

### GetSignedConfig

```proto
message GetSignedConfigRequest { string kind = 1; }           // the kind's segment; a config kind
message GetSignedConfigResponse { bytes document = 1; }       // the JWS bytes exactly as the config source gave them
```

- **It returns the signed document in force of a config kind, unread.** The bytes are the ones the config source gave store@, which store@ verified before it swapped them into the snapshot ([Signed config](/reference/signed-config/#verifying-a-document)). store@ vouches for nothing in them: the point of the call is that a reader which must not rely on store@ for what a document says verifies the signature and the sequence itself, under the publisher keys of its own copy of the bootstrap file. key@ does so for the `KeyPlan` ([0006](/decisions/0006-keys-and-sealing/#who-may-receive-a-wrap)).
- **It is a read of the kind.** The readers of the kind in the registry may call it and nobody else, by peer uid, and every refusal of a read applies ([Refusals](#refusals)): `permission_denied` with the reason `rule` for an actor with no read rule on the kind, and `unavailable` with the reason `engine` for a kind with no loaded document. A kind that is not a config kind, an unknown segment and a malformed one are `invalid_argument` with the reason `address` and the path `kind`. **A self-scoped kind** (`tunables`, `log-settings`, `integration`) has no signed document for any caller: the document holds every actor's items and an actor may read its own only, so the call is `permission_denied` with the reason `rule`, whatever the actor's rule on the kind. **The document is at most 3 MiB** ([Signed config](/reference/signed-config/#the-payload)).
- **It adds no edge to the call graph:** an actor that may call store@ at all is judged by its rule on the kind, as for `Get` ([REQ-DATA-099](/requirements/data/#REQ-DATA-099)).

### The lease value

A `Lease` carries a typed Protobuf message with one field the store reads, `expires_at`, so store@ can hold the expiry to the kind's maximum of 10 minutes (30 seconds by default) at every create and update. A value that does not decode, or an expiry beyond the maximum, is refused with `invalid_argument` and the reason `schema`. The verbs a lease allows are in [0005](/decisions/0005-the-store/#leases). The typed message is planned; until then the value is opaque and store@ checks only the TTL asked for.

### Watch

```proto
message WatchRequest {
  string kind = 1;
  string tenant = 2;          // empty only for a kind with no tenant, and for DataKeyWrap and KeyRevocation, as for List
  uint64 resume_point = 3;    // the change-log sequence last seen, or ListResponse.resume_point; 0 starts from now
  uint64 log_epoch = 4;       // the epoch that came with resume_point; a nonzero resume_point with any other epoch, none included, is refused. Ignored when resume_point is 0
}
message WatchResponse {
  uint64 resume_point = 1;    // hand this back after a restart; 0 for a config kind
  ChangeType type = 2;        // PUT, DELETE or BOOKMARK
  Item item = 3;              // PUT: the item as read at delivery. DELETE: its address and the version of the row, no value. BOOKMARK: none
  uint64 log_epoch = 4;       // the epoch of the log that resume_point is in, on every message of a stream; 0 for a config kind
  bool caught_up = 5;         // true on a BOOKMARK that says the stream has delivered every change up to a log head read linearizably: at the opening and renewed at idle ticks; never on a watch from 0
}
```

Watch is the Kubernetes list-watch contract ([0005](/decisions/0005-the-store/#watch-and-the-resume-point), decided 2026-11-04).

- **List, then watch.** `ListResponse.resume_point` is the change-log position that the snapshot reflects or is older than, read before the first page and the same on every page of one listing, and `ListResponse.log_epoch` is the epoch of the log it is in (see "The resume point is a pair" below). A watcher lists, then watches from that point under that epoch; nothing between the two is lost. A watch from 0 starts from now. A kind that nobody may watch has no log, and its listing names 0 and no epoch.
- **A change carries the address, the type, the version and its log sequence; the value is read at delivery.** `WatchResponse.resume_point` is the sequence of the change, the resume point after it. The change log holds no value: a `PUT` is the item as it is when the change is delivered, and a `DELETE` has the address and the version of the row, no value.
- **A version is not an identity;** a re-created item starts at version 1 again. A consumer dedupes by the sequence, inside one epoch: a change at or below the sequence it has applied, under the same epoch, is a repeat. A config kind is the exception: its changes have no sequence (`resume_point` 0), and a consumer applies every one.
- **Coalescing never loses a state.** Rows are read in runs. A put row is skipped only when a later row of the same address is in the run, which delivers the state. A delete row is never skipped, so a delete and the re-creation after it arrive in that order. An item that is gone when its put row is read, expired included, is a `DELETE`.
- **Expiry is a delete:** the driver's sweeper writes the delete row for an item that was written with a log row, and an item written with a log row that is removed by any path, an expired one not yet swept included, leaves a delete row.
- **Delivery is at-least-once, in the order of the log.** A watch gives the rows after its resume point.
- **No buffer beyond the driver's log.** The stream is read at the pace of its consumer, and HTTP/2 flow control is the backpressure. An idle stream sends a `BOOKMARK` with the latest resume point every 30 seconds, a config stream too (resume point 0). That bookmark is a sign of life and a point to resume from; it claims nothing about what the stream has seen.
- **Caught up.** When a watch of a kind with a change log opens, store@ reads the head of the log, linearizably, and sends one `BOOKMARK` with `caught_up = true` and `resume_point` equal to that head as soon as the stream has delivered every row up to it, like Kubernetes' initial-events-end bookmark ([REQ-DATA-120](/requirements/data/#REQ-DATA-120)). The rules:
  - **At once when there is nothing to deliver.** A watch from the head sends it as the first message, without waiting for the idle interval. A reconnect after a restart of store@ is the same: the changes made while the reader was away, then the bookmark.
  - **After the rows, never before.** The bookmark sits after the last row up to the head and before any row past it; a change written while the stream catches up comes after it. The claim is made from the rows the stream has delivered, not from the head alone, so a log that lags (the weak read of a replica that has not shown the last rows) delays it and cannot make it early. An engine that reports a head and then never shows the rows leaves the stream with idle bookmarks and no claim.
  - **A put is not skipped for a row past the head.** Coalescing skips a put row for a later row of the same address ([above](#watch)); up to the head, the later row must be up to the head too, so that the state the bookmark claims is in the reader's hands. A later row past the head follows the bookmark, and the earlier put is delivered before it.
  - **Renewed every interval.** A caught-up stream reads the head again, linearizably, when the bookmark interval (30 seconds) has passed since its last claim: on a quiet stream at the idle tick, on a busy one between two runs of rows, so a kind that changes more often than the interval is renewed too. One read per interval and per watch, with no audit record. If the head is at or below the last row the stream has dealt with, the message is the same bookmark again, `caught_up = true` with the position as `resume_point`; a reader that gets it in the order of the stream knows every row before it was consumed and that, at the read, the log had no more ([REQ-DATA-125](/requirements/data/#REQ-DATA-125)). If the head is ahead of the stream, or the read fails, nothing is renewed (a quiet stream sends the plain bookmark with `caught_up` false); the stream then claims again once it has delivered through that head, as at the opening. A log that was made again under the stream ends it with `resume_point_expired`.
  - **A watch from 0 never claims.** A watch from `resume_point` 0 ("from now") was given no point, so there is nothing it could say it had delivered up to: it sends idle bookmarks with `caught_up` false, first and always, and a reader that began there cannot take an empty set for a complete one ([REQ-DATA-126](/requirements/data/#REQ-DATA-126)). The claim covers only what the client supplied as its point.
  - **After the claims the stream is an ordinary stream:** changes, and idle messages. A reconnect is a new stream and claims again; the reader treats its state as unconfirmed from a listing, a break, a reconnect or a dropped call until it does ([typed clients](#typed-clients)).
  - **A kind with a change log only.** The first bookmark of a config watch closes its snapshot and carries no `caught_up`: it claims nothing about freshness beyond the snapshot in force.
  - **What a reader may conclude.** After a `caught_up` bookmark its state holds every change that was committed before store@ read the head: the head is a linearizable read, so it includes every write acknowledged before the call, and the rows up to it were delivered. That is a claim about the moment of the read, and it ages:
    - **A write acknowledged after that read** (a revocation included) follows the bookmark as a change, after the driver's next poll of the log (every 200 ms in the rqlite driver, from a replica that may trail the leader). Until it arrives the reader's state does not hold it, and a reader that answers "not revoked" in that window answers from state that is a little old. The window is the lag of the log, not a missed row.
    - **Talking is not freshness.** Idle bookmarks come from store@'s own timer: a tail that reads from a deposed or isolated node, or a consumer that reads messages queued long ago, still receives them. Only the renewal of the claim says the log was read lately, from the head, linearizably, and found at the position the stream delivered. A reader that decides authority therefore bounds the age of the last claim, not of the last message: it trusts its state only while a claim younger than 45 seconds (one renewal and a margin) stands (`caught_up_within`, [typed clients](#typed-clients)), and it asks at the moment it answers.
    - **The worst case** for a reader that applies that bound: while the claims go on, the lag of the log (some hundreds of milliseconds in the rqlite driver, more behind a replica that trails, but then the head is ahead and no claim is renewed); once they stop, because the tail is behind, the read fails, the store is down or the stream is half open, at most 45 seconds after the last claim, then the reader is unconfirmed and fails closed. So a revocation committed at the worst moment can be missed by an answer "not revoked" for at most 45 seconds plus the lag of the log, and never silently longer. A renewal that was already in the queue of the stream when the consumer asked is not counted as new, however small the gap between its calls, because a consumer that was away may find renewals piled up in front of a revocation it has not read: only a renewal that the read had to wait for dates the claim, and the typed client enforces it.
  - **It does not say the log is quiet.**
- **A resume point the change log no longer holds, or has not reached, or that belongs to another log,** is refused with `failed_precondition` and the reason `resume_point_expired`, path `resume_point`. The watcher lists the kind again and watches from the new point. The driver keeps the log for one hour by default and at most seven days. A stream that is open when the log is made again ends with the same refusal.
- **A kind with no change log cannot be watched.** A durable or temp kind that is neither watched nor exportable is not logged by any write, so a watch over it is refused with `invalid_argument` and the reason `address`, path `kind`, before the rules are read ([REQ-DATA-124](/requirements/data/#REQ-DATA-124)): a stream over it would say it is caught up and then deliver nothing for ever.
- **At most 16 watches per caller.** The 17th is refused with `resource_exhausted` and the reason `watch_limit`; a watch that ends gives its place back.
- **Who may watch.** A watch is judged as a read is: the actor needs a `watch` rule on the kind (`watched_by`, [rules](/reference/rules/)), a kind with a tenant is watched under a tenant, a rule bound to the caller's own ids watches only those, and a kind the registry does not declare is `invalid_argument` with the reason `address`. A read needs no grant today, so a watch needs none.
- **The resume point is a pair.** A resume point is the epoch of the change log and a sequence in it, the pair `(log_epoch, resume_point)` that a listing names and that every message of a stream carries. A restore into a new database or a reset of the log begins the sequence again, so the same number can name another position after it; the epoch is what tells the two logs apart. The rules, which store@ keeps for every engine ([0005](/decisions/0005-the-store/#watch-and-the-resume-point), decided 2026-11-06):
  - **The driver mints the epoch** when it creates the change log, and a log that is made again has another ([the item contract](#the-item-contract)). store@ passes it through and never makes one; an engine that names a position with no epoch is out of its contract, and store@ fails closed (`unavailable`, `engine`) rather than name a position that could be the same number in another log.
  - **A watch from a nonzero `resume_point` is good only under the log's epoch.** Another epoch, or none (`log_epoch` 0: a point saved before epochs existed, or made up), is `resume_point_expired`, even when the new log has grown past the number and holds it. There is no migration for a point with no epoch: v2 has no release, so none is kept alive, and the watcher lists once. From 0 ("from now") the epoch is not looked at, because there is no position in it to mistake.
  - **A consumer compares sequences only inside one epoch.** It keeps the pair, saves both (an `ExportCursor` holds both), hands both back, and treats a message that names another epoch than its stream was opened under as a refusal: it lists the kind again and replaces its applied point with the new pair. It never drops a change as a repeat because its number is at or below one applied under another epoch.
  - **What a restore does.** `sluis restore` writes through the store ([0010](/decisions/0010-backup-and-recovery/#restore)); a log is not part of the archive. Into an empty target the engine creates its log, with an epoch of its own, so every point saved before is refused. Into the same database with `--overwrite` the log goes on and only grows, so a saved point stays good and the restored rows arrive as changes.
  - **Loading a database file is not a restore.** Putting an older rqlite database file back (a snapshot copy, `/db/load`) brings back its log and its epoch with it, and a saved point can then name another position without a refusal until the log passes it. That is outside the supported path ([0005](/decisions/0005-the-store/#engines): a snapshot copy of a database is not the backup). An operator who does it deletes the row `log_epoch` of the `<namespace>_meta` table before the driver starts; the driver finds the row missing, makes a new epoch, and until then reads no position (`unavailable`).
  - **Read levels.** The head and the epoch of a listing are read in one statement at the level the listing asks for (`ListRequest.consistency`); the head and the epoch of a watch are read **linearizably** when it opens (a driver that cannot refuses the watch, `unavailable`), and again by the driver's `TailLog`; the rows of a tail are read at `weak` together with the epoch, in one statement, so rows of another log are never delivered; the value of a `PUT` is read linearizably at delivery. A lagging weak read of the rows can only delay the caught-up bookmark, never advance it ([Caught up](#watch)).
- **A watcher does not assume more than the log gives.** Order is that of the log for one address, because coalescing skips a put that a later row of its address supersedes; a change the listing already shows may come again after it; a delete may repeat, and may name an item the watcher never held; an item that expires reaches the watcher as a delete only when the sweeper runs, so a reader that must not use an expired item reads `expires_at`.
- **A config kind has no change log.** A config watch begins with the full snapshot: the snapshot in force as `PUT`s (at the document's `seq`), then a `BOOKMARK`. Replace your state for that kind with the items received before the first bookmark, so that an item a swap added or removed between a listing and the watch is not lost. Then, at each swap, store@ sends each item that was added or changed (`PUT`) and each that was removed (`DELETE`), all with `resume_point` 0, and a consumer applies every one: there is no sequence to dedupe by. store@ reads the document's `seq` and the items from one snapshot, and copies the kind only when the `seq` moved. A swap of another kind tells a watcher nothing. A resume point on a config kind is refused with `resume_point_expired`: the watcher reads the kind again.

### Refusals

A refusal is a Connect error with the `Refusal` detail and a reason that names the rule ([Contracts and errors](/reference/contracts/#errors)). **Every refusal of store@ is audited,** on every method and for every code and reason below, as an event `store.refused` that names the calling actor, the kind, the verb and the reason, and never a value of the request.

| Code | Reason | When |
|---|---|---|
| `invalid_argument` | `address`, `schema`, `ttl`, `index`, `batch` | The address does not fit the encoding, or a watch names a kind with no change log; the value fails the kind's schema; a TTL is above the kind's maximum; an index entry is undeclared; a batch is too large |
| `permission_denied` | `rule`, `writer`, `grant` | No rule allows this actor, kind and verb; the caller is not the kind's writer or the actor named in the id; the grant is missing, for another tenant or not allowing the verb |
| `not_found` | `absent` | No such item, or an expired one |
| `already_exists` | `taken` | A `CREATE` found the address in use |
| `aborted` | `version` | An `UPDATE` or `DELETE` named a version that is no longer current |
| `failed_precondition` | `bound`, `direction`, `link`, `maintenance`, `resume_point_expired` | A bound or the direction rule refuses the value; a link does not resolve; `MaintenanceMode` is set; the resume point is gone, not reached, or in another log |
| `resource_exhausted` | `watch_limit` | The caller already holds 16 watches |
| `unavailable` | `engine` | An engine or a source is down; store@ fails closed |

## Typed clients

- **A client is generated from the kind's Protobuf message** ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf)). In Go it is `store.Client[T Kind]`; in Rust a kind implements `trait Kind { type Id; type Value: buffa::Message; const NAME: &'static str; }` and the client is `Store<K: Kind>` ([0005](/decisions/0005-the-store/#typed-clients)).
- **The client does the encoding on this page:** the kind's name becomes its segment, the id is validated against [Address encoding](#address-encoding), and a sealed kind's value is sealed at key@ before it is written and opened after it is read ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)).
- **The Rust client follows a kind with `Store::watch`** ([REQ-DATA-108](/requirements/data/#REQ-DATA-108), [REQ-DATA-109](/requirements/data/#REQ-DATA-109)): it lists, watches from the position of the listing, drops a repeat, reconnects from the last position with a backoff, and says a resume point the log no longer holds as an explicit resync with the whole state of the kind. A value that does not decode or a change that is malformed ends the watch with an error. It retries for ever by default (a consumer escalates on the attempt count of the interruption; an option ends the watch after a time), takes a stream that is silent for 90 seconds for broken, and treats its state as unconfirmed after a listing, an interruption, a reconnect or a dropped call of `next` until the stream says it is caught up (`Event::CaughtUp`, [REQ-DATA-121](/requirements/data/#REQ-DATA-121)). An idle bookmark does not confirm it. Only a claim dates the confirmation: a reader on another task takes `Watch::confirmation()`, a handle that stays valid while the watch task waits, and asks `caught_up_within(max_age)` when it answers, with 45 seconds ([REQ-DATA-123](/requirements/data/#REQ-DATA-123)). A stream that makes no progress toward its claim within `catch_up_timeout` (60 seconds, two idle intervals; a bookmark that moves the position is progress), and any stream that has no new claim for `claim_timeout` (120 seconds, four intervals; progress does not count), is interrupted with the reason `catch-up stalled` (never claimed) or `claim not renewed` (a tail that fell behind the log after its first claim, or a store that inches the position forward for ever). The client decides this and not store@, because it sees what the reader sees whatever the cause, and a reconnect opens a new tail at the current leader. Neither that nor a stream that says it is caught up and dies ends the count of failures: only a change, or a caught-up stream that has stayed up for `stable_after` (15 seconds), does, so the reconnects back off to the cap and a limit on failures is reached. The Go client has no watch helper yet.
- **Both kits pass one conformance suite** ([0012](/decisions/0012-the-language-follows-the-executable/#the-rules), rule R9), which includes the vectors of this page.

## Address encoding

The address of an item is `<boundary>/<tenant | ->/<kind>/<id>` ([0004](/decisions/0004-the-data-model/#the-address)). As a key at a driver it is that text in ASCII.

- **A part is 1 to 128 characters** of lower-case letters, digits, `-`, `_` and `.`. A part is never `.` or `..`, and the whole address is at most 300 bytes.
- **The boundary** is its name, as in the [bootstrap file](/reference/bootstrap-file/#schema-and-validation). The driver of a store@ sees only its own boundary.
- **The tenant is `-` when the kind has none,** and the tenant id otherwise. A tenant id is never `-`.
- **The kind is its kebab-case segment.** The segment is the kind's PascalCase name with a hyphen before each capital that follows a lower-case letter or a digit, then lower-cased. Every name in the registry fits, and no two share a segment (checked on the 114 kinds of 2026-11-03).
- **The id has one or more parts,** separated by `/`. It names the item inside the kind: a random value, a keyed hash, or a path such as `<purpose>/<generation>/<recipient>` for a `DataKeyWrap` and `<actor>/<name>` for a `Lease`. A listing by prefix lists items and creates no scope.
- **An id never holds personal data:** no e-mail address, name or directory account. It is a random value (128 bits, lower-case base32 without padding) or a keyed hash of a natural key, made by key@'s `Mac` ([0006](/decisions/0006-keys-and-sealing/#sign-and-mac)). A person is found by the opaque subject, never by the address.

| Case | Verdict |
|---|---|
| `DataKeyWrap`, `SessionChain`, `Lease` | Segments `data-key-wrap`, `session-chain`, `lease` |
| `PredefinedPolicyLinkTemporary` | Segment `predefined-policy-link-temporary` |
| `prod/acme/session-chain/q7x2m5nt4kz3c6vdp9ba8hwrfe` | Valid |
| `prod/acme/data-key-wrap/data/1/board-a` | Valid: an id of three parts |
| `prod/-/lease/adapter-github/sync` | Valid: a kind with no tenant, an id of two parts |
| `prod/Acme/person/x` | Refused: an upper-case letter |
| `prod/acme/person/../x`, `prod/acme/person//x`, `prod/acme/person/x/` | Refused: a part that is `..` or empty |
| `prod/acme/person/a b` | Refused: a space |
| `prod/-/person/x` for a kind that has a tenant | Refused by the store: the kind's scope |
| A part of 129 characters, or an address of 301 bytes | Refused |

## The driver contracts

A driver is a separate binary behind one port, private to its owner ([0005](/decisions/0005-the-store/#drivers)). It sees items and bytes only, and never knows what a kind means. Two contracts serve store@'s four ports: the item contract for the durable and temp ports, and the source contract for the config and secret ports. The audit's blob port has its own, the [blob contract](#the-blob-contract).

### The item contract

`sluis.port.item.v2alpha1.ItemService`, served by the `rqlite` and `dynamodb` drivers on the durable and the temp socket.

```proto
service ItemService {
  rpc Get(ItemGetRequest) returns (ItemGetResponse);          // key -> item; not_found if absent or expired
  rpc Query(QueryRequest) returns (QueryResponse);            // items by key prefix, or by index entry, paged
  rpc Transact(TransactRequest) returns (TransactResponse);   // conditions, puts and deletes, all or none
  rpc TailLog(TailLogRequest) returns (stream TailLogResponse);  // the change log from a sequence
}

message DriverItem {
  bytes key = 1;                              // the address as text
  uint64 version = 2;                         // set by the driver: 1 at creation, plus 1 at each change; a re-created item starts at 1 again
  bytes value = 3;
  google.protobuf.Timestamp expires_at = 4;   // set by store@, never by the engine
  repeated IndexEntry indexes = 5;
}
message TransactRequest {
  repeated Condition conditions = 1;          // every one must hold
  repeated Put puts = 2;
  repeated Delete deletes = 3;
}
message Condition { bytes key = 1; oneof expect { bool absent = 2; uint64 version = 3; } }
message Put { bytes key = 1; bytes value = 2; google.protobuf.Timestamp expires_at = 3; repeated IndexEntry indexes = 4; bool log = 5; }
message Delete { bytes key = 1; bool log = 2; }
message TailLogResponse { uint64 sequence = 1; bytes key = 2; uint64 version = 3; bool deleted = 4; }
```

- **`Query` has the same choice as `Get`, as a flag:** `QueryRequest.linearizable` (`ItemGetRequest.linearizable` for a `Get`). It is false by default, which is the read a query always had. A driver that gets `true` answers at a linearizable level or refuses the call as `unavailable`, and never at a weaker one; a driver that is down, or in the middle of a leader change, is `unavailable`, not stale. The `rqlite` driver reads at rqlite's `weak` level when it is false and at `linearizable` when it is true, where the leader confirms its leadership with a quorum before it answers. The `dynamodb` driver, when it is built, has to read with `ConsistentRead` for `true`,. The item suite holds every driver to it: after each of fifty acknowledged writes, a linearizable listing holds all of them.
- **`Transact` is all or none.** A failed condition aborts it with `aborted` and the index of the first condition that failed.
- **`Transact` with one put and one condition is one conditional update,** not a transaction. A counter that many callers change depends on it ([0005](/decisions/0005-the-store/#drivers)).
- **`log` asks the driver to write a change-log row in the same transaction.** store@ sets it for a kind that some actor may watch and leaves it off for the rest. `TailLog` streams the rows from a sequence; a sequence the log no longer holds is `failed_precondition` with the reason `sequence_expired`.
- **A schema of another version is refused at start,** with the message that says how a development or board installation recreates its data (`just local-down` and `just local-up` locally; `SLUIS_PURGE_STATE=1 just boards-undeploy` and `just boards-deploy` on boards). The rqlite schema is version 2 since `Watch`: the items table has a `logged` column.
- **`QueryResponse.log_head` is the newest sequence of the change log,** read before the page. It is never 0: a log starts with a marker row at sequence 1 (no key), so that a listing of an empty log still names a position, because a resume point of 0 means "from now". store@ returns it as the `resume_point` of a listing.
- **The change log has an epoch,** `QueryResponse.log_epoch`, read with `log_head` in the same statement. It is a nonzero 64-bit value that the driver draws at random when it creates the log and keeps in the same database as the log, so that every node of a cluster reads the one value. A log that is made again, by a reset or by a restore into a new database, has another one; a schema that is run twice, or by a second node, keeps the epoch it finds. A driver that cannot read an epoch refuses the call (`unavailable`) and never names a position without one. `TailLogRequest.log_epoch` carries the epoch that came with `from_sequence`: for a nonzero `from_sequence` the driver compares it with the log's and answers `sequence_expired` to any other, no epoch (0) included, and ends a stream with the same refusal when the log's epoch changes under it; for 0 ("from now") it is ignored. The item suite holds a driver to this (the case `log_epoch`); that a log made again has another epoch is the test of each driver, because the suite cannot reset one.
- **A future driver keeps the epoch with the log, and ties it to the storage it lives in.** The `dynamodb` driver, when it is built, keeps the epoch in an item of its table and makes a new one whenever it creates the table and whenever the identity of the table it finds (its id, which a point-in-time restore changes) is not the one recorded beside the epoch, because a restore of the table brings the old epoch back with the old rows. `rqlite` has no identity of its storage to record, so the operator step for a loaded database file (above) takes its place.
- **The sweeper writes a delete row for an expired item that was written with a log row,** and trims the log to the retention (`--changelog-retention`, one hour by default, at most seven days). A trim raises a floor, and a tail that is behind the floor is refused.
- **An item past its expiry reads as absent,** and a sweeper frees the space: rqlite's leader, or DynamoDB TTL. A `Lease` is the one item never swept ([0005](/decisions/0005-the-store/#leases)).
- **A re-created item starts at version 1.** After a delete or a sweep the driver keeps no counter for the address ([0005](/decisions/0005-the-store/#time-to-live)); a `Lease`, which is never swept or deleted, is the item whose version only grows.
- **Timestamps come from store@,** because rqlite does not rewrite non-deterministic defaults and a replica would compute its own ([0005](/decisions/0005-the-store/#engines)).

### The source contract

`sluis.port.source.v2alpha1.SourceService`, served by the `file`, `appconfig`, `credential` and `ssm` drivers.

```proto
service SourceService {
  rpc Capabilities(CapabilitiesRequest) returns (CapabilitiesResponse);  // watch: NONE, NOTIFY or POLL
  rpc Read(ReadRequest) returns (ReadResponse);                          // name -> bytes and a version label
  rpc Watch(SourceWatchRequest) returns (stream SourceWatchResponse);    // NOTIFY drivers: a newer version exists
}
message ReadRequest { string name = 1; string if_none_match = 2; }
message ReadResponse {
  bool unchanged = 1;
  bytes data = 2;
  string version = 3;                           // a label, not a number: a file's digest, an AppConfig version
  google.protobuf.Duration poll_after = 4;      // POLL drivers: when to ask again
}
```

- **A config source driver returns bytes and never parses them.** The name is a config kind's segment ([Signed config](/reference/signed-config/#the-document)). The `watch` capability is `none` (a Lambda layer), `notify` (the `file` driver watching its directory) or `poll` (the `appconfig` driver).
- **A secret source driver returns the value of a named secret.** store@ fetches it on first use and keeps it in memory; it is never written to disk, an audit fact, a log line or a span ([0005](/decisions/0005-the-store/#secret-sources)).

### The blob contract

`sluis.port.blob.v2alpha1.BlobService` is the audit's own port, not one of store@'s four. It is served by the blob drivers (`fs` today, `s3-compatible` later) to the holders of the audit blob: `writer`, `witness`, `indexer` and `reader` ([0029](/decisions/0029-the-audit-log/#the-write-once-fence)). The path of an object is its key.

```proto
service BlobService {
  rpc Create(CreateRequest) returns (CreateResponse);      // create if absent
  rpc Put(PutRequest) returns (PutResponse);               // conditional overwrite of a pointer path only
  rpc Get(BlobGetRequest) returns (BlobGetResponse);       // path -> bytes and entity tag
  rpc List(BlobListRequest) returns (BlobListResponse);    // paths by prefix, paged
}
message BlobListRequest { string prefix = 1; string page_token = 2; int32 page_size = 3; }
message BlobListResponse { repeated string paths = 1; string next_page_token = 2; }
```

- **`Create` writes an object that must not exist** and answers `already_exists` when it does. It is the fence of the log ([0029](/decisions/0029-the-audit-log/#the-write-once-fence)).
- **`Put` overwrites only the paths a driver allows** (`checkpoint` and `writer-state`), and only at the entity tag the caller read (`if_match`, empty when the object must be absent).
- **`List` is paged like every list** ([Contracts and errors](/reference/contracts/#every-call)). The default `page_size` is 1,000 paths and the maximum 10,000; a larger request is cut to the maximum. `page_token` is opaque and bound to the prefix that made it; today it is a `string` and the driver does not check the binding.
- **A path is validated by the driver:** non-empty segments of at most 255 bytes, none starting with `.`, no NUL, at most 1,024 bytes in all, and never a link out of the root. A path that fails is refused with the reason `path`, which names the field and never the value.

The closed list of reasons of the blob port:

| Code | Reason | When |
|---|---|---|
| `invalid_argument` | `path` | The path, the prefix, the page size or the page token is not acceptable |
| `permission_denied` | `rule` | `Put` on a path that is not a pointer |
| `not_found` | `absent` | No such object |
| `already_exists` | `taken` | `Create` found the path in use |
| `aborted` | `version` | `Put` found another entity tag, or an object where none was wanted |
| `unavailable` | `engine` | The directory or the bucket failed; the driver fails closed |

The proto above is what is built. The target is a `bytes` token bound to the prefix and a page-size maximum written in the contract; both are planned ([Pagination](/reference/contracts/#every-call)). The store service's own `page_token` is a `string` in the same way.

### The command line and the suite

Every driver binary has the same four commands.

| Command | What it does |
|---|---|
| `serve` | Serves its contract on the socket the platform gives it |
| `check` | Verifies the driver's own configuration and its reach to the engine or the source, and exits non-zero on a failure |
| `version` | Prints the driver's version and the contract versions it speaks |
| `conformance` | Runs the port's suite against the driver. A driver passes the suite or it is not a driver |

The in-memory engine, for tests only, passes the same suite as `rqlite` and `dynamodb`. The suite holds the conditional-update, expiry, ordering and change-log cases of the item contract and the capability cases of the source contract.

## The sealed envelope

A sealed kind's value is a Protobuf message that key@ has sealed under a data key ([0006](/decisions/0006-keys-and-sealing/#data-keys)). The bytes that store@ keeps are the envelope.

```text
envelope = version     (1 byte, 0x01)
         | purpose     (1 byte)
         | generation  (4 bytes, big-endian)
         | nonce       (12 bytes, from the library)
         | ciphertext  (AES-256-GCM)
         | tag         (16 bytes)

aad      = "sluis-seal-v1"
         | version | purpose | generation
         | u16 length | boundary
         | u16 length | tenant        ("-" when the address has none)
         | u16 length | kind
         | u16 length | id
```

| Purpose | Code | Sealed under |
|---|---|---|
| `data` | `0x01` | The `data` key of the address's tenant, or of the boundary when the address has none |
| `evidence` | `0x02` | The `evidence` key of the tenant |
| `cookie` | `0x03` | The `cookie` key of the boundary |
| `grant` | `0x04` | The `grant` key of the boundary |
| `chain` | `0x05` | The `chain` key of the address's tenant |

- **AES-256-GCM, with a data key per purpose and generation.** The nonce comes from the cryptographic library, never from the caller: `crypto/cipher` with a random nonce in Go, `RandomizedNonceKey` of `aws-lc-rs` in Rust ([0006](/decisions/0006-keys-and-sealing/#algorithms)). Lengths are big-endian. The generation names the data key that sealed the value, so an older generation keeps opening what it sealed ([0006](/decisions/0006-keys-and-sealing/#rotation)).
- **The additional authenticated data binds the value to its full address** and to its own header: a value copied to another row, kind, tenant or boundary fails to open, and so does a header changed in place. A value that has to move is opened and sealed again ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)).
- **store@ validates the envelope and never opens it.** It checks that the version is known, that the purpose is `data`, the only purpose of a stored item ([0006](/decisions/0006-keys-and-sealing/#data-keys)), and that the length is at least the 34-byte minimum. A value that fails is refused with `invalid_argument` and the reason `schema`.
- **key@ uses the same layout for the cookies, the grants and the session-chain facts it seals,** with the context it is given in place of an item address. None of them is an item of its own ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)).
- **A hashed kind has no envelope.** Its message is kept as it is, and its compare-only fields hold hashes that the writer computed ([0004](/decisions/0004-the-data-model/#treatment)). A plain kind is kept as it is. A value from a secret source is neither: it passes through store@ in memory.

The vector below is for opening; key@ takes the nonce from the envelope. The key is a test key, and the plaintext is the ASCII text `example`.

| Part | Value |
|---|---|
| Data key (32 bytes, hex) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| Address | `prod/acme/person/q7x2m5nt4kz3c6vdp9ba8hwrfe` |
| Purpose and generation | `data`, generation 1 |
| Envelope (41 bytes, hex) | `010100000001a0a1a2a3a4a5a6a7a8a9aaab83601d4035a767333479d34abf5280916c787fad2fae39` |
| Additional authenticated data (hex) | `736c7569732d7365616c2d7631010100000001000470726f64000461636d650006706572736f6e001a713778326d356e74346b7a336336766470396261386877726665` |
| Opens to | `example` |

The same envelope under the address `prod/globex/person/q7x2m5nt4kz3c6vdp9ba8hwrfe` does not open (checked 2026-11-03 with a GCM implementation outside sluis).
