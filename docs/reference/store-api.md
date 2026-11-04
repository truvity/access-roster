---
title: Store API
description: "The store service on the wire, address encoding, the item and source contracts of drivers, the conformance suite, and the byte layout of the sealed envelope."
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
}
message ListResponse { repeated Item items = 1; string next_page_token = 2; }
```

- **`Get` is linearizable by default.** A reader that tolerates lag may ask for a follower read. A read that carries `if_none_match` and finds the same version answers `unchanged`; on Lambda, where nothing is pushed, that is how a reader re-reads cheaply ([0005](/decisions/0005-the-store/#watch-and-the-resume-point)).
- **A read of a layered kind returns its provenance:** the effective value and, for each field, the layer that set it and the version. The effective read of a whole group, such as `EffectivePolicySet` for policies, is a `Get` of the group's effective answer ([0004](/decisions/0004-the-data-model/#layered-and-linked-kinds)).
- **An item past its expiry reads as absent,** whatever the engine still holds ([0005](/decisions/0005-the-store/#time-to-live)).
- **`List` has no query language.** It lists a tenant's items of a kind, or follows a declared index; a new question is a new declared index ([0005](/decisions/0005-the-store/#the-store-api)). The page size is at most the maximum the contract declares, and a page token is opaque, bound to the query and the caller ([Contracts and errors](/reference/contracts/#every-call)).

### Write

```proto
message WriteRequest {
  repeated Operation operations = 1;  // at most 64, applied all or none, to kinds of the calling actor
  bytes grant = 2;                    // the sealed grant; required when an address is tenant-scoped (not for key@'s DataKeyWrap)
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
- **store@ checks, on every operation,** the rule of the actor, the kind and the verb; the schema of the kind; a TTL within the kind's maximum; the version; the bounds and the direction rule of a layered kind; the links the registry says are checked at write; and that the caller is the kind's one writer ([0005](/decisions/0005-the-store/#rules)). On a write to a tenant-scoped address, except key@'s own writes of `DataKeyWrap` ([0005](/decisions/0005-the-store/#rules)), it has key@ open the grant, and refuses the write unless the grant names the address's tenant and allows the verb ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)).
- **While `MaintenanceMode` is set,** every write except those of the restore command is refused ([0010](/decisions/0010-backup-and-recovery/#restore)).
- **A write that changes a watched kind** also writes its change-log row in the same transaction. A kind that nobody watches writes none, and a hot counter is one conditional update ([Item contract](#the-item-contract)).

### Watch

```proto
message WatchRequest {
  string kind = 1;
  string tenant = 2;          // empty: every tenant of the boundary the caller's rules allow
  uint64 resume_point = 3;    // the change-log sequence last seen; 0 starts from now
}
message WatchResponse {
  uint64 resume_point = 1;    // hand this back after a restart
  ChangeType type = 2;        // PUT or DELETE
  Item item = 3;
}
```

- **A watcher gets every change of the kind after its resume point,** in order, with none missed and none invented ([0005](/decisions/0005-the-store/#watch-and-the-resume-point)).
- **A resume point the change log no longer holds** is refused with `failed_precondition` and the reason `resume_point_expired`. The watcher lists the kind again and watches from the new point.
- **A config kind has no change log.** When the snapshot swaps, store@ delivers each changed config kind to its watchers with `resume_point` 0; a watcher that reconnects reads the kind again.

### Refusals

A refusal is a Connect error with the `Refusal` detail and a reason that names the rule, and it is an audit fact ([Contracts and errors](/reference/contracts/#errors)).

| Code | Reason | When |
|---|---|---|
| `invalid_argument` | `address`, `schema`, `ttl`, `index`, `batch` | The address does not fit the encoding; the value fails the kind's schema; a TTL is above the kind's maximum; an index entry is undeclared; a batch is too large |
| `permission_denied` | `rule`, `writer`, `grant` | No rule allows this actor, kind and verb; the caller is not the kind's writer or the actor named in the id; the grant is missing, for another tenant or not allowing the verb |
| `not_found` | `absent` | No such item, or an expired one |
| `already_exists` | `taken` | A `CREATE` found the address in use |
| `aborted` | `version` | An `UPDATE` or `DELETE` named a version that is no longer current |
| `failed_precondition` | `bound`, `direction`, `link`, `maintenance`, `resume_point_expired` | A bound or the direction rule refuses the value; a link does not resolve; `MaintenanceMode` is set; the resume point is gone |
| `unavailable` | `engine` | An engine or a source is down; store@ fails closed |

## Typed clients

- **A client is generated from the kind's Protobuf message** ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf)). In Go it is `store.Client[T Kind]`; in Rust a kind implements `trait Kind { type Id; type Value: buffa::Message; const NAME: &'static str; }` and the client is `Store<K: Kind>` ([0005](/decisions/0005-the-store/#typed-clients)).
- **The client does the encoding on this page:** the kind's name becomes its segment, the id is validated against [Address encoding](#address-encoding), and a sealed kind's value is sealed at key@ before it is written and opened after it is read ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)).
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

A driver is a separate binary behind one port, private to its owner ([0005](/decisions/0005-the-store/#drivers)). It sees items and bytes only, and never knows what a kind means. Two contracts serve store@'s four ports: the item contract for the durable and temp ports, and the source contract for the config and secret ports.

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

- **`Transact` is all or none.** A failed condition aborts it with `aborted` and the index of the first condition that failed.
- **`Transact` with one put and one condition is one conditional update,** not a transaction. A counter that many callers change depends on it ([0005](/decisions/0005-the-store/#drivers)).
- **`log` asks the driver to write a change-log row in the same transaction.** store@ sets it for a kind that some actor may watch and leaves it off for the rest. `TailLog` streams the rows from a sequence; a sequence the log no longer holds is `failed_precondition` with the reason `sequence_expired`.
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

- **AES-256-GCM, with a data key per purpose and generation.** The nonce comes from the cryptographic library, never from the caller: `crypto/cipher` with a random nonce in Go, `RandomizedNonceKey` of `aws-lc-rs` in Rust ([0006](/decisions/0006-keys-and-sealing/#algorithms)). Lengths are big-endian. The generation names the data key that sealed the value, so an older generation keeps opening what it sealed ([0006](/decisions/0006-keys-and-sealing/#rotation)).
- **The additional authenticated data binds the value to its full address** and to its own header: a value copied to another row, kind, tenant or boundary fails to open, and so does a header changed in place. A value that has to move is opened and sealed again ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)).
- **store@ validates the envelope and never opens it.** It checks that the version is known, that the purpose is `data`, the only purpose of a stored item ([0006](/decisions/0006-keys-and-sealing/#data-keys)), and that the length is at least the 34-byte minimum. A value that fails is refused with `invalid_argument` and the reason `schema`.
- **key@ uses the same layout for the cookies and the grants it seals,** with the context it is given in place of an item address. Neither is stored as an item ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)).
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
