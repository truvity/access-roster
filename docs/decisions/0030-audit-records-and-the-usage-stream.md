# 0030 — Audit records are OCSF events with one `unmapped.sluis` object, usage is a separate stream from the same call, and quota is idempotent and strict

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

[0029](/decisions/0029-the-audit-log/) decides how a log is laid out, sealed, witnessed, locked, encrypted and kept. This record decides what an entry holds: the audit record, the usage event that travels with it, and the quota service that writes balance effects into the usage log. v1's record format is dropped with no compatibility and no migration.

- **OCSF is the maintained and consumed security event schema.** The Open Cybersecurity Schema Framework (Linux Foundation, Apache-2.0) has written compatibility rules: a minor release only adds, a major release removes. Its release at the time of writing is 1.9.0 (2026-08-03). It has core classes for authentication, user, group and entity management and API activity, and `security_control` and `record_integrity` profiles. AWS Security Lake and the pipeline vendors read it.
- **Most sluis facts have a core home in 1.9.0;** a short list does not (the fields table below). OCSF has no class for issuing a certificate or a token, or for using a key. Its FAQ advises native producers to write an extension rather than use `unmapped`; that is advice, not a rule.
- **Billing and quota want a different record from security:** an account, a meter and an amount, with their own readers, retention and standard. OCSF has no usage class.
- **The log is sealed and verifiable,** so a hash must be reproducible by any implementation: one canonical serialisation (RFC 8785), and numbers that survive it.
- **Quota's callers retry.** Applications admit before work, confirm after it, cancel what did not happen and push top-ups that billing sold, and each call must count once (REQ-QUOTA-003, REQ-QUOTA-005). No RFC defines `X-Request-ID`; the IETF `Idempotency-Key` header is a working-group draft. Connect calls travel over HTTP, Unix sockets, Lambda invocations and in memory, and a header does not survive all of them.

v1's audit volume, measured in October 2026, is about 2.4 records a second at peak and about 75,000 a week. This record answers threats T-10, T-12, T-13, T-14, T-25 and T-26 of the [threat model](/security/threat-model/).

## Decision

### The record format

- **An audit record is an OCSF event of a core class of the pinned version** (REQ-AUDIT-111). The sluis action is `metadata.event_code`; product and release are `metadata.product.name` and `metadata.product.version` (REQ-AUDIT-116); the company is `metadata.tenant_uid`; the environment boundary is `metadata.log_name`, which the writer checks against the log; the record id is `metadata.uid`; the outcome is `status_id` with `status_code`; the trace id is `metadata.correlation_uid`.
- **The actor is `actor.user.uid = <actor>@<boundary>`** ([Names](/decisions/0002-families-of-actors/#names)) for every kind of principal; a person or external actor is a keyed pseudonym before the `@` ([Pseudonyms](/decisions/0029-the-audit-log/#pseudonyms)). `actor.user.type_id` is 1 user, 2 operator, 3 sluis actor, 4 workload or client; the OAuth client is `actor.application`, the upstream provider `actor.idp`.
- **Each release pins one OCSF version** in `metadata.version`; the first pins 1.9.0, and a `-dev` version is never pinned. An upgrade moves one minor release at a time in a deliberate pull request: CI compares the old and new generated schemas and fails when the action table or `unmapped.sluis` uses an item the new version deprecates (REQ-AUDIT-089), or when a new core attribute takes the name of an `unmapped.sluis` field, which the reviewer then moves. A new OCSF major release needs a new record.
- **Records are never rewritten.** A log holds records of several versions, and readers, the indexer and exporters handle each by the versions it names.
- **A record is RFC 8785 canonical JSON, and the same bytes travel end to end:** the emitter makes them, the transport carries them, the writer stores them unchanged, the reader returns them as opaque `bytes` beside typed envelope fields. Nothing re-encodes a record; proto3's JSON mapping would also turn 64-bit integers into strings.
- **Canonical rules:** UTF-8 strings, never normalised by the writer; integers within ±(2^53−1) and no floating point, so a 64-bit value that can exceed the bound is a string; times in integer milliseconds; no duplicate keys; bounded free text. The writer parses, canonicalises again and refuses a record whose bytes differ, then stores the bytes it received. A verifier hashes the stored bytes and never re-serialises.
- **The stored record is lean:** enum ids without captions (`activity_name` only for activity 99 or where the table names one), no `observables`, enrichments or `raw_data`, and no `unmapped` but `unmapped.sluis`.
- **A record validates in three places.** The writer enforces the JSON Schema 2020-12 generated from the action table (the pinned OCSF schema, `unmapped.sluis` and sluis's rules: no names, e-mail addresses or phone numbers, no floating point, bounded text), and is authoritative. Go and Rust emitters validate before they emit; a browser emitter does not. The pre-1.0 OCSF toolkit runs in CI only, on the table's example records, and one set of test vectors runs through the Go, Rust and TypeScript validators. The schema is one shared definitions document with a slim schema per action.
- **A record never carries a secret, an e-mail address, a name or a token** (REQ-AUDIT-003, REQ-AUDIT-037); a secret appears as a fingerprint and a revision.
- **A record may point at a trace; the trace never carries what the record says.** Telemetry is OTLP configured by `OTEL_*` ([0004](/decisions/0004-the-data-model/)), and the record carries the trace id in `metadata.correlation_uid` ([0016](/decisions/0016-telemetry/#pointing-from-audit-to-a-trace)).

### The sluis fields: `unmapped.sluis`

- **Every sluis fact without a core home goes in one object, `unmapped.sluis`, and nowhere else in `unmapped`** (REQ-AUDIT-112). `unmapped` is in the base event of every class and version, so the object survives down-mapping. A field with a core home uses it.
- **Its schema is sluis's own,** generated in CI from the action table (REQ-AUDIT-114), closed, with the fields each action requires; the writer refuses a record that does not validate (REQ-AUDIT-113).
- **No OCSF extension in 2.0.** The fields are versioned with the sluis release; within 2.x a field is only added, never removed or retyped (REQ-AUDIT-119). When OCSF gives a field a core home, the field is deprecated, new records use the home and old records keep the field. An extension comes only for a real consumer of typed fields, as a new record. Today no consumer needs one: a SIEM that flattens JSON queries `unmapped.sluis.key.algorithm` as easily, Security Lake takes OCSF 1.3 at most for a custom source and loads no extension, and the vendor mappings read on 2026-11-01 (OCSF's examples for CloudTrail, Okta and GitHub, and AWS's pipelines for Okta, Entra ID and GitHub) keep the rest in `unmapped`.
- **The fields at first** (the generated schema is the exact list):

  | Field | Shape | What it says |
  |---|---|---|
  | `sender_binding` | `type_id` (1 DPoP `jkt`, 2 mTLS `x5t#S256`, 99), `thumbprint` | A token's confirmation key |
  | `token` | `audience`, `scopes` | Of the token issued, refreshed or exchanged (no core home before 1.10) |
  | `assurance` | `acr`, `amr` | Authentication context class and methods |
  | `key` | `kind_id` (token signing, X.509 CA, SSH CA, log, sealing, data key), `algorithm`, `digest_algorithm`, `store` (`type_id`: software, cloud KMS, PIV token, other; `slot`) | The key used, created or destroyed; its id is in `resources[]` or `entity` |
  | `attestation` | `subject_id` (1 key, 2 device), `format`, `digest` | The statement itself is kept where the key or device is registered |
  | `config` | `digest`, `revision` | `revision` only on a reload |
  | `enrolment` | `proof_type_id`, `proof_digest` | The proof a node, device or workload gave |
  | `quota` | `meter`, `amount`, `balance` | For security readers; the usage stream is the source for roll-forward and billing |
  | `certificate` | `kind_id` (1 X.509, 2 SSH user, 3 SSH host), `serial_number`, `subject`, `sans`, `not_before`, `not_after`, `fingerprint`, `eku`, `ct_entry`, `ssh` (`key_id`, `principals`, `critical_options`, `extensions`, `ca_fingerprint`) | An issued or revoked certificate |
  | `actor_chain` | array of `<actor>@<boundary>` | Further hops of an RFC 8693 `act` chain, outermost first |
  | `approver` | `<actor>@<boundary>` | Who approved an impersonation or a break-glass action |

- **Out of `unmapped.sluis`:** the origin and sensitivity of a record kind, which its table entry gives ([Audit and telemetry by origin](/decisions/0004-the-data-model/#what-is-not-data)); the pseudonym key epoch, encoded in the pseudonym; the boundary and the configuration revision, which have core homes; and the roll-forward value of a console write, in OCSF's `updated_entity.data`.

### The action table is code, and the release identifies it

- **Each action's class and activity, required fields, sensitivity and declared meters are a table in code,** with its subject, target and request-id paths, which fields are filterable, facetable or searchable ([Search and the index](/decisions/0028-audit-pieces/#search-and-the-index)), and the origin and sensitivity of the kind. Each emitting product holds its own table. An entry's name is `metadata.event_code`, with one event code per grant type, so no field carries the grant type.
- **The records' JSON Schemas are generated from the table in CI,** published with the release and compiled into the emitters and the writer; Go, Rust and TypeScript types come from the same source.
- **No catalogue document is stored at run time, and no record carries a catalogue field** (REQ-AUDIT-115). Product name, release and event code identify the entry in force. The log holds no schema; witnesses cosign the log, not schemas; an auditor takes the schema from the release a record names.
- **A writer knows the table of every release that emits to it** and is upgraded before its emitters. For an application outside sluis, its generated schema is a release artefact the operator installs beside the writer, selected by `metadata.product`.

### The class mapping

Checked against OCSF 1.9.0 on 2026-11-01.

| sluis action | OCSF class / activity |
|---|---|
| Sign-in (browser, passkey, upstream OpenID Connect), recovery sign-in | 3002 Authentication / 1 Logon |
| Sign-out, end of a session | 3002 Authentication / 2 Logoff |
| Step-up ([Step-up](/decisions/0017-identity-and-sign-in/#step-up)) | 3002 / 1 Logon, `is_mfa` true, `auth_factors`, the session's `session.uid`, `is_new_logon` false, `activity_name` "Step-Up" |
| Token grant, refresh, exchange, revocation | 3002 / 99 with `activity_name`; an impersonating exchange is 7 Account Switch, `account_switch_type_id` 2, with `unmapped.sluis.approver` |
| A grant of scopes | 3003 Authorize Session / 1 Assign Privileges, scopes in `privileges[]` |
| Certificate (X.509 or SSH) issued or revoked | 3002 / 99 "Certificate Issue" or "Certificate Revoke"; profile digest in `policy.version`, revocation reason in `status_detail` |
| Credential minted to or revoked from a principal | 3007 User Management / 18, 19 Add, Remove Programmatic Credentials |
| Enrolment of a node, device or workload | 3004 Entity Management / 6 Enroll, 7 Unenroll |
| Passkey registered or removed | 3007 / 12, 13 Enable, Disable MFA Factors; the credential id in `resources[]` |
| Person first seen, roster change, role assignment | 3007 User Management, 3006 Group Management |
| Console write (configuration, client registration, lowered limit) | 3004 / 1, 3, 4; value in `updated_entity.data`, revision in `entity.version` |
| Quota call | 6003 API Activity / 1, 3, 4, request id in `api.request.uid` |
| Audit read (search, get, tail, proof) | 6003 / 2 Read |
| Audit export | 1008 Event Log Activity / 3 Export |
| Key use (sign, decrypt) | 6003 / 99 "Sign" or "Decrypt", the key in `resources[]` |
| Key created, rotated or destroyed, including a company's data key deleted by shredding | 3004 / 1, 3, 4, the key in `entity` |
| Configuration reload | 6002 Application Lifecycle / 99 "Reload" |
| Writer and log lifecycle | 1008 Event Log Activity |

- **A policy decision is part of the record of the action it gates,** in the `security_control` profile (`action_id`, `authorizations`, `policy`), not a record of its own.
- **Token stages stay activity 99.** Activities 3 to 5 are described as Kerberos tickets and no vendor mapping read on 2026-11-01 uses them for OAuth. A step-up is a Logon because it is a second authentication of an open session, so a rule on failed logons sees it; a token grant is not a logon.
- **A refresh rotation names two tokens:** `session.uid` is the family, `session.credential_uid` the presented token, `authentication_token` the new one.
- **The actor chain is not `delegation`,** which in 1.9.0 exists only through the `ai_operation` profile and holds identifiers only. The acting party is `actor.user`, the subject `user`.
- **An issued certificate is not Authentication's `certificate` object,** which means a presented certificate (a sign-in with a client certificate uses it). The field moves if OCSF adds a home for issuance (OCSF issue 1513).

### Export

- **The audit export in 2.0 is NDJSON of OCSF events,** decrypted for the caller's grant. It adds enum captions, `observables` and the `record_integrity` attestation, whose fingerprint (SHA-256 over the RFC 8785 bytes) and chain id point back to the log entry, and keeps `metadata.log_name` and `unmapped.sluis` as written.
- **Target-specific exporters are drivers, later.** Security Lake takes Parquet and OCSF 1.3 at most (checked 2026-10-31), so its exporter maps down; down-mapping lives in the exporter, never in the record.

### The usage stream

- **Usage is a separate log kind,** written by the same writer, with its own prefix (or bucket), checkpoints, witnesses, lock mode, readers and retention ([0029](/decisions/0029-the-audit-log/)). It has no key of its own: its writer's one log key signs both kinds, and each signed head names its log. Usage entries are encrypted per company to the company's usage data key, not its audit key ([Encryption and crypto-shredding](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding), [0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#two-classes-of-data-two-keys)).
- **Each stream declares its own retention,** with no default in production, so neither period binds the other ([Retention](/decisions/0029-the-audit-log/#retention)).
- **The usage log has no search index** (REQ-AUDIT-098). Its readers are `quota` and the finance export, and nothing else.
- **A usage event is CloudEvents 1.0 (1.0.2), structured mode, JSON in RFC 8785 form:**

  | Attribute | Value |
  |---|---|
  | `specversion` | `1.0` |
  | `id` | `<message id>/<n>`: the audit record's `metadata.uid` (UUIDv7, RFC 9562) and the event's position in the usage part, from 0 |
  | `source` | `<actor>@<boundary>`, the emitting actor |
  | `type` | the meter event, named by the action table |
  | `subject` | the account, the aggregation key, as in OpenMeter |
  | `time` | the time of use |
  | `datacontenttype` | `application/json` |
  | `data` | the unit, a signed integer amount, the request id where there is one, and for quota the named balance. No personal data ([0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#two-classes-of-data-two-keys)) |

- **The idempotency key is `source` plus `id`,** as CloudEvents and OpenMeter deduplicate; a bare message id would give two meters of one message one `id`. The writer removes duplicate messages by `metadata.uid`, so a usage event is written exactly as often as its audit record.
- **Only `quota` sends a balance effect.** An application's usage part carries meters only; the writer refuses a balance effect from any other actor.
- **The finance export is a table derived from the usage log, served by `quota`,** with FinOps FOCUS 1.4 column names where they fit (`ChargePeriodStart`, `ChargePeriodEnd`, `BillingAccountId`, `SubAccountId`, `SkuMeter`, `ConsumedQuantity`, `ConsumedUnit`). sluis holds no prices. The export can be rebuilt at any time and is never the record; a metering system such as OpenMeter reads it, or the log with a read grant. A closed period's statement, which billing pulls and which is an entry of the usage log, is [0051](/decisions/0051-the-finance-export-is-a-statement-per-account-and-period-closed-once-anchored-in-the-usage-log-and-pulled/).

### Usage is derived from the same event, once

- **The emitter library builds both parts of a message from one call.** The application describes the action once, with its meters; the library gives the message one id, used as `metadata.uid` and as the prefix of each usage `id`, and sends one message. No call emits a usage part alone or an audit part twice.
- **The table entry declares the meters an action may carry,** with units; the writer refuses an undeclared meter, an amount out of bounds or an id that is not the record's. What a meter is, which outcomes bill, how a meter stays fixed over releases and which period an event belongs to are [0040](/decisions/0040-meters-and-usage-evidence/).
- **Every usage event has an audit record,** so the two cannot disagree about what happened. A periodic gauge is an audited action of its own.
- **The writer splits the message and registers both logs' sealed batches in one atomic state batch,** with the removed duplicate ids and its transport cursor (REQ-AUDIT-094; sealing is in [0029](/decisions/0029-the-audit-log/)). A crash leaves both or neither.
- **A retried quota call reuses its message (the outbox).** `quota` writes the message it is about to send into its state in the same atomic batch as the balance or reservation change, with the request id; a relay sends and clears it. A retry with the same request id sends the stored message with the same id, which the writer deduplicates; after a crash the relay sends it on restart. A balance changes once and has one usage event however often the call is retried.

### Quota

- **Quota meters by default and enforces per policy rule,** for chosen subjects or audiences ([Four pieces](/decisions/0028-audit-pieces/#four-pieces)). It runs beside sluis, sharing its driver instances, or on its own.
- **The API is a Connect service of unary calls:** `Admit`, `Confirm`, `Cancel`, `TopUp`, `Adjust`, and `Balance`, which has no side effects and may use GET; the contract fixes the names. The TypeScript deliverable is a Connect client on connect-es.
- **Every changing call carries a canonical `request_id` field,** which survives every transport. `entry` also accepts `Idempotency-Key` and copies it in; both with different values is refused. A request id is scoped to the client and the method and remembered for 24 hours, as ephemeral state, with the id of the message it produced. A reused id with another payload is refused; a duplicate while the first runs is a conflict (HTTP 409, Connect `aborted`); an exhausted balance is `resource_exhausted` (HTTP 429) with `Retry-After`.
- **Reservations:** `Admit` reserves an amount with a time to live declared per rule (5 minutes by default); `Confirm` settles the actual amount, at most the reserved one unless the rule allows overage; `Cancel` releases. An expired reservation is released and counted as expired, so an honest crash costs nothing and abuse shows.
- **Top-ups, corrections, refunds:** `TopUp` takes positive amounts only, from declared clients whose policy allows `quota.topup` on that balance, so it cannot drain one. A correction is an `Adjust` with a reason and either sign, by a declared client or an operator with step-up. A refund is an `Adjust` naming the confirmed event it refunds, bounded by its amount, once. Each is one message with enough data to roll the balance forward (REQ-AUDIT-019).
- **Amounts are signed 64-bit integers in a unit declared per meter and balance** (`requests`, `cents`); no decimals anywhere.
- **A balance belongs to an account,** issued at run time under a declared plan template ([0004](/decisions/0004-the-data-model/#profiles), [0039](/decisions/0039-quota-allowance/)); rules map subjects, clients or a company to it, and its key (boundary, company, account, meter) carries no personal data. Balance effects live in the usage log and only `quota` writes them (REQ-QUOTA-004, REQ-QUOTA-010); an application that wants to change a balance calls quota.
- **Limits** are a rate (a token bucket, ephemeral) or a cap per UTC day or month. They are declared in a plan; an operator may lower one, tighten-only (REQ-QUOTA-013). Rate-limiting by address is the edge's.
- **The data follows the origin model** ([Quota by origin](/decisions/0039-quota-allowance/)): only `quota` writes balances ([One writer per kind](/decisions/0004-the-data-model/#one-writer-per-kind)); balances, top-ups and adjustments are backed up and rolled forward from quota's events in the usage log; reservations, rate buckets and request ids are not backed up, and the last 24 hours of request ids are rebuilt from the usage log; meters, hourly aggregates and the finance export are derived by `quota`, which follows the usage log by checkpoint. An hourly aggregate lists its event ids, so aggregates sum to the facts (REQ-QUOTA-012). After a restore an outbox message counts as unsent.
- **Enforcement is strict in 2.0:** never more than the limit under concurrent requests (REQ-QUOTA-002), by compare-and-set on the state port ([The port](/decisions/0005-the-store/#the-store-api)). Where a rule enforces, the minting actor asks `quota` before it mints; `policy` has no state and no network.
- **Enforcement is switched on in production only after a load test of the mint path with enforcement on** (REQ-QUOTA-008). Whether a soft mode is added is decided after that test; a soft mode would exceed a limit by at most one grant per instance (REQ-QUOTA-009). The test, the bound on the outbox and the window after a restore are [0053](/decisions/0053-quota-consistency-and-failure-are-measured-per-state-driver-before-enforcement-is-switched-on/).
- **An enforcing rule declares whether exhaustion blocks or allows overage, and whether an unreachable quota fails open or closed** (REQ-QUOTA-006, REQ-QUOTA-011). There is no default; `sluis config check` refuses a rule that declares neither.

## Consequences

- A decrypted record is an OCSF event of a published version; an OCSF-only tool finds every core field and sees `unmapped.sluis` as source data. OCSF tells consumers not to rely on structure there, so keeping it stable, and publishing its schema with each release, is sluis's job. There is no extension to own.
- A field that gains a core home (the token audience in 1.10) moves at an upgrade, and one log then holds two shapes. OCSF keeps deprecating classes (1.9.0 replaced Account Change by User Management); the CI comparison catches it.
- Some actions fit OCSF only approximately (token and certificate stages at activity 99, key use and quota as API Activity, step-up as a Logon); a security tool sees them in OCSF terms.
- A writer is upgraded before its emitters, because no catalogue is stored in the log.
- An OCSF record is about 2.8 times a minimal record of sluis's own: about 1.1 KB for a sign-in (measured 2026-10-31), plus up to a few hundred bytes of `unmapped.sluis` on a certificate issuance; a few gigabytes a year per boundary at v1's volume. Encrypted records do not compress.
- The integer bound and the canonical check refuse records other OCSF producers could send; emitters write large counters as strings.
- Billing and quota read a stream made for them and never parse security records, at the cost of a second set of checkpoints to witness and copy and a second retention to declare. One emit and one atomic registration keep the logs consistent; a writer outage stops both, and a bad usage part fails its whole message.
- A retry counts once within 24 hours on any transport, and again after that. Only `entry`'s mapping follows the header draft.
- Balances are money-like: one writer, a backup and a roll-forward, so a restore loses no top-up that reached the log. Quota carries an outbox and a relay.
- Strict enforcement puts a compare-and-set on the mint path, a consensus round trip per admitted request on rqlite, which is why the load test gates it. Meters cost nothing on the hot path but lag it by the seal interval.
- Every enforcing rule carries two declared lines, so each risk choice is reviewed. The TypeScript client is one more artefact on the [release train](/decisions/0013-release-train-packaging-and-distribution/).

## Roads not taken

- **A sluis OCSF extension, full or only for the homeless fields.** What the OCSF FAQ advises, but a registry entry, a source tree, a version and a compile step in every strict consumer, dropped by Security Lake, for typed fields no consumer reads yet; possible later in a minor release.
- **Plain OCSF with the facts spread over `policy.data`, `resources[].data` and `entity.data`.** Complete, but untyped slots that only the table explains, and no one place for a SIEM to look.
- **New event classes for token, certificate and key activity.** An exact fit, but an extension class is invisible to rules keyed on core classes.
- **Core tags and labels for the homeless fields.** Down-mapping-safe, but strings meant for classification, and still an unregistered schema of keys.
- **A catalogue document in the log, versioned in every record.** A self-describing log, at the cost of a second versioned artefact and a field in every record; the release already identifies the table.
- **Authentication's ticket activities for token stages.** In the class, but described as Kerberos, so they mislead.
- **No canonical form, deterministic Protobuf or CBOR.** Without RFC 8785 two implementations hash differently; the binary forms are not canonical across languages and no OCSF tool reads them.
- **A format of sluis's own (v1's Protobuf core, or a minimal record plus an OCSF exporter), CADF, the OpenTelemetry log model or ECS.** Invented formats need a mapping in every exporter; CADF is unmaintained, OpenTelemetry has no audit conventions, ECS is merging into OpenTelemetry.
- **Usage in the audit log, or derived from it by the writer.** One log, but billing in a security schema, one retention for both, and a writer parsing records for amounts that are often not there.
- **A separate usage writer, or a usage API that emits alone.** A dual write, and a second path that can emit twice or without an audit record.
- **`X-Request-ID`, or only the header, or only the field.** No RFC defines `X-Request-ID`; a header does not survive Lambda or in-memory calls; HTTP clients expect the header.
- **Soft enforcement in 2.0, or defaults for exhaustion and outage.** Two guarantees to build before a load test shows a need, and a default silently fails closed for everyone or silently stops enforcing.

## Follow-ups

- Emitter, action table and metering: [#841](https://github.com/truvity/sluis/issues/841).
- Quota service, its contract and the finance export: [#915](https://github.com/truvity/sluis/issues/915).
- A conditional counter adjust on the state port, only if the load test shows contention on balances ([0053](/decisions/0053-quota-consistency-and-failure-are-measured-per-state-driver-before-enforcement-is-switched-on/#pending-decision-lines)): [#1145](https://github.com/truvity/sluis/issues/1145). Delete, list and watch are v1 parity: [#1009](https://github.com/truvity/sluis/issues/1009).
- The quota installation's front ([0052](/decisions/0052-a-quota-installation-is-fronted-by-service-identity-for-services-and-exchanged-tokens-for-people/)): [#1026](https://github.com/truvity/sluis/issues/1026).
