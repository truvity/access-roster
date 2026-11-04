# 0030 — Audit records are OCSF events with one `unmapped.sluis` object, and usage is a separate stream from the same call

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

[0029](/decisions/0029-the-audit-log/) decides how a project's logs are laid out, sealed, witnessed, locked, encrypted and kept. This record decides what an entry holds: the audit record, and the usage facts that travel with it. v1's record format is dropped with no compatibility and no migration. The allowance that `quota` counts down, and its facts, are [0039](/decisions/0039-quota-allowance/).

- **OCSF is the maintained and consumed security event schema.** The Open Cybersecurity Schema Framework (Linux Foundation, Apache-2.0) has written compatibility rules: a minor release only adds, a major release removes. Its release at the time of writing is 1.9.0 (2026-08-03). It has core classes for authentication, user, group and entity management and API activity, and `security_control` and `record_integrity` profiles. AWS Security Lake and the pipeline vendors read it.
- **Most sluis facts have a core home in 1.9.0;** a short list does not (the fields table below). OCSF has no class for issuing a certificate or a token, or for using a key. Its FAQ advises native producers to write an extension rather than use `unmapped`; that is advice, not a rule.
- **Billing wants a different record from security:** a tenant, a meter and an amount, with their own readers, retention and standard. OCSF has no usage class.
- **The log is sealed and verifiable,** so a hash must be reproducible by any implementation: one canonical serialisation (RFC 8785), and numbers that survive it.
- **Several projects emit into one boundary's audit** ([0028](/decisions/0028-audit-pieces/#one-audit-per-boundary)): sluis, the infrastructure and each product, each with actions of its own and its own releases.

v1's audit volume, measured in October 2026, is about 2.4 records a second at peak and about 75,000 a week. This record answers threats T-10, T-12, T-13, T-14, T-25 and T-26 of the [threat model](/security/threat-model/).

## Decision

### The record format

- **An audit record is an OCSF event of a core class of the pinned version** (REQ-AUDIT-111). The action is `metadata.event_code`; product and release are `metadata.product.name` and `metadata.product.version` (REQ-AUDIT-116); the tenant is `metadata.tenant_uid`; the boundary is `metadata.log_name`, which the writer checks against the log; the record id is `metadata.uid`; the outcome is `status_id` with `status_code`; the trace id is `metadata.correlation_uid`.
- **A health `check` call is not audited; every other call is** (decided 2026-11-04). The health protocol's `check` answers whether a process is up and reads or changes nothing, so a record for it would only grow the log without end: an idle installation would write entries all day from its probes. Every real call, a refusal included, is audited, so the exemption is for the `check` method alone and for no caller or kind of caller ([REQ-AUDIT-161](/requirements/audit/#REQ-AUDIT-161)).
- **The project is the log's own,** like the boundary, so no record field names it. The writer refuses a record whose `metadata.product.name` its project does not declare, so one project's emitter cannot write as another's.
- **The actor is `actor.user.uid = <actor>@<boundary>`** for an actor of sluis ([0002](/decisions/0002-families-of-actors/#names)), and the emitting service's own name for a product; a person or external actor is a keyed pseudonym before the `@` ([Pseudonyms](/decisions/0029-the-audit-log/#pseudonyms)). `actor.user.type_id` is 1 user, 2 operator, 3 sluis actor, 4 workload or client; the OAuth client is `actor.application`, the upstream provider `actor.idp`.
- **Each release pins one OCSF version** in `metadata.version`; the first pins 1.9.0, and a `-dev` version is never pinned. An upgrade moves one minor release at a time in a deliberate pull request: CI compares the old and new generated schemas and fails when the action table or `unmapped.sluis` uses an item the new version deprecates (REQ-AUDIT-089), or when a new core attribute takes the name of an `unmapped.sluis` field, which the reviewer then moves. A new OCSF major release needs a new record.
- **Records are never rewritten.** A log holds records of several versions, and readers, the indexer and exporters handle each by the versions it names.
- **A record is RFC 8785 canonical JSON, and the same bytes travel end to end:** the emitter makes them, the transport carries them, the writer stores them unchanged inside the sealed entry, the reader returns them as opaque `bytes` beside typed envelope fields. Nothing re-encodes a record; proto3's JSON mapping would also turn 64-bit integers into strings.
- **Canonical rules:** UTF-8 strings, never normalised by the writer; integers within ±(2^53−1) and no floating point, so a 64-bit value that can exceed the bound is a string; times in integer milliseconds; no duplicate keys; bounded free text. The writer parses, canonicalises again and refuses a record whose bytes differ, then stores the bytes it received. A verifier hashes the stored bytes and never re-serialises.
- **The stored record is lean:** enum ids without captions (`activity_name` only for activity 99 or where the table names one), no `observables`, enrichments or `raw_data`, and no `unmapped` but `unmapped.sluis`.
- **A record validates in three places.** The writer enforces the JSON Schema 2020-12 of the project's catalogue (the pinned OCSF schema, `unmapped.sluis` and sluis's rules: no names, e-mail addresses or phone numbers, no floating point, bounded text), and is authoritative. Go and Rust emitters validate before they emit; a browser emitter does not. The pre-1.0 OCSF toolkit runs in CI only, on the table's example records, and one set of test vectors runs through the Go, Rust and TypeScript validators. The schema is one shared definitions document with a slim schema per action.
- **A record never carries a secret, an e-mail address, a name or a token** (REQ-AUDIT-003, REQ-AUDIT-037); a secret appears as a fingerprint and a revision. A sealed or hashed value of a kind never appears in a record ([0004](/decisions/0004-the-data-model/#treatment)).
- **A record may point at a trace; the trace never carries what the record says.** The record carries the trace id in `metadata.correlation_uid` ([0016](/decisions/0016-telemetry/#pointing-from-audit-to-a-trace)).

### The sluis fields: `unmapped.sluis`

- **Every sluis fact without a core home goes in one object, `unmapped.sluis`, and nowhere else in `unmapped`** (REQ-AUDIT-112). `unmapped` is in the base event of every class and version, so the object survives down-mapping. A field with a core home uses it.
- **Its schema is sluis's own,** generated in CI from the action table (REQ-AUDIT-114), closed, with the fields each action requires; the writer refuses a record that does not validate (REQ-AUDIT-113).
- **No OCSF extension.** The fields are versioned with the sluis release; within 2.x a field is only added, never removed or retyped (REQ-AUDIT-119). When OCSF gives a field a core home, the field is deprecated, new records use the home and old records keep the field. An extension comes only for a real consumer of typed fields, as a new record. Today no consumer needs one: a SIEM that flattens JSON queries `unmapped.sluis.key.algorithm` as easily, Security Lake takes OCSF 1.3 at most for a custom source and loads no extension, and the vendor mappings read on 2026-11-01 (OCSF's examples for CloudTrail, Okta and GitHub, and AWS's pipelines for Okta, Entra ID and GitHub) keep the rest in `unmapped`.
- **The fields at first** (the generated schema is the exact list):

  | Field | Shape | What it says |
  |---|---|---|
  | `sender_binding` | `type_id` (1 DPoP `jkt`, 2 mTLS `x5t#S256`, 99), `thumbprint` | A token's confirmation key |
  | `token` | `audience`, `scopes` | Of the token issued, refreshed or exchanged (no core home before 1.10) |
  | `assurance` | `acr`, `amr` | Authentication context class and methods |
  | `key` | `kind_id` (token signing, X.509 CA, SSH CA, log, wrapping, data key), `algorithm`, `digest_algorithm`, `store` (`type_id`: software, cloud KMS, PIV token, other; `slot`) | The key used, created or destroyed; its id is in `resources[]` or `entity` |
  | `attestation` | `subject_id` (1 key, 2 device), `format`, `digest` | The statement itself is kept where the key or device is registered |
  | `config` | `kind`, `seq`, `digest` | The signed config document a start or a reload took ([0005](/decisions/0005-the-store/#the-snapshot)) |
  | `enrolment` | `proof_type_id`, `proof_digest` | The proof a node, device or workload gave |
  | `quota` | `name`, `amount`, `left` | An admit, a refusal or a push of an allowance, for security readers and for the restore's roll-forward ([0010](/decisions/0010-backup-and-recovery/#roll-forward)); the usage stream is the source for billing |
  | `certificate` | `kind_id` (1 X.509, 2 SSH user, 3 SSH host), `serial_number`, `subject`, `sans`, `not_before`, `not_after`, `fingerprint`, `eku`, `ct_entry`, `ssh` (`key_id`, `principals`, `critical_options`, `extensions`, `ca_fingerprint`) | An issued or revoked certificate |
  | `actor_chain` | array of `<actor>@<boundary>` | Further hops of an RFC 8693 `act` chain, outermost first |
  | `approver` | `<actor>@<boundary>` | Who approved an impersonation or a break-glass action |

- **Out of `unmapped.sluis`:** the treatment and storage class of a kind, which the kind registry gives ([0004](/decisions/0004-the-data-model/#kinds)); the pseudonym key epoch, encoded in the pseudonym; the boundary, which has a core home; and the roll-forward value of a console write, in OCSF's `updated_entity.data`.

### The action table is code, and the release identifies it

- **Each project's actions are a table in code,** in the project's own release: each action's class and activity, required fields, the treatment of each field and the meters it may carry, with its subject, target and request-id paths and which fields are filterable, facetable or searchable ([Search and the index](/decisions/0028-audit-pieces/#search-and-the-index)). An entry's name is `metadata.event_code`, with one event code per grant type, so no field carries the grant type.
- **The records' JSON Schemas are generated from the table in CI,** published with the release and compiled into the emitters; Go, Rust and TypeScript types come from the same source.
- **The catalogue is the table with its schemas, published as config.** The publishing pipeline signs each release's table and its generated schemas as one item of the `AuditCatalogue` config kind, so the table and its schemas move together in one version. store@ loads it with the rest of the snapshot ([0005](/decisions/0005-the-store/#the-snapshot)), and the writer, the indexer and the reader read it through the data port.
- **The catalogue of a release is published before its emitters run.** The writer validates each record against the catalogue that its `metadata.product` names, and refuses a record whose release has no catalogue. A product's new release therefore needs no new writer.
- **No catalogue is stored in the log, and no record carries a catalogue field** (REQ-AUDIT-115). Product name, release and event code identify the entry in force. Witnesses cosign the log, not schemas; an auditor takes the schema from the release a record names.

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
| Tenant created by a product's push, suspended or erased | 3004 / 1, 3, 4, the tenant in `entity` |
| Quota admit, refusal or allowance push | 6003 API Activity / 1, 3, 4, request id in `api.request.uid` |
| Audit read (search, get, tail, proof) | 6003 / 2 Read |
| Audit export | 1008 Event Log Activity / 3 Export |
| Key use (sign, open) | 6003 / 99 "Sign" or "Open", the key in `resources[]` |
| Key created, rotated or destroyed, including a tenant's data key wraps deleted at its exit | 3004 / 1, 3, 4, the key in `entity` |
| Configuration start or reload | 6002 Application Lifecycle / 99 "Reload" |
| Writer and log lifecycle | 1008 Event Log Activity |

- **A policy decision is part of the record of the action it gates,** in the `security_control` profile (`action_id`, `authorizations`, `policy`), not a record of its own.
- **Token stages stay activity 99.** Activities 3 to 5 are described as Kerberos tickets and no vendor mapping read on 2026-11-01 uses them for OAuth. A step-up is a Logon because it is a second authentication of an open session, so a rule on failed logons sees it; a token grant is not a logon.
- **A refresh rotation names two tokens:** `session.uid` is the session chain, `session.credential_uid` the presented token, `authentication_token` the new one.
- **The actor chain is not `delegation`,** which in 1.9.0 exists only through the `ai_operation` profile and holds identifiers only. The acting party is `actor.user`, the subject `user`.
- **An issued certificate is not Authentication's `certificate` object,** which means a presented certificate (a sign-in with a client certificate uses it). The field moves if OCSF adds a home for issuance (OCSF issue 1513).

### Export

- **The audit export is NDJSON of OCSF events,** opened for the caller's grant ([0028](/decisions/0028-audit-pieces/#access)), one project and log kind per export. It adds enum captions, `observables` and the `record_integrity` attestation, whose fingerprint (SHA-256 over the RFC 8785 bytes) and chain id point back to the log entry, and keeps `metadata.log_name` and `unmapped.sluis` as written.
- **Target-specific exporters are drivers, later.** Security Lake takes Parquet and OCSF 1.3 at most (checked 2026-10-31), so its exporter maps down; down-mapping lives in the exporter, never in the record.

### The usage stream

- **Usage is a separate log kind,** written by the project's writer, with its own prefix, checkpoints, witnesses, lock mode, readers and retention ([0029](/decisions/0029-the-audit-log/#projects)). It has no key of its own: the writer's one log key signs both kinds, and each signed checkpoint names its log. Usage entries are sealed under the tenant's `evidence` key, like audit entries ([Encryption and crypto-shredding](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding)).
- **Each stream declares its own retention,** with no default in production, so neither period binds the other ([Retention](/decisions/0029-the-audit-log/#retention)).
- **The usage log has no search index** (REQ-AUDIT-098). It is read by those a binding grants `usage` ([0028](/decisions/0028-audit-pieces/#access)). A product builds its billing log from it outside sluis, in the `billing/` prefix of its project ([0039](/decisions/0039-quota-allowance/#the-billing-log-is-outside-sluis)); sluis holds no prices.
- **A usage fact is a CloudEvents 1.0 (1.0.2) event, structured mode, JSON in RFC 8785 form:**

  | Attribute | Value |
  |---|---|
  | `specversion` | `1.0` |
  | `id` | `<message id>/<n>`: the audit record's `metadata.uid` (UUIDv7, RFC 9562) and the event's position in the usage part, from 0 |
  | `source` | the emitter: `<actor>@<boundary>` for an actor of sluis, the service's own name for a product |
  | `type` | the meter event, named by the catalogue |
  | `subject` | the aggregation key: the tenant, or a key of the product's own within the tenant, never personal data |
  | `time` | the time of use |
  | `datacontenttype` | `application/json` |
  | `data` | the unit, a signed integer amount, the request id where there is one, and for `quota` the quota name and the units left. No personal data |

- **A usage fact carries no personal data** (REQ-AUDIT-132): no pseudonym, subject, e-mail address or free text. Caps and allowances are per tenant, so no consumer needs a person in it.
- **The idempotency key is `source` plus `id`,** as CloudEvents and OpenMeter deduplicate; a bare message id would give two meters of one message one `id`. The writer removes duplicate messages by `metadata.uid`, so a usage fact is written exactly as often as its audit record.
- **Only `quota` sends the facts of an allowance.** An application's usage part carries meters only; the writer refuses an admit, a refusal or a push from any other emitter ([0039](/decisions/0039-quota-allowance/#countdown-and-refusal)).

### Usage is derived from the same event, once

- **The emitter library builds both parts of a message from one call.** The application describes the action once, with its meters; the library gives the message one id, used as `metadata.uid` and as the prefix of each usage `id`, and sends one message. No call emits a usage part alone or an audit part twice.
- **The catalogue entry declares the meters an action may carry,** with units; the writer refuses an undeclared meter, an amount out of bounds or an id that is not the record's. What a meter is, which outcomes bill, how a meter stays fixed over releases and which period an event belongs to are [0040](/decisions/0040-meters-and-usage-evidence/).
- **Every usage fact has an audit record,** so the two cannot disagree about what happened. A periodic gauge is an audited action of its own.
- **The writer splits the message and registers both logs' sealed batches in one conditional write of its state** (REQ-AUDIT-094; sealing is in [0029](/decisions/0029-the-audit-log/#sealing)). A crash leaves both or neither.

## Consequences

- A decrypted record is an OCSF event of a published version; an OCSF-only tool finds every core field and sees `unmapped.sluis` as source data. OCSF tells consumers not to rely on structure there, so keeping it stable, and publishing its schema with each release, is sluis's job. There is no extension to own.
- A field that gains a core home (the token audience in 1.10) moves at an upgrade, and one log then holds two shapes. OCSF keeps deprecating classes (1.9.0 replaced Account Change by User Management); the CI comparison catches it.
- Some actions fit OCSF only approximately (token and certificate stages at activity 99, key use and quota as API Activity, step-up as a Logon); a security tool sees them in OCSF terms.
- A product's release publishes its catalogue before it emits, and a writer then accepts it without an upgrade. A record whose catalogue is missing is quarantined, not lost.
- An OCSF record is about 2.8 times a minimal record of sluis's own: about 1.1 KB for a sign-in (measured 2026-10-31), plus up to a few hundred bytes of `unmapped.sluis` on a certificate issuance; a few gigabytes a year per boundary at v1's volume. Sealed records do not compress.
- The integer bound and the canonical check refuse records other OCSF producers could send; emitters write large counters as strings.
- Billing and quota read a stream made for them and never parse security records, at the cost of a second set of checkpoints to witness and a second retention to declare. One emit and one conditional write keep the logs consistent; a writer outage stops both, and a bad usage part fails its whole message.
- Usage outlives the tenant's personal data under its `evidence` key, so a bill can be disputed after the tenant has left, and the exit still destroys everything personal.

## Roads not taken

- **A sluis OCSF extension, full or only for the homeless fields.** What the OCSF FAQ advises, but a registry entry, a source tree, a version and a compile step in every strict consumer, dropped by Security Lake, for typed fields no consumer reads yet; possible later in a minor release.
- **Plain OCSF with the facts spread over `policy.data`, `resources[].data` and `entity.data`.** Complete, but untyped slots that only the table explains, and no one place for a SIEM to look.
- **New event classes for token, certificate and key activity.** An exact fit, but an extension class is invisible to rules keyed on core classes.
- **Core tags and labels for the homeless fields.** Down-mapping-safe, but strings meant for classification, and still an unregistered schema of keys.
- **A catalogue document in the log, versioned in every record.** A self-describing log, at the cost of a second versioned artefact in the log and a field in every record; the release already identifies the catalogue, which is config.
- **The catalogue as a release artefact installed beside the writer.** Every product release would need an operator to install a file and restart the writer; as a signed config document it reloads with the snapshot.
- **Authentication's ticket activities for token stages.** In the class, but described as Kerberos, so they mislead.
- **No canonical form, deterministic Protobuf or CBOR.** Without RFC 8785 two implementations hash differently; the binary forms are not canonical across languages and no OCSF tool reads them.
- **A format of sluis's own (v1's Protobuf core, or a minimal record plus an OCSF exporter), CADF, the OpenTelemetry log model or ECS.** Invented formats need a mapping in every exporter; CADF is unmaintained, OpenTelemetry has no audit conventions, ECS is merging into OpenTelemetry.
- **Usage in the audit log, or derived from it by the writer.** One log, but billing in a security schema, one retention for both, and a writer parsing records for amounts that are often not there.
- **A separate usage writer, or a usage API that emits alone.** A dual write, and a second path that can emit twice or without an audit record.
- **A pseudonym in the usage fact.** No consumer needs it: caps are per tenant, and it would put personal data in the evidence.

## Follow-ups

- Emitter, catalogue and the usage stream: [#841](https://github.com/truvity/sluis/issues/841).
