# 0034 — An end user is a person with five states, erased by deleting its records, and upstream signals end sessions or suspend and erase

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-03

Proposal: [issue #1024](https://github.com/truvity/sluis/issues/1024).

## Context

[0019](/decisions/0019-person-and-upstream-link/) gives a person an opaque random subject, a link to the upstream account by the pair of issuer and subject claim, and four computed states: live, held, suspended and left. For the customer-identity milestone [#1024](https://github.com/truvity/sluis/issues/1024) collects 25 live requirement records that refer to "the defined state machine" which does not exist, a corporate-connection rule from the workforce idea, a pairwise design whose records disagree with each other, and the questions of erasure and export. A customer-identity upstream also has no directory pass, so three more gaps follow from how sluis learns that an account changed.

- **The state names.** [REQ-ACCT-011](/requirements/acct/#REQ-ACCT-011) wants transitions limited to a state machine; the withdrawn account records named five other states.
- **Pairwise subjects.** [REQ-CIAM-003](/requirements/ciam/#REQ-CIAM-003) gives each sector "its own non-rotating key", [REQ-SUBJ-007](/requirements/subj/#REQ-SUBJ-007) and [REQ-SUBJ-008](/requirements/subj/#REQ-SUBJ-008) say a keyed MAC of the upstream subject through the keys port. A key per sector is a key per tenant, which [principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule) rules out. [0017](/decisions/0017-identity-and-sign-in/#subjects) says `sub` is the same at every issuer, which pairwise subjects change, while single sign-on across products needs one person to be recognised across products.
- **Erasure.** [0019](/decisions/0019-person-and-upstream-link/#states) keeps the records of a person who left "so the subject is never reused". That collides with erasure unless "erase" is defined. The audit side already works by removing the link from the pseudonym to the person ([0029](/decisions/0029-the-audit-log/#pseudonyms), [REQ-AUDIT-057](/requirements/audit/#REQ-AUDIT-057)), and a tenant's exit is a crypto-shred ([0006](/decisions/0006-keys-and-sealing/#erasing-a-tenant)).
- **Who answers.** sluis has no intake for a data-subject request; the product and the upstream do ([0031](/decisions/0031-ciam-is-a-broker/#who-owns-what)).
- **Inbound logout.** The upstream may end a session; sluis has records for outbound back-channel logout ([REQ-SESS-009](/requirements/sess/#REQ-SESS-009)) and none for inbound. The upstream's `sid` is not tied to any sluis session.
- **Disable and delete.** Back-channel logout ends a session and does not mark a person gone. [REQ-SESS-024](/requirements/sess/#REQ-SESS-024) and [REQ-SUBJ-043](/requirements/subj/#REQ-SUBJ-043) assume sluis "learns" it. A human session is bounded by 24 hours ([0018](/decisions/0018-sessions/#human-sessions)), but an agent session lasts weeks, and a regulated customer may not wait a day.
- **Global sign-out.** One sign-out at one product must end the person's sessions at all the products, which is possible only because sluis holds a session per client.

## Decision

### States

An end user is a `Person` like any other, with the same kinds and the same computed states, plus one more:

| State | When | Set by |
|---|---|---|
| live | None of the below | |
| held | A `PersonHold` exists | An operator on the console, at once |
| suspended | The upstream's status says disabled | The status call or signal of [Upstream signals](/decisions/0034-end-users-and-upstream-signals/#upstream-signals) |
| left | The upstream said deleted, or the person's only connection was removed | The same, or the disconnect of a connection or tenant |
| erased | The person's records were deleted and a `Tombstone` remains | An erasure request, or the end of the retention after `left` |

- **The transitions are fixed.** live to held, suspended or left; held and suspended back to live; held, suspended and live to left; left to erased; erased is final. Any other transition is refused with `failed_precondition` ([REQ-ACCT-011](/requirements/acct/#REQ-ACCT-011), [REQ-ACCT-012](/requirements/acct/#REQ-ACCT-012)). A person who is not live is refused at sign-in, refresh, exchange and step-up, and every session of theirs ends at the moment sluis learns it ([REQ-SESS-024](/requirements/sess/#REQ-SESS-024), [REQ-ACCT-029](/requirements/acct/#REQ-ACCT-029)).
- **Lifecycle rules are a table in config** ([REQ-REG-056](/requirements/reg/#REQ-REG-056)): the retention between `left` and `erased` (default 30 days, at most 365) and whether an idle person is suspended (not by default; the upstream's session is its job). The table is Fixed, so a change is a reviewed, signed document ([0004](/decisions/0004-the-data-model/#profiles)).
- **A connection that is removed leaves its persons** whose only connection it was. A removed tenant makes all its persons `left` ([REQ-REG-057](/requirements/reg/#REQ-REG-057)).

### What sluis holds about an end user

| Kind | Class and treatment | Holds | Personal |
|---|---|---|---|
| `Person` | Durable, sealed | The subject (its id), the time created | The subject links to a person |
| `UpstreamLink` | Durable, sealed | The subject, the issuer and the claim name; its id is the keyed hash of the pair | The link to the upstream account |
| `PersonHold` | Durable, sealed | Who and when; the reason is free text | The subject |
| `PersonStatus` | Durable, sealed | The status the upstream reported | The subject |
| `SessionChain`, `UpstreamSession` | Temp, hashed | Class, client, `sid`, times; the agent's consent. Never an e-mail address or a name ([REQ-SESS-005](/requirements/sess/#REQ-SESS-005)) | The subject |
| Audit records | Audit log | Pseudonyms only ([0029](/decisions/0029-the-audit-log/#pseudonyms)) | Linked through the person record |
| `Tombstone` | Durable, hashed | A keyed hash of the subject, the time and the kind of erasure | None once the links are gone |

No other kind carries a field marked personal: a kind that holds personal data is sealed, and the schema check refuses one that is plain ([0004](/decisions/0004-the-data-model/#treatment)). sluis holds no e-mail address, name, phone number or password at rest. The sealed ones are sealed under the tenant's `data` key, so a tenant's exit makes them unreadable at once ([0006](/decisions/0006-keys-and-sealing/#erasing-a-tenant)).

### Erasure

- **Erasing a person deletes the `Person` and `UpstreamLink` items,** the holds and statuses, the session chains and upstream sessions, and writes a `Tombstone`. The pseudonyms in audit then name no one ([0029](/decisions/0029-the-audit-log/#pseudonyms)).
- **An `ErasureHold` stops an erasure while it exists,** for the tenant or for the whole boundary ([Tenant lifecycle](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)). A hold is linked, not layered ([0004](/decisions/0004-the-data-model/#layered-and-linked-kinds)).
- **The subject is never reused because it is 128 random bits,** not because a record keeps it. The tombstone exists to refuse a stale token or refresh as erased and to make a repeated erasure idempotent. Erasure reaches archives by expiry and replay: a restore re-applies each erasure that audit records ([0010](/decisions/0010-backup-and-recovery/#roll-forward)). A whole tenant's data reaches its archives by shredding its data keys.
- **A request enters through the product,** which asks the upstream to delete the account and calls sluis's `erase` for the subject. sluis does not take a request from the person.
- **A person who returns through a new upstream account is a new person** with a new subject.

### Export

The subject's export is a document of what the table above lists for one subject, produced by an operation of the console API for a caller with the right role ([0027](/decisions/0027-the-console/#writes)). It holds the state, the times, the upstream by connection name, the sessions and consents, and the pseudonyms for the months asked. The audit records themselves are read through the tenant's audit role and the reversal of [0029](/decisions/0029-the-audit-log/#pseudonyms).

### Pairwise subjects

- **The subject is public by default.** `sub` is the same at every issuer of an installation ([0017](/decisions/0017-identity-and-sign-in/#subjects)), which is what lets the products of a customer recognise one person.
- **A pairwise subject exists only for a client that declares a sector,** and a sector exists only when a relying party must not correlate a person with another. No client declares one now, and the derivation is specified so that the first consumer is a configuration change ([principle 8](/principles/#8-nothing-without-a-consumer)).
- **The derivation is a keyed hash made at `key@`.** The caller asks `Mac` over the `mac` data key with the label `pairwise` and the length-prefixed sector and `sub` of the person (not the upstream's claim) as input ([0006](/decisions/0006-keys-and-sealing/#sign-and-mac)). The result is truncated to 256 bits and written as base64url without padding. The `mac` data key is one per boundary, never leaves `key@` and is never rotated, because a new key would change every pairwise subject ([REQ-SUBJ-015](/requirements/subj/#REQ-SUBJ-015), [REQ-SUBJ-016](/requirements/subj/#REQ-SUBJ-016)). There is no key per sector and no key per tenant.
- **A sector never spans two issuers,** since each boundary's `mac` key differs. Products that must recognise one person use the public subject.
- **sluis never resolves a pairwise value back to a person.** Every request that names a person carries a session, a token or a `sid` that does, so there is no reverse index.
- **A sector is a `Sector` entry in config,** a name of 1 to 32 characters; a client names at most one, and the configuration check refuses a change that would alter a pairwise subject already given out, such as a renamed sector or a client moved to another.

### Upstream signals

A workforce directory is pulled, so sluis learns that a person was removed ([0019](/decisions/0019-person-and-upstream-link/#directory-facts-parity)). A customer-identity upstream is not pulled; it signals.

#### Inbound back-channel logout

- **sluis registers a back-channel logout URI and `backchannel_logout_session_required=true` with each upstream that supports it.** `entry` routes the logout token to `session`, which has `adapter-upstream-oidc` check it as OpenID Connect Back-Channel Logout 1.0 requires: signature against the connection's key set, `iss`, `aud` equal to sluis's client ID, `iat` and `exp`, the `events` claim, no `nonce`, a `sid` or a `sub`, and a `jti` accepted once. The adapter returns the `sid` and the subject-claim value to `session` as a fact and decides nothing.
- **The mapping is by `sid`.** At sign-in, `session` writes an `UpstreamSession`, a temp kind whose id is a keyed hash of (connection, `sid`) made at `key@` and which points to the sluis browser session. A logout token with a `sid` ends that browser session and every human session under it ([0018](/decisions/0018-sessions/#human-sessions)). A token with only a `sub` ends every human session of that person that came through that connection. A logout token for a `sid` that sluis does not know is acknowledged and changes nothing.
- **Agent sessions are not ended by a logout,** as for a person's sign-out at sluis ([0018](/decisions/0018-sessions/#agent-sessions)). A status signal ends them.
- **Logout is best-effort.** A missed delivery is bounded by the session's absolute limit.

#### Disable and delete

- **A person's status arrives as a call to sluis,** `suspend`, `resume` and `erase`, made by a product, in practice the customer-identity module or a small adapter that listens to the upstream's own events, authorised for its tenant. The call names the person by connection and subject-claim value, never by e-mail address. It is audited under the caller's name.
- **`suspend` and `erase` take effect at once** (a tightening, [principle 12](/principles/#12-a-loosening-is-temporary-a-tightening-is-durable)): a suspended person is refused everywhere and every session, agent sessions included, ends. **`resume` lifts only `suspended`,** never a `PersonHold` that an operator set, and gives back only what policy grants. The states are those of [States](/decisions/0034-end-users-and-upstream-signals/#states); the status is a `PersonStatus` item, observed from outside and written by `session`, which keeps it apart from the operator's hold.
- **The standard channel is a second source of the same fact,** not another mechanism. When an upstream transmits OpenID Shared Signals events (CAEP `account-disabled`, `account-enabled`, `account-purged`), a receiver turns them into the same `PersonStatus` fact. It is built with its first upstream that transmits them ([REQ-CIAM-006](/requirements/ciam/#REQ-CIAM-006) is the transmitting side).
- **A connection with no status source gets no agent sessions.** Agent sessions must end when the person is disabled ([0018](/decisions/0018-sessions/#agent-sessions)), and sluis can promise that only where it can be told. A human session needs no source: its bound is the 24 hours and the silent renewal that fails once the upstream refuses the account ([0018](/decisions/0018-sessions/#customers)).

#### Global sign-out

- **A sign-out at a client ends the person's browser session and every human session under it,** at every client ([REQ-SESS-011](/requirements/sess/#REQ-SESS-011)). sluis holds a session chain per client and per boundary, so it knows which clients to tell.
- **Each client with a registered back-channel URI gets one logout token per ended session,** with retries and an alarm on a dead letter ([REQ-SESS-009](/requirements/sess/#REQ-SESS-009), [REQ-SESS-010](/requirements/sess/#REQ-SESS-010), [REQ-SESS-021](/requirements/sess/#REQ-SESS-021)). The front tells each customer boundary, which ends its sessions and tells its own clients; a boundary's session never outlives the one that seeded it ([REQ-SESS-033](/requirements/sess/#REQ-SESS-033)).
- **Ending many sessions at once is a job:** paginated, asynchronous and idempotent ([REQ-PERF-002](/requirements/perf/#REQ-PERF-002), [#1062](https://github.com/truvity/sluis/issues/1062)). A tenant's removal, a suspended person with many sessions and a compromised provider all use it. It lists sessions by prefix through the store ([0005](/decisions/0005-the-store/#the-store-api)).

## Consequences

- The whole lifecycle is one set of kinds that the workforce already uses; the customer case adds a state, a tombstone and the status call.
- An erased person's pseudonyms stay stable inside their month and lead nowhere, as [0029](/decisions/0029-the-audit-log/#pseudonyms) accepts.
- The key for pairwise subjects is an existing data key: no ceremony, no extra KMS key, and nothing that signs or chains to a root.
- The retention between `left` and `erased` is the time in which an operator can still export the person's records; after it nothing brings them back, and a restore replays the erasure.
- A customer disabled at the upstream is out of every session within the delivery time of the status call, and out of human sessions within 24 hours without it.
- The status call is an authority-bearing API with a small blast radius: it can suspend or erase, and resume only what it suspended. A stolen client key can lock customers out of one tenant until an operator resumes them, which the audit shows.
- A connection without a status source loses agent sessions. That is the price of the promise in [0018](/decisions/0018-sessions/#agent-sessions).
- The `sid` mapping adds one temp item per session; it holds no personal data.
- Requirements: [REQ-SUBJ-048](/requirements/subj/#REQ-SUBJ-048), [REQ-SUBJ-049](/requirements/subj/#REQ-SUBJ-049), [REQ-SUBJ-050](/requirements/subj/#REQ-SUBJ-050), [REQ-SUBJ-051](/requirements/subj/#REQ-SUBJ-051), [REQ-SUBJ-052](/requirements/subj/#REQ-SUBJ-052), [REQ-SUBJ-053](/requirements/subj/#REQ-SUBJ-053), [REQ-SUBJ-054](/requirements/subj/#REQ-SUBJ-054), [REQ-SUBJ-055](/requirements/subj/#REQ-SUBJ-055), [REQ-SUBJ-056](/requirements/subj/#REQ-SUBJ-056), [REQ-ACCT-061](/requirements/acct/#REQ-ACCT-061), [REQ-FED-029](/requirements/fed/#REQ-FED-029), [REQ-FED-030](/requirements/fed/#REQ-FED-030), [REQ-FED-031](/requirements/fed/#REQ-FED-031), [REQ-FED-032](/requirements/fed/#REQ-FED-032), [REQ-FED-033](/requirements/fed/#REQ-FED-033), [REQ-SESS-038](/requirements/sess/#REQ-SESS-038), [REQ-SESS-039](/requirements/sess/#REQ-SESS-039), [REQ-SESS-040](/requirements/sess/#REQ-SESS-040) and [REQ-SESS-041](/requirements/sess/#REQ-SESS-041).

## Roads not taken

- **A customer kind apart from `Person`.** Two writers and two lifecycles for one idea, and the 25 records would need both.
- **Storing the e-mail address or name to answer a request.** The upstream already holds them, and a copy is a second place to erase.
- **A data key per person or per sector to shred.** Millions of wraps, or a key per tenant; [0029](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding) rejected a key per person, and a tenant's own data keys already shred a whole tenant.
- **Keeping the link after erasure so the subject is never reused.** The subject is random, and the link is the personal part.
- **Pairwise subjects for every client from the start.** Single sign-on across products needs one subject across products, and no consumer wants otherwise ([principle 8](/principles/#8-nothing-without-a-consumer)).
- **A MAC key per sector, or a KMS HMAC key.** A key per sector is a key per tenant, and a KMS `GenerateMac` key takes no encryption context, so it would be one key per purpose and boundary and a second mechanism beside `Mac` at `key@` ([0006](/decisions/0006-keys-and-sealing/#sign-and-mac)).
- **A reverse index from the pairwise value to the person.** It stores a second identifier for each person per sector, which the design does not need.
- **Shared Signals as the only channel.** It is the standard, but no upstream is known to transmit it, and without a consumer it would leave customers without a signal.
- **Polling the upstream for status.** OpenID Connect has no call for it, and a per-refresh check of the upstream would make every token a round trip.
- **Treating back-channel logout as disable.** A logout ends a session, not an account; a person who signed out would be locked out.
- **Ending agent sessions on logout.** It would break background agents at every sign-out, which [0018](/decisions/0018-sessions/#agent-sessions) refuses.
- **A pull of the upstream's user list.** That is the directory, which a customer-identity product need not offer and which makes sluis a copy of the accounts.
- **Letting the module set an operator hold.** Its suspension would mix an observed status with an operator's lasting choice; the two stay two kinds, `PersonStatus` and `PersonHold`.

## Follow-ups

- An agent session for a channel client of a regulated customer's boundary, whose consent is an external record ended by the status call, and an opaque `consent_id` claim for that audience only: decided as a customer-identity record, written with the first channel of a regulated customer.
- The lifecycle, the status call, the erasure and the export: [#1024](https://github.com/truvity/sluis/issues/1024).
- Inbound back-channel logout and the status operations: [#916](https://github.com/truvity/sluis/issues/916).
- Outbound back-channel logout and the sign-out fan-out: [#780](https://github.com/truvity/sluis/issues/780).
- Mass revocation: [#1062](https://github.com/truvity/sluis/issues/1062).
- The Shared Signals receiver, with its first transmitting upstream: [#927](https://github.com/truvity/sluis/issues/927).
