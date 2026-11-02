# 0050 — An end user is the same person record as anyone else, with five states, erased by deleting its records, and pairwise subjects wait for a consumer

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-02

Proposal: [issue #1024](https://github.com/truvity/sluis/issues/1024).

## Context

[0027](/decisions/0027-a-person-is-tied-to-an-upstream-account-by-issuer-and-subject-claim/) gives a person an opaque random subject, a link to the upstream account by the pair of issuer and subject claim, and four computed states: live, held, suspended and left. For the customer-identity milestone #1024 collects 25 live requirement records that refer to "the defined state machine" which does not exist, a corporate-connection rule from the workforce idea, a pairwise design whose records disagree with each other, and the questions of erasure and export.

- **The state names.** [REQ-ACCT-011](/requirements/acct/#REQ-ACCT-011) wants transitions limited to a state machine; the withdrawn account records named five other states.
- **Pairwise subjects.** [REQ-CIAM-003](/requirements/ciam/#REQ-CIAM-003) gives each sector "its own non-rotating key", [REQ-SUBJ-007](/requirements/subj/#REQ-SUBJ-007) and [REQ-SUBJ-008](/requirements/subj/#REQ-SUBJ-008) say a keyed MAC of the upstream subject through the keys port. KMS `GenerateMac` takes no encryption context, so a shared symmetric key cannot be separated by context as [principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule) needs, and a key per sector is a key per tenant. [0006](/decisions/0006-identity-issuers-audiences-and-sign-in/#subjects) says `sub` is the same at every issuer, which pairwise subjects change. The group single sign-on needs one person to be recognised across products.
- **Erasure.** [0027](/decisions/0027-a-person-is-tied-to-an-upstream-account-by-issuer-and-subject-claim/#states) keeps the records of a person who left "so the subject is never reused". That collides with erasure unless "erase" is defined. The audit side already works by removing the link from the pseudonym to the person ([0025](/decisions/0025-audit-pseudonyms-are-keyed-per-company-and-epoch/), [REQ-AUDIT-057](/requirements/audit/#REQ-AUDIT-057)), and the general rule is [0032](/decisions/0032-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/).
- **Who answers.** sluis has no intake for a data-subject request; the product and the upstream do ([0046](/decisions/0046-ciam-is-a-broker-the-upstream-owns-accounts-and-sluis-owns-sessions-and-tokens/#who-owns-what)).

## Decision

### States

An end user is a `person` like any other, with the same records and the same computed states, plus one more:

| State | When | Set by |
|---|---|---|
| live | None of the below | |
| held | A `person-hold` exists | An operator on the console, at once |
| suspended | The upstream's status says disabled | The status call or signal of [0051](/decisions/0051-upstream-signals-end-sessions-and-suspend-or-erase-a-person/) |
| left | The upstream said deleted, or the person's only connection was removed | The same, or the disconnect of a connection or tenant |
| erased | The person's records were deleted and a tombstone remains | An erasure request, or the end of the retention after `left` |

- **The transitions are fixed.** live to held, suspended or left; held and suspended back to live; held, suspended and live to left; left to erased; erased is final. Any other transition is refused with `failed_precondition` ([REQ-ACCT-011](/requirements/acct/#REQ-ACCT-011), [REQ-ACCT-012](/requirements/acct/#REQ-ACCT-012)). A person who is not live is refused at sign-in, refresh, exchange and step-up, and every session of theirs ends at the moment sluis learns it ([REQ-SESS-024](/requirements/sess/#REQ-SESS-024), [REQ-ACCT-029](/requirements/acct/#REQ-ACCT-029)).
- **Lifecycle rules are a declared table** ([REQ-REG-056](/requirements/reg/#REQ-REG-056)): the retention between `left` and `erased` (default 30 days, at most 365) and whether an idle person is suspended (not by default; the upstream's session is its job). The table is declared configuration, with the customer's defaults delivered as [0046](/decisions/0046-ciam-is-a-broker-the-upstream-owns-accounts-and-sluis-owns-sessions-and-tokens/#configuration) says.
- **A connection that is removed leaves its persons** whose only connection it was. A removed tenant makes all its persons `left` ([REQ-REG-057](/requirements/reg/#REQ-REG-057) is reworded from "corporate connection").

### What sluis holds about an end user

| Kind | Holds | Personal |
|---|---|---|
| `person` | The subject, the time created | The subject links to a person |
| `upstream-link` | The subject, the issuer and the claim name; the key is the keyed hash of the pair | The link to the upstream account |
| `person-hold`, `person-status` | Who and when; the status the upstream reported | The subject |
| Sessions and refresh records | Class, client, `sid`, times; never an e-mail address or a name ([REQ-SESS-005](/requirements/sess/#REQ-SESS-005)) | The subject |
| Agent consents | The client, the resources and scopes, the times | The subject |
| Audit records | Pseudonyms only ([0025](/decisions/0025-audit-pseudonyms-are-keyed-per-company-and-epoch/)) | Linked through the person record |
| `tombstone` | The subject, the time and the kind of erasure | None once the links are gone |

No other kind carries a field marked personal; the schema check refuses one ([0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#sensitivities)). sluis holds no e-mail address, name, phone number or password at rest.

### Erasure

- **Erasing a person deletes the `person` and `upstream-link` records,** the holds and statuses, the sessions, the refresh records and the consents, and writes a `tombstone`. The pseudonyms in audit then name no one ([0025](/decisions/0025-audit-pseudonyms-are-keyed-per-company-and-epoch/)).
- **The subject is never reused because it is 128 random bits,** not because a record keeps it. The tombstone exists to refuse a stale token or refresh as erased and to make a repeated erasure idempotent. Erasure reaches archives by expiry and replay, and a tenant's by shredding its data key, as [0032](/decisions/0032-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#backups) says; the audit log's record of the erasure is what a restore replays.
- **A request enters through the product,** which asks the upstream to delete the account and calls sluis's `erase` for the subject. sluis does not take a request from the person.
- **A person who returns through a new upstream account is a new person** with a new subject.

### Export

The subject's export is a document of what the table above lists for one subject, produced by an operation of the console API for a declared client with the right role ([0032](/decisions/0032-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/)). It holds the state, the times, the upstream by connection name, the sessions and consents, and the pseudonyms for the months asked. The audit records themselves are read through the company's audit role and the reversal of [0025](/decisions/0025-audit-pseudonyms-are-keyed-per-company-and-epoch/#decision).

### Pairwise subjects

- **The subject is public by default.** `sub` is the same at every issuer of an installation ([0006](/decisions/0006-identity-issuers-audiences-and-sign-in/#subjects)), which is what lets the products of a group recognise one person.
- **A pairwise subject exists only for a client that declares a sector,** and a sector exists only when a relying party must not correlate a person with another. No client declares one now, and the derivation is specified so that the first consumer is a configuration change.
- **The derivation:** `base64url(truncate-256(HMAC-SHA384(key, "sluis-pairwise-v1" || len(sector) || sector || len(sub) || sub)))`, without padding, over the person's `sub`, not the upstream's claim. The key is **one HMAC key per boundary**, non-extractable, used through the keys port; its key policy names exactly one actor, because `GenerateMac` takes no encryption context. It is never rotated, because a new key would change every pairwise subject ([REQ-SUBJ-015](/requirements/subj/#REQ-SUBJ-015), [REQ-SUBJ-016](/requirements/subj/#REQ-SUBJ-016)). It is not a key per tenant.
- **A sector never spans two issuers,** since each boundary's key differs. Products that must recognise one person use the public subject.
- **sluis never resolves a pairwise value back to a person.** Every request that names a person carries a session, a token or a `sid` that does, so there is no reverse index.
- **A sector is a name in a declared list,** 1 to 32 characters; a client names at most one, and the loader refuses a change of a sector's key while subjects exist.

## Consequences

- The whole lifecycle is one record kind set that the workforce already uses; the customer case adds a state, a tombstone and the status call.
- An erased person's pseudonyms stay stable inside their month and lead nowhere, as [0016](/decisions/0016-the-audit-log/#pseudonyms) accepts.
- The key for pairwise subjects is an authority key of its own purpose, born in KMS (or a card), with one per boundary: a ceremony-free key, since it signs nothing and chains to no root.
- The retention between `left` and `erased` is the time in which an operator can still export the person's records; after it nothing brings them back, and a restore replays the erasure.
- Requirements: [REQ-SUBJ-048](/requirements/subj/#REQ-SUBJ-048), [REQ-SUBJ-049](/requirements/subj/#REQ-SUBJ-049), [REQ-SUBJ-050](/requirements/subj/#REQ-SUBJ-050), [REQ-SUBJ-051](/requirements/subj/#REQ-SUBJ-051), [REQ-SUBJ-052](/requirements/subj/#REQ-SUBJ-052), [REQ-SUBJ-053](/requirements/subj/#REQ-SUBJ-053), [REQ-SUBJ-054](/requirements/subj/#REQ-SUBJ-054), [REQ-SUBJ-055](/requirements/subj/#REQ-SUBJ-055), [REQ-ACCT-061](/requirements/acct/#REQ-ACCT-061) are added; REQ-CIAM-003, REQ-SUBJ-003, REQ-SUBJ-004, REQ-SUBJ-007, REQ-TOKEN-015 and REQ-REG-057 are reworded.

## Roads not taken

- **A customer record kind apart from `person`.** Two writers and two lifecycles for one idea, and the 25 records would need both.
- **Storing the e-mail address or name to answer a request.** The upstream already holds them, and a copy is a second place to erase.
- **A key per person or per sector to shred.** Millions of keys, or a key per tenant; [0016](/decisions/0016-the-audit-log/#encryption-and-crypto-shredding) rejected a key per person.
- **Keeping the link after erasure so the subject is never reused.** The subject is random, and the link is the personal part.
- **Pairwise subjects for every client from the start.** Group single sign-on needs one subject across products, and no consumer wants otherwise ([principle 8](/principles/#8-nothing-without-a-consumer)).
- **A MAC key per sector.** It is a key per tenant and cannot be separated by an encryption context in KMS.
- **A reverse index from the pairwise value to the person.** It stores a second identifier for each person per sector, which the design does not need.

## Follow-ups

- The lifecycle, the status call, the erasure and the export: [#1024](https://github.com/truvity/sluis/issues/1024).
