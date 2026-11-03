# 0019 — A person is tied to an upstream account by the issuer and a configured subject claim, never by e-mail, and a directory only adds facts

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #1116](https://github.com/truvity/sluis/issues/1116).

## Context

sluis has no users of its own: people come from upstream identity providers and directories ([0017](/decisions/0017-identity-and-sign-in/#subjects), [REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)). A person's `sub` is an opaque random id that sluis assigns when it first sees them, and it is never an e-mail address. What was not written down is the part in between: which record holds a person, which key ties an upstream account to that record, what states a person has, and what a directory adds when there is one.

The first working version signs people in through the generic OpenID Connect upstream, sign-in only ([#1106](https://github.com/truvity/sluis/issues/1106)), so it sees a person for the first time at the first sign-in. Directory sync follows in the parity milestone ([#805](https://github.com/truvity/sluis/issues/805)) and brings a subject before the first sign-in. The record has to serve both without a rewrite. The end-user lifecycle and pairwise subjects stay with [#1024](https://github.com/truvity/sluis/issues/1024).

Two facts about real upstreams shape the key. An e-mail address is reused, renamed and, at some providers, not verified, so linking by address lets whoever can obtain an address become its owner. And the `sub` claim is not stable everywhere: Google's `sub` is a permanent account identifier, but Microsoft Entra's `sub` is pairwise per application, so it changes if the application registration is replaced, while its `oid` claim is the stable object id of the account in the tenant. The tests run against both: Keycloak on every pull request, and Google Cloud Identity Free and Microsoft Entra ID Free nightly ([0011](/decisions/0011-runtimes-and-installations/#the-local-installation)).

## Decision

### Linking an upstream account

- **An upstream account is identified by the pair (issuer, value of the upstream's subject claim).** The issuer is the `iss` of the ID token, which sluis has checked against the upstream's declared issuer; the value is the string in the subject claim.
- **The subject claim is configured per upstream, with the default `sub`.** The install file key is `subject_claim` ([Install file](/reference/install-file/#upstreams)). Google uses `sub`; Microsoft Entra needs `oid`.
- **There is no fallback.** An ID token without the configured claim, or with a value that is not a string of at most 255 characters, is refused ([0025](/decisions/0025-integrations/#the-upstream-contract)). sluis never tries another claim, and never reads the e-mail address, `preferred_username` or `upn` as an identity. `sluis config check` refuses a `subject_claim` that names one of those mutable claims.
- **E-mail never links, matches or merges.** It is a claim that the person's token may carry when the scope asks for it ([REQ-TOKEN-006](/requirements/token/#REQ-TOKEN-006)).
- **The first link of an issuer pins the claim.** The pin is an issued record. If an upstream's configured claim later differs from its pin, sluis refuses the sign-in: a contradicted pin is refused, never learned again ([0004](/decisions/0004-the-data-model/#origins)). Changing the claim of an upstream that has links is a migration, not a setting.
- **Two upstream accounts are two people.** sluis does not merge them, whether they differ by upstream or by tenant. Moving an installation to another upstream therefore makes new people; merging is a deliberate operator act that is out of scope until a consumer needs it.

### The records

The writer of every kind below is `session` of the front installation, which signs people in; a boundary reads a person only through the front's tokens ([0017](/decisions/0017-identity-and-sign-in/#step-up)). The kinds are listed with the others on [Storage](/reference/storage/#record-kinds-of-the-first-working-version).

| Kind | Origin | Holds |
|---|---|---|
| `person` | issued, durable | The subject, the WebAuthn user handle, the time created |
| `upstream-link` | issued, durable | The subject of the person, the issuer and the claim name; the key is the keyed hash of the pair |
| `upstream-pin` | issued, durable | The issuer and the subject claim first used for it; the key is the keyed hash of the issuer |
| `link-key` | issued, durable | The 32 random bytes that key the two hashes |
| `person-hold` | operator-set | That an operator holds the person, who set it, when and why |

- **The subject is 128 random bits from the operating system's generator, written in lower-case base32 without padding.** It is the key of the `person` record, it is the `sub` of every token at every issuer, and it is never reused.
- **The WebAuthn user handle is 32 random bytes stored on the person,** not derived from anything ([REQ-SUBJ-029](/requirements/subj/#REQ-SUBJ-029)).
- **A key holds no personal data.** The key of a link is `HMAC-SHA-256` under the `link-key`, over the issuer and the claim value, truncated to 128 bits and written in base32 ([Record keys](/reference/storage/#record-keys)). The `link-key` is made once, by a create-only `Put`, so concurrent first starts agree on one; it is never rotated, because a new key would orphan every link. Sealing hides the values; this hides the keys.
- **No origin is mixed.** What sluis issued (the person and the link) and what an operator chose (a hold) are two kinds with one writer each, and what a directory reports is a third origin ([0004](/decisions/0004-the-data-model/#origins)).

### Assigning a subject

- **At the first sign-in** through an upstream account with no link, `session` makes the subject and writes the `person` and the `upstream-link` in one atomic `Batch`, with the `upstream-pin` when it is the issuer's first. The link is a create-only `Put`: when two first sign-ins of one account race, one batch wins and the other fails with `already_exists`, reads the link and continues as the winner. Two people never result.
- **At a directory read,** which the parity milestone adds, `session` makes the person and the link when a pass first reports a directory person, using the upstream subject value that the facts carry, so the subject is known before the person signs in. The sign-in then finds the link.
- **Nothing is created for a refused sign-in.** A person record exists only for an authentication that sluis accepted.

### States

A person has four states, and the state is computed from the records, never stored.

| State | When | Effect |
|---|---|---|
| live | No hold, and the directory (if any) does not say otherwise | Sign-in, refresh and exchange work |
| held | A `person-hold` exists | Refused at once |
| suspended | The directory reports the person suspended or deleted (parity) | Refused at once |
| left | The person is absent from the last `N` full snapshots (parity) | Refused; the person's sessions end |

- **A person who is not live is refused at sign-in, refresh, exchange and step-up,** and every session and refresh grant of that person ends at the moment sluis learns it ([REQ-SESS-024](/requirements/sess/#REQ-SESS-024)). Tokens already issued stay valid until they expire.
- **A hold is set and lifted by an operator on the console,** audited under the operator's name. It takes effect at once, because suspending a subject is a tighten-only action ([0007](/decisions/0007-policy-and-sealed-grants/#template-links)). Lifting it gives back only what declared policy grants.
- **The records of a person who left are kept,** so the subject is never reused and the audit pseudonyms stay stable ([0044](/decisions/0044-audit-pseudonyms-are-keyed-per-company-and-epoch/)). They hold no personal data.
- **In the first working version a person removed at the upstream is not seen until they next sign in at the upstream.** The session's absolute limit bounds this ([0018](/decisions/0018-sessions/)), and an operator hold ends it at once.

### What policy sees

- **For a person, `policy` receives the subject, the declared name of the upstream, the claims of the upstream's allow-list (the e-mail address and whether it was verified, a display name), `acr`, `amr`, `auth_time`, the freshness of the authentication, and the person's state.** An absent `acr`, `amr` or `auth_time` is unknown ([0025](/decisions/0025-integrations/#what-an-integration-may-return)).
- **Internal groups are declared** ([0004](/decisions/0004-the-data-model/#origins)). In the first working version a declared binding names a person by the pair that links them, the upstream's declared name and the claim value, because an operator cannot know the random subject before the first sign-in and the e-mail address does not identify. A binding may name a directory group at the parity milestone.

### Directory facts (parity)

- **A directory is a `FactsSource`** ([0025](/decisions/0025-integrations/#the-contracts)). It reads the people, groups and memberships of one tenant and keeps them as learned facts, with the time observed and a maximum age, in its own namespace. Learned facts never configure ([0004](/decisions/0004-the-data-model/#origins)).
- **A person's fact carries the value that the upstream will present in its subject claim** (Google's user id, Entra's object id), the suspended and deleted flags, and the directory's own id. The directory id is a pin: a later pass that contradicts it is refused.
- **The pass is a pull.** A full snapshot runs on an interval (default 15 minutes), and a push from the vendor is a notification that starts a pull ([0004](/decisions/0004-the-data-model/#origins)).
- **Staleness is bounded and fails closed.** When the directory cannot be read, sluis serves the cached facts up to the freshness window (default 1 hour, maximum 24 hours in code, set per installation), then refuses refresh and exchange ([0017](/decisions/0017-identity-and-sign-in/#directory-outages)). A person the directory disabled is refused at once, whatever the window.
- **An unreadable directory is never an empty one.** A failed pass is not a snapshot and counts for nothing. A person is `left` only after being absent from `N` consecutive successful full snapshots (default 3), and a snapshot that lacks more than half of the people sluis knows is held and reported, not applied.

## Consequences

- One person has one subject at every issuer, found by the same pair whichever sign-in path reaches it, and the record fits a directory without change: the directory adds a way to create the person earlier and a state, not a new key.
- No key in the state store, and no claim in the tokens, reveals an e-mail address or an upstream id. The cost is the `link-key`: losing it orphans every link, so it is backed up and rolled forward like any issued record ([0004](/decisions/0004-the-data-model/#backup-and-restore-by-origin)).
- A person who has two upstream accounts, or whose installation changes upstream, is two people. Their grants, passkeys and sessions do not carry over.
- Delete and listing by prefix are not in the first working version ([Storage](/reference/storage/#state)), so a person cannot be looked up by anything but the pair, which is what sign-in needs.
- The first working version cannot see an upstream-side removal until the next upstream sign-in or the session limit. That is the price of sign-in only, and the directory removes it at parity.
- Requirements: [REQ-SUBJ-037](/requirements/subj/#REQ-SUBJ-037) to [REQ-SUBJ-047](/requirements/subj/#REQ-SUBJ-047) are added.

## Roads not taken

- **Link by verified e-mail address.** Addresses are reused and renamed, not every provider verifies them, and an attacker who obtains an address becomes its owner.
- **Always `sub`.** It is wrong for Entra, whose `sub` is pairwise per application and changes with the registration.
- **A list of claims to try in order.** The same account could present different claims at different times and become two people.
- **The upstream's subject as the sluis subject.** It leaks an upstream id into every token and log line, and two upstreams could collide.
- **Merging accounts automatically.** Any rule that merges on a shared attribute is the e-mail road again.
- **One `person` kind with a state field.** It would have two writers, `session` and the facts source, which [0004](/decisions/0004-the-data-model/#origins) forbids for learned and operator-set data of one object.
- **Assigning subjects only at a directory read.** The first working version has no directory.
- **A separate people actor.** It would add a process and a second holder of the sealing key for records that `session` already writes with the passkeys.
- **The unkeyed hash of the pair as the record key.** A reader of the store's keys could test whether a known upstream id is a user.

## Follow-ups

- Directory sync, the first `FactsSource`, and the subject before the first sign-in: [#805](https://github.com/truvity/sluis/issues/805).
- The generic OpenID Connect upstream: [#1106](https://github.com/truvity/sluis/issues/1106); subject basics: [#1081](https://github.com/truvity/sluis/issues/1081).
- End-user subject lifecycle and pairwise subjects: [#1024](https://github.com/truvity/sluis/issues/1024).
- Passkeys and step-up: [#885](https://github.com/truvity/sluis/issues/885).
