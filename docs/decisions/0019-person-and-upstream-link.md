# 0019 — A person is tied to an upstream account by issuer and subject claim

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #1116](https://github.com/truvity/sluis/issues/1116).

## Context

sluis has no users of its own: people come from upstream identity providers and directories ([0017](/decisions/0017-identity-and-sign-in/#subjects), [REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)). A person's `sub` is an opaque random id that sluis assigns when it first sees them, and it is never an e-mail address. What was not written down is the part in between: which kind holds a person, which key ties an upstream account to that kind, what states a person has, and what a directory adds when there is one.

The first working version signs people in through the generic OpenID Connect upstream, sign-in only ([#1106](https://github.com/truvity/sluis/issues/1106)), so it sees a person for the first time at the first sign-in. Directory sync follows in the parity milestone ([#805](https://github.com/truvity/sluis/issues/805)) and brings a subject before the first sign-in. The record has to serve both without a rewrite. The end-user lifecycle and pairwise subjects stay with [#1024](https://github.com/truvity/sluis/issues/1024).

Two facts about real upstreams shape the key. An e-mail address is reused, renamed and, at some providers, not verified, so linking by address lets whoever can obtain an address become its owner. And the `sub` claim is not stable everywhere: Google's `sub` is a permanent account identifier, but Microsoft Entra's `sub` is pairwise per application, so it changes if the application registration is replaced, while its `oid` claim is the stable object id of the account in the tenant of the directory. The tests run against both: Keycloak on every pull request, and Google Cloud Identity Free and Microsoft Entra ID Free nightly ([0011](/decisions/0011-runtimes-and-installations/#the-local-installation)).

The data model adds two more. A kind that holds personal data is sealed ([0004](/decisions/0004-the-data-model/#treatment)), and an id never contains personal data ([0004](/decisions/0004-the-data-model/#the-address)), so the id of a link cannot be the upstream's id in the clear.

## Decision

### Linking an upstream account

- **An upstream account is identified by the pair (issuer, value of the upstream's subject claim).** The issuer is the `iss` of the ID token, which sluis has checked against the upstream's issuer; the value is the string in the subject claim.
- **The subject claim is configured per upstream, with the default `sub`.** It is the field `subject_claim` of the config kind `Upstream` and of the durable kind `TenantConnection`. Google uses `sub`; Microsoft Entra needs `oid`.
- **There is no fallback.** An ID token without the configured claim, or with a value that is not a string of at most 255 characters, is refused ([0025](/decisions/0025-integrations/#the-upstream-contract)). sluis never tries another claim, and never reads the e-mail address, `preferred_username` or `upn` as an identity. The configuration check refuses a `subject_claim` that names one of those mutable claims in config, and `session` refuses it when it writes a `TenantConnection`.
- **E-mail never links, matches or merges.** It is a claim that the person's token may carry when the scope asks for it ([REQ-TOKEN-006](/requirements/token/#REQ-TOKEN-006)).
- **The first link of an issuer pins the claim.** The pin is a durable item, `UpstreamPin`. If an upstream's configured claim later differs from its pin, sluis refuses the sign-in: a contradicted pin is refused, never learned again. Changing the claim of an upstream that has links is a migration, not a setting.
- **Two upstream accounts are two people.** sluis does not merge them, whether they differ by upstream or by tenant. Moving an installation to another upstream therefore makes new people; merging is a deliberate operator act that is out of scope until a consumer needs it.

### The records

`session` writes every kind below, in the front installation that signs people in; a boundary reads a person only through the front's tokens ([0017](/decisions/0017-identity-and-sign-in/#step-up)). Each is a kind of a tenant, the tenant of the connection that signed the person in ([0008](/decisions/0008-boundaries-and-tenants/#tenants)): a `TenantConnection` names its tenant; an `Upstream` of config has none, so its people belong to the tenant whose connection to that app matched the sign-in (an `EntraConnection` for a customer directory), or else to the operator's own tenant ([0004](/decisions/0004-the-data-model/#the-upstream-criterion)). The sealed ones are sealed under that tenant's `data` key ([0006](/decisions/0006-keys-and-sealing/#data-keys)).

| Kind | Class | Treatment | Holds |
|---|---|---|---|
| `Person` | durable | sealed | The subject (the id of the item), the WebAuthn user handle, the time created, the claims for tokens |
| `UpstreamLink` | durable | sealed | The subject of the person, the issuer and the claim name; the id is a keyed hash of the pair |
| `UpstreamPin` | durable | plain | The issuer and the subject claim first used for it; the id is a keyed hash of the issuer |
| `PersonHold` | durable, Operable | sealed | That an operator holds the person, who set it, when and why |

- **The subject is 128 random bits from the operating system's generator, written in lower-case base32 without padding.** It is the id of the `Person` item, it is the `sub` of every token at every issuer, and it is never reused.
- **The WebAuthn user handle is 32 random bytes stored on the person,** not derived from anything ([REQ-SUBJ-029](/requirements/subj/#REQ-SUBJ-029)).
- **An id holds no personal data.** The id of a link is a keyed hash of the issuer and the claim value, made by key@'s `Mac` over the boundary's `mac` data key, with a label of its own ([0006](/decisions/0006-keys-and-sealing/#sign-and-mac)). Sealing hides the values; this hides the ids, and `session` never holds the key. There is no `LinkKey` kind.
- **The ids last as long as the `mac` key.** A new `mac` key would give every link another id, so replacing it is a migration that makes the ids again, not a rotation. Its wrap is a `DataKeyWrap` and is backed up with the others ([0010](/decisions/0010-backup-and-recovery/#what-the-archive-holds)).
- **The reason of a hold is free text, so a hold is sealed.** What `session` creates in the course of its job (the person and the link) and what an operator chose (a hold) are different kinds, and a directory's facts are a third thing, temp kinds that an adapter writes ([Directory facts](/decisions/0019-person-and-upstream-link/#directory-facts-parity)).

### Assigning a subject

- **At the first sign-in** through an upstream account with no link, `session` makes the subject and writes the `Person` and the `UpstreamLink` in one batch, with the `UpstreamPin` when it is the issuer's first ([0005](/decisions/0005-the-store/#the-store-api)). The link is a create: when two first sign-ins of one account race, one batch wins and the other fails with `already exists`, reads the link and continues as the winner. Two people never result.
- **At a directory read,** which the parity milestone adds, `session` makes the person and the link when a pass first reports a directory person, using the upstream subject value that the facts carry, so the subject is known before the person signs in. The sign-in then finds the link.
- **Nothing is created for a refused sign-in.** A person exists only for an authentication that sluis accepted.

### States

A person has four states, and the state is computed from the kinds, never stored.

| State | When | Effect |
|---|---|---|
| live | No hold, and the directory (if any) does not say otherwise | Sign-in, refresh and exchange work |
| held | A `PersonHold` exists | Refused at once |
| suspended | The directory reports the person suspended or deleted (parity) | Refused at once |
| left | The person is absent from the last `N` full snapshots (parity) | Refused; the person's sessions end |

- **A person who is not live is refused at sign-in, refresh, exchange and step-up,** and every session chain and refresh grant of that person ends at the moment sluis learns it ([REQ-SESS-024](/requirements/sess/#REQ-SESS-024)). Tokens already issued stay valid until they expire.
- **A hold is set and lifted by an operator on the console,** which routes the write to `session`; it is audited under the operator's name. It takes effect at once, because holding a person is a tightening ([0007](/decisions/0007-policy-and-sealed-grants/#template-links)). Lifting it gives back only what policy grants.
- **The items of a person who left are kept,** so the subject is never reused and the audit pseudonyms stay stable ([0029](/decisions/0029-the-audit-log/#pseudonyms)). They stay sealed under the tenant's keys and go with the tenant's crypto-shred ([0008](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)).
- **In the first working version a person removed at the upstream is not seen until they next sign in at the upstream.** The session's absolute limit bounds this ([0018](/decisions/0018-sessions/)), and an operator hold ends it at once.

### What policy sees

- **For a person, `policy` receives the subject, the declared name of the upstream, the claims of the upstream's allow-list (the e-mail address and whether it was verified, a display name), `acr`, `amr`, `auth_time`, the freshness of the authentication, and the person's state.** An absent `acr`, `amr` or `auth_time` is unknown ([0025](/decisions/0025-integrations/#what-an-integration-may-return)).
- **Internal groups are declared in config.** In the first working version a declared binding names a person by the pair that links them, the upstream's declared name and the claim value, because an operator cannot know the random subject before the first sign-in and the e-mail address does not identify. A binding may name a directory group at the parity milestone.

### Directory facts (parity)

- **A directory is read through a connection of the tenant.** The adapter of its vendor reads the people, groups and memberships and writes them as the temp kinds `DirectoryUser`, `DirectoryGroup` and `DirectoryMembership` of that tenant ([0025](/decisions/0025-integrations/#the-contracts)). They are sealed, because they hold names and addresses, and each has a time to live of 24 hours by default and 7 days at most ([0004](/decisions/0004-the-data-model/#storage-classes)): a re-sync rebuilds them, so they need no backup. A fact never becomes config.
- **A person's fact carries the value that the upstream will present in its subject claim** (Google's user id, Entra's object id), the suspended and deleted flags, and the directory's own id. The directory id is a pin: a later pass that contradicts it is refused.
- **The pass is a pull.** A full snapshot runs on an interval (default 15 minutes) as a job of the adapter under a lease ([0005](/decisions/0005-the-store/#leases)), and a push from the vendor is a notification that starts a pull.
- **Staleness is bounded and fails closed.** When the directory cannot be read, sluis serves the cached facts up to the freshness window (default 1 hour, a maximum of 24 hours built into the release, set per installation), then refuses refresh and exchange ([0017](/decisions/0017-identity-and-sign-in/#directory-outages)). A fact past its time to live reads as absent. A person the directory disabled is refused at once, whatever the window.
- **An unreadable directory is never an empty one.** A failed pass is not a snapshot and counts for nothing. A person is `left` only after being absent from `N` consecutive successful full snapshots (default 3), and a snapshot that lacks more than half of the people sluis knows is held and reported, not applied.

## Consequences

- One person has one subject at every issuer, found by the same pair whichever sign-in path reaches it, and the model fits a directory without change: the directory adds a way to create the person earlier and a state, not a new key.
- No id in the store, and no claim in the tokens, reveals an e-mail address or an upstream id. The cost is the `mac` key: losing it orphans every link, so its wrap is backed up with the other data keys ([0010](/decisions/0010-backup-and-recovery/#what-the-archive-holds)).
- Every sign-in costs a keyed hash at key@ to find the link. The hop is batched with the other opens of the request ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)).
- A person who has two upstream accounts, or whose installation changes upstream, is two people. Their grant names, passkeys and sessions do not carry over.
- The first working version cannot see an upstream-side removal until the next upstream sign-in or the session limit. That is the price of sign-in only, and the directory removes it at parity.
- A directory's facts are rebuilt after a loss of the temp class, at the cost of a re-sync.
- Requirements: [REQ-SUBJ-037](/requirements/subj/#REQ-SUBJ-037) to [REQ-SUBJ-047](/requirements/subj/#REQ-SUBJ-047) are added.

## Roads not taken

- **Link by verified e-mail address.** Addresses are reused and renamed, not every provider verifies them, and an attacker who obtains an address becomes its owner.
- **Always `sub`.** It is wrong for Entra, whose `sub` is pairwise per application and changes with the registration.
- **A list of claims to try in order.** The same account could present different claims at different times and become two people.
- **The upstream's subject as the sluis subject.** It leaks an upstream id into every token and log line, and two upstreams could collide.
- **Merging accounts automatically.** Any rule that merges on a shared attribute is the e-mail road again.
- **One `Person` kind with a hold field.** A hold is an Operable kind that an operator sets and lifts with a reason in free text, and the person is state that `session` creates in the course of its job; one kind would mix two profiles and make every hold change a write of the person.
- **Assigning subjects only at a directory read.** The first working version has no directory.
- **A separate people actor.** It would add a unit and a second route to the keys for kinds that `session` already writes with the passkeys.
- **The unkeyed hash of the pair as the id.** A reader of the store's ids could test whether a known upstream id is a user.
- **A `LinkKey` kind opened by `session`.** A plaintext key in the memory of a work actor, against [principle 18](/principles/#18-plaintext-lives-only-where-it-is-used-behind-two-independent-checks).
- **Directory facts as durable data.** A fact that a re-sync rebuilds is temp by the definition of the class, and a durable copy would be backed up and restored stale.

## Follow-ups

- Directory sync, the first directory adapter, and the subject before the first sign-in: [#805](https://github.com/truvity/sluis/issues/805).
- The generic OpenID Connect upstream: [#1106](https://github.com/truvity/sluis/issues/1106); subject basics: [#1081](https://github.com/truvity/sluis/issues/1081).
- End-user subject lifecycle and pairwise subjects: [#1024](https://github.com/truvity/sluis/issues/1024).
- Passkeys and step-up: [#885](https://github.com/truvity/sluis/issues/885).
