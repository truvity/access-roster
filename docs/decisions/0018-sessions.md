# 0018 — Sessions have three classes with limits per class, and session chains are temp kinds

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #998](https://github.com/truvity/sluis/issues/998).

## Context

`session@<boundary>` keeps the session chains, the session cookie and each person's freshness per boundary ([0002](/decisions/0002-families-of-actors/#the-four-families)). The requirements say that a refresh token ends at sign-out, at an idle limit and at an absolute limit (REQ-SESS-015), with one idle and one absolute limit for every refresh token.

Three kinds of caller hold tokens, and they differ in what a limit can measure and in who may end them:

- **A person at a browser, the console or the CLI.** The person is present now and then, signs out, and can be asked to authenticate again. v1 ended every chain at an absolute limit of 24 hours from `auth_time`, never reset by use, with an idle limit of 12 hours on the refresh token (v1 ADR 0001 on `master`, and v1's `lifetimes.refresh`).
- **An agent acting on a person's behalf,** such as an MCP client, after the person consented. It runs in the background, often for weeks, with no person to answer a prompt. Its client is identified by a Client ID Metadata Document URL ([#792](https://github.com/truvity/sluis/issues/792)) and its tokens are bound to a resource with RFC 8707 ([#822](https://github.com/truvity/sluis/issues/822)). v1 gave such clients their own class: 14 days idle, 30 days from `auth_time` with a ceiling of 90 days, and access tokens of at most 30 minutes (v1 ADR 0040), and a person's browser sign-out did not end them.
- **A machine or workload** with a workload proof ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)). Nobody is present; there is nothing to sign out of.

The test of [principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule) for sharing a key, equal audience, lifetime and revocation, keeps things apart here too. A boundary's session is seeded from the front's sign-in through token exchange ([0017](/decisions/0017-identity-and-sign-in/#step-up)), so a limit at one boundary is worthless if another can extend it. CIMD (#792), MCP authorization (#822) and agent-class sessions (#794) are in the parity milestone; this record fixes the classes now so that parity adds them without retrofitting the session model.

A session is state that may be lost: a lost chain costs a sign-in and never data. That makes it a temp kind, with a time to live, and it fixes where the limits live.

## Decision

### The classes

- **Every session has a class, fixed when it is created and never changed:** `human` or `agent`. Policy chooses the class from the client's declaration; a client never declares its own class, and a fetched client document cannot ([0021](/decisions/0021-clients/#self-described-clients)). A policy change can shorten a session, never lengthen it or change its class.
- **A machine or workload client has no session.** A workload exchange gets short-lived tokens and no refresh token, no session chain and no `sid`. A caller that needs a fresh token presents its proof again.

### Session chains

- **A session is a `SessionChain`,** a temp kind that `session` writes ([0004](/decisions/0004-the-data-model/#storage-classes)). It holds the hash of the current refresh token and its spent markers, the class, the client, the `sid`, the start and the last refresh, the freshness of the person's authentication for the boundary, the resource of the chain ([0021](/decisions/0021-clients/#resources)) and, for an agent, the consent. Its treatment is hashed: a refresh token is compared, never read back ([0004](/decisions/0004-the-data-model/#treatment)).
- **A spent marker catches reuse.** Every refresh rotates the token; presenting a spent token ends the chain at once (REQ-SESS-001).
- **The time to live of a chain is its absolute limit.** A human chain lasts 24 hours absolute. An agent chain lasts 14 days idle and 30 days absolute, and 90 days at most, which is the built-in maximum ([0004](/decisions/0004-the-data-model/#storage-classes)). An expired chain reads as absent ([0005](/decisions/0005-the-store/#time-to-live)).
- **A chain is lost with the temp class and is not in a backup.** After a restore, everyone signs in again ([0010](/decisions/0010-backup-and-recovery/#restore)).
- **The person lists and revokes chains.** The listing uses the declared indexes by person and by client, and the console routes a revoke to `session` ([0027](/decisions/0027-the-console/#writes)).
- **The session cookie is sealed and opened at key@ on every request,** under the boundary's `cookie` data key, in a batch with the other opens of the request. `session` never holds that key ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)). The cost of that hop on Lambda was measured in the latency spike ([#1179](https://github.com/truvity/sluis/issues/1179)): on 2026-11-03, a whole warm sign-in takes about 0.40 s at p50 and 0.49 s at p99, and about 0.29 s and 0.36 s with concurrent reads.

### Human sessions

- **An absolute limit from the start of the session, never reset by use:** the start is the moment sluis accepted the sign-in that began the session, and the `auth_time` of a token stays the upstream's ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)). Default 24 hours, as in v1, which is also its maximum: an installation or a tenant may only shorten it. A token's `exp` is capped at the limit, a refresh past it is refused, and a silent authorization past it ends the browser session.
- **An idle limit on each refresh token, under the absolute limit:** default 12 hours, as in v1, and never above the absolute limit. A per-client session ends at the earlier of the last refresh plus the idle limit and the session's start plus the absolute limit, recomputed at every rotation.
- **Step-up re-authentication** follows [0017](/decisions/0017-identity-and-sign-in/#step-up). A step-up refreshes the freshness of the authentication, not the session's start, so it does not extend the absolute limit.
- **The person's sign-out ends the browser session and every human session under it,** at every client, with back-channel logout to the clients that registered for it.
- **The limits bind the browser session and its refresh tokens alike.** The console's session is a human session.

### Agent sessions

- **An agent session starts only from a consent the person gave interactively.** The consent names the client, the resources and their scopes, and is recorded on the chain; an agent authorization never completes silently.
- **No interactive idle timer.** An agent session has an inactivity expiry on its refresh token (default 14 days) and an absolute lifetime from the consent (default 30 days, maximum 90 days). Its access tokens last at most 30 minutes (maximum 1 hour).
- **It never outlives the person or the consent.** Revoking the consent, the directory disabling the person, an operator's revoke, and refresh-token reuse each end it at once. Every refresh re-checks the consent and the person's state.
- **Refresh tokens rotate** at every use, as for every class (REQ-SESS-001).
- **Tokens are narrow:** one resource per token (RFC 8707), with the scopes the consent names for that resource. They are sender-constrained by DPoP where the client supports it, when DPoP arrives ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#binding)).
- **The person's sign-out does not end agent sessions,** and the sign-out page says so.
- **Each agent session is listed and revocable by the person,** in the console, and its start, its use and its end are audit facts.
- **Concurrent agent sessions are capped per person and client:** a default of 5 and a maximum of 20, set per installation. A new consent past the cap is refused; the person revokes one first.

### Across boundaries

- **A boundary's session never outlives the session that seeded it.** The exchange into a boundary carries the original start and class of the session, and the boundary applies its own limits under them, so it can shorten and never lengthen.

### Customers

A customer is a human session like any other: sluis adds no class and no limit longer than 24 hours for the people of a customer-identity product ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)).

- **The upstream holds the long single-sign-on session.** sluis keeps the 24-hour absolute limit above. When it ends, sluis authenticates the person at the upstream again, silently with `prompt=none` while the upstream's own session is valid, and interactively otherwise. A silent authentication starts a new session with a fresh check of the upstream and of the person's state; it does not extend the old one (REQ-SESS-035). The renewal is for connections of trust `customer` and `partner`; an `internal` connection keeps the periodic full sign-in of [0017](/decisions/0017-identity-and-sign-in/#passkeys) ([0033](/decisions/0033-customer-connections/#connection-trust)).
- **A customer's step-up is a re-authentication at the upstream** with the `acr_values` and `max_age` that policy asked for ([0017](/decisions/0017-identity-and-sign-in/#step-up)). sluis enrols no factor and asks for no passkey of a person who signs in through a customer upstream (REQ-SESS-036, REQ-SESS-037).

### Configuration

- **The limits are fields of the layered kind `TokenLifetime`,** per class, with the combine rule shortest wins ([0004](/decisions/0004-the-data-model/#layered-and-linked-kinds)). The layers are the built-in hard caps ([0006](/decisions/0006-keys-and-sealing/#floors-in-code)), the config kind `TokenLifetime`, and the durable kind `TokenLifetimeTenant`, which a tenant admin writes and `exchange` owns. A tenant's value longer than config is refused at the store; a tenant that shortens its people's sessions is tightening, and that takes effect at once.
- **The configuration check refuses** a value above a maximum, an idle limit above its absolute limit, and an agent class on a client that exchanges a person's token for other credentials.

## Consequences

- A person signs in at most once a working day on each device. An abandoned browser or laptop stops refreshing after 12 hours.
- An agent keeps working for weeks without the person present, yet it stops at once when the person leaves, is disabled or withdraws the consent. The cost is a second set of limits, a consent on the chain and a listing the person must be able to read.
- Agents are not ended by sign-out, which surprises some people; the sign-out page and the listing make it visible, and an operator revoke ends them.
- Machine clients have nothing to revoke but their credential; a revocation reaches them when their last token expires, so their tokens stay short.
- A cap on agent sessions bounds the damage of a client that registers a new session on every start.
- A customer is signed out of sluis at least once a day and back in by the upstream without a prompt, so a customer whom the upstream has disabled is refused within 24 hours at the latest, whatever the length of the upstream's own session. The cost is one silent redirect a day and a dependence on the upstream's session outlasting it.
- Every request that carries a session cookie costs one batched open at key@. On Lambda that is an invoke, and its cost is the open measurement of the latency spike.
- Chains live in the temp class, so a lost engine or a restore signs everyone out. That is the price of keeping sessions out of backups and out of the durable engine.
- Requirements: REQ-SESS-015 is narrowed to human sessions; [REQ-SESS-025](/requirements/sess/#REQ-SESS-025) to [REQ-SESS-037](/requirements/sess/#REQ-SESS-037) are added.

## Roads not taken

- **A human absolute limit above 24 hours.** v1 kept 24 hours, and a person who needs a longer-lived grant is what the agent class is for.
- **A cap of one agent session per person and client.** A person who uses the same client on two devices would lose one each time they signed in on the other.
- **No default cap, left to each installation.** An installation that sets none would have no bound on live agent grants.
- **One idle and one absolute limit for every refresh token.** An agent would either stop every day or a person's browser would stay signed in for a month.
- **An idle timeout measured at the issuer for agents.** An agent refreshes on its own schedule, so the issuer has no signal of a person's attention to measure.
- **Agent sessions ended by the person's sign-out.** Signing out of a browser would silently break every background agent; v1 made the same choice for the same reason.
- **Sessions for machine clients.** A session needs someone who signs in and out; a machine has a proof, and a session record would only be state to keep and revoke.
- **The class declared by the client or its metadata document.** Anyone who publishes a document could give their client a month-long session.
- **A fourth class for customers, or a longer limit per tenant.** A second maximum to defend, and a window of weeks after a disable that nothing signals yet; the upstream already holds the long session.
- **A boundary that sets its own limits from scratch.** A boundary could then extend a session the front had already ended.
- **Chains as durable data.** A chain would survive a lost engine, but a restore would bring back sessions of people who were signed out or removed since the archive, and every refresh would be a durable write.
- **The session cookie opened by `session` with a key of its own.** It would save a hop, but a plaintext cookie key would sit in the memory of a work actor ([principle 18](/principles/#18-plaintext-lives-only-where-it-is-used-behind-two-independent-checks)).

## Follow-ups

- Sessions, sign-in, listing and revocation for people: [#793](https://github.com/truvity/sluis/issues/793).
- Agent-class sessions and consent: [#794](https://github.com/truvity/sluis/issues/794); MCP authorization: [#822](https://github.com/truvity/sluis/issues/822); Client ID Metadata Documents: [#792](https://github.com/truvity/sluis/issues/792).
- Sender-constrained tokens with DPoP: [#912](https://github.com/truvity/sluis/issues/912).
