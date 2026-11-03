# 0055 — Upstream signals: back-channel logout ends sessions by `sid`, a status call suspends or erases a person, and a global sign-out reaches every client

**Status:** Superseded by 0034
**Layer:** CIAM module
**Date:** 2026-11-03

Proposal: [issue #916](https://github.com/truvity/sluis/issues/916).

## Context

A workforce directory is pulled, so sluis learns that a person was removed ([0019](/decisions/0019-person-and-upstream-link/#directory-facts-parity)). A customer-identity upstream has no directory pass. Three gaps follow.

- **Inbound logout.** The upstream may end a session; sluis has records for outbound back-channel logout ([REQ-SESS-009](/requirements/sess/#REQ-SESS-009)) and none for inbound. The upstream's `sid` is not tied to any sluis session.
- **Disable and delete.** Back-channel logout ends a session and does not mark a person gone. [REQ-SESS-024](/requirements/sess/#REQ-SESS-024) and [REQ-SUBJ-043](/requirements/subj/#REQ-SUBJ-043) assume sluis "learns" it. A human session is bounded by 24 hours ([0018](/decisions/0018-sessions/#human-sessions)), but an agent session lasts weeks, and a regulated customer may not wait a day.
- **Global sign-out.** One sign-out at one product must end the person's sessions at all the products, and [REQ-SESS-022](/requirements/sess/#REQ-SESS-022) words it so that sluis would not know which receivers know the person, which cannot be done while sluis holds a session per client.

## Decision

### Inbound back-channel logout

- **sluis registers a back-channel logout URI and `backchannel_logout_session_required=true` with each upstream that supports it.** `entry` routes the logout token to the connection that owns it, as it routes any push ([0025](/decisions/0025-integrations/#splitting-by-credential)); the connection checks it as OpenID Connect Back-Channel Logout 1.0 requires: signature against the connection's key set, `iss`, `aud` equal to sluis's client ID, `iat` and `exp`, the `events` claim, no `nonce`, a `sid` or a `sub`, and a `jti` accepted once. It returns the `sid` and the subject-claim value as a fact; it decides nothing.
- **The mapping is by `sid`.** At sign-in, `session` records the upstream's `sid` in an `upstream-session` record, keyed by a keyed hash of (connection, `sid`), pointing to the sluis browser session. A logout token with a `sid` ends that browser session and every human session under it ([0018](/decisions/0018-sessions/#human-sessions)). A token with only a `sub` ends every human session of that person that came through that connection. A logout token for a `sid` that sluis does not know is acknowledged and changes nothing.
- **Agent sessions are not ended by a logout,** as for a person's sign-out at sluis ([0018](/decisions/0018-sessions/#agent-sessions)). A status signal ends them.
- **Logout is best-effort.** A missed delivery is bounded by the session's absolute limit.

### Disable and delete

- **A person's status arrives as a call to sluis,** `suspend`, `resume` and `erase`, made over workload identity by a declared client of the customer boundary, in practice the customer-identity module or a small adapter that listens to the upstream's own events. The call names the person by connection and subject-claim value, never by e-mail address. It is audited under the client's name.
- **`suspend` and `erase` take effect at once** (tighten-only, [0004](/decisions/0004-the-data-model/#storage-classes)): a suspended person is refused everywhere and every session, agent sessions included, ends. **`resume` lifts only `suspended`,** never a hold an operator set, and gives back only what declared policy grants. The states are those of [0034](/decisions/0034-end-users-and-upstream-signals/#states); the status is a `person-status` record, observed from outside and written by the status operation's owner, not by the operator-set hold.
- **The standard channel is a second source of the same fact,** not another mechanism. When an upstream transmits OpenID Shared Signals events (CAEP `account-disabled`, `account-enabled`, `account-purged`), a receiver turns them into the same `person-status` fact. It is built with its first upstream that transmits them ([REQ-CIAM-006](/requirements/ciam/#REQ-CIAM-006) is the transmitting side).
- **A connection with no status source gets no agent sessions.** Agent sessions must end when the person is disabled ([0018](/decisions/0018-sessions/#agent-sessions)), and sluis can promise that only where it can be told. A human session needs no source: its bound is the 24 hours and the silent renewal that fails once the upstream refuses the account ([0018](/decisions/0018-sessions/#customers)).

### Global sign-out

- **A sign-out at a client ends the person's browser session and every human session under it,** at every client ([REQ-SESS-011](/requirements/sess/#REQ-SESS-011)). sluis holds a session record per client and per boundary, so it knows which clients to tell.
- **Each client with a registered back-channel URI gets one logout token per ended session,** with retries and an alarm on a dead letter ([REQ-SESS-009](/requirements/sess/#REQ-SESS-009), [REQ-SESS-010](/requirements/sess/#REQ-SESS-010), [REQ-SESS-021](/requirements/sess/#REQ-SESS-021)). The front tells each customer boundary, which ends its sessions and tells its own clients; a boundary's session never outlives the one that seeded it ([REQ-SESS-033](/requirements/sess/#REQ-SESS-033)).
- **Ending many sessions at once is a job:** paginated, asynchronous and idempotent ([REQ-PERF-002](/requirements/perf/#REQ-PERF-002), [#1062](https://github.com/truvity/sluis/issues/1062)). A tenant's removal, a suspended person with many sessions and a compromised provider all use it. Listing the sessions of a connection needs the state port's listing by prefix ([#1009](https://github.com/truvity/sluis/issues/1009)).
- **REQ-SESS-022 is withdrawn.** Its wording asked for a privacy property that the design does not have and does not need; the new records state what is tested.

## Consequences

- A customer disabled at the upstream is out of every session within the delivery time of the status call, and out of human sessions within 24 hours without it.
- The status call is an authority-bearing API with a small blast radius: it can suspend or erase, and resume only what it suspended. A stolen client key can lock customers out of one customer boundary until an operator resumes them, which the audit shows.
- A connection without a status source loses agent sessions. That is the price of the promise in [0018](/decisions/0018-sessions/#agent-sessions).
- The `sid` mapping adds one ephemeral record per session; it holds no personal data.
- Requirements: [REQ-FED-029](/requirements/fed/#REQ-FED-029), [REQ-FED-030](/requirements/fed/#REQ-FED-030), [REQ-FED-031](/requirements/fed/#REQ-FED-031), [REQ-FED-032](/requirements/fed/#REQ-FED-032), [REQ-FED-033](/requirements/fed/#REQ-FED-033), [REQ-SESS-038](/requirements/sess/#REQ-SESS-038), [REQ-SESS-039](/requirements/sess/#REQ-SESS-039), [REQ-SESS-040](/requirements/sess/#REQ-SESS-040), [REQ-SESS-041](/requirements/sess/#REQ-SESS-041), [REQ-SUBJ-056](/requirements/subj/#REQ-SUBJ-056) are added; REQ-SESS-022 is withdrawn.

## Roads not taken

- **Shared Signals as the only channel.** It is the standard, but no upstream is known to transmit it, and without a consumer it would leave customers without a signal.
- **Polling the upstream for status.** OpenID Connect has no call for it, and a per-refresh check of the upstream would make every token a round trip.
- **Treating back-channel logout as disable.** A logout ends a session, not an account; a person who signed out would be locked out.
- **Ending agent sessions on logout.** It would break background agents at every sign-out, which [0018](/decisions/0018-sessions/#agent-sessions) refuses.
- **A pull of the upstream's user list.** That is the directory, which a customer-identity product need not offer and which makes sluis a copy of the accounts.
- **Letting the module set an operator hold.** Its suspension would mix an observed status with an operator's lasting choice, which [0004](/decisions/0004-the-data-model/#storage-classes) keeps apart.

## Follow-ups

- Inbound back-channel logout and the status operations: [#916](https://github.com/truvity/sluis/issues/916).
- Outbound back-channel logout and the sign-out fan-out: [#780](https://github.com/truvity/sluis/issues/780).
- Mass revocation: [#1062](https://github.com/truvity/sluis/issues/1062).
- The Shared Signals receiver, with its first transmitting upstream: [#927](https://github.com/truvity/sluis/issues/927).
