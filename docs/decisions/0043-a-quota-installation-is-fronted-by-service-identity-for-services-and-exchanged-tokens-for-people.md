# 0043 — A quota installation is fronted by service identity for services and by exchanged tokens for people, and has no console until a consumer exists

**Status:** Proposed
**Layer:** quota module
**Date:** 2026-11-02

Proposal: [issue #1026](https://github.com/truvity/sluis/issues/1026).

## Context

Quota is a piece of its own that runs beside sluis or as an installation of its own ([0015](/decisions/0015-audit-pieces-transport-search-and-front/#four-pieces)). The audit installation has a front of its own, with its own `entry`, `session` and `console` for people ([0015](/decisions/0015-audit-pieces-transport-search-and-front/#the-audit-front)). A quota installation needs a front too, and its callers are different:

- **The hot path is a service calling `Admit` before it does work,** on every request it wants to count. Latency matters, and nobody is signed in.
- **A person calls rarely:** an operator lowers a limit ([REQ-QUOTA-013](/requirements/quota/#REQ-QUOTA-013)), a support engineer corrects a balance with step-up ([REQ-QUOTA-022](/requirements/quota/#REQ-QUOTA-022)).
- **Nobody has asked for a screen.** Nothing without a consumer ([principle 8](/principles/)).
- **A call must be authorised per account.** A service that serves one customer must not admit against another customer's account, and the billing system must not be able to admit. Policy has no state and no network ([0009](/decisions/0009-policy-is-cedar-in-a-rust-actor/#decision)), so facts about the account reach it in the request.

A machine holds no client secret and proves what it is ([0007](/decisions/0007-workload-identity-and-host-enrolment/#proofs-and-the-exchange)). The threats the audit front answers (T-1 to T-7 of the [threat model](/security/threat-model/)) arise from a browser, a cookie and a console; a front without them has fewer.

## Decision

### Service callers

- **A service calls over mutual TLS with its X.509-SVID.** Its SPIFFE ID is its identity ([0007](/decisions/0007-workload-identity-and-host-enrolment/#spiffe-identities)). The front's `entry` verifies the certificate against the trust bundle that the installation declares, and the SPIFFE ID is the caller that scopes request ids ([REQ-QUOTA-017](/requirements/quota/#REQ-QUOTA-017)). When the product's services run in another trust domain, the connection between the boundaries is declared ([0005](/decisions/0005-boundaries-and-the-isolation-ladder/#federation-between-boundaries)), and the call is one of the named flows between installations ([0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#listeners)).
- **No token is exchanged per call.** The certificate is the credential, short-lived and renewed by possession ([0007](/decisions/0007-workload-identity-and-host-enrolment/#proofs-and-the-exchange)); verifying it needs no network call to the issuer. An exchange per `Admit` would put the issuer on the hot path.
- **Every call is authorised by `policy` per account.** Quota reads the account from its state ([0042](/decisions/0042-plan-templates-are-declared-and-accounts-are-issued-at-run-time-by-a-declared-client/#accounts-are-issued)) and sends `policy` the caller's SPIFFE ID, the action (`quota.admit`, `quota.confirm`, `quota.cancel`, `quota.topup`, `quota.adjust`, `quota.account.create`, `quota.statement.read`, `quota.balance`) and the account with its company, plan and state as the resource. Declared Cedar policy says which service identity may do which action on which companies and plans. A refused call changes nothing.
- **Quota may reuse a grant for the same caller, action and account for at most 60 seconds.** A suspended or closed account therefore stops admitting within a minute. The 60 seconds is a ceiling chosen for that, not a measurement; the load test ([0045](/decisions/0045-quota-consistency-and-failure-are-measured-per-state-driver-before-enforcement-is-switched-on/#the-load-test)) may lower it.
- **The installation runs its own `policy` instance with its own declared policy.** Sluis's workforce policy and the product's quota policy are different documents with different reviewers, and neither can change the other.

### People

- **A person reaches the same contract with an exchanged token** (RFC 8693): its audience is the quota installation's registered client, its lifetime at most 5 minutes, and it is bound to the caller's X.509-SVID by mutual TLS (RFC 8705), as for the audit front ([0015](/decisions/0015-audit-pieces-transport-search-and-front/#the-audit-front), [0028](/decisions/0028-grants-come-from-a-declared-vocabulary-and-a-token-carries-fixed-claims-for-one-audience/#lifetimes)). The caller is sluis's console or `sluisctl`, which holds the SVID.
- **The person's identity and assurance reach `policy`** with the token, and policy decides with its own rules. A person's `Adjust` and `TopUp` need the step-up that [REQ-QUOTA-022](/requirements/quota/#REQ-QUOTA-022) names.
- **The installation accepts exchanged tokens from the issuer of its environment boundary only** (T-2, T-3).

### What the front does not have

- **No `session`, no `console`, no passkey ceremony and no browser bundle.** A quota-only installation runs `entry`, `policy`, `quota` and the drivers they need. A person uses a console that already exists (sluis's), through the exchanged token. If a consumer names a screen of its own, such as a customer's balance, the console bundle and the sibling host of the audit front are added by a new record.
- **When quota is combined with sluis, it still has its own `entry`,** as the audit front does, so the front is the same shape everywhere.

### When the issuer is down

- **Service calls continue.** Verifying an SVID needs the cached trust bundle, not the issuer, so `Admit` works for as long as the caller's certificate is valid. A caller whose certificate expires during a long outage is refused, and its rule says whether that fails open or closed ([REQ-QUOTA-011](/requirements/quota/#REQ-QUOTA-011)).
- **People calls stop,** because the exchange needs the issuer. Nothing on the hot path depends on a person.

### Open product facts: who calls `Admit`

This part is **Proposed**; the recommendation is written so that the record can be accepted when the product confirms it.

- **Now, the platform product's own services call `Admit`.** The decisions above are all that this needs.
- **Later, the product's customers' applications may call it,** as a designed extension. They would call the same contract with exchanged tokens for a registered client; the threat model of the audit front then applies in full, an edge connector and a rate limit at the edge are added, and the console question above is asked again. None of that is built until a customer needs it.
- **Confirmation is the open question:** whether the product promises customers a view of their balance or a call of their own. It is tracked in [#1026](https://github.com/truvity/sluis/issues/1026).

## Consequences

- The hot path is one mutual-TLS call, one policy decision at most once a minute per caller, action and account, and one compare-and-set. There is no browser, cookie or console in the quota installation to attack or to build.
- A compromised product service can act only on the accounts its policy names, and every call is audited under its SPIFFE ID.
- The declared policy needs an entry per service identity and plan, reviewed in git. A new service of the product is a policy change.
- Cached grants lag a suspension by up to a minute, so a suspension is not instant at the 60-second ceiling.
- A product that wants a customer-facing balance has to wait for a record, and a consumer.
- `entry` terminates mutual TLS on a listener that other installations reach, which is one of the named flows of [0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#listeners); its deny tests cover it.

## Roads not taken

- **The audit front's whole shape, with `session`, `console` and passkeys.** The full stack and its threats before a consumer exists.
- **An exchanged token for every service call.** One model for people and services, but it puts the issuer and an extra round trip on every `Admit`; caching tokens turns it into the certificate with more steps.
- **Client secrets or API keys for services.** Simple, but sluis holds no machine secrets of that kind ([0007](/decisions/0007-workload-identity-and-host-enrolment/#proofs-and-the-exchange)), and a leaked key is not bound to a workload.
- **No per-account check; the certificate alone grants everything.** The fastest, but a flaw in one service reaches every customer's balance.
- **A gateway filter or a library as the front.** Where a product calls `Admit` in its request path is the product's choice; the front is what quota itself accepts, and it is the same for either.
- **A policy instance shared with sluis.** One document to review, but a workforce policy and a product's quota policy would change together.

## Follow-ups

- The front, `entry` route table, policy schema and tests: [#1026](https://github.com/truvity/sluis/issues/1026).
- Confirm with the platform product who calls `Admit`, and whether customers are promised a balance view: [#1026](https://github.com/truvity/sluis/issues/1026).
- The grant ceiling is measured with the load test: [#915](https://github.com/truvity/sluis/issues/915).
