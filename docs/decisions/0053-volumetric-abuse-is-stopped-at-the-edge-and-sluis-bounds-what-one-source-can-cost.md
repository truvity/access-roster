# 0053 — Volumetric abuse is stopped at the edge, and sluis bounds what one connection, client or source can cost with a token bucket in its own state

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-02

Proposal: [issue #916](https://github.com/truvity/sluis/issues/916).

## Context

A customer-facing installation is reachable by anyone, and it spends real resources on each request: a redirect to someone else's identity provider, a signature in a key service, a write to the state store. The existing text covers the credential endpoints ([REQ-SEC-006](/requirements/sec/#REQ-SEC-006): rate limits per account, factor and source, with a progressive delay; [REQ-SEC-017](/requirements/sec/#REQ-SEC-017): no global lock-out) and the roadmap promises "rate limits per connection". Nothing says where a limit lives, what bounds the state that unauthenticated requests create, or what a noisy tenant can do to its neighbours. The [threat model](/security/threat-model/) lists no availability or abuse threat at all.

The quota actor is a later milestone and is built for admitted work with a strict count and an audited balance ([0017](/decisions/0017-audit-records-the-usage-stream-and-quota/#quota)). A sign-in limiter is a different thing: it protects availability, must be fast, and has no money in it.

## Decision

### At the edge

- **Volumetric protection is the edge's.** Address and network rate limits, bot management, request size and time limits, and denial-of-service absorption belong to the gateway, the web application firewall or the content delivery network in front of the installation ([Edge](/runtimes/kubernetes/#edge)). sluis does not try to be a firewall.
- **An internet-facing production installation declares its edge,** and `sluis config check` warns when it declares none. sluis reads the client address only from a trusted proxy.

### Inside sluis

- **Each of these has its own bound, by a token bucket in `state`:** the sign-in starts per connection; the callbacks per connection; the token endpoint per client; the refresh calls per session; the discovery and key-set refetches per connection; and the sign-in starts per source address and per account on the credential-bearing endpoints ([REQ-SEC-006](/requirements/sec/#REQ-SEC-006)). A bucket is keyed by (boundary, kind, subject of the limit), refilled by time, and moved by compare-and-set ([0011](/decisions/0011-state-is-one-port-with-compare-and-set/)). A bucket is ephemeral: it is not backed up and a restore starts it full.
- **Rates are declared** with the connection's or the client's template, under a maximum in code; a tenant may lower its own and never raise them ([0031](/decisions/0031-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/)).
- **State that unauthenticated requests create is bounded.** A `pending-signin` record lives at most 10 minutes, and each connection and each source address may hold a bounded number of them (default 1000 and 20). A request past a bound is refused before it writes.
- **One connection cannot starve another.** Each pooled connection has a concurrency limit, a timeout and a circuit breaker ([0048](/decisions/0048-customer-connections-run-in-a-pool-per-customer-boundary/#what-a-pool-is-allowed)); a breaker that is open refuses new sign-ins for that connection at once with `UNAVAILABLE`.
- **A refusal is `RATE_LIMITED`** ([0026](/decisions/0026-integrations-return-facts-or-carry-out-effects-that-core-authorised/#what-an-integration-may-return)): HTTP 429 with `Retry-After`, and the generic page of [REQ-UX-001](/requirements/ux/#REQ-UX-001). The reason is in the log only.
- **No limit locks an account out.** Limits are per source and per account together, with a progressive delay ([REQ-SEC-017](/requirements/sec/#REQ-SEC-017)), so an attacker cannot lock a customer out by guessing.
- **The limiter is sluis's own.** It has a narrow interface (allow a cost against a key) and lives in sluis state. Quota is not on the sign-in path. If the quota actor later offers the same interface at the sign-in path's latency and availability, it may back the interface; it does so only after the measurement of [0054](/decisions/0054-capacity-is-measured-before-it-is-promised/), and until then nothing changes.

### The threat model

The [threat model](/security/threat-model/#availability-and-abuse) gains an availability and abuse section, with the threats T-27 to T-32: a sign-in flood, exhaustion of pending state, a noisy or slow tenant provider, sluis used to amplify requests to a provider, a dependency outage, and exhaustion of the key service's request quota. Each has a control from this record or from [0054](/decisions/0054-capacity-is-measured-before-it-is-promised/), a residual and a test.

## Consequences

- A flood is absorbed outside sluis; what gets through is bounded per connection, client and source, so one tenant's burst or provider outage costs that tenant.
- The limiter writes to the state store on every sign-in start, a cost counted in the capacity spike. A bucket with a short refill uses one conditional write per allowed request.
- Operators must size the edge. A sluis behind no edge is protected against cost, not against saturation of its link.
- Requirements: [REQ-SEC-020](/requirements/sec/#REQ-SEC-020), [REQ-SEC-021](/requirements/sec/#REQ-SEC-021), [REQ-SEC-022](/requirements/sec/#REQ-SEC-022), [REQ-SEC-023](/requirements/sec/#REQ-SEC-023), [REQ-SEC-024](/requirements/sec/#REQ-SEC-024), [REQ-SEC-025](/requirements/sec/#REQ-SEC-025), [REQ-SEC-026](/requirements/sec/#REQ-SEC-026), [REQ-FED-034](/requirements/fed/#REQ-FED-034) are added.

## Roads not taken

- **Everything at the edge.** The edge does not know connections, clients or tenants, so one tenant's loop would look like traffic.
- **Everything in sluis.** It spends sluis's own capacity to refuse what a firewall refuses for free, and it puts sluis on a link it cannot defend.
- **Waiting for the quota actor.** The milestone's own done-when asks for limits per connection, and quota is a later milestone.
- **The quota actor on the sign-in path.** It would make a strict, audited counter an availability dependency of every sign-in.
- **A global lock-out after failures.** It turns guessing into a way to lock customers out.
- **A fixed global rate limit.** One busy product would starve the others.

## Follow-ups

- The limiter, the bounds and the breakers in the generic OIDC upstream: [#916](https://github.com/truvity/sluis/issues/916).
- Rate limits on the credential endpoints: [#796](https://github.com/truvity/sluis/issues/796).
