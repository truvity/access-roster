# 0048 — Customer-owned upstream connections run in a pool per customer boundary, and every other connector keeps its own process

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-02

Proposal: [issue #916](https://github.com/truvity/sluis/issues/916).

## Context

[0026](/decisions/0026-integrations-return-facts-or-carry-out-effects-that-core-authorised/#splitting-by-credential) runs one integration process per vendor tenant and capability, [REQ-ISO-051](/requirements/iso/#REQ-ISO-051) says so for every integration instance, and threat T-15 relies on it. On Kubernetes that is a pod per integration with its own egress policy ([Kubernetes](/runtimes/kubernetes/#what-runs-where)). The rule protects what a connector holds: a vendor credential that can read a directory or mint a credential. For a directory, a GitHub App or a cloud minter that stays true.

A customer organisation that brings its own identity provider is a different case. Its connection holds one client ID and one client secret at someone else's provider, and it can only run the sign-in flow. With the tenants of [0047](/decisions/0047-a-customer-identity-installation-is-a-front-a-few-customer-boundaries-and-key-less-tenants/#tenants) there can be thousands of such connections, and a pod each is thousands of pods, with a cold start on the sign-in path. Principles 1 and 3 (isolation) and 9 and 10 (it must run on a real installation) pull apart; the weight of the credential decides which one wins where.

## Decision

### Two classes of connection

- **A dedicated connection** is a process of its own with its own platform identity, one per vendor tenant, as [0026](/decisions/0026-integrations-return-facts-or-carry-out-effects-that-core-authorised/#splitting-by-credential) says. Every directory connector, every minter and notifier, the connections of company boundaries, and the single connection of a customer boundary to its customer-identity product are dedicated.
- **A pooled connection** is a generic OpenID Connect connection that belongs to a tenant of a customer boundary. It runs in the pool of that customer boundary, `oidc-pool` (one for each customer boundary): a few replicas of one process kind that serve every pooled connection of that boundary.

The class is a property of the connection kind and its owner, and it cannot be chosen per connection by a tenant.

### What a pool is allowed

- **One customer boundary only.** A pool never serves connections of two boundaries, so a compromise of a pool reaches the connections of one customer boundary.
- **No authority key and no directory credential** ([REQ-ISO-052](/requirements/iso/#REQ-ISO-052)). A pool holds client credentials only: the client secret of each pooled connection, sealed per connection with the connection in the encryption context, opened for one call and not kept. A `private_key_jwt` key per connection is refused, because it would be a key per tenant; an identity provider that accepts no client secret needs a dedicated connection.
- **Egress through a proxy.** The pool cannot list thousands of provider hosts in a network policy. Its policy admits only the egress proxy, and the proxy admits a request for a connection that exists, to the hosts of that connection's discovery document, after the address check of [REQ-FED-008](/requirements/fed/#REQ-FED-008) (no loopback, link-local or private address after name resolution). A dedicated connection keeps the declared host list of [0026](/decisions/0026-integrations-return-facts-or-carry-out-effects-that-core-authorised/#splitting-by-credential).
- **The bounds of [0053](/decisions/0053-volumetric-abuse-is-stopped-at-the-edge-and-sluis-bounds-what-one-source-can-cost/#inside-sluis).** Each connection has its own concurrency limit, timeout and circuit breaker, so a slow provider of one tenant cannot use up the pool's workers for the others.
- **Facts only.** A pool returns the assertion of [0026](/decisions/0026-integrations-return-facts-or-carry-out-effects-that-core-authorised/#the-upstream-contract) and decides nothing. The person's tenant is set by the connection's owner in declared or issued configuration, never read from what the provider sent.
- **State separation.** A pooled connection's pending sign-in state and its keys in `state` carry the connection and the tenant, and the port library scopes every call to them ([REQ-ISO-003](/requirements/iso/#REQ-ISO-003)).

### Scaling

The number of pooled processes grows with the sign-in rate and the number of customer boundaries, not with the number of tenants. A pool has at least two replicas, spread over zones. The sizing is a measurement of [0054](/decisions/0054-capacity-is-measured-before-it-is-promised/), not a figure of this record.

### What this changes

- **[REQ-ISO-051](/requirements/iso/#REQ-ISO-051) applies to dedicated connections,** and a new record bounds the pool. **Threat T-15** is read the same way, with the pool's residual risk named in the [threat model](/security/threat-model/#integrations-policy-and-companies): a pool compromise reaches the client secrets of one customer boundary's pooled connections, which let an attacker pose as sluis at those providers' token endpoints and nothing more; it reads no directory and mints nothing.
- **[0026](/decisions/0026-integrations-return-facts-or-carry-out-effects-that-core-authorised/#splitting-by-credential) and [0005](/decisions/0005-boundaries-and-the-isolation-ladder/#what-each-boundary-owns)** gain a sentence for the pooled class.
- **The OIDC upstream page** shows `oidc@<name>` for a dedicated connection and the pool for a tenant's.

## Consequences

- Thousands of customer connections need a handful of pods. A sign-in through a tenant's provider needs no cold start.
- A pool is a bigger prize than one connection: it holds the client secrets of a product's pooled connections. The prize is small (a client secret at a provider, usable only with a user's authorization code and the redirect URI sluis registered), and the pool holds nothing that signs for sluis.
- A tenant whose provider needs a client key, or whose connection must be separately failed, rotated or left, moves to a dedicated connection by a declared change.
- The egress proxy is a component to run, patch and watch, and its allow-list is data derived from the connection records.
- Requirements: [REQ-ISO-079](/requirements/iso/#REQ-ISO-079), [REQ-ISO-080](/requirements/iso/#REQ-ISO-080), [REQ-ISO-081](/requirements/iso/#REQ-ISO-081), [REQ-ISO-082](/requirements/iso/#REQ-ISO-082) are added, and REQ-ISO-051 is reworded for dedicated connections.

## Roads not taken

- **A process per connection, scaled to zero.** It keeps the old rule whole but costs a pod or a cold start per tenant and thousands of network policies.
- **One pool for every connection of the installation.** A compromise would reach every product's connections, and a noisy product would starve the others.
- **A key per pooled connection for `private_key_jwt`.** It is a key per tenant, which [0012](/decisions/0012-cryptography-and-authority-keys/#when-keys-are-shared-and-when-separate) rules out.
- **Pooling directory connectors as well.** They hold credentials that read a company's people; the strong rule stays where the credential is strong.
- **Letting each tenant choose pooled or dedicated.** A tenant could buy isolation by declaration, or force a pod per tenant.
- **A static host list for the pool.** Thousands of entries to keep in a network policy that the platform enforces poorly.

## Follow-ups

- The pool, the egress proxy and the per-connection bounds in the generic OIDC upstream: [#916](https://github.com/truvity/sluis/issues/916).
