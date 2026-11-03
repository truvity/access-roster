# 0033 — Customer connections run in a pool per customer boundary, and a domain routes only after DNS proof

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-03

Proposal: [issue #916](https://github.com/truvity/sluis/issues/916).

## Context

When more than one upstream is connected, sluis must decide where to send a person: to the customer-identity product that is the default, or to the identity provider of the person's own organisation. Five things were left open or in conflict.

- **Home-realm discovery** (routing by the domain of an e-mail address) and its **proof** by a DNS record are [REQ-FED-006](/requirements/fed/#REQ-FED-006), and the [OIDC upstream](/integrations/oidc-upstream/) page marks both as Proposed.
- **A connection's trust.** [REQ-FED-004](/requirements/fed/#REQ-FED-004) gives a connection a "trust policy" of an assurance ceiling, methods and an age, [REQ-AUTHN-010](/requirements/authn/#REQ-AUTHN-010) states the ceiling again, and the page has a `trust` field that limits what a sign-in may reach. Two ideas share one word.
- **`idp_hint`** is named in #916 and has no record.
- **Groups.** [REQ-FED-016](/requirements/fed/#REQ-FED-016) says sluis must not read upstream roles or groups, and the [OIDC upstream](/integrations/oidc-upstream/) page offers `groups: ignore | map | trust`.
- **Who serves thousands of connections.** A customer organisation that brings its own identity provider holds one client ID and one client secret at someone else's provider, and the connection can only run the sign-in flow. With the tenants of [0032](/decisions/0032-customer-identity-installations/#tenants) there can be thousands of such connections, and a process each would be thousands of pods with a cold start on the sign-in path.

A tenant's identity provider is controlled by that tenant's administrators. It can send any subject, any e-mail address and any group, so what it says is a claim ([principle 4](/principles/#4-verify-never-trust-a-claim)).

## Decision

### Choosing the connection

A sign-in request reaches a connection by the first rule that applies:

1. **`idp_hint`.** The client may send `idp_hint=<connection name>`. The name must be one of the connections that the client's customer boundary and tenant allow: the boundary's upstreams and the tenant's own `TenantConnection` items. Any other value, or an unknown one, is refused with `invalid_request`. A hint chooses among existing connections and cannot create or widen one. A hint is chosen by the client, not typed by the person, so a refusal reveals nothing about people.
2. **The client's default connection,** declared with the client. For single sign-on across products this is the customer-identity product.
3. **Discovery by domain,** only for a client that declares it. The sign-in page asks for an e-mail address, takes its domain and looks for a verified domain with an exact match. A domain with no connection, and an address that does not parse, go to the client's default connection, so the answer never tells whether a domain or an address is known.

The e-mail address typed on that page is a hint to route. It is not an identity and is never stored, matched or linked ([REQ-SUBJ-039](/requirements/subj/#REQ-SUBJ-039)).

### Domain proof

- **A domain is routable only after a DNS TXT record proves control** ([REQ-FED-006](/requirements/fed/#REQ-FED-006)). The record is `_sluis-challenge.<domain>`, and its value is a token that sluis made for that connection and tenant. The claim is a `DomainClaim` of the tenant, written by `session`.
- **One domain, one connection, in one customer boundary.** A second claim on a verified domain is refused until the first is released. A suffix such as `co.uk` is refused (the public suffix list), and only the exact domain routes: a verified `example.com` does not route `sub.example.com`.
- **The proof is checked again** every 24 hours and when the record's expiry passes, by a background job under a lease ([0005](/decisions/0005-the-store/#leases)). A domain that fails to prove for three checks in a row stops routing and is reported; its persons are not touched.
- **Proof of a domain is for routing only.** It does not make an address a key, and it does not vouch for any claim of the provider.

### Connection trust

A connection has two separate fields, which resolves the overlap:

- **`trust` limits reach.** It is one of `internal` (the operator's own workforce directory), `partner` (an organisation the operator has agreed with) and `customer` (end users of a product, including a tenant's own provider). The policy compiles it into Cedar `forbid` guards: a person who came through a connection can hold only grants in scopes that their trust level and, for a tenant's connection, their tenant may reach ([REQ-ISO-036](/requirements/iso/#REQ-ISO-036) is the model; [0007](/decisions/0007-policy-and-sealed-grants/#four-layers) says how guards are composed). A `customer` person never reaches an `all:` scope or a scope another tenant owns.
- **`assurance` limits strength.** It is the policy of [REQ-FED-004](/requirements/fed/#REQ-FED-004): an `acr` ceiling ([REQ-AUTHN-010](/requirements/authn/#REQ-AUTHN-010)), optionally required `amr` values, and a maximum authentication age. The upstream's `acr` values are mapped to the values that sluis's policy names by a per-connection table; an unmapped value is unknown, and a value above the ceiling is lowered to it.
- **An `internal` connection does not renew silently.** The periodic full sign-in with multi-factor authentication of [0017](/decisions/0017-identity-and-sign-in/#passkeys) stays; `customer` and `partner` connections renew as [0018](/decisions/0018-sessions/#customers) says.
- **A tenant cannot raise either.** Both are bounded by the client template in config ([0004](/decisions/0004-the-data-model/#profiles)): the template names the highest `trust` and ceiling a tenant's connection may carry, the store refuses a `TenantConnection` outside it ([0005](/decisions/0005-the-store/#rules)), and a tenant's own provider never exceeds `customer`.

### Claims and groups

- **sluis reads only the connection's claim allow-list** ([REQ-FED-005](/requirements/fed/#REQ-FED-005)). Per-connection claim mapping renames an allowed claim to a fact that policy knows; it never invents one.
- **`groups` and roles of an upstream are not read.** A connection has no `groups` choice, and none can trust groups. A person's grants come from sluis's bindings in policy ([0019](/decisions/0019-person-and-upstream-link/#what-policy-sees)). A product that wants the organisation's groups keeps them in its own module.

### A pool per customer boundary

**A tenant's own OpenID Connect connections are served by the pool of its customer boundary: `adapter-upstream-oidc@<boundary>`, a few replicas of one work actor that serve every connection of that boundary.** An adapter holds no credential at rest and opens each connection's client secret at `key@` for each call ([0002](/decisions/0002-families-of-actors/#work-actors)), so one actor can serve thousands of tenants without holding any of their secrets. The number of processes grows with the sign-in rate and the number of customer boundaries, not with the number of tenants.

#### What a pool is allowed

- **One customer boundary only.** An actor belongs to one boundary ([Names](/decisions/0002-families-of-actors/#names)), so a pool never serves the connections of two boundaries, and a compromise of a pool reaches the connections of one customer boundary.
- **No authority key and no directory credential** ([REQ-ISO-052](/requirements/iso/#REQ-ISO-052)). A pool reads a `TenantConnection`, whose client secret is sealed under its tenant's `data` key with the connection's address as authenticated data, and asks `key@` to open it for one call under a grant sealed for that tenant ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)). It does not keep the plaintext. A `private_key_jwt` key per connection is refused, because it would be an authority key per tenant ([principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule)); an identity provider that accepts no client secret cannot be a tenant's connection.
- **Egress through a proxy.** The pool cannot list thousands of provider hosts in a network policy. Its egress policy admits only the egress proxy, a platform piece and not an actor ([0002](/decisions/0002-families-of-actors/#platform-pieces)), and the proxy does the address check of [REQ-FED-008](/requirements/fed/#REQ-FED-008) (no loopback, link-local or private address after name resolution) and nothing else, because it holds no data port and cannot read a connection. Each adapter restricts every call to the hosts of its connection's discovery document.
- **The bounds of [0036](/decisions/0036-volumetric-abuse/#inside-sluis).** Each connection has its own concurrency limit, timeout and circuit breaker, so a slow provider of one tenant cannot use up the pool's workers for the others.
- **Facts only.** A pool returns the assertion of [0025](/decisions/0025-integrations/#the-upstream-contract) to `session` and decides nothing. The person's tenant is set by the owner of the connection, in its record, never read from what the provider sent.
- **State separation.** A pending sign-in and the keyed hashes it makes carry the connection and the tenant in their address, and the store scopes every call to the caller's grant ([REQ-DATA-013](/requirements/data/#REQ-DATA-013)).

#### Scaling

A pool has at least two replicas, spread over zones. The sizing is a measurement of [0037](/decisions/0037-capacity-is-measured-before-it-is-promised/), not a figure of this record.

#### Where the pool meets other rules

- **[REQ-ISO-079](/requirements/iso/#REQ-ISO-079) to [REQ-ISO-082](/requirements/iso/#REQ-ISO-082) bound the pool.**
- **The residual risk of a pool:** a compromise reaches the client secrets of the sign-ins in flight at that moment, which let an attacker pose as sluis at those providers' token endpoints and nothing more. It reads no directory, mints nothing, and holds no secret that it could replay later.

## Consequences

- A tenant can bring its own provider and cannot take over another tenant's domain, widen its trust, or ride its provider's group claims into grants.
- The default path, one product-wide upstream, needs no discovery and no domain at all.
- Thousands of customer connections need a handful of pods. A sign-in through a tenant's provider needs no cold start.
- A pool is a bigger prize than one connection: a flaw in it is a flaw in every sign-in of its boundary. The prize is small (a client secret at a provider, usable only with a user's authorization code and the redirect URI sluis registered), the pool holds nothing that signs for sluis, and it holds no secret between calls.
- The DNS proof needs a resolver that sluis can trust: it queries through the egress proxy with the address checks above, and a spoofed answer is as strong as the resolver. DNSSEC validation is used where the resolver offers it.
- The egress proxy is a component to run, patch and watch. It does the address check only, so a compromised adapter can reach any public host through it; keeping a call to its connection's hosts is the adapter's.
- An organisation that moves its provider keeps its domain and replaces the connection; the persons it had through the old connection are new persons through the new one ([0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)).
- Requirements: [REQ-FED-022](/requirements/fed/#REQ-FED-022), [REQ-FED-023](/requirements/fed/#REQ-FED-023), [REQ-FED-024](/requirements/fed/#REQ-FED-024), [REQ-FED-025](/requirements/fed/#REQ-FED-025), [REQ-FED-026](/requirements/fed/#REQ-FED-026), [REQ-FED-027](/requirements/fed/#REQ-FED-027), [REQ-FED-028](/requirements/fed/#REQ-FED-028), [REQ-SESS-042](/requirements/sess/#REQ-SESS-042), [REQ-ISO-079](/requirements/iso/#REQ-ISO-079), [REQ-ISO-080](/requirements/iso/#REQ-ISO-080), [REQ-ISO-081](/requirements/iso/#REQ-ISO-081) and [REQ-ISO-082](/requirements/iso/#REQ-ISO-082).

## Roads not taken

- **Routing by the e-mail domain without proof.** Anyone could claim a competitor's domain and capture its sign-ins.
- **A domain claim by first come with no re-check.** A domain that changes hands would keep routing to the old owner's provider.
- **Trusting a provider's groups for named groups.** The tenant's administrators write those groups; sluis would take their word for who holds a grant.
- **One field for reach and strength.** The two bound different things (what the person may reach, how strongly they authenticated) and are tested apart.
- **A free-text `idp_hint` that falls back to discovery.** The client would learn which hints exist by how the answer changes.
- **More than three trust levels, or levels a tenant defines.** Nothing needs them, and a tenant that defines its own level defines its own reach.
- **A process per connection, scaled to zero.** It costs a pod or a cold start per tenant and thousands of network policies, for a credential that the adapter already opens only for the length of a call.
- **One pool for every customer boundary of the installation.** A compromise would reach every boundary's connections, and a noisy boundary would starve the others; an actor belongs to one boundary in any case.
- **A key per connection for `private_key_jwt`.** It is an authority key per tenant, which [principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule) rules out.
- **A static host list for the pool.** Thousands of entries to keep in a network policy that the platform enforces poorly.

## Follow-ups

- The routing, the domain proof, `trust`, `assurance` and `idp_hint` in the generic OIDC upstream, and the pool with its egress proxy and per-connection bounds: [#916](https://github.com/truvity/sluis/issues/916).
