# 0033 — A domain routes to a connection only after DNS proof, a connection has a trust level and an assurance policy, and `idp_hint` chooses only among allowed connections

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-02

Proposal: [issue #916](https://github.com/truvity/sluis/issues/916).

## Context

When more than one upstream is connected, sluis must decide where to send a person: to the customer-identity product that is the default, or to the identity provider of the person's own organisation. Four things were left open or in conflict.

- **Home-realm discovery** (routing by the domain of an e-mail address) and its **proof** by a DNS record are [REQ-FED-006](/requirements/fed/#REQ-FED-006), parked in the unscheduled backlog, and the [OIDC upstream](/integrations/oidc-upstream/) page marks both as Proposed.
- **A connection's trust.** [REQ-FED-004](/requirements/fed/#REQ-FED-004) gives a connection a "trust policy" of an assurance ceiling, methods and an age, [REQ-AUTHN-010](/requirements/authn/#REQ-AUTHN-010) states the ceiling again, and the page has a `trust` field that limits what a sign-in may reach. Two ideas share one word.
- **`idp_hint`** is named in #916 and has no record.
- **Groups.** [REQ-FED-016](/requirements/fed/#REQ-FED-016) says sluis must not read upstream roles or groups, and the page offers `groups: ignore | map | trust`.

A tenant's identity provider is controlled by that tenant's administrators. It can send any subject, any e-mail address and any group, so what it says is a claim ([principle 4](/principles/#4-verify-never-trust-a-claim)).

## Decision

### Choosing the connection

A sign-in request reaches a connection by the first rule that applies:

1. **`idp_hint`.** The client may send `idp_hint=<connection name>`. The name must be one of the connections that the client's customer boundary and tenant allow; any other value, or an unknown one, is refused with `invalid_request`. A hint chooses among declared or issued connections and cannot create or widen one. A hint is chosen by the client, not typed by the person, so a refusal reveals nothing about people.
2. **The client's default connection,** declared with the client. For group single sign-on this is the customer-identity product.
3. **Discovery by domain,** only for a client that declares it. The sign-in page asks for an e-mail address, takes its domain and looks for a verified domain with an exact match. A domain with no connection, and an address that does not parse, go to the client's default connection, so the answer never tells whether a domain or an address is known.

The e-mail address typed on that page is a hint to route. It is not an identity and is never stored, matched or linked ([REQ-SUBJ-039](/requirements/subj/#REQ-SUBJ-039)).

### Domain proof

- **A domain is routable only after a DNS TXT record proves control** ([REQ-FED-006](/requirements/fed/#REQ-FED-006)). The record is `_sluis-challenge.<domain>`, and its value is a token that sluis made for that connection and tenant.
- **One domain, one connection, in one customer boundary.** A second claim on a verified domain is refused until the first is released. A suffix such as `co.uk` is refused (the public suffix list), and only the exact domain routes: a verified `example.com` does not route `sub.example.com`.
- **The proof is checked again** every 24 hours and when the record's expiry passes. A domain that fails to prove for three checks in a row stops routing and is reported; its persons are not touched.
- **Proof of a domain is for routing only.** It does not make an address a key, and it does not vouch for any claim of the provider.

### Connection trust

A connection has two separate fields, which resolves the overlap:

- **`trust` limits reach.** It is one of `internal` (the operator's own workforce directory), `partner` (an organisation the operator has agreed with) and `customer` (end users of a product, including a tenant's own provider). The policy compiles it into Cedar `forbid` guards: a person who came through a connection can hold only grants in scopes that their trust level and, for a tenant's connection, their tenant may reach ([REQ-ISO-036](/requirements/iso/#REQ-ISO-036) is the model). A `customer` person never reaches an `all:` scope or a scope another tenant owns.
- **`assurance` limits strength.** It is the policy of [REQ-FED-004](/requirements/fed/#REQ-FED-004): an `acr` ceiling ([REQ-AUTHN-010](/requirements/authn/#REQ-AUTHN-010)), optionally required `amr` values, and a maximum authentication age. The upstream's `acr` values are mapped to the values that sluis's policy names by a per-connection table; an unmapped value is unknown, and a value above the ceiling is lowered to it.
- **An `internal` connection does not renew silently.** The periodic full sign-in with multi-factor authentication of [0017](/decisions/0017-identity-and-sign-in/#passkeys) stays; `customer` and `partner` connections renew as [0018](/decisions/0018-sessions/#customers) says.
- **A tenant cannot raise either.** Both are bounded by the template's delegation policy ([0004](/decisions/0004-the-data-model/)): the template names the highest `trust` and ceiling a tenant's connection may carry, and a tenant's own provider never exceeds `customer`.

### Claims and groups

- **sluis reads only the connection's claim allow-list** ([REQ-FED-005](/requirements/fed/#REQ-FED-005)). Per-connection claim mapping renames an allowed claim to a fact that policy knows; it never invents one.
- **`groups` and roles of an upstream are not read.** The `groups: ignore | map | trust` choice of the page is withdrawn, and so is the claim that a connection could trust groups. A person's grants come from sluis's declared bindings ([0019](/decisions/0019-person-and-upstream-link/#what-policy-sees)). A product that wants the organisation's groups keeps them in its own module.

## Consequences

- A tenant can bring its own provider and cannot take over another tenant's domain, widen its trust, or ride its provider's group claims into grants.
- The default path, one product-wide upstream, needs no discovery and no domain at all.
- The DNS proof needs a resolver that sluis can trust: it queries through the egress proxy with the address checks of [0054](/decisions/0054-customer-connections-run-in-a-pool-per-customer-boundary/#what-a-pool-is-allowed), and a spoofed answer is as strong as the resolver. DNSSEC validation is used where the resolver offers it.
- An organisation that moves its provider keeps its domain and replaces the connection; the persons it had through the old connection are new persons through the new one ([0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)).
- Requirements: [REQ-FED-022](/requirements/fed/#REQ-FED-022), [REQ-FED-023](/requirements/fed/#REQ-FED-023), [REQ-FED-024](/requirements/fed/#REQ-FED-024), [REQ-FED-025](/requirements/fed/#REQ-FED-025), [REQ-FED-026](/requirements/fed/#REQ-FED-026), [REQ-FED-027](/requirements/fed/#REQ-FED-027), [REQ-FED-028](/requirements/fed/#REQ-FED-028), [REQ-SESS-042](/requirements/sess/#REQ-SESS-042) are added; REQ-FED-004 is reworded as the assurance policy, and REQ-FED-006 moves to [#916](https://github.com/truvity/sluis/issues/916).

## Roads not taken

- **Routing by the e-mail domain without proof.** Anyone could claim a competitor's domain and capture its sign-ins.
- **A domain claim by first come with no re-check.** A domain that changes hands would keep routing to the old owner's provider.
- **Trusting a provider's groups for named groups.** The tenant's administrators write those groups; sluis would take their word for who holds a grant.
- **One field for reach and strength.** The two bound different things (what the person may reach, how strongly they authenticated) and are tested apart.
- **A free-text `idp_hint` that falls back to discovery.** The client would learn which hints exist by how the answer changes.
- **More than three trust levels, or levels a tenant defines.** Nothing needs them, and a tenant that defines its own level defines its own reach.

## Follow-ups

- The routing, the domain proof, `trust`, `assurance` and `idp_hint` in the generic OIDC upstream: [#916](https://github.com/truvity/sluis/issues/916).
