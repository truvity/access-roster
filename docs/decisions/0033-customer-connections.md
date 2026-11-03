# 0033 — An installation federates to a fixed set of upstreams that its operator declares, and a customer installation sees exactly one

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-03

Proposal: [issue #916](https://github.com/truvity/sluis/issues/916).

## Context

When more than one upstream is connected, sluis must decide where to send a person: to the customer-identity product that is the default, or to the identity provider of the person's own company. Four things were left open or in conflict.

- **Which upstreams an installation has, and who adds one.** Letting every customer organisation connect its own identity provider to sluis would mean thousands of connections to serve, an egress path to hosts that nobody knows in advance, and a proof of each organisation's domain. The tenants' identity providers belong to the customer-identity product, which brokers them ([0031](/decisions/0031-ciam-is-a-broker/#who-owns-what)), so sluis need not be a second broker.
- **A connection's trust.** [REQ-FED-004](/requirements/fed/#REQ-FED-004) gives a connection a "trust policy" of an assurance ceiling, methods and an age, [REQ-AUTHN-010](/requirements/authn/#REQ-AUTHN-010) states the ceiling again, and the page has a `trust` field that limits what a sign-in may reach. Two ideas share one word.
- **`idp_hint`** is named in #916 and has no record.
- **Groups.** [REQ-FED-016](/requirements/fed/#REQ-FED-016) says sluis must not read upstream roles or groups, and the [OIDC upstream](/integrations/oidc-upstream/) page offers `groups: ignore | map | trust`.

An identity provider is controlled by its administrators. It can send any subject, any e-mail address and any group, so what it says is a claim ([principle 4](/principles/#4-verify-never-trust-a-claim)).

## Decision

### Which upstreams an installation has

- **The internal installation sees three upstreams.** It runs serverless on Lambda for infrastructure access, and it federates to a fixed set of upstreams that the operator declares: three, each a Google Workspace, one per company of the operator's group. Each is an `Upstream` of config ([0004](/decisions/0004-the-data-model/#profiles)), written by IaC under review. These are fixed config and not tenant self-service: a company's staff cannot add an upstream, and a change of upstream waits for review.
- **The customer installation sees exactly one upstream: the CIAM broker, Keycloak.** It runs on Kubernetes on AWS (EKS), for customer and product access. Each customer's own identity provider is configured on the Keycloak side (Keycloak Organizations holds the tenants' providers) and never in sluis. sluis sees the broker's ID token and one issuer, and stays one hop away from every tenant's provider ([0031](/decisions/0031-ciam-is-a-broker/#who-owns-what)). `sluis config check` refuses a second upstream at the front of a customer installation ([REQ-FED-035](/requirements/fed/#REQ-FED-035)).
- **The operator declares which upstream serves which e-mail domain,** as the `domains` of the `Upstream`. The operator is the authority for that mapping, so sluis asks for no proof of a domain.
- **The upstream hosts are known,** so the adapter's egress is an allow-list of those hosts and sluis runs no general egress proxy ([The upstream hosts are known](/decisions/0033-customer-connections/#the-upstream-hosts-are-known)).
- **The person's tenant comes from the organisation id that the upstream sends,** by the binding rule below, never from anything else the provider sent ([Which tenant a person belongs to](/decisions/0033-customer-connections/#which-tenant-a-person-belongs-to)).
- **The installations are listed in [0011](/decisions/0011-runtimes-and-installations/#installations);** this record is the only place that says which upstreams each sees.

### Which tenant a person belongs to

This is the one place that says how a sign-in finds its tenant.

- **Config names no tenant.** Each `Upstream` declares only the binding rule: `organisation_claim`, the allow-listed claim that carries the upstream's organisation id. The `Tenant` item, written by `exchange` ([0008](/decisions/0008-boundaries-and-tenants/#tenants)), records the upstream and the organisation id that belong to it, and the status client of the product that owns its people ([0034](/decisions/0034-end-users-and-upstream-signals/#erasure)).
- **In an internal installation** each of the three upstreams is one company's, and the organisation id it sends maps to the one `Tenant` that records it.
- **In a customer installation** the broker's fixed organisation id comes in the allow-listed claim and maps to the one `Tenant` that records it ([REQ-FED-036](/requirements/fed/#REQ-FED-036)).
- **A sign-in is refused when the id is absent, unknown or ambiguous,** that is, when no `Tenant` records it or more than one does. A person whom no binding names is refused ([0019](/decisions/0019-person-and-upstream-link/#the-records)). It fails closed.
- **A broker account in several organisations** is signed in for exactly one: the broker must send only the organisation chosen for that sign-in, and a sign-in whose claim carries more than one id is refused.
- **The id is never emitted in a token.** It is the upstream's fact and the `Tenant`'s record, and a token for a regulated audience names no organisation or tenant beyond what `iss` and `aud` say ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)).

### Choosing the connection

A sign-in request reaches an upstream by the first rule that applies:

1. **`idp_hint`.** The client may send `idp_hint=<upstream name>`. The name must be one of the upstreams that the client's boundary allows. Any other value, or an unknown one, is refused with `invalid_request` ([REQ-FED-026](/requirements/fed/#REQ-FED-026)). A hint chooses among declared upstreams and cannot create or widen one. A hint is chosen by the client, not typed by the person, so a refusal reveals nothing about people.
2. **The client's default upstream,** declared with the client. For single sign-on across products this is the customer-identity product.
3. **Discovery by domain,** only for a client that declares it, and only where more than one upstream exists. The sign-in page asks for an e-mail address, takes its domain and looks for an upstream that declares that exact domain. A domain no upstream declares, and an address that does not parse, go to the client's default upstream with the same answer ([REQ-FED-022](/requirements/fed/#REQ-FED-022)), so the answer never tells whether a domain or an address is known. One domain belongs to one upstream ([REQ-FED-023](/requirements/fed/#REQ-FED-023)), and only the exact domain routes: `example.com` does not route `sub.example.com`.

The e-mail address typed on that page is a hint to route. It is not an identity and is never stored, matched or linked ([REQ-SUBJ-039](/requirements/subj/#REQ-SUBJ-039)).

### Connection trust

A connection has two separate fields, which resolves the overlap:

- **`trust` limits reach.** It is one of `internal` (the operator's own workforce directory), `partner` (an organisation the operator has agreed with) and `customer` (end users of a product; the broker of a customer installation is always `customer`). The policy compiles it into Cedar `forbid` guards: a person who came through a connection can hold only grants in scopes that their trust level and tenant may reach ([REQ-ISO-036](/requirements/iso/#REQ-ISO-036) is the model; [0007](/decisions/0007-policy-and-sealed-grants/#four-layers) says how guards are composed). A `customer` person never reaches an `all:` scope or a scope another tenant owns.
- **`assurance` limits strength.** It is the policy of [REQ-FED-004](/requirements/fed/#REQ-FED-004): an `acr` ceiling ([REQ-AUTHN-010](/requirements/authn/#REQ-AUTHN-010)), optionally required `amr` values, and a maximum authentication age. The upstream's `acr` values are mapped to the values that sluis's policy names by a per-connection table; an unmapped value is unknown, and a value above the ceiling is lowered to it.
- **An `internal` connection does not renew silently.** The periodic full sign-in with multi-factor authentication of [0017](/decisions/0017-identity-and-sign-in/#passkeys) stays; `customer` and `partner` connections renew as [0018](/decisions/0018-sessions/#customers) says.
- **Both are set in the `Upstream` and nowhere else.** The operator writes them under review, and no tenant can raise either.

### Claims and groups

- **sluis reads only the connection's claim allow-list** ([REQ-FED-005](/requirements/fed/#REQ-FED-005)). Per-connection claim mapping renames an allowed claim to a fact that policy knows; it never invents one.
- **`groups` and roles of an upstream are not read.** A connection has no `groups` choice, and none can trust groups. A person's grants come from sluis's bindings in policy ([0019](/decisions/0019-person-and-upstream-link/#what-policy-sees)). A product that wants the organisation's groups keeps them in its own module.

### The upstream hosts are known

- **The adapter's egress is an allow-list of the declared upstreams' hosts.** `adapter-upstream-oidc@<boundary>` may call the issuer, authorization, token and key-set hosts of the `Upstream` items of its boundary and no other host ([REQ-ISO-110](/requirements/iso/#REQ-ISO-110)), enforced by the platform's network policy where it has one and by the adapter's own check everywhere. A host is added by a change to the `Upstream`, under review.
- **The client secret is the operator's.** It is the `UpstreamSecret` of a secret source ([0025](/decisions/0025-integrations/#the-upstream-contract)), and the adapter keeps no credential at rest ([REQ-ISO-106](/requirements/iso/#REQ-ISO-106)). A `private_key_jwt` key is an authority key and stays refused ([REQ-ISO-052](/requirements/iso/#REQ-ISO-052)).
- **The bounds of [0036](/decisions/0036-volumetric-abuse/#inside-sluis).** Each upstream has its own concurrency limit, timeout and circuit breaker, so a slow upstream cannot use up the adapter's workers for the others.
- **Facts only.** The adapter returns the assertion of [0025](/decisions/0025-integrations/#the-upstream-contract) to `session` and decides nothing.
- **State separation.** A pending sign-in and the keyed hashes it makes carry the upstream in their address, and the store scopes every call to the caller's grant ([REQ-DATA-013](/requirements/data/#REQ-DATA-013)).

## Consequences

- sluis has a handful of connections and no per-tenant connection: three upstreams in the internal installation and one in the customer installation. A company or a customer cannot add an upstream, take over another's domain, widen its trust or ride its provider's group claims into grants.
- The default path, one product-wide upstream, needs no discovery and no domain at all.
- sluis runs no pool, no egress proxy and no resolver that it must trust for a domain proof. The adapter is one actor per boundary with an egress allow-list that the operator already knows.
- A customer organisation that moves its identity provider changes it in the broker and sluis sees no change. The persons it had keep their upstream link, because the issuer and the subject claim are the broker's ([0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)).
- A compromise of the broker is a compromise of every tenant's sign-in, which the connection's trust and assurance bound but do not remove ([AP-16](/security/threat-model/)). That is the price of a single hop, and the broker's own operator carries it.
- A new company of the operator's group is a new `Upstream` and a review, not a self-service step.
- Requirements: [REQ-FED-022](/requirements/fed/#REQ-FED-022), [REQ-FED-023](/requirements/fed/#REQ-FED-023), [REQ-FED-026](/requirements/fed/#REQ-FED-026), [REQ-FED-027](/requirements/fed/#REQ-FED-027), [REQ-FED-028](/requirements/fed/#REQ-FED-028), [REQ-FED-035](/requirements/fed/#REQ-FED-035), [REQ-FED-036](/requirements/fed/#REQ-FED-036), [REQ-SESS-042](/requirements/sess/#REQ-SESS-042), [REQ-ISO-079](/requirements/iso/#REQ-ISO-079), [REQ-ISO-110](/requirements/iso/#REQ-ISO-110) and [REQ-SEC-026](/requirements/sec/#REQ-SEC-026). The requirements of the roads below are withdrawn and keep their ids: [REQ-FED-006](/requirements/fed/#REQ-FED-006), [REQ-FED-024](/requirements/fed/#REQ-FED-024), [REQ-FED-025](/requirements/fed/#REQ-FED-025), [REQ-ISO-080](/requirements/iso/#REQ-ISO-080), [REQ-ISO-081](/requirements/iso/#REQ-ISO-081) and [REQ-ISO-082](/requirements/iso/#REQ-ISO-082).

## Roads not taken

- **A pool of `adapter-upstream-oidc` connections per customer boundary, one for each tenant's own provider.** The tenants' identity providers live in the upstream broker, and sluis stays one hop away; a pool would make sluis a second broker, with thousands of connections, client secrets sealed per tenant, per-connection bounds and a bigger prize in one compromised process.
- **A general egress proxy that checks addresses after name resolution.** It existed only because a pool could not list thousands of provider hosts; the hosts of the declared upstreams are known, so an allow-list replaces it, and a proxy would let a compromised adapter reach any public host.
- **Domain proof by a DNS TXT record, with a re-check every 24 hours.** It existed only to stop a tenant from claiming another's domain, and the operator declares the e-mail domains itself, so no tenant claims one.
- **A domain claim by first come with no re-check.** It is the same self-service route and would keep routing a domain that changed hands to the old owner's provider.
- **Routing by the e-mail domain without any declaration.** Anyone could claim a competitor's domain and capture its sign-ins.
- **A tenant that connects its own provider to sluis as well as to the broker.** Two places would hold the same provider, and sluis would hold a client secret per tenant for nothing the broker does not already do.
- **Trusting a provider's groups for named groups.** The provider's administrators write those groups; sluis would take their word for who holds a grant.
- **One field for reach and strength.** The two bound different things (what the person may reach, how strongly they authenticated) and are tested apart.
- **A free-text `idp_hint` that falls back to discovery.** The client would learn which hints exist by how the answer changes.
- **More than three trust levels, or levels a tenant defines.** Nothing needs them, and a tenant that defines its own level defines its own reach.
- **A key per upstream for `private_key_jwt`.** It is an authority key per upstream, which [principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule) rules out.

## Follow-ups

- The routing by declared domain, `trust`, `assurance` and `idp_hint` in the generic OIDC upstream, the adapter's egress allow-list and its per-upstream bounds: [#916](https://github.com/truvity/sluis/issues/916).
