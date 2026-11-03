---
title: Generic OIDC and peer sluis
description: How sluis signs people in through any OpenID Connect provider, strictly and without trusting the provider's group claims, and how one sluis trusts another.
status: target
sidebar:
  order: 4
---

The **generic OpenID Connect upstream** is the same kind of integration as Google sign-in, for any provider that publishes OIDC discovery: a customer's identity provider, a partner's, or a CIAM product. `adapter-upstream-oidc@<boundary>` serves it. The connections of a product's customer organisations are served by a pool of that adapter in their customer boundary, a few replicas that open each connection's client secret at key@ for each call ([0033](/decisions/0033-customer-connections/#a-pool-per-customer-boundary)). A **peer sluis** is the case where the provider is another sluis installation.

## What it's for

- **A partner signs in with their own provider.** sluis sends the person there and accepts the proof it returns.
- **A person is routed by the domain of their e-mail address.** `person@partner.example` goes to the partner's provider, `person@example.org` to the company directory. A connection's claim on a domain is proven by a DNS record, not taken on trust ([0033](/decisions/0033-customer-connections/#domain-proof)).
- **A CIAM product plugs in as an upstream.** sluis stays a broker and hosts no customer accounts ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)): a CIAM product that speaks OpenID Connect is one more upstream, and its end users get sluis subjects like anyone else who signs in. What sluis requires of such a product is in [0031](/decisions/0031-ciam-is-a-broker/#what-sluis-requires-of-an-upstream).
- **One sluis trusts another.** An installation accepts people and robots vouched for by another installation, and the trust graph stays acyclic ([Boundaries](/concepts/boundaries/)).

## Integration kinds

| Kind | What it does |
|---|---|
| `Upstream` | `adapter-upstream-oidc` begins and completes a sign-in as an OpenID relying party: it exchanges the code at the provider and returns the verified assertion to `session`. |
| `WorkloadVerifier` | Peer sluis only: `exchange` verifies the peer's tokens inbound ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)). |

## Connections

| Whose provider | Kind | Class | Made by |
|---|---|---|---|
| The operator's own (workforce, a partner the operator agreed with) | `Upstream` and `UpstreamSecret` | Config and secret | Hand or IaC; a multi-tenant app is one `Upstream` for many customer directories |
| A tenant's own | `TenantConnection`, written by `session` | Durable, per tenant, client secret sealed | The UI or the API |
| A customer's Microsoft Entra directory | `EntraConnection`, written by `adapter-upstream-oidc` | Durable, per tenant | The admin consent, a browser round trip in the UI |

- **Who connects decides.** A tenant's own connection is never config the operator commits: a tenant never appears in config, and a customer's single sign-on change does not wait for review ([0004](/decisions/0004-the-data-model/#who-connects-decides)).
- **The client secret is opened per call.** The adapter reads the connection, asks key@ to open the sealed secret with a grant for that tenant, exchanges the code and keeps nothing. A `private_key_jwt` key per connection is refused, because it would be an authority key per tenant; a provider that accepts no client secret cannot be a tenant's connection ([0033](/decisions/0033-customer-connections/#what-a-pool-is-allowed)).

## What sluis asks the vendor for

Only to be a registered client. sluis asks for `openid email profile` and holds one client id and one client secret per connection. It reads the provider's discovery document and key set from public URLs.

Every returned ID token is checked strictly: issuer and audience match, `nonce` matches the one sent, the signature verifies against the provider's keys, the configured subject claim is present, and the claim matches the one pinned for the issuer. Anything else is refused with `INVALID`; there is no lenient fallback ([0025](/decisions/0025-integrations/#the-upstream-contract)).

The subject claim is `sub` unless the connection says otherwise (`subject_claim`). Microsoft Entra needs `oid`, because its `sub` is different for each application. A person is found by the pair of the issuer and that claim's value, never by e-mail address ([0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)). The tests sign in through Keycloak on every pull request, and through Google Cloud Identity Free and Microsoft Entra ID Free every night.

## What a connection can do

Beyond sign-in, a connection supports what a CIAM product or any strict provider needs:

- **Claim mapping per connection**, from the allow-listed claims of the provider to the facts sluis uses ([0033](/decisions/0033-customer-connections/#claims-and-groups)).
- **`acr` and `amr` passthrough**, so policy sees how strongly a person signed in. A provider that sends them only on request, as Google does, needs a configured `claims` request parameter ([#1154](https://github.com/truvity/sluis/issues/1154)).
- **Step-up (RFC 9470).** When a grant needs a stronger sign-in than the session has, sluis sends the person back with a challenge for a higher `acr`, or asks for a passkey ([0017](/decisions/0017-identity-and-sign-in/#step-up)).
- **Sessions and step-up for customers.** The upstream holds the long single-sign-on session; sluis keeps the 24-hour limit of a human session and authenticates the person at the upstream again, silently while the upstream's session is valid. A customer's step-up is a re-authentication at the upstream with the `acr_values` and `max_age` that policy asked for, and sluis asks no customer for a passkey ([0018](/decisions/0018-sessions/#customers)).
- **Back-channel logout**: the upstream can end the session at sluis with a back-channel logout token, mapped by `sid` ([0034](/decisions/0034-end-users-and-upstream-signals/#inbound-back-channel-logout)).
- **Rate limits** per connection, kept in sluis state ([0036](/decisions/0036-volumetric-abuse/#inside-sluis)).

The sign-in-only slice of the generic connector is in the first working version ([#1106](https://github.com/truvity/sluis/issues/1106)); the rest of it, [#916](https://github.com/truvity/sluis/issues/916), is in the CIAM upstream milestone ([Roadmap](/roadmap/)). A SAML identity provider and SCIM provisioning for AWS IAM Identity Center are Later ([#918](https://github.com/truvity/sluis/issues/918)).

:::note[Proposed]
Which identity product backs the first group single sign-on, and whether it brokers social login and SAML for the organisations that use it, is a product fact that the repository cannot know ([#1023](https://github.com/truvity/sluis/issues/1023)). Until it is named, this page describes the contract any product must meet ([0031](/decisions/0031-ciam-is-a-broker/#what-sluis-requires-of-an-upstream)). If the product cannot broker SAML for the organisations that need it, the SAML records ([REQ-FED-009](/requirements/fed/#REQ-FED-009)) are reopened.
:::

A connection proves each domain it serves with a DNS TXT record (a `DomainClaim` of the tenant), and carries a `trust` level (`internal`, `partner` or `customer`) that limits what a sign-in through it may reach, and an `assurance` policy that limits how strong it counts ([0033](/decisions/0033-customer-connections/#connection-trust)). A tenant cannot raise either: both are bounded by the client template in config. A client may send `idp_hint` to choose among the connections it is allowed.

## What policy controls

- **Which connections exist, and for which domains.**
- **What a connection's claims are worth**: only the allow-listed claims are read, and the provider's groups and roles never are.
- **Admission.** A sign-in proves an identity; the client's `requires` and the policy decide what it reaches.
- **For a peer:** which peer issuers are trusted, and the audiences each may exchange for.

## What is audited

- Each sign-in through a connection: the connection, the class of session and the outcome.
- Each refusal, with its reason in the record (not shown to the caller): a missing subject claim, a contradicted pin, a bad `nonce`.
- The connection's lifecycle: created, changed, disconnected.
- For a peer, each inbound verification and outbound exchange.

## Setup

See [the generic OIDC pattern](/integrations/connecting/#generic-oidc-upstream); names and keys are [illustrative](/integrations/#examples-are-illustrative).

For the operator's own upstream, commit the `Upstream` and put the secret in the secret source:

```yaml
# Upstream, a config kind (example); its secret is an UpstreamSecret in the secret source
upstreams:
  - id: partner
    issuer: https://idp.example.org
    client_id: sluis-partner
    subject_claim: sub
```

For a tenant's own provider, connect it in the UI or through the API. The values below are what the request carries; `session` writes the `TenantConnection` and seals the client secret.

```yaml
# a TenantConnection request through the API (example); the client secret is sent once and sealed
issuer: https://idp.example.org
client_id: sluis-partner
domains: [partner.example]
trust: customer                     # what this sign-in may reach; a tenant's own provider never exceeds customer
assurance:                          # how strong this sign-in counts
  ceiling: urn:example:acr:2
  max_age: 12h
```
