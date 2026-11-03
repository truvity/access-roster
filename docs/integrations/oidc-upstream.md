---
title: Generic OIDC and peer sluis
description: How sluis signs people in through any OpenID Connect provider, strictly and without trusting the provider's group claims, and how one sluis trusts another.
status: target
sidebar:
  order: 4
---

The **generic OpenID Connect upstream** is the same kind of integration as Google sign-in, for any provider that publishes OIDC discovery: a customer's identity provider, a partner's, or a CIAM product. A dedicated connection is its own process, `oidc@<name>`; the connections of a product's customer organisations run in a pool of their customer boundary ([ADR 0033](/decisions/0033-customer-connections/)). A **peer sluis** is the case where the provider is another sluis installation.

## What it's for

- **A partner signs in with their own provider.** sluis sends the person there and accepts the proof it returns.
- **A person is routed by the domain of their e-mail address.** `person@partner.example` goes to the partner's provider, `person@example.org` to the company directory. A connection's claim on a domain is proven by a DNS record, not taken on trust ([ADR 0033](/decisions/0033-customer-connections/#domain-proof)).
- **A CIAM product plugs in as an upstream.** sluis stays a broker and hosts no customer accounts ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)): a CIAM product that speaks OpenID Connect is one more upstream, and its end users get sluis subjects like anyone else who signs in. What sluis requires of such a product is in [ADR 0031](/decisions/0031-ciam-is-a-broker/#what-sluis-requires-of-an-upstream).
- **One sluis trusts another.** An installation accepts people and robots vouched for by another installation, and the trust graph stays acyclic ([Boundaries](/concepts/boundaries/)).

## Integration kinds

| Kind | What it does |
|---|---|
| `Upstream` | Begins and completes a sign-in as an OpenID relying party. |
| `FactsSource` | Returns the ID token's allow-listed claims as facts. The provider's asserted groups and roles are not read ([REQ-FED-016](/requirements/fed/#REQ-FED-016)). |
| `WorkloadVerifier`, `CredentialMinter` | Peer sluis only: verify the peer's tokens inbound, and ask the peer's policy for a token outbound by token exchange (RFC 8693). |

## What sluis asks the vendor for

Only to be a registered client. sluis asks for `openid email profile` and holds one client id and one client secret (or a `private_key_jwt` signing key) per connection, as credentials. It reads the provider's discovery document and key set from public URLs.

Every returned ID token is checked strictly: issuer and audience match, `nonce` matches the one sent, the signature verifies against the provider's keys, the e-mail is verified, and the value of the connection's subject claim is the one first recorded for that person. Anything else is refused.

The subject claim is `sub` unless the connection says otherwise (`subject_claim`). Microsoft Entra needs `oid`, because its `sub` is different for each application. A person is found by the pair of the issuer and that claim's value, never by e-mail address ([ADR 0019](/decisions/0019-person-and-upstream-link/)). The tests sign in through Keycloak on every pull request, and through Google Cloud Identity Free and Microsoft Entra ID Free every night.

## What a connection can do

Beyond sign-in, a connection supports what a CIAM product or any strict provider needs:

- **Claim mapping per connection**, from the allow-listed claims of the provider to the facts sluis uses ([ADR 0033](/decisions/0033-customer-connections/#claims-and-groups)).
- **`acr` and `amr` passthrough**, so policy sees how strongly a person signed in. A provider that sends them only on request, as Google does, needs a configured `claims` request parameter ([#1154](https://github.com/truvity/sluis/issues/1154)).
- **Step-up (RFC 9470).** When a grant needs a stronger sign-in than the session has, sluis sends the person back with a challenge for a higher `acr`, or asks for a passkey ([ADR 0017](/decisions/0017-identity-and-sign-in/#step-up)).
- **Sessions and step-up for customers.** The upstream holds the long single-sign-on session; sluis keeps the 24-hour limit of a human session and authenticates the person at the upstream again, silently while the upstream's session is valid. A customer's step-up is a re-authentication at the upstream with the `acr_values` and `max_age` that policy asked for, and sluis asks no customer for a passkey ([ADR 0018](/decisions/0018-sessions/#customers)).
- **Back-channel logout**: the upstream can end the session at sluis with a back-channel logout token, mapped by `sid` ([ADR 0034](/decisions/0034-end-users-and-upstream-signals/#inbound-back-channel-logout)).
- **Rate limits** per connection, kept in sluis state ([ADR 0036](/decisions/0036-volumetric-abuse/#inside-sluis)).

The sign-in-only slice of the generic connector is in the first working version ([#1106](https://github.com/truvity/sluis/issues/1106)); the rest of it, [#916](https://github.com/truvity/sluis/issues/916), is in the CIAM upstream milestone ([Roadmap](/roadmap/)). End-user subjects follow the subject-lifecycle decision record (planned, [#1024](https://github.com/truvity/sluis/issues/1024)). A SAML identity provider and SCIM provisioning for AWS IAM Identity Center are Later ([#918](https://github.com/truvity/sluis/issues/918)).

:::note[Proposed]
Which identity product backs the first group single sign-on, and whether it brokers social login and SAML for the organisations that use it, is a product fact that the repository cannot know ([#1023](https://github.com/truvity/sluis/issues/1023)). Until it is named, this page describes the contract any product must meet ([ADR 0031](/decisions/0031-ciam-is-a-broker/#what-sluis-requires-of-an-upstream)). If the product cannot broker SAML for the organisations that need it, the SAML records ([REQ-FED-009](/requirements/fed/#REQ-FED-009)) are reopened.
:::

A connection proves each domain it serves with a DNS TXT record, and carries a `trust` level (`internal`, `partner` or `customer`) that limits what a sign-in through it may reach, and an `assurance` policy that limits how strong it counts ([ADR 0033](/decisions/0033-customer-connections/)). A client may send `idp_hint` to choose among the connections it is allowed.

## What policy controls

- **Which connections exist, and for which domains.**
- **What a connection's claims are worth**: only the allow-listed claims are read, and the provider's groups and roles never are.
- **Admission.** A sign-in proves an identity; the client's `requires` and the policy decide what it reaches.
- **For a peer:** which peer issuers are trusted, and the audiences each may exchange for.

## What is audited

- Each sign-in through a connection: the connection, the class of session and the outcome.
- Each refusal, with its reason in the record (not shown to the caller): a changed subject, an unverified e-mail, a bad `nonce`.
- The connection's lifecycle: created, changed, disconnected.
- For a peer, each inbound verification and outbound exchange.

## Setup

See [the generic OIDC pattern](/integrations/connecting/#generic-oidc-upstream); names and keys are [illustrative](/integrations/#examples-are-illustrative).

```yaml
# /etc/sluis/install.yaml (example)
integrations:
  oidc:
    partner:
      actors: [upstream, facts]
      issuer: https://idp.example.org
      client_id: sluis-partner
      client_secret: cred:sluis-int-oidc.partner.client-secret
      domains: [partner.example]
      trust: partner                      # internal | partner | customer: what this sign-in may reach
      assurance:                          # how strong this sign-in counts
        ceiling: urn:example:acr:2
        max_age: 12h
```
