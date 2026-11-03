# 0031 — CIAM is a broker: a customer-identity product owns the accounts, sluis owns the session and the tokens, and the contract between them is written down

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-03

Proposal: [issue #1023](https://github.com/truvity/sluis/issues/1023).

## Context

The customer-identity capability is single sign-on across products: the end users of several products sign in once and are signed in at all of them. It is not an account store. sluis hosts no end-user accounts and stores no passwords ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017), [0008](/decisions/0008-boundaries-and-tenants/#boundaries), [principles](/principles/#what-sluis-is-and-is-not)); a customer-identity product plugs in as one more OpenID Connect upstream ([OIDC upstream](/integrations/oidc-upstream/)). The requirement records for hosting accounts are out of scope for the same reason.

What was missing is the map of who does what, and what sluis needs from the upstream. Without it two teams can build the other half twice: a registration page in sluis, or a session cap in the product that sluis already enforces. The first half of [#1023](https://github.com/truvity/sluis/issues/1023) asked whether each regulated customer gets an installation and left the contract open; this record answers the contract. [0008](/decisions/0008-boundaries-and-tenants/#scale) answers the installation question, and [0032](/decisions/0032-customer-identity-installations/) applies it to customer identity.

Where a customer's defaults and a tenant's changes live is settled by the storage classes and profiles of [0004](/decisions/0004-the-data-model/#profiles).

## Decision

### Who owns what

| Capability | Owner |
|---|---|
| Registration, e-mail and phone verification, passwords, recovery, factor enrolment and multi-factor authentication, social login, a customer's own identity provider brokered into the product, the long single sign-on session, disabling and deleting an account, answering a request about the account's data | **The upstream**, the customer-identity product |
| Checking the upstream's ID token, the person record and its subject, the link to the upstream account, sessions of at most 24 hours, refresh, tokens for the products, admission by policy, step-up by asking the upstream to authenticate again, logout towards the products, limits, audit, and erasing and exporting what sluis itself holds | **sluis** |
| Organisations (a group of users), creating and changing a customer organisation, its administrators, and their self-service screens | **A customer-identity module**, a product concern. It calls the API for its tenants and writes only the Tenant-adjustable kinds of its own tenant, inside the bounds that config declares ([0004](/decisions/0004-the-data-model/#profiles), [0032](/decisions/0032-customer-identity-installations/#tenants)) |
| What a signed-in person may do inside a product | **The product**, from the claims of the token and its own data |

- **sluis never enrols, resets or changes a factor of an end user,** never offers a reset by e-mail, an anonymous reset or a reset by support staff ([REQ-CIAM-008](/requirements/ciam/#REQ-CIAM-008), [REQ-CIAM-015](/requirements/ciam/#REQ-CIAM-015), [REQ-CIAM-016](/requirements/ciam/#REQ-CIAM-016), [REQ-REG-051](/requirements/reg/#REQ-REG-051)). Passkeys at sluis belong to people who come from a directory ([0017](/decisions/0017-identity-and-sign-in/#passkeys)), not to customers.
- **sluis connects no social provider and no SAML provider itself.** Both stay behind the upstream. A provider that speaks OAuth 2 without an ID token cannot be an upstream. The SAML connector records stay out of scope ([REQ-FED-009](/requirements/fed/#REQ-FED-009)).
- **sluis is not strong customer authentication** and does not check transaction text ([REQ-CIAM-009](/requirements/ciam/#REQ-CIAM-009)).

### What sluis requires of an upstream

Any product that meets this can be the one upstream of a customer installation ([0033](/decisions/0033-customer-connections/#which-upstreams-an-installation-has)); sluis has no code for a named product ([0025](/decisions/0025-integrations/#the-rule)). The tests sign in through a real identity provider run beside the installation ([0011](/decisions/0011-runtimes-and-installations/#the-local-installation)), so sluis keeps no accounts even in tests.

1. **OpenID Connect Core and discovery,** the authorization code flow with PKCE (S256), a signed ID token, and the `iss` response parameter of RFC 9207.
2. **A subject claim that is stable and never reassigned,** at most 255 characters, named in the connection ([0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)). An e-mail address is not one.
3. **`prompt=none` and `max_age`.** The first lets sluis renew a session silently; the second and `acr_values` carry a step-up ([0018](/decisions/0018-sessions/#customers)).
4. **`auth_time`, and `acr` and `amr` where the product can say how the person authenticated.** An absent value is unknown and stays absent ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)).
5. **A single sign-on session that outlasts sluis's 24 hours,** so that the silent renewal has something to renew.
6. **OpenID Connect back-channel logout with `sid`,** and a way to say that an account is disabled or deleted ([0034](/decisions/0034-end-users-and-upstream-signals/#upstream-signals)).
7. **`email_verified` truthfully,** because a policy may read it; sluis never links by it.
8. **No linking of accounts by e-mail address,** and no merging of two accounts of one person into one `sub` unless the person links them themselves in the upstream. Two upstream accounts are two people to sluis ([0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)).
9. **A multi-factor proof relayed from a corporate login never raises `acr` in sluis's tokens on its own.** The upstream reports what it verified itself in `acr` and `amr`, and a proof made further behind it travels as a separate claim that sluis does not read for assurance. `acr` in sluis's tokens is the upstream's own `acr`, mapped and capped by the connection's `assurance`; a relayed multi-factor proof never raises it above that cap ([0033](/decisions/0033-customer-connections/#connection-trust), [0017](/decisions/0017-identity-and-sign-in/#step-up)).

An upstream outage stops new sign-ins and silent renewals; tokens already issued stay valid until they expire ([REQ-OPS-014](/requirements/ops/#REQ-OPS-014)). sluis states no uptime figure for the upstream.

### Configuration

Where a customer's defaults and a tenant's changes live follows the storage classes ([0004](/decisions/0004-the-data-model/#storage-classes)). Defaults are config, which IaC or the publishing pipeline writes as signed documents under review: the boundary's upstreams, the client templates with the bounds on what a tenant may change, and the rate bounds. A tenant's own records are durable kinds of that tenant, written through the API by their one owner inside those bounds ([0004](/decisions/0004-the-data-model/#one-writer-per-kind)): its clients and settings by `exchange`. The customer-identity module makes those calls as a product, for its own tenant, with a grant sealed for that tenant ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). This record adds only the boundary: the module owns organisations and the tenants' screens, and sluis owns the tokens.

## Consequences

- One page now says what to build where. A registration page, a password reset or a factor screen proposed for sluis is refused by this record and by the negative tests of the CIAM records.
- sluis depends on the upstream's availability for every sign-in and every daily renewal. The cost is accepted: the alternative is hosting accounts.
- A product that cannot meet the contract (no stable subject, no `prompt=none`) cannot be an upstream. A product that cannot broker SAML reopens [REQ-FED-009](/requirements/fed/#REQ-FED-009).
- The contract is a list of requirements on a product, which sluis can check only by the behaviour it sees. The checks are the strict validation of [REQ-FED-001](/requirements/fed/#REQ-FED-001) to [REQ-FED-017](/requirements/fed/#REQ-FED-017) and [REQ-CIAM-018](/requirements/ciam/#REQ-CIAM-018) and [REQ-CIAM-019](/requirements/ciam/#REQ-CIAM-019).
- A customer's change of client takes effect at once, because it is a write to a durable kind and not a change to config under review. A change of the customer's own identity provider is made in the broker and needs nothing from sluis.

## Roads not taken

- **sluis hosts the accounts, with registration and recovery.** It makes sluis a store of a regulated customer's end users and a target for account takeover; the requirement records for it are out of scope for this reason.
- **Social providers connected to sluis directly.** One connector per provider, each with its own quirks and no consumer, when the upstream already brokers them.
- **A SAML service-provider connector in sluis.** A second protocol stack to defend for a need the upstream can meet; the records stay out of scope.
- **An adapter per named product.** It puts vendor code in core, which [0025](/decisions/0025-integrations/#the-rule) forbids; a written contract does the same without it.
- **A customer's clients as config, a pull request per customer.** One organisation's change would wait for a review and a release of the whole estate, and a tenant would appear in config, against [principle 17](/principles/#17-where-a-thing-is-written-decides-its-class).

## Follow-ups

- The generic OpenID Connect upstream with the contract's checks: [#916](https://github.com/truvity/sluis/issues/916).
- The contract between sluis and a customer-identity product, and what a product that does not broker SAML changes: [#1023](https://github.com/truvity/sluis/issues/1023).
