# 0031 — CIAM is a broker: a customer-identity product owns the accounts, sluis owns the session and the tokens, and the contract between them is written down

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-02

Proposal: [issue #1023](https://github.com/truvity/sluis/issues/1023).

## Context

The customer-identity milestone is group single sign-on: the end users of several products of one group sign in once and are signed in at all of them. It is not an account store. sluis hosts no end-user accounts and stores no passwords ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017), [0008](/decisions/0008-boundaries-and-tenants/#the-ladder), [principles](/principles/#what-sluis-is-and-is-not)); a customer-identity product plugs in as one more OpenID Connect upstream ([OIDC upstream](/integrations/oidc-upstream/)). The account-hosting requirement records were withdrawn on that ground.

What was missing is the map of who does what, and what sluis needs from the upstream. Without it two teams can build the other half twice: a registration page in sluis, or a session cap in the product that sluis already enforces. The first half of [#1023](https://github.com/truvity/sluis/issues/1023) asked whether each regulated entity gets an installation and left the contract open; this record answers the contract. [0008](/decisions/0008-boundaries-and-tenants/) answers the installation question, and [0032](/decisions/0032-customer-identity-installations/) applies it to customer identity.

Where a customer's defaults and a tenant's changes live is settled by [0004](/decisions/0004-the-data-model/).

## Decision

### Who owns what

| Capability | Owner |
|---|---|
| Registration, e-mail and phone verification, passwords, recovery, factor enrolment and multi-factor authentication, social login, a customer's own identity provider brokered into the product, the long single sign-on session, disabling and deleting an account, answering a request about the account's data | **The upstream**, the customer-identity product |
| Checking the upstream's ID token, the person record and its subject, the link to the upstream account, sessions of at most 24 hours, refresh, tokens for the products, admission by policy, step-up by asking the upstream to authenticate again, logout towards the products, limits, audit, and erasing and exporting what sluis itself holds | **sluis** |
| Organisations (a group of users), creating and changing a customer organisation, its administrators, and their self-service screens | **A customer-identity module**, a product concern. sluis exposes the issued-record and template-link mechanism that it plugs into ([0004](/decisions/0004-the-data-model/), [0032](/decisions/0032-customer-identity-installations/#tenants)) |
| What a signed-in person may do inside a product | **The product**, from the claims of the token and its own data |

- **sluis never enrols, resets or changes a factor of an end user,** never offers a reset by e-mail, an anonymous reset or a reset by support staff ([REQ-CIAM-008](/requirements/ciam/#REQ-CIAM-008), [REQ-CIAM-015](/requirements/ciam/#REQ-CIAM-015), [REQ-CIAM-016](/requirements/ciam/#REQ-CIAM-016), [REQ-REG-051](/requirements/reg/#REQ-REG-051)). Passkeys at sluis belong to people who come from a directory ([0017](/decisions/0017-identity-and-sign-in/#passkeys)), not to customers.
- **sluis connects no social provider and no SAML provider itself.** Both stay behind the upstream. A provider that speaks OAuth 2 without an ID token cannot be an upstream. The SAML connector records stay out of scope ([REQ-FED-009](/requirements/fed/#REQ-FED-009)).
- **sluis is not strong customer authentication** and does not check transaction text ([REQ-CIAM-009](/requirements/ciam/#REQ-CIAM-009)).

### What sluis requires of an upstream

Any product that meets this is one more `oidc` connection ([0054](/decisions/0054-customer-connections-run-in-a-pool-per-customer-boundary/)); sluis has no code for a named product ([0025](/decisions/0025-integrations/#the-rule)). The tests sign in through a real identity provider run beside the installation ([0011](/decisions/0011-runtimes-and-installations/#the-local-installation)), so sluis keeps no accounts even in tests.

1. **OpenID Connect Core and discovery,** the authorization code flow with PKCE (S256), a signed ID token, and the `iss` response parameter of RFC 9207.
2. **A subject claim that is stable and never reassigned,** at most 255 characters, named in the connection ([0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)). An e-mail address is not one.
3. **`prompt=none` and `max_age`.** The first lets sluis renew a session silently; the second and `acr_values` carry a step-up ([0018](/decisions/0018-sessions/#customers)).
4. **`auth_time`, and `acr` and `amr` where the product can say how the person authenticated.** An absent value is unknown and stays absent ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)).
5. **A single sign-on session that outlasts sluis's 24 hours,** so that the silent renewal has something to renew.
6. **OpenID Connect back-channel logout with `sid`,** and a way to say that an account is disabled or deleted ([0055](/decisions/0055-upstream-signals-end-sessions-and-suspend-or-erase-a-person/)).
7. **`email_verified` truthfully,** because a policy may read it; sluis never links by it.

An upstream outage stops new sign-ins and silent renewals; tokens already issued stay valid until they expire ([REQ-OPS-014](/requirements/ops/#REQ-OPS-014)). sluis states no uptime figure for the upstream.

### Configuration

Where a customer's defaults and a tenant's changes live is [0008](/decisions/0008-boundaries-and-tenants/#example-installations): defaults are declared slots of a template, kept in project configuration and not in git, and per-tenant changes are issued records made by the customer-identity module's client under a declared template. This record adds only the boundary: the module owns organisations and tenants' screens, and sluis owns the tokens.

## Consequences

- One page now says what to build where. A registration page, a password reset or a factor screen proposed for sluis is refused by this record and by the negative tests of the CIAM records.
- sluis depends on the upstream's availability for every sign-in and every daily renewal. The cost is accepted: the alternative is hosting accounts.
- A product that cannot meet the contract (no stable subject, no `prompt=none`) cannot be an upstream. Naming the product that backs the first group single sign-on, and whether it brokers social login and SAML, is a product fact tracked in an issue; a product that cannot broker SAML reopens [REQ-FED-009](/requirements/fed/#REQ-FED-009).
- The contract is a list of requirements on a product, which sluis can check only by the behaviour it sees. The checks are the strict validation of [REQ-FED-001](/requirements/fed/#REQ-FED-001) to [REQ-FED-017](/requirements/fed/#REQ-FED-017) and the new records [REQ-CIAM-018](/requirements/ciam/#REQ-CIAM-018) and [REQ-CIAM-019](/requirements/ciam/#REQ-CIAM-019).
- Requirements: [REQ-CIAM-018](/requirements/ciam/#REQ-CIAM-018), [REQ-CIAM-019](/requirements/ciam/#REQ-CIAM-019) are added.

## Roads not taken

- **sluis hosts the accounts, with registration and recovery.** It makes sluis a store of a regulated entity's end users and a target for account takeover; the records for it were withdrawn on this ground.
- **Social providers connected to sluis directly.** One connector per provider, each with its own quirks and no consumer, when the upstream already brokers them.
- **A SAML service-provider connector in sluis.** A second protocol stack to defend for a need the upstream can meet; the records stay out of scope.
- **An adapter per named product.** It puts vendor code in core, which [0025](/decisions/0025-integrations/#the-rule) forbids; a written contract does the same without it.
- **Customer defaults in git, a pull request per customer.** One organisation's change would wait for a review and a release of the whole estate.

## Follow-ups

- Naming the product that backs the group single sign-on and whether it brokers social login and SAML, shown as a Proposed note on the [OIDC upstream](/integrations/oidc-upstream/) page: [#1023](https://github.com/truvity/sluis/issues/1023).
- The generic OpenID Connect upstream with the contract's checks: [#916](https://github.com/truvity/sluis/issues/916).
