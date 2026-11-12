# 0045 — Customers sign in through the upstream identity provider, realms follow boundaries, and the sluis token carries customer, organisation and product

**Status:** Accepted
**Date:** 2026-11-12

Proposal: [issue #782](https://github.com/truvity/sluis/issues/782), maintainer decisions D1 B, D3 and D7 A, 2026-11-12.

## Context

[0031](/decisions/0031-ciam-is-a-broker/) made sluis a broker: a customer-identity product owns the accounts, and sluis owns the session, the tokens and, through a customer-identity module, the organisations. [0032](/decisions/0032-customer-identity-installations/) shaped a customer installation around it, with pairwise subjects per tenant, an issuer host per tenant, [0033](/decisions/0033-customer-connections/) for federation of customer providers, [0034](/decisions/0034-end-users-and-upstream-signals/) for the lifecycle of an end user, [0035](/decisions/0035-customer-pages/) for customer pages and [0038](/decisions/0038-fapi-2-profile/) for a FAPI 2.0 profile.

On 2026-11-12 the maintainer decided the other way round. The group has one single sign-on service that holds the customer identities and federates the customers' own identity providers, as a set of realms. A token from that service is exchanged for a sluis token that carries the identity, the organisation and the product, and services call each other with the sluis token. sluis does not build a second customer-facing identity layer.

The maintainer's decisions:

| Label | Decision |
|---|---|
| D1 B | sluis keeps its own sign-in for staff and operators (passkeys, card holders). Customers sign in only through the upstream. The customer-facing pieces (FAPI, the customer pages, pairwise subjects and the abuse limits of login) are cancelled. |
| D3 | Realms follow boundaries, not customers. Each regulated boundary has a segregated realm of its own. A product that is not regulated uses a generic realm. A central realm holds the end-user accounts. The chain is end user, then the boundary's realm, then the central realm. |
| D7 A | The cancel list is approved as it stands, and the records are marked superseded with links. |

## Decision

### Who signs in where

- **sluis signs in staff and operators itself,** with passkeys and the hardware tiers of [0017](/decisions/0017-identity-and-sign-in/#two-tiers-of-staff-sign-in), and break-glass recovery ([0017](/decisions/0017-identity-and-sign-in/#break-glass-recovery)). That is the whole of sluis's own sign-in.
- **A customer signs in only at the upstream identity provider.** sluis hosts no customer account, page, registration, recovery or factor enrolment ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)), and it serves no customer-facing profile such as FAPI 2.0, PAR or DPoP for customers. The lifecycle of an end-user account, the federation of a customer's own provider and the pages of sign-in belong to the upstream.

### Realms follow boundaries

- **A regulated boundary has a realm of its own,** in which only that boundary's people are known. A generic realm serves a product that is not a regulated boundary. A central realm holds the end-user accounts, and a boundary's realm brokers to it: end user, boundary realm, central realm.
- **One sluis installation serves one boundary and trusts one realm.** The trusted issuer is declared with the `ExchangeTrust` config kind of that installation ([0022](/decisions/0022-workload-identity-and-host-enrolment/)), so a token of another realm is refused. A boundary of a regulated customer therefore never sees a person or a claim of another boundary's realm.
- **Realm names are the operator's,** and this record names none. The public examples use `acme` and `globex`.

### The exchange and the claims

- **`exchange` takes a token of the trusted realm as the subject token** (RFC 8693) and issues a sluis token for one audience. A token that the realm issued to a person is the input; the output is the sluis token of [0020](/decisions/0020-grant-vocabulary-and-token-claims/).
- **The sluis token carries three more claims: `customer`, `org` and `product`.** `exchange` sets them from the claims of the upstream token through a mapping that the installation declares for its realm, and never from the request. The claim set stays fixed: these three are added to it. A token that did not come from an exchange of an upstream token, such as a staff sign-in at sluis, carries none of them, and an absent claim stays absent.
- **Services call each other with the sluis token,** and read the three claims. A policy decision may use them as facts ([0007](/decisions/0007-policy-and-sealed-grants/)).
- **The subject is the person's sluis subject** ([0019](/decisions/0019-person-and-upstream-link/)). Pairwise subjects per sector are cancelled with the customer installation.

### Records that change

| Record | Change |
|---|---|
| [0031](/decisions/0031-ciam-is-a-broker/) | Superseded: the upstream owns the accounts, the organisations and the customer-facing screens, and sluis owns the token. |
| [0033](/decisions/0033-customer-connections/) | Superseded: federation of customers' providers is a feature of the realms. |
| [0034](/decisions/0034-end-users-and-upstream-signals/) | Superseded: the end-user lifecycle is the upstream's, and the pairwise sectors go. |
| [0035](/decisions/0035-customer-pages/) | Superseded: sluis serves no customer page. |
| [0038](/decisions/0038-fapi-2-profile/) | Superseded: the customer-facing profile is the upstream's. |
| [0032](/decisions/0032-customer-identity-installations/) | Amended: see its amendment. A tenant's data keys, one installation per boundary and the rules of moving stand; the broker's single sign-on, the sectors, the issuer host per tenant and the tenant-named client IDs do not. |
| [0020](/decisions/0020-grant-vocabulary-and-token-claims/) | Amended: the claim set gains `customer`, `org` and `product`. |
| [0017](/decisions/0017-identity-and-sign-in/) | Amended: staff and operators only. |

## Consequences

- sluis has one sign-in surface to defend and test, for staff, and no second identity layer for customers.
- The three claims need the upstream's claims to be trustworthy: the installation trusts one realm, so a wrong mapping is a configuration error of that installation and shows in its audit log, not a cross-boundary leak.
- A regulated boundary's relying parties learn only that boundary's customer, organisation and product, because the installation issues nothing about another boundary.
- A relying party that read the earlier rule "no organisation or tenant claim" now reads the three claims. The ID token and the access token both carry them.
- The code derives a pairwise `sub` today; it stays until a change removes it, and no new work builds on it.
- The exchange of a person's token is not built yet: `exchange` refuses a subject token that is not its own. P2 of the [roadmap](/roadmap/#phases) builds it.
- Requirements: [REQ-AUTHN-112](/requirements/authn/#REQ-AUTHN-112), [REQ-TOKEN-045](/requirements/token/#REQ-TOKEN-045) and [REQ-EXCH-027](/requirements/exch/#REQ-EXCH-027) are added; the rows of the cancelled work are withdrawn.

## Roads not taken

- **Keep CIAM as a broker with a customer-identity module in sluis (0031).** It builds a second identity layer beside the group's single sign-on.
- **A realm per customer.** Realms follow boundaries: a product that is not regulated shares the generic realm, and only a regulated boundary needs a segregation of its own.
- **One sluis installation that trusts every realm.** A token of one boundary's realm could then reach another boundary's relying parties.
- **A `memberships` claim listing a person's organisations.** It carries data about many organisations in every token. The token carries the one organisation of the exchange.
- **Pairwise subjects per sector.** They needed tenants with sectors and a lifecycle of subjects, and the single sign-on service already separates the boundaries by realm.

## Follow-ups

- The exchange of a person's token and the three claims are built in P2: [#782](https://github.com/truvity/sluis/issues/782), [#785](https://github.com/truvity/sluis/issues/785), [#961](https://github.com/truvity/sluis/issues/961).
- The sign-in-only slice of the generic upstream is in the first working version: [#1106](https://github.com/truvity/sluis/issues/1106).
