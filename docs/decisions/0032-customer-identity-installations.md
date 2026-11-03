# 0032 — A customer-identity installation is a front, a few customer boundaries and key-less tenants, a tenant's client IDs carry its name, and a move keeps every subject

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-02

Proposal: [issue #1023](https://github.com/truvity/sluis/issues/1023).

## Context

[0008](/decisions/0008-boundaries-and-tenants/) fixes the words and the scale: a boundary holds keys and a tenant is a record, an installation carries about 5 to 10 customer boundaries and thousands of tenants, and growth past a cohort is another installation. [0004](/decisions/0004-the-data-model/) fixes how a tenant's records are written. [0031](/decisions/0031-ciam-is-a-broker/) fixes who owns what. What none of them says is what the customer-identity installation looks like when put together, how a tenant's client is named, what a tenant holds, and what moving a tenant or a cohort does to the people in it.

Three gaps remained.

- **Group single sign-on needs a shape.** The products of a group must not each ask the person again, yet each customer boundary has an issuer of its own ([0017](/decisions/0017-identity-and-sign-in/#issuers)).
- **Client IDs are readable and unique per issuer,** with names of 1 to 32 characters ([0017](/decisions/0017-identity-and-sign-in/#audiences)). Thousands of tenants that each have a `web` client need a rule.
- **The NATS mapping said "an account per tenant"** ([0028](/decisions/0028-audit-pieces/)) while [REQ-ISO-025](/requirements/iso/#REQ-ISO-025) says "in its boundary's account". With a tenant now meaning a customer organisation, the first reading would be thousands of accounts.

## Decision

### The shape

- **The front is the one place a person signs in.** Each customer boundary runs a slim `entry` whose upstream is the front, and exchanges the front's token silently ([0017](/decisions/0017-identity-and-sign-in/#step-up)). `sub` is the same at every issuer, so the products of a group recognise one person. That is the group single sign-on. Pairwise subjects are a separate, later tool ([0034](/decisions/0034-end-users-and-upstream-signals/#pairwise-subjects)).
- **A relying party of a product pins that product's customer boundary issuer,** as for any issuer. Which boundary a client belongs to is declared with the client.

### Tenants

- **A tenant's records are connections, domains, clients and limits,** issued under a declared template by the customer-identity module's client ([0004](/decisions/0004-the-data-model/#profiles)). The template fixes the kinds of connection a tenant may add and their ceiling of trust ([0033](/decisions/0033-customer-connections/#connection-trust)), the redirect rules of its clients and its limits ([0036](/decisions/0036-volumetric-abuse/#inside-sluis)). A tenant cannot widen a claim, a ceiling or a grant.
- **A person who signed in through a tenant's own connection is bounded to that tenant** by the connection that vouched for them: the tenant is set by the connection's owner, never by what the provider sent. A policy guard keeps such a person out of any other tenant's scope ([REQ-ISO-036](/requirements/iso/#REQ-ISO-036) is the model).
- **sluis stores no organisation membership and no tenant claim.** Which users belong to an organisation is the customer-identity module's data ([0008](/decisions/0008-boundaries-and-tenants/#boundaries)). The claim set of a token is fixed ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)); a product that needs the organisation in a token adds a claim with its first consumer.
- **A tenant is not a transport account.** The NATS mapping is an account per boundary ([0028](/decisions/0028-audit-pieces/), [REQ-ISO-025](/requirements/iso/#REQ-ISO-025)). Thousands of tenants never become thousands of accounts.
- **A tenant leaves** by disconnecting its connections, making its persons `left` ([0034](/decisions/0034-end-users-and-upstream-signals/#states)) and shredding its data key ([0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#erasure-and-export)).

### Client names

- **A client that belongs to a product is declared,** with a readable name that is the same in every environment (`web`, `wallet`), as in [0017](/decisions/0017-identity-and-sign-in/#audiences).
- **A client that belongs to a tenant is `<tenant>:<name>`,** where `<tenant>` is the tenant's name and `<name>` the client's, each 1 to 32 characters in lower-case kebab-case. The tenant's name is set when the tenant is created, is unique in its customer boundary and is never reused or changed. The colon is the separator that `aws:<account>:<role>` already uses, and client IDs stay unique per issuer.

### Moving

[0008](/decisions/0008-boundaries-and-tenants/#scale) says a tenant does not move up alone: one that needs keys becomes a customer boundary, and a cohort moves to an installation of its own. For the people in a move:

1. **The persons of the tenant or the cohort are exported from the subject lifecycle and imported with the same subjects;** the link keys are recomputed under the new installation's `link-key` ([0019](/decisions/0019-person-and-upstream-link/#the-records)). A person's `sub` does not change.
2. **Sessions and tokens do not move.** The new issuer is a new `iss`, so the relying parties pin it and people sign in again, silently where the upstream session lasts.
3. **A tenant that becomes a customer boundary keeps its client names;** its clients are registered at the new issuer under the same names.

## Consequences

- Thousands of customer organisations cost records, not keys, processes or ceremonies. The yearly certification count follows the customer boundaries, a handful.
- A regulated customer that needs keys of its own is one step: a customer boundary or a cohort of one. The step costs a certification item, an issuer host and the relying parties' re-pinning.
- A tenant's connection is a path into a product. The ceiling of trust and the tenant bound are what keep one tenant's identity provider from reaching another's data.
- sluis cannot answer "who is in this organisation": the module can.
- A moved person keeps their `sub`, so a relying party that stored it keeps its users.
- Requirements: [REQ-ISO-076](/requirements/iso/#REQ-ISO-076), [REQ-ISO-077](/requirements/iso/#REQ-ISO-077), [REQ-ISO-078](/requirements/iso/#REQ-ISO-078) are added.

## Roads not taken

- **An issuer, or a signing key, per tenant.** It is a key per tenant, which [0008](/decisions/0008-boundaries-and-tenants/#tenants) rules out, and it would break one sign-in across the products.
- **One customer boundary for the whole group.** All products would share an issuer and an audience space, so a token for one product would be a candidate for another's relying parties.
- **Organisation membership stored in sluis.** It would make sluis the store of a product's user groups, which [0031](/decisions/0031-ciam-is-a-broker/) refuses.
- **A tenant claim in every token.** Nothing reads it yet, and a claim outside the fixed set needs its own consumer.
- **Client IDs from a counter or a random string.** Nobody could read which tenant a client belongs to in a log or a relying party's configuration.
- **A new subject for a moved person.** Every relying party would lose its users and every link would be a new person.

## Follow-ups

- Customer boundaries, tenant templates and the customer-identity module's contract: [#1023](https://github.com/truvity/sluis/issues/1023).
- Issued records and live reload of declared configuration: [#977](https://github.com/truvity/sluis/issues/977).
- Subject export and import for a move: [#1024](https://github.com/truvity/sluis/issues/1024).
