# 0032 — A customer-identity installation is a front and a few customer boundaries whose tenants each have their own data keys, a tenant's client IDs carry its name, and a move keeps every subject

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-03

Proposal: [issue #1023](https://github.com/truvity/sluis/issues/1023).

## Context

[0008](/decisions/0008-boundaries-and-tenants/) fixes the words and the scale: a boundary holds keys and policy, a tenant is a scope with data keys of its own, an installation is designed for about 5 to 10 customer boundaries and thousands of tenants, and growth past a cohort is another installation ([Scale](/decisions/0008-boundaries-and-tenants/#scale)). [0004](/decisions/0004-the-data-model/#profiles) fixes how a tenant's records are written. [0031](/decisions/0031-ciam-is-a-broker/) fixes who owns what. What none of them says is what the customer-identity installation looks like when put together, how a tenant's client is named, what a tenant holds, and what moving a tenant or a cohort does to the people in it.

Three gaps remained.

- **Single sign-on across products needs a shape.** The products of a customer must not each ask the person again, yet each customer boundary has an issuer of its own ([0017](/decisions/0017-identity-and-sign-in/#issuers)).
- **Client IDs are readable and unique per issuer,** with names of 1 to 32 characters ([0017](/decisions/0017-identity-and-sign-in/#audiences)). Thousands of tenants that each have a `web` client need a rule.
- **The NATS mapping must not become an account per tenant.** [REQ-ISO-025](/requirements/iso/#REQ-ISO-025) says "in its boundary's account". With a tenant now meaning a customer organisation, an account per tenant would be thousands of accounts.

## Decision

### The shape

- **The front is the one place a person signs in.** Each customer boundary runs a slim `entry` whose upstream is the front, and exchanges the front's token silently ([0017](/decisions/0017-identity-and-sign-in/#step-up)). `sub` is the same at every issuer, so the products of a customer recognise one person. That is the single sign-on across products. Pairwise subjects are a separate, later tool ([0034](/decisions/0034-end-users-and-upstream-signals/#pairwise-subjects)).
- **A customer installation has one boundary per regulated customer plus one shared customer boundary** ([Example installations](/decisions/0008-boundaries-and-tenants/#example-installations)). A regulated customer's boundary has an engine, a bucket and a queue of its own; the shared boundary serves the other customers as tenants. A customer that outgrows the shared boundary is promoted to a boundary of its own ([Promotion](/decisions/0008-boundaries-and-tenants/#promotion)).
- **A relying party of a product pins that product's customer boundary issuer,** or the issuer of its client's login domain, which shares the boundary's keys ([0017](/decisions/0017-identity-and-sign-in/#issuers)), as for any issuer. Which boundary a client belongs to is declared with the client.

### Tenants

- **A tenant has three data keys of its own and no authority key.** `key@` makes its `data`, `pseudonym` and `evidence` keys when `exchange` writes the `Tenant` ([Tenant lifecycle](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)). No tenant of a customer boundary shares a data key with another, the tenants of the shared boundary included.
- **A tenant's records are connections, domains, clients and limits.** They are Tenant-adjustable durable kinds, each written by its one owner: `TenantConnection` and `DomainClaim` by `session`, `TenantClient` and the tenant's settings by `exchange`. A tenant admin, or the customer-identity module for its tenant, writes them through the API inside the bounds of a client template in config ([0004](/decisions/0004-the-data-model/#profiles), [0021](/decisions/0021-clients/)). The template fixes the kinds of connection a tenant may add and their ceiling of trust ([0033](/decisions/0033-customer-connections/#connection-trust)), the redirect rules of its clients and its limits ([0036](/decisions/0036-volumetric-abuse/#inside-sluis)). A tenant cannot widen a claim, a ceiling or a grant, because the store refuses a write outside the bounds ([0005](/decisions/0005-the-store/#rules)).
- **A person who signed in through a tenant's own connection is bounded to that tenant** by the connection that vouched for them: the tenant is set by the connection's owner, never by what the provider sent. A policy guard keeps such a person out of any other tenant's scope ([REQ-ISO-036](/requirements/iso/#REQ-ISO-036) is the model; [Tenants](/decisions/0008-boundaries-and-tenants/#tenants) names the guard).
- **sluis stores no organisation membership and no tenant claim.** Which users belong to an organisation is the customer-identity module's data ([0031](/decisions/0031-ciam-is-a-broker/#who-owns-what)). The claim set of a token is fixed ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)); a product that needs the organisation in a token adds a claim with its first consumer.
- **A tenant is not a transport account.** The NATS mapping is an account per boundary ([0028](/decisions/0028-audit-pieces/#nats-jetstream), [REQ-ISO-025](/requirements/iso/#REQ-ISO-025)). Thousands of tenants never become thousands of accounts.
- **A tenant leaves** by disconnecting its connections, making its persons `left` ([0034](/decisions/0034-end-users-and-upstream-signals/#states)) and erasing the tenant, which deletes its `data` and `pseudonym` wraps at once ([Tenant lifecycle](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle), [0006](/decisions/0006-keys-and-sealing/#erasing-a-tenant)).

### Client names

- **A client that belongs to a product is declared,** with a readable name that is the same in every environment (`web`, `wallet`), as in [0017](/decisions/0017-identity-and-sign-in/#audiences).
- **A client that belongs to a tenant is `<tenant>:<name>`,** where `<tenant>` is the tenant's name and `<name>` the client's, each 1 to 32 characters in lower-case kebab-case. The tenant's name is set when the tenant is created, is unique in its customer boundary and is never reused or changed. The colon is the separator that `aws:<account>:<role>` already uses, and client IDs stay unique per issuer.

### Moving

[0008](/decisions/0008-boundaries-and-tenants/#scale) says a tenant does not move up alone: one that needs keys becomes a customer boundary by [promotion](/decisions/0008-boundaries-and-tenants/#promotion), and a cohort moves to an installation of its own. For the people in a move:

1. **The persons of the tenant or the cohort keep their subject.** A promotion reads each durable kind through the old boundary's store and writes it at its new address, and the subject is the id of the `Person`. A cohort that moves to another installation is exported from the subject lifecycle and imported with the same subjects. The link ids, which are keyed hashes of the issuer and the claim value, are made again under the new boundary's `mac` data key ([0006](/decisions/0006-keys-and-sealing/#sign-and-mac)). A person's `sub` does not change.
2. **Sessions and tokens do not move.** The new issuer is a new `iss`, so the relying parties pin it and people sign in again, silently where the upstream session lasts. Temp kinds do not move.
3. **A tenant that becomes a customer boundary keeps its client names;** its clients are registered at the new issuer under the same names.

## Consequences

- Thousands of customer organisations cost durable items and three data keys each, not authority keys, processes or ceremonies. The yearly certification count follows the customer boundaries, a handful.
- A regulated customer that needs keys of its own is one step: a customer boundary or a cohort of one. The step costs a certification item, an issuer host and the relying parties' re-pinning.
- A tenant's connection is a path into a product. The ceiling of trust and the tenant bound are what keep one tenant's identity provider from reaching another's data.
- sluis cannot answer "who is in this organisation": the module can.
- A moved person keeps their `sub`, so a relying party that stored it keeps its users.
- Requirements: [REQ-DATA-025](/requirements/data/#REQ-DATA-025), [REQ-ISO-077](/requirements/iso/#REQ-ISO-077) and [REQ-ISO-078](/requirements/iso/#REQ-ISO-078).

## Roads not taken

- **An issuer, or a signing key, per tenant.** It is an authority key per tenant, which [principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule) rules out, and it would break one sign-in across the products.
- **One customer boundary for the whole customer base.** All products would share an issuer and an audience space, so a token for one product would be a candidate for another's relying parties.
- **A boundary for every tenant.** Each would carry keys, an issuer host and a yearly certification ([0008](/decisions/0008-boundaries-and-tenants/#scale)).
- **Organisation membership stored in sluis.** It would make sluis the store of a product's user groups, which [0031](/decisions/0031-ciam-is-a-broker/) refuses.
- **A `memberships` claim listing a person's organisations.** It would carry the product's membership data through sluis, which stores none, and name organisations to relying parties that must not learn them, regulated audiences first ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)). The product holds the active organisation.
- **A tenant claim in every token.** Nothing reads it yet, and a claim outside the fixed set needs its own consumer.
- **Client IDs from a counter or a random string.** Nobody could read which tenant a client belongs to in a log or a relying party's configuration.
- **A new subject for a moved person.** Every relying party would lose its users and every link would be a new person.

## Follow-ups

- Customer boundaries, tenant templates and the customer-identity module's contract: [#1023](https://github.com/truvity/sluis/issues/1023).
- Subject export and import for a move: [#1024](https://github.com/truvity/sluis/issues/1024).
