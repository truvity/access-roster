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

- **The front is the one place a person signs in.** Each customer boundary runs a slim `entry` whose upstream is the front, and exchanges the front's token silently ([0017](/decisions/0017-identity-and-sign-in/#step-up)). The products of one controller are clients of one boundary and see the same `sub`, so they recognise one person. That is the single sign-on across the products of a controller. Which `sub` a boundary's clients see is [0034](/decisions/0034-end-users-and-upstream-signals/#subjects-and-sectors)'s rule.
- **A customer installation has one boundary per regulated customer plus one shared customer boundary** ([Example installations](/decisions/0008-boundaries-and-tenants/#example-installations)). **Each product controller is its own boundary,** so two controllers never share an issuer, an audience space or a `sub` ([0034](/decisions/0034-end-users-and-upstream-signals/#subjects-and-sectors)); a regulated customer's boundary is declared regulated ([0008](/decisions/0008-boundaries-and-tenants/#boundaries)). A product reaches a regulated customer's API as a client registered in that customer's boundary. A regulated customer's boundary has an engine, a bucket and a queue of its own; the shared boundary serves the other customers as tenants. A customer that outgrows the shared boundary is promoted to a boundary of its own ([Promotion](/decisions/0008-boundaries-and-tenants/#promotion)).
- **A relying party of a product pins that product's customer boundary issuer,** or the issuer of its client's login domain, which shares the boundary's keys ([0017](/decisions/0017-identity-and-sign-in/#issuers)), as for any issuer. Which boundary a client belongs to is declared with the client.

### Tenants

- **A tenant has three data keys of its own and no authority key.** `key@` makes its `data`, `pseudonym` and `evidence` keys when `exchange` writes the `Tenant` ([Tenant lifecycle](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)). No tenant of a customer boundary shares a data key with another, the tenants of the shared boundary included.
- **A tenant's records are clients and limits.** They are Tenant-adjustable durable kinds, written by their one owner: `TenantClient` and the tenant's settings by `exchange`. A tenant admin, or the customer-identity module for its tenant, writes them through the API inside the bounds of a client template in config ([0004](/decisions/0004-the-data-model/#profiles), [0021](/decisions/0021-clients/)). The template fixes the redirect rules of its clients and its limits ([0036](/decisions/0036-volumetric-abuse/#inside-sluis)). A tenant has no connection of its own in sluis: its identity provider is configured in the broker, which is the one upstream ([0033](/decisions/0033-customer-connections/#which-upstreams-an-installation-has)). A tenant cannot widen a claim, a ceiling or a grant, because the store refuses a write outside the bounds ([0005](/decisions/0005-the-store/#rules)).
- **A person is bounded to a tenant by a binding, never by anything else the provider sent.** The binding is the organisation id that the upstream sends and the `Tenant` that records it ([0033](/decisions/0033-customer-connections/#which-tenant-a-person-belongs-to)). A policy guard keeps such a person out of any other tenant's scope ([REQ-ISO-036](/requirements/iso/#REQ-ISO-036) is the model; [Tenants](/decisions/0008-boundaries-and-tenants/#tenants) names the guard).
- **sluis stores no organisation membership and no tenant claim.** Which users belong to an organisation is the customer-identity module's data ([0031](/decisions/0031-ciam-is-a-broker/#who-owns-what)). The claim set of a token is fixed ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)); a token for a regulated audience names no organisation or tenant beyond what `iss` and `aud` already say ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)).
- **A tenant is not a transport account.** The NATS mapping is an account per boundary ([0028](/decisions/0028-audit-pieces/#nats-jetstream), [REQ-ISO-025](/requirements/iso/#REQ-ISO-025)). Thousands of tenants never become thousands of accounts.
- **A tenant leaves** by disconnecting its connections, making its persons `left` ([0034](/decisions/0034-end-users-and-upstream-signals/#states)) and erasing the tenant, which deletes its `data` and `pseudonym` wraps at once ([Tenant lifecycle](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle), [0006](/decisions/0006-keys-and-sealing/#erasing-a-tenant)).

### Client names

- **A client that belongs to a product is declared,** with a readable name that is the same in every environment (`web`, `wallet`), as in [0017](/decisions/0017-identity-and-sign-in/#audiences).
- **A client that belongs to a tenant is `<tenant>:<name>`,** where `<tenant>` is the tenant's name and `<name>` the client's, each 1 to 32 characters in lower-case kebab-case. The tenant's name is set when the tenant is created, is unique in its customer boundary and is never reused or changed. The colon is the separator that `aws:<account>:<role>` already uses, and client IDs stay unique per issuer.

### Moving

[0008](/decisions/0008-boundaries-and-tenants/#scale) says a tenant does not move up alone: one that needs keys becomes a customer boundary by [promotion](/decisions/0008-boundaries-and-tenants/#promotion), and a boundary or a cohort moves to a boundary or an installation of its own. For the people in a move:

1. **A moved boundary keeps its issuer host.** `iss` is unchanged: DNS is repointed to the new boundary's `entry`, and the relying parties pin nothing new. The new boundary signs with keys of its own, published in the key set of the same issuer.
2. **A moved boundary keeps its `mac` key,** so its pairwise subjects, link ids and upstream session ids survive and nothing is made again ([0006](/decisions/0006-keys-and-sealing/#sign-and-mac)). The key is moved sealed from the old `key@` to the new one in a ceremony, never on a run-time path, and no other actor sees it. How the key reaches a customer-held KMS: pending counsel.
3. **The persons keep their subject.** The move reads each durable kind through the old boundary's store and writes it at its new address, and the subject is the id of the `Person`; a cohort that moves to another installation is exported from the subject lifecycle and imported with the same subjects. A person's `sub` does not change.
4. **Sessions and tokens do not move.** People sign in again, silently where the upstream session lasts. Temp kinds do not move.
5. **While the old and the new installation both run, they may exchange tokens** only under the declared trust of one operator ([0008](/decisions/0008-boundaries-and-tenants/#federation-between-boundaries)); every other exchange between them stays refused.
6. **A promoted tenant gets its own boundary.** It keeps its `Person` ids and its client names, and its clients are registered at the new issuer. Whether its pairwise subjects survive promotion is decided in a follow-up.

## Consequences

- Thousands of customer organisations cost durable items and three data keys each, not authority keys, processes or ceremonies. The yearly certification count follows the customer boundaries, a handful.
- A regulated customer that needs keys of its own is one step: a customer boundary or a cohort of one. The step costs a certification item and an issuer host, and a later move to its own installation costs the relying parties nothing, because the issuer and the subjects stay.
- A tenant's identity provider is a path into a product, but through the broker and not through sluis. The tenant bound and the connection's trust keep a person of one tenant from another's data, and the broker's own isolation keeps one tenant's provider from vouching for another's people.
- sluis cannot answer "who is in this organisation": the module can.
- A person of a moved boundary keeps their `sub` and the boundary keeps its `iss`, so a relying party that stored them keeps its users and its pin.
- Two controllers are two boundaries, so a regulated customer's relying party and a product's never see the same `sub`.
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
- **A new `iss` for a moved boundary.** Every relying party would re-pin and every person would sign in again, which fails the exit that [0008](/decisions/0008-boundaries-and-tenants/#example-installations) promises.
- **A pairwise key made again at the new boundary.** Every pairwise subject would change, as a new subject for a moved person does.
- **One boundary for every controller, with a client-level sector.** Controllers would share an issuer, and one client with the wrong sector would give a controller's `sub` to another.

## Follow-ups

- Customer boundaries, tenant templates and the customer-identity module's contract: [#1023](https://github.com/truvity/sluis/issues/1023).
- Subject export and import for a move: [#1024](https://github.com/truvity/sluis/issues/1024).
- How the `mac` key reaches a customer-held KMS: pending counsel.
- Whether a promoted tenant's pairwise subjects survive promotion: a follow-up.
