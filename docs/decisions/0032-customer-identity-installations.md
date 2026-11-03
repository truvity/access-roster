# 0032 — A customer-identity installation is a front and a few customer boundaries whose tenants each have their own data keys, a tenant's client IDs carry its name, and a move keeps every subject

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-03

Proposal: [issue #1023](https://github.com/truvity/sluis/issues/1023).

## Context

[0008](/decisions/0008-boundaries-and-tenants/) fixes the words and the scale: a boundary holds keys and policy, a tenant is a scope with data keys of its own, an installation is designed for about 5 to 10 customer boundaries and thousands of tenants, and growth past a cohort is another installation ([Scale](/decisions/0008-boundaries-and-tenants/#scale)). [0004](/decisions/0004-the-data-model/#profiles) fixes how a tenant's records are written. [0031](/decisions/0031-ciam-is-a-broker/) fixes who owns what. What none of them says is what the customer-identity installation looks like when put together, how a tenant's client is named, what a tenant holds, and what moving a tenant or a cohort does to the people in it.

Three gaps remained.

- **Single sign-on across products needs a shape.** The products of a customer must not each ask the person again, yet each tenant has an issuer of its own ([0017](/decisions/0017-identity-and-sign-in/#issuers)).
- **Client IDs are readable and unique per issuer,** with names of 1 to 32 characters ([0017](/decisions/0017-identity-and-sign-in/#audiences)). Thousands of tenants that each have a `web` client need a rule.
- **The NATS mapping must not become an account per tenant.** [REQ-ISO-025](/requirements/iso/#REQ-ISO-025) says "in its boundary's account". With a tenant now meaning a customer organisation, an account per tenant would be thousands of accounts.

## Decision

### The shape

- **A person signs in once, at the upstream broker.** Single sign-on across tenants is the broker's session ([0033](/decisions/0033-customer-connections/#which-upstreams-an-installation-has)). Each tenant's issuer has sluis sessions of its own and two tenants never share one ([0018](/decisions/0018-sessions/#session-chains)); a second tenant's app asks the broker again and is answered silently while the broker's session lasts, and each tenant's policy may still demand a step-up or a fresh sign-in ([0017](/decisions/0017-identity-and-sign-in/#step-up)).
- **The tenant is the controller.** Each controller is a tenant with an issuer host of its own, its own `pairwise` key and its own sector, and its clients inherit the sector. All apps of one controller see the same `sub` for a person, and different controllers see different ones ([0034](/decisions/0034-end-users-and-upstream-signals/#subjects-and-sectors)). A regulated customer's tenant is declared regulated ([0008](/decisions/0008-boundaries-and-tenants/#tenants)).
- **A customer installation has one boundary per regulated customer plus one shared customer boundary** ([Example installations](/decisions/0008-boundaries-and-tenants/#example-installations)). The boundary is the unit of keys, engine and failure domain, and apps cannot see it. A regulated customer's boundary has an engine, a bucket and a queue of its own; the shared boundary serves the other customers as tenants. A tenant that outgrows the shared boundary is promoted to a boundary of its own ([Promotion](/decisions/0008-boundaries-and-tenants/#promotion)), and an app notices nothing.
- **A relying party pins its tenant's issuer.** Each tenant has an issuer host of its own, under the operator's domain or its own, with discovery and the key set served there from the boundary's static documents ([0017](/decisions/0017-identity-and-sign-in/#issuers)). A boundary serves one or more issuers. Which tenant a client belongs to is in its ID.

### Tenants

- **A tenant has four data keys of its own and, by default, no authority key.** `key@` makes its `data`, `pseudonym`, `pairwise` and `evidence` keys when `exchange` writes the `Tenant` ([Tenant lifecycle](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)). No tenant of a customer boundary shares a data key with another, the tenants of the shared boundary included. Where the keys live, and the issuer signing key of a tenant that keeps its keys in a customer account, is [0006](/decisions/0006-keys-and-sealing/#where-a-tenants-keys-live)'s.
- **A tenant's records are clients and limits.** They are Tenant-adjustable durable kinds, written by their one owner: `TenantClient` and the tenant's settings by `exchange`. A tenant admin, or the customer-identity module for its tenant, writes them through the API inside the bounds of a client template in config ([0004](/decisions/0004-the-data-model/#profiles), [0021](/decisions/0021-clients/)). The template fixes the redirect rules of its clients and its limits ([0036](/decisions/0036-volumetric-abuse/#inside-sluis)). A tenant has no connection of its own in sluis: its identity provider is configured in the broker, which is the one upstream ([0033](/decisions/0033-customer-connections/#which-upstreams-an-installation-has)). A tenant cannot widen a claim, a ceiling or a grant, because the store refuses a write outside the bounds ([0005](/decisions/0005-the-store/#rules)).
- **A person's tenant is the tenant of the client they sign in to.** The broker's organisation id binds only a tenant's own business staff ([0033](/decisions/0033-customer-connections/#which-tenant-a-person-belongs-to)). A policy guard keeps a person of one tenant out of any other tenant's scope ([REQ-ISO-036](/requirements/iso/#REQ-ISO-036) is the model; [Tenants](/decisions/0008-boundaries-and-tenants/#tenants) names the guard).
- **sluis stores no organisation membership and no tenant claim.** Which users belong to an organisation is the customer-identity module's data ([0031](/decisions/0031-ciam-is-a-broker/#who-owns-what)). The claim set of a token is fixed ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)); a token for a regulated audience names no organisation or tenant beyond what `iss` and `aud` already say, and `iss` is the tenant's own issuer host ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)).
- **A tenant is not a transport account.** The NATS mapping is an account per boundary ([0028](/decisions/0028-audit-pieces/#nats-jetstream), [REQ-ISO-025](/requirements/iso/#REQ-ISO-025)). Thousands of tenants never become thousands of accounts.
- **A tenant leaves** by disconnecting its connections, making its persons `left` ([0034](/decisions/0034-end-users-and-upstream-signals/#states)) and erasing the tenant, which deletes its `data`, `pseudonym` and `pairwise` wraps at once ([Tenant lifecycle](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle), [0006](/decisions/0006-keys-and-sealing/#erasing-a-tenant)).

### Client names

- **A client that belongs to a product is declared,** with a readable name that is the same in every environment (`web`, `wallet`), as in [0017](/decisions/0017-identity-and-sign-in/#audiences).
- **A client that belongs to a tenant is `<tenant>:<name>`,** where `<tenant>` is the tenant's name and `<name>` the client's, each 1 to 32 characters in lower-case kebab-case. The tenant's name is set when the tenant is created, is unique in its customer boundary and is never reused or changed. The colon is the separator that `aws:<account>:<role>` already uses, and client IDs stay unique per issuer.

### Moving

[0008](/decisions/0008-boundaries-and-tenants/#scale) says a tenant does not move up alone: one that needs keys becomes a boundary by [promotion](/decisions/0008-boundaries-and-tenants/#promotion), and a boundary or a cohort moves to a boundary or an installation of its own. The rules below apply to a whole boundary and to one tenant that is promoted, and moving a tenant changes nothing an app sees.

1. **A moved tenant keeps its issuer host.** `iss` is unchanged: DNS is repointed to the new boundary's `entry`, and the apps pin nothing new. The new boundary signs with keys of its own, published in the key set of the same issuer.
2. **A moved tenant keeps its `pairwise` key.** The key is re-wrapped for the new boundary's wrapping key at the move ceremony, moved sealed from the old `key@` to the new one, never replaced and never on a run-time path ([0006](/decisions/0006-keys-and-sealing/#sign-and-mac)). Its pairwise subjects survive. A whole boundary that moves takes the same step for each of its tenants and also keeps its `mac` key, so its link ids and upstream session ids survive; a promoted tenant's link ids are made again under the new boundary's `mac` key ([0008](/decisions/0008-boundaries-and-tenants/#promotion)).
3. **The persons keep their subject.** The move reads each durable kind through the old boundary's store and writes it at its new address, and the subject is the id of the `Person`; a cohort that moves to another installation is exported from the subject lifecycle and imported with the same subjects. A person's `sub` does not change.
4. **Sessions and tokens do not move.** People sign in again, silently at the upstream broker where its session lasts. Temp kinds do not move.
5. **While the old and the new installation both run, they may exchange tokens** only under the declared trust of one operator ([0008](/decisions/0008-boundaries-and-tenants/#federation-between-boundaries)); every other exchange between them stays refused.
6. **A move into a customer account** re-wraps the tenant's keys under the customer's KMS key at the same ceremony and changes nothing else ([0006](/decisions/0006-keys-and-sealing/#where-a-tenants-keys-live)).
7. **A promoted tenant keeps its `Person` ids and its client names.**

### Example

This example is not normative, and its names are generic. A wallet product (tenant `w`) and the portal of regulated customer A (tenant `a`) are tenants of the shared customer boundary. The portal of regulated customer B (tenant `b`) is a tenant of a boundary of its own.

- One person has three unlinkable `sub` values, one at each tenant, because each tenant has its own `pairwise` key and sector.
- A single sign-in at the broker covers all three apps. The broker's session answers the second and the third silently, and regulated customers A and B may still demand a step-up or a fresh sign-in.
- When A is promoted to a boundary of its own, its issuer and its `sub` values stay the same. The wallet and B's portal see nothing.

## Consequences

- Thousands of customer organisations cost durable items and four data keys each, not authority keys, processes or ceremonies. The yearly certification count follows the customer boundaries, a handful.
- A regulated customer that needs keys of its own is one step: a tenant in a customer account ([0006](/decisions/0006-keys-and-sealing/#where-a-tenants-keys-live)), or a customer boundary or a cohort of one. A boundary costs a certification item, and a later move to its own installation costs the relying parties nothing, because the issuer and the subjects stay. Whether the keys stay with the operator or sit in an account of the customer is a contract choice that the design does not wait on.
- A tenant's identity provider is a path into a product, but through the broker and not through sluis. The tenant bound and the connection's trust keep a person of one tenant from another's data, and the broker's own isolation keeps one tenant's provider from vouching for another's people.
- sluis cannot answer "who is in this organisation": the module can.
- A person of a moved tenant keeps their `sub` and the tenant keeps its `iss`, so a relying party that stored them keeps its users and its pin.
- Two controllers are two tenants, so a regulated customer's relying party and a product's never see the same `sub`, and an app cannot tell which boundary serves its tenant.
- Each tenant's issuer host is one more name to publish and to watch with the CAA and Certificate Transparency rules of [REQ-SEC-029](/requirements/sec/#REQ-SEC-029) to [REQ-SEC-031](/requirements/sec/#REQ-SEC-031).
- Requirements: [REQ-DATA-025](/requirements/data/#REQ-DATA-025), [REQ-ISO-116](/requirements/iso/#REQ-ISO-116), [REQ-ISO-077](/requirements/iso/#REQ-ISO-077) and [REQ-ISO-078](/requirements/iso/#REQ-ISO-078).

## Roads not taken

- **An issuer per boundary, shared by its tenants.** Apps of different controllers would share an issuer and an audience space, and moving one tenant would change its `iss`.
- **One customer boundary for the whole customer base.** All products would share an issuer and an audience space, so a token for one product would be a candidate for another's relying parties.
- **A boundary for every tenant.** Each would carry keys, an issuer host and a yearly certification ([0008](/decisions/0008-boundaries-and-tenants/#scale)).
- **Organisation membership stored in sluis.** It would make sluis the store of a product's user groups, which [0031](/decisions/0031-ciam-is-a-broker/) refuses.
- **A `memberships` claim listing a person's organisations.** It would carry the product's membership data through sluis, which stores none, and name organisations to relying parties that must not learn them, regulated audiences first ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)). The product holds the active organisation.
- **A tenant claim in every token.** Nothing reads it yet, and a claim outside the fixed set needs its own consumer.
- **Client IDs from a counter or a random string.** Nobody could read which tenant a client belongs to in a log or a relying party's configuration.
- **A new subject for a moved person.** Every relying party would lose its users and every link would be a new person.
- **A new `iss` for a moved tenant.** Every relying party would re-pin and every person would sign in again, which fails the exit that [0008](/decisions/0008-boundaries-and-tenants/#example-installations) promises.
- **A pairwise key made again at the new boundary.** Every pairwise subject would change, as a new subject for a moved person does.

## Follow-ups

- Customer boundaries, tenant templates and the customer-identity module's contract: [#1023](https://github.com/truvity/sluis/issues/1023).
- Subject export and import for a move: [#1024](https://github.com/truvity/sluis/issues/1024).
