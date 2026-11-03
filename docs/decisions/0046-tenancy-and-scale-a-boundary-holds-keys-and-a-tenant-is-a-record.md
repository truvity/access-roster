# 0046 — Tenancy and scale: a boundary is the unit of keys and isolation, a tenant is a record without keys, and growth past a cohort is another installation

**Status:** Superseded by 0008
**Date:** 2026-11-03

Proposal: [issue #1023](https://github.com/truvity/sluis/issues/1023).

## Context

The v1 parity, customer-identity and quota milestones all ask the same questions: what is a tenant, what is a boundary, how many of each does one installation carry, and where does it run. The words have drifted:

- [0008](/decisions/0008-boundaries-and-tenants/) called a boundary for a company's customers a "product boundary". [0011](/decisions/0011-runtimes-and-installations/) runs audit-with-quota as "one installation for each product", and an audit record names the emitting application as its product. A reader cannot tell a product that is a boundary from a product that is an installation.
- A tenant is defined for audit, quota and directory data, and nowhere for the customers of a company that signs in through sluis.

Three facts bound the answer:

- **Keys belong to boundaries.** A tenant has no key of its own ([principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule), [0006](/decisions/0006-keys-and-sealing/#when-keys-are-shared-and-when-separate)). A boundary with keys needs intermediates certified through the hand-off and re-signed every year ([0024](/decisions/0024-root-custody-and-the-signing-api/)).
- **An install file has a ceiling.** Each boundary has a `uid_block` from 0 to 54, unique in the file ([Install file](/reference/install-file/#boundaries), REQ-ISO-072, REQ-ISO-073), so one file declares at most 55 boundaries.
- **Nothing says where an installation runs** or what happens when it does not.

## Decision

### The words

| Word | Means | Keys |
|---|---|---|
| **Installation** | One deployment: a runtime, its nodes, its dependencies and one driver per port ([0011](/decisions/0011-runtimes-and-installations/#installations)) | Those of its boundaries |
| **Boundary** | The unit of keys and isolation, of one kind: environment, company or customer ([0008](/decisions/0008-boundaries-and-tenants/#boundary-kinds)) | Environment and customer: their own. Company: no authority key |
| **Customer boundary** | A company and an environment together, with its own keys and issuer, for the customers of a company or of one of its products who sign in through sluis. This is 0005's former "product boundary" | Its own |
| **Product** | Something the operator builds and sells. sluis has no kind for it. A product that needs audit and quota gets an installation of its own ([0011](/decisions/0011-runtimes-and-installations/#installations)); a product whose customers sign in through sluis gets a customer boundary | None |
| **Tenant** | A division inside a boundary that has settings of its own, such as an audit, directory or quota tenant, or the customer organisation of a customer boundary. It is a record, kept apart by code only (L0) | None |
| **Billing account** | A quota account ([0030](/decisions/0030-audit-records-and-the-usage-stream/#quota)) in one installation. Its balance is keyed by boundary, company, account and meter | None |

An organisation, a group of a customer's users, is not a sluis kind: it is part of the customer-identity module of [0047](/decisions/0047-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/#customer-identity-installations), outside the core.

### Keys and isolation

- **Keys and isolation belong to a boundary and to nothing smaller.** A tenant's data keys are wrapped under its boundary's sealing key with the tenant in the encryption context, and shredding a tenant deletes its data key. sluis creates no key in a key store for a tenant (REQ-ISO-068, REQ-ISO-070).
- **A party that needs keys, an issuer or a failure domain of its own is a customer boundary or an installation, never a tenant with a key.** A secret that belongs to one tenant, such as the client secret of its upstream connection, is a sealed secret in the `secrets` port ([0005](/decisions/0005-the-store/#sealed-secrets)), not a key in the store.
- **A regulated entity is at least a customer boundary** ([0008](/decisions/0008-boundaries-and-tenants/#the-isolation-ladder)), and its customers come from its own customer-identity product as an upstream. sluis hosts no end-user accounts ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)).

### The scale to design for

- **An installation is designed for about 5 to 10 customer boundaries and thousands of tenants.** Customer boundaries are few because each pays for keys, a yearly certification, an issuer host, a `uid_block`, a state prefix and its own actor instances. Tenants are many because each is a record.
- **The ceiling of 55 boundaries in an install file is enough and stays.** Five to ten customer boundaries, a handful of environments and a few companies use under half of it. A ceiling is not raised without an installation that needs more (principle 8); a 56th boundary is refused by `sluis config check` (REQ-ISO-073).
- **The target is a design size, not a measured capacity.** Sign-in rate, signing cost, state hot keys and the audit writer are measured first and dated (principle 9) before any capacity number enters a record.

### Growth is another installation

- **When a cohort of customer boundaries must be separate, it moves to an installation of its own.** The reasons are a failure domain, a residency region, or an installation that has reached the target. A cohort is the customer boundaries that share a failure domain, a region and an operator; one regulated entity is a cohort of one. The new installation has its own install file, keys, state and issuers, and the runbook is the promotion of [0008](/decisions/0008-boundaries-and-tenants/#promotion).
- **A tenant does not move up the ladder alone.** A tenant that needs keys of its own becomes a customer boundary, or goes with its cohort to a new installation.
- **A billing account belongs to one installation.** A limit never spans installations: a plan that covers several products is pooled by the billing system pushing top-ups to each installation, not by a quota installation that every product calls ([REQ-QUOTA-025](/requirements/quota/#REQ-QUOTA-025)).

### Where installations run

- **One region for now: one region of one cloud provider, chosen per installation in its install file.** An installation's state, blobs, queues, compute and keys are there. The multi-Region replica of the sealing key ([Keys](/concepts/keys/)) is the one thing that lives in a second region, and it must be in the allowed set of the region guard ([REQ-OPS-007](/requirements/ops/#REQ-OPS-007)).
- **Later, one installation per residency region, sharing nothing.** An installation does not span regions, and a region is not an attribute of a tenant: a second region means a second installation with its own keys, state and issuer, as environments never share keys ([0006](/decisions/0006-keys-and-sealing/#when-keys-are-shared-and-when-separate)).
- **A regional outage stops signing in that region**, because KMS is regional and the software key fallback is refused in production ([0006](/decisions/0006-keys-and-sealing/#floors-in-code)). This record accepts that for the one region and sets no recovery time or recovery point; [ADR 0056](/decisions/0056-a-regional-outage-is-accepted-public-keys-outlive-it-and-a-drill-measures-recovery/#recovery) records the targets and the drill that measures them.

## Consequences

- One vocabulary serves all three milestones. 0005, the boundaries page, the install-file reference and the requirements glossary say "customer boundary" where they said "product boundary", and "product" means only what the operator sells.
- A customer-identity installation is a few boundaries and many records, so per-tenant change cannot be a boundary, an install-file edit or a deployment. [0047](/decisions/0047-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/) is the write path for it.
- Tenants in one customer boundary share its actors, its sealing key and its fate: a flaw in the shared code reaches every tenant of the boundary. That is the accepted L0 risk; an entity that cannot accept it is a customer boundary of its own.
- Every customer boundary adds a certification item to the yearly cycle of the root custodian, which is why the target is a handful and not a hundred.
- Past about ten customer boundaries the answer is another installation, which costs an install file, keys, state, an operator runbook and an upgrade to keep in step, in place of a larger file.
- One region concentrates the risk: a regional outage stops signing, and the design stays honest about it: the recovery targets are in [ADR 0056](/decisions/0056-a-regional-outage-is-accepted-public-keys-outlive-it-and-a-drill-measures-recovery/#recovery) and a drill measures them.
- Requirements: [REQ-ISO-075](/requirements/iso/#REQ-ISO-075).

## Roads not taken

- **Every tenant a boundary.** At most 55 per install file, and each would carry keys, an issuer host and a yearly certification.
- **A key in the key store for each tenant.** It breaks principle 3 and costs a key and a policy per tenant; a per-tenant signing key stays a possible later feature ([0006](/decisions/0006-keys-and-sealing/#when-keys-are-shared-and-when-separate)).
- **Raise the ceiling now.** No installation needs more than the target, and the uid arithmetic and the actor instances per boundary grow with every block.
- **Keep the name "product boundary" and rename the installation per product.** "Product" would stay overloaded; the rarer meaning, a boundary, takes the new word.
- **One installation per regulated entity from the start.** An install file, keys, state and upgrades for each small entity; the cohort is the promotion unit instead.
- **One installation across regions.** One set of keys, one state store and one issuer spanning jurisdictions, and a failure that crosses them.
- **One central quota installation that every product calls.** One failure domain and one hot path for all products.

## Follow-ups

- Customer boundaries and the customer-identity installation, in the CIAM milestone: [#1023](https://github.com/truvity/sluis/issues/1023).
- The runbook for promoting a boundary to an installation of its own: [#973](https://github.com/truvity/sluis/issues/973).
- The region guard: [#1061](https://github.com/truvity/sluis/issues/1061).
