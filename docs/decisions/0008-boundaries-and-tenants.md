# 0008 — A boundary is the unit of keys and policy on a cumulative ladder from L0 to L4, and a tenant is a scope with data keys of its own

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

sluis holds the keys, the policy, the data and the audit trail of whatever it signs people and machines into. The first question about running it is how much of that may be shared. If development and production, or the people of two companies, sit together, a mistake or a compromise in one reaches the keys and data of the other. If everything is separate, every party costs its own keys, its own certification of intermediates, its own processes and its own engine.

Four facts bound the answer.

- **Keys belong to a boundary.** An authority key needs an intermediate certified through the hand-off ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)), so each boundary with keys of its own is a recurring cost.
- **A tenant needs an exit that destroys its personal data and keeps its evidence.** A bill or an audit fact can be disputed after the tenant has left, so one key per tenant is not enough ([0006](/decisions/0006-keys-and-sealing/#data-keys)).
- **An installation is a deployment, not a scope of data** ([0011](/decisions/0011-runtimes-and-installations/#installations)). Settings that are the same everywhere need a home that does not make one boundary read another.
- **Regulated customers ask for separation, key control, an exit and a tested restore.** The public texts they work under say so (table in [Example installations](/decisions/0008-boundaries-and-tenants/#example-installations)). Read on 2026-11-03, none of them prescribes an engine or a runtime of its own for each customer of a service. DORA asks that a restore on own systems is segregated from its source and that an exit is planned; the ECB guide counts an assessment of the multi-tenant risk and keys that are not shared as good practice. So how much separation to buy is a choice of cost and comfort, and the ladder makes it a per-boundary choice.

## Decision

### Boundaries

- **A boundary is the unit of keys and policy.** Every address starts with the boundary ([the address](/decisions/0004-the-data-model/#the-address)). A boundary has its own key@ and wrapping key from L1, its own issuer ([0017](/decisions/0017-identity-and-sign-in/#issuers)), its own SPIFFE trust domain ([0022](/decisions/0022-workload-identity-and-host-enrolment/#trust-domains)), its own policy bundle and its own audit log. A grant sealed in one boundary opens in no other, because each boundary has its own `grant` data key ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). A policy bundle for one boundary that contains another boundary's policy fails the build.
- **The boundary kinds are environment and customer.** An **environment boundary** holds the machine plane of one environment (clusters, hosts, workloads, certificates, SSH and workload identity) and the identity plane of the companies that work in it, as tenants. A **customer boundary** is made for a party that needs keys, an issuer or a failure domain of its own, such as a regulated customer. The `Boundary` config kind declares the kind, the level (L1 to L4), the parent, the issuer host and the unit numbering of a boundary.
- **A boundary declares its sector, and it may be declared regulated.** The `Boundary` item carries `sector`, which is required and which a client of the boundary inherits ([0034](/decisions/0034-end-users-and-upstream-signals/#subjects-and-sectors)). It also carries `regulated`. **A boundary is regulated when its `Boundary` item says so.** The declaration is the operator's, made for a boundary whose customer works under a supervisor's rules on outsourcing, data or secrecy (the texts in [Example installations](/decisions/0008-boundaries-and-tenants/#example-installations)), and nothing is computed from it. A client is a **regulated audience** when its boundary is regulated. This record defines the word; the rules that use it live where their subject lives: the subject a regulated audience gets is [0034](/decisions/0034-end-users-and-upstream-signals/#subjects-and-sectors) and the claims it gets are [0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token).
- **A company is a tenant of an environment boundary.** A company's directory, its chat workspace, its code host and its DNS provider account are kinds of that tenant, as are its upstream, people and operator delegation. Every connection to a provider, made through a UI or API flow (`DirectoryConnection`, `GitHubApp`, `SlackConnection`, `EntraConnection`, `MinterConnection`), the directory read through it and the desired state belong to the tenant that made them, and a connection the operator makes lives in the operator's own company, which is a tenant. Config never has a tenant: an app definition made by hand or IaC for the whole installation (`SlackApp`) is config of the boundary ([the upstream criterion](/decisions/0004-the-data-model/#the-upstream-criterion)). A party that needs authority keys is a customer boundary and never a tenant ([principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule)).
- **A boundary on its own runtime (L4) is an installation of its own,** joined to the others by declared trust ([Federation between boundaries](/decisions/0008-boundaries-and-tenants/#federation-between-boundaries)). A product is not a kind of sluis: it calls the API for its tenants.
- **A boundary may have a parent.** Below L2 the parent's store serves a boundary under its address prefix ([The ladder](/decisions/0008-boundaries-and-tenants/#the-ladder)).

### The ladder

Each boundary declares a level. A level includes the ones below it. A tenant is the lowest level, L0, and is not a boundary.

| Level | Adds |
|---|---|
| L0 tenant | Separation by the store's rules, a grant sealed for the tenant and the tenant's own three data keys |
| L1 keys | Its own key@ and wrapping key (a KMS key, or a card of its own, such as a second card per board), so its own authority keys, intermediates and issuer. It uses the parent's store@, units and engine |
| L2 process | Its own store@ and its own units, with their own uid or role, on the parent's engine under its own address prefix |
| L3 engine | Its own engine (an rqlite cluster or a DynamoDB table), bucket and queue |
| L4 runtime | Its own runtime: its own cloud account, cluster or hosts, joined to the others by declared trust |

- **The level follows the need.** A higher level costs more keys, units, engines or accounts, and a boundary pays only for the level it declares.
- **L1 boundaries on a shared engine are separated by their own wrapping keys.** Their values stay apart because each boundary's data keys are wrapped for its own key, not because the engine differs.
- **Two independent checks hold at every level** ([0007](/decisions/0007-policy-and-sealed-grants/#two-independent-checks)): the store's rule with a grant sealed for the tenant, and key@'s grant check. A level adds separation under them, never instead of them.
- **What a boundary owns follows its level.** Keys and intermediates per boundary (the root custodian signs intermediates only, [0024](/decisions/0024-root-custody-and-the-signing-api/#sluis-holds-no-root)); an issuer per boundary and per login domain ([0017](/decisions/0017-identity-and-sign-in/#issuers)); below L2 a prefix in the parent's store, from L2 its own store@, from L3 its own engine; one audit per boundary, with a log per project and log kind, whose entries are sealed under each tenant's `evidence` data key ([0029](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding)).

### Tenants

- **A tenant is a scope inside a boundary** with its own settings, clients, allowance and three data keys: `data`, `pseudonym` and `evidence` ([0006](/decisions/0006-keys-and-sealing/#data-keys)). It is the second address dimension and only durable and temp kinds use it ([the address](/decisions/0004-the-data-model/#the-address)). The `Tenant` kind, written by exchange, holds its name and its state: active, suspended or erasing.
- **A tenant has no authority key and no wrapping key.** Its data keys are wrapped under its boundary's wrapping key with the tenant and the purpose in the context. A party that needs an issuer, authority keys or a failure domain of its own is a boundary.
- **A tenant may exist in several boundaries.** A company is a tenant of a development, a staging and a production boundary at once. Each boundary holds its own copy of the tenant with its own data keys, so a flaw in one boundary does not reach the tenant's data in another.
- **Tenants of one boundary share its actors, its authority keys and its fate.** A flaw in shared code reaches every tenant of the boundary. That is the accepted L0 risk; a tenant that cannot accept it becomes a customer boundary by [promotion](/decisions/0008-boundaries-and-tenants/#promotion).
- **Tenant separation is two checks and a key.** The store refuses a write without a grant sealed for the tenant, key@ refuses a seal or an open without one, and a value sealed for one tenant does not open with another's data key.
- **Tenant guards are Cedar `forbid` rules of the baseline.** A subject of one tenant gets no grant on a resource that another tenant owns unless the grant is declared cross-tenant, and the guard is checked when the policy loads ([0007](/decisions/0007-policy-and-sealed-grants/#four-layers)).

### Installation-wide settings

- **An installation is not a scope.** There is no address dimension above the boundary and no boundary reads another's configuration.
- **Settings that are the same everywhere are one signed config document that IaC writes into every boundary's config source.** The trust anchors and the front host are examples. Each store@ verifies the document and loads it with the rest of its own snapshot ([configuration loading](/decisions/0005-the-store/#configuration-loading)).
- **A change is a new document with a higher sequence number, written to every boundary.** Until the last write lands, boundaries differ by one version of the document, which every reader of such a document tolerates ([0015](/decisions/0015-evolution-and-compatibility/#n-and-n-1-inside-a-major-version)).

### Federation between boundaries

- **One front plus one installation for each L4 boundary, run by one operator and joined by declared trust.** People get one sign-in URL, one console and one identity plane. Boundaries below L4 run inside the installation that hosts their parent.
- **Calls between boundaries use mutual TLS with SPIFFE IDs** ([0022](/decisions/0022-workload-identity-and-host-enrolment/#spiffe-identities)). Which issuers and trust bundles a boundary accepts is declared in its config.
- **The target re-decides.** A boundary that receives a request decides it again with its own policy and never takes another boundary's decision as its own.
- **A sensitive boundary verifies the person's passkey assertion itself,** against its own challenge, so a compromised front cannot act there ([0017](/decisions/0017-identity-and-sign-in/#passkeys)).
- **A token exchange between two installations is allowed only between installations of one operator that both declare that trust.** The exchanging installation names the other's issuer as a trusted token source, and the other names the exchanging installation's ([REQ-EXCH-006](/requirements/exch/#REQ-EXCH-006)). Every other exchange across installations stays refused, and so does a token of one installation at another's token endpoint or introspection ([REQ-SEC-011](/requirements/sec/#REQ-SEC-011)). The audit front's exchange for another installation's console ([0028](/decisions/0028-audit-pieces/#the-audit-front)) is this case.
- **Each installation runs its own `entry`** ([0003](/decisions/0003-units-transports-and-fusion/#listeners)). The front never holds another boundary's keys.

### Shared parts and accepted risks

- **Shared by every boundary:** the front with its `entry`, the console, the roots held by the root custodian and the operator.
- **Accepted risks that no level removes:** a compromise of the roots; the operator who deploys sluis and the cluster administrators; a compromise of a boundary's `ca`, which reaches the workloads of every tenant in that boundary, because its tenants share its authority keys; a bug in a shared policy definition; data that lives outside sluis.
- **The test installation is separate.** It serves no real user and trusts nothing of the federation.

### Scale

- **An installation is designed for about 5 to 10 customer boundaries and thousands of tenants.** Customer boundaries are few because each pays for keys, a yearly certification of its intermediates ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)), an issuer host, a unit numbering, its own units and, from L3, its own engine. Tenants are many because each is a handful of items and three data keys.
- **The number of boundaries one installation declares has a ceiling,** set by the unit numbering that each boundary reserves on boards. The ceiling is not raised without an installation that needs more ([principle 8](/principles/#8-nothing-without-a-consumer)).
- **The target is a design size, not a measured capacity.** Sign-in rate, signing cost, hot keys and the audit writer are measured first and dated ([principle 9](/principles/#9-measure-before-deciding-and-date-the-measurement), [0037](/decisions/0037-capacity-is-measured-before-it-is-promised/)) before a capacity number enters a record.
- **Growth is another installation.** When a cohort of customer boundaries must be separate, it moves to an installation of its own, with its own keys, store and issuer. The reasons are a failure domain, a residency region, or an installation that has reached the target. A cohort is the customer boundaries that share a failure domain, a region and an operator; one regulated customer is a cohort of one. Where an installation runs is in [0011](/decisions/0011-runtimes-and-installations/#installations).

### Promotion

- **Promotion moves a tenant into a boundary of its own.** It moves the tenant's kinds to the new boundary and rewraps its data keys for the new boundary's wrapping key. It is the only way a tenant moves up the ladder, and the tenant keeps its name, its clients' names and its settings.
- **The procedure, in order:**
  1. The new boundary is declared in config, its key@ is running and its intermediates are certified through the hand-off.
  2. The tenant is suspended, so that no write races the move ([Tenant lifecycle](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)).
  3. The new boundary's key@ wraps the tenant's `data`, `pseudonym` and `evidence` keys for its own wrapping key, as DataKeyWrap items of the new boundary ([0006](/decisions/0006-keys-and-sealing/#datakeywrap)).
  4. The tenant's durable kinds are read through the old boundary's store and written through the new one at their new address. A value is bound to its full address, so a sealed value is opened by the old boundary's key@ and sealed again by the new one's. A hashed value moves as it is, and a keyed hash made under the old boundary's `mac` key is made again under the new one's. Temp kinds do not move.
  5. The tenant's clients are registered at the new boundary's issuer under the same names, and people sign in again ([0032](/decisions/0032-customer-identity-installations/#moving)).
  6. The old boundary's copy is deleted when the new boundary reads back clean.
- **The runbook that tests this procedure is a follow-up** (see below). Until it has run, no installation relies on a promotion.

### Tenant lifecycle

- **Create.** A product, or a seed apply, asks exchange to write the `Tenant`; key@ makes its three data keys. A tenant that exists in another boundary is created again there, with its own keys.
- **Suspend.** Setting the state `suspended` is a tightening: it takes effect at once, keeps all data and keys, and is lifted by an operator ([principle 12](/principles/#12-a-loosening-is-temporary-a-tightening-is-durable)).
- **Erase.** Erasure sets the state `erasing` and runs in this order:
  1. Records that an `ErasureHold` covers are kept, and so is the tenant's `data` wrap that seals them, until the hold's retention period ends; the steps below then run ([0034](/decisions/0034-end-users-and-upstream-signals/#erasure)).
  2. The tenant's slice of the audit trail is read out through audit's reader, if its contract asks for it.
  3. key@ deletes the tenant's `data` and `pseudonym` wraps. This is the **crypto-shred**: every value sealed for the tenant, its directory and connections among them, and every pseudonym made for it, stops opening ([0006](/decisions/0006-keys-and-sealing/#erasing-a-tenant)).
  4. The plain items of the tenant are deleted by their writers. What remains of the tenant is audit facts and its evidence.
  5. The `evidence` wrap is deleted when the evidence retention ends ([0029](/decisions/0029-the-audit-log/#retention)). Evidence never shares a key with personal data and outlives it, so a bill or a dispute can be answered after the exit and the exit still destroys everything personal.
- **Archives are reached by replay and by expiry.** An archive taken before the shred still holds the tenant's wraps until it expires. A restore re-applies the shred from the audit log before it lifts maintenance ([0010](/decisions/0010-backup-and-recovery/#roll-forward)).

### Example installations

These are the generic installations the design is checked against.

- **A three-board installation** is one boundary. Its tenants are L0 scopes, its keys are wrapped for each board's card and for the recovery recipient ([0006](/decisions/0006-keys-and-sealing/#the-recovery-recipient)), and its engine is one rqlite cluster over the boards.
- **An internal installation with kernel, devel, stage and prod boundaries** has four environment boundaries, each at L4: its own cloud account or cluster, keys, store, issuer and audit log. Production never shares a key or a store with development, so a fault, a leaked key or a bad policy change in devel cannot reach prod. The companies that work there are tenants of every boundary, and their people sign in once at the front.
- **A customer installation with one boundary per regulated customer plus one shared customer boundary** has customer boundaries, each at L3: a regulated customer has an engine, a bucket and a queue of its own, and the shared boundary serves the other customers as tenants, each with its own data keys. A customer that outgrows the shared boundary is promoted to its own.

**L3 for a regulated customer is a cost choice, not a requirement.** The public texts below ask for separation, key control, a segregated restore and an exit. An installation could meet them with L1 or L2 boundaries, a separate restore target ([0010](/decisions/0010-backup-and-recovery/#restore)) and the checks of [Tenants](/decisions/0008-boundaries-and-tenants/#tenants). The installation chooses L3 because a regulated customer then has a failure domain, a backup, a restore and an exit of its own, and because the price is low: an on-demand DynamoDB table is billed for the requests it serves and the data it stores, not for idle capacity (AWS pricing page, read 2026-11-03), and a bucket and a queue are billed by use with no minimum charge (AWS DynamoDB, S3 and SQS pricing pages, read 2026-11-03). A runtime of its own (L4) per customer costs far more and no text below asks for it.

These texts bind or guide the regulated customer, not sluis: DORA is law, the EBA guidelines are addressed to the customer, the ECB guide states non-binding expectations and good practice, and ISO/IEC 27017 is a voluntary code of practice. Read on 2026-11-03:

| Text | What it asks | Where the design answers |
|---|---|---|
| ECB, Guide on outsourcing cloud services to cloud service providers, July 2025, section 2.3.1 | As good practice: encryption keys used for the supervised entity's data are unique and not shared with other users of the cloud service | A tenant's own data keys; a customer boundary's own wrapping key |
| The same guide, section 2.1.2 | As good practice, the ex ante risk assessment takes account of the risks of a multi-tenant environment | The ladder: the level is chosen per boundary, with the risk of L0 stated in [Tenants](/decisions/0008-boundaries-and-tenants/#tenants) |
| [DORA, Regulation (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj), Article 12(3), and the same guide, section 2.2.1 | DORA: when restoring backup data on its own systems, use ICT systems physically and logically segregated from the source ICT system. The guide recommends that the risk assessment consider storing backups on such segregated systems | A restore writes into a separate target ([0010](/decisions/0010-backup-and-recovery/#restore)); an L3 boundary has its own engine and bucket |
| DORA, Article 28(8), and the same guide, section 2.4 | For ICT services supporting critical or important functions: an exit strategy and transition plans that remove the services and the data and transfer them securely and integrally to another provider or in-house | A boundary or a tenant can be moved ([Promotion](/decisions/0008-boundaries-and-tenants/#promotion)) or erased ([Tenant lifecycle](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)) as a unit |
| [EBA Guidelines on outsourcing arrangements](https://www.eba.europa.eu/activities/single-rulebook/regulatory-activities/internal-governance/guidelines-third-party-risk-management?version=2019) (EBA/GL/2019/02) | An exit strategy and exit plans for critical or important functions (paragraphs 106 to 108); a risk-based approach to the country or region where data is stored and processed (paragraph 83). Final guidelines of September 2026 will repeal these and leave ICT services to DORA | One installation per residency region ([Scale](/decisions/0008-boundaries-and-tenants/#scale)); the same exit rows as above |
| ISO/IEC 27017:2015, control CLD.9.5.1, 8.35 in the 2026 edition that replaced it ([catalogue entry](https://www.iso.org/standard/43757.html)) | A cloud service customer's virtual environment is protected from other customers and unauthorized persons | The two independent checks and the tenant's data keys |

## Consequences

- A fault, a leaked key or a bad policy change in one environment cannot reach another, because they share no key or store, and people still sign in once, in one place.
- Each boundary picks its level, so cost follows need: a tenant costs items and three data keys, an L1 boundary costs a key@ and a certification, an L3 boundary adds an engine, and an L4 boundary adds a runtime and an installation to upgrade.
- Tenants in one boundary share its fate. The cost of that is accepted at L0 and ends at promotion.
- The front is the one place everyone trusts for sign-in. A compromised front can ask any boundary for a token as a signed-in person, which is why each target re-decides and a sensitive boundary checks the passkey itself. A call between boundaries costs a mutual-TLS hop and a second decision.
- Installation-wide settings cost one write per boundary, and boundaries differ by one version while it lands.
- A tenant that leaves is erased by deleting wraps, not by a data migration, and its evidence outlives it by a declared retention.
- A company that works in several environments is several tenants, each with its own data keys, so a restore or an erasure in one boundary never touches another.
- Promotion needs the old and the new key@ to open and seal the same tenant's values, which is why it is a procedure with a runbook and not a switch.
- Each customer boundary adds a certification item to the yearly cycle of the root custodian, which is why the target is a handful and not a hundred.

## Roads not taken

- **One installation for every environment, with the environment as a tenant.** Development would share keys, store and policy with production, so a mistake there is a production incident.
- **One installation per boundary at every level.** A group would get one sign-in URL, console and identity plane per environment for the same people; the ladder lets a boundary at L1 to L3 live inside its parent's installation.
- **A boundary for every company.** A company has no authority key to protect, so a boundary would cost keys and certification for a division that its data keys and the store's rules already separate.
- **Every tenant a boundary.** Each would carry keys, an issuer host and a yearly certification, and thousands of tenants would be thousands of ceremonies.
- **A key in the key store for each tenant.** It breaks principle 3 and costs a key and a policy per tenant; a per-tenant signing key stays a possible later feature.
- **One data key per tenant.** An exit would shred the evidence together with the personal data, and a bill could no longer be proved.
- **Delay the shred until the evidence retention ends.** Personal data would be kept for years after the exit, against any erasure promise.
- **A scope above the boundary for installation-wide settings.** A second address dimension that every actor reads across the boundary would let one boundary read another's configuration.
- **Environment and customer cells as the only boundary.** About three times the keys and issuing processes, while shared clusters must trust every cell's CA anyway.
- **The front decides, and boundaries trust its assertion.** A compromised front could then act in every boundary.
- **L4 for every regulated customer.** Its own account or cluster is the strongest failure domain, and no public text asks for it; the price of a runtime per customer is the reason it is an option and not the rule.
- **One shared L1 boundary for all regulated customers.** It is the cheapest, and a shared engine would give every regulated customer the same failure domain, backup and restore.
- **One installation across regions.** One set of keys, one store and one issuer spanning jurisdictions, and a failure that crosses them.

## Follow-ups

- The runbook for promoting a tenant to a boundary of its own, and the test that runs it: [#973](https://github.com/truvity/sluis/issues/973).
- Customer boundaries and the customer-identity installation: [#1023](https://github.com/truvity/sluis/issues/1023).
