# 0008 — Boundaries are environments, companies and customer boundaries on an isolation ladder, and a boundary on its own runtime is an installation federated by declared trust

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

sluis holds the keys, the policy, the records and the audit trail of whatever it signs people and machines into. The first question about running it is how much of that may be shared. If development, staging and production, or the people of two companies, sit together, a mistake or a compromise in one reaches the keys and state of the others. v1 answered differently in different places: the sign-in service was deployed once per operating party, and audit once per application (v1 ADR 0053, on `master`).

An **installation** is one concrete deployment: a runtime, its nodes, its dependencies and its drivers ([0011](/decisions/0011-runtimes-and-installations/#installations)). A group of companies that share people, clusters and an operator runs on two cuts at once:

- **The machine plane** (clusters, hosts, workloads, certificates, SSH, workload identity, and the tokens clusters and cloud accounts accept) is cut by **environment** and shared by the companies, because the clusters are shared.
- **The identity plane** (directories, sign-in upstreams, vendor integrations, people records, who may operate what) is cut by **company** and has no environment.

One installation per environment still puts every company's vendor credentials in one place; one per company and environment multiplies keys and processes and still needs one issuer for group-level applications. A boundary has to be able to be less than an installation, and an installation has to be able to trust another.

## Decision

### Boundary kinds

A **boundary** is a unit of isolation.

- **An environment boundary** owns the machine plane of one environment, such as management, development, staging or production: its keys and intermediate certificates ([0024](/decisions/0024-root-custody-and-the-signing-api/)), its SSH CAs, its token issuer ([0017](/decisions/0017-identity-and-sign-in/#issuers)), its sealing key (which seals its grants), its audit log, its SPIFFE trust domain ([0022](/decisions/0022-workload-identity-and-host-enrolment/#trust-domains)) and its state. Production never shares a key or a state store with development.
- **A company boundary** owns a company's identity plane: its directory and sign-in upstream, its integrations, its people records, its operator delegation and its audit tenant's data key, wrapped under the environment's sealing key. It holds **no authority key**.
- **A customer boundary** is a company and an environment together, with its own keys and issuer, created when a company's customers sign in through sluis. It has no consumer yet and comes with the CIAM upstream milestone, as Later ([#1023](https://github.com/truvity/sluis/issues/1023)). It is the first candidate for promotion to an installation of its own. How many an installation carries, and what a tenant is inside one, is [0046](/decisions/0046-tenancy-and-scale-a-boundary-holds-keys-and-a-tenant-is-a-record/).

### The isolation ladder

Each boundary declares a level. A higher level adds to the ones below it.

| Level | Adds |
|---|---|
| L0 tenant | Separation by sluis's code only |
| L1 keys | Its own sealing key (which also seals grants), CA and signing key |
| L2 process | Its own actor instances, with their own uid or role, and its own state prefix |
| L3 store | Its own state store (an rqlite cluster or a DynamoDB table), bucket and queue |
| L4 runtime | Its own Kubernetes cluster, cloud account or hosts, and a separate install file joined by declared trust |

- **A tenant is L0:** a division such as an audit tenant, a quota tenant or a directory tenant, kept apart by code and by the conformance suite of the port that holds it. A tenant is not a substitute for a boundary.
- **Every port is enforced in three layers** ([0003](/decisions/0003-units-transports-and-fusion/#three-layers-per-port)). A driver whose backend cannot check its callers is allowed at L3 and above only.
- **A regulated entity is at least a customer boundary.** A tenant is never enough for it, and sluis does not join accounts across entities. sluis stays a broker: an entity's customers come from its own CIAM product as an upstream, and sluis hosts no end-user accounts ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)).

### Federation between boundaries

- **One front installation, plus one boundary installation for each L4 boundary,** run by one operator and joined by declared trust. People get one sign-in URL, one console and one identity plane.
- **Boundaries below L4 live in the front installation** and are declared in its install file. An L4 boundary has an install file of its own. Companies are L2 boundaries with sealed data, in the front installation.
- **An example layout:** the front and the management boundary share the management account; development, staging and production are each L4, with their own account or cluster, state and keys. A boundary's keys and state table may start in the management account, with per-actor roles and per-boundary keys, and move into the boundary's own account later.
- **Each boundary installation runs its own slim `entry`** ([0041](/decisions/0041-core-actors-with-one-responsibility-each/#the-actors)).
- **Calls between boundaries use mutual TLS with SPIFFE IDs.**
- **The target re-decides.** A boundary that receives a request decides it again with its own policy and never takes another boundary's decision as its own.
- **A sensitive boundary verifies the person's passkey assertion itself,** against its own challenge, so a compromised front cannot act there ([0017](/decisions/0017-identity-and-sign-in/#passkeys)).

### What each boundary owns

- **Keys and intermediates per environment.** Roots are held by [ritueel](https://ritueel.id); each installation asks for its intermediates to be certified through the hand-off ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)).
- **An issuer per environment, and process level at least** for every environment on a cloud runtime.
- **State.** Below L3 one state engine holds a prefix per boundary; from L3 a boundary has its own store.
- **Policy from one source,** compiled into a bundle per environment, with the environment's sealing key sealing its grants. A minter accepts only a grant its own environment's sealing key opens. **Company-ceiling guards** are Cedar `forbid` rules: a subject from one company's directory gets no grant on a scope another company owns unless the grant is declared cross-company ([0007](/decisions/0007-policy-and-sealed-grants/)). A bundle for one environment that contains another environment's policy fails the build.
- **An audit log per environment,** with each company as a reader tenant that has its own data key.
- **Operator delegation per company,** plus an environment scope for machine-plane records, such as enrolling a production host.
- **One integration process per vendor tenant,** owned by its company; each directory tenant has its own upstream. A customer organisation's own provider is the one exception: it runs in a pool of its customer boundary ([0054](/decisions/0054-customer-connections-run-in-a-pool-per-customer-boundary/)).
- **People.** A subject per directory account, plus a declared link between the subjects of one person. Grants are never inherited across the link. An SSH certificate carries the person key.
- **Issuance bound to the requester.** `ca` signs only the names and SPIFFE IDs that the requester's proven identity owns; trust bundles and SSH CAs are per environment, and each company's principals are in that environment's principals bundle.
- **The management boundary hosts the group-level applications** that serve every environment.

### Shared parts and accepted risks

- **Shared by every boundary:** the front with its `entry`, the console, the roots (held by ritueel) and the operator.
- **Accepted risks, which no level removes:** a compromise of the roots; the operator who deploys sluis, and cluster administrators; a compromise of an environment's `ca`, which reaches every company's workloads in that environment, because companies are not cryptographically separate inside an environment; a bug in a shared policy definition or a ceiling guard; data that lives outside sluis.
- **The test installation is separate.** It serves no real user, trusts nothing of the federation and lives outside the sluis host names.

### Promotion

A company leaves, or moves to an installation of its own, by a runbook that exists from day one:

1. Disconnect its company boundary: its upstream, directory, integrations and minters are its own processes and records.
2. Export its slice of the audit trail, then crypto-shred it by deleting its audit tenant's data key.
3. Re-issue its workloads under the new installation's CA.
4. Remove the person links of its subjects.

## Consequences

- A fault, a leaked key or a bad policy change in development cannot reach production, because they share no key or state. People still sign in once, in one place.
- Each boundary picks its level, so the cost follows the need: a company costs processes and prefixes, an L4 boundary pays for its own keys, state, install file and upgrades.
- The front is the one place everyone trusts for sign-in. A compromised front can ask any boundary for a token as a signed-in person, which is why each target re-decides and sensitive boundaries check the passkey themselves. A call between boundaries costs a mutual-TLS hop and a second decision; the front never holds a boundary's keys.
- Company ceilings are enforced in code for the first time: a ceiling guard is checked when the policy loads, and a cross-company grant has to be declared.
- A company leaves by a tested runbook, not an extraction project. The runbook and each isolation layer (with the others switched off) need tests, recorded as the [isolation requirements](/requirements/iso/).
- A workload's SPIFFE ID says which environment it belongs to, and SPIFFE federation is the path for a boundary that moves out.
- The docs use "installation" for the deployment, "boundary" for the unit of isolation and L0 to L4 for the levels; v1's per-application installation is written "v1 installation".
- Threats addressed: T-3, T-5, T-8, T-11, T-16, T-17, T-18, T-19, T-21 and T-26, see the [threat model](/security/threat-model/).

## Roads not taken

- **One installation per boundary.** A group would get one sign-in URL, console and identity plane per environment for the same people, and companies would either multiply everything or sit as tenants with every vendor credential in one process.
- **One installation for every environment, with the environment as a tenant.** Development would share keys, state and policy with production, so a mistake there is a production incident.
- **Environment boundaries only, with companies as tenants.** One integration process would hold every company's credential for a vendor, and nothing in code would stop a grant across companies.
- **Company and environment cells as the only boundary.** About three times the keys and issuing processes, while shared clusters must trust every company's CA anyway and a directory has no environment to be filed under.
- **The front decides, and boundaries trust its assertion.** A compromised front could then act in every boundary.
- **One installation per application, as in v1 audit.** As many installations as applications, each with keys, state and upgrades; an application is a tenant or a client, not a unit of isolation.

## Follow-ups

- CIAM upstream, customer boundaries and installations per regulated entity: [#1023](https://github.com/truvity/sluis/issues/1023), Later.
