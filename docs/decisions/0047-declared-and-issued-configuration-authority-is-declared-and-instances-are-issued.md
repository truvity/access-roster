# 0047 — Declared and issued configuration: authority is declared and delivered through a configuration service, and instances are issued at run time under declared templates

**Status:** Superseded by 0004
**Date:** 2026-11-03

Proposal: [issue #977](https://github.com/truvity/sluis/issues/977).

## Context

[0004](/decisions/0004-the-data-model/#origins) says that authority is declared: written in a reviewed file in git and delivered read-only, with one exception, template-linked Cedar policies within a declared delegation policy ([0007](/decisions/0007-policy-and-sealed-grants/#template-links)). That fits a workforce installation, where a few operators change who may do what.

Three milestones meet the same limit from different sides:

- A **customer-identity installation** has thousands of tenants. Each needs its own upstream connection, clients and domains, and each changes them on its own schedule. A pull request per change is not self-service, and a reviewed file with thousands of entries is not a configuration.
- **Quota** has a balance account for each customer of a product, created when the customer arrives.
- The **console** of the parity milestone lets operators issue what a policy then uses.

So the question is how run-time self-service fits "authority is declared". Principle 7 asks for a person only where a person adds safety; principle 8 asks that nothing arrives before its first consumer. Live reload of whole configuration snapshots is already decided in 0010 and tracked in [#977](https://github.com/truvity/sluis/issues/977).

## Decision

### Three kinds of configuration

| Kind | What it is | Written by | Where it lives |
|---|---|---|---|
| **Authority** | Who may do what: policy, the delegation policy, templates, plans, the vocabulary of grants, exchange trust, the installation's own clients and upstreams | An operator, through review | Declared |
| **Defaults** | Values for the slots of a declared template, kept per customer (customer-identity installations only) | An operator, in project configuration | The configuration service |
| **Instances** | Tenants, accounts, upstream connections and clients that belong to a tenant | A declared client or an operator, at run time | `state`, as issued records |

An upstream or a client that the operator runs for its own relying parties is authority and stays declared. An upstream connection or a client that a tenant registers for itself is an instance.

### Workforce installations

- **Authority is declared in git, reviewed, and delivered at run time through a configuration service:** AWS AppConfig on serverless, or the equivalent for the runtime, which is a ConfigMap on Kubernetes and a file on bare-metal ([0004](/decisions/0004-the-data-model/#origins)).
- **Live reload applies it** as whole versioned snapshots: validated, swapped atomically and audited with the snapshot's digest, a failing snapshot refused while the version in force stays ([#977](https://github.com/truvity/sluis/issues/977), REQ-OPS-021).
- **The service holds the published copy of a reviewed commit.** The pipeline that publishes it is the operator's. sluis records the digest it applied, so a reviewer can match it to the commit. How a service is read, composed with the other sources and trusted is [0057](/decisions/0057-configuration-sources-are-a-port-sources-own-disjoint-paths-authority-is-signed-and-a-failing-source-keeps-the-version-in-force/).

### Customer-identity installations

- **The installation's own authority is declared as in a workforce installation:** its policy, delegation policy, templates and vocabulary are in git.
- **Only per-customer defaults live in project configuration, delivered through the configuration service and not kept in git.** A default fills a slot of a declared template and cannot exceed the bound the template sets for it, so it carries no authority. It is delivered, validated and reloaded as declared configuration is, and a snapshot with a default outside its bound is refused (REQ-OPS-028).
- **Per-tenant changes, and the organisation of users into organisations, belong to a dedicated customer-identity module.** An organisation is a group of users. The module is a product concern outside the core of sluis: sluis hosts no user and no organisation ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)). The module is a declared client of sluis, and sluis exposes the issued-record and template-link mechanism below for it to plug into.

### Instances are issued under declared templates

The pattern is the template link of 0009, generalised from policy to records.

1. **A kind of instance is marked issuable in the schema and the manifest,** with one owning actor, the only writer of the kind ([0005](/decisions/0005-the-store/#one-writer-per-kind)). Its origin is issued, durable ([0004](/decisions/0004-the-data-model/#origins)).
2. **A declared template says what an instance may be:** the slots, and the bounds on each. A declared delegation policy says which caller may issue which template with which slot values.
3. **`policy` decides the issue** as it decides a link, from the caller, the template and the slot values ([Policy](/reference/policy/#template-links)). The owning actor then validates the slots against the template and writes the record by compare-and-set. An instance is refused when no template covers it, no delegation permits the caller, or a slot is outside its bound (REQ-OPS-025, REQ-OPS-027).
4. **An instance holds no authority the template did not already carry:** no new grant name, no claim and no logic. What it names is a value in a slot.
5. **The audit record names the caller, the template, the slot values apart from secrets, and the delegation that permitted it** (REQ-OPS-026), as the record of any issued kind does.
6. **Tighten-only changes take effect at once.** Suspending an instance, revoking it or lowering a limit needs no delegation to widen anything.
7. **A secret of an instance is a sealed secret** ([0005](/decisions/0005-the-store/#sealed-secrets)), never a key in a key store ([0046](/decisions/0046-tenancy-and-scale-a-boundary-holds-keys-and-a-tenant-is-a-record/#keys-and-isolation)).
8. **Instances are backed up and rolled forward from the audit log,** as every issued durable kind is ([0004](/decisions/0004-the-data-model/#backup-and-restore-by-origin)).

A kind of instance arrives with its first real caller, in its own milestone: tenant connections and clients with the customer-identity module ([#1023](https://github.com/truvity/sluis/issues/1023)), balance accounts with quota ([#915](https://github.com/truvity/sluis/issues/915)).

### The amendment to 0010

0010 says authority is declared only, with one exception. It now says that authority is declared, and that two things are issued under it: template links and instances. Declared configuration is written in a reviewed file, or, for per-customer defaults, in project configuration of the configuration service; either way it is delivered read-only.

## Consequences

- A customer is onboarded, changed and removed with no pull request, no deployment and no operator, and every change is an audited record bounded by a template a reviewer has read.
- The reviewed surface stays small: templates and delegation policies, not one entry per tenant. The cost is a template and a delegation rule for each kind of thing a tenant may create.
- A stolen credential of the customer-identity module can create instances inside the templates and bounds it is delegated, and no more. It cannot widen a grant, because no template lets a slot do that.
- Per-customer defaults have no review in git. The configuration service's own change history and approval are their control, and the bound in the template limits what a wrong default can do.
- Every runtime needs a configuration source with versions, which 0010 already lists. Live reload is needed by every installation that changes policy or clients without a deploy, the workforce installation first, so #977 belongs to the v1 parity milestone and gates the customer-identity installation as well ([reload classes](/decisions/0004-the-data-model/#reload-classes)).
- Requirements: [REQ-OPS-025](/requirements/ops/#REQ-OPS-025) to [REQ-OPS-029](/requirements/ops/#REQ-OPS-029).

## Roads not taken

- **Every change a commit to git, made by a pipeline.** A commit, a review and a deployment for each customer change, and a file that grows with every customer.
- **Authority written at run time through a policy API.** A stolen operator session could widen any grant; 0009 and 0010 rejected it.
- **Per-customer defaults in git.** The same file and the same churn, with no review that adds safety to a value that cannot exceed its bound.
- **Accounts created on first use from a rule default.** A typo or a hostile caller would create records; it is the weakest control on a record that stands for money.
- **Signed declared fragments per tenant.** Each tenant would need a publisher scope and a fragment format, and a reload for every change.
- **Users and organisations inside sluis.** It would make sluis a CIAM product, against [REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017) and principle 6.
- **Treat a tenant's connection as an operator-set record.** An operator-set record is a person's lasting choice made on the console; a connection issued by a client under a template is an act with a caller and a delegation, which is what an issued record is.

## Follow-ups

- Live reload of declared configuration, on every runtime: [#977](https://github.com/truvity/sluis/issues/977).
- The first kinds of instance, with the customer-identity module's contract: [#1023](https://github.com/truvity/sluis/issues/1023).
- Balance accounts issued under plan templates: [#915](https://github.com/truvity/sluis/issues/915).
