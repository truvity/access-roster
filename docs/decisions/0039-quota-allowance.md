# 0039 — Plan templates are declared, and an account is an issued record that a declared client creates at run time

**Status:** Accepted
**Layer:** quota module
**Date:** 2026-11-02

Proposal: [issue #915](https://github.com/truvity/sluis/issues/915).

## Context

A balance belongs to an account, and an account is keyed by boundary, company, account and meter, with no personal data in the key ([0030](/decisions/0030-audit-records-and-the-usage-stream/#quota), [REQ-QUOTA-025](/requirements/quota/#REQ-QUOTA-025)). Limits are declared and an operator may only lower them ([0004](/decisions/0004-the-data-model/#quota-by-origin)).

A quota installation serves one platform product with thousands of customers, and its accounts are records, not boundaries ([0046](/decisions/0046-tenancy-and-scale-a-boundary-holds-keys-and-a-tenant-is-a-record/#the-scale-to-design-for)). An account appears with each sale. One reviewed file entry per account would mean a deploy per sale, a file that grows with the customer count and a live reload ([#977](https://github.com/truvity/sluis/issues/977)) on the sales path.

[0047](/decisions/0047-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/#instances-are-issued-under-declared-templates) settles the general case: authority is declared, and instances are issued at run time by a declared caller under a declared template and a delegation policy, with `policy` deciding the issue, the owning actor writing the record and an audit record naming caller, template and slots. It names balance accounts as the first kind of instance for the quota milestone. This record fixes what the template, the instance and the calls are for quota. Billing decides what a customer has bought and pushes top-ups; sluis holds no prices ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-usage-stream)).

## Decision

### Plans are declared

- **A plan template is declared configuration** in the install file: a name, and for each meter its unit and its limits, a rate or a cap per UTC day or month ([REQ-QUOTA-028](/requirements/quota/#REQ-QUOTA-028)). It holds no price and no customer. It is the template of [0047](/decisions/0047-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/#instances-are-issued-under-declared-templates); its slots are the account id and the company.
- **What an enforcing rule does on exhaustion, and when quota is unreachable, stays a declared rule** ([0030](/decisions/0030-audit-records-and-the-usage-stream/#quota)). A plan sets how much; a rule sets what happens at the end of it.
- **Quota reloads the templates as a whole snapshot** (0031). A snapshot that removes a plan an account still uses is refused, and the snapshot in force stays.

### Accounts are issued

- **An account is an issued record, written only by `quota`.** It holds the account id, the company, the plan, and whether it is open or closed. Its id is chosen by the caller, normally the billing system's own, and carries no personal data. Its key is the boundary, the company and the account id.
- **A declared client creates it with `CreateAccount`,** naming the id, the company and the plan. The delegation policy says, per plan, which client may issue accounts of that plan, as the Cedar action `quota.account.create` ([0007](/decisions/0007-policy-and-sealed-grants/#template-links)); it is the same pattern as `TopUp` ([REQ-QUOTA-021](/requirements/quota/#REQ-QUOTA-021)).
- **Creation is idempotent by the account id.** The same id with the same company and plan returns the account that exists. The same id with another plan or company is refused as a conflict. The call also carries a `request_id` like every changing call ([0030](/decisions/0030-audit-records-and-the-usage-stream/#quota)).
- **Nothing else creates an account.** `Admit`, `Confirm`, `Cancel`, `TopUp`, `Adjust` and `Balance` on an account that does not exist are refused as not found. The billing system creates the account at the sale, before the first top-up.
- **`ChangePlan` and `CloseAccount` are the other changes,** by a declared client under the same delegation. A plan change swaps the limits; what the account has already used in the period counts against the new plan. A closed account refuses `Admit` and keeps its balance, meters and record until its last statement is closed ([0051](/decisions/0051-the-finance-export-is-a-statement-per-account-and-period-closed-once-anchored-in-the-usage-log-and-pulled/#a-period-closes-once)).
- **An operator may lower an account's limit, never raise it.** The lowered limit is a tighten-only operator-set record ([REQ-QUOTA-013](/requirements/quota/#REQ-QUOTA-013)); a limit of zero suspends the account. Raising a limit is a plan change by a declared client.
- **Every change is one message from quota,** an audit record of the change and a usage event of amount zero that names the account, the company and the plan. The audit record shows who did it. The usage event is what rolls the account forward after a restore ([0030](/decisions/0030-audit-records-and-the-usage-stream/#quota)), as it does the balance.
- **The account record is a stored shape** and changes by expand and contract ([0015](/decisions/0015-evolution-and-compatibility/#n-and-n-1-inside-a-major-version)).

## Consequences

- The number of accounts follows the sales without a deploy. What bounds it is the capacity of the state driver, measured in the load test ([0053](/decisions/0053-quota-consistency-and-failure-are-measured-per-state-driver-before-enforcement-is-switched-on/#the-load-test)).
- Quota gains an issued record kind, one more writer path to guard, and a place in the backup and the roll-forward. The guard is the same: one writer per kind, compare-and-set, an audit record and a usage event.
- The billing system has an ordering to keep: create the account, then top it up, then admit. A call out of order fails loudly instead of creating an account from a typo.
- A template change is a reviewed change in git, and reaches every account of the plan at the next reload.
- An account record has no personal data, so it is kept when its company leaves and its audit key is shredded ([0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#two-classes-of-data-two-keys)).
- The company is an attribute of the account and adds no key ([principle 3](/principles/)).

## Roads not taken

- **Accounts declared in the install file, generated by a billing pipeline.** Fully reviewed and no new record kind, but a deploy per customer and a live reload on the sales path.
- **Creating an account on its first `TopUp`.** One call fewer, but the plan would travel in the call that moves money, and a top-up with a mistyped id would open an account. Creating one on first use is the road 0031 already refused.
- **The caller passes the limit with each `Admit`.** Quota stays stateless about plans, but the caller then sets its own limit and strictness cannot be proved.

## Follow-ups

- The account record, its calls and their test vectors, in the quota engine: [#915](https://github.com/truvity/sluis/issues/915).
- Live reload of declared configuration: [#977](https://github.com/truvity/sluis/issues/977).
