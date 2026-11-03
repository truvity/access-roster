# 0039 — Quota holds an allowance per tenant that the product pushes, counts it down, refuses at zero and records every fact

**Status:** Proposed
**Layer:** quota module
**Date:** 2026-11-03

Proposal: [issue #915](https://github.com/truvity/sluis/issues/915).

## Context

A product that sells what sluis does for it, such as sign-ins, mints or signatures, needs two things from sluis: a count that stops work at a limit, and evidence of what was used. It does not need sluis to know a price. v1 designed plans, accounts, balances, period statements and a finance export inside sluis. v2 keeps the count and the evidence and nothing else.

Three rules from the model bound the design.

- **Money is the product's.** Plans, prices, invoices and money balances live in the product, and the product is joined to sluis by a written contract ([principle 6](/principles/#6-generic-products-joined-by-a-contract)). A price change touches no sluis configuration and needs no deploy.
- **The count is a tenant's setting, written by the product for its tenant.** A tenant is a scope with its own settings and allowance ([0008](/decisions/0008-boundaries-and-tenants/#tenants)). A product writes through the same Tenant-adjustable path as a tenant admin, inside bounds that config declares ([0004](/decisions/0004-the-data-model/#profiles)).
- **A count is a hot counter.** One allowance is one item that every admit changes, and every store bounds the writes to one item. The shape of the write decides whether the peak of a busy allowance fits, so the shape rests on a dated measurement ([principle 9](/principles/#9-measure-before-deciding-and-date-the-measurement)).

Quota is a module of its own: the actor `quota` on top of the foundation, run beside sluis or in an installation of its own ([0002](/decisions/0002-families-of-actors/#the-foundation-and-the-modules)). It holds no storage, key or audit credential at rest; it reaches data through store@, keys through key@ and audit through the emitter library like every work actor.

## Decision

### The allowance

- **An allowance is a durable kind, `Allowance`, per tenant and quota.** Its one writer is `quota` ([0004](/decisions/0004-the-data-model/#one-writer-per-kind)); its id is the quota's name. It holds the mode, the units left (a signed 64-bit integer that never goes below zero), the version and the hash of the last push applied. It holds no personal data, so its treatment is plain, its profile is Tenant-adjustable, and it is backed up ([0004](/decisions/0004-the-data-model/#treatment)).
- **A quota is declared in config.** The config kind `Quota` names each quota, its unit and the bounds a push must respect: the largest amount of one push and the largest number of units an allowance may hold. A push for an undeclared quota, or outside the bounds, is refused. The profile is Fixed, so a new quota or a wider bound is a reviewed, signed document.
- **There are three modes, and they are built in.** A **prepaid** or **limited** allowance is counted down and refused at zero; an **unlimited** allowance is only recorded and never refused ([0004](/decisions/0004-the-data-model/#built-in)). The mode tells the product what the units mean, and sluis treats prepaid and limited alike.
- **An allowance exists only after the product has set it.** An admit, an `add` or a `write-off` on an allowance that does not exist is refused as not found, so a mistyped tenant or quota creates nothing. The product creates the allowance with its first `set`.
- **Every write carries a grant sealed for the tenant** ([0005](/decisions/0005-the-store/#rules)). A suspended tenant therefore stops being admitted within the lifetime of a reused grant, about 60 seconds ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). When a tenant is erased, quota deletes its allowances with the tenant's other plain items ([0008](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)).
- **Nobody watches an allowance.** The store writes no change-log row for it, so an admit is one conditional update and nothing else ([0005](/decisions/0005-the-store/#watch-and-the-resume-point)). The console reads it.
- **The shape of the record is a stored shape,** and changes by expand and contract ([0015](/decisions/0015-evolution-and-compatibility/#n-and-n-1-inside-a-major-version)).

### The push

A **push** is the one way the product changes an allowance. The call is `Push`, and a second call, `Left`, answers "how much is left" with the mode, the units and the version, without side effects.

- **A push carries a request id, an operation and, optionally, the expected version.** The tenant and the quota are in the address.

  | Operation | Effect |
  |---|---|
  | `add` | Adds the amount. A top-up, a credit and the return of units after a refund are all an `add`; the product decides which it is |
  | `set` | Sets the units to the amount and sets the mode. The first `set` creates the allowance |
  | `write-off` | Removes the amount. It is refused when the units would fall below zero |

- **With an expected version the push applies only if the allowance is at that version.** Otherwise it is refused as a conflict and nothing changes. Without one it applies to the allowance as it is. A product that needs an exact result passes the version it read with `Left`.
- **A push is applied with a conditional update,** so it races with admits safely: whichever write reaches the item second sees the first and either applies on top of it or is refused by its own condition. Neither is lost ([Consistency under load](/decisions/0039-quota-allowance/#consistency-under-load)).
- **A push is idempotent by request id.** The marker is the temp kind `SpentPush`, written by `quota`: its id is a hash of the caller and the request id, and its value is a hash of the request's content. It lives 7 days by default and 30 days at most. A repeat of an applied push with the same content is answered "already applied" with the allowance as it is now, and changes nothing. The same request id with other content is refused as a conflict. After the marker expires a repeat is a new push, so a product that retries for longer than 7 days passes the expected version.
- **The update comes first and the marker second.** The update stores the hash of the request id in the allowance (`last_push`) in the same write. A retry that finds no marker but finds its own hash there writes the missing marker and answers "already applied". A push can apply twice only when a second push to the same allowance lands between a crash and the retry, and the expected version removes that case.
- **A push is authenticated and authorised per tenant and quota.** A product's service calls over mutual TLS with its X.509-SVID, and `entry` verifies it against the trust bundle ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)). No token is exchanged per call: the certificate is short-lived and checking it needs no round trip to the issuer. A person, such as an operator correcting an allowance, comes through the console with an exchanged token and step-up ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#lifetimes), [0017](/decisions/0017-identity-and-sign-in/#step-up)), and the console routes the push to `quota` ([0027](/decisions/0027-the-console/#writes)).
- **`policy` decides every call.** `entry` routes the call to `quota`, which sends `policy` the caller, the action and the tenant with its quota; `policy` answers with a grant sealed for the tenant, which `quota` carries on its writes ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). Declared Cedar policy says which service identity may push to which tenants, and which may admit or read. The actions are distinct, so the service that may push cannot admit, and the service that may admit cannot push. `quota` reuses a grant for the same caller, action, tenant and quota for the time that 0007 allows.
- **A quota-only installation has a small front.** It runs `entry`, `policy`, `quota` and the drivers they need, with a `policy` instance and a declared policy of its own, because a workforce policy and a product's quota policy have different reviewers. It has no `session`, no `console`, no passkey ceremony and no browser bundle: a person uses a console that exists. The sign-in and the browser threats of the audit front ([0028](/decisions/0028-audit-pieces/#the-audit-front)) do not arise.
- **Every push is an audit fact,** with the caller's name, the operation, the amount, the request id and the version before and after ([Countdown and refusal](/decisions/0039-quota-allowance/#countdown-and-refusal)).

### Countdown and refusal

- **An admit takes an amount from the allowance,** one unit by default. It is one conditional update of the allowance: it applies only if the units cover the amount at the moment of the write. An admit that applies answers with the units left; one that does not is refused as exhausted (HTTP 429, Connect `resource_exhausted`) and changes nothing. An unlimited allowance takes nothing and records the admit.
- **An admit is final.** There is no reservation, no confirm and no cancel. Giving units back after a failed piece of work is an `add` by the product, which owns the decision to refund.
- **An admit is idempotent by request id.** The canonical field `request_id` survives every transport, and `entry` copies an `Idempotency-Key` header into it; both with different values is refused. Quota remembers the request as the durable kind `AdmitRecord` for 24 hours, written before the update. A repeat returns the first answer. A crash between the record and the update leaves a record with no outcome, and the retry then applies the update, so an admit is never missed. If the crash fell after the update, that one admit counts twice. The error is toward refusing, never toward admitting more, and the audit fact shows it.
- **Where an admit is asked for.** A product's service asks before it does its own work. Where a policy rule names a quota, the actor that serves the request asks quota before it does the work, as `exchange` does before a mint ([0025](/decisions/0025-integrations/#how-core-authorises-an-effect)), and the rule declares whether an unreachable quota fails open or closed. There is no default, and `sluis config check` refuses a rule that declares neither, so each risk is chosen in review.
- **Every admit, refusal and push is an audit fact.** The call makes one emit through the emitter library: an audit record and a usage part from one call ([0030](/decisions/0030-audit-records-and-the-usage-stream/#usage-is-derived-from-the-same-event-once)). The fact names the caller, the tenant, the quota, the operation or amount, the request id, the outcome and the units and version after. A refusal names its reason: exhausted, not found, conflict, not authorised or unavailable. A fact holds no personal data. The usage part goes to the usage log of the product's project ([The usage stream](/decisions/0030-audit-records-and-the-usage-stream/#the-usage-stream)).
- **Facts are never dropped.** The emitter library spools a message when the transport is down. Quota answers a changing call only after the library has accepted the message, and at the spool's bound it refuses changing calls as `unavailable` and keeps serving `Left`. The bound is declared with `UsageEmitter` and is a pending line below. A bound is needed because the allowance is rolled forward from the facts: a fact that never reached the log is lost if the state is lost.

### Consistency under load

- **Enforcement is strict.** The units admitted never exceed the units the product set and added, whatever the concurrency, because the update's condition is checked at the write. A soft mode is not added.
- **The update is one conditional update, not a transaction.** A conditional update of one hot item reaches the peak with room to spare on every driver, and a transaction per admit does not. Measured on 2026-11-02, one admit taking one unit from one hot allowance, from many concurrent writers; after every run the store was read back and no limit was exceeded and no admitted unit was lost, in more than 100 runs on three drivers:

  | Driver and setup (MEASURED 2026-11-02) | Conditional update, per second | With the idempotency record in the same atomic step | Read, then compare-and-set |
  |---|---|---|---|
  | SQLite file, one committer that batches, 32 to 128 writers | 3,800 to 15,400 | 3,400 to 13,200 | about 220 to 230 |
  | rqlite 10.6.6, one node | about 11,800 at 32 writers, 28,000 at 128 | 2,700 at 32, 10,800 at 128 | 61 to 165 |
  | rqlite, three nodes on one host | 780 at 32, 4,000 at 128 | 1,200 at 32, 2,300 at 128 | 27 to 88 |
  | DynamoDB on demand, from a function in one region, 8 to 128 writers | about 1,000 to 1,080, flat; the rest throttled | 91 to 149 (a transaction) | 101 to 281 |

  The target is the maintainer's estimate of 2026-11-02, not a measurement: 5 to 10 admits a second for one allowance, and a peak of about 100. The setup over- and under-counts. The SQLite and rqlite runs were on one workstation with a real `fsync`, not on the reference installations; the three-node run had no network; the DynamoDB table was new, and its own limit is the per-partition write limit of 1,000 units a second (READ 2026-11-02, AWS developer guide, "Best practices for designing and using partition keys"). Not run: several quota instances on one store, a restart during a run, the real `quota` actor.
- **A throttled or unreachable call is `unavailable`,** never "exhausted". When quota cannot do its job it says so and does not guess ([principle 4](/principles/#4-verify-never-trust-a-claim)), and the calling rule decides whether that fails open or closed. `policy` that cannot decide denies ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)).
- **The issuer being down stops people, not services.** Checking an X.509-SVID needs the cached trust bundle and not the issuer, so `Admit` works for as long as the caller's certificate is valid. A caller whose certificate expires during a long outage is refused, and its rule says whether that fails open or closed. A person's call needs the exchange and stops.
- **A restore rolls the allowance forward from its facts.** Each fact carries the version and the units after, so the merge rule of `Allowance` takes, for each allowance, the fact with the highest version after the archive and sets the units and mode from it ([0010](/decisions/0010-backup-and-recovery/#roll-forward)). `AdmitRecord` is not backed up and is rebuilt from the last 24 hours of facts. There is no reservation to forget, so there is no quiet window after a restore. Units admitted whose facts were still in the spool when the state was lost can be admitted again, and the spool's bound caps them.
- **Enforcement is switched on in production only after a load test on each driver.** It runs `k6` (pinned) against `Admit` and `Push` on the reference installation of the driver, with versions, region, instance sizes and the date written in the result. It runs three workloads (one hot allowance, many allowances with equal traffic, a few with most) with the ramp by concurrency, and it measures the admits a second one allowance sustains, the latency at p50, p99 and p99.9, the conflicts and retries, the errors at saturation, the spool's depth and drain, and the cost of a policy decision with and without grant reuse. A strictness run sets a limit, admits from many clients on several quota instances, restarts one during the run, and checks the admitted total against the limit. The result is posted in the shape of a research result, each claim labelled READ, MEASURED or UNVERIFIED, and repeated when a driver's major version changes.
- **Pending decision lines.** Each is filled when the measurement exists, with its date and versions. This record stays `Proposed` until they are.

  | Line | Recommendation | Decided by |
  |---|---|---|
  | The target per allowance and the latency budget of `Admit` | The estimate above; the budget stays open | The measured p99 on each driver against the peak, then the load test |
  | The write of an admit: a delta applied by the driver, or compare-and-set on the version | Take the shape that meets the target on every driver in use. The harness favours the conditional update, so a driver call that applies a delta is the likely choice | Whether compare-and-set misses the target while a delta meets it ([#1145](https://github.com/truvity/sluis/issues/1145)) |
  | The idempotent admit: the record and the update in one transaction, or the record first | The record first, as above | The measured cost of a transaction on a hot item on each driver |
  | The spool's bound, by count and by age of the oldest message | The depth that the longest outage of the audit transport the installation tolerates would build at its peak rate, capped by the driver's item limits | The measured drain rate and the driver's limits |
  | The number of allowances an installation holds | Thousands of tenants, with several quotas each, the scale of [0008](/decisions/0008-boundaries-and-tenants/#scale) | The measured size and speed of a table with that many items |

### The billing log is outside sluis

- **The product owns plans, prices and money.** sluis holds no price and issues no invoice or period statement. It closes no period, and it runs no finance export. A product that bills sets the allowance when its own period starts and pushes a top-up when its customer pays.
- **What sluis gives is evidence.** Each admit, refusal and push is a usage fact in the usage log of the product's project, sealed and witnessed like any entry, and encrypted under the tenant's evidence key, which is deleted when the evidence retention ends ([Encryption and crypto-shredding](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding), [Retention](/decisions/0029-the-audit-log/#retention)). A person or a system can be granted the usage log without the audit log.
- **The product builds its billing log from those facts,** or from its own metering, outside sluis. A product that keeps its billing log beside its evidence writes it to the `billing/` prefix of its own project's bucket, with a credential of its own scoped to that prefix; no audit piece writes it ([0029](/decisions/0029-the-audit-log/)). sluis neither builds nor reads it.
- **The calendar, the grace for late events and the corrections belong to the product.** sluis records the time of use and the time it recorded the fact, and gives the rule that lets every reader trust the first ([The period of an event](/decisions/0040-meters-and-usage-evidence/#the-period-of-an-event)). A correction is a `write-off` or an `add`, a fact like any other.
- **The evidence outlives the personal data.** The facts hold no personal data, so they remain when a tenant exits and its `data` and `pseudonym` keys are shredded; the tenant's allowances are deleted ([0008](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)).

## Consequences

- A price change, a new plan and a new customer need no sluis deploy. The product sets an allowance when it sells, and the count follows without a reviewed file entry per sale.
- Quota is small: two durable kinds (`Allowance` and `AdmitRecord`), one temp kind (`SpentPush`), the config kinds it reads, and three calls. Nothing in it closes a period, holds a price or writes a statement.
- Every number that rests on a store is dated, and the strict guarantee holds on any driver that passes the load test. The cost is that the record stays `Proposed` while the pending lines are open.
- An admit can count twice after a crash that fell between the update and the write of its outcome, and a push can apply twice in the narrow case above. Both errors are visible in the facts, and the product corrects them with a push.
- A suspension reaches admits within about a minute, because a grant is reused for that long.
- The writer being down stops audit and usage together ([0029](/decisions/0029-the-audit-log/#sealing)). Quota carries on while the spool has room and then refuses changing calls; no sign-in or mint depends on it unless a rule says that quota must answer.
- The product has an ordering to keep: set the allowance, then top it up, then admit. A call out of order fails loudly instead of creating an allowance from a typo.
- A product that wants a customer-facing screen of its allowance waits for a consumer to name it ([principle 8](/principles/#8-nothing-without-a-consumer)).

## Roads not taken

- **Plans, accounts, balances, period statements and a finance export in sluis (v1's design).** Money logic, a billing calendar and a close job inside a security product; a price change would need a deploy; no consumer of the statement is named.
- **Plan templates in config, with an account record per sale.** A reviewed template and a record per customer, and a deploy or a config change on the sales path; the product already knows what its tenant bought and can push it.
- **An allowance in config.** A tenant never appears in config, and a signed document per sale means a review per sale.
- **Reservations with confirm and cancel.** A second, ephemeral state that a restore forgets, which needs a quiet window afterwards; no consumer asks for it, and a refund is an `add`.
- **Limits per UTC day or month, counted in sluis.** A calendar and hourly aggregates in sluis; the product sets the allowance when its period starts.
- **An overage mode at exhaustion.** A second behaviour to specify and prove; the product can push an `add` and retry.
- **Soft enforcement.** A second guarantee to build and prove before a measurement shows a need.
- **A default of failing open, or of failing closed, when quota is unavailable.** A default silently stops enforcing for everyone, or silently refuses everyone.
- **A transaction for every update of a hot item.** It measured 91 to 149 a second on DynamoDB against about 1,000 for a conditional update.
- **Sharding a hot allowance over several items.** It lifts the per-item limit, but the total can then exceed the units unless the shares are leased, which is a soft mode in all but name.
- **A token exchanged for every service call.** One model for people and services, but the issuer and a round trip sit on every admit; caching tokens turns it into the certificate with more steps.
- **Client secrets or API keys for services.** Simple, but sluis holds no machine secret of that kind ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)), and a leaked key is not bound to a workload.
- **An unbounded spool.** Admission would never stop, and the facts in the spool would be the only copy of them.
- **Blocking each admit until its fact is sealed in the log.** No window at all, but the writer's seal interval would sit on every admitted request.
- **Deciding the numbers from the design alone.** A store's limit is a property of the store and its configuration, and a published limit does not tell what this workload does on it.

## Follow-ups

- The quota actor, its contract and test vectors: [#915](https://github.com/truvity/sluis/issues/915).
- The load test per driver, its report and the pending lines above: [#1144](https://github.com/truvity/sluis/issues/1144).
- A driver call that applies a delta, only if the load test shows that compare-and-set misses the target: [#1145](https://github.com/truvity/sluis/issues/1145).
- The front of a quota installation and who calls `Admit` (the product's own services now; its customers' applications later, with the audit front's threats and an edge connector added): [#1026](https://github.com/truvity/sluis/issues/1026).
