# 0053 — Quota consistency and failure are measured per state driver before enforcement is switched on

**Status:** Superseded by 0039
**Layer:** quota module
**Date:** 2026-11-03

Proposal: [issue #915](https://github.com/truvity/sluis/issues/915).

## Context

Quota is strict in 2.0: the admitted total never exceeds a limit under concurrent requests, by compare-and-set on the state port ([0030](/decisions/0030-audit-records-and-the-usage-stream/#quota), [REQ-QUOTA-002](/requirements/quota/#REQ-QUOTA-002)). Enforcement is switched on in production only after a load test of the mint path with enforcement on ([REQ-QUOTA-008](/requirements/quota/#REQ-QUOTA-008)), and a soft mode is decided after that test ([REQ-QUOTA-009](/requirements/quota/#REQ-QUOTA-009)). A design choice that depends on a number rests on a dated measurement ([principle 9](/principles/)). Today there is none, and the questions below depend on it:

- **How fast can one balance be admitted against?** One hot balance is one record, and every store bounds the writes to one record: DynamoDB by its per-partition write limit, rqlite by a consensus round for each commit, SQLite by one writer and a sync. The limit is a number nobody has measured for this workload.
- **What does a compare-and-set cost under contention?** Retries multiply the writes. A conditional adjust, which changes a number by a delta and refuses to cross a floor in one store operation ([Data](/concepts/data/#further-operations)), may cost less. It is added only if the measurement shows the need.
- **What happens after a restore?** Reservations are ephemeral and are not backed up ([0030](/decisions/0030-audit-records-and-the-usage-stream/#quota)). A balance restored from backup and rolled forward from the usage log has forgotten what was reserved when the failure came, so for as long as a reservation lives, more can be admitted than the limit allows.
- **What if the writer is down?** Quota keeps its effects in an outbox until the writer takes them ([0030](/decisions/0030-audit-records-and-the-usage-stream/#usage-is-derived-from-the-same-event-once)). How long and how many it may hold while it keeps admitting is open.
- **What if the issuer, the state store or `policy` is down?**

The records and requirements that can be written now are below. Each number that cannot is a decision line that stays pending until the measurement exists.

## Decision

### Settled now

These follow from the principles and the records above, and need no number.

- **Strict is the only enforcement mode until a measurement says otherwise** ([REQ-QUOTA-027](/requirements/quota/#REQ-QUOTA-027)), and no state driver enforces in production before its own load test ([REQ-QUOTA-008](/requirements/quota/#REQ-QUOTA-008)).
- **When quota cannot do its job, it says so and does not guess** ([principle 4](/principles/)). It answers `unavailable`, and the calling rule decides whether that fails open or closed ([REQ-QUOTA-011](/requirements/quota/#REQ-QUOTA-011)). A state store that cannot be reached, a `policy` that cannot be reached and a full outbox all answer that way.
- **`policy` that cannot decide denies** ([0007](/decisions/0007-policy-and-sealed-grants/#decision)).
- **The issuer being down does not stop service calls** ([0052](/decisions/0052-a-quota-installation-is-fronted-by-service-identity-for-services-and-exchanged-tokens-for-people/#when-the-issuer-is-down)).
- **A restore ends with a quiet window.** After a restore and the roll-forward, quota refuses `Admit` on an enforcing balance, as `unavailable`, until the longest reservation time to live in force has passed since the restore. Within the window a `Confirm` for a reservation quota does not know is handled as an `Admit` and a `Confirm` in one step under the strict check, and the rule's exhaustion behaviour applies. The window makes the strict guarantee hold again at the cost of a few minutes ([REQ-QUOTA-014](/requirements/quota/#REQ-QUOTA-014): five by default). A request id is rebuilt from the usage log as before ([REQ-QUOTA-030](/requirements/quota/#REQ-QUOTA-030)).
- **A period does not close while its events wait in the outbox** ([0051](/decisions/0051-the-finance-export-is-a-statement-per-account-and-period-closed-once-anchored-in-the-usage-log-and-pulled/#a-period-closes-once)).

### The writer is down

- **Quota keeps admitting while the writer is down, up to a bound.** An effect is committed to quota's state and its outbox in one atomic batch ([REQ-QUOTA-035](/requirements/quota/#REQ-QUOTA-035)); `Confirm` returns when that batch is committed. It promises that the effect is in quota's state and will reach the log. It does not promise that the usage entry is in the log.
- **The outbox has a bound, by count and by age of its oldest message,** declared in the install file, with a warning level below it. At the bound quota refuses changing calls as `unavailable` and keeps serving reads. A bound is needed because the state is backed up and rolled forward from the log: effects that never reached the log are lost if the state is lost.
- **Both bound values are pending** (see the table below).

### The load test

- **The test runs for each state driver in production use,** as `k6` (pinned) against the mint path and against `Admit`, `Confirm` and `Cancel` directly, with enforcement on and off, on the reference installation of the driver, with versions, region, instance sizes and the date written in the result.

  | Driver | Reference installation | What it is |
  |---|---|---|
  | `dynamodb` | A quota installation on Kubernetes ([0011](/decisions/0011-runtimes-and-installations/#kubernetes)) | The hot item is bounded by the per-partition write limit of DynamoDB (1,000 write units a second per partition, READ on 2026-11-02 in AWS's developer guide, "Best practices for designing and using partition keys"; re-read it on the day of the test) |
  | `rqlite` | A three-node cluster on the boards ([Bare metal](/runtimes/bare-metal/)) | A consensus round per commit; about 430 commits a second measured for the cluster on 2026-10-31 for all writes ([0005](/decisions/0005-the-store/#consequences)) |
  | `embedded` | The local installation | One writer and a sync per commit |

- **Three workloads:** one hot balance; many balances taking equal traffic; a few balances taking most of it. The ramp is by concurrency, and each step holds long enough to reach a steady rate.
- **What it measures, per driver and workload:**
  - the admits a second one balance sustains, with the p50, p99 and p99.9 latency of `Admit` and of `Admit` plus `Confirm`;
  - the compare-and-set conflicts and retries a second, and the write rate they cause;
  - the errors at saturation, and how the driver degrades;
  - the outbox depth and the relay's lag behind the writer, and how long a backlog takes to drain once the writer returns;
  - the lag of the meters behind the log;
  - the cost of a policy decision, with and without the 60-second grant reuse of 0043;
  - the same `Admit` with the reservation written durably and not ephemerally.
- **A strictness run on every driver:** a limit is set, many clients admit against it at the same time on several quota instances, an instance is restarted during the run, and the admitted total is checked against the limit ([REQ-QUOTA-002](/requirements/quota/#REQ-QUOTA-002)).
- **The result is posted in the shape of a research result** ([Decisions, requirements and research](/contributing/decisions/#the-shape-of-a-result)), with each claim labelled READ, MEASURED or UNVERIFIED and what the setup over- and under-counts. It is dated, and it is repeated when a driver's major version changes.

### What the first measurement shows

A harness measured the balance step alone on 2026-11-02, before the load test above, to see the order of magnitude. One operation, `Admit(account, request id, 1)`, took one unit from a balance with a cap, from many concurrent writers on one hot account; after every run the store was read back and no cap was over and no admitted unit was lost, in more than 100 runs on the three drivers (MEASURED). The target is the maintainer's estimate of 2026-11-02, in the table below: a typical 5 to 10 admits a second for one balance, and a peak of about 100. Three shapes were run on each driver: a **conditional update** (take the unit only if the balance covers it, in one store operation); the same with an **idempotency record written in the same atomic step**; and **read, then compare-and-set** on the version, retried on conflict.

| Driver and setup (MEASURED 2026-11-02) | Conditional update | With the idempotency record | Read, then compare-and-set |
|---|---|---|---|
| SQLite file, one committer that batches (group commit, up to 256 admits per `fsync`), `synchronous=FULL`, 32 to 128 writers | 3,800 to 15,400 a second | **3,400 to 13,200 a second**, p99 16 to 19 ms | about 220 to 230 a second on a single connection |
| rqlite 10.6.6, one node, 32 to 128 writers | **about 11,800 a second** at 32 writers, p99 5.7 ms; 28,000 at 128 | 2,700 at 32, 10,800 at 128 | 61 to 165 a second; callers give up after 100 retries from 32 writers |
| rqlite, three nodes on one host | 780 at 32, 4,000 at 128 | 1,200 at 32, 2,300 at 128, p99 114 to 335 ms | 27 to 88 a second |
| DynamoDB, on-demand table, from a function in one region, 8 to 128 writers | **about 1,000 to 1,080 a second**, flat at every writer count; the rest of the calls are throttled | **91 to 149 a second** (a transaction; 76 uncontended), conflicts on 8 to 36 % of the calls | 101 to 281 a second (236 uncontended), p99 up to 1.3 s |

What it says:

- **A conditional update clears the peak of about 100 a second on every driver, with wide headroom.** It gives 3,800 a second or more on SQLite with group commit, 11,800 or more on one rqlite node, 780 or more on three rqlite nodes on one host, and about 1,000 to 1,080 on DynamoDB, about ten times the peak. Every shape on every driver clears the typical 5 to 10 a second; the lowest figure is 27.
- **Read-then-compare-and-set is near or below the peak.** It gives 101 to 281 a second on DynamoDB, about 220 to 230 on SQLite with a single connection, and 27 to 165 on rqlite, so from about a quarter of the peak to about three times it. Its conflicts grow with the writers, and on DynamoDB the p99 reaches 1.3 s.
- **SQLite needs one committer that batches.** A pool of connections gives 600 to 780 a second with a starvation tail (p99.9 of 8 to 10 s from 8 writers), and a single connection about 250.
- **DynamoDB is capped at about 1,000 a second per item,** which is the per-partition limit of 1,000 write units (READ above) and ten times the estimated peak. A throttled call is neither an admit nor a refusal: `quota` answers `unavailable` for it, never "over the limit". The cap is far from the estimated load, and it is the limit to watch if the real peak turns out to be higher.
- **A DynamoDB transaction per admit is the trap.** It gives 91 to 149 a second (76 uncontended), which is around the peak of 100 with no headroom, and 7 to 11 times below the plain conditional update, so the idempotent form cannot be a transaction on a hot balance. An idempotency scheme without a transaction was not measured.
- **The pending line on a conditional adjust:** against about 100 a second, compare-and-set is marginal or below on some drivers (DynamoDB, rqlite) and the conditional update is clearly above on all of them in this harness. That is the condition the line names, seen in a harness and not on the reference installations. The line stays pending and the record stays `Proposed`; the maintainer decides it after the load test of this record has run on the reference installations.
- **Soft mode in 2.0 keeps its recommendation, strict only.** Its condition, a driver that misses the peak on a hot balance, is not met by the conditional update on any driver in this harness. The shapes near the peak are compare-and-set and the DynamoDB transaction, and the load test of the real `quota` actor decides whether any of them is the one in use.
- The setup over- and under-counts. SQLite and rqlite ran on one workstation (x86_64, 32 threads, NVMe under ext4, real `fsync`), not on the reference installations of the table above; the three-node rqlite ran on one host and one disk, with no network. DynamoDB ran from a function with 3.5 GB of memory, SDK retries off, on a table created minutes before, so the many-balances figures there (1,100 to 2,000 a second) are a new table's. Not run: several quota instances on one store, a restart during a run, the real `quota` actor, a sustained run, and the load test of this record.

### Pending decision lines

Each line is filled when the measurement exists, with its date and versions, and then the record can be accepted. The recommendation is the one to take if the measurement does not point elsewhere.

| Decision line | Recommendation | Decided by |
|---|---|---|
| The target: the admits a second per balance, and the latency budget of `Admit` | The maintainer's estimate on 2026-11-02, not a measurement: typical load is 5 to 10 admits a second for one balance, and the peak is at most about 100 a second. The load test checks the peak. The latency budget stays open | The measured p99 of `Admit` on each driver, against the peak above, then the test |
| Soft mode in 2.0 | No: strict only | Whether any driver misses the peak above on a hot balance |
| A conditional adjust on the state port | Not added | Whether compare-and-set misses the target while a conditional adjust meets it, on one driver or more |
| The outbox bound, by count and by age, and the warning level | The depth that the longest writer outage the installation tolerates would build at its peak rate, with the state's capacity as a ceiling | The measured relay and drain rates, and the state driver's item and table limits |
| The quiet window after a restore, or durable reservations instead | The window, as above | The measured cost of a durable reservation on each driver: if it is small, drop the window |
| The ceiling on a reused grant, 60 seconds in 0043 | Keep 60 seconds | The measured cost of a policy decision per call |
| The account capacity of an installation | Thousands of accounts, the scale of [0046](/decisions/0046-tenancy-and-scale-a-boundary-holds-keys-and-a-tenant-is-a-record/#the-scale-to-design-for), with headroom | The measured size and speed of a table with that many accounts |

## Consequences

- No enforcement is switched on in production on a guess, and the numbers that decide it are public, dated and repeatable.
- The restore has a visible cost: a few minutes in which enforcing rules fall back to their declared unavailable behaviour. An operator sees it announced, not found.
- An outbox bound can stop admission when the writer is down for long. It is the price of never losing an effect that is in the state and not in the log.
- The writer being down stops audit and usage together ([0029](/decisions/0029-the-audit-log/#sealing)). Quota carries on for as long as its bound lasts, and no sign-in or mint depends on it.
- The pending lines keep this record `Proposed`; the settled lines are requirements now.

## Roads not taken

- **A target of 1,000 admits a second for one balance.** Considered and dropped on 2026-11-02: it was ten times the estimated peak, and the maintainer's real peak is about 100 a second.
- **Soft enforcement in 2.0.** A second guarantee to build and prove before a measurement shows a need.
- **Persisting reservations from the start.** It removes the window after a restore, but writes a second record on every `Admit`, the hot path; the test measures it so the window can be dropped if it is cheap.
- **A default of failing open, or of failing closed, when quota is unavailable.** A default silently stops enforcing for everyone, or silently refuses everyone ([0030](/decisions/0030-audit-records-and-the-usage-stream/#quota)).
- **An unbounded outbox.** Admission would never stop, and the effects in the outbox would be the only copy of them.
- **Blocking each `Admit` until its usage entry is in the log.** No window at all, but the writer's seal interval of up to 5 seconds would sit on every admitted request.
- **Deciding the numbers from the design alone.** A store's limit is a property of the store and its configuration, and a published limit does not tell what this workload does on it.
- **Sharding a hot balance across several records.** It lifts a per-record limit, but the total can then exceed the limit unless the shares are leased, which is a soft mode in all but name.

## Follow-ups

- The load test per driver, its report and the pending lines: [#1144](https://github.com/truvity/sluis/issues/1144).
- A conditional adjust on the state port, only if the load test shows contention that compare-and-set cannot meet: [#1145](https://github.com/truvity/sluis/issues/1145).
- A measured peak per balance, to check or replace the maintainer's estimate of the target (2026-11-02): [#1144](https://github.com/truvity/sluis/issues/1144).
