# 0051 — The finance export is a statement per boundary, account and period, closed once, anchored in the usage log and pulled by the billing system

**Status:** Superseded by 0039
**Layer:** quota module
**Date:** 2026-11-03

Proposal: [issue #915](https://github.com/truvity/sluis/issues/915).

## Context

[0030](/decisions/0030-audit-records-and-the-usage-stream/#the-usage-stream) makes the finance export a table derived from the usage log, served by `quota`, with FinOps FOCUS column names where they fit; sluis holds no prices, and the table can be rebuilt at any time and is never the record. [0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#the-period-statement-is-the-portable-evidence) decides that the portable evidence of a bill is a period statement, an entry of the usage log under the company's usage key, and leaves the close rule to the finance export. That rule is this record's: what a statement holds, when a period closes, what a late event does, and how billing receives it.

- **A bill is disputed months later.** A rebuilt table changes when a late event arrives, so it cannot settle a dispute. Billing needs a document that was fixed at one moment and that anyone can check against the log.
- **Events arrive late.** A spool that was down, a queue that backed up or a wrong clock all deliver usage after its period ended.
- **A quota installation serves one platform product,** and a billing account belongs to one installation ([0008](/decisions/0008-boundaries-and-tenants/#scale)); a statement therefore never combines installations.

v1 designed, and did not build, a statement written once after a close delay of 72 hours by default, with later events flagged and not billed and corrections as credit notes (v1 "Billing and metering", on `master`). This record keeps that shape and changes the late events: they count in the next open period instead of being lost. FOCUS is a published open standard that billing systems read ([principle 5](/principles/)).

## Decision

### A statement is the unit of hand-off

- **A statement is one canonical JSON document (RFC 8785) per boundary, account and period.** The account is the account of [0039](/decisions/0039-quota-allowance/). The table forms are views of the document, never a second source.
- **It holds, and nothing else:**

  | Part | FOCUS name | Content |
  |---|---|---|
  | Account | `BillingAccountId`, `SubAccountId` | The account, and the company it belongs to |
  | Period | `BillingPeriodStart`, `BillingPeriodEnd`, `ChargePeriodStart`, `ChargePeriodEnd` | UTC instants |
  | Meter lines | `SkuMeter`, `ConsumedQuantity`, `ConsumedUnit` | One line per meter: the quantity by the meter's kind ([0040](/decisions/0040-meters-and-usage-evidence/#the-meter-is-declared)), its unit and its event count |
  | Late lines | `SkuMeter`, `ConsumedQuantity` | The same, for events counted here though their own time is in an earlier period, each line naming that period and why (late, or time out of bounds) |
  | Adjustments | `ChargeCategory` | Each `Adjust` of the period: its event id, amount and the event it refunds; no reason text |
  | Balance movement | | Opening balance, top-ups, consumption, adjustments and closing balance, per balance |
  | Sources | | For each usage log: its origin, the checkpoint (size and root hash) and the first and last entry the statement covers |

  The exact column set is fixed with the export's test vectors, against the FOCUS version the release pins ([REQ-QUOTA-033](/requirements/quota/#REQ-QUOTA-033)).
- **A statement carries no personal data and no free text,** like every usage event ([0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#two-classes-of-data-two-keys)).
- **The format is a stored shape** and changes by expand and contract ([0015](/decisions/0015-evolution-and-compatibility/#n-and-n-1-inside-a-major-version)): a statement already written is never reissued in a new form.

### A period closes once

- **A period is a UTC calendar month and closes after a grace period.** Recommended, and the starting value of the install file's declared `close_after`: 72 hours after the period ends. The grace is the same value that bounds how old an event's own time may be ([0040](/decisions/0040-meters-and-usage-evidence/#the-period-of-an-event)). Both are open product facts, below.
- **At the close instant plus one seal interval,** quota takes, for each usage log of the boundary, the latest checkpoint it has verified ([0029](/decisions/0029-the-audit-log/#sealing)), and sums the entries that checkpoint covers and that belong to the period. Everything recorded before the close instant is sealed by then.
- **A period does not close while an event of it waits in the outbox,** or while a usage log's writer cannot be reached ([0053](/decisions/0039-quota-allowance/#consistency-under-load)). The close waits, and an alarm tells the operator that it waits.
- **The statement is appended once.** Quota sends it as one message, an audit record of the close and a usage event that holds the statement, and keeps a marker for the boundary, account and period in the same atomic batch as the message (the outbox of [0030](/decisions/0030-audit-records-and-the-usage-stream/#usage-is-derived-from-the-same-event-once)). A second run of the close finds the marker and sends the stored message again, which the writer removes as a duplicate. The log is append-only, so nothing edits or deletes a closed statement.
- **A recomputation gives the same bytes.** From the checkpoints and entry ranges a statement names, quota recomputes the statement byte for byte, so a changed statement is detected.

### The usage log is the evidence

- **The statement is an entry of the usage log** under the company's usage key, and its clear envelope carries the SHA-384 digest of the statement ([0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#the-period-statement-is-the-portable-evidence)). Whoever holds a statement recomputes its digest, finds the entry by that digest, and checks the entry's inclusion proof against a checkpoint that the log key signed and the witnesses cosigned, with standard tools and without the usage key.
- **The proof is not part of the statement.** It exists only after the entry is sealed. Quota serves it beside the statement, from the log, like the reader's get with a proof ([0028](/decisions/0028-audit-pieces/#the-reader)).

### Late events and corrections

- **An event whose own period is closed counts in the earliest open period** and is flagged with the period it belongs to; so is an event whose time is out of bounds. The statement of the open period shows both on late lines. Which events belong to which period is [0040](/decisions/0040-meters-and-usage-evidence/#the-period-of-an-event).
- **A correction is an `Adjust` in an open period** ([0030](/decisions/0039-quota-allowance/#the-allowance)). A closed statement is never rewritten and never reopened. A credit for a disputed bill is an adjustment line on the next statement.

### Delivery is a pull

- **Quota serves statements on its contract** (Connect, unary): one call lists the closed periods of an account, and one gets a statement. It reads the statement from the usage log, as one of the two readers of that log ([0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#two-classes-of-data-two-keys)). The reply is the canonical document with its proof, or its table form as NDJSON or CSV with FOCUS names. A period that is still open returns the running totals, marked provisional, and is not a statement.
- **Each call is authorised per account** by `policy`, for the billing system's service identity and for a person with the grant ([0052](/decisions/0039-quota-allowance/#the-push)).
- **A statement is kept as long as the usage log is.** Its retention is the usage retention, which is declared with no default and has to cover the duty of finance ([0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#two-classes-of-data-two-keys)).

### Open product facts: the billing calendar

These are **Proposed**; the recommendation is written so that the record can be accepted when the product confirms it.

- **The calendar is the UTC month.** Recommended. A customer whose contract bills on another calendar sees edge effects at month borders; one more calendar would add a parameter to caps, aggregates and statements.
- **The grace period is 72 hours.** Recommended, as v1 designed.
- **Late events go into the next open period.** Recommended, with the flag above.
- **Confirmation is the open question:** whether any contract of the platform product needs another calendar, or a grace other than 72 hours. It is tracked in [#915](https://github.com/truvity/sluis/issues/915).

## Consequences

- Billing gets a document that does not change, with a digest it can store and a proof it can check; a dispute is settled against the log, not against a table that moves. It survives the exit of the company because it sits under the usage key.
- A late event is billed a period late, and the customer sees it as a flagged line. A usage log whose writer was unreachable for a whole period closes that period late, not wrongly.
- Quota gains a close job and two calls; the close job is a timer, not a person, so a close needs no operator ([principle 7](/principles/)).
- Pull means the billing system sets its own cadence and holds the only credential; quota holds no outbound credential and has no push to fail.
- The adjustment lines show amounts and event ids, so a question about why an adjustment was made is answered from the usage log, which the statement does not copy.
- A statement entry is the largest usage entry of an account with many meters; there is one per account and month, small beside the usage events themselves.

## Roads not taken

- **The derived table as the bill.** Rebuildable and cheap, but it changes with every late event and proves nothing after the fact.
- **A statement kept in quota's state, with a signature of its own.** [0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#roads-not-taken) rejected a key for statements; and a record in state would be a second place that holds the evidence, outside the log's lock and witnesses.
- **Reopening a closed period for late events.** Exact, but a statement that can change cannot be signed or disputed.
- **Dropping late events, as v1 designed.** Simple, but usage that was used is then neither billed nor visible; the flag and the next period cost one line.
- **A billing calendar per account.** Matches contracts, but adds a parameter to caps, aggregates and statements before a contract needs it.
- **Pushing statements to the billing system, or dropping a file in a blob.** Quota would hold a credential for the receiver and own its retries and its failures; the receiver also cannot say "not yet".
- **One statement per meter, or per company.** The bill is per account, and a company with several accounts would get a bundle no invoice matches.

## Follow-ups

- The close job, the statement entry, the calls and their test vectors: [#915](https://github.com/truvity/sluis/issues/915).
- Confirm the billing calendar, the grace period and late events with the platform product: [#915](https://github.com/truvity/sluis/issues/915).
