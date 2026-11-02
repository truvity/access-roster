# 0044 — A meter has a name, a unit and a kind that never change, only declared outcomes bill, and a usage event belongs to the period of its event time within a stated skew

**Status:** Accepted
**Layer:** quota module
**Date:** 2026-11-02

Proposal: [issue #841](https://github.com/truvity/sluis/issues/841).

## Context

[0017](/decisions/0017-audit-records-the-usage-stream-and-quota/#usage-is-derived-from-the-same-event-once) says that the action table declares the meters an action may carry, with units, and that the writer refuses an undeclared one. It does not say what a meter is, which outcomes of an action bill, what happens to a meter over releases, or which period an event belongs to. Three readers need those answers to agree:

- **Quota's caps** count per UTC day or month ([REQ-QUOTA-028](/requirements/quota/#REQ-QUOTA-028)).
- **The statement** sums a period ([0041](/decisions/0041-the-finance-export-is-a-statement-per-account-and-period-closed-once-anchored-in-the-usage-log-and-pulled/)).
- **The roll-forward** after a restore replays balance effects in an order that matters, because a floor and a refund that may happen once depend on it.

This is a record of its own and not a section of 0017, because the period rule serves caps and statements as much as the usage stream, and 0017 links here from the usage stream.

v1 counted a metered action's success only, billed a gauge as the average of hourly samples, and treated a renamed meter as a new one (v1 "Billing and metering", on `master`). v2 keeps those three.

## Decision

### The meter is declared

- **A meter is declared in the action table entry of the emitting product's code:** a name, a unit and a kind. The name is the CloudEvents `type` of its events. The unit is a lower-case word such as `requests` or `bytes`. Amounts are signed 64-bit integers ([REQ-QUOTA-020](/requirements/quota/#REQ-QUOTA-020)).
- **The kind is `count` or `gauge`.** A count is an event: its amounts add up over a period. A gauge is an absolute sample, such as stored bytes, never a change. It is emitted by a periodic action that is audited as an action of its own ([0017](/decisions/0017-audit-records-the-usage-stream-and-quota/#usage-is-derived-from-the-same-event-once)), and the meter declares how a period's samples combine: `avg`, `max` or `last`. sluis picks none of them; the product chooses.

### Only declared outcomes bill

- **A meter declares the outcomes it bills,** and the default is `success`. A refusal by policy or by quota never bills. An action priced by attempt lists the failure it bills.
- **The emitter library adds the usage part only for a listed outcome.** The audit part is always written, so a failed call is visible and not billed.

### A meter never changes

- **A meter's name, unit and kind are fixed from its first release.** Renaming it, or changing its unit or kind, is a new meter. The old meter stays in the table, marked retired: a retired meter can still be read from old events, and no release emits it.
- **CI compares the action table with the previous release's** and fails when a meter was renamed, retyped or dropped without being retired, as it does for OCSF ([0017](/decisions/0017-audit-records-the-usage-stream-and-quota/#the-record-format)). The table is a published shape, so within a major version it changes by expand and contract and only gains meters ([0033](/decisions/0033-evolution-and-compatibility-n-and-n-1-inside-a-major-and-parallel-cutover/#n-and-n-1-inside-a-major-version)).
- **Statements and aggregates never merge two meters.** A customer's bill for a renamed meter shows both lines.
- **OpenTelemetry metrics are never a source of usage** ([0022](/decisions/0022-telemetry-is-opentelemetry-with-fixed-conventions/)). Telemetry is sampled and may be dropped; the usage stream is neither.

### The period of an event

- **A period is a UTC calendar month for statements, and a UTC day or month for caps.** One calendar, UTC, for every reader. A customer's own invoice calendar is the billing system's concern ([0041](/decisions/0041-the-finance-export-is-a-statement-per-account-and-period-closed-once-anchored-in-the-usage-log-and-pulled/#open-product-facts-the-billing-calendar)).
- **An event belongs to the period of its CloudEvents `time`** when that time is not earlier than the time the writer recorded it by more than the grace period of [0041](/decisions/0041-the-finance-export-is-a-statement-per-account-and-period-closed-once-anchored-in-the-usage-log-and-pulled/#a-period-closes-once), and not later by more than 5 minutes. The recorded time is the writer's stamp in the entry's clear envelope ([0016](/decisions/0016-the-audit-log/#sealing)), never the emitter's.
- **Otherwise the event belongs to the period of its recorded time,** and quota flags it `time_adjusted`; the statement shows it on a late line. A delayed spool delivers its events with their own times, up to the grace; a wrong clock, or a replay of old events, cannot place usage in a period it was not used in.
- **If that period is already closed, the event counts in the earliest open period** and is flagged late, with the period it belonged to ([0041](/decisions/0041-the-finance-export-is-a-statement-per-account-and-period-closed-once-anchored-in-the-usage-log-and-pulled/#late-events-and-corrections)). Because the lower bound equals the grace, an event with a trusted time is never late by clock alone: it is late only when it was recorded after the close.
- **The same assignment serves the caps,** so a day's or month's cap and a statement count the same events.

### Order across logs

- **Quota follows each usage log by checkpoint and merges the logs of a boundary by recorded time,** keeping each log's own order and breaking ties by log id ([REQ-AUDIT-035](/requirements/audit/#REQ-AUDIT-035), [0016](/decisions/0016-the-audit-log/#witnesses)). Balances are additive, but a floor and a refund that may happen once are not, so a roll-forward replays in this order.
- **The clock offset a seal records** ([REQ-AUDIT-036](/requirements/audit/#REQ-AUDIT-036)) is the claim's limit: quota claims no order across logs closer than it.

## Consequences

- The three readers agree on which events count and when, from one rule.
- A product cannot rename a meter to fix a name; the old one stays in its table for as long as its events are kept. The action table grows with retired meters.
- A gauge's `avg` needs samples at a steady rate. The periodic action's cadence is the product's, and a gap is visible as fewer samples in the statement's event count.
- A period near the month border may hold an event of the last minutes of the previous month when the writer was unreachable for longer than the grace. This is the flagged late line of the statement.
- The 5-minute future bound assumes clocks synchronised by the check of [REQ-AUDIT-017](/requirements/audit/#REQ-AUDIT-017); it is a ceiling chosen for that, not a measurement.
- Billing a failure is possible, but it is a deliberate line in a product's table that a reviewer sees.

## Roads not taken

- **Decimal quantities, as v1.** Exact for money in a string, but every sum needs a decimal library and a rounding rule; integers in a unit fine enough for the meter are exact on every store ([REQ-QUOTA-020](/requirements/quota/#REQ-QUOTA-020)).
- **Letting a meter be renamed through an alias.** The bill reads well, but "the sum equals the facts" ([REQ-QUOTA-012](/requirements/quota/#REQ-QUOTA-012)) then needs a map that every reader must hold.
- **Trusting the emitter's time alone.** An emitter with a wrong clock moves usage across periods, and a replayed old event is billed in the past.
- **Using the recorded time alone.** Immune to clocks, but a spool that was down for an hour at midnight moves a month's last minutes into the next month.
- **A billing calendar per account.** See [0041](/decisions/0041-the-finance-export-is-a-statement-per-account-and-period-closed-once-anchored-in-the-usage-log-and-pulled/#open-product-facts-the-billing-calendar).
- **Billing every outcome, or a meter per outcome.** The first bills refused calls; the second multiplies meters for what a flag in the declaration says.
- **A gauge as deltas.** A lost delta corrupts every later value; an absolute sample heals on the next one.
- **Folding this into 0017.** One record fewer, but the longest record would also carry a rule that caps and statements read.

## Follow-ups

- The action table fields for meters and the CI comparison, in the emitter: [#841](https://github.com/truvity/sluis/issues/841).
- Period assignment, late flags and the merge order, in the quota engine: [#915](https://github.com/truvity/sluis/issues/915).
