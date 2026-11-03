# 0040 — A meter has a name, a unit and a kind, and only declared outcomes become usage evidence

**Status:** Accepted
**Layer:** quota module
**Date:** 2026-11-03

Proposal: [issue #841](https://github.com/truvity/sluis/issues/841).

## Context

[0030](/decisions/0030-audit-records-and-the-usage-stream/#usage-is-derived-from-the-same-event-once) says that an action may carry meters, with units, and that an undeclared meter is refused. It does not say what a meter is, which outcomes of an action become usage, what happens to a meter over releases, or which time a usage fact counts at. The readers of the usage log need those answers to agree:

- **The product** builds its billing log from the usage facts, outside sluis ([0039](/decisions/0039-quota-allowance/#the-billing-log-is-outside-sluis)). sluis closes no period and writes no statement.
- **Quota** records an admit, a refusal and a push as usage facts, with amounts ([0039](/decisions/0039-quota-allowance/#countdown-and-refusal)).
- **Anyone granted the usage log** without the audit log totals it by their own rules.

This is a record of its own and not a section of 0030, because the rule for the time of a fact serves every reader of the usage log, and 0030 links here from the usage stream.

v1 counted a metered action's success only, billed a gauge as the average of hourly samples, and treated a renamed meter as a new one (v1 "Billing and metering", on `master`). v2 keeps those three.

## Decision

### The meter is declared

- **A meter is a document of the config kind `Meter`:** a name, a unit and a kind. The profile is Fixed, so a new meter is a reviewed, signed document ([0004](/decisions/0004-the-data-model/#profiles)). The name is the CloudEvents `type` of its events. The unit is a lower-case word such as `requests` or `bytes`. Amounts are signed 64-bit integers.
- **The action table names the meters an action may carry.** The table is code, and the release identifies it ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-action-table-is-code-and-the-release-identifies-it)). The emitter library refuses a meter that no `Meter` document declares and an amount out of bounds.
- **The kind is `count` or `gauge`.** A count is an event: its amounts add up over any span. A gauge is an absolute sample, such as stored bytes, never a change. It is emitted by a periodic action that is audited as an action of its own ([0030](/decisions/0030-audit-records-and-the-usage-stream/#usage-is-derived-from-the-same-event-once)), and the meter declares how the samples of a span combine: `avg`, `max` or `last`. sluis picks none of them; the product chooses.

### Only declared outcomes become usage evidence

- **A meter declares the outcomes it records,** and the default is `success`. A refusal by policy or by quota is never metered use. An action priced by attempt lists the failure it records.
- **The emitter library adds the usage part only for a listed outcome.** The audit part is always written, so a failed call is visible and carries no usage.
- **The facts of an allowance are the exception by design.** An admit, a refusal and a push each record the allowance changing, or declining to change ([0039](/decisions/0039-quota-allowance/#countdown-and-refusal)). They are not metered use of an action, and they carry their amounts so that the product can total them.

### A meter never changes

- **A meter's name, unit and kind are fixed from its first release.** Renaming it, or changing its unit or kind, is a new meter. The old meter stays in the table and in the `Meter` documents, marked retired: a retired meter can still be read from old events, and no release emits it.
- **A check compares the action table with the previous release's and the `Meter` documents with the ones in force,** before anything is published. It fails when a meter was renamed, retyped or dropped without being retired, as the comparison does for OCSF ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-record-format)). Within a major version the table changes by expand and contract and only gains meters ([0015](/decisions/0015-evolution-and-compatibility/#n-and-n-1-inside-a-major-version)).
- **A reader never merges two meters.** A product's bill for a renamed meter shows both lines.
- **OpenTelemetry metrics are never a source of usage** ([0016](/decisions/0016-telemetry/)). Telemetry is sampled and may be dropped; the usage stream is neither.

### The period of an event

- **sluis closes no period.** A usage fact carries two times: the time of use, which is the CloudEvents `time` that the emitter sets, and the time the writer recorded it, which is the writer's stamp in the entry's clear envelope and never the emitter's ([0029](/decisions/0029-the-audit-log/#sealing)). A reader that assigns facts to periods uses its own calendar. This record fixes only which of the two times a reader trusts, so that every reader of the log agrees.
- **A fact counts at the time of use** when that time is not earlier than the recorded time by more than 72 hours, and not later by more than 5 minutes. A spool that was down delivers its events with their own times, up to that bound.
- **Otherwise the fact counts at its recorded time,** and the reader marks it `time_adjusted`. A wrong clock, or a replay of old events, cannot place usage in a span it was not used in.
- **The bounds are built in.** The 5-minute future bound assumes synchronised clocks; it is a ceiling chosen for that, not a measurement.

## Consequences

- The readers of the usage log agree on which facts count and at what time, from one rule.
- A product cannot rename a meter to fix a name; the old one stays for as long as its events are kept. The table and the `Meter` documents grow with retired meters.
- A gauge's `avg` needs samples at a steady rate. The periodic action's cadence is the product's, and a gap shows as fewer samples.
- A fact near a period border may count in the previous period when the writer was unreachable for longer than 72 hours. The product's billing log can show it as a late line.
- Billing a failure is possible, but it is a deliberate line in a product's table that a reviewer sees.
- sluis carries no billing calendar, grace period or close job. The product's billing log holds them.

## Roads not taken

- **Decimal quantities, as v1.** Exact for money in a string, but every sum needs a decimal library and a rounding rule; integers in a unit fine enough for the meter are exact on every store.
- **Letting a meter be renamed through an alias.** The bill reads well, but "the sum equals the facts" then needs a map that every reader must hold.
- **Trusting the emitter's time alone.** An emitter with a wrong clock moves usage across periods, and a replayed old event is counted in the past.
- **Using the recorded time alone.** Immune to clocks, but a spool that was down for an hour at midnight moves a month's last minutes into the next month.
- **A period, a calendar or a close in sluis.** One more calendar for every reader to share and a job to run; the product owns the contract with its customers and so owns the calendar ([0039](/decisions/0039-quota-allowance/#the-billing-log-is-outside-sluis)).
- **Recording every outcome, or a meter per outcome.** The first meters refused calls; the second multiplies meters for what a flag in the declaration says.
- **A gauge as deltas.** A lost delta corrupts every later value; an absolute sample heals on the next one.
- **Folding this into 0030.** One record fewer, but the longest audit record would also carry a rule that every reader of the usage log applies.

## Follow-ups

- The action table fields for meters, the `Meter` kind and the comparison check, in the emitter: [#841](https://github.com/truvity/sluis/issues/841).
- The quota actor that records the facts of an allowance: [#915](https://github.com/truvity/sluis/issues/915).
