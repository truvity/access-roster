# 0050 — Audit lifecycle tiers move only cold objects, and compliance profiles are floors that the configuration check enforces

**Status:** Superseded by 0029
**Date:** 2026-11-03

Proposal: [issue #1016](https://github.com/truvity/sluis/issues/1016).

## Context

[0029](/decisions/0029-the-audit-log/#retention) fixes retention, legal holds and the lock mode of the log, and says that framework profiles and archive lifecycle tiers are parity. Two planned records remain: when old objects of the log move to colder storage ([#1016](https://github.com/truvity/sluis/issues/1016)) and what a compliance profile is ([#1027](https://github.com/truvity/sluis/issues/1027)). v1 had both. Its archive moved objects to colder classes, and its profiles (such as DORA, NEN 7513 and PCI DSS) were standard-specific bundles of required fields, retention, identity treatment and integrity, composed by taking the strictest, each producing a purpose-bound copy of the records in a store of its own (v1 ADR 0044 and 0056, on `master`; parity row [#840](https://github.com/truvity/sluis/issues/840)).

v2's log is different in the ways that matter here. There is one log per writer, written once ([0029](/decisions/0029-the-audit-log/#the-write-once-fence)); each company's records are encrypted to its own data key and can be shredded ([0029](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding)); and usage is a separate log with its own retention ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-usage-stream)). Evidence is kept apart from personal data ([0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/)). A copy of the log in another store with another retention would be a second place for evidence and for personal data, with its own key, lock and shredding.

The forces: a lock or a retention period is never shortened (0016); the reader and the verifier must work with no help from sluis; sluis writes nothing it does not own, and the bucket belongs to the operator's infrastructure ([0015](/decisions/0015-evolution-and-compatibility/)); and the numbers a standard sets are facts with a source and a date (principle 9), which change faster than a record.

## Decision

### Lifecycle tiers

- **Only cold, immutable objects move.** The tiles of the log are static objects ([0029](/decisions/0029-the-audit-log/#tiled-log)). The entry bundles and the level-0 hash tiles that are complete may move to a colder storage class after a declared age. Partial tiles, hash tiles of higher levels, the checkpoints and the pointer stay in the hot class, so a proof and the newest entries never wait for a retrieval.
- **A tier never touches retention.** A transition leaves the object's lock and retention as they are, and expiry at the end of retention deletes the object from any tier. The conformance suite of each blob driver proves that a transitioned object keeps its lock ([#851](https://github.com/truvity/sluis/issues/851)).
- **Each blob driver declares the tiers it supports,** and `sluis config check` refuses a tier the driver lacks. A driver with none (`fs`) takes none.
- **The ages are declared per log kind:** `audit.tiers`, a list of age and class, applied to the audit log and the usage log separately.
- **sluis renders the lifecycle rule and does not apply it.** The rule is a neutral artifact derived from the declaration, applied by the operator's infrastructure code, like the other artifacts of the installation ([0015](/decisions/0015-evolution-and-compatibility/)). The reader learns an object's class from the driver.
- **A read of a cold object is explicit.** The reader returns a `pending` state with a retry time and asks for the retrieval when its role allows it; it never blocks a request on one. The search index holds the searchable fields, so a query does not touch cold objects; only showing a full record and verifying do. `sluis audit verify` asks for a range in batches.

### Compliance profiles

- **A profile is a floor, not a copy.** It is a data file shipped in the release, one per standard: `profiles/<id>.yaml`. The release ships `dora`, `nen-7513` and `pci-dss`. A file states, for the audit log and the usage log separately, the least retention, the least lock mode (or a witness in its place, as 0016 allows), whether a witness is required, the least identity treatment (a keyed pseudonym, [0044](/decisions/0044-audit-pseudonyms-are-keyed-per-company-and-epoch/)), the record classes that must be emitted and the review cadence. Each value carries the clause of the standard it comes from and the date it was last checked.
- **An installation declares the profiles it keeps,** `audit.profiles: [...]`. The strictest value of each floor applies: the longest retention, the strongest lock, a witness if any requires it.
- **`sluis config check` enforces the floors.** It refuses a declared retention, lock or identity treatment below the floor of a declared profile, in a production boundary, naming the profile and the clause. It cannot check that a standard is met, only that the installation is not below the floor the profile file states.
- **The record classes are reported, not refused.** The reader reports, per period, a required class with no records, so that an application that stopped emitting is seen.
- **There are no purpose-bound copies.** One log holds the evidence; a second store for a second retention would copy personal data outside the shredding of 0016. A consumer that needs another view reads the log through the reader, or takes the usage log, which has its own retention.
- **Time-stamp anchoring of checkpoints (RFC 3161) is not built.** It proves when a hash existed, not that every reader saw one history; witnesses do that ([0029](/decisions/0029-the-audit-log/#roads-not-taken)). It stays a planned line, REQ-AUDIT-031, with its own issue.

## Consequences

- The cost of old evidence falls without a change to what can be verified; the cost is a delay of minutes to hours when a cold range is read, and a runbook for a verifier that needs one.
- A profile file is data: a standard's change is a reviewed change to one file, dated and sourced, with no record to rewrite. The maintenance cost is the review cadence of three files.
- Because a profile is a floor, an installation that wants more keeps more; an installation that declares none is checked against nothing but 0016.
- v1's per-profile stores and its purpose-bound copies are not carried. A v1 reader of the `history` or `billing` copies is wired differently in the cutover inventory ([#1017](https://github.com/truvity/sluis/issues/1017)).
- Requirements: REQ-AUDIT-136 to REQ-AUDIT-140 are added.

## Roads not taken

- **A copy of the log per profile, as v1 did.** Several retentions and several stores of the same evidence, each outside the company's shredding, and a writer or a copier to run for each.
- **Tier by moving the object to another bucket.** A new key means a new address, and the checkpoints and tiles name each other by path.
- **Tier every object, tiles of higher levels included.** Every proof would wait for a retrieval, and the saving is small because those tiles are a tiny part of the bytes.
- **sluis applies the lifecycle rule itself.** The writer, whose credential has no delete right, would need rights over bucket configuration.
- **Compliance numbers in the record.** The values are the standards' and change when the standards do; the record would go stale.
- **A profile that turns on features.** A floor can be checked; a feature switch would hide which control meets which clause.
- **RFC 3161 anchoring in the parity milestone.** v1 did not ship it and no consumer has asked for it.

## Follow-ups

- Which audit installation receives the audit of the workforce installation, and so which profiles apply there: [#1143](https://github.com/truvity/sluis/issues/1143).
- Time-stamp anchoring of checkpoints (REQ-AUDIT-031), later: [#1027](https://github.com/truvity/sluis/issues/1027).
- Build: the profile files and the check [#840](https://github.com/truvity/sluis/issues/840); the tier declaration and the rendered rule [#837](https://github.com/truvity/sluis/issues/837).
