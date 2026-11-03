# 0048 — Data lifecycle and evidence: evidence and personal data never share a key, erasure is shredding the key, and v1's history stays where it is

**Status:** Superseded by 0029
**Date:** 2026-11-03

Proposal: [issue #1016](https://github.com/truvity/sluis/issues/1016).

## Context

sluis keeps two kinds of data that live for different times.

- **Personal data** has to end when a person or a company leaves: audit records carry pseudonyms of people ([0044](/decisions/0029-the-audit-log/)), and a company that leaves has its audit data key deleted ([0029](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding)).
- **Evidence** has to last as long as a duty needs it. A bill can be disputed after the customer has left, and finance keeps usage for years. Today usage entries are encrypted to the company's audit data key, so the exit shred makes them unreadable, and the evidence ends with the personal data (REQ-AUDIT-097).

Principle 3 keeps keys apart where lifetimes differ, and principle 1 says a key never leaves its store. Three more things need one answer for the parity, customer-identity and quota milestones: how a person's erasure and export work, what a backup may hold, and what happens to v1's audit and billing history, whose retention outlives v1.

## Decision

### Two classes of data, two keys

| Class | What it is | Key | Ends |
|---|---|---|---|
| **Personal data** | Audit entries (pseudonymised), the mapping from a pseudonym to a person, a person's records | The company's audit data key, wrapped under the boundary's sealing key | At exit: the key is shredded. At a person's erasure: their records and the mapping are deleted |
| **Evidence** | Usage events and period statements | The company's usage data key, wrapped under the same sealing key | At the end of the usage log's declared retention |

- **Evidence and personal data never share a key.** The company has two data keys, an audit key and a usage key, both wrapped under the sealing key, and neither is a key in the key store ([0006](/decisions/0006-keys-and-sealing/#key-purposes), REQ-AUDIT-133).
- **A usage event carries no personal data:** no pseudonym, subject, e-mail address or free text. It names the account, the meter, the amount, the time and the request (REQ-AUDIT-132).
- **A usage entry is encrypted to the company's usage key** (REQ-AUDIT-097). Its readers are `quota` and the finance export, and nothing else; the indexer does not read it ([REQ-AUDIT-098](/requirements/audit/#REQ-AUDIT-098)).
- **Exit shreds the audit key and keeps the usage key** until the usage retention ends (REQ-AUDIT-134, REQ-AUDIT-135). Both retentions are declared, and neither binds the other ([0029](/decisions/0029-the-audit-log/#retention)).
- **Whether a contract treats a company's usage totals as personal data is a legal fact.** The design keeps none in the usage class; a record that would need one is a personal-data record and belongs under the audit key.

### The period statement is the portable evidence

- **When a billing period closes, `quota` writes a statement for each billing account as an entry of the usage log** (REQ-QUOTA-036). It holds the amounts per meter and names the checkpoint of the usage log that it was computed from. It holds no personal data and no price.
- **The log key signs it with the rest of the batch,** and the witnesses cosign the checkpoint. The entry's clear envelope carries the statement's SHA-384 digest, so the holder of a statement can recompute the digest and check inclusion against a cosigned checkpoint with standard tools, without the usage key and after the company has left.
- **A statement is written once.** A correction is an `Adjust` in the next period, not a rewrite ([0030](/decisions/0039-quota-allowance/#the-allowance)). The close rule, which is the calendar, the grace and the treatment of late events, belongs to the finance export ([#915](https://github.com/truvity/sluis/issues/915)).

### Erasure and export

- **Erasure of a company is the shred of its audit key.** Its records stay in the log, sealed and verifiable, and nobody can read them again ([0029](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding)).
- **Erasure of a person deletes their records and the mapping from their pseudonyms to them** ([0044](/decisions/0029-the-audit-log/)), so their audit records name no one. There are no per-subject keys in 2.0.
- **Export of a person's data comes from the subject lifecycle record** ([#1024](https://github.com/truvity/sluis/issues/1024)), never from decrypting the audit log.

### Backups

- **An archive is encrypted to at least two recipients held apart, one of them offline** ([0004](/decisions/0004-the-data-model/#treatment), [REQ-BACKUP-001](/requirements/backup/#REQ-BACKUP-001), [REQ-BACKUP-020](/requirements/backup/#REQ-BACKUP-020)).
- **Keys never leave their stores, and an archive holds wrapped data only.** It holds no authority key and no sealing key. The one escrow copy it carries is of the data keys of sealed secrets, never of a company's audit or usage key (REQ-BACKUP-037), so an archive cannot undo a shred.
- **Each installation declares how long it keeps an archive,** and `sluis config check` refuses a production installation without it (REQ-BACKUP-039). An erasure reaches the copies in archives when they expire.
- **A restore re-applies every shred and erasure that the audit log records after the archive was taken** (REQ-BACKUP-038), so restoring an old archive does not bring back erased data.

### v1's history

- **v1's audit archives and billing history stay where they are, read-only,** under their locks. They are not imported: v1's hash chains do not survive an import, and v2 does not carry v1's format ([0029](/decisions/0029-the-audit-log/)).
- **A final v1 verifier is pinned for the retention period.** The last v1 release's verifier and reader are kept as a tagged source, built binaries with checksums and attestations, so an auditor can verify a v1 archive after v1 is retired (principle 4). The retention period is that of the longest v1 compliance profile.
- **v1's billing history is exported once** to a file with the FOCUS column names of the finance export, with its digest recorded, and kept for the billing retention.

## Consequences

- A billing dispute after a company has left can be answered from the usage log and the statements, and the exit still destroys everything personal.
- Each company has one more data key, with its own lifetime. The usage retention has to be declared and at least as long as the longest duty, and the usage key outlives the audit key by that difference.
- REQ-AUDIT-097 and [0029](/decisions/0029-the-audit-log/) change in the same pull request as this record: a usage entry is encrypted to the usage key, and the exit shred deletes the audit key only.
- Personal data in archives is reached by expiry and replay, not at the moment of erasure, so the archive retention is the longest time an erased record can exist in a copy.
- Old v1 code lives on past v1's retirement, and for a while an auditor has two places to look. The cost is a pinned build and a tagged source for years.
- Requirements: [REQ-AUDIT-097](/requirements/audit/#REQ-AUDIT-097), [REQ-AUDIT-132](/requirements/audit/#REQ-AUDIT-132) to [REQ-AUDIT-135](/requirements/audit/#REQ-AUDIT-135), [REQ-QUOTA-036](/requirements/quota/#REQ-QUOTA-036), [REQ-BACKUP-037](/requirements/backup/#REQ-BACKUP-037) to [REQ-BACKUP-039](/requirements/backup/#REQ-BACKUP-039).

## Roads not taken

- **Usage under the audit key, as before.** The exit shred destroys the proof of a bill.
- **Delay the shred until the billing retention ends.** Personal data would be kept for years after exit, against the runbook and any erasure promise.
- **A signed statement only, with usage left under the audit key.** A dispute could not be proved from events after exit, and the statement is a summary, not the facts.
- **A key for each person.** Millions of keys and a lookup for each record, as 0016 rejected.
- **A pseudonym in the usage event.** No consumer needs it: caps are per account, and it would put personal data in the evidence class.
- **A key purpose of its own for signing statements.** One more asymmetric key and slot for each installation, where the log key and the witnesses already give order and tamper evidence.
- **Import v1's history into the v2 log.** The hash chains break, and it needs an importer, a provenance record and a new evidence rule.
- **Export v1's archives to cold storage and drop the verifier.** Nobody could verify them later, which is weak for a regulated profile.
- **Escrow every data key, to restore after the loss of the sealing key.** The archive could then reopen a shredded company.

## Follow-ups

- Retention, lifecycle tiers and the usage retention: [#1016](https://github.com/truvity/sluis/issues/1016).
- Archive format, retention and replay: [#1015](https://github.com/truvity/sluis/issues/1015).
- The subject lifecycle and the export of a person's data: [#1024](https://github.com/truvity/sluis/issues/1024).
- The pinned v1 verifier and the one-time billing export, with the cutover: [#1017](https://github.com/truvity/sluis/issues/1017).
- The period close rule and the statement, with the finance export: [#915](https://github.com/truvity/sluis/issues/915).
- Compliance profiles and the retention they set: [#1027](https://github.com/truvity/sluis/issues/1027).
