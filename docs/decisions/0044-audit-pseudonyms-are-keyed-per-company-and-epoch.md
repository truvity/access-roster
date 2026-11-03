# 0044 — Audit pseudonyms are HMAC-SHA384 of the subject under a data key per company and month, wrapped by the sealing key, and only the company's audit role reverses them

**Status:** Superseded by 0029
**Date:** 2026-11-03

Proposal: [issue #1005](https://github.com/truvity/sluis/issues/1005).

## Context

A person or external actor is recorded in audit under a keyed pseudonym, never by name, e-mail address or token, and the mapping from a pseudonym to the person lives outside the log, so that erasure deletes it ([0029](/decisions/0029-the-audit-log/#pseudonyms)). The operator's own view of a company's records shows rotating pseudonyms (REQ-AUDIT-038), and the pseudonym encodes its key epoch ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-sluis-fields-unmappedsluis)). The audit log is in the first working version (decided by the maintainer on 2026-11-01), so every actor that emits a record needs the function from the first build.

Constraints:

- **Tenants have no keys of their own.** A company's data keys are wrapped under the boundary's sealing key with the company in the encryption context ([0006](/decisions/0006-keys-and-sealing/#key-purposes)).
- **Subjects are already opaque.** `sub` is a random identifier that sluis assigns, never an e-mail address ([0017](/decisions/0017-identity-and-sign-in/#subjects)); it is still personal data, because it links to a person.
- **Rotation trades two things.** A pseudonym that never changes lets anyone who reads the envelopes follow one person for years; one that changes often makes an investigation across periods depend on reversal.
- **The algorithms stay within the approved set** ([0006](/decisions/0006-keys-and-sealing/#algorithms)).

## Decision

- **A pseudonym is `p1.<epoch>.<value>`,** where `<epoch>` is the UTC month as `YYYYMM` and `<value>` is the first 128 bits, base64url without padding, of HMAC-SHA384 over a domain-separated input: the label `sluis-pseudonym-v1`, the boundary, the company, the kind of identity and its stable identifier, each length-prefixed. The identifier is the sluis subject for a person; for an identity sluis has assigned no subject, it is the upstream's issuer and subject; for a workload or client, its SPIFFE ID or client id. A record of the machine plane, which belongs to no company, uses the boundary as its company.
- **The key is a data key per (boundary, company, epoch),** 256 random bits, wrapped under the boundary's sealing key through the `keys` port with `purpose=pseudonym`, the company and the epoch in the context, like the cookie key of `session`. A company has no key in a key store; the sealing key is the only authority key involved.
- **The pseudonym is computed where the record is made.** The emitter library of each actor that records an identity unwraps the current epoch's key through its `keys` port and computes the pseudonym before the record leaves the process, so a raw subject never reaches a transport, a spool or the writer. The manifest grants `unwrap` for `purpose=pseudonym` only to those actors and to `reader`.
- **The pseudonyms rotate every month,** when the epoch changes. Within a month the records of one person link to each other; across months they do not, without reversal.
- **Only the company's own audit role reverses a pseudonym.** The `reader` answers two questions for a person who holds the company's declared reversal permission: the pseudonyms of a named subject for a range of epochs, and, for a given pseudonym, which of the company's known subjects produces it in that epoch. Each reversal is audited under the asking person's name. The operator of the installation cannot reverse a company's pseudonyms.
- **Erasure of a person removes the link from the subject to the person.** The pseudonym leads to the subject, and the subject leads to a person only through the person's record, which lives outside the log ([REQ-AUDIT-057](/requirements/audit/#REQ-AUDIT-057)). Once that record is erased the pseudonyms name no one, as 0016 says.
- **Epoch keys are kept for the log's retention** and deleted with the company's audit data key when the company is shredded ([0029](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding)). A compromise of a pseudonym key is answered by a new epoch at once; past records keep their pseudonyms.
- **HMAC-SHA384 joins the approved algorithms** as the keyed function; it is the function HKDF-SHA384 is built on.

## Consequences

- No process outside an emitting actor, `key-holder` or the key service sees a raw subject on the audit path, and the writer, the transport and the spools hold pseudonyms only.
- The operator sees a person's activity linked within a month and not beyond, which matches the rotating view the requirements ask for. An investigation across months needs the company's reversal role, and every reversal is visible in the log.
- A leaked pseudonym key lets its holder confirm whether a subject they already know appears in that company's month; it does not reveal subjects, because they are random, and it does not let anyone forge a record.
- Each emitting actor unwraps one data key per company per month, cached for the month; a boundary with many companies holds many small wrapped keys in state.
- Reversal of a pseudonym to a subject is a search over the company's known subjects for one epoch. It is bounded by the company's size and is an interactive operation, not a bulk export.
- Records of one person stay linkable within each month after erasure, as 0016 already accepts for the log as a whole.
- Requirements: [REQ-AUDIT-127](/requirements/audit/#REQ-AUDIT-127) to [REQ-AUDIT-131](/requirements/audit/#REQ-AUDIT-131).

## Roads not taken

- **A plain hash of the subject.** Anyone with a list of subjects could reverse it without any key.
- **One pseudonym key for the life of the log.** One person could be followed through every record for years by whoever reads the envelopes, against the rotating view REQ-AUDIT-038 asks for.
- **A stored mapping table from pseudonym to person.** A second store of personal data to protect, back up and erase, where the keyed function already gives the mapping on demand.
- **Pseudonymising in the writer.** Every transport, spool and remote audit installation would then carry raw subjects.
- **A key per person.** Millions of keys and a lookup per record, as 0016 rejected for shredding.
- **Format-preserving encryption of the subject.** Reversible by whoever holds the key, without the person's record, so erasure could not unlink it.

## Follow-ups

- The emitter and the reader that implement it, in the first working version: [#841](https://github.com/truvity/sluis/issues/841) and [#839](https://github.com/truvity/sluis/issues/839), sliced into the first version.
- Identity treatment and audit profiles for parity: [#840](https://github.com/truvity/sluis/issues/840).
