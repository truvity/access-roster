---
title: Checkpoint history
description: "The checkpoints/<size> objects of a tiled log, the one part of its layout that is sluis's own: names, content, reader rules, limits and tests."
status: partial
sidebar:
  order: 13
---

A sluis audit log is a C2SP `tlog-tiles` log: the entry bundles, the hash tiles and the `checkpoint` object are the standard ones, written and read by libraries ([Approved libraries](/reference/approved-libraries/#c2sp-transparency-logs), [REQ-SEC-018](/requirements/sec/#REQ-SEC-018)). **One part is sluis's own: `checkpoints/<size>`.** The `checkpoint` object is rewritten with every batch, so it shows only the newest state. `checkpoints/<size>` keeps every checkpoint the writer ever signed, so that a verifier can check that the log only grew. The reasons are in [0029](/decisions/0029-the-audit-log/#tiled-log); this page fixes the format, the limits and the tests, as the rule for an own format asks (Q23a, decided 2026-11-06): a written spec, length limits and fuzz tests.

## Objects

- **One object for each checkpoint, at `<prefix>checkpoints/<size>`.** `<prefix>` is the log's prefix, `<kind>/<log>/` in the project's bucket. `<size>` is the tree size of the checkpoint it holds.
- **The name is a size in the strict decimal form,** `0` or a digit `1` to `9` followed by at most 18 digits, and at most 2^63-1. A sign, a leading zero, a space, a non-ASCII digit or any other character makes the name wrong. The name is read in one place (`historySize` in `cli/sluis/auditverify.go`).
- **The content is a C2SP signed note** ([signed-note](https://c2sp.org/signed-note)) of signature type 0x02, signed with the log key, whose text is a [tlog-checkpoint](https://c2sp.org/tlog-checkpoint) of the same log. The size in the text is the size in the name. The writer writes no extension line; a reader accepts the extension lines that tlog-checkpoint allows.
- **It is created once and never changed.** The writer creates it only if absent, with the other write-once objects of the log ([The write-once fence](/decisions/0029-the-audit-log/#the-write-once-fence)), after the tiles and before the writer's state. A crash that leaves a checkpoint without its state is finished by the next start, which reads the checkpoint it finds, checks its signature and root, and uses it.
- **The `checkpoint` object is a convenience copy of the newest one.** A verifier does not trust it on its own: it is one more checkpoint of the history, and the largest size wins.

## What a reader checks

`sluis audit verify` reads the directory and refuses the log with a closed reason when:

| Reason (suffix of the file's path) | Meaning |
|---|---|
| `.name` | The name is not a size in the strict form, or the entry is a directory |
| `.length` | The file is longer than the limit |
| `.signature` | The note does not open with the log key |
| `.format` | The text is not a tlog-checkpoint with a non-empty origin | <!-- terms-allow: origin (the C2SP checkpoint origin line) -->
| `.size` | The size in the text is not the size in the name |
| `.origin` | The origin differs from the one in the `checkpoint` object, or from `--origin` | <!-- terms-allow: origin (the C2SP checkpoint origin line) -->
| `.fork` | Two checkpoints of one size name different roots |
| `.inconsistent` | The root of the checkpoint is not the tree hash of the first `<size>` entries, computed from the tiles |

An absent directory is an empty history. The tiles are checked against the newest checkpoint, and each older checkpoint against the tiles, so a history that does not lead to the newest root is refused.

## Limits

**The count of files has no limit.** The writer makes one checkpoint for each sealed batch, for the life of the log. A batch closes at 256 messages or 5 seconds after its first, so a busy log holds one checkpoint every 5 seconds (17,280 a day) up to 51 messages a second, and more above that, up to the rate the log key can sign (about 7 a second on a YubiKey 5 Nano, about 600,000 a day; measured 2026-10-31). A compliance lock forbids deleting any of them. A count limit would make a healthy log fail to verify one day, so the reader streams: it lists the directory in batches of 1,024 names, keeps the sizes (8 octets each) and reads one file at a time, in ascending order of size.

| Limit | Value | Why |
|---|---|---|
| Name | 19 octets | The digits of the largest size, 2^63-1 |
| File | 1,048,576 octets | A checkpoint is a few hundred octets; the library bounds a checkpoint text at the same order |

The limits are constants in `cli/sluis/auditverify.go` (`maxHistoryName`, `maxCheckpointFile`). The memory of a verification grows with the number of checkpoints (8 octets each) and with nothing else; its time grows with it too, because each checkpoint is checked against the tiles.

**The same log always gives the same refusal.** A name that is not a size is reported first, the smallest name in byte order if there are several. Then the files are read in ascending order of size, and the first that fails is reported.

## Tests

- **The format keeps its bytes.** `tests/testdata/audit-log/old-writer` is a log written by the writer before the checkpoint code moved to libraries (measured 2026-11-06, commit `a01e20863`). The CLI verifies it and the writer reads its checkpoints; a test builds a signed note with a fixed signature and compares it with the old assembly byte by byte.
- **An independent reader.** `github.com/transparency-dev/formats`, the reference implementation that signed-note names for type 0x02, opens every checkpoint the writer makes and every checkpoint of the fixtures, and parses their text with its own parser (`TestCheckpointsVerifyWithTheTransparencyDevVerifier`, `TestCheckpointsOpenWithTheTransparencyDevVerifier`).
- **Fuzz targets.** `FuzzParseCheckpoint` (writer and CLI) parses a checkpoint text, `FuzzHistorySize` parses a name, and `FuzzHistoryReader` reads a directory with one file of any name and content. Each asserts that nothing panics and that what is accepted is well formed. CI runs their seed corpora with `go test`; run one for longer with `go test -tags sluis_test -run xxx -fuzz FuzzHistoryReader -fuzztime 60s ./cli/sluis/`.
- **Refusals.** Each reason above has a test case in `TestHistoryReaderRefusals` or `TestAuditVerifyRefusals`. `TestHistoryHasNoLimitOnItsCount` verifies a history of more than two reads of the directory, `TestHistoryRefusalIsDeterministic` the order of the refusals, and `TestRepeatedSignatureLinesOfTheLogKey` pins the rule for a repeated signature line of the log key: the note library checks only the first and drops a repeat unchecked, so the reader checks every line of the key and refuses the note if any fails, as the Rust verifier does.
