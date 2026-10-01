# 0024 — Reconciler rails are shared pieces, not a framework

**Status:** Accepted
**Date:** 2026-10-01

## Context

The GitHub controller was the first reconciler; the Slack controller the second.
Writing the second showed which pieces the first had that were identical in
meaning and which only looked alike.

## Decision

`internal/rails` holds exactly what both call with the same meaning: the pass loop
with its bounded policy-retry backoff, the two questions put to the console (who
holds a group, what is true of one address) each gated by the policy digest, the
removal rule (only on a vouched answer), the held-once ledger, the last-good-report
journal, the breaker and its fingerprint, and the dry-run switch. It takes funcs
and small interfaces and imports no generated client. It holds **no** reconciler
interface, row or action type, status document, pass skeleton or metrics: those differ
in kind or are exported names that must stay identical to what one system already
publishes. A piece moves in when a second reconciler needs it unchanged, not before.

## Consequences

A third reconciler repeats some skeleton code and imports the rails; the two
existing ones keep identical decisions, audit records and metrics.

## Alternatives considered

**A reconciler framework with a pass skeleton and a shared status type.**
Rejected: a shape guessed from one system and bent to fit the second.
