# 0018 — Do not configure what the product already knows

**Status:** Accepted; applies [0007](0007-breaking-changes-inside-1x.md)
**Date:** 2026-10-01

## Context

v1.41.0 let the policy carry, for each Slack workspace, `team_id`, `domains`
and `owner`, and for each GitHub organisation, `owner`. access-roster already
learns each at run time: every connected directory records its workspace id and
the domains it serves, a Slack install reports the team, and the person who
connects a thing acts within a directory. Holding each twice, in git and at
runtime, makes drift possible, and a mismatch of an identity (a team, an owner)
is a security matter, not a cosmetic one.

## Decision

A value the product learns from a trusted source at run time is **not a policy
key**:

- the **owner** (the directory workspace that owns a Slack workspace or GitHub
  organisation) is recorded in the connection record when the connection is
  made, by one rule: the installation-wide operator chooses among connected
  directories or none; an operator of exactly one directory owns what they
  connect; an operator of several chooses among theirs. Only the
  installation-wide operator changes it later, and that is audited;
- the Slack **team** is recorded at the first install; any later install or
  reconnect must match it, else the token is revoked and refused;
- a person is looked up by the **served domains** of the owning directory, read
  from the console every pass;
- the policy keeps what is policy: the workspace key, `channels`, `people`, and
  GitHub team bindings.

Per [0007](0007-breaking-changes-inside-1x.md), the removed keys are **refused
at load**, with a message that names where the value now comes from, rather than
ignored. A workspace with no owner is held ("no owning directory: set the owner
on the console") rather than guessed.

## Consequences

The first connect of a Slack workspace or GitHub organisation has one more
choice on the console, and an old policy must delete four keys before it
loads. A policy review no longer shows who owns a workspace; the connection
record and the audit trail do.

## Alternatives considered

**Keep the keys and verify them against runtime.** Rejected: it keeps two
sources of one fact and turns every mismatch into an operator puzzle.

**Ignore the removed keys.** Rejected by 0007: a silently ignored key reads as a
declaration that never took effect.
