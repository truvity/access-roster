# 0020 — A channel defined twice is held, not taken over

**Status:** Accepted; refines [0019](0019-two-kinds-of-slack-channel-never-mixed.md)
**Date:** 2026-10-01

## Context

v1.47.0 added **Take over from git**: a console record with
`supersedes_policy: true` covered a policy channel, the controller reconciled the
record and reported the policy entry as `superseded`. It was meant as a
migration aid with no unmanaged gap. It also made one channel two definitions at
once, one of them reported as superseded, and it needed a status state
(`superseded`) that existed only to describe that. It contradicts a rule the
rest of the design keeps: a channel is managed one way.

## Decision

The feature is removed (v1.48.0). The rule is the plain one: a channel defined
both in the policy and as a console record is **held on both sides** and
nothing on it changes until one definition is removed. The console refuses to
create or update a record for a channel git defines (by name or adopted id), and
the server refuses the same. To move a channel from git to the console: remove
it from the policy, then Manage it from Discovered.

A stored record that still has `supersedes_policy: true` keeps loading with the
field ignored, is never written with it again, and is a plain console channel once
git no longer defines the channel. This is an exception to
[0007](0007-breaking-changes-inside-1x.md)'s "refuse removed configuration": the
field is in a record the service itself wrote, not in configuration someone
reviewed, so refusing it would make an installed record unreadable. The audit
catalogue keeps the `reason` data field (version 1.3.0 declared it and an
installation holds that version); nothing emits a value.

## Consequences

A migration has a short window in which the channel is managed by neither (git
entry removed, record not yet created) rather than by both; the channel stays as
it is in Slack and adds and removes nothing in that window.

## Alternatives considered

**Keep the take-over.** Rejected: it contradicts "a channel is managed one way".

**Last writer wins.** Rejected: silent, and the loser is whoever did not notice.
