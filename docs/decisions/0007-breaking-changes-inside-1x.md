# 0007 — Breaking changes inside 1.x

**Status:** Accepted
**Date:** 2026-09-25

## Context

This product is young and still finding its shape: the `resources` and
`client_documents` tables, the `display_name`/`description` fields on a
client, and the Back-Channel Logout fix to `end_session` all landed after
1.0, each correcting or extending something the schema or the protocol
surface had gotten wrong or left out
([CHANGELOG.md](../../CHANGELOG.md)). Holding every such correction for a
2.0.0 release would either delay a fix that closes a real gap — the
`end_session` fix in particular closed a security hole
([design/access-roster.md#sessions-and-sign-out](../design/access-roster.md#sessions-and-sign-out))
— or force a 2.0.0 every few weeks, which stops meaning what a major
version is supposed to mean.

The alternative — carrying a deprecated key or behaviour alongside its
replacement indefinitely, so nothing ever breaks a minor release — has
its own cost here specifically: an unknown or removed key in the policy
schema is a **security-relevant** thing to get wrong. The schema already
refuses unknown keys rather than ignoring them, precisely because a
silently-ignored key is a grant somebody wrote, reviewed and merged that
never took effect
([design/access-roster.md#appendix-what-was-removed-and-why](../design/access-roster.md#appendix-what-was-removed-and-why)).
Keeping a removed key *accepted but inert*, purely to avoid a breaking
release, would reintroduce exactly that failure mode on purpose.

## Decision

**Breaking changes ship in 1.x minor releases.** A 2.0.0 is not required
to remove a table, rename a field, or change a default. Two obligations
come with that instead of a major-version bump:

1. **Every breaking change is marked `**Breaking:**` in the CHANGELOG**,
   with the migration spelled out in the same entry — what changes, what
   an installation must edit, and by when, following the pattern already
   in use there (for example the `end_session` and `audit.s3.*` entries).
2. **Removed configuration is refused, never silently ignored.** The
   schema's unknown-key refusal is the enforcement mechanism: a key that
   used to mean something and no longer does fails the render or the
   load with a message naming its replacement, exactly as `memberships`
   is refused today rather than accepted and dropped. A removal that
   cannot be phrased as "this key now fails validation, and the message
   says why" is not ready to ship.

## Consequences

An installation pins one tag, per the README's own convention, and reads
the CHANGELOG on every bump rather than assuming a minor version is safe
to take blind. That is a real cost, asked of every consumer, in exchange
for not delaying a correction — including a security one — behind a major
version this product is not ready to promise the stability of yet.

A contributor proposing a removal must design the refusal message as part
of the change, not as an afterthought: "refused, name the replacement" is
the bar a removal has to clear before it merges, not something to bolt on
after users report confusion.

This record does not set a date for when the product stops treating minor
releases this way — that is a decision to make once the schema and the
protocol surface have stopped moving, not one to pre-commit to here.

## Alternatives considered

**Semantic versioning in full: every breaking change is a 2.0.0.**
Rejected for the reasons above — either fixes get held back to batch a
major release, which delays a security-relevant correction like the
`end_session` fix, or major versions stop being rare enough to signal
anything, which is the opposite of what they are for.

**Accept and silently ignore removed keys, to keep every release
non-breaking.** Rejected outright: for a policy schema, a silently
ignored key is indistinguishable from a grant that was merged and never
took effect — the one failure mode this repository's validation exists to
make impossible, not to reintroduce for the sake of a smoother upgrade.

**A deprecation window — accept the old key with a warning for one or two
releases before refusing it.** Considered and left open rather than
adopted outright: a warning a rendering pipeline does not surface is as
silent as no warning at all, and this repository's own render-time
validation has no established place to put one yet. A future record can
add this once that place exists; today's answer is the more conservative
one — refuse immediately, name the replacement.
