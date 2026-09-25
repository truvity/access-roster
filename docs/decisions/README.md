# Architecture decisions

One record per decision that shapes this repository from the outside —
what a relying party must do, what an installation must accept, what a
release removes. The design pages under [`../design/`](../design/) say
how the shipped thing works; a record here says why it is shaped that
way, what was weighed against it, and what follows from choosing it. When
the two disagree, the design pages describe what actually shipped and a
record here is read as the reasoning that got there.

A record is never edited to reverse a decision. A changed mind gets a new
record that supersedes the old one, so the index below stays a true
timeline and nothing is silently rewritten under an old date.

## Index

| ADR | Decision |
|---|---|
| [0001](0001-sessions-and-an-absolute-limit.md) | Sessions and an absolute limit |
| [0002](0002-mission-boundary-tokens-and-memberships.md) | Mission boundary: tokens and memberships |
| [0003](0003-deprecate-access-proxy.md) | Deprecate and remove the access-proxy chart |
| [0004](0004-ssh-opkssh-and-the-secret-stores-ca.md) | SSH: opkssh for people, the secret store's SSH CA for hosts |
| [0005](0005-es384-signing-algorithm.md) | ES384 is the signing algorithm |
| [0006](0006-groups-claim-scoped-per-audience.md) | The groups claim is scoped per audience, by default |
| [0007](0007-breaking-changes-inside-1x.md) | Breaking changes inside 1.x |

## Template

Start a new record from this shape. Keep it tight — long enough to make
the reasoning checkable, short enough that the next reader finishes it.

```markdown
# NNNN — <a decision, stated as a decision>

**Status:** Proposed | Accepted | Superseded by [NNNN](NNNN-slug.md)
**Date:** YYYY-MM-DD

## Context

The situation that made a decision necessary, and the constraint that
ruled some answers out before the rest were compared.

## Decision

What was decided, stated so a reader could act on it without reading
anything else. Include the shape of the mechanism, not just its name.

## Consequences

What this costs, what it forecloses, and what a relying party or an
operator must now do differently. Say the honest boundary out loud —
the case this decision does not cover — rather than leaving it to be
discovered.

## Alternatives considered

Each one named, with the specific reason it was not chosen. "We didn't
think of it" is a fine thing to be able to write here later; do not
retrofit reasons no one had at the time.
```
