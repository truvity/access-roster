# 0006 — The groups claim is scoped per audience, by default

**Status:** Accepted
**Date:** 2026-09-25

## Context

`groups` is the whole of the authorization a token carries — a flat list
of internal group names, and nothing downstream re-maps them
([reference/policy.md#groups--token-by-deep-merge](../reference/policy.md#groups--token-by-deep-merge)).
Today that list is every internal group the caller holds, in every token,
regardless of which client or resource the token is for. A person with a
long reach across an installation carries the whole of it into a
gateway's cookie for one console that gates on a single group, and into
every other token besides.

Two costs follow directly from that, both structural rather than
theoretical. A gateway-fronted console keeps its bearer in a browser
cookie, and cookies have size limits that a large, flat `groups` list
approaches faster the more groups an installation grows; a cloud
provider's own session-tag mechanism has a comparable ceiling. And every
relying party that ever sees the token — including ones logging it,
including a browser's developer tools — sees the installation's whole
naming structure, not the slice that concerns it.

## Decision

**A token carries only the internal groups relevant to its audience**: the
groups its client's or its resource's `requires`
([reference/policy.md#clients--audience-and-gate](../reference/policy.md#clients--audience-and-gate),
[reference/policy.md#resources--what-a-token-is-for](../reference/policy.md#resources--what-a-token-is-for))
names, plus any further group the client or resource explicitly declares
it needs to read — for example one it maps into an application role but
does not itself gate on. A group the caller holds that neither the
audience's `requires` names nor its declaration asks for is left out of
that token.

This is a smaller, audience-scoped view of the same authorization, not a
narrower one: nothing here changes who is admitted to a client or a
resource, or what `requires` means. `groups` remains flat and remains the
whole of what is checked; what changes is which subset of a caller's
groups a given token is asked to carry.

The exact policy key that lets a client or resource declare "these
groups too, beyond what I gate on" is an implementation detail this
record does not fix — describe the principle here, and let the schema
that ships it speak for itself in
[reference/policy.md](../reference/policy.md) once it exists.

## Consequences

**This is a breaking change**, shipped inside the 1.x line per
[0007](0007-breaking-changes-inside-1x.md). A client that today reads a
group from the token beyond what its own `requires` names — most often to
map it into an application-level role rather than to gate entry — stops
seeing that group once scoping ships, unless it is updated to declare
that it needs it. An installation upgrading must audit every client and
resource that reads `groups` for more than membership before taking the
release that turns scoping on, and the CHANGELOG entry names the
migration per
[0007](0007-breaking-changes-inside-1x.md)'s convention.

What does not change: a client's `requires` and a resource's `requires`
still gate exactly as they do today; `groups` is still the only place
authorization lives; nothing re-maps a group's name based on which
audience receives it. A smaller token is a smaller version of the same
fact, never a different one.

## Alternatives considered

**Leave `groups` unscoped and let an installation shrink it by holding
fewer, coarser groups.** Rejected: that asks every installation to
redesign its own group structure around a token-size ceiling instead of
asking the issuer to send only what an audience needs — the wrong layer
to push the constraint onto, and a redesign that does not scale as the
installation's own group vocabulary grows.

**Scope by client only, never by resource.** Rejected: a resource's
`requires` is exactly as much a gate as a client's
([reference/policy.md#resources--what-a-token-is-for](../reference/policy.md#resources--what-a-token-is-for)),
and a resource-audienced token that still carried every group the caller
holds would leak the same information a client-audienced one does today —
solving the problem for one shape of audience and not the other it was
built alongside.
