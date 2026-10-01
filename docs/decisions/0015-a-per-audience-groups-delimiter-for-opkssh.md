# 0015 — A per-audience groups delimiter, for opkssh's colon-splitting bug

**Status:** Accepted; refines [0004](0004-ssh-opkssh-and-the-secret-stores-ca.md) and [0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md)
**Date:** 2026-09-28

## Context

[0004](0004-ssh-opkssh-and-the-secret-stores-ca.md) and
[0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md) settled how
people authenticate over SSH: opkssh verifies this issuer's ID token
directly, with no certificate authority in between, and a server's own
policy reads `oidc:groups:<value>` against the `groups` claim
[0009](0009-a-default-signing-algorithm-and-per-audience-exceptions.md)
already lets a client pin `signing_alg: RS256` or `ES256` for, since
opkssh cannot verify this installation's ES384 default.

That leaves one gap 0004 and 0011 did not anticipate: **opkssh's own
policy parser splits its argument on every `:` and compares only the LAST
segment.** A server line written as

```
oidc:groups:devel:ssh:user
```

is not "match the group `devel:ssh:user`" to opkssh — it is "match
whatever the LAST `:`-separated field is", `user`, against a held group
of the same name. This schema's own grant shape,
`<scope>:<thing>:<role>` ([taxonomy.md](../taxonomy.md)), is built
entirely out of the one character opkssh's parser treats as a field
separator, so no group this schema would ever mint for opkssh can match
by name at all — not `devel:ssh:user`, not any other. Quoting the value
in the server's own policy file does not help: opkssh does not strip
quotes from what it compares against, so a quoted value simply never
matches either.

This is upstream's bug, not a gap in what this issuer mints — a `groups`
claim that says `devel:ssh:user`, verbatim, exactly as
[Groups → token, by deep merge](../reference/policy.md#groups--token-by-deep-merge)
promises every other relying party. Waiting for opkssh to fix its own
parser is the right long-term answer and is not this repository's to
schedule. In the meantime, opkssh-facing SSH access is unusable through
this issuer at all, for every installation that has adopted 0004 and
0011 otherwise.

## Decision

**A client row or a resource row may pin `groups_delimiter`, modelled
exactly on [0009](0009-a-default-signing-algorithm-and-per-audience-exceptions.md)'s
`signing_alg`: one more optional string on the same two tables, read by
the same audience-resolution rule, refused at load if it is not safe.**
Set, it rewrites every `:` in each name under THAT AUDIENCE's `groups`
claim to the configured string, after
[Groups in a token (scoping)](../reference/policy.md#groups-in-a-token-scoping)
has already decided which groups survive. `devel:ssh:user` becomes
`devel.ssh.user` under `groups_delimiter: "."` — a single field to
opkssh's own splitting, which its policy line can then match.

The full mechanism — validation, precedence, where it hooks into
minting — is
[reference/policy.md#groups-delimiter-per-audience-opkssh-interop](../reference/policy.md#groups-delimiter-per-audience-opkssh-interop).
What belongs here is why a character-level restriction on the delimiter
is not, by itself, the whole of what makes this safe:

**No single delimiter character can be proven absent from every group
name this schema could ever declare.** A Groups-table key is not
required to fit `<scope>:<thing>:<role>` at all — an installation may
declare any string as a group, [taxonomy.md](../taxonomy.md) calls this
"unconventional" and warns rather than refuses it — and even a concrete
grant's own segments carry no character restriction narrower than "not
empty, no `:`". So this schema refuses a delimiter built from the
alphabet a real grant is conventionally written in (`[A-Za-z0-9-]`,
literally every scope, thing and role example in this codebase) as the
character-level rule, and separately, at the SAME load, checks whether
the chosen delimiter would actually collide two of THIS policy's own
declared groups — the one check that is a genuine proof rather than a
convention, because it runs against the installation's real, finite set
of names rather than every string that could theoretically exist.

`.` is the documented example because it sits outside that alphabet and
outside every fixture, test and reference example this repository
declares — not because it is somehow structurally impossible in a group
name, which nothing in this schema can promise for every installation's
every future edit.

## Consequences

**opkssh is usable for the groups a `groups_delimiter`-pinned client
grants, without moving anything else.** Every audience that has not set
it keeps minting `devel:ssh:user` exactly as before; the shim is scoped
to the one relying party that needs it, the same shape 0009 chose for
`signing_alg`.

**This is an interop shim, not a naming change.** The policy's own
`groups` table, `requires`, `claims` and every `groups:` override still
read and write the REAL name, `devel:ssh:user` — the rewrite happens once,
at the moment a token for that one audience is minted, and nowhere else.
An operator reading the policy file never sees the rewritten spelling; an
operator reading THAT AUDIENCE's tokens always does.

**It is temporary.** The day opkssh's own parser treats its argument as
one opaque value rather than splitting on every `:`, `groups_delimiter`
has nothing left to do for that installation, and the row can simply be
removed — nothing else in this schema depends on it existing.

**An installation that points this at its own hub client locks itself
out of its own console.** [The service's own two groups, and scoping
them](../reference/policy.md#the-services-own-two-groups-and-scoping-them)
are parsed by splitting the SAME `:` this option removes; the reference
documentation says so plainly, and nothing here adds a code-level guard
against it, the same way nothing stops an operator from pinning an
unusable `signing_alg` to that same client either.

## Alternatives considered

**Fix it only in opkssh, upstream, and wait.** The right destination, and
not rejected — but it is not this repository's release to schedule, and
every installation that has already adopted 0004/0011 for opkssh is
blocked on SSH access for any group whose name contains `:` until it
lands, which is every group this schema's own taxonomy produces.

**Rename this installation's groups to avoid `:` entirely**, e.g. give
every group a single-segment alias. Rejected: it does not merely work
around opkssh's bug, it reverses [taxonomy.md](../taxonomy.md)'s whole
point — the name being the whole of the fact, `<scope>:<thing>:<role>`,
carried unchanged into every relying party's own binding — for every
consumer, to accommodate the one relying party that cannot read it, when
the fix can instead be scoped to exactly that one audience.

**A single installation-wide delimiter, instead of per-audience.**
Rejected for the same reason 0009 rejected a single installation-wide
signing algorithm: it would change what EVERY relying party's token says,
including every one that already reads `:`-separated names correctly
today, to work around a bug in exactly one of them.

**Let an operator write an arbitrary rewrite (a regex, a template)
instead of a single substitution character.** Rejected: the substitution
this issuer needs is one thing, replace the separator, and an expression
language buys generality nothing here asks for at the cost of a load-time
check that would have to reason about arbitrary functions instead of one
substitution whose injectivity a straightforward collision check can
actually decide.
