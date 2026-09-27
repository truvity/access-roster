# 0012 — Per-role scopes in the vocabulary

**Status:** Accepted
**Date:** 2026-09-27

Extends [0010](0010-a-declared-vocabulary.md).

## Context

0010 gave a thing a `scopes` list — the environments it exists in at all —
and checked every concrete grant's scope against it. That check is
thing-wide: every role a thing declares is valid on every scope the thing
declares, with no way to say otherwise. In practice a thing's roles do
not always share that shape. An `ssh` thing declared across `kernel`,
`devel`, `stage` and `prod` might have an `admin` role that legitimately
belongs on all four, and a `user` role meant only for a break-glass login
on `devel` — but the vocabulary as 0010 left it could not say that:
`kernel:ssh:user` validated exactly as cleanly as `devel:ssh:user`, even
though the second is the only one anyone meant to grant.

The cost is the same one 0010 exists to remove for scopes and things
generally: a name that looks checked but is not, discovered only when
someone notices a grant that should never have loaded. The difference
here is granularity — the mistake is not in the scope or the thing, both
of which are correctly declared, but in the combination of scope and
*role*.

## Decision

**A role's own value in `things.<t>.roles` may restrict it to some of its
thing's declared scopes.** The YAML shape stays backward-compatible: a
role's value is EITHER the plain list of implied roles 0010 already
accepts (`admin: [operator]`, `viewer: []`) OR an object naming `implies`
and/or `scopes` explicitly (`user: { scopes: [devel] }`), both keys
optional. `policy.RoleSpec.UnmarshalYAML` reads either shape into the same
struct; every policy written before this decision used the list form,
which still means exactly what it always did — a role restricted to
nothing, i.e. valid on every scope its thing declares.

**A role's own `scopes`, when declared, must be a non-empty subset of its
thing's own scopes**, checked at load: a scope the role names that is not
declared under `vocabulary.scopes` at all, a scope the role names that
its own thing does not have among `things.<t>.scopes`, and an explicit
empty list are each refused, distinctly, because each is a different
authoring mistake.

**A concrete grant is refused when the role does not cover its scope**,
checked after the existing thing-scope check and reported distinctly from
it: `kernel:ssh:user` is refused with a message naming the role's own
scopes (`role "user" of thing "ssh" is valid only on scopes [devel]`),
never conflated with `ssh` not declaring `kernel` at all, which is a
different, already-existing refusal.

**A mapping wildcard skips a combination the role disallows, exactly like
it already skips a thing that lacks the role.** `*:ssh:user` expands to
`devel:ssh:user` alone; `kernel`, `stage` and `prod` are left out
silently, the same way `devel:*:viewer` already silently leaves out a
thing with no `viewer` role. The existing "a wildcard that expands to no
group is refused" rule gains one more reason a wildcard can come back
empty — every candidate ruled out by the role's own scope restriction —
and `Vocabulary.emptyWhy` explains that reason by name rather than
folding it into the generic sensitivity message.

**An `implies` edge is refused at load when its target does not cover
every scope its source does.** `admin: [user]` where `admin` is valid on
every scope (the default) and `user` restricts itself to `devel` alone is
refused, naming the scope the mismatch would have lost (`role "admin"
implies "user", but "user" is not valid on scope "kernel", which "admin"
is`). Silently intersecting the two — granting `admin` only as much
`user` as `user` itself covers — was rejected: see Alternatives.

## Consequences

**A conservative default**, matching 0010's own posture: a role that
declares no `scopes` restricts nothing, so no existing vocabulary changes
shape or behaviour by upgrading past this release. Every table in
[reference/policy.md#vocabulary](../reference/policy.md#vocabulary) and
[taxonomy.md](../taxonomy.md) that already worked in terms of "the role
exists on the thing" now also means "and the role covers this scope,"
which is a no-op check for a role that names no `scopes` of its own.

**The inheritance rule is a real constraint on how a ladder may be
authored**, not just a validation nicety. A thing whose most-restricted
role sits below a broader one in the ladder — `user` scoped to `devel`
implying `admin` which is valid everywhere — is fine, since implying
*upward* in coverage is exactly what it looks like. The mistake this
catches is a broader role implying a narrower one: `admin` (everywhere)
implying `user` (`devel` only) can never be declared this way once
`user`'s restriction exists; the ladder has to be re-shaped, or `admin`'s
`implies` has to point at a role that covers what `admin` does.

**Explainability keeps its shape.** `policy.Result`'s `Held`, `Key` and
`Implies` fields ([0010](0010-a-declared-vocabulary.md#decision)) need no
change: a role-scope restriction changes which grants exist to be held or
implied, not how a hold is recorded once it exists.

## Alternatives considered

**Intersecting scopes across an `implies` edge**, rather than refusing a
mismatch: `admin` (everywhere) implying `user` (`devel` only) would
silently grant `user` on `devel` alone wherever `admin` is held, with no
error. Rejected: it is exactly the kind of silent narrowing 0010 already
rejected once, for the same reason — an author reading `admin: [user]`
would reasonably expect holding admin anywhere to hold user there too,
and a ladder that quietly does not do that for some scopes is a footgun
discovered by someone missing access, not by the loader.

**Scoping at the `implies` edge itself**, rather than on the role
(`admin: [{role: user, scopes: [devel]}]`). Rejected: it moves the
restriction to the wrong place. A role's own scopes describe what the
role legitimately grants, once, however it is reached — directly or
through any number of `implies` edges — while scoping the edge would let
two different roles imply `user` with two different scope subsets,
answering "which scopes does `user` cover" with "it depends which role
you ask," which is not a question this schema should have two answers
to.

**A thing-level default scope for a role name shared across things**
(declaring `user` scoped to `devel` once, applying to every thing with a
`user` role). Rejected: 0010 already settled that a thing's role ladder
is the thing's own — `admin` on `k8s` and `admin` on `argocd` share
nothing but a name — and a cross-thing default for a role's scopes would
quietly resurrect exactly the coupling that decision closed off.
