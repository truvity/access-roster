# 0010 — A declared vocabulary: things, scopes, roles, inheritance and mapping wildcards

**Status:** Accepted
**Date:** 2026-09-26

## Context

Every grant is named `<scope>:<thing>:<role>`
([design/trust.md#naming](../design/trust.md#naming),
[reference/policy.md#naming](../reference/policy.md#naming)), and the
loader has never checked what a segment MEANS — only that the shape has
three non-empty parts. `prod:k8s:admin` and `prod:k8s:adimn` are both
accepted; the second is a typo that grants nobody anything and is
discovered, if at all, by someone noticing a group nobody holds, or by
someone who should have access not having it.

Two costs follow from that, and they grow with an installation rather
than shrink. First, there is no way to say that `admin` of a thing should
also count as its `operator` and its `viewer` — every consumer (a
client's `requires`, a GitHub team binding) has to name every role that
should admit it, by hand, and a role added to the ladder later means
auditing every consumer that should have picked it up automatically.
Second, a caller that should reach "every environment's admin of this one
thing" or "every thing's viewer in this one environment" has no way to
say so except by being placed in one group per environment or per thing,
by hand, which does not scale as either axis grows — and there was no way
to say "except the sensitive ones" even if there had been a way to say
"every one."

## Decision

**An installation may declare a `vocabulary`**: the scopes and things
that exist, each thing's declared scopes, and each thing's role ladder as
explicit `implies` edges (`admin: [operator]`, not an ordered list — see
Alternatives). It is OPTIONAL and, once declared, STRICT: no vocabulary
changes nothing; a declared one makes every concrete grant name anywhere
in the file — `groups` keys, `claims` keys, `lifetimes` keys, every
`requires`, every GitHub binding — a claim the loader checks rather than
trusts, refusing to load and naming the offending name and the reason
when one does not fit.

**Inheritance is explicit and one-hop, closed by evaluation.** A role's
`implies` list names the roles it directly grants; a chain (`admin` →
`operator` → `viewer`) or a branch (`admin` implying both `deployer` and
`operator`) is expressed by what each role's own entry says, and the
transitive closure is computed once, in evaluation
([reference/policy.md#groups--token-by-deep-merge](../reference/policy.md#groups--token-by-deep-merge)),
so a `requires` gate, a token's `groups` claim and GitHub team
reconciliation all see the expanded set without any of them knowing
inheritance exists. It never crosses scope: holding a role on `all`
never implies the same role on an environment, and the reverse never
holds either — the two are unrelated axes, and mixing them is exactly the
mistake `all` invites when used for a thing that is not once-per-installation
([taxonomy.md](../taxonomy.md)).

**Mapping wildcards are a `groups`-key-only shorthand, not a new kind of
grant.** `*` in the scope and/or thing position of a `groups` key
(`*:k8s:admin`, `devel:*:viewer`) expands, against the vocabulary, into
every concrete `(scope, thing)` pair that declares the named role,
EXCLUDING every scope marked `sensitive`. A caller matched by the
wildcard key holds every one of those concrete groups, unioned with
whatever concrete keys also match, before inheritance runs. A role
wildcard is always refused, and so is `*:*:*` — a role is never swept in,
because "every role this thing has" is not a decision a mapping shorthand
should make silently. The wildcard needs a declared vocabulary; nothing
past evaluation — a `requires` gate, a GitHub binding, a token — ever
sees anything but a concrete name.

**Explainability is data, not UI, in this change.** `policy.Result`'s
`Held` gains `Key` (the `groups` key that matched directly — a wildcard's
own spelling when that is how it happened) and `Implies` (the concrete
group whose role, one hop at a time, implied this one). A caller may hold
one group through more than one route, and `Held` carries one entry per
route rather than picking a winner. The console page that renders this is
a separate, later change.

## Consequences

**A conservative default.** No installation is forced to declare a
vocabulary, and none of today's policies changes shape or behaviour by
upgrading past this release — proven by a test that removing this whole
feature from a policy with no `vocabulary` table changes nothing it
evaluates.

**A vocabulary is a real commitment once declared.** Adding a thing, a
scope or a role later is additive and safe; renaming one is exactly as
disruptive as renaming a grant always was, because the vocabulary's names
ARE the grant's segments. An installation that wants the safety net
should expect to write it once, early, and grow it rather than restructure
it.

**This narrows 0006's scoping to a smaller, sharper claim.** 0006 said a
token would carry only the groups relevant to its audience but left the
exact mechanism for what "relevant" means to whatever schema shipped it.
This decision is that schema's naming half: a token minted for an
audience that declares a thing will eventually carry that audience's
`<scope>:<thing>` roles specifically — the grants that are actually about
it — rather than every group the caller holds. Scoping the token itself
(the mechanism that reads a client's or resource's declared things and
narrows `groups` to them) is not part of this change and ships later; what
this decision provides is the vocabulary such a mechanism will read.

**GitHub team reconciliation changes what it sees, not how it works.** A
team bound to `S:T:viewer` is now fed by anyone in `S:T:admin` too,
automatically, wherever a vocabulary declares that admin implies operator
implies viewer (or admin implies it directly). An installation relying on
the OLD behaviour — admin holders excluded from a team bound only to
viewer — must declare no vocabulary, or declare one whose ladder does not
imply that far.

## Alternatives considered

**An ordered-list role syntax** (`roles: [viewer, operator, admin]`,
each implying everything before it). Rejected: it cannot express a
branch — argocd's `admin` implying both `deployer` and `operator`, which
themselves do not imply each other — without inventing a second shape
for the branching case anyway. Explicit `implies` expresses a line as a
special case of a graph for free and never needs a second syntax.

**Warn-only, matching the existing `Unconsumed` lint's posture.**
Rejected for the fit checks specifically: `Unconsumed` warns because an
installation may legitimately declare a group ahead of its consumer, and
nothing is wrong yet. A grant naming an undeclared scope, thing or role
is not "not yet" — it is a name that was never going to mean what its
author intended, at the moment it is read. A warning here would let a
production rollout carry a typo indistinguishable from a real grant, in
a mechanism whose entire purpose is not doing that. Wildcards keep the
same posture as everything else in this schema: strict.

**Scope inheritance for `all`** (a role on `all` also implying the same
role on every named environment, or the reverse). Rejected: it collapses
two questions — "does this thing exist once or once per environment"
and "does holding a role here also hold it everywhere else" — into one
axis, and an installation that got the first one right by using `all`
correctly would then have no way to say it did NOT mean the second.
Keeping the axes separate means an operator who wants "every environment"
says so as a mapping wildcard, explicitly, rather than getting it as an
unannounced side effect of naming a thing `all`.

**Token-side wildcards** (minting `devel:*:viewer` itself into a token,
letting a relying party expand it). Rejected: it moves the very thing
0006 exists to prevent — every relying party independently re-implementing
the same expansion, or reading a token whose shape it cannot check without
also holding the vocabulary — back downstream, off the one process that
already has both. Rule 4's own text says it plainly: a token sees only
concrete names.

**A closed role list in code**, shipping `viewer`/`operator`/`admin` as
the only roles this schema knows, the way [`Client.Kind`](../reference/policy.md)
is a fixed set. Rejected: a role ladder is exactly the part of this
schema that must vary per installation and per thing — argocd's ladder
branches, grafana's does not — and a role list fixed in code would mean
every installation with a different shape waits for a release to express
it, the opposite of what a declared, installation-owned vocabulary is
for.

**Composition bundles in the policy** (a `bundles` table naming sets of
grants a caller is placed in at once, authored here rather than upstream
of this file). Rejected: this repository's schema is deliberately not an
authoring layer — an installation's own tooling composes bundles, roles
by team, or anything else upstream, and hands this file the resolved
`groups` table, exactly as `docs/design/trust.md` already draws that
line. A vocabulary that constrains NAMES fits this file; a mechanism that
COMPOSES memberships belongs to the estate, one layer up.
