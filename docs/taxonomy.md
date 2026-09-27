# Taxonomy

The grammar every grant name follows, what each segment means, and the
anti-patterns a name falls into when it does not. This page is about the
NAME; what a name is checked against, when an installation opts in, is
[reference/policy.md#vocabulary](reference/policy.md#vocabulary).

## The grammar

Every grant is **`<scope>:<thing>:<role>`** — three segments, `:`
between, lowercase. *Role, on thing, in scope.*

| Segment | Is | Examples |
|---|---|---|
| `scope` | an environment, a tenant id, or `all` | `kernel`, `prod`, `devel`, `C0north`, `all` |
| `thing` | what the role is **on**: a subsystem, a project, an application | `k8s`, `argocd`, `grafana`, `shop`, `access-roster` |
| `role` | from that thing's own ladder | `viewer`, `operator`, `admin`, `deployer`, `editor` |

So: `prod:k8s:admin`, `devel:argocd:deployer`, `all:grafana:viewer`,
`all:access-roster:operator` — *admin of prod's Kubernetes*, *deployer of
devel's ArgoCD*, *viewer of the one Grafana this installation has*,
*operator of this hub, installation-wide*.

**Two-segment names are not grants, deliberately**, and are exempt from
everything on this page: `rung:<name>` carries a session lifetime;
`emp:<slug>` is a person, which per-scope bindings attach to. Neither is
*a role on a thing*. A reader who sees two segments knows it is not a
grant; there are no other two-segment families, and a name that is
neither three segments nor one of these two is unconventional — see
[reference/policy.md's validation section](reference/policy.md#validation-at-load).

## What `all` means

`all` is a scope like any other, with one constraint: it is for a thing
that exists **once per installation**, never once per environment. A
Grafana every environment shares is `all:grafana:viewer`; a Kubernetes
cluster that exists once per environment is `devel:k8s:viewer` and
`prod:k8s:viewer`, never `all:k8s:viewer` standing in for either — there
is no single Kubernetes an `all:k8s:*` name could mean.

Getting this backwards is the anti-pattern: naming a per-environment
thing with `all` erases which environment a role is actually held over,
and a mapping wildcard (below) that swept it in would then reach every
environment through one scope that was never supposed to mean that.

## Sensitive scopes

A [declared vocabulary](reference/policy.md#vocabulary) marks a scope
`sensitive` — `kernel` and `prod`, typically, the two an installation
least wants reached by anything less deliberate than a scope named
outright. It changes exactly one thing: a [mapping
wildcard](#mapping-wildcards) never expands into it. A concrete grant
naming a sensitive scope is unaffected — `kernel:k8s:admin` is checked and
granted exactly as `devel:k8s:admin` is; what a person can never do is
reach `kernel` by writing `*:k8s:admin` and letting the wildcard sweep it
in along with everything else.

## Inheritance

A thing's roles form a ladder, declared as **explicit implies**: a role
name to the roles it directly implies. `admin: [operator]` means holding
admin also holds operator; whatever operator itself implies is operator's
own entry, and evaluation walks the chain — so a ladder can chain
(`admin` → `operator` → `viewer`) or branch (`admin` implying **both**
`deployer` and `operator`, each separately implying `viewer`).

Holding `S:T:admin` therefore also holds every role admin implies,
transitively, on the **same** `S:T`. This is applied once, at evaluation
— [reference/policy.md#groups--token-by-deep-merge](reference/policy.md#groups--token-by-deep-merge)
— so every downstream reader sees the expanded set without knowing
inheritance exists: a `requires` gate, a token's `groups` claim, a GitHub
team bound to `S:T:viewer` fed by someone who is only ever `S:T:admin`.

**There is no scope inheritance.** `all:x:admin` never implies
`devel:x:admin`, whatever the two things otherwise have in common — the
implies graph walks role, never scope, and the two are unrelated axes.
Declaring a role on `all` and expecting it to reach every environment is
the same backwards move as [naming a per-environment thing `all` in the
first place](#what-all-means): if an environment is meant to be reached,
name it.

## Per-role scopes

A role's own value may restrict it to some of its thing's declared
scopes — `ssh`'s `user` role valid on `devel` alone, even though `ssh`
itself also declares `kernel`, `stage` and `prod` — using an object form
(`user: { scopes: [devel] }`) in place of the plain implies-list one
(`admin: []`). See
[reference/policy.md#per-role-scopes](reference/policy.md#per-role-scopes)
for the full syntax and the load-time checks.

This is a second, finer axis than [what `all`
means](#what-all-means) and [sensitive
scopes](#sensitive-scopes): the *thing*'s `scopes` says which
environments it exists in at all, and a *role*'s own `scopes`, when
declared, narrows that further to the ones the role itself makes sense
on. `kernel:ssh:user` is refused even though `ssh` names `kernel`,
because `user` does not.

**Inheritance may not lose scope coverage.** A role that implies another
must cover no more scopes than the one it implies — `admin` (valid
everywhere) implying `user` (valid on `devel` alone) is refused at load,
because holding `kernel:ssh:admin` would otherwise imply a `user` role
that was never meant to reach `kernel`.

## Mapping wildcards

`*` is allowed in the **scope** and/or **thing** position of a
Groups-table key, and nowhere else — never in `requires`, a GitHub
binding, `claims` or `lifetimes`, and never in the role position:
`*:k8s:admin`, `devel:*:viewer`, but not `devel:k8s:*` and not `*:*:*`.
Wildcards need a [declared vocabulary](reference/policy.md#vocabulary);
without one, `*` is an ordinary character with no special meaning refused
at load, because nothing could say what it should expand to.

A wildcard key stands for every concrete `(scope, thing)` where the thing
declares both that scope and that role AND the role itself allows that
scope (see [per-role scopes](#per-role-scopes)), excluding [every scope
marked sensitive](#sensitive-scopes): `*:k8s:admin` reaches every
non-sensitive environment's Kubernetes admin group at once; `devel:*:viewer`
reaches every thing that has both a `devel` scope and a `viewer` role;
`*:ssh:user` reaches `devel:ssh:user` alone when `ssh`'s `user` role
restricts itself to `devel`, silently skipping `kernel`, `stage` and
`prod` the same way it skips a thing that lacks the role entirely. Whoever
matches the key's members or matchers is in **all** of those concrete
groups, unioned with whatever concrete keys separately match, and then
[inheritance](#inheritance) applies on top. Nothing past evaluation ever
sees the wildcard itself — a token, a `requires` gate and a GitHub
binding all see only concrete names.

**A wildcard that expands to nothing is refused, not silently accepted.**
A `groups` key nobody is ever in is the one failure this vocabulary
exists to catch, so an empty expansion fails the load rather than sitting
in the file looking like it does something: `prod:*:viewer` where `prod`
is sensitive is refused by naming the sensitive scope directly and
pointing at a real concrete group to write instead; `devel:*:admins`
where no declared thing has an `admins` role, `*:k8s:viewer` where every
scope `k8s` declares happens to be sensitive, or `kernel:*:user` where
every thing's `user` role restricts itself to scopes that never include
`kernel`, are refused with the generic *expands to no group* message and
the specific reason.

## Examples

| Name | Reads as |
|---|---|
| `prod:k8s:admin` | admin of prod's Kubernetes |
| `all:access-roster:operator` | operator of this hub, installation-wide |
| `C0north:access-roster:viewer` | viewer of one directory only |
| `*:k8s:admin` (Groups key only) | admin of every non-sensitive environment's Kubernetes |
| `devel:*:viewer` (Groups key only) | viewer of everything devel has that declares a viewer role |
| `devel:ssh:user` | user of devel's ssh, a role scoped to devel alone |
| `rung:sre` | a session lifetime, not a grant |
| `emp:alice` | a person, not a grant |

## Anti-patterns

- **A name that is not `<scope>:<thing>:<role>`** (or `rung:`/`emp:`,
  which are deliberately not grants). A reader who sees anything else has
  no way to tell a grant from a stray convention by looking, which is the
  whole reason the shape is fixed.
- **The identity provider's own vocabulary leaking through.**
  `cluster-prod:cluster:admin` said "cluster" twice because the two
  occurrences meant different things — the prefix was a mapper's residue,
  and the tier meant *Kubernetes*, which `k8s` says outright. See
  [design/trust.md#naming](design/trust.md#naming) for the full history.
- **An application role parked under a cluster's scope it has nothing to
  do with.** `cluster-prod:roster:operator` put a `thing` that is an
  application under a `scope` that is a tier, so nothing could tell an app
  role from a project role from a tier role by looking at the scope
  alone. Give the application its own `thing`.
- **Naming a per-environment thing with `all`**, or expecting a role on
  `all` to reach an environment — see [What `all`
  means](#what-all-means) and [Inheritance](#inheritance).
- **A mapping wildcard anywhere but a Groups-table key** — in `requires`,
  a GitHub binding, `claims` or `lifetimes`. Those name a caller's
  entitlement or a token's shape directly, in one concrete name a person
  reviewing the file can check; a wildcard there would make the same line
  mean something different depending on the vocabulary in force elsewhere
  in the file.
- **A role wildcard**, `S:T:*`, and its total form `*:*:*`. A role is
  never swept in — it is always the one thing a mapping wildcard key
  states outright, because "every role this thing has" is not a decision
  anyone actually wants to make by typing one character.
