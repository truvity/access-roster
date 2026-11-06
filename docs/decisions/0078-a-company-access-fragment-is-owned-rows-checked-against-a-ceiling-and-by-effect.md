# 0078 — A company access fragment is owned rows, checked against a ceiling and by effect

**Status:** Proposed (2026-11-06). Applies [0010](0010-a-declared-vocabulary.md) (one vocabulary for groups) and
[0018](0018-do-not-configure-what-the-product-knows.md) (the product's facts are not policy).
**Date:** 2026-11-06

## Context

An installation can serve several companies. One of them, the platform, owns the access matrix: the rungs, the scopes
and the levels each rung holds on each scope. The others own people and projects, and want to state in their own
repository who holds which group, which GitHub organisation or Slack workspace they bind, and which of their own
workloads and CI jobs may call in. The platform then merges what each company states into the matrix it renders.

Today nothing makes that safe. `compile.Roster` derives every table from one `compile.Model` and trusts it, and the
policy layers (`policy.Policy.Merge`, `sluisctl policy render`) merge by file name: a duplicate key is refused naming
the file, and the lists that merge additively (`github[org].ignore`, `exchange_limits`, the `exchange` lists, the
claims) have no notion of who declared an entry. Any layer can declare any group, claim, GitHub organisation or
matcher. The one ownership-like rule, `Conventions.OwnDirectory`, defers an installation-wide application grant for a
partner directory. It is a hook, and it refuses nothing.

A company that may only declare its own rows must therefore be held to three things the code does not check:

- **Whose rows.** A row names a group, a project, an organisation, a workspace or a place (a cluster or an account).
  Each belongs to one owner.
- **How far.** Each owner has a ceiling: the directories its people live in, the groups it may mint or be granted, the
  rungs it may add people to, the organisations and workspaces it holds and the places its workloads run.
- **What it does.** A company that joins a rung inherits every cell of that rung in the matrix. A check of the rows
  alone cannot see that.

An owner that fails the check must fail alone. Another company's last good configuration keeps applying.

## Decision

1. **D1. A fragment is a narrow, typed value, not a policy layer.** `policy/tenant.Fragment` carries only what a
   company may author: population additions to named rungs (no session duration), projects, application grants, GitHub
   and Slack bindings, CI jobs and workloads, all in the types of `policy/compile`. It has no scopes matrix, no scope
   facts, no vocabulary, no conventions, no lifetimes, no claims and no clients. Widening the matrix is not
   representable, and the decoder refuses an unknown key, so a typo or a matrix key is an error and not a silently
   ignored line.
2. **D2. A ceiling states the owner's reach, in the vocabulary the policy already has.** `tenant.Ceiling` holds the
   directories (email domains) every address and directory group of the owner must belong to; group patterns of the
   form `scope:thing:role`, where `*` matches one segment, as in the policy's group keys; the rungs the owner may
   extend; the GitHub organisations, Slack workspaces, clusters and accounts it holds. An installation authors it
   beside the company's registration, on a path only the platform's owners may change. The zero ceiling refuses every
   non-empty fragment, so a missing ceiling can never read as "no limit". `Ceiling.Scopes` lists the non-wildcard
   scopes in the group patterns, so a network-level destination ceiling in another tool can be cross-checked against
   the same authored data.
3. **D3. The check has two levels.** The input level refuses an address outside the directories, a rung outside the
   ceiling, a session duration, a GitHub organisation, a CI job's repository owner, a Slack workspace or a place the
   owner does not hold, and a key already declared by the base or by another owner. The effect level derives
   `compile.Roster` for the base and for the base with the fragment, and compares them. Every group that is new or
   gained a member or a matcher must match a ceiling pattern, every gained member must be in the directories, and
   anything else that changed (a removed member or matcher, a lifetime, the default lifetime, a deferred grant) is
   refused. The effect level is the guard. The input level is its early, base-free form, so a company can run it in
   its own repository without the platform's matrix.
4. **D4. A violation is a value with a stable code.** `owner-directory`, `owner-name`, `owner-collision`, `owner-rung`,
   `owner-github`, `owner-slack`, `owner-place`, `owner-effect` and `owner-empty-ceiling`, each with the owner, the
   path and a sentence naming what was refused. A list is sorted by owner, then path, so a refusal is the same twice.
5. **D5. An owner is valid as a whole or not at all.** `MergeAll` excludes an owner that has any violation and merges
   the others. The result does not depend on the order of the owners. A key declared by two owners, or by an owner and
   the base, refuses both owners and names both. A bundle that is partly acceptable is not partly applied: the owner
   keeps its last good pin, and nobody else is affected.
6. **D6. A reference to another company is not a fragment row.** A company that wants a group of another company, or
   a shared unit, asks the platform for a reviewed row in the base. The check refuses it in the fragment as an
   address outside the directories.
7. **D7. The platform company has no fragment path in the first release.** Its rows stay authored with the matrix.
   Whether any of them may be delegated later is a decision for the maintainer, not for this record.
8. **D8. Nothing existing changes.** The package is additive. With no fragments `MergeAll` returns the base, and
   `Roster` of a base split into fragments and merged equals `Roster` of the whole model, byte for byte. Existing
   goldens do not move. The release is a minor.
9. **D9. A test notices a new model field.** A test fails when `compile.Model` gains a field that `Fragment` neither
   carries nor lists as excluded, as `TestMergeCoversEveryField` does for the policy.

## Consequences

- A company can change its own people, projects and bindings without a review of the matrix, and cannot widen it.
- A company that joins a rung is bounded by the groups that rung derives, not only by the names it wrote. A new rule in
  `Roster` cannot widen a company without a ceiling that allows the result.
- The check is conservative. It refuses a change it cannot tell is harmless, and the maintainer widens the ceiling or
  reviews a base row.
- Two companies cannot share a group by writing it twice. A shared group is a base row.
- OIDC client declarations and claim fragments are not covered. They need a client-ownership guard (a client id
  prefix, owner groups only, redirects) once a company bundle carries them.
- The wire format of a company bundle's access section is defined outside this repository. This package decodes its own
  YAML and JSON, and the installation maps between them. A drift test joins this package once that format is released.

## Alternatives considered

**Check only the input.** Cheap, and it misses the case that matters: an allowed rung whose cells reach groups outside
the ceiling, and any later change of the derivation. Rejected.

**Guard the policy layers.** Layers can carry clients, claims and resources, so a ceiling over them is a second
policy language. Rejected for the first release; a fragment is the model the installation already resolves.

**Exclude one row, not the owner.** A bundle then applies in part, and reasoning about what a company holds needs the
list of rows that were dropped. Rejected: the owner keeps its last good pin.

**Allow extra directories in the ceiling for shared units.** It reopens the cross-company hole under a different
name, and a shared grant becomes a rule nobody reviews. Rejected for D6.

**Delegate the platform company's rows too.** A smaller first release is the safer one. Deferred to the maintainer.
