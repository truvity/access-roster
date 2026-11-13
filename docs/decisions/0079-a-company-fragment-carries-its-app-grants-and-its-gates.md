# 0079 — A company fragment carries its App grants and its gates

**Status:** Proposed (2026-11-13). Amends [0078](0078-a-company-access-fragment-is-owned-rows-checked-against-a-ceiling-and-by-effect.md)
(a company access fragment is owned rows, checked against a ceiling and by effect).
**Date:** 2026-11-13

## Context

ADR 0078 lets a company state its people, projects, bindings, CI jobs and workloads, and holds them to a ceiling. Two
things a company does every week still need a change by the installation:

- **A CI job that may ask for a GitHub App token.** A job row is only half of it. The App's `grants` list says which
  group may ask for which repositories with which permissions, and that list is the installation's. A company that adds
  a release job for a new repository can write the job and not the grant, so the job opens nothing.
- **A sign-in gate in front of a company's own site.** A gateway asks the issuer to sign a person in before it serves
  the site. That needs a client, and ADR 0078 left clients out: "They need a client-ownership guard (a client id
  prefix, owner groups only, redirects) once a company bundle carries them."

Both are bounded in the same terms as the rest of the fragment: which of the installation's Apps, at most which
permissions, which client ids, which hosts and which groups.

## Decision

1. **D1. A fragment carries App grants, by App id.** Each grant has the shape of an App's `grants` entry: a `group`,
   `repositories` and `permissions`. They are not rows of `compile.Model`; the installation adds an accepted owner's to
   the App's own list.
2. **D2. The ceiling names the Apps an owner may grant and the most each permission may be.** `github_apps` maps an App
   id to permission levels. The check refuses an App the ceiling does not name, a permission it does not name or names
   lower (read before write before admin), a repository with an owner (`org/name`), since the App's organisation is
   the owner, and a grant with no group, repository or permission. The group must match a group pattern of the
   ceiling, as a job's group must, so a job and its grant are held to the same patterns.
3. **D3. A fragment carries gates, a narrow kind of client.** A gate has a display name, a description, redirects,
   sign-out pages, the groups it requires and a TTL cap. Everything else is fixed: it is confidential, the issuer
   generates its secret, and PKCE is required. A gate cannot choose a kind, a secret, a signing algorithm, a session
   class, a groups override or a token exchange, and the decoder refuses those keys. `Gate.Client` returns the client
   the installation adds.
4. **D4. The ceiling names the gate ids and the zones.** `clients` are `path.Match` patterns of the ids an owner may
   declare, which is the client id prefix ADR 0078 asked for. `zones` are the DNS zones the owner holds. Every redirect
   and sign-out page is `https://`, has no user information, and is on a zone or a name under one. Every group a gate
   requires must match a group pattern of the ceiling.
5. **D5. Two codes, and the merge carries the result.** `owner-app` and `owner-gate` join the codes of ADR 0078. Two
   owners that declare one gate id are both refused with `owner-collision`. `MergeAll` returns an accepted owner's App
   grants and gates in its `Result`, so the installation adds exactly what was checked. A gate id that is already one of
   the installation's own clients is the installation's to refuse, since its clients are not in the model; the
   installation keeps its own ids out of every owner's `clients` patterns.
6. **D6. Nothing existing changes.** The new fields are optional, an existing fragment and ceiling decode as before,
   and the zero ceiling still refuses everything. The release is a minor.

## Consequences

- A company can add a release job and its App token for a new repository, and a sign-in gate for a site on its own
  zone, with no change by the installation once the installation reads the company's fragment.
- An App grant cannot reach outside the App's organisation, and cannot give more than the ceiling names. Which
  repositories an App is installed on is still decided on GitHub.
- A gate cannot redirect to another company's host and cannot admit a group outside the owner's ceiling.
- Whether a job holds any grant at all stays the installation's check: a job may be granted things this package does
  not see.
- Loading a company's fragment at run time, with a last good pin, is not part of this record. The installation merges
  at render time until it is.

## Alternatives considered

**A client of any kind in the fragment.** A company could then choose a public client with token exchange, or a
groups override. The ceiling would need a rule for every client field. Rejected: a gate is the one client a company
asked for.

**Hosts as patterns in the ceiling.** Patterns of redirect URIs are harder to read than zones and easy to write too
wide. Rejected: a zone is what a company holds in DNS.

**A grant check against the App's installed repositories.** That needs GitHub at check time, and the check runs in a
company's repository with no credentials. Rejected for the check; GitHub refuses a token for a repository the App is
not installed on.
