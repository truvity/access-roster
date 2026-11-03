# 0027 — Console roles are declared grants, and its pages are organised by the origin of what they show

**Status:** Accepted
**Date:** 2026-11-02

Proposal: [issue #831](https://github.com/truvity/sluis/issues/831).

## Context

The `console` actor is the operator API behind the browser. It checks the operator's delegation and routes each operator-set write to the actor that owns the record kind ([0002](/decisions/0002-families-of-actors/#the-four-families), [0004](/decisions/0004-the-data-model/#storage-classes)). What it shows and who may use it are not yet specified. v1's console showed every person, group, rule, session and connected system, with a dry run of what each controller would change, and offered connect and manage actions, under two roles: an installation-wide operator and viewer, and the same two scoped to one directory (parity rows [#831](https://github.com/truvity/sluis/issues/831) and [#832](https://github.com/truvity/sluis/issues/832); the v1 console roles reference, on `master`).

What v2 already decides: authority is declared and the console can never widen it, only tighten and configure operational records (0010); a person is granted things by a declared vocabulary of `<scope>:<thing>:<role>` ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary)); an operator's delegation is per company, plus an environment scope for the machine plane ([0008](/decisions/0008-boundaries-and-tenants/#boundaries)); every console page must show the origin, the lock state and the held objects of what it shows (0010, Consequences); and the browser holds no token ([Actors](/concepts/actors/)).

## Decision

### Roles

- **There are two roles, `operator` and `viewer`,** and nothing between them. They are grants of a thing `console` in the declared vocabulary: `<scope>:console:operator` and `<scope>:console:viewer`, where `operator` implies `viewer`. The scope is an environment, a company or `all`.
- **The scope carries v1's two levels.** `all` is the installation-wide role. A company scope gives the same role over what that company boundary owns: its directory, its integrations, its channels and its people records. v1's "owner of a connected system" is the company boundary that declares the integration.
- **The role is a grant like any other.** The console asks `policy` for the person's full set of grants, as `session` does, and checks the role locally. Role bindings are declared policy: nobody gets a console role from the console, because authority is declared only. A person's company administrator may bind roles of their own company by the delegation policy of [Policy](/reference/policy/#the-grants-of-one-tenant).
- **A viewer can cause no write.** Every read is open to a viewer; every connect, change, confirmation or switch needs an operator of the right scope (REQ-UX-009).
- **Reading has its own limit.** A value of `personal` sensitivity is shown to a role that may see it, and a secret never: its reference only ([0004](/decisions/0004-the-data-model/#treatment)).

### Pages follow origins

- **A page is one of five kinds, by the origin of what it shows:** declared (read-only, with its source and digest), operator-set (editable by an operator), learned (with the time it was observed and its age), derived (with the cursor it was built to), and issued (with who issued it and when). Every field on every page shows its origin and, for a declared field, that it is locked; every page lists the objects held because they exist both as declared and as operator-set ([0004](/decisions/0004-the-data-model/#storage-classes), REQ-UX-010).
- **The sections of the console,** in the order a person uses them:

  | Section | Shows | Origin | Operator actions |
  |---|---|---|---|
  | People and sessions | People, their sessions and agent sessions, and the chain by which a person holds each grant | learned, issued | Revoke a session or a consent; suspend a person |
  | Directories and groups | Directory groups, internal groups and who holds them, with the age of the facts | learned, declared | Connect or disconnect a directory; choose the synced groups |
  | Rules | The effective policy, its bindings and the template links | declared | Link a template within the delegation policy |
  | Integrations | Each connected system and its dry run: what its reconciler would change, and what is held | declared, learned, issued | Connect a system; wake a pass; confirm a held change |
  | Channels | Channels bound in policy (read-only) and channels made on the console | declared, operator-set | Create, change and delete console channels; request a pass |
  | Clients and resources | Declared clients, resources and the metadata-document gate; secret versions, never their value | declared, issued | Generate or rotate a client secret |
  | Backup and restore | The latest archives, rehearsals and the restore preview | issued | Start a backup |
  | Switches | Tighten-only switches and their generation | operator-set | Turn recovery off; pause a reconciler |
  | Audit | A link to the audit front, which has its own console ([0028](/decisions/0028-audit-pieces/#the-audit-front)) | none | None |

- **The chain by which a person holds a grant** and the dry run of a reconciler are the console's two explanations. The first is the determining policies that `policy` returns with an answer ([0007](/decisions/0007-policy-and-sealed-grants/)); the second is the outcome of a `dry_run` pass ([0026](/decisions/0026-reconcilers/#the-contract)). The console computes neither.

### Writes

- **A connect action starts a vendor flow and never holds a vendor credential.** The console starts the GitHub App manifest flow or the Slack authorization; the integration completes it and keeps the key as a vendor-issued secret and the ids as pins ([Connecting](/integrations/connecting/)).
- **Each write goes to the owner of the kind** and is audited under the person's name, with the previous and new revision and the full new value apart from secrets (0010). A confirmation of a held change is an issued record of that act.
- **An action that cannot be undone is an explicit opt-in,** off by default and checked against the vendor first. The same holds for turning recovery off, which is tighten-only and moves back only by a declared change with a new generation.

## Consequences

- The console has no role store of its own and no grant it can give; a stolen operator session can tighten and configure operational records and cannot widen authority.
- Roles are added with the vocabulary, so a new thing with its own operator needs a declared thing, not code in the console.
- The page list is the checklist for parity rows #831 and #832; a section without an owning actor or record kind has no page.
- Because pages are by origin, the console needs the origin annotations of the schema at run time. They are generated into the console's API description.
- Requirements: REQ-UX-009 to REQ-UX-011 are added.

## Roads not taken

- **Roles stored by the console and assigned on its pages.** It would be operator-set authority, which 0010 refuses, and the console would hold the right to widen its own reach.
- **Three or more roles (auditor, integration manager, support).** v1 managed with two; a finer split is a thing and a role in the vocabulary when a consumer needs it.
- **Roles read from the token's groups claim.** A token carries only the groups its audience requires ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)), and a role would travel to places that should not see it.
- **A page per v1 controller.** It would mirror v1's internals; the same record kinds are reached through their section instead.
- **The console computes the dry run and the explanation itself.** It would re-implement `policy` and every provisioner and drift from them.
- **Embed the audit search in the console.** The audit installation has its own front and its own console; the operator console would hold a second reader.

## Follow-ups

- The console actor: [#960](https://github.com/truvity/sluis/issues/960); the read model and roles [#831](https://github.com/truvity/sluis/issues/831); the connect and manage actions [#832](https://github.com/truvity/sluis/issues/832); host enrolment pages [#967](https://github.com/truvity/sluis/issues/967).
