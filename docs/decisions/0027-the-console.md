# 0027 — The console checks delegation and routes writes, and its pages follow the storage class and profile of what they show

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #831](https://github.com/truvity/sluis/issues/831).

## Context

The `console` actor is the operator API behind the browser ([0002](/decisions/0002-families-of-actors/#the-console)). It checks the operator's delegation and routes each write to the actor that owns the kind. What it shows and who may use it are not yet specified. v1's console showed every person, group, rule, session and connected system, with a dry run of what each controller would change, and offered connect and manage actions, under two roles: an installation-wide operator and viewer, and the same two scoped to one directory (parity rows [#831](https://github.com/truvity/sluis/issues/831) and [#832](https://github.com/truvity/sluis/issues/832); the v1 console roles reference, on `master`).

What v2 already decides:

- Authority is declared. A kind is Fixed, Operable or Tenant-adjustable, and the console can only tighten and configure what the profile of a kind allows ([0004](/decisions/0004-the-data-model/#profiles)).
- A person is granted things by a declared vocabulary of `<scope>:<thing>:<role>` ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary)).
- An operator's delegation is per tenant, plus a scope for the boundary ([0008](/decisions/0008-boundaries-and-tenants/#tenants)).
- Every run-time write is authorised for a named person and audited under that name ([0004](/decisions/0004-the-data-model/#one-writer-per-kind)).
- The browser holds no token: the session is a cookie that key@ seals ([0002](/decisions/0002-families-of-actors/#the-console)).

## Decision

### Roles

- **There are two roles, `operator` and `viewer`,** and nothing between them. They are grants of a thing `console` in the declared vocabulary: `<scope>:console:operator` and `<scope>:console:viewer`, where `operator` implies `viewer`. The scope is one the vocabulary declares: an environment, a company (a tenant) or `all`.
- **The scope carries v1's two levels.** `all` is the installation-wide role. A tenant's scope gives the same role over what that tenant owns: its connections, its clients, its policy links and its people. v1's "owner of a connected system" is the tenant that made the connection ([0025](/decisions/0025-integrations/#adapters-and-connections)).
- **The role is a grant like any other.** The console asks `policy` for the person's full set of grants, as `session` does, and checks the role locally. Role bindings are declared policy: nobody gets a console role from the console, because authority is declared only. A tenant admin may bind roles of its own tenant by the delegation policy of [0007](/decisions/0007-policy-and-sealed-grants/#template-links).
- **A viewer can cause no write.** Every read is open to a viewer; every connect, change, confirmation or switch needs an operator of the right scope (REQ-UX-009).
- **Reading has its own limit.** A sealed value that holds personal data is opened at key@ for a role that may see it, and a secret never: its reference only ([0004](/decisions/0004-the-data-model/#treatment)).

### Pages

- **A page shows kinds, and each field shows what governs it.** For every kind the page shows its storage class and profile, and by that what the operator can do with it:

  | Class and profile | What the page offers |
  |---|---|
  | Config | Read-only, with the signed document it came from and its version; a change is made in the repository that writes config, never here |
  | Secret | The reference to the secret, never its value |
  | Durable, Operable or Tenant-adjustable | Editable by an operator of the right scope, within the bounds of config; the page shows the bound |
  | Durable, written by the owner only | Read-only, with the actor that owns it |
  | Temp | Read-only, with its age and when it expires |

- **A layered kind shows its provenance.** The store returns, with a read of a layered kind, which layer each part came from ([0004](/decisions/0004-the-data-model/#layers-and-the-direction-rule)), and the page shows it. An operator sees why a value cannot be changed and where it comes from (REQ-UX-010).
- **The sections of the console,** in the order a person uses them:

  | Section | Shows | Operator actions |
  |---|---|---|
  | People and sessions | People, their session chains and the consent recorded on an agent chain, and the chain by which a person holds each grant | Revoke a chain or a consent; suspend a person |
  | Directories and groups | `DirectoryConnection`, the directory facts with the age of each, and the internal groups with who holds them | Connect or disconnect a directory; choose the synced groups |
  | Rules | The effective policy of the tenant with its provenance, its bindings and its template links | Link a template within the delegation policy |
  | Integrations | Each `Integration`, each connection of the tenant, and the dry run of each reconciler: what it would change, and the `HeldChange` entries | Connect a system; confirm a held change |
  | Channels | Channels bound in config (`ReconcileTarget`, read-only) and channels made on the console (`ConsoleChannel`) | Create, change and delete console channels |
  | Clients and resources | Installation clients and templates (config), the tenant's clients, the metadata-document gate; secret versions, never their value | Generate or rotate a client secret |
  | Backup | The `BackupPlan` (config) and the latest archives and drills, from their audit facts | None; a restore is a command of store@ ([0010](/decisions/0010-backup-and-recovery/#restore)) |
  | Switches and log levels | The `Switch` entries and the `LogLevelOverride` entries with their expiry | Turn recovery off; pause a reconciler; raise a log level for a while |
  | Audit | A link to the audit front, which has its own console ([0028](/decisions/0028-audit-pieces/#the-audit-front)) | None |

- **The chain by which a person holds a grant** and the dry run of a reconciler are the console's two explanations. The first is the determining policies that `policy` returns with an answer ([0007](/decisions/0007-policy-and-sealed-grants/)); the second is the outcome of a `dry_run` pass ([0026](/decisions/0026-reconcilers/#the-contract)). The console computes neither.
- **A section without an owning actor or kind has no page.** The page list is the checklist for parity rows #831 and #832.

### Writes

- **The console routes each write to the owner of the kind.** It checks the operator's delegation and calls the owner, which validates the write with its own logic: `session` for people and their connections, `exchange` for what a tenant has configured (its clients, links and settings), the adapter of a vendor for its connections, held changes and channels ([0004](/decisions/0004-the-data-model/#one-writer-per-kind)). The store refuses any writer but the owner.
- **The console itself writes exactly two kinds, `Switch` and `LogLevelOverride`.** No actor has domain logic for either, so the store checks their schema, bounds and direction from the kind registry, which was the owner's validation for them. A `Switch` only tightens (recovery off, a reconciler paused, sign-in paused), and deleting it returns to what config says. A `LogLevelOverride` is a loosening, so it expires: 1 hour by default and 24 hours at most ([0016](/decisions/0016-telemetry/)).
- **A connect action starts a vendor flow and never holds a vendor credential.** The console starts the flow in the adapter, the GitHub App manifest flow or the Slack authorization for example; the adapter completes it and writes the connection with its credential sealed, as the kinds of [0025](/decisions/0025-integrations/#adapters-and-connections) say ([Connecting](/integrations/connecting/)).
- **Every write is audited under the person's name,** with the previous and new version and the full new value apart from secrets. A confirmation of a held change is a write of the adapter that owns the target, made on the person's behalf.
- **An action that cannot be undone is an explicit opt-in,** off by default and checked against the vendor first.

## Consequences

- The console has no role store of its own and no grant it can give; a stolen operator session can tighten and configure what the profiles allow and cannot widen authority.
- The console writes two kinds and needs no write rule for any other: a flaw in it reaches those two and the routing, not the kinds of other actors. Each owner needs validation and tests for the writes it accepts.
- Roles are added with the vocabulary, so a new thing with its own operator needs a declared thing, not code in the console.
- Because pages follow the class and profile of a kind, the console needs those annotations of the kind registry at run time. They are generated into the console's API description.
- A section without an owner has no page, so a gap in the owners shows as a gap in the console.
- Requirements: REQ-UX-009 to REQ-UX-011 are added.

## Roads not taken

- **Roles stored by the console and assigned on its pages.** It would be authority written at run time, which the profiles refuse, and the console would hold the right to widen its own reach.
- **Three or more roles (auditor, integration manager, support).** v1 managed with two; a finer split is a thing and a role in the vocabulary when a consumer needs it.
- **Roles read from the token's groups claim.** A token carries only the groups its audience requires ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)), and a role would travel to places that should not see it.
- **A page per v1 controller.** It would mirror v1's internals; the same kinds are reached through their section instead.
- **The console computes the dry run and the explanation itself.** It would re-implement `policy` and every provisioner and drift from them.
- **Embed the audit search in the console.** The audit installation has its own front and its own console; the operator console would hold a second reader.
- **Route every write to an owner, `Switch` and `LogLevelOverride` included.** `LogLevelOverride` has no owner at all, and a switch per owner would multiply kinds.
- **A console that writes every operator and tenant-admin kind.** It would lose the validation of the owner for clients, connections and links.

## Follow-ups

- The console actor: [#960](https://github.com/truvity/sluis/issues/960); the read model and roles [#831](https://github.com/truvity/sluis/issues/831); the connect and manage actions [#832](https://github.com/truvity/sluis/issues/832); host enrolment pages [#967](https://github.com/truvity/sluis/issues/967).
