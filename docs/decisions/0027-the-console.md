# 0027 — The console checks delegation and routes writes, and its pages follow the storage class and profile of what they show

**Status:** Accepted
**Date:** 2026-11-07

Proposal: [issue #831](https://github.com/truvity/sluis/issues/831).

## Context

The `console` actor is the operator API behind the browser ([0002](/decisions/0002-families-of-actors/#the-console)). It checks the operator's delegation and routes each write to the actor that owns the kind. What it shows and who may use it are not yet specified. v1's console showed every person, group, rule, session and connected system, with a dry run of what each controller would change, and offered connect and manage actions, under two roles: an installation-wide operator and viewer, and the same two scoped to one directory (parity rows [#831](https://github.com/truvity/sluis/issues/831) and [#832](https://github.com/truvity/sluis/issues/832); the v1 console roles reference, on `master`).

What v2 already decides:

- Authority is declared. A kind is Fixed, Operable or Tenant-adjustable, and the console can only tighten and configure what the profile of a kind allows ([0004](/decisions/0004-the-data-model/#profiles)).
- A person is granted things by a declared vocabulary of `<scope>:<thing>:<role>` ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary)).
- An operator's delegation is per tenant, plus a scope for the boundary ([0008](/decisions/0008-boundaries-and-tenants/#tenants)).
- Every run-time write is authorised for a named person and audited under that name ([0004](/decisions/0004-the-data-model/#one-writer-per-kind)).
- The browser holds no token: the session is a cookie that key@ seals ([0002](/decisions/0002-families-of-actors/#the-console)).

What v1's console learned, read on `master` on 2026-11-07, and what the first draft of this record would have repeated:

- **A read can disclose.** `Explain`, which says what any person would be granted, was open to every viewer for five weeks until it was restricted to operators and every look-up audited ([f261acc32](https://github.com/truvity/sluis/commit/f261acc32), 2026-10-11). The first draft of this record said "every read is open to a viewer".
- **A refusal can disclose.** A caller who could not see a record got a different answer from one who could, until "no such record" was answered before any role check ([f510d73e0](https://github.com/truvity/sluis/commit/f510d73e0), 2026-10-01).
- **A flow with no session in it fails after the vendor has agreed.** The consent callback ran on a route that carried no operator, and refused the operator after the vendor had granted consent ([99f6c679a](https://github.com/truvity/sluis/commit/99f6c679a), 2026-09-09).
- **An irreversible click needs more than a click.** Sessions could be revoked, and a directory disconnected, with no confirmation until 2026-10-09 ([20e311e1a](https://github.com/truvity/sluis/commit/20e311e1a)); and revoking every session row left the browser's sign-in standing ([086e811af](https://github.com/truvity/sluis/commit/086e811af), 2026-09-11).
- **A page found by hand is found late.** Nearly every v1 console defect was found by a person looking at the live page, because the 26 test files of the v1 front end tested pure models only (counted 2026-11-07).

## Decision

### Roles

- **There are two roles, `operator` and `viewer`,** and nothing between them. They are grants of a thing `console` in the declared vocabulary: `<scope>:console:operator` and `<scope>:console:viewer`, where `operator` implies `viewer`. The scope is one the vocabulary declares: an environment, a company (a tenant) or `all`.
- **The scope carries v1's two levels.** `all` is the installation-wide role. A tenant's scope gives the same role over what that tenant owns: its connections, its clients, its policy links and its people. v1's "owner of a connected system" is the tenant that made the connection ([0025](/decisions/0025-integrations/#adapters-and-connections)).
- **The role is a grant like any other.** The console asks `policy` for the person's full set of grants, as `session` does, and checks the role locally. Role bindings are declared policy: nobody gets a console role from the console, because authority is declared only. A tenant admin may bind roles of its own tenant by the delegation policy of [0007](/decisions/0007-policy-and-sealed-grants/#template-links).
- **A viewer can cause no write.** Every connect, change, confirmation or switch needs an operator of the right scope (REQ-UX-009).
- **The browser is not an authority.** `WhoAmI` returns the grants so the page can hide a control, and a hidden control is a hint: every call is authorised again on the server.

### Reads

- **A read has one of three classes.** R0 is the caller's own data: their grants, their sessions and the chain by which they hold each grant. R1 is a kind in the caller's scope, including a fact that a directory or vendor reported, such as who is in a group: open to a viewer of that scope. R2 is a read that computes or enumerates what another person may do or hold through `policy`: the chain by which another person holds a grant, an effective-access look-up for a subject, and a listing of other people's sessions.
- **An R2 read is an operator's read and is audited.** A viewer is refused. The console writes an audit record under the operator's name that names the subject, before it answers (REQ-UX-018, REQ-UX-022). A viewer sees their own chain (R0) and the people and groups of their scope (R1), not the chain of anyone else. Placing the membership of a group in R1 was a decision taken while this record was written up, and was not put to the maintainer on its own; the alternative is under Roads not taken.
- **`Explain` takes a subject and, optionally, a target** (a resource and an action), and names the policies that decided. The target form is part of the call from the first version, so the access explorer that comes after parity needs no new call (REQ-UX-034).
- **A record outside the caller's scope answers as a missing record,** before any check of role, in every read and every write. The answer to a record the caller may not see and to one that does not exist is the same body (REQ-UX-019).
- **Reading has its own limit.** A sealed value that holds personal data is opened at key@ for a role that may see it, and a secret never: its reference only ([0004](/decisions/0004-the-data-model/#treatment)).
- **A list is paged and a value says where it is from.** A list is paged by key with a capped page size. Every answer that carries a cached or remote fact carries its `as_of` and `source` ([States](/decisions/0027-the-console/#states)).

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
  | Overview and setup | Counts of what needs an operator, each a link to the thing counted, and the day-one checklist until it is done | None |
  | People and sessions | People, their session chains and the consent recorded on an agent chain, and the chain by which a person holds each grant (R2) | Revoke a chain or a consent; suspend a person |
  | Directories and groups | `DirectoryConnection`, the directory facts with the age of each, and the internal groups with who holds them | Connect or disconnect a directory; choose the synced groups |
  | Rules | The effective policy of the tenant with its provenance, its bindings and its template links, and `Explain` with a target (R2) | Link a template within the delegation policy |
  | Integrations | Each `Integration`, each connection of the tenant, and the dry run of each reconciler: what it would change, and the `HeldChange` entries | Connect a system; confirm a held change; rotate or revoke what a minter issued |
  | Channels | Channels bound in config (`ReconcileTarget`, read-only) and channels made on the console (`ConsoleChannel`), with the channels a chat adapter found that no record names | Create, change and delete console channels; adopt a found channel |
  | Clients and resources | Installation clients and templates (config), the tenant's clients, the metadata-document gate; secret versions, never their value | Generate or rotate a client secret |
  | Backup | The `BackupPlan` (config) and the latest archives and drills, from their audit facts | None; a restore is a command of store@ ([0010](/decisions/0010-backup-and-recovery/#restore)) |
  | Switches and log levels | The `Switch` entries and the `LogLevelOverride` entries with their expiry | Turn recovery off; pause a reconciler; raise a log level for a while |
  | Audit | A link to the audit front, which has its own console ([0028](/decisions/0028-audit-pieces/#the-audit-front)) | None |

  The shell around them holds a search over people, groups and clients, in the scope of the caller, and a banner while the installation is in maintenance mode ([0010](/decisions/0010-backup-and-recovery/#restore)).

- **The chain by which a person holds a grant** and the dry run of a reconciler are the console's two explanations. The first is the determining policies that `policy` returns with an answer ([0007](/decisions/0007-policy-and-sealed-grants/)); the second is the outcome of a `dry_run` pass ([0026](/decisions/0026-reconcilers/#the-contract)). The console computes neither.
- **A section without an owning actor or kind has no page.** The page list is the checklist for parity rows #831 and #832, and a page has a named operator task. A kind that is only counted, as on the overview, has no page of its own.
- **A URL names a kind, never a vendor.** A route that is renamed keeps a redirect from the old address, and a test covers it (REQ-UX-031). Filters of a list belong in the URL (REQ-UX-032).

### States

- **Every value from a cached or remote fact shows its source and the time it was true** (`as_of`), in the same words on every page (REQ-UX-023). Facts have an age already ([0025](/decisions/0025-integrations/#adapters-and-connections)); the page does not hide it.
- **A page has six states and says which one it is in:** ok, waiting (expected, nobody has to act), needs an operator, failed, unknown (the read could not be made) and stale.
- **A read that failed is never drawn as an empty list** (REQ-UX-024), and unknown is never drawn as signed out. A state that is expected, such as a connection made a moment ago that has not read its first snapshot, is never drawn as a failure (REQ-UX-025).
- **The shell shows a banner while the installation is in maintenance mode** and polls for it, so a banner does not outlive the restore.

### Writes

- **The console routes each write to the owner of the kind.** It checks the operator's delegation and calls the owner: `session` for people and their connections, `exchange` for what a tenant has configured (its clients, links and settings), the adapter of a vendor for its connections, held changes and channels ([0004](/decisions/0004-the-data-model/#one-writer-per-kind)). The store refuses any writer but the owner.
- **The owner checks the operator again.** The console passes the verified operator, and the scope of the delegation, in a form the owner verifies itself and does not take on the console's word; the owner then has `policy` decide for that person and carries the grant that `policy` sealed, as for any tenant-scoped write ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). The console's check is the first gate and the owner's is the second, so a flaw in the console is not an authorisation bypass at every owner (REQ-ISO-053, REQ-ISO-120; [principle 18](/principles/#18-plaintext-lives-only-where-it-is-used-behind-two-independent-checks)).
- **The console itself writes exactly two kinds, `Switch` and `LogLevelOverride`.** No actor has domain logic for either, so the store checks their schema, bounds and direction from the kind registry, which was the owner's validation for them. A `Switch` only tightens (recovery off, a reconciler paused, sign-in paused), and deleting it returns to what config says. A `LogLevelOverride` is a loosening, so it expires: 1 hour by default and 24 hours at most ([0016](/decisions/0016-telemetry/)).
- **A connect action starts a vendor flow and never holds a vendor credential.** The console starts the flow in the adapter, the GitHub App manifest flow or the Slack authorization for example; the adapter completes it and writes the connection with its credential sealed, as the kinds of [0025](/decisions/0025-integrations/#adapters-and-connections) say ([Connecting](/integrations/connecting/)). No page asks an operator to paste a vendor token or key (REQ-UX-026).
- **The callback of a connect flow lands on the console's host,** so the operator's session cookie comes with it. The flow's state names the operator and the browser that started it; a callback that cannot show both is refused on a page that says what to do, not with a server error. v1's consent callback ran where no operator was known ([99f6c679a](https://github.com/truvity/sluis/commit/99f6c679a)).
- **Every write is audited under the person's name,** with the previous and new version and the full new value apart from secrets. A confirmation of a held change is a write of the adapter that owns the target, made on the person's behalf (REQ-OPS-018).
- **A secret that a write creates is shown once, from memory.** A generated client secret ([0021](/decisions/0021-clients/#the-client-declaration)) or an enrolment token ([0022](/decisions/0022-workload-identity-and-host-enrolment/)) is in the response of the write that made it and nowhere else: the answer carries `Cache-Control: no-store`, the page keeps the value in memory and not in storage or a URL, and clears it when the dialog closes. The console does not log it, and the audit record names the secret version, not the value (REQ-UX-035). A general read returns a reference or a version, never the value (REQ-UX-027).

### Destructive actions

- **A destructive action is one of a named set.** Ending sessions (one chain, a consent, a browser's sign-in, everything of a person, or a client's sessions for everybody); disconnecting a connection; rotating or revoking a credential; pausing sign-in or a reconciler; confirming a held removal. Each such method is marked `destructive` in the console's API description, and a build check refuses a call to one without the confirmation step.
- **It takes two calls.** `Prepare` returns a confirmation: the exact set of things the action will change, their count, what survives, and a short expiry (minutes). `Commit` presents it. The confirmation is signed, bound to the person, their session and the request, so replaying it or changing the set fails (REQ-UX-020). A held-change confirmation already names its set and lapses in 24 hours (REQ-OPS-098); this is the same shape for the rest.
- **A control names what it ends.** Ending one chain, ending a browser's sign-in and ending everything of a person are three controls with three labels, and each answer says how many ended and what did not, such as agent sessions after a person's sign-out ([0018](/decisions/0018-sessions/)). Revoking is not signing out: after an operator ends a person's browser sign-in, the next authorisation from that browser asks for sign-in (REQ-SESS-056).
- **A commit also needs a fresh sign-in.** `Commit` is refused with a step-up challenge unless the person authenticated within the age that policy sets for the action, by RFC 9470 as in [0017](/decisions/0017-identity-and-sign-in/#fresh-privileged-sign-in) (REQ-UX-021, REQ-AUTHN-086). A write that only tightens needs the confirmation alone, so a pause stays cheap; a write that loosens needs both ([principle 12](/principles/#12-a-loosening-is-temporary-a-tightening-is-durable)).
- **There is one confirmation dialog and one destructive style,** so an operator learns the shape once.

### The browser

- **The console has a host of its own,** a sibling of the issuer's host, such as `sluis-console.example.com` beside `sluis.example.com`, as the audit front has ([0028](/decisions/0028-audit-pieces/#the-audit-front)). The bundle is at its root and the API under one fixed prefix, same-origin ([0013](/decisions/0013-release-train-packaging-and-distribution/#packaging-per-runtime)), so the bundle knows no mount path and no issuer (REQ-UX-028, REQ-UX-029). The host-only session cookie has the `__Host-` prefix and no `Domain` (REQ-SEC-041), and the host is on every passkey verifier's allow-list.
- **The console actor serves no HTML.** The bundle is static files; the sign-in, consent, sign-out and refusal pages are `session`'s ([0035](/decisions/0035-customer-pages/)) (REQ-UX-033).
- **The operator API takes only JSON, and a state change is never a GET.** A call that changes state with a body of another type, or by GET, is refused (REQ-SEC-040), with the checks of REQ-SEC-003 and REQ-SEC-016 on top.
- **Headers follow REQ-SEC-004,** and the content security policy is chosen per route: the shell has none of the exceptions, and a route that completes a vendor flow with a form post allows that one form action and no more (REQ-SEC-039).
- **The bundle sends the API version it was built for,** and the server answers a skewed one with an instruction to refresh, because the bundle and the API are two artifacts of one release and can be apart for a while (REQ-UX-030).
- **The console meets WCAG 2.1 AA,** checked in CI for every screen with keyboard and focus scenarios, at 390 and 1440 pixels wide (REQ-A11Y-003).
- **Each screen has a browser test against the local installation,** with fixtures for ok, empty, forbidden, unavailable, stale and waiting, and it is a merge gate (REQ-TEST-013). CI fails on a content-security-policy violation in a scripted flow (REQ-TEST-015) and runs every method as each role and scope against the answer its annotations declare (REQ-TEST-016).
- **There is no demonstration mode.** The local installation loads a documented set of fixtures (people, groups, tenants, states both expected and not) that only a test-only kind set can load and no production image contains (REQ-TEST-014; the parity row [#849](https://github.com/truvity/sluis/issues/849)).
- **The toolkit is React, TypeScript and Connect,** generated from the same protos, as the audit console's bundle is, from one source tree ([0028](/decisions/0028-audit-pieces/#the-audit-front)).
- **Usage is counted on the server.** The console counts each operator call by method and outcome with no person identifier, and the browser sends no telemetry (REQ-OBS-037). The counts order the screens that come later.

### Before the pages exist

The first working version has the `console` actor and no pages. So that the console is not harder to build later, it must not:

1. **Put the only role or scope check in the console,** or give the owner no way to verify the operator.
2. **Define page-shaped or vendor-shaped calls** (`GetOverviewPage`). Calls are shaped by kind (list, get, put) plus a few computed reads.
3. **Return an unpaged list,** or a list that cannot show its `as_of` and `source`.
4. **Answer "not found" and "not allowed" differently** to a caller within its scope.
5. **Answer an error with more than a stable code, a generic message and a request id,** or turn a failed read into an empty list.
6. **Let a state change be reached by GET or by a form post,** or accept a body that is not JSON.
7. **Serve HTML from the console actor.**
8. **Put the operator API under a path of another host,** or set the console cookie on a parent domain.
9. **Return a secret from a general read,** even once. Show-once is in the response of the write that creates it.
10. **Leave an R2 read unaudited.**
11. **Make a destructive write a single call.** Adding the prepare step later changes every client.

Rules 1, 4, 6, 7, 8, 9, 10 and 11 are requirements (Consequences); rules 2, 3 and 5 are guidance for review.

## Consequences

- The console has no role store of its own and no grant it can give; a stolen operator session can tighten and configure what the profiles allow and cannot widen authority.
- The console writes two kinds and needs no write rule for any other: a flaw in it reaches those two and the routing, not the kinds of other actors. Each owner needs validation and tests for the writes it accepts, and now a check of the operator it is told about.
- A viewer cannot see why a person holds a grant. An operator can, and each look-up is on the audit trail; the cost is audit volume, so a page does not repeat an R2 read on a timer and a filter is not run on each keystroke.
- A destructive action takes two calls and a fresh sign-in, so a routine disconnect or rotation is slower than v1's one click; a pause that tightens stays cheap.
- The console needs a host and a certificate of its own, and its host is added to every passkey verifier's allow-list, as the audit front's is ([0028](/decisions/0028-audit-pieces/#the-audit-front)). The connect callbacks of the vendors name the console host, not the issuer's host.
- Because pages follow the class and profile of a kind, the console needs those annotations of the kind registry at run time. They are generated into the console's API description, with the read class and `destructive` of each method.
- A section without an owner has no page, so a gap in the owners shows as a gap in the console.
- Every screen costs a browser test and a fixture, which makes the first screen slower and the later ones safe.
- Requirements: REQ-UX-009 to REQ-UX-011, REQ-UX-018 to REQ-UX-035, REQ-ISO-120, REQ-SEC-039 to REQ-SEC-041, REQ-A11Y-003, REQ-TEST-013 to REQ-TEST-016 and REQ-OBS-037 and REQ-SESS-056 are added.

## Roads not taken

- **Roles stored by the console and assigned on its pages.** It would be authority written at run time, which the profiles refuse, and the console would hold the right to widen its own reach.
- **Three or more roles (auditor, integration manager, support).** v1 managed with two; a finer split is a thing and a role in the vocabulary when a consumer needs it.
- **Roles read from the token's groups claim.** A token carries only the groups its audience requires ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)), and a role would travel to places that should not see it.
- **A page per v1 controller.** It would mirror v1's internals; the same kinds are reached through their section instead.
- **The console computes the dry run and the explanation itself.** It would re-implement `policy` and every provisioner and drift from them.
- **Embed the audit search in the console.** The audit installation has its own front and its own console; the operator console would hold a second reader.
- **Route every write to an owner, `Switch` and `LogLevelOverride` included.** `LogLevelOverride` has no owner at all, and a switch per owner would multiply kinds.
- **A console that writes every operator and tenant-admin kind.** It would lose the validation of the owner for clients, connections and links.
- **One read class: every read open to a viewer.** v1's `Explain` was open for five weeks and had to be restricted in a breaking change; the viewer's loss is the chain of other people.
- **Group membership as an R2 read, because it is personal data.** A viewer would see groups and not who is in them, which is safer, and the Directories and groups page would lose the holders it shows today. It lost for now because the membership is a stored fact that a directory reports, not a computed answer about access; it is the first place to tighten if the maintainer prefers.
- **The console as the only check of delegation.** A flaw in one actor would be a bypass at every owner; the owner checking again costs a context to verify in each owner.
- **The console under a path of the issuer's host.** It saves a host and costs v1's five mount-path and host fixes in two days, one cookie scope with the issuer, and one content security policy for two jobs.
- **Confirmation in the page only.** A script or a second client skips it; the confirmation is signed by the server and the commit refuses without it.
- **Confirmation alone, with no step-up.** A stolen operator session could end every session and rotate every credential with a click.
- **Step-up for every write.** It would put a hardware tap in front of routine work and against [principle 7](/principles/#7-a-person-only-where-a-person-adds-safety).
- **A secret never shown in the browser.** It is the safest, and it pushes client rotation to the command line.
- **Vendor tokens pasted into the console.** The console would hold a credential, even for a moment, that an adapter completes a flow to avoid.
- **Browser tests sampled, not a gate.** v1 found its console defects by hand because nothing forced a test; a sampled test would be skipped under time.
- **A revived demonstration mode.** It is a second path in production code that only tests use; a fixture set loaded by a test-only kind set does the same job outside the image.
- **A lighter toolkit than React.** Not measured as better; it would split the audit console's source tree from this one. Revisit if the bundle size or accessibility of the first screens proves poor.
- **Browser telemetry for usage.** It would send operator behaviour to a collector; server-side counts answer the question without.

## Follow-ups

- The console actor: [#960](https://github.com/truvity/sluis/issues/960) and [#1219](https://github.com/truvity/sluis/issues/1219); the read model and roles [#831](https://github.com/truvity/sluis/issues/831); the connect and manage actions [#832](https://github.com/truvity/sluis/issues/832); host enrolment pages [#967](https://github.com/truvity/sluis/issues/967).
- **Before #960 is built:** how the console shows an owner a session the owner can verify. `session` alone holds the cookie key ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)), so an owner cannot open the cookie, and the mechanism that carries the verified operator to the owner (REQ-ISO-120) must be settled in #960 before the console actor is built.
- The access explorer (paths, differences and the grants that matter most) and saved filters come after parity, on the target form of `Explain` above. Neither has an issue yet, and no part of this record waits for them.
