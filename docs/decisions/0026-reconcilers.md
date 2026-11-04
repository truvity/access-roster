# 0026 — A reconciler manages membership only, one per target under a lease

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #1012](https://github.com/truvity/sluis/issues/1012).

## Context

A `Provisioner` makes an external system equal to a desired state that is stored as data ([0025](/decisions/0025-integrations/#the-contracts)): teams, chat channels, wiki groups and on-call rotations. 0025 fixes that the adapter receives a desired state by digest and reports an outcome. It does not fix the method, the safety rules or the tests, which v1 spread over four controllers with their own breakers and dry runs (parity rows [#801](https://github.com/truvity/sluis/issues/801), [#808](https://github.com/truvity/sluis/issues/808), [#812](https://github.com/truvity/sluis/issues/812), [#813](https://github.com/truvity/sluis/issues/813) and [#815](https://github.com/truvity/sluis/issues/815)). Two planned records, the reconciler rules ([#1012](https://github.com/truvity/sluis/issues/1012)) and the Provisioner contract ([#1018](https://github.com/truvity/sluis/issues/1018)), described one subject and are merged here.

The forces: an external system is changed by a process that uses a vendor credential, so a mistake is felt by real people (principle 4: a check that cannot run is not a pass); more than one process acting on a target would fight; an unreadable directory must never look like an empty one ([0025](/decisions/0025-integrations/#what-an-integration-may-return)); and a kind that two places could write must have one owner ([0004](/decisions/0004-the-data-model/#one-writer-per-kind)).

The desired state needs three answers besides the rule: which actor computes and writes it, where it is stored when a container holds people of several companies, and what makes a stored part safe to act on. They are under [The desired state](/decisions/0026-reconcilers/#the-desired-state) ([issue #1181](https://github.com/truvity/sluis/issues/1181)).

## Decision

### Scope

- **A reconciler manages membership only:** who is in a team, a channel, a group, a rotation. It creates or adopts the container by name, invites, adds, promotes and removes people. It does not manage the container's content, settings or sharing, and it reports risky settings it sees without changing them.
- **A reconciler is a job of an adapter.** The adapter of the vendor (`adapter-github` for teams, `adapter-slack` for channels) runs it with the connection of the tenant whose container it manages ([0025](/decisions/0025-integrations/#adapters-and-connections)).
- **One reconciler per target.** A target is one container namespace of one connection, such as the teams of a GitHub organisation or the channels of a Slack workspace, and is declared in the durable kind `ReconcileTarget`, which also lists the directory connections whose people the target may hold (its sources) and, for a Slack Connect channel, a `shared` flag ([The desired state](/decisions/0026-reconcilers/#the-desired-state)). Exactly one process acts on it, holding the lease of the target. A `Lease` is a temp kind whose id starts with the adapter's name and names the tenant and the target ([0005](/decisions/0005-the-store/#leases)). The process passes the fencing token, the version of the lease, with every call that changes the vendor, and a call with a lower token is refused by the adapter.
- **It acts on a tick or on a wake.** The scheduler runs a pass per target under the lease: an in-process ticker, a systemd timer or EventBridge Scheduler by installation. A pushed notification wakes one pass ([0025](/decisions/0025-integrations/#push-then-pull)); a periodic full pass runs as well.

### The contract

- **`Reconcile` takes** the digest of the desired state, the mode (`dry_run` or `apply`), the fencing token and a budget of changes for one pass. The desired state is the kind `DesiredState`, a temp kind of the tenant that holds names and is therefore sealed; the provisioner reads it through its data port by its digest and never asks core a question. Its writer, its parts and its storage are under [The desired state](/decisions/0026-reconcilers/#the-desired-state).
- **`Reconcile` returns an outcome** that is one of `done`, `held`, `refused` or `failed`, with a reason from the closed list of [0025](/decisions/0025-integrations/#what-an-integration-may-return), a list of changes (operation, subject reference, container reference, result), a list of held changes with their reasons, a list of drift (what the vendor holds that the desired state does not name, and the reverse), counts, and the digest of what it observed. No vendor text crosses the contract. The messages are in the package `sluis.integration.v2alpha1` ([Contracts and errors](/reference/contracts/)).
- **A dry run changes nothing and returns the same lists** that an apply would act on. A target is in dry run until the operator declares `enabled: true` for it in its `ReconcileTarget`.
- **A pass is idempotent.** A second pass on an unchanged desired state and vendor makes no change.
- **An operator can pause a reconciler.** The pause is a `Switch`, a durable kind that only tightens; deleting it returns to what config says ([0027](/decisions/0027-the-console/#writes)).

### The desired state

- **The directory adapter writes `DesiredState`.** It writes it under the lease it already holds for refreshing the directory of one connection, straight after each refresh. `adapter-upstream-oidc`, for example, writes it once per connection, which is once per company's Google Workspace. The adapter makes one batch call to `policy`, which asks for the members of these targets given these facts ([Policy](/reference/policy/#the-batch-membership-method)), and writes the answer. Writing the answer is executing, not deciding ([0025](/decisions/0025-integrations/#the-rule)). No actor and no scheduler is added.
- **A part is the desired state of one target from one source.** `DesiredState` is stored per target and source directory connection, and addressed by digest. A target with several sources has several parts.
- **The provisioner of the target reconciles to the union of the parts.** `adapter-github`, for a team, reads every current part of its target through its data port, takes their union and reconciles to it. It reads nothing else and asks core nothing.
- **A missing or stale part is unreadable, never empty.** A part is missing when a source the target lists has none, and stale when it has passed the time to live of the kind. The pass holds that source's people and does not remove them, and it reports the part. The rest of the target is reconciled as usual.
- **The owner of the container holds the parts.** All parts of a target are stored in the tenant that owns the container and sealed under that tenant's `data` key ([0006](/decisions/0006-keys-and-sealing/#data-keys)). A company's GitHub organisation is stored in that company's tenant, and a Slack Connect shared channel in the tenant that owns (hosts) the channel. The provisioner opens only its own tenant's credentials, as every adapter does ([0025](/decisions/0025-integrations/#adapters-and-connections)).
- **A company's people may be written into another company's tenant.** When a part's source directory belongs to another company, the adapter of that directory writes the part into the owner's tenant. It learns where from `policy`'s answer alone, which names each target and its owner's tenant; it never reads another tenant's `ReconcileTarget`. Only the declared people cross, and only their vendor identifiers, such as a GitHub login. This is a narrow cross-tenant write: one kind, between declared pairs only. `policy` seals the grant for the owner's tenant only for a declared pair, and key@ checks the grant as it does for any seal ([0008](/decisions/0008-boundaries-and-tenants/#tenants)); both tenants audit the write.
- **Both sides declare a share.** A part from another company is written only when both sides have declared it: the owner's `ReconcileTarget` lists the other company's directory connection as a source, and the other company's reviewed policy allows its group to be provisioned into that target. With one side declared, nothing is written and the pass reports the missing declaration, because a tenant gets nothing from another tenant that is not declared ([0008](/decisions/0008-boundaries-and-tenants/#tenants)).
- **Slack Connect is a shared target.** People of several companies share one channel. The `adapter-slack` of the owner reconciles it, with `shared` set on the target. A member of another company is added by a Slack Connect invitation, and that company's own admin approval or connection policy still applies.

### Sharing across tenants

The rules in this section and the three below were decided on 2026-11-04.

- **External containers follow the container-owner model.** A GitHub organisation or team, a Slack channel or a Slack Connect channel is shared across tenants only as [The desired state](/decisions/0026-reconcilers/#the-desired-state) says: the tenant that owns the container holds the parts under its own `data` key, and another tenant's people are added only when both sides declare the share.
- **This is a membership share, not data sharing.** What crosses is the vendor identifier of each declared person and nothing else ([REQ-OPS-076](/requirements/ops/#REQ-OPS-076)). sluis has no general sharing of data between tenants; sharing beyond memberships exists only for a specific integration that declares its own contract on both sides, decided case by case ([0008](/decisions/0008-boundaries-and-tenants/#tenants)).
- **A person is linked across tenants through the source connection, never through a subject.** A person has a different `sub` in each tenant ([0034](/decisions/0034-end-users-and-upstream-signals/#subjects-and-sectors)), and the owner's tenant cannot compute or compare the source tenant's subjects. The provisioner therefore knows a person of another tenant only as a vendor identifier named by the part of one source connection, and that connection's directory is the person's own directory for every rule here ([REQ-OPS-091](/requirements/ops/#REQ-OPS-091)).
- **The owner keeps the minimal reference only.** For a person of another tenant, the owner's tenant holds the vendor identifier that its container needs (in the parts, in a `HeldChange` and in what its provisioner observes), and never the source's directory data beyond it: no name, no address, no group, no subject ([REQ-OPS-085](/requirements/ops/#REQ-OPS-085)).

In the three sections below, tenant A owns the container and tenant B owns a source directory connection that A's `ReconcileTarget` lists.

### Propagation from a source to the owner

- **B's directory adapter learns of the change.** It reads B's directory on its interval, 15 minutes by default, and a push from the vendor starts a read sooner ([0019](/decisions/0019-person-and-upstream-link/#directory-facts-parity)). Straight after the read it writes the parts of every target B's connection feeds, A's included, into the tenant of each owner ([The desired state](/decisions/0026-reconcilers/#the-desired-state)). There is no other path: B never calls A's provisioner, and nothing else carries B's changes to A.
- **A's provisioner watches the parts.** It lists `DesiredState` in A's tenant, then watches it from the listing's resume point ([0005](/decisions/0005-the-store/#watch-and-the-resume-point)); the parts of B are in A's tenant, so the watch is A's own and crosses no tenant. A delivered change to a part of a target wakes one pass of that target under its lease. Delivery is at least once, so the provisioner dedupes as the Watch contract of [0005](/decisions/0005-the-store/#watch-and-the-resume-point) says, and a second pass on an unchanged part changes nothing anyway ([REQ-OPS-034](/requirements/ops/#REQ-OPS-034), [REQ-OPS-086](/requirements/ops/#REQ-OPS-086)).
- **The periodic full pass is the backstop.** Every target gets a full pass at least once per `full_pass_interval`, a tunable of its `ReconcileTarget` with a default of 15 minutes and a ceiling of one hour built into the release ([REQ-OPS-087](/requirements/ops/#REQ-OPS-087), [REQ-OPS-088](/requirements/ops/#REQ-OPS-088)). It catches a change that a lost stream, an expired resume point or a restart missed, and it is the only path on Lambda, where nothing is pushed.
- **A removal reaches the container within one full-pass interval of the part that carries it.** The pass applies it or holds it under the breaker, and a held removal is reported ([REQ-OPS-089](/requirements/ops/#REQ-OPS-089)). Counted from B's directory, a person suspended or deleted there is removed within B's read interval plus A's full-pass interval: 30 minutes with the defaults, and usually the read interval plus seconds while the watch is up. A person who is merely absent is `left` only after `N` successful reads (3 by default, [0019](/decisions/0019-person-and-upstream-link/#directory-facts-parity)), so that removal takes `N` read intervals more. These are design figures from the defaults, not measurements; the reconciler's integration tests measure them.

### When a source tenant exits

B's exit must destroy B's personal data ([0008](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)), and a restore must not bring it back ([0010](/decisions/0010-backup-and-recovery/#roll-forward)). The parts B wrote into A are sealed under A's key, so B's crypto-shred does not reach them, and B's people would stay in A's container. The exit therefore ends every share B is the source of, before the shred.

- **B's exit withdraws every part it wrote into another tenant.** When B is `erasing`, B's directory adapter replaces each part it wrote into another tenant with a **withdrawal**: a part that names the vendor identifiers of B's people that the part held and marks them withdrawn. It writes it as it writes every part, from `policy`'s batch answer, which marks every member withdrawn for a connection whose tenant is erasing and gives the grant for the owner's tenant ([Policy](/reference/policy/#the-batch-membership-method), [REQ-OPS-081](/requirements/ops/#REQ-OPS-081)). Deleting the parts would not do: a missing part is unreadable and holds B's people in place.
- **A withdrawal is B's directory ceasing to vouch.** A's provisioner removes every person that a withdrawal names and no other current part of the target names, in `strict` and in `extend` mode alike ([REQ-OPS-082](/requirements/ops/#REQ-OPS-082)). `extend` keeps the members that sluis does not manage; a withdrawal names only people that B's share put in the target. A person that another source still names stays, a container owner is reported and not removed, and the breaker holds a pass that would remove too many, as for any pass ([Safety](/decisions/0026-reconcilers/#safety)).
- **The exit waits for the owners, within a bound.** Before the shred, B's exit waits until B's own audit log holds, for every withdrawal, the outcome of the owner's pass that applied it ([Audit in both tenants](/decisions/0026-reconcilers/#audit-in-both-tenants)), or until the ceiling of the full-pass interval has passed since the last withdrawal was written ([REQ-OPS-083](/requirements/ops/#REQ-OPS-083)). B never reads A's configuration, so the bound is the ceiling, not A's own interval. B's log already holds the write of each withdrawal ([REQ-OPS-077](/requirements/ops/#REQ-OPS-077)), so the exit knows how many outcomes to wait for.
- **What was not removed is an accepted residual.** A removal that the breaker held, that the vendor refused, or that did not happen within the bound, and a person the external system keeps (a container owner, or a Slack Connect member whom the other workspace keeps as its own), is recorded in B's exit record as a residual: the target and the count, never the people ([REQ-OPS-084](/requirements/ops/#REQ-OPS-084)). It is data outside sluis, the accepted risk of [0008](/decisions/0008-boundaries-and-tenants/#shared-parts-and-accepted-risks), and A's operators see the same held change on their console.
- **What A keeps afterwards.** The withdrawal parts expire with the kind's lifetime, and a `HeldChange` lasts until A's operator confirms or drops it; both hold vendor identifiers only. A's audit log keeps its records, which name B's people by A's own pseudonyms. A's `ReconcileTarget` still lists B's connection, so every pass then reports a missing part for it, which holds no one, until A's operator removes the source. A change applied after B's shred is audited in A's log only, because B's pseudonym key is gone.

### Audit in both tenants

- **A change in A's container that B's part caused is audited in both logs.** A's provisioner, which made the change, emits two records: one for A and one for B. The audit writer seals each under the `evidence` key of the tenant it names, so each tenant reads its own record and neither reads the other's ([0029](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding), [REQ-OPS-090](/requirements/ops/#REQ-OPS-090)). A held change and a withdrawal's outcome are changes for this rule.
- **Each record names the person under its own tenant's pseudonym.** The identity is the vendor account, the kind of identity an external actor has ([0029](/decisions/0029-the-audit-log/#pseudonyms)), and the provisioner asks key@ for its pseudonym under the `pseudonym` key of the tenant whose log receives the record; key@ checks that purpose by rule ([0006](/decisions/0006-keys-and-sealing/#data-keys)). A's record names B's source connection by its id; B's record names A's target by its id. Neither carries any other personal data of the other tenant ([REQ-AUDIT-165](/requirements/audit/#REQ-AUDIT-165)), and each tenant's reversal role answers for its own pseudonyms only.
- **B's record is what B can show.** It is how B proves to its own people and auditors what happened to them in a container B does not own, and it is what B's exit waits for.

### Safety

- **A removal needs a vouching directory.** A person is removed only when their own directory, the one that sluis reads for them, has stopped vouching for them and their account is tied to a person ([0019](/decisions/0019-person-and-upstream-link/)). A person who is absent from another source's part is not removed for that. `UNAVAILABLE`, a stale fact and a missing or stale part never remove anyone: the pass is held for that source's people.
- **The breaker holds a pass** that would remove more than half of a container's members, remove the last administrator or demote more than one, or exceeds the vendor's per-pass limit. The thresholds are declared tunables of the `ReconcileTarget`, with these defaults. A held change is a `HeldChange`, a durable kind of the adapter, and it waits for an operator's confirmation; the confirmation is a write that the console routes to the adapter that owns the target ([0027](/decisions/0027-the-console/#writes)).
- **A container owner is reported, never removed.** A leaver still present is reported.
- **Two modes for a container:** `extend` only adds; `strict` also removes whom the desired state does not name.
- **Adoption is explicit and holds on conflict.** A container found by name is adopted only when the `ReconcileTarget` declares it; a container that is both bound in config and made on the console is held, and nothing changes on it.
- **Channels bound in reviewed policy and channels made on the console are two kinds with two owners** and never mix. The first are `ReconcileTarget` (durable), the second `ConsoleChannel` (durable, written by the chat adapter).
- **A pass is audited:** its outcome, its digest and counts, and every change, including each held one ([0025](/decisions/0025-integrations/#splitting-by-credential)).

### Tests

- **Every provisioner passes one conformance suite against a fake vendor server:** idempotence, dry run writes nothing, a lower fencing token is refused, `UNAVAILABLE` removes no one, the breaker thresholds, `extend` and `strict`, adoption and conflict, and no vendor text in an outcome. A provisioner that fails any of them is not released.

## Consequences

- A new vendor is a new provisioner plus its fake server and the suite; the rules above are not written again per vendor. Per-vendor behaviour stays on the integration pages.
- Two processes never act on one target; a failover waits for the lease to expire and a stale holder cannot write after it.
- A mass removal needs a person. The price is a held pass when a directory has a real large change, such as a reorganisation; the operator confirms it once.
- A reconciler runs for a tenant with the credential of that tenant's connection, opened at key@ for each call, so a pass over many tenants costs many opens.
- A directory refresh ends with one batch call to `policy` and one sealed write per target and source, so the cost of the desired state follows the directory's refresh, not the passes of the provisioners.
- A target in a shared container needs two reviews: the owner's `ReconcileTarget` and the other company's policy. A share that one side has not declared is reported on every pass and changes nothing.
- A change in one company's directory reaches another company's container in about the directory's read interval while the watch is up, and within that interval plus one full pass in every case, Lambda included. Each target costs a full pass at least once an hour, whatever the watch delivers.
- A company's exit reaches every container it shared people into, before its keys are shredded, and waits at most an hour for the owners; what an owner's breaker or vendor keeps is a residual that the exit names by count. An `extend` container loses the people that an exited company's share put there.
- A change across tenants writes two audit records, one per tenant, with two pseudonyms of the same vendor account that cannot be linked to each other without both tenants' reversal roles.
- Requirements: REQ-OPS-031 to REQ-OPS-037 are added, and REQ-OPS-068 to REQ-OPS-077 cover the desired state. Sharing across tenants adds REQ-OPS-081 to REQ-OPS-091, REQ-AUDIT-165 and REQ-ISO-117. Issue #1018 is closed into #1012.

## Roads not taken

- **Reconcile settings and content as well as membership.** It widens what a vendor credential must be allowed to do and what a bug can break; membership is where the directory's authority is.
- **A reconciler per vendor with its own lease rule.** Each would invent its own safety rules, as v1's four controllers did.
- **No breaker: trust the desired state.** A directory error or a policy mistake would remove a whole team before anyone saw it.
- **Remove whoever the desired state does not name, in every mode.** Channels and teams that people use for other purposes would lose members silently; `extend` exists for them.
- **A database advisory lock as the only guard.** It gives no fencing token, so a paused holder could write over its successor ([0005](/decisions/0005-the-store/#leases)).
- **The console writes the held-change confirmation itself.** It would write a kind that the adapter owns and validates; the console writes only `Switch` and `LogLevelOverride`.
- **`exchange` writes the desired state.** It puts a batch load on the sign-in path and gives `exchange` a second job.
- **A new work actor for it.** An extra actor and scheduler, for what the lease of the directory refresh already gives.
- **The target's adapter computes its own list.** A vendor would read another vendor's directory, repeated per vendor, which is v1's four-controller shape.
- **Store a part in the tenant of its source directory, and let the provisioner open the other tenant's key.** It would widen every provisioner and break the rule that an adapter opens only its own tenant's credentials.
- **Leave the writer open.** The reconcilers would have nothing to reconcile to, and the milestone would stall on the first pass.
- **General sharing of data between tenants, with a cross-tenant grant per kind.** Every kind would become a possible path between companies, and each share needs a review on both sides that only an integration's own contract gives.
- **Link a person across tenants by subject.** A person's `sub` differs per tenant, and comparing subjects would need one tenant's `pairwise` key in another.
- **Let the source's shred alone end a share.** The parts are sealed under the owner's key, so the people would stay in the owner's tenant and container.
- **Delete the source's parts at its exit.** A missing part is unreadable and holds its people, so no one would be removed.
- **Remove a withdrawn person in `strict` mode only.** Every `extend` container would keep an exited company's people, against the exit's promise; `extend` exists for members that sluis does not manage.
- **Let the exit wait for the owners without a bound.** One owner's breaker or outage would hold another company's erasure forever.
- **Read the owner's interval to bound the wait.** The source would read another tenant's `ReconcileTarget`; the ceiling bounds every owner.
- **Watch only, with no periodic full pass.** A lost stream, an expired resume point or Lambda, where nothing is pushed, would leave a removal with no bound.
- **Full passes only, with no watch.** Every change would wait for the next pass, and a short interval to hide that would spend vendor calls on unchanged targets.
- **The source's directory adapter calls the owner's provisioner.** A call between adapters of two tenants, and a second channel beside the store that would need its own fencing and audit.
- **Audit a change across tenants in the owner's log only.** The source could not show its own people or auditors what happened to them, and its exit would have nothing to wait for.

## Follow-ups

- The batch membership method, `DesiredState` and the targets are built with the reconciler milestone: [#1220](https://github.com/truvity/sluis/issues/1220). The watch of `DesiredState` (its `watched_by` entry in the kinds registry), `full_pass_interval`, the withdrawal and the two audit records arrive with it, with their first consumer.
- The first provisioners: GitHub teams [#808](https://github.com/truvity/sluis/issues/808), Slack channels [#812](https://github.com/truvity/sluis/issues/812), [#813](https://github.com/truvity/sluis/issues/813), the wiki controller [#815](https://github.com/truvity/sluis/issues/815); the scheduler and lease [#801](https://github.com/truvity/sluis/issues/801).
