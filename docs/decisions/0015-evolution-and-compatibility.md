# 0015 — Evolution and compatibility: N and N-1 inside a major version, a parallel cutover from v1, and neutral artifacts as the deliverable

**Status:** Accepted
**Date:** 2026-11-02

Proposal: [issue #1022](https://github.com/truvity/sluis/issues/1022).

## Context

Three questions about change share one answer.

- **Upgrades.** [0013](/decisions/0013-release-train-packaging-and-distribution/#compatibility-between-releases) says that all artifacts of one version are compatible with each other and only with each other. That reads as lockstep. But Lambda updates one function at a time, Kubernetes replaces pods one by one, and the boards update one node at a time, so a window with two versions always exists unless the product stops. v1 stopped it with a maintenance freeze; a customer-facing installation has no window to stop in.
- **Cutover from v1.** v1's own cutover froze, copied state and switched one issuer. v2 cannot copy state: it has a new key hierarchy, an opaque `sub` ([0017](/decisions/0017-identity-and-sign-in/#subjects)) and an issuer for each boundary host. v1's `sub` appears to be a person's e-mail address, to be confirmed by an inventory, so anything keyed on it changes.
- **Deliverables.** v1 shipped a Pulumi library that rendered sluis documents. v2 pages say that "infrastructure as code applies" the result and name no deliverable. And the parity milestone's done-when gathers capabilities v1 never had with the ones that replace what v1 does, so it is not clear what has to hold before v1 can be retired.

Principle 6 joins products by a contract with vectors; principle 1 says v1's keys never move; principle 11 builds one product for several installation shapes, a driver at a time; principle 8 asks for a consumer first.

## Decision

### N and N-1 inside a major version

- **Within one major version, release N works with release N-1** for every contract and every stored record: the messages between actors, the transport message of the audit emitter, the record kinds in `state`, the published documents and the entries of the audit log. An emitter library built with N-1 keeps working against a writer of N.
- **A stored record changes by expand and contract.** Release N reads old and new and writes old; release N+1 writes new; a later release stops reading old. A field is never removed in the release that stops writing it (REQ-SUPPLY-026).
- **Deployments roll.** Readers are updated before writers. No release inside a major needs a stop. Lambda functions, pods and board nodes update one at a time, and the mixed window is a tested state, not an accident.
- **Rollback is the previous release.** N-1 reads what N wrote, so going back needs no migration.
- **Contract vectors in CI enforce it** (principle 6, REQ-SUPPLY-025, REQ-SUPPLY-027). The vectors of the previous release run against the current actors, and the current vectors run against the previous release's artifacts, for messages, records and documents. Protocol contracts are also checked for breaking changes ([GOVERNANCE.md](https://github.com/truvity/sluis/blob/main/GOVERNANCE.md)).
- **A major version may break N-1.** It ships with an upgrade note and, where stored data changes, a tool that migrates it, and it may need a stop.
- **The rule holds from v2.0.0.** Between alphas anything may change, as 0019 says. The configuration schema keeps its own rule: a published `$id` never changes ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf)).
- **This replaces 0019's lockstep sentence.** [0013](/decisions/0013-release-train-packaging-and-distribution/#compatibility-between-releases) carries the rule in its short form: one release is built and shipped together, and also works with the previous release of its major.

### Cutover from v1

- **v1 and v2 run in parallel, and relying parties move one at a time.** v2 comes up on its own issuer hosts. Each relying party, such as a cluster API server, a cloud identity provider, a GitOps tool, a console or a CI system, is rewired and switched alone. v1 keeps serving the others until the last has moved, and a move is undone by pointing that relying party back.
- **v2 never takes over v1's issuer.** v1's keys never move (principle 1), the v2 chain comes from the root custodian, and each boundary has its own issuer host ([0008](/decisions/0008-boundaries-and-tenants/)).
- **An inventory comes first.** Before the first relying party moves, a list names every relying party of the v1 issuer and every consumer that keys on v1's `sub`, `aud` or `groups` format (REQ-OPS-030). A consumer keyed on the e-mail `sub` is re-keyed to v2's opaque `sub` before it moves.
- **No state is carried.** What happens to each thing follows its origin in [0010](/decisions/0010-backup-and-recovery/#what-the-archive-holds): declared configuration is converted by a tool (policy to Cedar, clients and vocabulary to the v2 files), learned data is learned again, durable issued records are issued again for each workload, vendor-issued secrets are connected again, and sessions are not carried, so everyone signs in again.
- **v1's audit and billing history follows [0048](/decisions/0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data/#v1s-history).**

### Deliverables

- **Neutral rendered artifacts are the contract** (principles 6 and 11). The manifest renders IAM policies, the function and schedule map, units, chart values and install-file fragments as plain files that any tool applies (REQ-DEPLOY-014). They are versioned with the release and covered by golden tests ([0002](/decisions/0002-families-of-actors/)).
- **A thin Pulumi library lives in its own Go module and release** and only consumes those artifacts, for our own estate, which is its consumer (principle 8, REQ-DEPLOY-015). The product does not depend on it, and sluis ships no other infrastructure-as-code library before a consumer asks.

### The v1 parity milestone has two gates

- **The v1-retirement gate** is the replacement of what v1 does. It holds when every row of the [v1 parity checklist](/features/) is `Done` or `Changed` with its decision, the lambda and kubernetes installations are built and tested, the cutover inventory is complete, and v1's history is handled as 0032 says. v1 is retired when this gate holds and the fact of [0001](/decisions/0001-v1-and-v2-lines/) holds: the maintainers' own production runs v2.
- **The new-capabilities gate** is what v1 never did: the SSH CA, database certificates, host enrolment, trust sync, the cert-manager issuer, the peer witness and the boards installation. It is delivered by the installation that needs it and does not hold v1 back.
- The [Roadmap](/roadmap/) states both gates.

## Consequences

- A release causes no downtime inside a major version, on every runtime, at the price of a rule that CI has to enforce: vectors for each contract, record and document, kept from release to release.
- Changing a stored record takes at least two releases. A change that cannot be split that way waits for a major version.
- Each relying party moves in its own window and can be put back. Two live issuers exist for the length of the cutover, and fixes continue on v1 until the last move ([0001](/decisions/0001-v1-and-v2-lines/)).
- The inventory can find that a consumer is keyed on the e-mail `sub`. That consumer is rewired first, and its owner has to act.
- Retirement no longer waits for the SSH CA, the boards or the other new capabilities, so the schedule risk of the root custodian's later milestones does not fall on it. The board needs a way to tell the two gates apart.
- Our estate keeps using a Pulumi library without the product being tied to one tool; the cost is one more module to release and test.

## Roads not taken

- **Lockstep upgrades with a maintenance window, as v1.** Sign-in would be down at every release, which is hard on the boards and Lambda and against high availability.
- **A format version on each record with lazy migration only.** It cannot express a change of contract between two actors.
- **A big-bang cutover per installation, as v1 did.** The freeze copied state, which v2 cannot; one failing relying party would stall all; a switch is hard to undo once people have signed in on v2.
- **v2 takes over v1's issuer address.** It needs v1's signing keys, which never leave their store, and it breaks one issuer for each boundary.
- **Carry v1 state across.** The key hierarchy, the subjects and the issuers all differ, and a copy would import what the new design does not trust.
- **A Pulumi component library as the deliverable, per runtime.** The product would be tied to one tool.
- **Rendered artifacts only, with no library.** Our estate would write the glue again for a consumer that exists.
- **Every new capability gates retirement.** v1 would stay for months, and its end would depend on work that replaces nothing v1 does.
- **Gate on replacements only and re-label the rest "parity+".** Same effect, but it renames the milestone and every issue on the board.

## Follow-ups

- Compatibility per artifact, written before v2.0.0: [#1022](https://github.com/truvity/sluis/issues/1022).
- The cutover, its inventory and its tooling: [#1017](https://github.com/truvity/sluis/issues/1017).
- The Pulumi library: [#845](https://github.com/truvity/sluis/issues/845); rendering of the installation document and service configuration: [#846](https://github.com/truvity/sluis/issues/846).
