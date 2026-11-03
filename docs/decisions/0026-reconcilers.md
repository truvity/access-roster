# 0026 — A reconciler manages membership only, one per target under a lease, through the Provisioner contract

**Status:** Accepted
**Date:** 2026-11-02

Proposal: [issue #1012](https://github.com/truvity/sluis/issues/1012).

## Context

A `Provisioner` makes an external system equal to a desired state that core published ([0025](/decisions/0025-integrations/#the-contracts)): teams, chat channels, wiki groups and on-call rotations. 0026 fixes that it receives a desired state by digest from a read-only prefix and reports an outcome. It does not fix the method, the safety rules or the tests, which v1 spread over four controllers with their own breakers and dry runs (parity rows [#801](https://github.com/truvity/sluis/issues/801), [#808](https://github.com/truvity/sluis/issues/808), [#812](https://github.com/truvity/sluis/issues/812), [#813](https://github.com/truvity/sluis/issues/813) and [#815](https://github.com/truvity/sluis/issues/815)). Two planned records, the reconciler rules ([#1012](https://github.com/truvity/sluis/issues/1012)) and the Provisioner contract ([#1018](https://github.com/truvity/sluis/issues/1018)), described one subject and are merged here.

The forces: an external system is changed by a process that holds a vendor credential, so a mistake is felt by real people (principle 4: a check that cannot run is not a pass); more than one process acting on a target would fight; an unreadable directory must never look like an empty one ([0025](/decisions/0025-integrations/#what-an-integration-may-return)); and a record defined twice in two places must not be changed by either ([0004](/decisions/0004-the-data-model/#storage-classes)).

## Decision

### Scope

- **A reconciler manages membership only:** who is in a team, a channel, a group, a rotation. It creates or adopts the container by name, invites, adds, promotes and removes people. It does not manage the container's content, settings or sharing, and it reports risky settings it sees without changing them.
- **One reconciler per target.** A target is one container namespace of one vendor tenant, such as the teams of an organisation or the channels of a workspace. Exactly one process acts on it, holding the named lease `reconcile/<integration>@<tenant>` ([0005](/decisions/0005-the-store/#leases)). It passes the fencing token with every call that changes the vendor, and a call with a lower token is refused by the integration.
- **It acts on a tick or on a wake.** The scheduler runs a pass per target under the lease: an in-process ticker, a systemd timer or EventBridge Scheduler by installation. A pushed notification wakes one pass ([0004](/decisions/0004-the-data-model/#storage-classes)); a periodic full pass runs as well.

### The contract

- **`Reconcile` takes** the digest of the desired state, the mode (`dry_run` or `apply`), the fencing token and a budget of changes for one pass. The desired state is read from the prefix core wrote; the provisioner never asks core a question.
- **`Reconcile` returns an outcome** that is one of `done`, `held`, `refused` or `failed`, with the reason from the closed list of 0026, a list of changes (operation, subject reference, container reference, result), a list of held changes with their reasons, a list of drift (what the vendor holds that the desired state does not name, and the reverse), counts, and the digest of what it observed. No vendor text crosses the contract. The messages are in the package `sluis.integration.v2alpha1` ([Contracts and errors](/reference/contracts/)).
- **A dry run changes nothing and returns the same lists** that an apply would act on. A target is in dry run until the operator declares `enabled: true` for it.
- **A pass is idempotent.** A second pass on an unchanged desired state and vendor makes no change.

### Safety

- **A removal needs a vouching directory.** A person is removed only when the directory that sluis reads for them no longer vouches for them and their account is tied to a person ([0019](/decisions/0019-person-and-upstream-link/)). `UNAVAILABLE` or a stale fact never removes anyone: the pass is held.
- **The breaker holds a pass** that would remove more than half of a container's members, remove the last administrator or demote more than one, or exceeds the vendor's per-pass limit. The thresholds are declared tunables with these defaults; the held change waits for an operator's confirmation, which is an issued record of that act and not a setting ([0004](/decisions/0004-the-data-model/#storage-classes)).
- **A container owner is reported, never removed.** A leaver still present is reported.
- **Two modes for a container:** `extend` only adds; `strict` also removes whom the desired state does not name.
- **Adoption is explicit and holds on conflict.** A container found by name is adopted only when declared; an object defined both as declared and as operator-set is held, and nothing changes on it ([0004](/decisions/0004-the-data-model/#storage-classes)).
- **Channels bound in reviewed policy and channels made on the console are two record kinds with two owners** and never mix. The first are declared, the second operator-set.
- **A pass is audited:** its outcome, its digest and counts, and every change, including each held one ([0025](/decisions/0025-integrations/#splitting-by-credential)).

### Tests

- **Every provisioner passes one conformance suite against a fake vendor server:** idempotence, dry run writes nothing, a lower fencing token is refused, `UNAVAILABLE` removes no one, the breaker thresholds, `extend` and `strict`, adoption and conflict, and no vendor text in an outcome. A provisioner that fails any of them is not released.

## Consequences

- A new vendor is a new provisioner plus its fake server and the suite; the rules above are not written again per vendor. Per-vendor behaviour stays on the integration pages.
- Two processes never act on one target; a failover waits for the lease to expire and a stale holder cannot write after it.
- A mass removal needs a person. The price is a held pass when a directory has a real large change, such as a reorganisation; the operator confirms it once.
- Requirements: REQ-OPS-031 to REQ-OPS-037 are added. Issue #1018 is closed into #1012.

## Roads not taken

- **Reconcile settings and content as well as membership.** It widens what a vendor credential must be allowed to do and what a bug can break; membership is where the directory's authority is.
- **A reconciler per vendor process with its own lease rule.** Each would invent its own safety rules, as v1's four controllers did.
- **No breaker: trust the desired state.** A directory error or a policy mistake would remove a whole team before anyone saw it.
- **Remove whoever the desired state does not name, in every mode.** Channels and teams that people use for other purposes would lose members silently; `extend` exists for them.
- **A database advisory lock as the only guard.** It gives no fencing token, so a paused holder could write over its successor ([Data](/concepts/data/#leases-and-fencing-tokens)).

## Follow-ups

- The first provisioners: GitHub teams [#808](https://github.com/truvity/sluis/issues/808), Slack channels [#812](https://github.com/truvity/sluis/issues/812), [#813](https://github.com/truvity/sluis/issues/813), the wiki controller [#815](https://github.com/truvity/sluis/issues/815); the scheduler and lease [#801](https://github.com/truvity/sluis/issues/801).
