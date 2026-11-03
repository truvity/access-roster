# 0056 — A regional outage is accepted for signing, public key material outlives it, and recovery objectives are measured by a drill

**Status:** Superseded by 0010
**Layer:** core
**Date:** 2026-11-03

Proposal: [issue #1142](https://github.com/truvity/sluis/issues/1142).

## Context

[0046](/decisions/0046-tenancy-and-scale-a-boundary-holds-keys-and-a-tenant-is-a-record/#where-installations-run) puts the customer-identity installation in one region of one cloud provider, chosen per installation in its install file, makes a later residency region an installation of its own that shares nothing, and accepts that a regional outage stops signing. It sets no recovery time or recovery point and leaves them to the backup record. What is still missing for a customer-facing installation is how residency is checked, what survives a regional outage, and how a recovery promise is earned.

- **Residency needs a check.** The sealing key is multi-Region plus a replica ([Keys](/concepts/keys/#aws-kms-layout)), and a backup archive has a copy; both leave the region unless something refuses it. [REQ-OPS-007](/requirements/ops/#REQ-OPS-007) and the region guard ([#1061](https://github.com/truvity/sluis/issues/1061)) are the check.
- **A regional outage should not make verification fail.** Relying parties verify tokens against the discovery document and key set, which [0017](/decisions/0017-identity-and-sign-in/#issuers) makes static documents in a bucket.
- **There is no number.** No page states a recovery time or point, and no restore has been timed ([principle 9](/principles/#9-measure-before-deciding-and-date-the-measurement)).

## Decision

### Residency

- **The allowed set of regions is declared in the install file,** and the region guard refuses a table, a bucket, a queue, an index or a key replica outside it, at load and at deployment ([REQ-OPS-007](/requirements/ops/#REQ-OPS-007)). An installation's set is its declared region and one other region in the same jurisdiction, which holds the sealing key's replica and the copy of the backup archive.
- **Signing keys are single-region keys.** A multi-Region key copies key material to another region, against [principle 1](/principles/#1-a-key-is-born-in-its-store-and-never-leaves-it); only the sealing key is replicated, for loss protection ([principle 2](/principles/#2-trust-is-layered-and-redundancy-is-not-a-defence-against-compromise)).

### A regional outage

- **Public material outlives it.** The discovery document and the key set are public static documents. They are served through a content delivery network with a stale-if-error window, so verification of tokens already issued continues while the region is down. Public material has no residency. Tokens already issued stay valid until they expire ([REQ-OPS-014](/requirements/ops/#REQ-OPS-014)).
- **There is no standby region and no failover** in the first installation. New sign-ins and signing wait for the region.

### Recovery

- **An installation publishes its recovery point and recovery time and proves them.** For the loss of the state, of a bucket and of the region it states how much issued durable data may be lost and how long recovery takes, and a recovery drill measures both: at least once a year and after any change to the backup or restore path. The result is published with its date and versions. The restore follows [Backup](/concepts/backup/) and the order of [0004](/decisions/0004-the-data-model/#backup-and-restore-by-origin).
- **The targets before the first drill are decided.** The maintainer decided them on 2026-11-02 ([#1142](https://github.com/truvity/sluis/issues/1142)). Each is a target and not a measurement, and the first drill replaces it with the measured figure. No page promises a recovery time that no drill has measured.
- **The targets cover the customer-identity installation and the serverless workforce installation.** The boards installation is best effort and states no target; it publishes a figure only after a drill has measured one.

  | Loss of | Recovery point | Recovery time |
  |---|---|---|
  | The state | 5 minutes | 4 hours |
  | A bucket | 24 hours, the interval between archives | 8 hours |
  | The region | no figure until a drill measures it | no figure until a drill measures it |

  The region has no failover, and a rebuild in a second region needs new intermediates through the hand-off, so a figure waits for a drill that has measured the rebuild.

## Consequences

- The residency claim is checkable: a table in the wrong region fails the deployment, not an audit a year later.
- A regional outage is felt as no new sign-ins until AWS restores the region. The first customers accept that; the day they do not, a second region is a consumer and a new record.
- A drill costs a day of work and a restore environment each year, and it is the only way the published figures become true.
- Requirements: [REQ-OPS-038](/requirements/ops/#REQ-OPS-038), [REQ-OPS-039](/requirements/ops/#REQ-OPS-039), [REQ-OPS-040](/requirements/ops/#REQ-OPS-040) are added.

## Roads not taken

- **A multi-Region signing key for failover.** The key material would live in two regions, against principle 1, and its policy would have to be kept equal in both.
- **A standby region from the start.** Money and operations for an outage no customer has asked to survive.
- **Public documents served only from the region.** Every relying party would fail verification during an outage that tokens already issued could ride out.
- **Recovery figures from the provider's documentation.** The restore time of a table is a property of its size and our order of restore, which only a drill measures.
- **A stated target for the boards installation.** It runs on small computers its operator owns, and a figure would be a promise that nothing measured backs; it is best effort until a drill measures one.
- **No stated objectives until a customer asks.** A customer-facing installation has customers on the first day, and an unstated objective is a promise nobody can hold.

## Follow-ups

- The first recovery drill, its published result and the replacement of each target by the measured figure: [#1142](https://github.com/truvity/sluis/issues/1142).
- The region guard: [#1061](https://github.com/truvity/sluis/issues/1061).
