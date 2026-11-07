# 0009 — exporter@ publishes the kinds marked exportable to destinations outside sluis, never to a secret source

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #1014](https://github.com/truvity/sluis/issues/1014).

## Context

sluis holds secrets because it has to: a vendor-issued app key, a bot token, a generated client secret. It is not a secrets engine for anyone else ([Data and secrets](/concepts/data/)). Some of what it holds must still leave it, because something outside sluis needs it with its own identity: a cluster that needs a client secret, a relying party that needs the key set, a host that needs the revocation list.

Three rules from the data model bound the design.

- **Where a thing is written decides its class** ([principle 17](/principles/#17-where-a-thing-is-written-decides-its-class)). A secret source is written by IaC and read-only for sluis. If sluis wrote into one, a value would have two writers and two classes.
- **Few credential holders** ([principle 16](/principles/#16-few-credential-holders)). A destination needs a credential. That credential belongs to one holder of the data family, exporter@, and to no work actor ([0002](/decisions/0002-families-of-actors/#credential-holders)).
- **Nothing without a consumer** ([principle 8](/principles/#8-nothing-without-a-consumer)). A kind leaves sluis only when someone is named who reads it.

v1 exported typed credential documents to OpenBao and wrote Kubernetes objects. The design rule "sluis writes no Kubernetes object" is amended here, and the single case it allows is below.

## Decision

### What is exportable

- **Only a kind marked exportable in the kind registry may leave sluis.** The mark is a property of the kind ([0004](/decisions/0004-the-data-model/#kinds)), so what may leave is decided in review and not at run time. exporter@ refuses any other kind.
- **Exactly seven kinds are exportable.** `SigningRing` (the key set), `KeyCertificate` (the certificate chains), `TrustAnchors` (input to the trust bundle), `Crl`, `Krl` and `TrustBundle` are public material. `ClientSecretExport` is the sealed copy of a generated client secret.
- **A kind is marked only when a consumer is named** (principle 8). A new exportable kind needs the mark, a consumer and a rule that lets exporter@ read it, in that order.
- **A generated secret that must leave sluis is stored twice:** as a hash to verify and as a sealed copy to export ([0004](/decisions/0004-the-data-model/#treatment)). The sealed copy exists only for a client marked exportable. A secret that is not exported keeps only its hash.
- **No export carries a secret for a vendor that sluis could mint for.** sluis mints a scoped credential instead ([0025](/decisions/0025-integrations/)).

### Destinations

- **A destination is a config kind, `ExportDestination`,** with one driver per destination type, private to exporter@ ([0005](/decisions/0005-the-store/#drivers)). exporter@ holds the destination credentials; no work actor does, and store@ does not.
- **A store of record** (AWS SSM or OpenBao) receives values that a cluster reads through External Secrets with its own identity. sluis never holds the cluster's identity.
- **A directory** receives public material at static paths on a file system, as a bucket does: the local installation uses it, and a forwarder serves the files. Like a bucket, it never receives `ClientSecretExport` or a sealed kind, and the configuration check refuses that pairing. Its driver writes a document through a temporary file and a rename, and keeps a record of what it wrote, so that `List` and `Delete` touch nothing else in the directory.
- **A bucket** receives public material at static addresses: the key set, certificate chains, revocation lists and the trust bundle. A bucket never receives `ClientSecretExport`; the configuration check refuses that pairing. A bucket may sit behind an edge cache ([Publishing public material](/decisions/0009-export/#publishing-public-material)).
- **A single cluster may receive a Kubernetes Secret directly,** written by exporter@ alone and only when the installation chooses the direct path. exporter@'s cluster credential is limited to writing the named Secrets in the named namespaces, and the threat model lists it.
- **The amended rule:** sluis writes no Kubernetes object, except an exported Secret written by exporter@ when an installation chooses the direct path. Cluster tools such as cert-manager, trust-manager and External Secrets stay its clients and distributors.
- **A destination may not overlap a secret source.** The configuration check refuses a destination whose address is also read as a secret source ([secret sources](/decisions/0005-the-store/#secret-sources)), so sluis never reads back what it wrote and no value has two writers.
- **Every board of a boundary runs exporter@ with the same destination files.** The `ExportManifest` is one item for the boundary and each exporter@ writes it at its start, so boards with different files would overwrite each other's manifest and `signer` would wait for whichever was written last. Until store@ serves `ExportDestination`, the file is the operator's, and the operator keeps it identical on every board.

### Watch and reconcile

- **exporter@ watches the exportable kinds from a resume point** ([0005](/decisions/0005-the-store/#watch-and-the-resume-point)) and keeps the resume point of each destination in a temp kind, `ExportCursor`. Losing it costs a full reconcile, not data.
- **A sealed value is opened at key@ with exporter@'s own grant,** written with the destination credential, and every write is an audit fact. The grant is sealed for the tenant of the value ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). Public material is read and written as it is.
- **A full reconcile runs at start and once a day.** It writes what is missing or different at the destination and removes what exporter@ wrote for a value that no longer exists, so a missed change or an edit made at the destination is corrected within a day.

### Publishing public material

The key set is the first public document, and the other public kinds follow the same rules. This part was decided on 2026-11-06. The first version has one issuer, and so one key set, for each boundary; the other destinations, the other kinds and the trigger on Lambda (nothing is pushed there, [0005](/decisions/0005-the-store/#watch-and-the-resume-point)) come with their installations ([#1014](https://github.com/truvity/sluis/issues/1014)).

- **A published document is one object at an address that `ExportDestination` declares,** with its content type and its `max-age`; the address is never derived from the kind. It is written whole and atomically: a rename in a directory, one put in a bucket. A reader never sees half a document.
- **The key set is the JSON Web Key Set of RFC 7517,** built by the rule that `entry` uses for its live key set, with `Content-Type: application/json`, `Cache-Control: public, max-age=300` and `Access-Control-Allow-Origin: *` ([REQ-KEYS-016](/requirements/keys/#REQ-KEYS-016)). <!-- terms-allow: origin (the CORS header name) -->
- **exporter@ leaves out every `kid` that `KeyRevocation` lists** ([REQ-EXPORT-020](/requirements/export/#REQ-EXPORT-020)). It watches `KeyRevocation` and `SigningRing` and rebuilds on a change at once, not at the daily reconcile.

#### The edge

The edge's settings (its time to live, its stale window and its fallback) are delivered by infrastructure code and not by sluis, and `sluis config check` cannot see them; the requirements below are checked by reading the edge of a test installation. **UNVERIFIED until the first measurement on the first edge (2026-11-06):** that a purge by address evicts a stale copy, that the stale window can be bounded at 65 minutes, that the fallback to `entry` can be set, and the 60 seconds of the next part. The measurement is part of [#1454](https://github.com/truvity/sluis/issues/1454) and fills the rows of the [incident page](/security/incident-response/#measured-times).

- **A bucket destination has an `edge` setting: `none` or a named edge.** `none` is what the directory and the local installation use. The first named edge is Cloudflare in front of R2, for the boards. Another edge arrives with the first installation that needs it ([principle 11](/principles/#11-one-product-many-installations)).
- **The edge keeps the key set for at most its `max-age`** ([REQ-KEYS-084](/requirements/keys/#REQ-KEYS-084), [#1338](https://github.com/truvity/sluis/issues/1338)).
- **The static document is the public `jwks_uri` wherever a bucket destination exists, and the edge falls back to the live key set of `entry` when the bucket cannot be read** ([REQ-EXPORT-025](/requirements/export/#REQ-EXPORT-025)). Both filter revoked kids, and `entry`'s fails closed ([REQ-KEYS-107](/requirements/keys/#REQ-KEYS-107)). An installation without a bucket destination serves `entry`'s key set alone.
- **If the bucket and `entry` both fail, the edge may serve a cached copy for at most 65 minutes after it expired** ([REQ-EXPORT-023](/requirements/export/#REQ-EXPORT-023)). That is the access-token cap of one hour plus five minutes of clock skew, the figure of the retention of a retiring key ([0006](/decisions/0006-keys-and-sealing/#rotation)). The bucket and `entry` both being unavailable, no token is signed after the outage began, and a longer window would serve a key set that no live token needs. A purge evicts stale copies too.
- **exporter@ alone holds a purge credential,** and it can purge only the public addresses of the documents of its destinations, nothing else ([REQ-EXPORT-026](/requirements/export/#REQ-EXPORT-026)). It is held beside the destination credential, and the threat model lists it ([T-39](/security/threat-model/#export-and-backup)).

#### The order and the time

After a change of `KeyRevocation` or `SigningRing`, exporter@ does four things in this order ([REQ-EXPORT-021](/requirements/export/#REQ-EXPORT-021)). A destination that has no public address, such as a directory with none declared, cannot read back: its `ReadBack` answers `unsupported`, and the report says `written` and carries no purge or read back time. The confirmation then rests on the live key set of `entry`, and `signer` does not count that document as published.

1. **Write** the new document to the destination.
2. **Purge** its public address. One purge covers the cached copy, whichever back end, the bucket or `entry`, filled it.
3. **Read back** the public address the way a verifier does: no credential and no cache-buster. The answer must be 200 with the written digest.
4. **Report** by writing the temp kind `ExportReport` ([REQ-EXPORT-022](/requirements/export/#REQ-EXPORT-022)): the state, the digest, for a key set the kids it lists, and the times of the write, the purge and the read back. The state is `published` when the read back matches, `purge-pending` while a purge or a read back is being retried, `written` when the destination cannot read back, and `unverified` when exporter@ could not tell. `published` needs a purge that was accepted (or no edge to purge) before the read back: a read back after a failed purge says nothing about the other copies of the edge. A configuration that gives a public address to a destination whose driver cannot read it back is refused.

The write, the purge and the read back finish within 60 seconds of the moment exporter@ sees the change ([REQ-EXPORT-028](/requirements/export/#REQ-EXPORT-028)). This is a target and not a measurement, and UNVERIFIED until the first measurement on the first edge (2026-11-06): the first drill replaces it with the measured figure ([REQ-OPS-080](/requirements/ops/#REQ-OPS-080), [Incident response](/security/incident-response/#measured-times)). A step that fails is retried with a back-off, and past the 60 seconds it raises an alarm. The daily reconcile runs the same four steps, so a report that nothing refreshes expires with its time to live, and a reader treats an absent report as "not seen".

`signer` makes a token key active only after the report of every published key set has the state `published`, lists the key's `kid` and has a read back at most 26 hours old (a day of the reconcile and a margin, [REQ-KEYS-116](/requirements/keys/#REQ-KEYS-116)), and the lead time has passed since that read back ([REQ-KEYS-085](/requirements/keys/#REQ-KEYS-085)). A replacement for a revoked key signs only after the report shows the key published and purged ([REQ-KEYS-089](/requirements/keys/#REQ-KEYS-089)).

#### When exporter@ cannot tell

- **When exporter@ cannot read `KeyRevocation` or `SigningRing`, it leaves the published object as it is, raises an alarm and reports `unverified`** ([REQ-EXPORT-024](/requirements/export/#REQ-EXPORT-024)). It does not delete or empty the object. The one change it makes is a removal: a key that a `KeyRevocation` event has just named is taken out of the last good document, because removal is monotone (no revocation puts a key back) and needs nothing that cannot be read; nothing is added, and the state stays `unverified`. The alarm repeats every five minutes while the state lasts, with the number of documents in it, and each way into and out of the state is one audit fact. A blip of store@ would then stop verification for every relying party, and exporter@ cannot learn of the revocation it cannot read in any case ([0010](/decisions/0010-backup-and-recovery/#a-regional-outage)).
- **`signer` holds activation while a report does not list the key as `published` within the 26 hours, and `sluis key revoke` prints "not confirmed"** ([REQ-KEYS-116](/requirements/keys/#REQ-KEYS-116), [REQ-KEYS-088](/requirements/keys/#REQ-KEYS-088)). The live key set of `entry` goes on failing closed.
- **exporter@ down leaves the object as it was.** Its reports expire, so `signer` holds, and the start reconcile runs the four steps again.

#### Confirmation

`sluis key revoke` does not trust the report: it checks, and it reports "not confirmed" until both of these lack the revoked `kid` ([REQ-KEYS-088](/requirements/keys/#REQ-KEYS-088), [principle 4](/principles/#4-verify-never-trust-a-claim)):

- the public `jwks_uri`, fetched through the edge as a verifier fetches it;
- the live key set of `entry`, fetched from `entry`'s own listener, which is what the edge falls back to. How the command reaches it on each runtime is in [`sluis key revoke`](/reference/cli/#sluis-key-revoke).

#### The destination port

Each destination type is a driver behind the port `destination`, private to exporter@ ([0005](/decisions/0005-the-store/#drivers)). The port has five calls ([REQ-EXPORT-027](/requirements/export/#REQ-EXPORT-027)):

| Call | What it does |
|---|---|
| `Put` | Writes a document whole at an address, with its content type and `Cache-Control`, and returns its version |
| `Delete` | Removes a document that exporter@ wrote |
| `List` | Lists, under a prefix, the documents that exporter@ wrote with their digests, so that a reconcile can compare and remove |
| `Purge` | Evicts the edge copy of public addresses; with `edge: none` it answers `none` |
| `ReadBack` | Fetches a public address the way a verifier does, with no credential and no cache-buster, and returns the status, `Cache-Control`, `Age`, the cache state the edge reports, and the body |

A driver for a store of record or a Kubernetes Secret implements `Put`, `Delete` and `List`, and answers `unsupported` to `Purge` and `ReadBack`, because it has no public address. Like every port it has `serve`, `check`, `version` and `conformance`, and the in-memory driver passes the suite. The first drivers are `directory` for the local installation and a bucket driver on S3-compatible storage with the Cloudflare edge for the boards. The port is not the audit blob port, which is create-if-absent and cannot overwrite, delete or purge ([0029](/decisions/0029-the-audit-log/#the-write-once-fence)).

### Refusals

- **exporter@ refuses a write** for a kind that is not marked, for a destination that is not configured, for a sealed kind sent to a bucket, and for a value that key@ refuses on its grant check.
- **A refusal is an audit fact and an alarm,** not a retry loop. The next reconcile tries again, and an operator sees why it was refused.

## Consequences

- What leaves sluis is a short, reviewed list, and a reader of the registry can see every export and its consumer.
- A cluster reads a client secret from a store of record with its own identity, and sluis holds no cluster identity. A single cluster without a store of record can take the direct path, at the price that exporter@ holds one cluster credential.
- A secret is readable outside sluis only through an export. An operator who wants the cloud console to show a value gets it from the store of record, not from sluis.
- exporter@ is one more unit in every installation that exports. It shares its family with store@ and never shares a unit with a work actor.
- The principles page loses the absolute "sluis never writes Kubernetes objects" and gains the amended sentence.
- A revoked key leaves the edge within 60 seconds by target, and a verifier's own copy expires within `max-age` after that. If the purge fails, the edge copy lives for its time to live on top of that. The first drill measures both.
- exporter@ holds one more credential, the purge, which is narrow: it can evict named public addresses and write nothing. A compromised exporter@ can already write the key set; the purge adds the power to make an edge forget it.
- The key set has two back ends behind one address, so a revocation has two places to be checked, and the confirmation checks both.
- exporter@ is in the first version, with the directory driver, and then the bucket and the purge for the boards, so the foundation of the first version is store@, exporter@ and key@, as [0002](/decisions/0002-families-of-actors/#the-foundation-and-the-modules) says.

## Roads not taken

- **Always go through a store of record and External Secrets.** One rule instead of two, but a single cluster would need a store it does not otherwise have.
- **Write into the secret source.** sluis would read back what it wrote, and the same value would be IaC-written and sluis-written.
- **Each work actor exports its own kinds.** Work actors would hold destination credentials, against principle 16.
- **store@ does the exporting.** It would hold destination credentials beside its storage credentials and mix serving with publishing.
- **Export any kind on request.** Whether a value may leave sluis would become a run-time choice instead of a property of the kind, and the rules could not be generated from the registry.
- **A drop of files encrypted to a consumer's own recipient.** No consumer is named for it, so none is built; the first one arrives as a new destination type with its consumer.
- **A general-purpose secrets engine with dynamic secrets, leases and transit.** It is the product of another team and widens the trusted base.
- **Export a secret for a vendor sluis can mint for.** A long-lived copy would exist where a short-lived scoped credential is possible.
- **No purge: the edge never caches the key set.** It needs no purge credential, but every fetch of a verifier reaches the back end, and the key set no longer outlives an outage of the bucket's region ([0010](/decisions/0010-backup-and-recovery/#a-regional-outage)).
- **Purge by hand.** It needs no code, and it is slow at the worst moment; the confirmation and the replacement ([REQ-KEYS-089](/requirements/keys/#REQ-KEYS-089)) could not rely on it.
- **A versioned address for the key set.** The discovery document names one `jwks_uri`, and relying parties cache that document, so a new address would reach them slower than the key set itself.
- **Delete or empty the published key set when `KeyRevocation` cannot be read.** `entry` answers 503 then, but a blip of store@ would become an outage of verification for every relying party.
- **Only the live key set, with exporter@ just purging.** Verification would depend on the compute of the issuer, against [0017](/decisions/0017-identity-and-sign-in/#issuers).
- **Only the static key set, with no fallback to `entry`.** One back end instead of two, but a failed bucket would leave the edge's stale window as the only protection.
- **Confirm from the report of exporter@.** It proves what exporter@ saw and not what a verifier sees, against [principle 4](/principles/#4-verify-never-trust-a-claim).
- **Reuse the audit blob port.** Its writes are create-if-absent, and a key set must be overwritten, removed and purged.

## Follow-ups

- Build of exporter@ in the first version: the directory driver, the static key set and the report ([#1453](https://github.com/truvity/sluis/issues/1453)), then the bucket driver, the Cloudflare purge for the boards and the measurement of the edge ([#1454](https://github.com/truvity/sluis/issues/1454)). They serve [#962](https://github.com/truvity/sluis/issues/962) (static discovery and key set), [#1338](https://github.com/truvity/sluis/issues/1338) (the header and the edge time to live) and the confirmation of `sluis key revoke` ([#1362](https://github.com/truvity/sluis/issues/1362)).
- The rest of exporter@: the other destination drivers, the other exportable kinds, the daily reconcile for them, the Lambda trigger and the conformance suite: [#1014](https://github.com/truvity/sluis/issues/1014).
