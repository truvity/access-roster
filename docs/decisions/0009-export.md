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
- **A bucket** receives public material at static addresses: the key set, certificate chains, revocation lists and the trust bundle. A bucket never receives `ClientSecretExport`; the configuration check refuses that pairing.
- **A single cluster may receive a Kubernetes Secret directly,** written by exporter@ alone and only when the installation chooses the direct path. exporter@'s cluster credential is limited to writing the named Secrets in the named namespaces, and the threat model lists it.
- **The amended rule:** sluis writes no Kubernetes object, except an exported Secret written by exporter@ when an installation chooses the direct path. Cluster tools such as cert-manager, trust-manager and External Secrets stay its clients and distributors.
- **A destination may not overlap a secret source.** The configuration check refuses a destination whose address is also read as a secret source ([secret sources](/decisions/0005-the-store/#secret-sources)), so sluis never reads back what it wrote and no value has two writers.

### Watch and reconcile

- **exporter@ watches the exportable kinds from a resume point** ([0005](/decisions/0005-the-store/#watch-and-the-resume-point)) and keeps the resume point of each destination in a temp kind, `ExportCursor`. Losing it costs a full reconcile, not data.
- **A sealed value is opened at key@ with exporter@'s own grant,** written with the destination credential, and every write is an audit fact. The grant is sealed for the tenant of the value ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). Public material is read and written as it is.
- **A full reconcile runs at start and once a day.** It writes what is missing or different at the destination and removes what exporter@ wrote for a value that no longer exists, so a missed change or an edit made at the destination is corrected within a day.

### Refusals

- **exporter@ refuses a write** for a kind that is not marked, for a destination that is not configured, for a sealed kind sent to a bucket, and for a value that key@ refuses on its grant check.
- **A refusal is an audit fact and an alarm,** not a retry loop. The next reconcile tries again, and an operator sees why it was refused.

## Consequences

- What leaves sluis is a short, reviewed list, and a reader of the registry can see every export and its consumer.
- A cluster reads a client secret from a store of record with its own identity, and sluis holds no cluster identity. A single cluster without a store of record can take the direct path, at the price that exporter@ holds one cluster credential.
- A secret is readable outside sluis only through an export. An operator who wants the cloud console to show a value gets it from the store of record, not from sluis.
- exporter@ is one more unit in every installation that exports. It shares its family with store@ and never shares a unit with a work actor.
- The principles page loses the absolute "sluis never writes Kubernetes objects" and gains the amended sentence.

## Roads not taken

- **Always go through a store of record and External Secrets.** One rule instead of two, but a single cluster would need a store it does not otherwise have.
- **Write into the secret source.** sluis would read back what it wrote, and the same value would be IaC-written and sluis-written.
- **Each work actor exports its own kinds.** Work actors would hold destination credentials, against principle 16.
- **store@ does the exporting.** It would hold destination credentials beside its storage credentials and mix serving with publishing.
- **Export any kind on request.** Whether a value may leave sluis would become a run-time choice instead of a property of the kind, and the rules could not be generated from the registry.
- **A drop of files encrypted to a consumer's own recipient.** No consumer is named for it, so none is built; the first one arrives as a new destination type with its consumer.
- **A general-purpose secrets engine with dynamic secrets, leases and transit.** It is the product of another team and widens the trusted base.
- **Export a secret for a vendor sluis can mint for.** A long-lived copy would exist where a short-lived scoped credential is possible.

## Follow-ups

- Build of exporter@, its destination drivers and the conformance suite: [#1014](https://github.com/truvity/sluis/issues/1014).
