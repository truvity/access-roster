# 0009 — The secrets port has one driver, sealed state, and the export port publishes only kinds marked external

**Status:** Accepted
**Date:** 2026-11-02

Proposal: [issue #1014](https://github.com/truvity/sluis/issues/1014).

## Context

sluis holds secrets because it has to: a vendor-issued App key, a bot token, a generated client secret. It is not a secrets engine for anyone else ([Data and secrets](/concepts/data/#secrets-and-export)). [0005](/decisions/0005-the-store/#sealed-secrets) lets state hold a sealed secret on every runtime and leaves the interfaces of the `secrets` and `export` ports to this record. [0004](/decisions/0004-the-data-model/#backup-and-restore-by-origin) says that whether a value may leave sluis is a property of its kind.

v1 had a secrets port with four stores (a cloud parameter store, OpenBao KV v2, Kubernetes Secrets, memory) and exported typed credential documents to OpenBao (parity row [#798](https://github.com/truvity/sluis/issues/798); v1 ADR 0028 and the v1 secrets reference, on `master`). v2 has no OpenBao driver and writes no Kubernetes objects (principles, "What sluis is, and is not").

The forces: principle 8 (nothing without a consumer) and principle 10 ("A port has one driver until a second real installation needs another"), which point the same way here; principle 1 (the sealing key never leaves its store); and the boards, which have no cloud store at all.

## Decision

### The secrets port

- **The port holds whole values under addresses** `<boundary>/<owner>/<name>`, where the owner is the actor or integration that wrote the secret. A secret is never a plain record in `state` ([0004](/decisions/0004-the-data-model/#sensitivities)).
- **Four operations:** `get` (the current version, or a named one), `put` (creates a new version, as compare-and-set against the revision the caller read), `delete` (a version, or all of them), and `list`, which returns names and metadata and never a value. There is no unconditional put.
- **Each version is one immutable item,** and a record names the current version, so a rotation overlaps with its predecessor. A store that keeps only one version is refused at start (REQ-SECRETS-007).
- **Stores and sources.** A **store** is writable and holds sluis's own secrets. A **source** is read-only and supplies referenced and bootstrap secrets: a systemd credential or a mounted file. A declared field that names a secret names a source or the operator's own store, and sluis only reads it. A store's own credentials always come from a source.
- **Every driver declares these flags,** and `sluis config check` refuses an installation that needs one the driver lacks: `writable`, `encryption` (at rest, by whom), `versioned`, `consumer-readable` (a consumer outside sluis can read the store with its own identity) and `per-path-grants`.
- **A secret that only sluis uses lives in a namespace granted to no consumer** (REQ-SECRETS-010).

### One driver: sealed state

- **`sealed-state` is the one `secrets` store in 2.0, on every runtime.** It keeps ciphertext in `state`, with the envelope and `purpose=secret` of [0005](/decisions/0005-the-store/#sealed-secrets), so it works wherever a state driver does, and the archive carries it sealed ([0010](/decisions/0010-backup-and-recovery/)). Its `consumer-readable` flag is false.
- **A cloud parameter store, a Kubernetes Secret or an OpenBao store is not a driver.** One is added only with a named consumer: a value that something outside sluis must read with its own identity, and that is not served by an export. The consumer is named in the issue that adds the driver.
- **Sealing, re-sealing and loss of the sealing key** are as [0005](/decisions/0005-the-store/#sealed-secrets) and [0010](/decisions/0010-backup-and-recovery/#the-archive) say. This record does not restate them.

### The export port

- **An export is a typed, versioned document** with a kind, a schema and a version, stored once at `<boundary>/export/<consumer>/<kind>`. A breaking change is a new version written beside the old one for a declared window (REQ-SECRETS-006).
- **Only a kind marked external (`x-sluis-external`) may be exported.** The marker is a property of the kind in the schema ([0004](/decisions/0004-the-data-model/#sensitivities)); the port refuses any other kind, and every export is authorised and audited (REQ-EXPORT-003, REQ-EXPORT-004). A secret referenced from declared configuration is never exported: the consumer is granted the operator's own path, which sluis may render for the operator to apply.
- **Operations:** `put`, `delete` and `status`. A consumer reads an export with its own identity; sluis never holds the consumer's identity, only its public recipient (REQ-EXPORT-005).
- **Export drivers at parity:** `publication`, which puts public material (the key set, CA certificates, trust bundles) at static addresses through a blob. Its consumers are every relying party and every cert-manager or trust-manager installation.
- **A drop driver (a file in a directory, an object in a bucket) is added only when an issue names its consumer.** A drop is age-encrypted to the consumer's own recipient and is a derived, single-writer artefact replaced as a whole (REQ-EXPORT-002). None has a named consumer today, so none is built; the rule is recorded so that the first one is written the same way.
- **No export carries a secret for a vendor that sluis could mint for** (REQ-SECRETS-008): sluis mints a scoped credential instead ([0049](/decisions/0049-credential-minters-mint-only-for-declared-targets-whose-entitlement-sluis-governs/)).

## Consequences

- Parity row #798 is delivered by a smaller port: v1's four stores and its export to a vault are not carried. A v1 consumer that read an exported credential from OpenBao is wired differently in the cutover inventory ([#1017](https://github.com/truvity/sluis/issues/1017)).
- Every installation tests one secrets path, the one that already holds the vendor-issued secrets of the boards. The price is that a secret is readable only through sluis: an operator who wants the AWS console to show it cannot.
- Principle 10 asks for a second driver only when a second installation needs one, and none does: the state drivers underneath (embedded, rqlite, DynamoDB) already serve every installation. The first consumer of a second secrets driver will say what it needs.
- A new external kind needs a schema marker, a consumer and a grant, in that order, and the checks that generate the deny matrix follow.
- Requirements: REQ-SECRETS-013 and REQ-EXPORT-007 are added. The explanation page loses its proposed note.

## Roads not taken

- **A cloud parameter store driver for AWS installations.** It has size limits on a value, a second sealing path to test and no consumer that `sealed-state` does not serve.
- **An OpenBao driver, or an export to a vault.** v2 has no OpenBao, and a vault would hold a copy of a secret that sluis already holds; the consumer is granted a path or minted a credential.
- **Kubernetes Secrets as a store or an export.** sluis writes no Kubernetes objects; clusters pull from it.
- **A general-purpose secrets engine with dynamic secrets, leases and transit.** It is the product of another team and widens the trusted base (REQ-SECRETS-009).
- **Build the file drop and the bucket drop now.** They are described, but nothing reads them; principle 8.
- **Export any kind on request.** Whether a value may leave sluis would become a runtime choice instead of a property of the schema, and the deny matrix could not be generated.

## Follow-ups

- Build of `sealed-state`: [#957](https://github.com/truvity/sluis/issues/957); of the ports and the conformance suite: [#798](https://github.com/truvity/sluis/issues/798).
- Generated client secrets and rotation on top of the port: [#790](https://github.com/truvity/sluis/issues/790).
