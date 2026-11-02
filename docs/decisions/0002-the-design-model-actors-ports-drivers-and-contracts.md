# 0002 — The design model: actors declare ports, drivers declare requirements, placement is derived, and a permission manifest per actor generates the enforcement

**Status:** Accepted; amended by 0057
**Date:** 2026-11-01

Proposal: [issue #901](https://github.com/truvity/sluis/issues/901).

## Context

sluis v1 is one issuer function that serves sign-in, machine token exchange and downstream minting, and it touches 25 resources; least privilege cannot be expressed for something that broad. v1 later split its parts by credential holder (v1 ADR 0071, on `master`), and its contracts are Protobuf served over Connect (v1 ADR 0064, on `master`). This record is the v2 successor of both, for the method.

v2 is several processes. Each needs keys, state, a lease, blob storage, a transport, an index, a secret or a cloud credential, and each of those has several implementations: a hardware key or a cloud key service, an embedded store or a replicated one, a spool on disk or a managed queue. Deciding per deployment where each process runs, and writing each runtime's permissions by hand, repeats the rules in every deployment and lets an IAM policy, a key policy, a systemd unit and a network rule drift apart. A component that calls another through a plain function call cannot later move into its own process without a rewrite.

We need one model that says what a process needs, what an implementation needs, where a process may run and where its permissions come from, so that a tool can check an installation instead of a reader checking a table.

## Decision

### Ports and drivers

- **An actor declares the ports it requires.** An actor is a process with one responsibility ([0003](/decisions/0003-core-actors-with-one-responsibility-each/#the-actors)). For each port the actor says required or optional; for example, `signer` requires keys, state and transport.
- **The ports are keys, state, lease, blob, transport, index, cloud, witness, secrets, export and config-source.**
  - `keys`: `sign`, `public-key`, `wrap` and `unwrap`. A key never leaves its store ([0012](/decisions/0012-cryptography-and-authority-keys/#keys-sign-in-place)).
  - `state`: records with a revision and compare-and-set; every value is encrypted in the port library ([0011](/decisions/0011-state-is-one-port-with-compare-and-set/#every-value-is-encrypted)). `lease`: `acquire` and `renew` with a fencing token, on the state store ([0011](/decisions/0011-state-is-one-port-with-compare-and-set/#leases)).
  - `blob`: `put-once`, `get` and `list`, with a lock mode. `transport`: `put`, `receive` and `ack`, or a stream. `index`: `write` and `query`. `witness`: `cosign`. `cloud`: credentials for a cloud role.
  - `secrets` holds sluis's own secrets and its integrations' secrets, sealed as [0011](/decisions/0011-state-is-one-port-with-compare-and-set/#sealed-secrets) says. `export` publishes a small, typed set of documents that something outside sluis may read; its consumer is the export API ([REQ-SECRETS-001](/requirements/secrets/#REQ-SECRETS-001) onwards). sluis is not a general secrets engine, and it never writes into the systems that read an export.
  - `config-source`: `read` of one configuration document as bytes, with a `watch` flag; an installation has a list of sources, composed by disjoint ownership of paths ([0057](/decisions/0057-configuration-sources-are-a-port-sources-own-disjoint-paths-authority-is-signed-and-a-failing-source-keeps-the-version-in-force/)).
  - Audit uses the same port definitions as the rest of sluis and adds only `witness`. A new port amends this record.
- **Ports carry capability flags.** `blob` has a lock mode (none, removable, compliance); `state` has compare-and-set. A consumer asks for the flag it needs, and only drivers that offer it qualify.
- **A driver declares its requirements.** A driver implements one port, or two (rqlite serves state and lease). It says whether it needs a long-running process, a persistent local disk, how many nodes it supports and which outside dependency it needs (a cloud account, a hardware key on each node, a message service). Drivers are platform-started services on Unix sockets ([0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#drivers-are-platform-started-services)).
- **A driver runs per actor and holds only that actor's credential, unless its backend cannot tell callers apart.** That leaves one mediator, `key-holder` ([0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#key-holder-is-the-one-mediator)). Every port is protected in three layers generated from the manifest ([0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#three-layers-per-port)).
- **Every record kind declares its origin and every field its sensitivity** ([0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#origins)). They decide which port holds a value: a secret is behind `secrets`, never a plain record in `state`.

### Placement is derived

- **Where an actor runs is derived from the declarations.** This holds for every sluis actor and for the audit pieces. There are no per-installation placement decisions; a tested installation names only its runtime, its nodes and a default driver per port ([0018](/decisions/0018-runtimes-installations-and-delivery-order/#installations)). Example: with a sqlite index on a cluster, the reader runs on the indexer's node, because sqlite has one writer and needs local disk.
- **Some actors declare `instances: exactly 1`:** the audit writer of one log, the facts-source reconciler and the indexer. With more than one node, or elastic nodes, such an actor needs the lease port ([0011](/decisions/0011-state-is-one-port-with-compare-and-set/#leases)). On serverless a concurrency limit of 1 is an optimisation, not the guarantee: the lease and the target store's own fence are.
- **`sluis config check` enforces the rules.** It validates an installation against what its drivers declare (runtime, node count, available dependencies), refuses a driver attached where the runtime cannot provide it, and warns about allowed but weaker choices, such as an audit log with no witness.

### Contracts

- **Every major component is a ConnectRPC contract, even when caller and callee share a process.** In-process calls use an in-memory transport, so moving a component into its own process changes configuration, not code. The same contract is served over a Unix socket with peer credentials locally, a Lambda invoke on AWS, and HTTPS with mutual TLS remotely.
- **Contracts are written in Protobuf.** The `proto/` directory is the source of every contract, and a contract change is reviewed there first. Other descriptions, such as OpenAPI, are generated from it.

### The permission manifest

- **One permission manifest per actor is the spine.** It states which record kinds the actor reads and writes, which of its kinds accept operator-set writes, which secrets and keys it may use, which hosts it may reach, which actors may call it and which it calls. The manifests live in `manifest/`.
- **Nothing that enforces least privilege is written by hand.** The manifest generates, for every runtime: IAM and trust policies; key policies, one actor per key; the access lists and per-caller sockets of `key-holder` and the users of each per-actor rqlite cluster; systemd units and sandbox drop-ins; network rules (nftables, Kubernetes NetworkPolicies); the call graph, which is default deny, enforced by one interceptor in every process; and, with the schema's origin and sensitivity annotations, the backup list, the telemetry allowlist and the audit redaction.
- **Enforcement is tested, not assumed.** The deny matrix is generated from the same data: for every pair of actors, X is denied Y's records, secrets, keys and sockets, and a test proves it. The blast-radius report of every actor is checked in, so a pull request shows what a change grants.

### Three zoom levels

The design is described at three levels, and the output of each is the input of the next:

- **L1, black box:** what sluis does, for whom, and which resources each use case touches.
- **L2, components:** which component owns each operation, through which contract and ports, the call graph, and one writer per record kind.
- **L3, processes:** the actors, one permission manifest each, packaging, and the enforcement in each runtime.

### Words

"Actor" replaces "role" and "process role"; the directory of the actors' executables is `actors`. "Runtime" is the kind of place processes run ([0018](/decisions/0018-runtimes-installations-and-delivery-order/#runtime-kinds)), "environment" is development, staging or production, and "installation" is one concrete deployment. Instance names are fixed in [0003](/decisions/0003-core-actors-with-one-responsibility-each/#names).

## Consequences

- A new platform or driver adds a row of requirements, not placement rules in every installation. Compatibility between a driver and a runtime is a derived table, checked by a tool.
- Audit reuses the driver code, tests and conformance suite of sluis, and adds one port.
- A reviewer can follow one use case from the black box down to the credential that serves it, and the runtimes differ in the mechanism that enforces the manifest, not in the actors.
- A component can start inside another process and move out later. The cost is a contract, and a generated client and server, for components that would otherwise be one function call; every language in use needs a ConnectRPC kit over Unix sockets and a conformance suite.
- Drivers must state their requirements truly: a wrong declaration lets `sluis config check` pass an installation that fails at run time, so each driver's conformance tests verify what it declares.
- The manifest and its generators are a large piece of work and a single point of failure: a wrong generator grants what the manifest does not say. Each generator needs golden tests and the deny matrix, and review of the manifest and the blast-radius report is where the design is held to account.
- Until the manifest exists, the architecture diagrams are written by hand in Mermaid; afterwards they are generated from the design model.

## Roads not taken

- **Separate audit ports.** Every driver would be written and tested twice, while audit needs the same kinds of storage and costs one extra port when it shares them.
- **Placement decided per deployment.** The same rules would be repeated in every deployment and drift apart, and each new platform multiplies the decisions.
- **A mediating driver for every backend with one login (`key-holder` and a `state-owner`).** A mediator sits in the data path with code as its access list and adds no check for a backend that checks callers itself; rqlite is light enough to run a cluster per owning actor.
- **Hand-written policies per runtime.** The IAM policy, key policy, unit and network rule of one actor would drift apart, and a reviewer could not see what a change grants without reading all of them.
- **Plain interfaces inside a process, contracts only between processes.** Moving a component into its own process, the move least privilege wants, would become a rewrite.
- **Hand-written OpenAPI, or gRPC only.** OpenAPI drifts from the code the first time one is edited without the other (v1 ADR 0064), and gRPC alone is not reachable from a browser or a function gateway without the translation Connect already is.
- **Keep the word "role".** It already means a user role in scopes and a cloud role in IAM, so a process called a role is ambiguous in every sentence about access.

## Follow-ups

- The interface details of the `secrets` and `export` ports: [#1014](https://github.com/truvity/sluis/issues/1014).
