# 0057 — Configuration sources are a port: sources own disjoint paths, authority is signed, and a failing source keeps the version in force

**Status:** Accepted
**Date:** 2026-11-02

Proposal: [issue #1156](https://github.com/truvity/sluis/issues/1156).

## Context

Declared configuration has one strict loader today. It reads one install file under the strict YAML profile and the generated schema, and Go and Rust agree on every vector of spike S7 ([#945](https://github.com/truvity/sluis/issues/945), [0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#pkl-and-json-schema)). Records already say that declared configuration has more than one home: [0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#origins) lists files, a ConfigMap, a Lambda layer, AWS AppConfig and "signed fragments merged by the scope each publisher owns", and [0031](/decisions/0031-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/) delivers workforce authority and per-customer defaults through a configuration service. What no record gives is the seam: the way several sources are put together, and the way a source that is not a file is trusted.

The maintainer asked for that seam to be generic, like a port with drivers, and for the drivers on offer to be limited by what an installation has: no AWS, no AWS AppConfig. This record designs it with the vocabulary of [0002](/decisions/0002-the-design-model-actors-ports-drivers-and-contracts/#ports-and-drivers). The principles that settle it are 4 (verify, never trust a claim), 6 (a written contract with vectors, not shared code), 8 (nothing without a consumer) and 10 (one product, many shapes); principle 10 is read in both of its wordings, and `file` and `appconfig` meet both because each has a real installation.

## Decision

### A port, `config-source`

- **`config-source` is a port, the eleventh in the list of 0002.** A source is one named place that holds one document of declared configuration. The port has one operation, `read`, which returns the document's bytes and a version label, and a capability flag `watch`: `none`, `notify` or `poll`.
- **A driver returns bytes and never parses them.** The loader of the kits applies the strict YAML profile and the schema ([Install file](/reference/install-file/#format)), so strictness lives in one place per language and a driver cannot make it weaker. The port is read-only: sluis writes to no configuration service, and "promote to declared" still renders a fragment for review ([0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#origins)).
- **`file` is offered by every installation.** A path on disk. A Lambda layer is a file, and so is a ConfigMap mounted into a pod; there is no ConfigMap driver, because reading the object would need a credential and a Role that a mounted file does not. `file` runs in the port library of the actor, not as a service: the install file is read before any driver can start, and a `file` driver holds no credential. Its check is the file's mode.
- **`appconfig` is offered by installations that have AWS.** It reads one AWS AppConfig configuration profile through the AppConfig data API, not through the agent, as [Serverless](/runtimes/serverless/) says. It is a driver as 0004 describes: on Lambda it is part of the `aws` extension, on Kubernetes a native sidecar, and it holds only its actor's credential from the `cloud` port, so the AppConfig permission is per actor and per profile ([0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#three-layers-per-port)).
- **Other services are planned lines, with no promise and no issue:** Azure App Configuration, Google Cloud Parameter Manager, Consul and etcd. Each arrives with the first installation that needs it, as principle 8 says, and as a driver of this port with no change to the rules below.
- **Unlike the other ports, this one takes a list.** An installation has one driver for keys or state, and several sources of configuration, because composing them is the purpose of the port.

### The sources of an installation

- **The install file is the base.** It is always read from a file, first, and nothing can replace it. It carries `sources`, an ordered list. Each entry has a `name`, a `driver`, the paths it `owns`, how its document is `verify`-ed, and the driver's own settings. The exact shape is [Configuration sources](/reference/config-sources/#the-sources-list).
- **The base keeps the keys that say where to read and whom to trust:** `$schema`, `runtime`, `environment`, `nodes`, `drivers`, `sources` and `trust`. A source cannot own them, because a source that could rewrite the list of sources, or the roots, would choose its own authority.

### Composition: disjoint ownership, no override

- **Each source owns paths and the paths of the sources are disjoint.** A path is a JSON Pointer (RFC 6901) through mappings: `/policy`, `/boundaries/dev/clients`. The base owns every path that no source owns. The merged document is the union of the owned subtrees. No source wins over another, because no two of them can set the same key.
- **What is refused** ([the list and the vectors](/reference/config-sources/#composition)): two sources with the same path or one inside another; the base setting a key under a path a source owns, even to the same value; a source document with a key outside its paths, or without one of its paths; a path through a sequence; an owned path that is a base key. A sequence is a value, never merged or appended to; `null` is a value, never a deletion.
- **The result does not depend on the order of the list.** The order is the order of reading and of reporting, and nothing else.
- **Layers are separate.** Composition builds the install layer of 0010. The defaults, the runtime and the environment overrides of the other layers apply after it, as 0010 says, and an override still touches tunables only.

This is the rule 0010 already states for fragments ("the fragment that writes outside its publisher's scope is refused"), made exact. It follows from the strict loader's own rules: the profile refuses a duplicate key and a merge key inside a document, so a merge across documents that silently chose one would be weaker than the rule inside one. A later-wins layer would let a document in a configuration service override a reviewed file with no trace in git, which principle 4 does not allow.

### Validation

- **Each document is checked before it is merged:** the signature if there is one, then the strict YAML profile, then the ownership rule, then the schema of each owned subtree.
- **The merged document is checked once, after composition,** against the whole schema, and then by the checks of `sluis config check` that span keys, such as an upstream's `org` naming a company boundary. An error names the source and the path, never the value.
- **Vectors.** The composition rules have their own vector set, run by the Go and Rust loaders beside the profile vectors; the first rows are in [Configuration sources](/reference/config-sources/#composition).

### Environment limits

- **An installation offers the source drivers it can run.** The driver table says what each needs ([Ports and drivers](/concepts/drivers/#what-each-driver-requires)): `file` nothing, `appconfig` AWS credentials from the `cloud` port. The shapes declare their offer in [Installations](/runtimes/installations/#configuration-sources): `file` in all four tested installations, `appconfig` in lambda and kubernetes, and not on boards.
- **`sluis config check` refuses a source the installation does not offer,** with the check of 0002 for any driver: an `appconfig` source on boards says that the installation has no AWS ([how it checks](/concepts/drivers/#how-sluis-config-check-validates-an-installation)).

### Declared versus issued

| Document | May come from | Verified by |
|---|---|---|
| The base keys above | The base file only | The file's mode, as any file of the install |
| Authority (a field marked `x-sluis-authority`) | `file`, or `appconfig` | `host` (the mode of a file; a mounted ConfigMap's access rules) or `signed` |
| A per-customer default (a field marked `x-sluis-defaults`, a new annotation beside those of 0010) | `appconfig` only, never git | `service`: the service's own identity and change history ([0031](/decisions/0031-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/#customer-identity-installations)) |
| Operator-set, learned and issued kinds | No source | The schema refuses them in a source |

- **How sluis proves an AppConfig document is the reviewed file (principle 4).** Authority delivered through a service is a signed document: a compact JWS (RFC 7515) with `alg` ES384, whose payload is the exact bytes of the reviewed file and whose `kid` names a publisher key listed in the install file. The operator's pipeline signs after the merge, with a key in its own key service; sluis holds the public key only. The loader verifies the signature over the received bytes before it parses them, and refuses any other `alg`, `crit`, `jku`, `x5u` or embedded `jwk`. The audit record of a start or reload names the SHA-384 of the payload, so a reviewer matches it to `sha384sum` of the file at the commit ([0031](/decisions/0031-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/#workforce-installations)). The signature proves the publisher and the bytes; that the commit was reviewed is git's branch protection.
- **A sequence number in the signed header** stops a running process from taking an older signed document than the one in force.
- **`service` never owns authority.** `sluis config check` refuses a source whose paths hold an authority field unless it is `host` or `signed`, and refuses a `x-sluis-defaults` field from any source that is not `service`.

### Reload

- **The unit is the composition.** When any source changes, the loader reads all sources again, composes, validates the whole result and swaps it atomically; one source is never applied alone. What a reload is, that it is audited with digests and that a failing snapshot is refused is 0010 and [#977](https://github.com/truvity/sluis/issues/977) ([REQ-OPS-021](/requirements/ops/#REQ-OPS-021)); this record adds only how a driver signals a change.
- **`file` signals by notify.** The loader watches the directory, so the atomic swap of a mounted ConfigMap or a replaced file is seen. A Lambda layer cannot change under a running function: its `watch` is `none`, and a new layer is a new function version.
- **`appconfig` signals by poll.** The driver starts a session, asks for the latest configuration at the interval the service returns, and an empty answer means unchanged. A Lambda sandbox is frozen between invocations, so the poll happens at an invocation once the interval has passed.
- **The list of sources, and a driver choice, are applied at the next start** ([0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#origins)).

### Failure

- **At start, any source that is unreachable, unsigned or invalid stops the start.** Nothing is remembered between starts, there is no cached copy and no fallback to a weaker source. A check that cannot run is reported as not run, never as passed (principle 4), and the other dependencies of the signing path already fail closed ([0056](/decisions/0056-a-regional-outage-is-accepted-public-keys-outlive-it-and-a-drill-measures-recovery/#a-regional-outage)).
- **At reload, the version in force stays.** An unreachable source is retried with a back-off and reported; a document that fails is refused and audited with its digest. A revocation that waits behind an unreachable source is the case the tighten-only switches of 0010 are for: they are operator-set, take effect at once and need no source.

## Consequences

- A new source is a driver of one port: the check, the vectors and the audit stay as they are. The cost is a second table of rules (paths, ownership, verification) that an operator must learn, and a `sources` list in the base that is the one file deployed by hand.
- Authority can be delivered at run time without trusting the service: the access to AppConfig is not the access to authority, because only the publisher key can make a document sluis accepts. A stolen AppConfig credential can withhold or roll back a signed document but not write a new one.
- Disjoint ownership makes the origin of every field one source, so `sluis config explain` can name it and a review of the install file shows who may set what. Moving a path to another source is a change in two places in one commit; a transition where both hold it is refused, and that is the intent.
- Starting needs every source: an AppConfig outage at a cold start stops that start. This adds a dependency to the start of each function of a lambda installation, and the measure of it belongs to that installation's tests.
- A signed document is not fresh: a process that starts may be served an older signed version, and the sequence number only protects a running process. The audit record shows which digest applied.
- Requirements: [REQ-OPS-041](/requirements/ops/#REQ-OPS-041) to [REQ-OPS-056](/requirements/ops/#REQ-OPS-056). This record amends the list of ports in 0002. The pages that follow are [Configuration sources](/reference/config-sources/), [Ports and drivers](/concepts/drivers/), [Installations](/runtimes/installations/) and [Configuration](/concepts/configuration/#sources).

## Roads not taken

- **Later source wins, per key or per document.** A document in a configuration service could override a reviewed file with no trace in git, and the effective value would depend on the order of a list.
- **A deep merge.** What happens to a sequence, a `null` and a key present in one source and absent in another is a choice for every field, and the review of one file no longer shows the result.
- **A merge patch (RFC 7396) or a JSON Patch (RFC 6902).** A patch can be validated only against the document it patches, so a source could not be checked alone, and `null` as a deletion adds a way to remove a reviewed key.
- **A digest of the document pinned in the install file.** Every change of authority becomes a change of the install file and a deployment of it, which is what delivery through a service was meant to avoid; it has no consumer once the signature exists.
- **Trusting the service's own access control for authority.** The right to write to AppConfig would become the right to grant, against principle 4.
- **A last known good copy kept on disk or in `state`.** It is a second, unreviewed home for authority that can hold a revoked grant after the service is fixed.
- **A `configmap` driver that reads the Kubernetes API.** It needs a credential and a Role for objects, and a mounted file gives the same bytes with the platform's own access rules.
- **A configuration service or actor that every actor calls.** A new single point of failure on the start of every actor, for a read that each actor can make for itself with its own credential.
- **The AppConfig agent or its Lambda extension.** A cache between the driver and the signature check, and [Serverless](/runtimes/serverless/) already says the API is used.
- **One driver per port, as for keys or state.** Composition is the purpose of this port.

## Follow-ups

- The loader, the `file` and `appconfig` drivers, the check and the composition vectors: [#1157](https://github.com/truvity/sluis/issues/1157).
- Live reload on every runtime, with the per-driver signals above: [#977](https://github.com/truvity/sluis/issues/977).
