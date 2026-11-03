# 0041 — Core is a few actors with one responsibility each: a slim entry, session, console, exchange, signer, policy, ca and ssh-ca

**Status:** Superseded by 0002
**Date:** 2026-11-03

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

In v1 the issuer is one function that serves sign-in, machine token exchange and downstream minting, and it touches 25 resources. v1 first ran everything as one process (v1 ADR 0037, on `master`), then split the modules by credential holder (v1 ADR 0071) but kept the signer and the console inside the issuer (v1 ADR 0072). A flaw in request parsing in that function still reaches the signing keys.

v2 states the permissions of every process in a manifest ([0002](/decisions/0002-families-of-actors/#the-permission-manifest)), and a manifest is only as narrow as the process it describes. So the question is where the lines between processes go, who holds which key, and when two of them may share a unit on a small machine. The actor that parses unauthenticated internet input must not also be the broadest one, and one integration process must not hold several companies' credentials.

## Decision

### The actors

- **An actor is a process with one responsibility.** It declares the ports it requires ([0002](/decisions/0002-families-of-actors/#ports-and-drivers)).
- **The core actors are these:**

  | Actor | Responsibility | Holds |
  |---|---|---|
  | `entry` | Parses each request, validates it against closed parameter lists generated from the contracts, and routes it to the actor that owns the step. It sits behind the edge connector. | Nothing: no key, no secret, no state, no outbound network. It reaches only the sockets of the actors it routes to (on serverless it invokes them) |
  | `session` | Sign-in, session records, the session cookie and freshness per boundary (step-up) | The cookie-sealing key, behind the keys port |
  | `console` | The operator API, as the browser's backend. It checks the operator's delegation and routes each write to the owning actor | No key |
  | `exchange` | Token exchange (RFC 8693), enrolment, the front of the signing API, and the verifiers of proofs | Verifier drivers, which hold public material only. The enrolment private key stays in `key-holder` or the cloud key service |
  | `signer` | Signs tokens under a signing policy, and artifacts for a grant that `policy` sealed ([0045](/decisions/0045-the-signing-api-signs-sent-content-for-an-authorised-proof-and-returns-an-armoured-detached-signature/)). It is not a pure signing oracle | The token-signing keys and the release-signing key |
  | `policy` | The decision point. A declared Cedar policy maps facts to grants ([0007](/decisions/0007-policy-and-sealed-grants/)). It has no state and no network | Use of the sealing key, to seal grants only ([0006](/decisions/0006-keys-and-sealing/#grants-are-sealed-not-signed)) |
  | `ca` | The X.509 certificate authority | The X.509 CA keys |
  | `ssh-ca` | The SSH certificate authority, for user and host certificates | The SSH CA keys |

- **`entry` routes and does nothing else.** `session` serves sign-in and sessions, `exchange` token exchange and enrolment, `console` the operator API, and `signer` signing.
- **`ssh-ca` is its own actor, separate from `ca`.** An SSH CA is a different authority from an X.509 CA, with a different key, format and relying parties, so a flaw in one does not sign for the other ([0023](/decisions/0023-certificate-authorities/)).
- **`signer` and `policy` are split from the first slice.** v1 deferred the same split and never made it.
- **`signer`, `policy`, `ca` and `ssh-ca` run per boundary** ([0008](/decisions/0008-boundaries-and-tenants/)).
- **A copied token is worth little, and later nothing.** Authorization codes are always bound by PKCE. The first working version issues bearer tokens with short lifetimes, because the relying parties of v1 parity (AWS web identity, the Kubernetes API server, Argo CD) accept bearer JWTs only. Sender-constrained tokens, by DPoP or mutual TLS, arrive after the parity milestone ([#912](https://github.com/truvity/sluis/issues/912)); from then on binding is declared per audience, required where the client and the relying party support it, and the actor that serves the endpoint checks it.
- **`entry` is hardened as the edge it is.** It is written in a memory-safe language ([0012](/decisions/0012-the-language-follows-the-executable/)), fuzzed against its closed parameter lists, loads no plugins and runs on a read-only file system. Its listener is in [0003](/decisions/0003-units-transports-and-fusion/#listeners).
- **The other actors are named elsewhere.** `quota` is the engine of the Quota piece, beside core ([0030](/decisions/0030-audit-records-and-the-usage-stream/#quota)). The audit actors are writer, witness, indexer and reader, with no notary ([0028](/decisions/0028-audit-pieces/#four-pieces)). The platform actors are the node agent `sluis-node` and the one mediating driver, `key-holder` ([0003](/decisions/0003-units-transports-and-fusion/#key-holder-is-the-one-mediator)).
- **Integration actors return facts or carry out effects that core has authorised, and never decide** ([0025](/decisions/0025-integrations/)): upstream, facts source, credential minter, provisioner and notifier. They are split by credential, so each process holds one vendor tenant's credential only. The verifiers of proofs are not actors but verifier drivers of `exchange` ([0022](/decisions/0022-workload-identity-and-host-enrolment/)).

### Names

- **Every actor instance is named `<actor>@<boundary>`,** for example `ca@prod`. The name is generated from the manifest, and the same name appears in every layer:

  | Layer | Example for `ca@prod` |
  |---|---|
  | systemd unit | `sluis-ca@prod.service` |
  | Unix user | `sluis-ca-prod` |
  | socket | `/run/sluis/ca/prod.sock` |
  | Lambda function and IAM role | `sluis-ca-prod` |
  | Kubernetes container and ServiceAccount | `ca-prod` |
  | KMS alias | `alias/sluis/prod/ca/<purpose>` |
  | state prefix | `prod/ca/…` |
  | lease name, audit field | the same name; `actor=ca@prod` in audit |
  | SPIFFE ID | `spiffe://prod.<td>/sluis/ca`, in the boundary's own trust domain |

- **An integration instance is named `<vendor>[-<capability>]@<tenant>`.** For example `google-signin@<company>` and `google-directory@<company>` are two credentials and so two processes; `github@<org>`, `slack@<workspace>`, `cloudflare@<company>`, `aws-minter@<org>`; `oidc@<name>` for the generic OpenID Connect upstream.
- **The central actor is `entry`** (`sluis-entry`).

### The console

- **The console API is the `console` actor, the browser's backend.** The session is an HttpOnly cookie that `session` seals; there are no tokens in the browser.
- **Operator-set writes are done by the owning actor.** `console` checks the operator's delegation and routes the write to the actor that owns the record kind, which validates it with its own logic. The manifest declares which kinds accept operator-set writes, and the state backend refuses any writer but the owner ([0005](/decisions/0005-the-store/#one-writer-per-kind)). Every operator change is authorised for a named person and audited under that name.
- **The console's single-page application is a separate artifact,** served same-origin by each runtime's static host ([0013](/decisions/0013-release-train-packaging-and-distribution/#packaging-per-runtime)).

### One credential holder per unit

- **Each actor instance is its own OS user and systemd unit on bare metal,** its own function on serverless and its own container on Kubernetes.
- **A compromise of one actor gives the attacker that actor's credentials and nothing else.** An actor that uses an authority key does not parse unauthenticated internet input. `signer`, `ca` and `ssh-ca` each use a different authority key; `policy` uses the sealing key; `session` uses its cookie-sealing key; `entry` holds nothing.
- **Processes follow the owner of a credential, not the port:** a process per owner, never a process per port.

### The fusion rule

- **Actors are not the same as units.** An installation may run several actors in one unit, to fit a small machine, only if both hold:
  1. **The manifest of the unit is the union of the manifests of its actors.** Fusing never grants something no member actor was allowed.
  2. **No unit holds a key next to an unauthenticated listener.**
- **The rule is tested for every installation.** `signer` cannot be fused into `entry`, because the signing key would sit beside the internet-facing listener, and on serverless the same reasoning keeps `signer` a separate function. Small actors that hold no key and have no listener, such as `quota`, can share a unit on a small board.
- **On Kubernetes the unit is the container.** A generated check fails the build when a container that holds a key credential exposes a listener ([0011](/decisions/0011-runtimes-and-installations/#kubernetes)).

## Consequences

- A flaw in request parsing in `entry` reaches no key, no session record and no state, and `entry` cannot send anything out. To obtain a credential an attacker needs a grant that `policy` sealed and a minter that accepts it; to forge a token, `signer` and its signing policy must agree; a copied token is useful only until it expires, and fails its sender binding once the audience requires one.
- The cost is more processes. Each actor instance is its own user, unit, socket and manifest, each call between actors is a hop over a Unix socket, and a request crosses `entry` and then its owning actor. Small machines rely on the tested fusion rule to fit.
- One generated name per instance lets a unit, a role, a key alias and an audit record be matched without a lookup table; a rename is a manifest change.
- Splitting integrations by credential means a process per vendor tenant and capability. A company's sign-in, directory, GitHub organisation or Slack workspace then fails, rotates and leaves on its own.
- Every actor is an audit producer, because every success is audited: the split multiplies audit producers, not audit writers.
- Routing operator-set writes to the owning actor keeps `console` without write access to other actors' records; each owning actor needs validation and tests for the writes it accepts. A flaw in the single-page application reaches no token.

## Roads not taken

- **One process everywhere.** A flaw in any part holds every credential the others use; v1 ADR 0071 already replaced it for that reason.
- **A broad `entry` that runs the OIDC protocol, sessions, token exchange and the console API.** The actor that parses internet input would hold every session, enrolment and operator write, and a parsing flaw would reach them all without a key.
- **The signer inside `entry`, as in the v1 issuer, or split later.** The signing key would sit beside the internet-facing listener, and a split deferred is a split that becomes a rewrite.
- **One `ca` for X.509 and SSH.** Two authorities with different keys, formats and relying parties would share a process, so a flaw in one could sign for the other.
- **The decision point with state or network access.** An actor that can be made to read or exfiltrate anything is a target, and its grants could no longer be reviewed as a file.
- **A process per port.** A process that serves many owners holds many credentials, which defeats the split.
- **One integration process per vendor, serving every tenant.** One process would hold every company's credential for that vendor, and a company could not leave or rotate alone.
- **DPoP or mutual TLS from the first working version.** The parity relying parties cannot check a binding, so their tokens would be bearer anyway, and the binding code would have no consumer before the FAPI 2.0 profile.
- **Free fusion, with no rule.** A unit could quietly gain a key next to a listener, or a permission no member actor was allowed.

## Follow-ups

- Sender-constrained tokens with DPoP, after the parity milestone: [#912](https://github.com/truvity/sluis/issues/912).
