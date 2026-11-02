---
title: Threat model
description: "What sluis v2 protects, who attacks it from where, the control that stops each threat at which layer, what is left, and the test that proves it."
status: target
sidebar:
  order: 0
---

This page lists the threats that sluis v2 is designed against. Each threat names the asset, the attacker's position, the control that stops it, what is left after the control, and the requirements whose test vectors prove the control. The requirements are in the [isolation area](/requirements/iso/) of the catalogue, and each test vector names the threat it proves (`T-n`).

This is the threat model that [REQ-SEC-009](/requirements/sec/#REQ-SEC-009) requires: a threat is added here before its control is designed, and a control is accepted only with a test vector that fails at its own layer. The decisions it follows are the boundaries and the isolation ladder ([ADR 0005](/decisions/0005-boundaries-and-the-isolation-ladder/)), defence in depth per port ([ADR 0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/)), issuers, tokens and passkeys ([ADR 0006](/decisions/0006-identity-issuers-audiences-and-sign-in/)), workload identity ([ADR 0007](/decisions/0007-workload-identity-and-host-enrolment/)) and the certificate authorities ([ADR 0008](/decisions/0008-certificate-authorities-for-x509-ssh-and-databases/)).

## Scope and assets

The scope is one sluis operator's estate: a **front installation** (the shared sign-in, `entry`, `session`, `console` and `exchange`, and the group issuer at `sluis.example.com`) and one **boundary installation** per environment that runs on its own runtime (issuer at `sluis.<env>.example.com`), joined by declared trust.

A [boundary](/concepts/boundaries/) is the unit of isolation. An **environment** boundary owns the machine plane: its `policy`, `ca`, `ssh-ca`, `signer` and `quota` actors, its keys, its issuer, its trust domain and its audit log. A **company** boundary owns the identity plane: its directory, upstream identity providers, integrations, people records, operator delegation and audit tenant key, and **no authority key**. A **customer** boundary (one company in one environment, with its own keys and issuer) exists only when that company's customers sign in through sluis, and the customer organisations inside it are key-less tenants ([ADR 0047](/decisions/0047-a-customer-identity-installation-is-a-front-a-few-customer-boundaries-and-key-less-tenants/)).

How much a boundary has of its own is its **isolation level**: L0 tenant (code only), L1 keys, L2 process (its own actor instances, Unix user or cloud role, and state prefix), L3 store (its own state store, bucket and queue) and L4 runtime (its own cluster, cloud account or hosts, and install file). Environments run at L2 at least, and an environment on its own runtime is L4. Companies are L2 with sealed data, in the front installation.

The assets, in the order an attacker wants them:

| Asset | Where it lives |
|---|---|
| Authority keys: each environment's CA, SSH CA and token-signing keys, and the sealing key that seals its grants | The keys port: a YubiKey behind `key-holder`, or KMS. Never exported ([ADR 0012](/decisions/0012-cryptography-and-authority-keys/)). |
| Issued credentials: tokens, X.509 and SSH certificates, SVIDs | With the clients and workloads; short-lived and, where possible, sender-constrained. |
| Records: sessions, people, grants, hosts, enrolments, secrets of integrations | The state port, encrypted value by value. |
| Vendor credentials: OAuth client secrets, API tokens of each company's tenants | The secrets of one integration process each. |
| The audit trail | The blob port, written create-if-absent and witnessed. |
| Trust: the root list, the trust bundles hosts install, and the policies each boundary compiles | The root list is signed by a root; each certificate in a bundle chains to a root in it. |

## The three layers

Every port is protected by three independent layers, generated from one manifest ([ADR 0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#three-layers-per-port)):

1. **The port library in the actor.** The scope `<boundary>/<kind>/…` comes from the actor's own identity, never from the request. Every state value is encrypted with AES-256-GCM under a data key per boundary and record kind, wrapped under the boundary's sealing key, with the boundary, kind, key and version as additional authenticated data. Keys are chosen by purpose. Blobs are created only if absent.
2. **The driver's or backend's own check** of the caller's platform identity: the peer uid on a Unix socket, the IAM role or key policy, the Kubernetes ServiceAccount token, the client certificate. What it is for each driver is in [Per-driver checks](/decisions/0004-drivers-listeners-and-boundary-enforcement/#per-driver-checks).
3. **Physical separation** at L3 and L4: another store, bucket, queue, account or host.

Encryption stands on its own: with layers 2 and 3 off, a raw read returns ciphertext, and unwrapping the data key is a keys-port call that the key's own access list refuses.

A test vector runs one layer with the others switched off ([REQ-ISO-001](/requirements/iso/#REQ-ISO-001)), and a vector that is refused even with every layer off is void ([REQ-ISO-002](/requirements/iso/#REQ-ISO-002)). A driver whose backend cannot tell callers apart has no layer 2, so it is allowed only at L3 or above ([REQ-ISO-054](/requirements/iso/#REQ-ISO-054)).

## Attacker positions

| Position | Who | What they start with |
|---|---|---|
| **AP-1** Internet client | Anyone on the internet, including a holder of a copied token or cookie | The public endpoints |
| **AP-2** Compromised `entry` | Code execution in the front's parser and router | Every request in flight; no key, secret, state or outbound network |
| **AP-3** Compromised actor instance | Code execution in one actor, such as `ca@env-a`, `policy@env-b` or `session` | That actor's platform identity and its own keys, state and sockets |
| **AP-4** Compromised integration | Code execution in one integration, such as `google-signin@company-a` | That vendor tenant's credential |
| **AP-5** Compromised mediator | Code execution in the `key-holder` of one node | Every key on that node's card |
| **AP-6** Compromised store or its account | An admin of the state store, the bucket or the queue, or its cloud account | Every row, object and message in it |
| **AP-7** Operator mistake | A delegated operator on the console, or a wrong install file | That operator's delegation |
| **AP-8** Malicious neighbour | Another workload in a shared Kubernetes cluster, or another Unix user on a host | The same kernel, network and API server |
| **AP-9** Lying machine | A host or workload that enrols or renews with a false claim | An enrolment endpoint and whatever it can read on its machine |
| **AP-10** Company leaving | A company that leaves the operator's group, and the group it leaves | Its people, workloads and records at the time it leaves |
| **AP-11** Abusive client or tenant | A client, a tenant or an address that sends more than its share, or a tenant whose identity provider is slow or hostile | A valid connection or client, or only the public endpoints |

## Threats

### Tokens and sign-in

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-1** | A copied token or code is replayed | Access and refresh tokens, codes | AP-1, AP-2 | Codes are bound by PKCE. Tokens are bearer tokens with short lifetimes in the first working version; an audience that declares binding gets sender-constrained tokens (DPoP or mutual TLS) with the FAPI 2.0 profile ([ADR 0055](/decisions/0055-fapi-2-is-a-profile-a-client-declares/#binding-is-declared-per-audience)). | Until binding arrives, and for audiences that take only bearer tokens, such as a cloud's web-identity endpoint, a copied token works until it expires: the short lifetime is its only bound. Afterwards, a thief who also has the client's key. | [REQ-ISO-027](/requirements/iso/#REQ-ISO-027) |
| **T-2** | A token for one client is used at another | Access to relying parties | AP-1, a malicious relying party | `aud` is exactly one client ID registered at the issuer; a resource indicator is mapped to a client ID and never copied into `aud`. | A relying party that does not check `aud`. | [REQ-ISO-028](/requirements/iso/#REQ-ISO-028), [REQ-ISO-029](/requirements/iso/#REQ-ISO-029) |
| **T-3** | A token of one environment is accepted in another | Production relying parties | AP-1, AP-3 in a lower environment | An issuer, a key set and token-signing keys per environment; every printed relying-party snippet pins `iss` and `aud`. | A relying party configured by hand without the snippet. | [REQ-ISO-030](/requirements/iso/#REQ-ISO-030), [REQ-ISO-031](/requirements/iso/#REQ-ISO-031) |
| **T-4** | A compromised `entry` steals or alters what passes through it | Tokens, codes, enrolments in flight | AP-2 | `entry` holds no key, secret or state and has no outbound network; its parameter lists are closed and fuzzed. Codes are bound by PKCE, and tokens are sender-constrained where their audience declares binding (arrives with the FAPI 2.0 profile, [ADR 0055](/decisions/0055-fapi-2-is-a-profile-a-client-declares/#binding-is-declared-per-audience)); enrolments are HPKE-encrypted end to end. | It can refuse service and alter the pages it serves; the passkey origin check and PKCE limit what an altered page gains. | [REQ-ISO-042](/requirements/iso/#REQ-ISO-042), [REQ-ISO-043](/requirements/iso/#REQ-ISO-043), [REQ-ISO-047](/requirements/iso/#REQ-ISO-047), [REQ-ISO-027](/requirements/iso/#REQ-ISO-027) |
| **T-5** | A compromised front acts in a sensitive boundary on a person's behalf | Grants in production and management | AP-3 (`session`, `console`, `exchange` of the front) | The target boundary decides every request with its own policy; one that demands fresh MFA verifies a passkey assertion over its own challenge. | Boundaries that ask for no fresh passkey, within the person's grants, while the front is compromised. | [REQ-ISO-032](/requirements/iso/#REQ-ISO-032), [REQ-ISO-033](/requirements/iso/#REQ-ISO-033) |
| **T-6** | A passkey assertion is collected on another host | A person's passkey | AP-1 with a host under the same parent domain | The relying-party ID is the registrable parent, so one passkey serves every boundary; every verifier refuses an origin that is not one of the installation's sluis hosts. | A compromised sluis host on the allow-list. | [REQ-ISO-034](/requirements/iso/#REQ-ISO-034), [REQ-AUTHN-050](/requirements/authn/#REQ-AUTHN-050) |
| **T-7** | A stolen browser session is used | That person's grants | AP-1 with a copied cookie | Each boundary sets its own freshness; a stale session is challenged with an RFC 9470 step-up. | The boundaries with a loose freshness rule, within that rule. | [REQ-ISO-035](/requirements/iso/#REQ-ISO-035) |

### Keys and signing

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-8** | An actor uses another boundary's key, or a key of another purpose | Authority keys | AP-3, such as `ca@env-a` | Layer 1 picks keys by purpose from the actor's identity; layer 2 is `key-holder`'s access list or the KMS key policy; layer 3 is the boundary's own account or hosts at L4. | Within its boundary and purpose, a compromised `ca` signs what its constraints allow until the issuance log shows it. | [REQ-ISO-003](/requirements/iso/#REQ-ISO-003), [REQ-ISO-004](/requirements/iso/#REQ-ISO-004), [REQ-ISO-005](/requirements/iso/#REQ-ISO-005) |
| **T-9** | A key is made to sign another protocol's data or a wider certificate | Authority keys | AP-3 | Content-aware signing per purpose in `key-holder`: `ca` signs only a parseable TBSCertificate within its constraints, `ssh-ca` only an OpenSSH certificate body, token purposes only a JWS signing input, and the OpenPGP binding purpose builds its own digest. | A wrong constraint set, which is reviewed configuration. KMS has no content check; there the key policy limits each key to one role. | [REQ-ISO-006](/requirements/iso/#REQ-ISO-006), [REQ-ISO-007](/requirements/iso/#REQ-ISO-007), [REQ-ISO-008](/requirements/iso/#REQ-ISO-008) |
| **T-10** | The mediator is compromised | Every key on one node's card | AP-5 | `key-holder` is the only mediator: a memory-safe language, no network, seccomp, the PIN in locked memory, a rate limit and an audit record per signature. Backends that tell callers apart need no mediator. | It can sign with every key on that card, within the rate limit, until the audit log shows it. A card belongs to one boundary, so it stays inside that boundary. | [REQ-ISO-011](/requirements/iso/#REQ-ISO-011), [REQ-ISO-012](/requirements/iso/#REQ-ISO-012) |

### State, blobs and transport

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-11** | An actor reads or writes another actor's or boundary's records | Records | AP-3, AP-4 | Layer 1 scope and encryption; layer 2 per driver (an rqlite cluster per owning actor with query-only readers, DynamoDB `LeadingKeys`, a file per user); layer 3 an own store at L3. Only the writer and declared readers may unwrap a kind's data key. | Its own records, and the records it is a declared reader of. | [REQ-ISO-003](/requirements/iso/#REQ-ISO-003), [REQ-ISO-013](/requirements/iso/#REQ-ISO-013) to [REQ-ISO-016](/requirements/iso/#REQ-ISO-016), [REQ-ISO-019](/requirements/iso/#REQ-ISO-019) |
| **T-12** | An actor writes into another's blob prefix or rewrites a written blob | The audit trail, exports, backups | AP-3 | Layer 1 scope and create-if-absent; layer 2 IAM prefix conditions or prefix-scoped temporary credentials; layer 3 a bucket per boundary, with Object Lock where the store has it. | Blobs not yet written can be raced for; the witnesses of the audit log detect a fork. | [REQ-ISO-021](/requirements/iso/#REQ-ISO-021) to [REQ-ISO-023](/requirements/iso/#REQ-ISO-023) |
| **T-13** | An actor sends messages as another actor | Audit events, work items | AP-3 | Layer 2 judges the sender at the receiver or the broker: peer uid, queue policy per sender role, or a NATS user per actor instance limited to its own subjects; layer 3 a queue per boundary. | A sender may flood its own queue; quotas and limits bound it. | [REQ-ISO-024](/requirements/iso/#REQ-ISO-024) to [REQ-ISO-026](/requirements/iso/#REQ-ISO-026) |
| **T-14** | The store or its account is compromised | Records | AP-6 | Every value is encrypted in the port library, and the AAD binds it to its boundary, kind, key and version, so a moved value does not decrypt; record keys hold no personal data. | Metadata (key names, sizes, times, access patterns), deletion and denial of service. A rollback of the whole store shows only against the audit log and its witnesses. | [REQ-ISO-017](/requirements/iso/#REQ-ISO-017), [REQ-ISO-018](/requirements/iso/#REQ-ISO-018), [REQ-ISO-020](/requirements/iso/#REQ-ISO-020) |

### Integrations, policy and companies

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-15** | A compromised integration reaches other tenants or signs for sluis | Vendor credentials, authority | AP-4 | One process per vendor tenant, with its own identity, secret and state prefix; no authority key; egress only through the proxy. A customer organisation's own provider runs in a pool of its customer boundary, with its secret sealed per connection ([ADR 0048](/decisions/0048-customer-connections-run-in-a-pool-per-customer-boundary/)). | That tenant's credential, and whatever it allows at the vendor. For a pool: the client secrets of one customer boundary's pooled connections, which let an attacker pose as sluis at those providers and read or mint nothing. | [REQ-ISO-051](/requirements/iso/#REQ-ISO-051), [REQ-ISO-052](/requirements/iso/#REQ-ISO-052) |
| **T-16** | A subject of one company gets a grant in another company's scope | Company boundaries | AP-1 with a valid sign-in, AP-7 | Company-ceiling guards compiled as Cedar `forbid`, which no `permit` overrides; a partner grant is the only exception. | A bug in a shared policy definition (accepted, below). | [REQ-ISO-036](/requirements/iso/#REQ-ISO-036) |
| **T-17** | One environment's policy leaks into another's bundle | Environment boundaries | AP-7 | Policy has one source and is compiled per environment; the build fails on a policy scoped to another environment. | As T-16. | [REQ-ISO-037](/requirements/iso/#REQ-ISO-037) |
| **T-18** | A grant decided in one environment is spent in another | Environment boundaries | AP-3 | A sealing key per environment; a signing actor refuses a grant that its own environment's sealing key does not open. | None beyond T-8. | [REQ-ISO-066](/requirements/iso/#REQ-ISO-066) |
| **T-19** | A person link is used to inherit grants across companies | Company boundaries | AP-1 with one linked account | A subject per directory account and a declared person link with no grant inheritance across it; SSH certificates carry the person key, not the grants. | None beyond T-16. | [REQ-ISO-058](/requirements/iso/#REQ-ISO-058) |

### Machine identity, enrolment and trust

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-20** | A workload or host gets a credential for another identity | Machine identities | AP-9 | Issuance bound to the requester: the subject of a certificate, SVID or workload token comes from the requester's authenticated identity, never from the request. | A wrong declared rule that gives one identity too wide a name. | [REQ-ISO-039](/requirements/iso/#REQ-ISO-039) |
| **T-21** | A caller from one boundary passes for an actor of another | Cross-boundary calls | AP-3 in another boundary | Mutual TLS with SPIFFE IDs, the trust domain being the boundary; a JWT-SVID across boundaries has the target's SPIFFE ID as its only `aud`; the target re-decides with its own policy. | What the target's own policy allows that trust domain. | [REQ-ISO-040](/requirements/iso/#REQ-ISO-040), [REQ-ISO-041](/requirements/iso/#REQ-ISO-041), [REQ-ISO-032](/requirements/iso/#REQ-ISO-032) |
| **T-22** | An enrolment proof is stolen, replayed or altered | Host and workload enrolment | AP-2, AP-9 | The enrolment token never travels: the client sends its ID and an HMAC over the CSR and a server nonce; tokens are single-use or counted and expire; an instance identity document is accepted once per instance; the request is HPKE-encrypted. | A token read on the target machine before its first use, limited by bound groups and a short expiry. | [REQ-ISO-044](/requirements/iso/#REQ-ISO-044) to [REQ-ISO-047](/requirements/iso/#REQ-ISO-047) |
| **T-23** | A host is made to trust the wrong roots | Trust bundles | AP-1 on the path, AP-6 for the bucket that serves bundles | The root list is signed by a root the host already holds and carries a trust sequence that only increases, so an older list is refused; each certificate in a bundle must chain to a root in that list, and a bundle with a lower `spiffe_sequence` is refused; the roots' public keys (SPKI hashes) are pinned at enrolment, except where a person compares the pin; web PKI is used for reachability only. | One root card with its PIN, until that root is revoked and the update reaches the hosts (accepted, below). | [REQ-ISO-048](/requirements/iso/#REQ-ISO-048) to [REQ-ISO-050](/requirements/iso/#REQ-ISO-050) |

### Operators, shared platforms and leaving

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-24** | A neighbour on a shared host or cluster uses an actor's socket or cloud role | Keys, records, cloud roles | AP-8 | `key-holder` sockets in directories only their caller can open, plus a peer-uid check; a container mounts only the sockets its call graph allows; per-uid node tokens and trust policies that pin the actor at its boundary. | Cluster admins and node root (accepted, below). | [REQ-ISO-009](/requirements/iso/#REQ-ISO-009), [REQ-ISO-010](/requirements/iso/#REQ-ISO-010), [REQ-ISO-056](/requirements/iso/#REQ-ISO-056), [REQ-ISO-057](/requirements/iso/#REQ-ISO-057) |
| **T-25** | An operator's mistake opens a boundary | Configuration, delegation | AP-7 | Console delegation per company and environment, every change audited under the operator's name; one generator for scopes, access lists, IAM and KMS policies, units, sockets and ServiceAccounts, with a drift test; `sluis config check` refuses an inconsistent installation. | A mistake inside one's own delegation; the deploying operator (accepted, below). | [REQ-ISO-053](/requirements/iso/#REQ-ISO-053) to [REQ-ISO-055](/requirements/iso/#REQ-ISO-055) |
| **T-26** | A company that leaves keeps access, or leaves its records readable | Company records, workloads | AP-10 | The promotion runbook: disconnect its company boundary, export and crypto-shred its audit tenant key, re-issue its workloads under the new CA, remove its person links. Hosts pin their own boundary's CA. | Copies taken before it left, and data outside sluis. | [REQ-ISO-059](/requirements/iso/#REQ-ISO-059), [REQ-ISO-060](/requirements/iso/#REQ-ISO-060) |

### Availability and abuse

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-27** | A sign-in or token flood saturates sluis | Availability of sign-in | AP-1, AP-11 | Volumetric traffic is absorbed at the edge; a token bucket in `state` per connection, per client and per source; a refusal is a 429 ([ADR 0053](/decisions/0053-volumetric-abuse-is-stopped-at-the-edge-and-sluis-bounds-what-one-source-can-cost/)). | Saturation of the link or the edge; a distributed flood below every per-source limit. | [REQ-SEC-020](/requirements/sec/#REQ-SEC-020), [REQ-SEC-021](/requirements/sec/#REQ-SEC-021), [REQ-SEC-024](/requirements/sec/#REQ-SEC-024), [REQ-SEC-025](/requirements/sec/#REQ-SEC-025) |
| **T-28** | Unauthenticated requests fill the state with unfinished sign-ins | The state store | AP-1 | A pending sign-in expires within 10 minutes and is capped per connection and per source address. | Sign-ins to one connection can be crowded out until the records expire. | [REQ-SEC-022](/requirements/sec/#REQ-SEC-022), [REQ-SEC-023](/requirements/sec/#REQ-SEC-023), [REQ-FED-034](/requirements/fed/#REQ-FED-034) |
| **T-29** | A slow or failing tenant provider starves the other tenants | Workers of a connector pool | AP-11, AP-4 | A concurrency limit, a timeout and a circuit breaker per connection; a pool per customer boundary. | That tenant's own sign-ins fail; tenants of one pool share the nodes it runs on. | [REQ-SEC-026](/requirements/sec/#REQ-SEC-026), [REQ-ISO-079](/requirements/iso/#REQ-ISO-079) |
| **T-30** | sluis is used to send requests to a provider or an internal address | Providers and the internal network | AP-1, AP-11 | The egress proxy refuses private addresses and hosts that no connection names; a limit on sign-in starts and on discovery refetches per connection. | A provider receives up to the connection's allowed rate. | [REQ-ISO-081](/requirements/iso/#REQ-ISO-081), [REQ-FED-008](/requirements/fed/#REQ-FED-008), [REQ-SEC-020](/requirements/sec/#REQ-SEC-020) |
| **T-31** | A dependency outage stops sign-in | Availability of sign-in | AP-6, an outage of the key service, the store or an upstream | Fail closed with the documented error and no weaker path; tokens already issued stay valid until they expire; the key set is a static document that outlives the compute ([ADR 0056](/decisions/0056-a-regional-outage-is-accepted-public-keys-outlive-it-and-a-drill-measures-recovery/#a-regional-outage)). | A regional outage of the key service stops new sign-ins and signing until the region returns (accepted). | [REQ-OPS-006](/requirements/ops/#REQ-OPS-006), [REQ-OPS-013](/requirements/ops/#REQ-OPS-013), [REQ-OPS-014](/requirements/ops/#REQ-OPS-014) |
| **T-32** | Sign-ins and refreshes use up the key service's request quota | Token signing | AP-1, AP-11 | The limits above bound the signing rate per client and connection; the quota and the first bottleneck are measured ([ADR 0054](/decisions/0054-capacity-is-measured-before-it-is-promised/)). | The default quota is 1000 signatures a second per account and Region (measured 2026-11-02); the margin over the customers' load is unknown until the rest of the spike is recorded. | [REQ-PERF-003](/requirements/perf/#REQ-PERF-003), [REQ-SEC-021](/requirements/sec/#REQ-SEC-021) |

## Accepted risks

These are shared by design and are not mitigated by isolation. They are revisited when a boundary is promoted to its own operator.

- **The roots.** The roots are held by [ritueel](https://ritueel.id) and certify every boundary's intermediates. Any single root may change the root list, so whoever holds one root card and its PIN can sign what hosts trust until that root is revoked and the update reaches them; standard tools cannot require two roots to agree. A stolen card without its PIN locks after three wrong tries (T-23). The break-glass SSH CA is ritueel's too ([SSH](/integrations/ssh/)).
- **The operator who deploys sluis.** Whoever writes the install files and runs the deployment can change any boundary they deploy.
- **Cluster admins.** An admin of a shared Kubernetes cluster can mint service-account tokens and read mounted secrets of any pod on it.
- **Production `ca` reaching every company in production.** One environment's `ca` signs for every company in that environment; company boundaries hold no authority key.
- **Bugs in shared policy definitions.** Policy has one source, so a wrong definition is wrong in every environment it compiles into, until a test finds it.
- **Data outside sluis.** Secrets stores, observability and deployment tools of the operator's estate are outside this model.

## Related

- The [isolation requirements](/requirements/iso/) and their test vectors, and the [coverage](/requirements/coverage/) of the catalogue.
- [Break-glass recovery](/security/break-glass/), the operator's way back in when no upstream can vouch.
- The [standards register](/standards/), for SPIFFE, HPKE, RFC 9470 and WebAuthn.
- [Ports and drivers](/concepts/drivers/) and [Keys](/concepts/keys/), for the ports and the key layouts.
