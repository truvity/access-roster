---
title: Threat model
description: "What sluis v2 protects, who attacks it from where, the check that stops each threat, what is left, the test that proves it, and the risks accepted."
status: target
sidebar:
  order: 0
---

This page lists the threats that sluis v2 is designed against. Each threat names the asset, the attacker's position, the control that stops it, what is left after the control, and the requirements whose test vectors prove the control. Each test vector names the threat it proves (`T-n`). The page describes; the records decide, and each control links the record that holds it.

This is the threat model that [REQ-SEC-009](/requirements/sec/#REQ-SEC-009) requires: a threat is added here before its control is designed, and a control is accepted only with a test vector that fails on its own. A threat whose Test cell says "planned" has its control decided and its requirement not yet written.

## Scope and assets

The scope is one operator's installation: its [boundaries](/concepts/boundaries/), each with the foundation (store@, exporter@ and key@) and the modules it runs (identity, audit and quota), and the front that gives people one sign-in URL ([0002](/decisions/0002-families-of-actors/#the-foundation-and-the-modules), [0008](/decisions/0008-boundaries-and-tenants/#boundaries)).

A boundary is the unit of keys and policy, and its level on the [ladder](/decisions/0008-boundaries-and-tenants/#the-ladder) says what it has of its own: L0 a tenant (the store's rules and its own data keys), L1 its own keys, L2 its own processes, L3 its own engine, L4 its own runtime. A tenant lives inside a boundary, with three data keys of its own and no authority key ([0008](/decisions/0008-boundaries-and-tenants/#tenants)).

The assets, in the order an attacker wants them:

| Asset | Where it lives |
|---|---|
| Authority keys: token signing, the X.509 intermediates, the SSH CAs, the audit log keys | Behind key@, never exported: a card per board on boards, KMS on AWS. The roots are ritueel's, and sluis holds intermediates only ([0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place), [0024](/decisions/0024-root-custody-and-the-signing-api/#sluis-holds-no-root)) |
| Data keys | Wrapped only, as `DataKeyWrap` items, for each board's card and the offline recovery recipient, or by KMS; opened only in key@'s memory ([0006](/decisions/0006-keys-and-sealing/#data-keys)) |
| Sealed values: personal data, provider tokens, connection credentials | Ciphertext in the durable and temp kinds, bound to their full address; the plaintext exists only in the actor that uses it ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)) |
| Hashed values: session ids, refresh tokens, codes, client secrets | Compare-only hashes in the store ([0004](/decisions/0004-the-data-model/#treatment)) |
| Secret-source values: provider app secrets that IaC writes | A systemd credential or SSM, read by store@ and held in its memory ([0005](/decisions/0005-the-store/#secret-sources)) |
| Signed config, and the publisher keys that sign it | Signed config documents in the config source; the publisher pins in the bootstrap file ([0005](/decisions/0005-the-store/#configuration-loading)) |
| Sealed grants | In flight only, for about 60 seconds, never stored ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)) |
| Export destination credentials | exporter@ alone ([0009](/decisions/0009-export/#destinations)) |
| The card PIN of a board | key@'s locked memory; between boards only sealed to a one-time key ([0006](/decisions/0006-keys-and-sealing/#touch-and-pin)) |
| Break-glass credentials | Public keys in config, the kind `BreakGlassPasskey` ([0017](/decisions/0017-identity-and-sign-in/#break-glass-recovery)) |
| Issued credentials: tokens, X.509 and SSH certificates, SVIDs | With the clients and workloads; short-lived and, where the audience declares it, sender-constrained |
| The audit trail | One audit per boundary, a bucket per project, written create-if-absent and witnessed ([0029](/decisions/0029-the-audit-log/#projects)) |
| Trust: the root list, the trust bundles hosts install | Signed by a root; each certificate in a bundle chains to a root in the list ([0024](/decisions/0024-root-custody-and-the-signing-api/#root-pins-and-the-root-list)) |

## Few credential holders

Every actor belongs to one of four families, and only a few units hold a credential at rest ([0002](/decisions/0002-families-of-actors/#credential-holders), [principle 16](/principles/#16-few-credential-holders)). A work actor holds none: it reaches data, keys and audit only through its ports, so a flaw in it yields what it is using at that moment and nothing it can replay later ([0002](/decisions/0002-families-of-actors/#work-actors)).

| Holder | Family | What it holds | What its compromise yields |
|---|---|---|---|
| store@ | data | The credentials of its four storage ports | Ciphertext, hashes, plain values and the values of secret sources, and the power to change or delete items. No plaintext of a sealed value, because the store never seals or opens |
| exporter@ | data | The credentials of its export destinations | The exportable kinds it may open with its grant, written to the destinations it holds |
| key@ | keys | The card PIN on boards, the KMS permission on AWS | The data keys it opens, and signatures with its keys while it runs. Not the data, which is in store@, and not the authority keys, which stay in the card or KMS |
| writer, witness, indexer, reader | audit | A writer, the write credential of its project's bucket; the witness, its cosignatures; the indexer and the reader, the credential of the boundary's one search index | A writer, its own project's log; the indexer or the reader, the index of every project of the boundary, whose records still open only under a grant at key@; every signature still goes through key@ |

- **A holder never shares a unit with a work actor,** and key@ never shares one with `entry` ([0003](/decisions/0003-units-transports-and-fusion/#fusion)).
- **On Lambda only the holders' roles reach storage, keys, export destinations or the audit blob.** A work function's role may invoke and emit, and nothing else ([0002](/decisions/0002-families-of-actors/#credential-holders)).

## The checks

### Two independent checks

Two checks stand between any actor and a tenant's sealed value, and each holds alone ([0007](/decisions/0007-policy-and-sealed-grants/#two-independent-checks), [principle 18](/principles/#18-plaintext-lives-only-where-it-is-used-behind-two-independent-checks)):

1. **The store's rule.** store@ checks the caller, the kind and the verb against the rules of the [kind registry](/reference/rules/) on every call, and on every tenant-scoped write it has key@ open the grant and refuses unless the grant names the address's tenant and the verb ([0005](/decisions/0005-the-store/#rules)). The caller is known by the transport, never by a field of the request.
2. **key@'s grant check on every Seal and Open.** key@ checks the caller's identity, the caller's rule for the purpose and the operation, and a grant sealed for the address's tenant ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)).

The two run in different holders with different credentials and take their inputs from different registries. A value is sealed with the full address as authenticated data, so a value moved to another row, kind, tenant or boundary does not open.

### Sealing only in actors

**The store never seals or opens.** An actor asks key@ to `Seal(address, value, grant)` and writes the result; to read, it asks key@ to `Open` what the store returned ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)). Only `policy` may have key@ seal a grant, and only the store, `ca`, `signer`, key@ and the minters open one ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)).

### The call graph, enforced twice

Which actor may call which is declared once in the [actor registry](/reference/actors/) and enforced in two places ([0003](/decisions/0003-units-transports-and-fusion/#the-call-graph)):

- **In code.** A generated client exists only for an allowed callee, and one interceptor in every process refuses a caller that is not listed.
- **By the transport** ([0003](/decisions/0003-units-transports-and-fusion/#transports)):

  | Installation | The second lock |
  |---|---|
  | Boards and local | The callee's socket group holds only the uids of its allowed callers, and each caller's systemd sandbox makes only its allowed sockets visible ([Bare metal](/runtimes/bare-metal/#sockets-and-the-call-graph)) |
  | Lambda | The callee function's resource policy grants invoke to the roles of its allowed callers only ([Serverless](/runtimes/serverless/#the-call-graph)) |
  | Kubernetes | A NetworkPolicy per callee, and a projected service-account token with one audience per callee that the interceptor checks. Mutual TLS between callers is later work ([Kubernetes](/runtimes/kubernetes/#the-call-graph)) |

The deny matrix tests every pair of actors against both layers ([Rules](/reference/rules/#deny-matrix)).

### The ladder

The ladder adds separation beyond the two checks: its own key@ from L1, its own store@ and units from L2, its own engine from L3, its own runtime from L4 ([0008](/decisions/0008-boundaries-and-tenants/#the-ladder)).

## Attacker positions

| Position | Who | What they start with |
|---|---|---|
| **AP-1** Internet client | Anyone on the internet, including a holder of a copied token or cookie | The public endpoints |
| **AP-2** Compromised `entry` | Code execution in the one parser reachable from outside | Every request in flight; no key, secret, state or outbound network |
| **AP-3** Compromised work actor | Code execution in one work actor, such as `ca@prod`, `policy@dev` or `session` | Its platform identity, its rules, and the grants it carries, for about 60 seconds each |
| **AP-4** Compromised adapter | Code execution in one adapter, such as `adapter-github@prod` | Its rules, and each tenant connection credential it opens at key@ for one call |
| **AP-5** Compromised key@ | Code execution in key@ of one boundary or one board | The card PIN or the KMS permission, and the data keys in its cache |
| **AP-6** Compromised engine or its account | An administrator of the engine, the bucket or the queue, or of its cloud account | Every item, object and message in it |
| **AP-7** Operator mistake | A delegated operator on the console, or a wrong bootstrap file or config document | That operator's delegation, or a reviewed commit |
| **AP-8** Malicious neighbour | Another workload in a shared Kubernetes cluster, or another Unix user on a host | The same kernel, network and API server |
| **AP-9** Lying machine | A host or workload that enrols or renews with a false claim | An enrolment endpoint and whatever it can read on its machine |
| **AP-10** Tenant leaving | A tenant that leaves a boundary, and the operator it leaves | Its people, workloads and data at the time it leaves |
| **AP-11** Abusive client or tenant | A client, a tenant or an address that sends more than its share, or a tenant whose identity provider is slow or hostile | A valid connection or client, or only the public endpoints |
| **AP-12** Compromised store@ | Code execution in store@ of one boundary | The four storage credentials, and the secret-source values in its memory |
| **AP-13** Compromised exporter@ | Code execution in exporter@ of one boundary | The export destination credentials, a Kubernetes cluster credential on the direct path among them |
| **AP-14** Compromised product service | The service identity of a product that pushes allowances or emits audit records | Its X.509-SVID and what its policy allows it |
| **AP-15** Stolen break-glass credential | A thief of a registered hardware key and its PIN, or of the synced passkey's vault | One recovery credential |

## Threats

### Tokens and sign-in

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-1** | A copied token or code is replayed | Access and refresh tokens, codes | AP-1, AP-2 | Codes are bound by PKCE. A token is sender-constrained (DPoP or mutual TLS) where its audience declares a binding; an audience that declares none gets a bearer token with a short lifetime ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#binding), [0038](/decisions/0038-fapi-2-profile/#binding-is-declared-per-audience)). | For a bearer audience, such as a cloud's web-identity endpoint, a copied token works until it expires: the short lifetime is its only bound. For a bound audience, a thief who also has the client's key. | [REQ-ISO-027](/requirements/iso/#REQ-ISO-027) |
| **T-2** | A token for one client is used at another | Access to relying parties | AP-1, a malicious relying party | `aud` is exactly one client ID registered at the issuer; a resource indicator is mapped to a client ID and never copied into `aud` ([0017](/decisions/0017-identity-and-sign-in/#audiences)). | A relying party that does not check `aud`. | [REQ-ISO-028](/requirements/iso/#REQ-ISO-028), [REQ-ISO-029](/requirements/iso/#REQ-ISO-029) |
| **T-3** | A token of one boundary is accepted in another | Production relying parties | AP-1, AP-3 in a lower boundary | An issuer, a key set and token-signing keys per environment boundary; every printed relying-party snippet pins `iss` and `aud` ([0017](/decisions/0017-identity-and-sign-in/#issuers)). | A relying party configured by hand without the snippet. | [REQ-ISO-030](/requirements/iso/#REQ-ISO-030), [REQ-ISO-031](/requirements/iso/#REQ-ISO-031) |
| **T-4** | A compromised `entry` steals or alters what passes through it | Tokens, codes, enrolments in flight | AP-2 | `entry` holds no key, secret or state, has no outbound network, and is reached only through the key-less edge connector: on a Unix socket on boards and Kubernetes, on the loopback address inside its function on Lambda; its parameter lists are closed and fuzzed ([0003](/decisions/0003-units-transports-and-fusion/#listeners)). Codes are bound by PKCE, and enrolments are HPKE-encrypted end to end. | It can refuse service and alter the pages it serves; the passkey origin check and PKCE limit what an altered page gains. | [REQ-ISO-042](/requirements/iso/#REQ-ISO-042), [REQ-ISO-043](/requirements/iso/#REQ-ISO-043), [REQ-ISO-047](/requirements/iso/#REQ-ISO-047), [REQ-ISO-027](/requirements/iso/#REQ-ISO-027) |
| **T-5** | A compromised front acts in a sensitive boundary on a person's behalf | Grants in production | AP-3 (`session`, `console` or `exchange` of the front) | The target boundary decides every request with its own policy; one that demands fresh multi-factor authentication verifies a passkey assertion over its own challenge ([0017](/decisions/0017-identity-and-sign-in/#step-up)). | Boundaries that ask for no fresh passkey, within the person's grants, while the front is compromised. | [REQ-ISO-032](/requirements/iso/#REQ-ISO-032), [REQ-ISO-033](/requirements/iso/#REQ-ISO-033) |
| **T-6** | A passkey assertion is collected on another host | A person's passkey | AP-1 with a host under the same parent domain | One relying-party ID, the shared sign-in domain; every verifier refuses a web origin that is not on its allow-list of the installation's sluis hosts ([0017](/decisions/0017-identity-and-sign-in/#passkeys)). | A compromised sluis host on the allow-list. | [REQ-ISO-034](/requirements/iso/#REQ-ISO-034), [REQ-AUTHN-050](/requirements/authn/#REQ-AUTHN-050) |
| **T-7** | A stolen browser session is used | That person's grants | AP-1 with a copied cookie | The cookie is sealed and opened at key@ on every request; each boundary sets its own freshness, and a stale session is challenged with an RFC 9470 step-up ([0018](/decisions/0018-sessions/#session-chains)). | The boundaries with a loose freshness rule, within that rule. | [REQ-ISO-035](/requirements/iso/#REQ-ISO-035) |

### Keys and signing

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-8** | An actor uses another boundary's key, or a key of another purpose | Authority keys | AP-3, such as `ca@dev` | key@ serves one boundary, and its rules say which actor may use which purpose and operation; on AWS the key policy names key@'s role alone; at L4 the boundary has its own account or hosts ([0006](/decisions/0006-keys-and-sealing/#keys-per-boundary-on-aws)). | Within its boundary and purpose, a compromised `ca` signs what its constraints allow until the issuance log shows it. | [REQ-KEYS-029](/requirements/keys/#REQ-KEYS-029), [REQ-KEYS-030](/requirements/keys/#REQ-KEYS-030), [REQ-ISO-005](/requirements/iso/#REQ-ISO-005) |
| **T-9** | A key is made to sign another protocol's data or a wider certificate | Authority keys | AP-3 | key@ signs content, not digests, and per purpose: a parseable TBSCertificate within its constraints, an OpenSSH certificate body, a JWS signing input, an OpenPGP signature input ([0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place)). | A wrong constraint set, which is reviewed config. | [REQ-ISO-006](/requirements/iso/#REQ-ISO-006), [REQ-ISO-007](/requirements/iso/#REQ-ISO-007), [REQ-ISO-008](/requirements/iso/#REQ-ISO-008) |
| **T-10** | key@ is compromised | Every key of its boundary or board, the cached data keys | AP-5 | key@ is a holder that rate-limits and audits every signature; on a board it has no network, runs under seccomp, keeps the PIN in locked memory and has the card to itself, and on AWS the key policy names its role alone ([0006](/decisions/0006-keys-and-sealing/#keys-per-boundary-on-aws)) ([0006](/decisions/0006-keys-and-sealing/#exclusive-card-access)). The data is in store@, not in key@. | It can sign and open within its boundary, within the rate limit, until the audit log shows it; the keys stay in the card or KMS. | [REQ-ISO-011](/requirements/iso/#REQ-ISO-011), [REQ-ISO-061](/requirements/iso/#REQ-ISO-061) |

### Data, blobs and transport

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-11** | An actor reads or writes another actor's, tenant's or boundary's data | Sealed values, hashed and plain items | AP-3, AP-4 | The store's rule per actor, kind and verb, and a grant sealed for the tenant on every tenant-scoped write; key@'s grant check on every Seal and Open; one writer per kind ([0007](/decisions/0007-policy-and-sealed-grants/#two-independent-checks), [0004](/decisions/0004-the-data-model/#one-writer-per-kind)). | What its rules allow, for the tenants of the grants it carries. | [REQ-DATA-013](/requirements/data/#REQ-DATA-013), [REQ-DATA-073](/requirements/data/#REQ-DATA-073) |
| **T-12** | An actor writes into another's blob prefix or rewrites a written blob | The audit trail, exports, backups | AP-3 | Only holders hold blob credentials, each scoped to its project's bucket and prefix; every object is created only if absent, and no credential carries a delete right on a project's bucket ([0029](/decisions/0029-the-audit-log/#the-write-once-fence)). | Blobs not yet written can be raced for; the witnesses of the audit log detect a fork. | [REQ-ISO-022](/requirements/iso/#REQ-ISO-022), [REQ-ISO-023](/requirements/iso/#REQ-ISO-023) |
| **T-13** | An actor sends audit records as another actor | Audit records | AP-3, AP-14 | The audit transport authenticates every emitter by its platform identity: a peer uid, an IAM role, NATS credentials or a service-account token ([0028](/decisions/0028-audit-pieces/#transport)). | A sender may flood its own stream; limits bound it. | [REQ-ISO-024](/requirements/iso/#REQ-ISO-024), [REQ-ISO-026](/requirements/iso/#REQ-ISO-026) |
| **T-14** | The engine or its account is compromised | Durable and temp items | AP-6 | A sealed value is ciphertext bound to its full address, a compare-only value is a hash, and an id never holds personal data ([0004](/decisions/0004-the-data-model/#the-address)); the data keys are wrapped for cards, the recovery recipient or KMS ([0006](/decisions/0006-keys-and-sealing/#datakeywrap)). | Plain values, metadata (ids, sizes, times, access patterns), deletion and denial of service. A rollback of the whole engine shows only against the audit log and its witnesses. | [REQ-DATA-012](/requirements/data/#REQ-DATA-012) |
| **T-33** | A compromised store@ reads or changes what it serves | Secret-source values, every item | AP-12 | store@ never seals or opens, so it holds nothing that opens a sealed value ([0005](/decisions/0005-the-store/#secret-sources)); it parses no unauthenticated input and is never fused with a work actor ([0003](/decisions/0003-units-transports-and-fusion/#fusion)); every refusal is an audit fact, and the backup restores what it changes ([0010](/decisions/0010-backup-and-recovery/#restore)). | The values of the secret sources, which pass through store@ in memory (accepted, below); plain values; changes and deletions until the audit log shows them. | Planned |
| **T-34** | A config document is forged, rolled back or swapped | Signed config | AP-6 on the config source, AP-7 | store@ verifies every signature against the publisher keys pinned in the bootstrap file before it parses, takes only a growing sequence while it runs, and validates the whole set before it swaps the snapshot; a regulated party's policy needs its own signature as well ([0005](/decisions/0005-the-store/#configuration-loading), [0007](/decisions/0007-policy-and-sealed-grants/#a-regulated-partys-policy)). | At a cold start store@ takes the latest validly signed document whatever its sequence, so a source can serve an older one ([0005](/decisions/0005-the-store/#freshness-at-a-cold-start)); the audit fact of every start names each document's sequence and hash. A stolen publisher key signs until the bootstrap file drops it. | [REQ-DATA-076](/requirements/data/#REQ-DATA-076), [REQ-DATA-077](/requirements/data/#REQ-DATA-077), [REQ-DATA-080](/requirements/data/#REQ-DATA-080), [REQ-DATA-085](/requirements/data/#REQ-DATA-085) |

### Keys at rest and in memory

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-35** | A deleted tenant's data is opened from key@'s cache | Sealed values of an erased tenant | AP-3, AP-5 after an erasure | Each cached data key has its own time to live, set in `KeyPlan` under a built-in maximum; on boards key@ watches `DataKeyWrap` and drops an entry when its wrap is deleted ([0006](/decisions/0006-keys-and-sealing/#the-cache)). | On Lambda nothing is pushed: a warm key@ keeps the entry until it expires, so the time to live is the erasure delay (accepted, below). | Planned |
| **T-36** | The card PIN is taken while a board unlocks | A board's card | AP-6, a listener between boards | A peer's key@ releases the PIN through the store, sealed to a one-time P-384 key that the locked key@ made for the request. The request is signed by the locked key@ with a card slot whose PIN policy is never, attested in the slot map, and the peer verifies the signature and the attestation before it seals, so a request written by a compromised store@ gets no PIN; both items are temp kinds of key@ (5 minutes by default, 15 at most); the PIN crosses only the Raft port, is never on disk, and is never retried ([0006](/decisions/0006-keys-and-sealing/#touch-and-pin)). | The PIN opens the card only for a process that reaches it, and only key@'s driver user does ([0006](/decisions/0006-keys-and-sealing/#exclusive-card-access)). | Planned |

### Integrations, policy and tenants

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-15** | A compromised adapter reaches other tenants or signs for sluis | Connection credentials, authority | AP-4 | An adapter holds no credential at rest and no authority key; it opens a tenant's connection credential at key@ for one call under a grant for that tenant, and keeps nothing. A pass that no caller started gets a grant from `policy` for that pass and one tenant at a time ([0025](/decisions/0025-integrations/#adapters-and-connections)). A pooled adapter serves one customer boundary ([0033](/decisions/0033-customer-connections/#a-pool-per-customer-boundary)). | The credentials it opens while compromised, for the tenants `policy` grants it passes for, and what they allow at the vendor; the installation-wide app secret it reads from the secret source, such as `UpstreamSecret` or `SlackAppSecret` ([0025](/decisions/0025-integrations/#adapters-and-connections)). | [REQ-ISO-052](/requirements/iso/#REQ-ISO-052), [REQ-ISO-079](/requirements/iso/#REQ-ISO-079), [REQ-ISO-080](/requirements/iso/#REQ-ISO-080) |
| **T-16** | A subject of one tenant gets a grant in another tenant's scope | Tenants of a boundary | AP-1 with a valid sign-in, AP-7 | Tenant guards are Cedar `forbid` rules of the baseline, which no `permit` overrides ([0008](/decisions/0008-boundaries-and-tenants/#tenants)); a grant names its tenant, and key@ refuses it for any other ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). | A grant declared cross-tenant; a bug in a shared policy definition (accepted, below). | [REQ-ISO-036](/requirements/iso/#REQ-ISO-036), [REQ-ISO-078](/requirements/iso/#REQ-ISO-078) |
| **T-17** | One boundary's policy leaks into another's | Environment boundaries | AP-7 | Policy is signed config of its own boundary, and no boundary reads another's config ([0008](/decisions/0008-boundaries-and-tenants/#installation-wide-settings)). | As T-16. | [REQ-ISO-037](/requirements/iso/#REQ-ISO-037) |
| **T-18** | A grant decided in one boundary is spent in another | Environment boundaries | AP-3 | A grant is sealed under its boundary's `grant` data key, so it opens in no other boundary ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). | None beyond T-8. | [REQ-ISO-066](/requirements/iso/#REQ-ISO-066) |
| **T-19** | A person link is used to inherit grants across tenants | Tenants | AP-1 with one linked account | Two upstream accounts are two people and are never merged, so grant names, passkeys and sessions do not carry over from one to the other ([0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)); an SSH certificate carries identity only, the person key and never the grants ([0023](/decisions/0023-certificate-authorities/#ssh)). | None beyond T-16. | [REQ-ISO-058](/requirements/iso/#REQ-ISO-058) |
| **T-37** | A run-time loosening is abused or made to last | Policy and tunables | AP-3, AP-7 | The store checks the direction rule at write; a loosening carries an expiry; only the temp kind `PredefinedPolicyLinkTemporary` accepts a predefined policy that loosens, for 1 hour by default and 24 at most; a delegation policy says who may link what ([0004](/decisions/0004-the-data-model/#layers-and-the-direction-rule), [0007](/decisions/0007-policy-and-sealed-grants/#template-links)). A restore does not apply a loosening again ([0010](/decisions/0010-backup-and-recovery/#roll-forward)). | A loosening within its delegation, until it expires. Each one is an audit fact. | [REQ-POLICY-009](/requirements/policy/#REQ-POLICY-009) |
| **T-38** | A forged or replayed allowance push changes a tenant's allowance | Allowances | AP-1, AP-14 | A push comes over mutual TLS with the product service's X.509-SVID; `policy` decides each push per service, tenant and quota, and push and admit are distinct actions; the push is idempotent by request id, applied by conditional update, bounded by the `Quota` config kind, and an audit fact ([0039](/decisions/0039-quota-allowance/#the-push)). | A compromised product service pushes within its policy and the declared bounds, visible in audit. | [REQ-QUOTA-086](/requirements/quota/#REQ-QUOTA-086), [REQ-QUOTA-091](/requirements/quota/#REQ-QUOTA-091) |

### Export and backup

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-39** | exporter@'s destination credentials are abused | Exportable values, destinations | AP-13 | Only seven kinds are exportable and exporter@ refuses any other; destinations are config and may not overlap a secret source; the direct Kubernetes Secret path exists only when an installation chooses it, and its credential writes only the named Secrets in the named namespaces; every write is an audit fact ([0009](/decisions/0009-export/#destinations)). The backup job's bucket credential is write-only and opens nothing ([0010](/decisions/0010-backup-and-recovery/#the-archive-key)). | The exportable values it opens, `ClientSecretExport` among them, written to the destinations it holds; on the direct path, the named Secrets of one cluster. | [REQ-EXPORT-007](/requirements/export/#REQ-EXPORT-007) |

### Machine identity, enrolment and trust

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-20** | A workload or host gets a credential for another identity | Machine identities | AP-9 | Issuance bound to the requester: the subject of a certificate, SVID or workload token comes from the requester's authenticated identity, never from the request ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)). | A wrong declared rule that gives one identity too wide a name. | [REQ-ISO-039](/requirements/iso/#REQ-ISO-039) |
| **T-21** | A caller from one boundary passes for an actor of another | Calls between boundaries | AP-3 in another boundary | Mutual TLS with SPIFFE IDs, the trust domain being the boundary; a JWT-SVID across boundaries has the target's SPIFFE ID as its only `aud`; the target decides again with its own policy ([0008](/decisions/0008-boundaries-and-tenants/#federation-between-boundaries)). | What the target's own policy allows that trust domain. | [REQ-ISO-040](/requirements/iso/#REQ-ISO-040), [REQ-ISO-041](/requirements/iso/#REQ-ISO-041), [REQ-ISO-032](/requirements/iso/#REQ-ISO-032) |
| **T-22** | An enrolment proof is stolen, replayed or altered | Host and workload enrolment | AP-2, AP-9 | The enrolment token never travels: the client sends its ID and an HMAC over the CSR and a server nonce; tokens are single-use or counted and expire; an instance identity document is accepted once per instance; the request is HPKE-encrypted ([0022](/decisions/0022-workload-identity-and-host-enrolment/#host-enrolment)). | A token read on the target machine before its first use, limited by bound groups and a short expiry. | [REQ-ISO-044](/requirements/iso/#REQ-ISO-044) to [REQ-ISO-047](/requirements/iso/#REQ-ISO-047) |
| **T-23** | A host is made to trust the wrong roots | Trust bundles | AP-1 on the path, AP-6 for the bucket that serves bundles | The root list is signed by a root the host already holds and carries a trust sequence that only increases; each certificate in a bundle must chain to a root in that list, and a bundle with a lower `spiffe_sequence` is refused; the roots' public keys are pinned at enrolment ([0022](/decisions/0022-workload-identity-and-host-enrolment/#the-trust-bundle)). | One root card with its PIN, until that root is revoked and the update reaches the hosts (accepted, below). | [REQ-ISO-048](/requirements/iso/#REQ-ISO-048), [REQ-ISO-050](/requirements/iso/#REQ-ISO-050), [REQ-ISO-064](/requirements/iso/#REQ-ISO-064), [REQ-ISO-065](/requirements/iso/#REQ-ISO-065) |

### Operators, shared platforms and leaving

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-24** | A neighbour on a shared host or cluster uses an actor's socket or cloud role | Keys, data, cloud roles | AP-8 | Sockets in directories only their allowed callers can open, plus a peer-uid check; in the local installation a container mounts only the socket directories the actor registry allows; on Kubernetes a NetworkPolicy per callee admits only its allowed callers, and the interceptor checks the audience of the caller's service-account token; the cloud token is mounted only into a driver container, and a container that holds one has no listener ([0003](/decisions/0003-units-transports-and-fusion/#transports)). | Cluster administrators and node root (accepted, below). | [REQ-KEYS-044](/requirements/keys/#REQ-KEYS-044), [REQ-KEYS-045](/requirements/keys/#REQ-KEYS-045), [REQ-ISO-056](/requirements/iso/#REQ-ISO-056) |
| **T-25** | An operator's mistake opens a boundary | Config, delegation | AP-7 | Console delegation per tenant and boundary, every change audited under the operator's name; units, sockets, roles, policies and service accounts generated from the registries ([0002](/decisions/0002-families-of-actors/#registries-generate-the-enforcement)); config is a reviewed, signed commit; `sluis config check` refuses an inconsistent installation. | A mistake inside one's own delegation, or one that passes review; the deploying operator (accepted, below). | [REQ-ISO-053](/requirements/iso/#REQ-ISO-053), [REQ-ISO-055](/requirements/iso/#REQ-ISO-055) |
| **T-26** | A tenant that leaves keeps access, or leaves its data readable | Tenant data, workloads | AP-10 | The exit deletes the tenant's `data` and `pseudonym` wraps at once (the crypto-shred), so every value sealed for it stops opening; its `evidence` wrap goes when the evidence retention ends ([0008](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle), [0029](/decisions/0029-the-audit-log/#encryption-and-crypto-shredding)). A restore applies every shred again, and an archive's copy of the wraps leaves with the archive ([0010](/decisions/0010-backup-and-recovery/#roll-forward)). | Credentials issued before it left, until they expire ([0023](/decisions/0023-certificate-authorities/)); copies taken before it left, data outside sluis, and an archive taken before the shred until it expires: the archive retention is the longest time an erased value can exist in a copy. | [REQ-KEYS-036](/requirements/keys/#REQ-KEYS-036), [REQ-AUDIT-068](/requirements/audit/#REQ-AUDIT-068), [REQ-BACKUP-038](/requirements/backup/#REQ-BACKUP-038) |
| **T-40** | A reader of one project or tenant reads another's audit | The audit trail | AP-3, AP-14 | Access is checked twice: the reader asks `policy` for a grant per project, log kind and tenant, which filters every query and is needed to open a record at key@; and the blob store's own access control scopes every credential to a bucket and its prefixes. Each project has its own writer and log keys ([0028](/decisions/0028-audit-pieces/#access), [0029](/decisions/0029-the-audit-log/#projects)). | What its bindings allow. | Planned |
| **T-41** | A break-glass credential is stolen, or recovery is lost with the store | Recovery sign-in | AP-15, AP-6 | The credentials are config, so a damaged or restored store cannot lose or roll them back; two attested hardware keys and one synced passkey pinned by credential id; a recovery session has the recovery scope only, linked for 1 hour by default; every use is audited and alerted, and drilled each quarter ([0017](/decisions/0017-identity-and-sign-in/#break-glass-recovery), [Break-glass recovery](/security/break-glass/)). | A thief with one hardware key and its PIN, or the vault of the synced passkey, opens one recovery session, bounded by its scope and expiry and seen by the alert. | [REQ-AUTHN-066](/requirements/authn/#REQ-AUTHN-066) to [REQ-AUTHN-073](/requirements/authn/#REQ-AUTHN-073) |

### Units and fusion

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-42** | A flaw in `entry` reaches a signing right, a key or a credential | Authority keys, holder credentials | AP-2 | `entry` is never fused with `signer`, `ca` or `ssh-ca`; key@ is never fused with `entry`; a holder is never fused with a work actor. `sluis config check` and the build refuse such a unit, and print the union of rules of every fused unit ([0003](/decisions/0003-units-transports-and-fusion/#fusion)). | An installation that fuses `console` with `entry` widens the one unit reachable from outside by the console's rules. | Planned |

### Availability and abuse

| ID | Threat | Asset | Position | Control | Residual | Test |
|---|---|---|---|---|---|---|
| **T-27** | A sign-in or token flood saturates sluis | Availability of sign-in | AP-1, AP-11 | Volumetric traffic is absorbed at the edge; a token bucket in the temp kind `RateWindow` per connection, per client and per source; a refusal is a 429 ([0036](/decisions/0036-volumetric-abuse/#inside-sluis)). | Saturation of the link or the edge; a distributed flood below every per-source limit. | [REQ-SEC-020](/requirements/sec/#REQ-SEC-020), [REQ-SEC-021](/requirements/sec/#REQ-SEC-021), [REQ-SEC-024](/requirements/sec/#REQ-SEC-024), [REQ-SEC-025](/requirements/sec/#REQ-SEC-025) |
| **T-28** | Unauthenticated requests fill the store with unfinished sign-ins | The temp class | AP-1 | A pending sign-in is a temp kind that expires within 10 minutes and is capped per connection and per source address ([0036](/decisions/0036-volumetric-abuse/#inside-sluis)). | Sign-ins to one connection can be crowded out until the items expire. | [REQ-SEC-022](/requirements/sec/#REQ-SEC-022), [REQ-SEC-023](/requirements/sec/#REQ-SEC-023), [REQ-FED-034](/requirements/fed/#REQ-FED-034) |
| **T-29** | A slow or failing tenant provider starves the other tenants | Workers of a pooled adapter | AP-11, AP-4 | A concurrency limit, a timeout and a circuit breaker per connection; a pool per customer boundary ([0033](/decisions/0033-customer-connections/#a-pool-per-customer-boundary)). | That tenant's own sign-ins fail; tenants of one pool share the nodes it runs on. | [REQ-SEC-026](/requirements/sec/#REQ-SEC-026), [REQ-ISO-079](/requirements/iso/#REQ-ISO-079) |
| **T-30** | sluis is used to send requests to a provider or an internal address | Providers and the internal network | AP-1, AP-11 | Egress is denied by default per unit; the egress proxy refuses loopback, link-local and private addresses after name resolution, and each adapter keeps its calls to the hosts of its connection's discovery document ([0033](/decisions/0033-customer-connections/#a-pool-per-customer-boundary)); a limit on sign-in starts and on discovery refetches per connection. | A provider receives up to the connection's allowed rate. | [REQ-ISO-081](/requirements/iso/#REQ-ISO-081), [REQ-FED-008](/requirements/fed/#REQ-FED-008), [REQ-SEC-020](/requirements/sec/#REQ-SEC-020) |
| **T-31** | A dependency outage stops sign-in | Availability of sign-in | AP-6, an outage of the key service, the engine or an upstream | Fail closed with the documented error and no weaker path; tokens already issued stay valid until they expire; the key set is a static document that outlives the compute ([0010](/decisions/0010-backup-and-recovery/#a-regional-outage)). | A regional outage of the key service stops new sign-ins and signing until the region returns (accepted). | [REQ-OPS-006](/requirements/ops/#REQ-OPS-006), [REQ-OPS-013](/requirements/ops/#REQ-OPS-013), [REQ-OPS-014](/requirements/ops/#REQ-OPS-014) |
| **T-32** | Sign-ins and refreshes use up the key service's request quota | Token signing | AP-1, AP-11 | The limits above bound the signing rate per client and connection; the quota and the first bottleneck are measured ([0037](/decisions/0037-capacity-is-measured-before-it-is-promised/)). | The default quota is 1000 ECC operations a second per account and Region, shared by every ECC operation there (read from the account's quota service, 2026-11-02); the margin over the load is unknown until the rest of the spike is recorded. | [REQ-PERF-003](/requirements/perf/#REQ-PERF-003), [REQ-SEC-021](/requirements/sec/#REQ-SEC-021) |

## Accepted risks

The first five, and data outside sluis, are shared by design and are not removed by any level of the ladder ([0008](/decisions/0008-boundaries-and-tenants/#shared-parts-and-accepted-risks)). They are revisited when a boundary is promoted to its own operator.

- **The roots.** The roots are held by [ritueel](https://ritueel.id) and certify every boundary's intermediates; sluis holds none ([0024](/decisions/0024-root-custody-and-the-signing-api/#sluis-holds-no-root)). The offline recovery recipient is under ritueel's custody too, and using it is a ceremony ([0006](/decisions/0006-keys-and-sealing/#the-recovery-recipient)). The break-glass SSH CA is ritueel's ([SSH](/integrations/infrastructure-access/#the-break-glass-ssh-ca)).
- **The operator who deploys sluis.** Whoever writes the bootstrap file, holds a publisher key and runs the deployment can change any boundary they deploy.
- **Cluster administrators.** An administrator of a shared Kubernetes cluster can mint service-account tokens for any audience and open a shell in any container on it.
- **A boundary's `ca` reaches every tenant in that boundary.** Tenants share their boundary's authority keys and hold none of their own.
- **Bugs in shared policy definitions.** A wrong definition is wrong for every tenant it applies to, until a test finds it.
- **Secret-source values are visible to store@.** A secret source holds them in the clear for whoever may read it, so they pass through store@ in memory, and a compromised store@ yields them, though no sealed data ([0005](/decisions/0005-the-store/#secret-sources)). Tightening this on AWS is tracked in [#1182](https://github.com/truvity/sluis/issues/1182).
- **A compromised store@ can change or delete items in its engine.** The audit log and the backup are the control against that ([0005](/decisions/0005-the-store/#rules)).
- **The erasure delay on Lambda is the cache's time to live,** and an archive keeps an erased tenant's wraps until the archive expires ([0006](/decisions/0006-keys-and-sealing/#the-cache), [0010](/decisions/0010-backup-and-recovery/#roll-forward)).
- **Config is not fresh at a cold start.** A start takes the latest validly signed document whatever its sequence ([0005](/decisions/0005-the-store/#freshness-at-a-cold-start)).
- **Data outside sluis.** Secret stores, observability and deployment tools of the operator are outside this model.

## Related

- The [isolation requirements](/requirements/iso/) and their test vectors, and the [coverage](/requirements/coverage/) of the catalogue.
- [Break-glass recovery](/security/break-glass/), the operator's way back in when no upstream can vouch.
- [Families](/concepts/families/), [Data](/concepts/data/) and [Keys](/concepts/keys/), for the holders, the store and sealing; [Rules](/reference/rules/) and [Keys](/reference/keys/), for the generated matrices.
- [Deployment](/architecture/deployment/#enforcement-per-runtime), for the enforcement on each runtime.
- The [standards register](/standards/), for SPIFFE, HPKE, RFC 9470 and WebAuthn.
