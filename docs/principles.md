---
title: Design principles
description: "Sixteen principles that shape sluis, shared with ritueel or its own, and what sluis is not: no users, no roots, no Kubernetes object but one exported Secret."
status: target
---

These are the principles that the decision records follow. Each one is short, and each links to the records that apply it. A record that seems to break a principle should say why. Each principle is marked **Shared** with the sister product [ritueel](https://ritueel.id), which keeps the roots, or **sluis's own**. Principles 1 to 10 carry the same numbers as in ritueel, and 11 and up come from one common sequence, so a number never means two things.

## 1. A key is born in its store and never leaves it

**Shared with ritueel.**

An authority key or a wrapping key is made inside its key store, a cloud KMS or a card, is used there in place, and cannot be exported: `key@` asks the key store to sign or to unwrap, and never holds the private key. A transition, such as a new store or a new key, makes a new key that the old one vouches for; it never moves the old key. A data key is not an authority key: `key@` makes it, keeps it only wrapped, as a `DataKeyWrap` stored like any other data, and opens it only in its own memory. Wrapped data keys in a backup are escrow of data, not of keys: the wrapping key never leaves its store. See [ADR 0006](/decisions/0006-keys-and-sealing/), [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/) and [ADR 0010](/decisions/0010-backup-and-recovery/).

*Questions it settles:* may `key@` cache a private key? (No: only opened data keys.) May a data key be stored? (Yes, wrapped, as data.) Does a backup hold keys? (Only wrapped data keys.)

## 2. Trust is layered, and redundancy is not a defence against compromise

**Shared with ritueel.**

Roots are offline: they sign at a ceremony or, for a key service, under a declared renewal policy that can extend trust and never create it. Intermediates are re-signed every year, and leaf certificates are short. Redundancy protects against losing a key, not against its compromise: use two cards where a key cannot be copied, and a replica where the store can replicate. A compromise is answered by revocation and a transition. See [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/) and [Keys](/concepts/keys/).

## 3. Keys are shared, rotated and given to tenants by rule

**Sharing and rotation are shared with ritueel. The log-key exception and the tenant rule are sluis's own.**

- **Sharing.** A key is shared only when the audience, the lifetime, the revocation coupling and the callers are equal, and the store itself separates the uses. There is one key per purpose and per algorithm: an asymmetric key never serves two purposes, and several audiences of one purpose share its key. A boundary's one symmetric KMS key is shared by sealing, wrapping and grants, each under its own encryption context. Boundaries never share keys. See [Key purposes](/decisions/0006-keys-and-sealing/#key-purposes).
- **Rotation.** Renewal re-signs. Key material is replaced on an event: an advisory that affects the device, its firmware or the service, deprecation of its algorithm, loss or end of life, a suspected compromise, or a change of store or custody; the holder reviews the advisories at every yearly ceremony. A key that can be copied, a software key, is also replaced at most every three years. This is the wording of [ritueel's principle 3](https://ritueel.id/principles/). sluis holds no root, and its own authority keys follow the same rule. The log keys, of the audit log and of the issuance log, are the exception: they rotate only on compromise, because a log's signatures must verify for the life of the log. Intermediates keep their own lifetimes (13 months, renewed over the same key). See [Rotation](/decisions/0006-keys-and-sealing/#rotation).
- **Tenants.** By default a tenant has no authority key and no wrapping key of its own. It has four data keys of its own, one per purpose (`data`, `pseudonym`, `pairwise` and `evidence`), each wrapped under its boundary's wrapping key with the tenant and the purpose in the context. A tenant's exit deletes the `data`, `pseudonym` and `pairwise` wraps at once, so every value sealed for it stops opening; a copy in an older archive goes when the archive expires, and a restore re-applies the erasure ([ADR 0010](/decisions/0010-backup-and-recovery/#roll-forward)); the `evidence` wrap is deleted when the evidence retention ends, because evidence never shares a key with personal data and outlives it. Any other party that needs authority keys of its own is a boundary ([0006](/decisions/0006-keys-and-sealing/#where-a-tenants-keys-live)). See [Erasing a tenant](/decisions/0006-keys-and-sealing/#erasing-a-tenant) and [Tenants](/decisions/0008-boundaries-and-tenants/#tenants).

*Questions it settles:* does a tenant get a KMS key or a card slot? (Not by default; only a tenant declared to keep its keys in a customer account has KMS keys of its own, [0006](/decisions/0006-keys-and-sealing/#where-a-tenants-keys-live).) Does a regulated customer get its own keys? (As a tenant in a customer account, or as a boundary.) May the RS256 audience reuse the token key? (No: another algorithm, another key.) Do two audiences of the token purpose need two keys? (No.)

## 4. Verify; never trust a claim

**Shared with ritueel.**

A proof is checked, not believed: attestation, a chain to a root, a signature. A check that cannot run is reported as not run, never as passed. See [ADR 0022](/decisions/0022-workload-identity-and-host-enrolment/) and [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off).

## 5. Open standards, as their consumers implement them

**Shared with ritueel. The audit format choices are sluis's own.**

sluis follows published standards, in the form that the software which consumes them actually implements, and takes the core of a standard before its extensions. See [ADR 0006](/decisions/0006-keys-and-sealing/), [ADR 0029](/decisions/0029-the-audit-log/) and [ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/).

## 6. Generic products, joined by a contract

**Shared with ritueel.**

Products are generic and are joined by a written contract with test vectors, not by shared code. Things are named for what they are. See [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/) and [ADR 0002](/decisions/0002-families-of-actors/).

## 7. A person only where a person adds safety

**Shared with ritueel.**

Routine work is automated, and a node signs unattended. A renewal over the same key is routine and is automated where the store allows it; a person is required to make a root, to change the root set, and to certify a new key. A person takes part where a person adds safety, such as a root ceremony or an unlock after a full power loss. Irreversible steps belong to the operator. See [Touch and PIN](/decisions/0006-keys-and-sealing/#touch-and-pin) and [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#lifetimes-and-the-warning).

## 8. Nothing without a consumer

**Shared with ritueel.**

A feature has a consumer before it is built. Be strict where safety needs it, such as the floors in code, and lean elsewhere. See [Floors in code](/decisions/0006-keys-and-sealing/#floors-in-code) and [ADR 0011](/decisions/0011-runtimes-and-installations/).

## 9. Measure before deciding, and date the measurement

**Shared with ritueel.**

A design choice that depends on a number rests on a measurement, and the record names the date and the version. See the signing rates in [ADR 0006](/decisions/0006-keys-and-sealing/#consequences) and [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/).

## 10. Public by default, private where it protects

**Shared with ritueel.**

The design, the code and the reasons are public. What stays private is what protects someone: secrets, accounts, and findings that are not yet fixed. See [Public content and secrets](/contributing/public-content/) and [ADR 0001](/decisions/0001-v1-and-v2-lines/).

## 11. One product, many installations

**sluis's own.**

Every installation runs the same actors and the same holders; what differs is the driver behind each holder's port. `store@` has four ports, one per storage class, `exporter@` one per destination, and `key@` one for its card or KMS. A driver is private to its owner (`store@`, `key@` or `exporter@`; `key@`'s card and KMS driver included), and only its owner can open its socket. Each port has one driver until a second real installation needs another, and that driver arrives with that installation. sluis is built against these reference installations: a self-hosted installation on three small boards, a workforce installation on serverless, a customer-identity installation on Kubernetes, and a local one-node installation for development. See [Installations](/runtimes/), [ADR 0005](/decisions/0005-the-store/#drivers) and [ADR 0011](/decisions/0011-runtimes-and-installations/).

*Questions it settles:* may an installation add a driver "for later"? (No.) Does a work actor ever see a driver? (No.) Do Lambda or Kubernetes run different actors from the boards? (No.)

## 12. A loosening is temporary, a tightening is durable

**sluis's own.**

A change that lets less happen takes effect at once and stays: a revocation, a shorter lifetime, a stricter sign-in, a paused job. A change that lets more happen is allowed only as far as the layer below permits, and when it is made at run time it carries an expiry: a debug log level, a break-glass link. Making a loosening permanent goes through the reviewed path that sets the layer below. A restore never loosens what was tightened after the archive was taken. See [Layers and the direction rule](/decisions/0004-the-data-model/#layers-and-the-direction-rule) and [ADR 0010](/decisions/0010-backup-and-recovery/).

*Questions it settles:* may an operator raise a limit for a tenant without review? (Only up to config's bound, and only with an expiry.) Must a revocation wait for a deploy? (No.) Does a roll-forward after a restore undo a switch turned on later? (No.)

13 to 15 are ritueel's own; see [ritueel's principles](https://ritueel.id/principles/). A new principle takes the next free number, whichever product adds it.

## 16. Few credential holders

**sluis's own.**

Only four kinds of unit hold a credential at rest: `store@` and `exporter@` (data), `key@` (keys), and the audit pieces that hold a credential (writer, witness, indexer, reader). A work actor holds no storage, key or audit credential: it reaches data, keys and audit only through its ports, so a flaw in a work actor yields what it is using right now and nothing it could replay later. A holder never shares a unit with a work actor, and `key@` never with `entry`. See [ADR 0002](/decisions/0002-families-of-actors/#credential-holders) and [ADR 0003](/decisions/0003-units-transports-and-fusion/#fusion).

*Questions it settles:* may an integration keep its provider token in a file? (No: a config-referenced secret or sealed durable data, opened per call.) May an installation fuse the store into the session unit to save memory? (No.) Who gets a cloud role? (On Lambda every function has a role; only the holders' roles may reach storage, keys, export destinations or the audit blob, and a work function's role may only invoke other functions and emit to the audit transport.)

## 17. Where a thing is written decides its class

**sluis's own.**

IaC and the publishing pipeline write config and secrets, under review; sluis writes durable and temp data, through the store, one writer per kind; sluis never writes config. A kind lives in exactly one class, so a setting that comes from several places is split into one kind per layer. See [ADR 0004](/decisions/0004-the-data-model/#storage-classes) and [ADR 0005](/decisions/0005-the-store/#configuration-loading).

*Questions it settles:* may the console "promote" a setting into config? (No; it may render a change for review.) Is a generated client secret a secret? (No: it is sealed or hashed durable data.) Is an app made through a browser flow config? (No: durable, by the upstream criterion.)

## 18. Plaintext lives only where it is used, behind two independent checks

**sluis's own.**

The store keeps sealed values as ciphertext and compare-only values as hashes; it never seals or opens. The actor that needs a sealed value asks `key@` to open it, and the plaintext exists only in that actor, for that call. Values from secret sources pass through `store@` in memory (accepted, and stated in the [threat model](/security/threat-model/)), and plain kinds are stored as they are. Two independent checks stand between any actor and a tenant's sealed value: the store's rule for the actor, kind and verb, with a grant sealed for the tenant on every write, and `key@`'s check of the grant on every seal and open. A value is bound to its full address, so a value moved to another row or tenant no longer opens. See [ADR 0006](/decisions/0006-keys-and-sealing/#seal-and-open) and [ADR 0007](/decisions/0007-policy-and-sealed-grants/#two-independent-checks).

*Questions it settles:* may the store decrypt to validate a field? (No: sealed fields are validated by the writing actor before sealing.) Does a compromise of the store expose tenant data? (Sealed values as ciphertext only; secret-source values and plain kinds are not sealed, which the threat model states.) Does a compromise of `key@` expose data? (Keys but no data, except its own wraps.)

## 19. One model, many transports

**sluis's own.**

A request takes the same steps and passes the same checks on every installation; only the transport of each hop differs: a Unix socket checked by peer uid on the boards, a Lambda invoke checked by role, an in-cluster call checked by service-account token. A design that needs a different step on one platform is a design change for all of them. See [ADR 0003](/decisions/0003-units-transports-and-fusion/#transports) and [ADR 0011](/decisions/0011-runtimes-and-installations/).

*Questions it settles:* may Lambda skip `key@` and decrypt in the store for latency? (Not without a design change recorded for every installation; the Lambda latency spike found invokes fast enough, so there is no in-process store: Lambda changes the transport, not the steps.) Does Kubernetes get its own data model? (No.) Can the boards' test suite stand in for Lambda's checks? (For the steps, yes; for the transport, no.)

## What sluis is, and is not

These product decisions follow from the principles above.

- **sluis has no users of its own.** It hosts no end-user accounts and stores no passwords. People come from upstream directories, and customer identity is broker-only too ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)). The one exception is the operator's break-glass recovery, with passkeys only: see [Break-glass recovery](/security/break-glass/).
- **sluis never generates roots.** It holds intermediates only. Any certificate authority that signs a PKCS#10 request can certify them; [ritueel](https://ritueel.id) is the root custodian the project builds and tests against, and the two are joined through its hand-off contract. See [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#sluis-holds-no-root).
- **sluis writes no Kubernetes object, except an exported Secret written by `exporter@` when an installation chooses the direct path.** Cluster tools such as cert-manager, trust-manager and External Secrets stay its clients and distributors; sluis serves APIs and exports. See [ADR 0009](/decisions/0009-export/#destinations), [ADR 0011](/decisions/0011-runtimes-and-installations/#kubernetes) and [Data and secrets](/concepts/data/).
- **A development or test installation differs by configuration only.** There is no test-only code in the product: "dev is not a build". Tests sign in through a real identity provider run beside the installation, not through accounts in sluis. See [ADR 0013](/decisions/0013-release-train-packaging-and-distribution/) and [ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation).
- **Tenants live inside a boundary.** A tenant shares its boundary's authority keys and has its own data keys; boundaries never share keys. See [ADR 0008](/decisions/0008-boundaries-and-tenants/) and [principle 3](#3-keys-are-shared-rotated-and-given-to-tenants-by-rule).
- **The product owns money; sluis owns the allowance and the evidence.** Plans, prices and money balances live in the product. sluis holds an allowance per tenant and quota, pushed by the product, counts it down, refuses at zero, and records every admit, refusal and top-up as an audit fact; the billing log is built outside sluis. See [ADR 0039](/decisions/0039-quota-allowance/).
- **sluis is a young project.** It is maintained by one person with AI agents, has had no independent security review yet, and v2 has no code. v1 runs in the maintainer's production. [GOVERNANCE.md](https://github.com/truvity/sluis/blob/main/GOVERNANCE.md) says how that changes.

*Questions the money bullet settles:* does sluis issue invoices or statements? (No.) Does a price change need a sluis deploy? (No.) Can sluis answer "how much is left"? (Yes, from the allowance.)
