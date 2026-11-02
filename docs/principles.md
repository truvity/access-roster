---
title: Design principles
description: "Eleven principles that shape sluis, marked shared with ritueel or sluis-only, and what sluis is and is not: no users, no roots, no Kubernetes objects."
status: target
---

These are the principles that the decision records follow. Each one is short, and each links to the records that apply it. A record that seems to break a principle should say why. Each principle is marked **shared** with the sister product [ritueel](https://ritueel.id), which keeps the roots, or **sluis-only**.

## 1. A key is born in its store and never leaves it

**Shared with ritueel.**

An authority key is made inside its key service or its card, signs in place, and cannot be exported. A transition, such as a new store or a new key, makes a new key that the old one vouches for. It never moves the old key. Wrapped data keys in a backup are escrow of data, not of keys: the wrapping key never leaves its store ([ADR 0034](/decisions/0034-a-backup-is-an-age-encrypted-tar-of-canonical-json-per-kind-and-restores-onto-any-driver/)). See [ADR 0012](/decisions/0012-cryptography-and-authority-keys/) and [ADR 0013](/decisions/0013-the-hand-off-to-root-custody-and-the-signing-api/).

## 2. Trust is layered, and redundancy is not a defence against compromise

**Shared with ritueel.**

Roots are offline, intermediates are re-signed every year, and leaf certificates are short. Redundancy protects against losing a key, not against its compromise: use two cards where a key cannot be copied, and a replica where the store can replicate. A compromise is answered by revocation and a transition. See [ADR 0013](/decisions/0013-the-hand-off-to-root-custody-and-the-signing-api/) and [Keys](/concepts/keys/).

## 3. Keys are shared, rotated and given to tenants by rule

**Sharing and rotation are shared with ritueel. The log-key exception and the tenant rule are sluis-only.**

- **Sharing.** A key is shared only when the audience, the lifetime, the revocation coupling and the callers are equal, and the store itself separates the uses. Symmetric KMS keys are shared with an encryption context; asymmetric signing keys never are; environments never share keys. See [When keys are shared and when separate](/decisions/0012-cryptography-and-authority-keys/#when-keys-are-shared-and-when-separate).
- **Rotation.** The yearly cycle re-signs. A software root is replaced every three years. A root on a card or in a cloud KMS is replaced on events (an advisory affecting the device or firmware, deprecation of its algorithm, loss or end of life), plus a review of advisories at the yearly ceremony; the rule is ritueel's, on [its principles page](https://ritueel.id/principles/). sluis holds no root, and its own authority keys follow the same rule: three years for a software key, events for a key on a card or in a cloud KMS, with a suspected compromise an event in every store. The log keys, the audit log key and the issuance-log key of `ca`, are the exception: they rotate only on compromise, because a log's signatures must verify for the life of the log. Intermediates keep their own lifetimes (13 months, renewed over the same key). See [Rotation](/decisions/0012-cryptography-and-authority-keys/#rotation).
- **Tenants.** A tenant has no key of its own: its data keys are wrapped under the sealing key, and shredding a tenant deletes its data key. See [When keys are shared and when separate](/decisions/0012-cryptography-and-authority-keys/#when-keys-are-shared-and-when-separate).

## 4. Verify; never trust a claim

**Shared with ritueel.**

A proof is checked, not believed: attestation, a chain to a root, a signature. A check that cannot run is reported as not run, never as passed. See [ADR 0007](/decisions/0007-workload-identity-and-host-enrolment/) and [ADR 0013](/decisions/0013-the-hand-off-to-root-custody-and-the-signing-api/#the-hand-off).

## 5. Open standards, as their consumers implement them

**Shared with ritueel. The audit format choices are sluis-only.**

sluis follows published standards, in the form that the software which consumes them actually implements, and takes the core of a standard before its extensions. See [ADR 0012](/decisions/0012-cryptography-and-authority-keys/), [ADR 0016](/decisions/0016-the-audit-log/) and [ADR 0017](/decisions/0017-audit-records-the-usage-stream-and-quota/).

## 6. Generic products, joined by a contract

**Shared with ritueel.**

Products are generic and are joined by a written contract with test vectors, not by shared code. Things are named for what they are. See [ADR 0013](/decisions/0013-the-hand-off-to-root-custody-and-the-signing-api/) and [ADR 0002](/decisions/0002-the-design-model-actors-ports-drivers-and-contracts/).

## 7. A person only where a person adds safety

**Shared with ritueel.**

Routine work is automated, and a node signs unattended. A renewal over the same key is routine and is automated where the store allows it; a person is required to make a root, to change the root set, and to certify a new key. A person takes part where a person adds safety, such as a root ceremony or an unlock after a full power loss. Irreversible steps belong to the operator. See [Touch and PIN](/decisions/0012-cryptography-and-authority-keys/#touch-and-pin) and [ADR 0013](/decisions/0013-the-hand-off-to-root-custody-and-the-signing-api/#lifetimes-and-the-warning).

## 8. Nothing without a consumer

**Shared with ritueel.**

A feature has a consumer before it is built. Be strict where safety needs it, such as the floors in code, and lean elsewhere. See [Floors in code](/decisions/0012-cryptography-and-authority-keys/#floors-in-code) and [ADR 0018](/decisions/0018-runtimes-installations-and-delivery-order/).

## 9. Measure before deciding, and date the measurement

**Shared with ritueel.**

A design choice that depends on a number rests on a measurement, and the record names the date and the version. See the signing rates in [ADR 0012](/decisions/0012-cryptography-and-authority-keys/#consequences) and [ADR 0013](/decisions/0013-the-hand-off-to-root-custody-and-the-signing-api/).

## 10. One product, many shapes

**sluis-only.**

A port has one driver until a second real installation needs another; the second driver is added with that installation. sluis is built against these reference shapes: a workforce installation on serverless, a customer-identity installation on Kubernetes, audit-with-quota installations, a self-hosted installation on small boards, and development on software keys. See [Reference installation shapes](/runtimes/installations/#reference-installation-shapes), [ADR 0002](/decisions/0002-the-design-model-actors-ports-drivers-and-contracts/) and [ADR 0018](/decisions/0018-runtimes-installations-and-delivery-order/).

## 11. Public by default, private where it protects

**Shared with ritueel.**

The design, the code and the reasons are public. What stays private is what protects someone: secrets, accounts, and findings that are not yet fixed. See [Public content and secrets](/contributing/public-content/) and [ADR 0001](/decisions/0001-v1-and-v2-lines/).

## What sluis is, and is not

These product decisions follow from the principles above.

- **sluis has no users of its own.** It hosts no end-user accounts and stores no passwords. People come from upstream directories, and customer identity is broker-only too ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)). The one exception is the operator's break-glass recovery, with passkeys only: see [Break-glass recovery](/security/break-glass/).
- **sluis never generates roots.** It holds intermediates only. Any certificate authority that signs a PKCS#10 request can certify them; [ritueel](https://ritueel.id) is the root custodian the project builds and tests against, and the two are joined through its hand-off contract. See [ADR 0013](/decisions/0013-the-hand-off-to-root-custody-and-the-signing-api/#sluis-holds-no-root).
- **sluis never writes Kubernetes objects.** Cluster tools such as cert-manager, trust-manager and External Secrets stay its clients and distributors; sluis serves APIs and exports. See [ADR 0018](/decisions/0018-runtimes-installations-and-delivery-order/#kubernetes) and [Data and secrets](/concepts/data/).
- **A development or test installation differs by configuration only.** There is no test-only code in the product: "dev is not a build". Tests sign in through a real identity provider run beside the installation, not through accounts in sluis. See [ADR 0019](/decisions/0019-release-train-packaging-and-distribution/) and [ADR 0018](/decisions/0018-runtimes-installations-and-delivery-order/#the-local-installation).
- **One product, many installations.** Tenants live inside an installation and share its keys; environments never share keys. See [ADR 0030](/decisions/0030-tenancy-and-scale-a-boundary-holds-keys-and-a-tenant-is-a-record/), [ADR 0005](/decisions/0005-boundaries-and-the-isolation-ladder/) and [When keys are shared and when separate](/decisions/0012-cryptography-and-authority-keys/#when-keys-are-shared-and-when-separate).
- **sluis is a young project.** It is maintained by one person with AI agents, has had no independent security review yet, and v2 has no code. v1 runs in the maintainer's production. [GOVERNANCE.md](https://github.com/truvity/sluis/blob/main/GOVERNANCE.md) says how that changes.
