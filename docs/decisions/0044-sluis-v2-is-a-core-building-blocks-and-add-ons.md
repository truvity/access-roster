# 0044 — sluis v2 is a core, building blocks and add-ons, and the first working version is the core

**Status:** Accepted
**Date:** 2026-11-12

Proposal: [issue #1017](https://github.com/truvity/sluis/issues/1017), maintainer decisions D2 A, D5 A, D6 A and D7 A, 2026-11-12.

## Context

The roadmap so far was a core (workforce sign-on and reconcilers) and two later layers, CIAM and quota ([0011](/decisions/0011-runtimes-and-installations/#delivery-order)). On 2026-11-12 the maintainer re-planned v2 with seven updates:

1. ritueel owns the roots; sluis owns the intermediates and the request and install side.
2. Customers sign in through an upstream identity provider, and a sluis token carries the customer, the organisation and the product ([0045](/decisions/0045-customers-sign-in-upstream-and-the-sluis-token-carries-customer-org-and-product/)).
3. `store`, `key` and `policy` may become building blocks that other services reuse.
4. The core is separate from optional add-ons such as Cloudflare and GitHub.
5. Internal PKI, SSH and database access is the most important add-on.
6. Audit also serves the product, and covers usage and limits ([0046](/decisions/0046-usage-records-are-never-dropped-and-balances-live-in-the-product/)).
7. Everything else goes to the backlog or is cancelled.

The code already has the shape: a core spine, no outbound call to GitHub, Cloudflare or AWS in any built actor, and `ca` as a v0 that issues the token certificate. What disagreed was the written plan: it put the exporter's bucket driver and the Cloudflare edge purge inside the first working version, and ranked the PKI and SSH work after the whole v1 retirement gate.

## Decision

### The shape

- **The core** is what every installation needs: install and run, the commands of the [first-version command table](/reference/cli/#the-first-working-versions-commands), `entry`, `session`, `exchange`, `signer` and `ca` as a v0. The core installs, runs and passes its tests without any add-on.
- **The building blocks** are store, key, policy, and audit with usage and limits. Each keeps its interface; a product may reuse one later. Until a block is extracted, no domain type is coupled into a block: the store driver holds bytes and a new storage need is a kind, and key holds no root.
- **The add-ons** are optional and each has a scope of its own: PKI with SSH and database access first, then Cloudflare, then GitHub. No actor of the core calls an add-on.

### Phases

The phases P0 to P4 and what each is done by are on the [roadmap](/roadmap/#phases), the one place that states them. The order that this record fixes is this:

- **The first working version is the core (P1).** The three boards stay in it (D2 A); the other board rows are Backlog. The exporter's bucket driver, the edge purge and the R2 token leave it and become the Cloudflare add-on. The `github-oidc` verifier leaves the core and becomes part of the GitHub add-on.
- **Identity and audit (P2) come before the PKI add-on (P3)** (D6 A).
- **P3 is the PKI, SSH and database add-on and the cutover of the maintainer's v1 platform** to the three-board install, once sluis is at v1 parity for what that platform uses (D5 A). The audit log moves from the local spool to R2 buckets then, so the Cloudflare add-on is built in P3 because the cutover needs it.
- **The "CIAM upstream" and "Quota" milestones are removed** (D7 A).

### Backlog and cancelled

The maintainer approved the cancel list as it stands (D7 A). The records below are superseded, each by the record that carries the reason:

| Record | Superseded by | Reason |
|---|---|---|
| [0031](/decisions/0031-ciam-is-a-broker/), [0033](/decisions/0033-customer-connections/), [0034](/decisions/0034-end-users-and-upstream-signals/), [0035](/decisions/0035-customer-pages/), [0038](/decisions/0038-fapi-2-profile/) | [0045](/decisions/0045-customers-sign-in-upstream-and-the-sluis-token-carries-customer-org-and-product/) | Customers sign in through the upstream identity provider (D1 B) |
| [0039](/decisions/0039-quota-allowance/) | [0046](/decisions/0046-usage-records-are-never-dropped-and-balances-live-in-the-product/) | Plans and balances live in the product (D4 A) |

Plans that no update serves go to the backlog: the isolation harness and generators, the extra board rows, the extras of the Cloudflare and GitHub add-ons, the audit read API and front, and libraries in languages other than Go and Rust. Which v1 parity rows the cutover needs is mapped separately; the rest of the parity group is Backlog. Moving issues and board fields is the maintainer's script, not this record.

### The ritueel boundary

ritueel owns the roots, the root list, the CA bundle, the revocation lists, the keyring file, what it knows about its cards, and the SSH CA. sluis owns the intermediates and the request and install side. They meet only through [hand-off contract v1](https://ritueel.id/reference/hand-off-contract/) ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)).

- **ritueel builds the trust files and does not publish them for sluis.** The trust files are the root list, the CA bundle, the revocation lists, the SSH CA key list and the keyring. A pipeline outside ritueel publishes them. Prose that says "ritueel publishes" is corrected to say who builds and who publishes.
- **ritueel issues no leaf certificate.** A leaf is sluis's: `ca` issues every leaf from the boundary's intermediate ([0023](/decisions/0023-certificate-authorities/#leaf-profiles)).
- **A root is "used only in a ceremony",** not "offline": a cloud root is not offline.

### Names

Maintainer decision R3, 2026-11-12: sluis follows ritueel's names. They are read from ritueel's naming table at commit `d9f9b66` of `truvity/ritueel` (2026-11-12). Only a term that ritueel's records decide is fixed here.

- **A root key is one key; a root is what is built from keys,** of one kind: an X.509 trust anchor, an OpenPGP identity or an SSH CA.
- **"CA bundle" is the one PEM file with the certificates of the active X.509 root keys.** "Trust bundle" is the SPIFFE document that `ca` renders ([0022](/decisions/0022-workload-identity-and-host-enrolment/#the-trust-bundle)) and nothing else. "Bundle" alone is ritueel's directory, which holds one trust domain, and is never a file.
- **The trust files are the root list, the CA bundle, the revocation lists, the SSH CA key list and the keyring.** The root list pins each root key by a digest of its public key and carries the trust sequence; an X.509 root key signs it. ritueel builds the trust files and a pipeline outside ritueel publishes them.
- **The hand-off contract has three request types:** `x509-intermediate`, `openpgp-subkey` and `ssh-ca-key`. A request is answered by an answer, which always holds a result file. "Hand-off" alone, or "intermediate hand-off", does not name the contract.
- **A ceremony is one act that uses a root key.** A step of sluis, such as writing a request or installing an answer, is not a ceremony.
- **`TrustAnchors` is sluis's own config kind.** It holds copies of the root list with its signature, the CA bundle and the SSH CA key list that ritueel builds. It is not a ritueel file.
- **File names of ritueel's reference pages** (`root-list.json`, `root-list.jws`, `ca-bundle.pem`, `crl-<label>.pem`, `ssh-ca-keys.json`) are cited as they stand at `d9f9b66`. They are not permanent; ritueel may rewrite them until its first release.
- **Words that ritueel has not fixed are not used:** the word for the person who keeps a root and publishes its files, the file names of its cards, the folder of a trust set, the name of the keyring file, the paths of its wanted files, and what `acme/A` names.
- **These replacements are proposals from ritueel's side, not decisions of its records:** "CA bundle" for the file and "trust bundle" for SPIFFE only, "ceremony" for "root ceremony", "hand-off request" with its type, "ritueel builds it; a pipeline outside ritueel publishes it", and the description of `TrustAnchors` above.

### Name constraints of the boards' intermediates

Maintainer decision R1 A, 2026-11-12: each board's intermediate carries one permitted DNS subtree, the same internal zone on all three boards. ritueel adds the policy member that lists DNS subtrees in its M2 ([truvity/ritueel#70](https://github.com/truvity/ritueel/issues/70)); until then the boards keep the test certifier ([Local](/runtimes/local/#a-boards-intermediate)).

### The recovery key is not a ritueel object

Maintainer decision R2 A, 2026-11-12: the recovery key of sluis (the recovery recipient of [0006](/decisions/0006-keys-and-sealing/#the-recovery-recipient)) is not a ritueel object. It is not part of the first working version. Later sluis keeps it itself, for example as a second KMS key or as a key on a card held outside ritueel. [0006](/decisions/0006-keys-and-sealing/#the-recovery-recipient) and [0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#wrapping-keys-recipients-and-archives) are amended, and the pages that put it under ritueel's custody are corrected.

### SSH under ritueel's SSH CA

sluis issues a short-lived SSH user certificate to the holder of a sluis token, and a host certificate to an enrolled host, under an SSH CA key that ritueel lists on its signed SSH CA key list ([0023](/decisions/0023-certificate-authorities/#ssh), [0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)). This replaces an opkssh-style flow, in which `sshd` checks an OpenID Connect token: the host needs no token verifier, only the SSH CA key list and the principals that `sluis-host` writes. REQ-SSH-004, which said that sluis does not provide such a sign-in, is withdrawn and replaced by [REQ-SSH-011](/requirements/ssh/#REQ-SSH-011) (update 5, D5 A). The break-glass SSH CA stays offline in ritueel's hands.

### Staff keys and ritueel

The ritueel half of [0043](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/) is superseded: ritueel dropped staff keys on 2026-11-11, so there is no ritueel card helper, no shared bundle format and no trust-signature ceremony over a sluis certification key. The sluis half (a person binds their own key, sluis checks the proof on the server) stays in Backlog with the staff-key work. [0024](/decisions/0024-root-custody-and-the-signing-api/#company-openpgp-certification) is read the same way.

## Consequences

- The first version is smaller and has no Cloudflare dependency at run time. A revoked key leaves the key set that the directory driver publishes; the confirmation through an edge comes with the Cloudflare add-on.
- The cutover of the v1 platform is later than the core and later than identity and audit, and it needs the Cloudflare add-on, which the first version no longer has.
- The PKI add-on runs on a test root until ritueel has built the SSH CA key list and the cloud root.
- Pages and records that said ritueel publishes files, or issues the certificates of the rqlite Raft port, are corrected. Where sluis cannot issue a certificate because its own store is not up yet, the page says the question is open.
- Requirement rows follow the records: the rows of the cancelled work are withdrawn, and new rows carry the new obligations.
- A cost: the Kubernetes and Lambda installations have no phase. They wait in the backlog until a consumer needs them.

## Roads not taken

- **Keep CIAM and Quota as later layers.** The maintainer's updates replace both with an upstream identity provider and a product-side balance.
- **Keep the Cloudflare edge in the first version.** The core would depend on a vendor for its first run, and nothing in the done-when needs it.
- **Run the PKI add-on after the whole v1 retirement gate.** The maintainer ranks it first among the add-ons, because it completes the retirement of the v1 secrets store.
- **Extract the blocks now.** Nothing outside sluis consumes them yet; a rule of no new coupling keeps the option.
- **Supersede ADR 0043 whole.** Its sluis half is a valid design that waits in Backlog; only the ritueel half contradicts ritueel.

## Follow-ups

- The board, the issue milestones and the cancelled issues follow this record in a script that the maintainer runs.
- Which parity rows the cutover of the v1 platform needs: mapped separately, tracked in [#1017](https://github.com/truvity/sluis/issues/1017).
- The SSH CA key list reader and `sluis key request` for an SSH CA key: [#925](https://github.com/truvity/sluis/issues/925), [#1369](https://github.com/truvity/sluis/issues/1369).
