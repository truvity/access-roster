# 0024 — sluis holds no root: it asks root custody to certify its intermediates, and signs artifacts through a signing API

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #1001](https://github.com/truvity/sluis/issues/1001).

## Context

A chain of trust has a few keys that almost never change, the roots, and many that work every day. A root is used rarely, by a person who is present, and a mistake with it is slow and expensive to repair. The intermediates sign certificates, tokens and artifacts all the time and must be online and automated. Putting both in one product puts the rarest and most valuable keys beside the busiest code.

On 2026-11-01 the maintainer split them. A separate product, [ritueel](https://ritueel.id), owns the roots, the ceremonies that certify an intermediate, and every transition of a root between key stores. sluis owns the intermediates and everything that signs with them. The two share no code and have no code or runtime dependency on each other; they exchange standard formats through a written contract. This record is sluis's side of that contract: what it hands over, what it installs, how it warns, what it verifies and what it signs. How its keys are born and used is [0006](/decisions/0006-keys-and-sealing/).

## Decision

### sluis holds no root

- **sluis holds intermediates and the keys that sign with them, never a root.** It does not create, keep, rotate or revoke a root.
- **sluis never generates a root.** Its intermediates are certified by any certificate authority that signs a PKCS#10 request and issues the profile of ritueel's hand-off contract ([the floor](https://ritueel.id/reference/hand-off-contract/#the-floor-pkcs10-in-x509-out)). The test harness uses a throwaway root from a plain CA tool, and ritueel's software-root mode when it exists.
- **The key commands are `sluis key request`, `sluis key install` and `sluis key status`.** There is no ceremony command in sluis.
- **The profile of an intermediate** (path length, name and URI constraints, extended key usage) and its test vectors are written once, in ritueel's [hand-off contract](https://ritueel.id/reference/hand-off-contract/). Each side tests against them; no code is shared.

### The hand-off

sluis hands ritueel a request and installs what comes back. The specification is ritueel's [hand-off contract, version 1](https://ritueel.id/reference/hand-off-contract/); it owns the files, the members, the profiles, the reason codes and the test vectors, and this record does not copy them. sluis writes exactly what the contract defines, refuses a version it does not know and a member it does not define, and passes the contract's vectors, the floor vectors included ([#1070](https://github.com/truvity/sluis/issues/1070)).

- **There are three request types:** an X.509 intermediate, an OpenPGP signing subkey and an SSH CA key. The first working version requests the first, and the second with the signing API; the third comes with `ssh-ca` ([#1072](https://github.com/truvity/sluis/issues/1072)).
- **An X.509 answer is one certificate and, with the full contract, a result file.** The root is never in the answer. `sluis key install` takes its anchors from `trust.ca_bundle`; when sluis also holds a root list, a certificate of the bundle is an anchor only if its key is on that list. The result file only names which anchor issued the certificate.
- **An OpenPGP request holds the subkey and one back-signature for every active primary** on the signed root list that sluis holds, and its proof names those primaries. Either root card can then make the binding, with no second request. A root list that is not current gives the contract's `unknown-primary`, and the fix is a newer list, not a new key.
- **`key-holder` makes the back-signatures on the board.** The subkey stays in a PIV slot and the card signs the digest of each primary-key binding. The keys are version 4, ECDSA on P-384, and every signature uses SHA-384. Each back-signature carries the Issuer Fingerprint in its hashed area and the Issuer Key ID in its unhashed area; `gpg` 2.2 refuses a certificate whose signatures lack the key ID. sluis builds the OpenPGP packets itself and does not use `gpg` on a board. Tested 2026-10-31 with a throwaway primary: `gpg`, `gpgv` and `sqv` accept the subkey with the back-signature and refuse it without.
- **The proof names the store by the contract's words:** `piv` for a key in a PIV slot, which is sluis's `yubikey-piv` driver; `aws-kms`; and `software`. A node never uses the `openpgp-card` store, because the OpenPGP applet is not used on a node ([0006](/decisions/0006-keys-and-sealing/#the-slot-plan)).
- **A KMS proof names the key by its full ARN.** The certifier reads the key itself and trusts no copy. ritueel's roots live in an account of their own, so a sluis key is in another account: sluis creates a read-only role in the key's account that allows `DescribeKey`, `GetPublicKey` and `GetKeyPolicy` on that key and nothing else, and trusts the certifier's principal to assume it. The certifier refuses a key whose policy lets more than one principal `kms:Sign`, which is the rule [0006](/decisions/0006-keys-and-sealing/#key-purposes) already sets for every signing key. An OpenPGP subkey in KMS needs its creation time kept, for example as a tag, because the fingerprint depends on it and KMS's creation date is not it.
- **`sluis key request`** creates the key if it does not exist, reads the active primaries from the root list when the request needs them, writes the request and the proof, and prints the key's fingerprint. **`sluis key install`** runs the requester's checks of the contract and only then starts using the answer: the certificate verifies to an anchor; when it holds a root list, that list is at least as recent as the answer's `trust_sequence`; the key is its own; the subject, constraints and key usage are exactly what it asked; the validity is the length it expects and has not ended. **`sluis key status`** lists each key, its store, its expiry and its warning level.
- **Attestation is checked on both sides.** sluis checks the attestation of its own keys when it requests, and ritueel checks it again before it certifies. Both use the maker's current attestation root with the full bundle of its intermediates, because the list that `piv-go` v2.6.0 embeds lacks the intermediate that firmware 5.8 uses (measured 2026-11-01).
- **The token certificate is not part of the hand-off.** The node's intermediate issues it on the node ([0006](/decisions/0006-keys-and-sealing/#the-token-signing-key)), under the profile of [0042](/decisions/0042-leaf-certificate-profiles-lifetimes-and-revocation/#leaf-profiles).
- **The request carries the intermediate's name constraints,** built from the boundary's declared names ([0042](/decisions/0042-leaf-certificate-profiles-lifetimes-and-revocation/#the-intermediates-name-constraints)). The contract requires at least one permitted subtree, and ritueel's certifier checks each against the subtrees its policy lists for the requester. Today that policy lists URI hosts only, so ritueel does not yet check the DNS part (waiting on ritueel, tracked in [truvity/ritueel#70](https://github.com/truvity/ritueel/issues/70)).
- **An SSH CA key is not certified, it is listed.** With `ssh-ca`, `sluis key request` writes the public key as an OpenSSH line, an SSH signature by that key in the contract's namespace, and a proof whose `use` is `user` or `host`. ritueel checks where the key lives, as for every other type, and lists it on its signed SSH CA key list; a key that replaces the old one replaces its entry. How the hosts of an installation learn the CA keys is unchanged ([0023](/decisions/0023-certificate-authorities/#ssh)).

### The floor

The least that sluis needs from a root is a certificate for its request. That is the **floor** of ritueel's contract ([PKCS#10 in, X.509 out](https://ritueel.id/reference/hand-off-contract/#the-floor-pkcs10-in-x509-out)), and this record accepts it as sluis's own.

- **Any certificate authority that signs a PKCS#10 request in the profile can certify sluis.** ritueel is the custodian the project builds and tests against; nothing in sluis needs it. The floor is X.509 only: an OpenPGP subkey and an SSH CA key need the full contract.
- **Anchors come from `trust.ca_bundle` alone, and `trust.root_list` is optional.** The bundle is a file the operator placed, and sluis trusts it as a TLS client trusts the file it is given.
- **There is no rollback protection and no trust sequence on the floor.** An older bundle put back in place is accepted. A host that wants both holds a signed root list, and then the rules of the next section apply.
- **`sluis key install` says what it did not run.** On the floor it checks the issuer, its own key, the profile and the validity, and reports as not run the contract version, `request_sha256`, the digests of the result file, the `trust_sequence`, and the certifier's checks 6 to 8, which are the store, the evidence and the key match. Nobody but sluis has then checked where its key lives. A check that cannot run is never reported as passed ([principle 4](/principles/#4-verify-never-trust-a-claim)).
- **The test harness may use the floor.** The contract's test vectors have an `openssl` recipe for a throwaway root, and the vectors `x509-floor-*` fix what a requester must accept and refuse with `pinned.floor_anchors`.

### Lifetimes and the warning

- **An intermediate certificate and an OpenPGP subkey last 13 calendar months,** the length the certifier sets. In month 12 the root re-signs the same key; the new certificate overlaps the old one. When key material must change, the new key is requested like the first ([0006](/decisions/0006-keys-and-sealing/#rotation)).
- **A renewal re-signs the same key, and who does it depends on the root.** With a card root it needs a person at ritueel's side once a year, and the long warning is the protection. With a KMS root, `ritueel renew` re-signs unattended under the declared policy (`aws_kms.renewal`), which can extend trust and never create it, and the warning covers a broken scheduler. The table of what may run unattended is ritueel's ([what may run unattended](https://ritueel.id/learn/re-sign/#what-may-run-unattended)).
- **sluis warns before expiry:** a notice 60 days before, an alert 30 days before and a critical alert 14 days before. The warning is a metric, an alert rule and a line in `sluis key status` and `sluis doctor`. The lead time is long because a card renewal needs a person.
- **A stolen or lost board is a small event.** ritueel revokes the board's certificate in the root CRLs and drops its subkey from the next keyring package, and sluis stops using the key and its token certificate ([Root pins and the root list](/decisions/0024-root-custody-and-the-signing-api/#root-pins-and-the-root-list)).

### Root pins and the root list

- **sluis verifies a signed root list and never makes one, and the list is optional** ([the floor](/decisions/0024-root-custody-and-the-signing-api/#the-floor)). ritueel signs `root-list.json` as a detached JSON Web Signature in the general JSON serialisation (RFC 7515, section 7.2.1): `root-list.jws` beside it holds one signature for every signer, and the list may carry `removals`, the stored removal authorisations of roots that leave. The reader's format and its 11 checks, in order and with their codes, are ritueel's [How a host reads it](https://ritueel.id/reference/root-list/#how-a-host-reads-it); sluis implements them and passes the vectors. The local installation reads the list from the file the install file names ([`trust.root_list`](/reference/install-file/#trust)); `sluis trust sync` fetches it at parity.
- **The signing rule is ritueel's, and sluis checks exactly this:** a list with the same roots carries one active root's signature; a list that changes the root set carries, for every root of the list it replaces, its signature or its stored removal authorisation, and every root it adds signs it ([Who signs](https://ritueel.id/reference/root-list/#who-signs)).
- **The list carries the trust sequence,** one integer that grows by one whenever any trust product changes. sluis takes a list only if a root it already trusts has signed it (or one of its initial pins, before it holds a list), the rule above holds, and its sequence is not lower than the one it holds. A list at the same sequence must be byte for byte the one held, or it is refused. The same sequence is what an answer's `trust_sequence` is compared with.
- **sluis pins the public keys of roots (SPKI hashes), never certificate fingerprints.** The list pins keys, so a root whose validity is extended gets a new certificate over the same key and no pin breaks.
- **The roots' certificates come from ritueel's CA bundle,** which carries the list's sequence in its first line and is checked against the list. `signer` takes the root certificate for the `x5c` chain of the key set from it ([`trust.ca_bundle`](/reference/install-file/#trust)).
- **The trust bundle needs no signature of its own.** It is a set of certificates, and each one chains to a root in the root list; the root list is what a root signs ([0022](/decisions/0022-workload-identity-and-host-enrolment/#the-trust-bundle)).
- **A host keeps its last good list.** The list is re-signed at least once a year and lasts 13 calendar months. When it expires with no newer one, the host keeps it, goes on trusting its roots and warns; it does not drop them. A list close to expiry is a warning on sluis's side and a renewal on ritueel's.
- **An intermediate is revoked by a CRL that each root signs,** valid for 25 months, so a root that signs every second year always has a current one. No certificate carries a distribution point, and ritueel's pipeline publishes the files. sluis does not sign or replace them. A relying party that wants to check an intermediate against a root's CRL configures the file, as with a leaf CRL ([0042](/decisions/0042-leaf-certificate-profiles-lifetimes-and-revocation/#revocation)); serving the roots' CRLs with the trust bundle comes with `sluis trust sync` ([#968](https://github.com/truvity/sluis/issues/968)).
- **The limits of root security are ritueel's to state:** changing the root set requires every current root, or a root's stored removal authorisation; any one root signs the rest. sluis's threat model points to ritueel's documents. How hosts receive the bundle is [0022](/decisions/0022-workload-identity-and-host-enrolment/#the-trust-bundle).

### The signing API

sluis signs four kinds of thing, each with a key bound to its purpose: artifacts through the signing API; tokens and the key set that verifies them; X.509 leaf and SSH certificates, by `ca` and `ssh-ca` ([0023](/decisions/0023-certificate-authorities/)); and, later, OpenPGP certifications of people's keys.

- **A caller, such as a CI job, proves its identity with an OIDC token.** Policy decides which repository, branch or workflow may use which key. sluis signs in place, records the signature in the audit log and returns it. The key is never shown.
- **The first stage returns an OpenPGP detached signature;** a raw signature and a Sigstore bundle come later, each with a key of its own. The request, the response, the policy action and the audit record are [0045](/decisions/0045-the-signing-api-signs-sent-content-for-an-authorised-proof-and-returns-an-armoured-detached-signature/). The action names and audit events live in code, like every other action ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-action-table-is-code-and-the-release-identifies-it)).
- **OpenPGP artifact signing arrives in stages:**

| Stage | What sluis signs |
|---|---|
| First working version | A detached, ASCII-armoured `.asc` signature over the content it is sent |
| Parity milestone | The `Release.gpg` and `InRelease` files of an apt repository, and the `repomd.xml.asc` of an rpm repository |
| Later | The header signature of each rpm package, and a stand-in for `gpg` that git can call (`gpg.program`), for CI |

### Signed releases

- **Nothing is signed with OpenPGP before the roots exist.** Until ritueel has held the root ceremony and its drill, sluis's own releases carry checksums, SBOMs and keyless Sigstore attestations and signatures from the CI build, which need no root ([0013](/decisions/0013-release-train-packaging-and-distribution/#signing-and-checksums)).
- **From then on, releases are signed through the signing API with a release subkey held in a cloud key service (KMS), an `ECC_NIST_P384` key of its own with `SIGN_VERIFY` usage,** bound by a root primary in the release keyring. CI reaches the signing API with its OIDC token, so a release needs no card work. The project's releases are the API's first user. Channels and packaging are [0013](/decisions/0013-release-train-packaging-and-distribution/#signing-and-checksums).

### Company OpenPGP certification

Later, not in the first working version. OpenPGP has no intermediates as X.509 does, but it can delegate: at a ritueel ceremony the company root makes a trust signature, limited to a domain, over a sluis certification key. That key then certifies online the OpenPGP keys of people whom sluis has authenticated against the directory, for their verified addresses in that domain, each with an expiry, and stops when the person leaves. The root stays offline.

## Consequences

- sluis gets smaller and easier to test. Its tests need a card or a key service and a root, which the test harness makes with a plain CA tool or, when it exists, with ritueel's software-root mode; none needs a root ceremony.
- The contract is an interface between two products: a change needs a version and a compatibility rule on both sides. The floor is the part that needs no ritueel: a CA tool and a PKCS#10 request.
- A renewal over a card root needs a person on ritueel's side once a year, and the long warning is sluis's only protection: if no one renews by month 13, certificates expire and `ca` stops issuing. A KMS root renews unattended under ritueel's declared policy, and then `ca` stops only if the scheduler is broken for a month and nobody read the alerts.
- The revocation of a stolen board crosses the line between the products, and the time from theft to verifiers refusing it belongs to neither alone; the runbook names both parts.
- The attestation check and the OpenPGP packet code exist on both sides, so the two share a test matrix: `gpg`, `gpgv`, `sqv`, apt and rpm.
- Early releases are verifiable by checksum only, not by signature.
- The root-custody requirements moved to ritueel; sluis keeps requirements for the hand-off, the back-signature, expiry warnings, the root list, exclusive card access, keys born in place and the signing API.

## Roads not taken

- **Keep root ceremonies in sluis.** Root custody would sit next to the busiest code, and a user who only needs roots would have to adopt a signing system; the product boundary enforces the cleanest boundary in the model.
- **A development root inside sluis.** A plain CA tool already makes a throwaway root for a test, and ritueel's software-root mode is the other source; a root that exists in sluis can ship by mistake.
- **Always require a signed root list.** One mode, and rollback protection everywhere, but ritueel's format becomes a requirement on every CA, which is what the floor set out to remove. The floor path states what it lacks instead.
- **A shared library with ritueel.** It would tie two release trains together and make neither replaceable; a written profile with test vectors costs only a specification.
- **Pin the certificate of a root.** Every extension of a root's validity would break pinned hosts, and a pin alone gives no rollback protection.
- **Use `gpg` on the board for the back-signature.** `gpg` cannot bind an existing P-384 key as a signing subkey (tested 2026-10-31 with 2.2.27 and 2.4.7), and it sent wrong PINs to a test card.
- **A Sigstore bundle in the first version.** More to build before the first user, and apt and rpm do not read it.
- **Sign releases before the roots exist, with a provisional key.** A signature that a later root does not vouch for teaches users to trust a key that is then thrown away.
- **A trust log of sluis's own, appended by `sluis key install`.** The root list and the ceremony records that vouch for an intermediate are ritueel's, an installed certificate is an issued record of the installing actor and an audit event, and the certificates `ca` issues are in its issuance log ([0023](/decisions/0023-certificate-authorities/#issuance-log-and-revocation)); a fourth log would hold nothing the others do not.
- **Online OpenPGP certification in the first version, or never.** It needs strict policy and expiry rules before it exists, and never would leave company-wide keys manual with no follow of joiners and leavers.

## Follow-ups

- The signing API's later stages: [#1074](https://github.com/truvity/sluis/issues/1074), [#1075](https://github.com/truvity/sluis/issues/1075).
- SSH CA key requests and the signed list of SSH CA keys on hosts: [#1072](https://github.com/truvity/sluis/issues/1072).
- The roots' CRLs served with the trust bundle, and the root list fetched by `sluis trust sync`: [#968](https://github.com/truvity/sluis/issues/968).
- DNS name constraints in ritueel's policy, so that ritueel also checks the DNS part of an intermediate's constraints, a ritueel change that the harness waits for: [truvity/ritueel#70](https://github.com/truvity/ritueel/issues/70).
