# 0024 — sluis holds no root: it asks root custody to certify its intermediates, and signs artifacts through a signing API

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #1001](https://github.com/truvity/sluis/issues/1001).

## Context

A chain of trust has a few keys that almost never change, the roots, and many that work every day. A root is used rarely, by a person who is present, and a mistake with it is slow and expensive to repair. The intermediates sign certificates, tokens and artifacts all the time and must be online and automated. Putting both in one product puts the rarest and most valuable keys beside the busiest code.

On 2026-11-01 the maintainer split them. A separate product, [ritueel](https://ritueel.id), owns the roots, the ceremonies that certify an intermediate, and every transition of a root between key stores. sluis owns the intermediates and everything that signs with them. The two share no code and have no code or runtime dependency on each other; they exchange standard formats through a written contract. This record is sluis's side of that contract: what it hands over, what it installs, how it warns, what it verifies and what it signs. How its keys are born and used is [0006](/decisions/0006-keys-and-sealing/).

Signing artifacts for a caller on the internet adds three facts about the formats:

- **An OpenPGP signature cannot be made from a digest alone.** The signature hashes the data, then its own version, type, algorithm and hashed subpackets, then a trailer (RFC 9580, section 5.2.4). The signer has to see the data. A release signs the checksum file, which is small; the large files are covered by the checksums in it.
- **A key signs only what it is for.** A second signature format under the same key would let a chosen input for one format pass as a signature in the other, which is why signing keys are never shared across purposes ([principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule)).
- **`signer` must not be a signing oracle for whoever reaches it** ([0002](/decisions/0002-families-of-actors/#work-actors)). The caller is a CI job on the internet's side of `entry`, so the decision to sign has to come from `policy` and reach `signer` in a form that only `policy` can make.

## Decision

### sluis holds no root

- **sluis holds intermediates and the keys that sign with them, never a root.** It does not create, keep, rotate or revoke a root.
- **sluis never generates a root.** Its intermediates are certified by any certificate authority that signs a PKCS#10 request and issues the profile of ritueel's hand-off contract ([the floor](https://ritueel.id/reference/hand-off-contract/#the-floor-pkcs10-in-x509-out)). The test harness uses a throwaway root from a plain CA tool, and ritueel's software-root mode when it exists.
- **The key commands are `sluis key request`, `sluis key install` and `sluis key status`.** There is no ceremony command in sluis.
- **The profile of an intermediate** (path length, name and URI constraints, extended key usage) and its test vectors are written once, in ritueel's [hand-off contract](https://ritueel.id/reference/hand-off-contract/). Each side tests against them; no code is shared.

### The hand-off

sluis hands ritueel a request and installs what comes back. The specification is ritueel's [hand-off contract, version 1](https://ritueel.id/reference/hand-off-contract/); it owns the files, the members, the profiles, the reason codes and the test vectors, and this record does not copy them. sluis writes exactly what the contract defines, refuses a version it does not know and a member it does not define, and passes the contract's vectors, the floor vectors included ([#1070](https://github.com/truvity/sluis/issues/1070)).

- **There are three request types:** an X.509 intermediate, an OpenPGP signing subkey and an SSH CA key. The first working version requests the first, and the second with the signing API; the third comes with `ssh-ca` ([#1072](https://github.com/truvity/sluis/issues/1072)).
- **An X.509 answer is one certificate and, with the full contract, a result file.** The root is never in the answer. `sluis key install` takes its anchors from the CA bundle of `TrustAnchors`, the config kind that holds the root list, the CA bundle and the SSH CA key list; when sluis also holds a root list, a certificate of the bundle is an anchor only if its key is on that list. The result file only names which anchor issued the certificate.
- **An OpenPGP request holds the subkey and one back-signature for every active primary** on the signed root list that sluis holds, and its proof names those primaries. Either root card can then make the binding, with no second request. A root list that is not current gives the contract's `unknown-primary`, and the fix is a newer list, not a new key.
- **key@ makes the back-signatures on the board.** The subkey stays in a PIV slot and the card signs the digest of each primary-key binding. The keys are version 4, ECDSA on P-384, and every signature uses SHA-384. Each back-signature carries the Issuer Fingerprint in its hashed area and the Issuer Key ID in its unhashed area; `gpg` 2.2 refuses a certificate whose signatures lack the key ID. sluis builds the OpenPGP packets itself and does not use `gpg` on a board. Tested 2026-10-31 with a throwaway primary: `gpg`, `gpgv` and `sqv` accept the subkey with the back-signature and refuse it without.
- **The proof names the store by the contract's words:** `piv` for a key in a PIV slot, which is the `yubikey-piv` driver of key@; `aws-kms`; and `software`. A node never uses the `openpgp-card` store, because the OpenPGP applet is not used on a node ([0006](/decisions/0006-keys-and-sealing/#the-slot-plan)).
- **A KMS proof names the key by its full ARN.** The certifier reads the key itself and trusts no copy. ritueel's roots live in an account of their own, so a sluis key is in another account: sluis creates a read-only role in the key's account that allows `DescribeKey`, `GetPublicKey` and `GetKeyPolicy` on that key and nothing else, and trusts the certifier's principal to assume it. The certifier refuses a key whose policy lets more than one principal `kms:Sign`, which is the rule [0006](/decisions/0006-keys-and-sealing/#key-purposes) already sets for every signing key. An OpenPGP subkey in KMS needs its creation time kept, for example as a tag, because the fingerprint depends on it and KMS's creation date is not it.
- **`sluis key request`** creates the key if it does not exist, reads the active primaries from the root list when the request needs them, writes the request and the proof, and prints the key's fingerprint. **`sluis key install`** runs the requester's checks of the contract and only then starts using the answer: the certificate verifies to an anchor; when it holds a root list, that list is at least as recent as the answer's `trust_sequence`; the key is its own; the subject, constraints and key usage are exactly what it asked; the validity is the length it expects and has not ended. It hands the verified chain to key@, which stores it as the kind `KeyCertificate` ([0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place)). **`sluis key status`** lists each key, its store, its expiry and its warning level.
- **Attestation is checked on both sides.** sluis checks the attestation of its own keys when it requests, and ritueel checks it again before it certifies. Both use the maker's current attestation root with the full bundle of its intermediates, because the list that `piv-go` v2.6.0 embeds lacks the intermediate that firmware 5.8 uses (measured 2026-11-01).
- **The token certificate is not part of the hand-off.** The node's intermediate issues it on the node ([0006](/decisions/0006-keys-and-sealing/#the-token-signing-key)), under the profile of [0023](/decisions/0023-certificate-authorities/#leaf-profiles).
- **The request carries the intermediate's name constraints,** built from the boundary's declared names ([0023](/decisions/0023-certificate-authorities/#the-intermediates-name-constraints)). The contract requires at least one permitted subtree, and ritueel's certifier checks each against the subtrees its policy lists for the requester. Today that policy lists URI hosts only, so ritueel does not yet check the DNS part (waiting on ritueel, tracked in [truvity/ritueel#70](https://github.com/truvity/ritueel/issues/70)).
- **An SSH CA key is not certified, it is listed.** With `ssh-ca`, `sluis key request` writes the public key as an OpenSSH line, an SSH signature by that key in the contract's namespace, and a proof whose `use` is `user` or `host`. ritueel checks where the key lives, as for every other type, and lists it on its signed SSH CA key list; a key that replaces the old one replaces its entry. How the hosts of an installation learn the CA keys is unchanged ([0023](/decisions/0023-certificate-authorities/#ssh)).

### The floor

The least that sluis needs from a root is a certificate for its request. That is the **floor** of ritueel's contract ([PKCS#10 in, X.509 out](https://ritueel.id/reference/hand-off-contract/#the-floor-pkcs10-in-x509-out)), and this record accepts it as sluis's own.

- **Any certificate authority that signs a PKCS#10 request in the profile can certify sluis.** ritueel is the custodian the project builds and tests against; nothing in sluis needs it. The floor is X.509 only: an OpenPGP subkey and an SSH CA key need the full contract.
- **Anchors come from the CA bundle of `TrustAnchors` alone, and the root list is optional.** The bundle is a document the operator committed, and sluis trusts it as a TLS client trusts the file it is given.
- **There is no rollback protection and no trust sequence on the floor.** An older bundle put back in place is accepted. A host that wants both holds a signed root list, and then the rules of the next section apply.
- **`sluis key install` says what it did not run.** On the floor it checks the issuer, its own key, the profile and the validity, and reports as not run the contract version, `request_sha256`, the digests of the result file, the `trust_sequence`, and the certifier's checks 6 to 8, which are the store, the evidence and the key match. Nobody but sluis has then checked where its key lives. A check that cannot run is never reported as passed ([principle 4](/principles/#4-verify-never-trust-a-claim)).
- **The test harness may use the floor.** The contract's test vectors have an `openssl` recipe for a throwaway root, and the vectors `x509-floor-*` fix what a requester must accept and refuse with `pinned.floor_anchors`.

### Lifetimes and the warning

- **An intermediate certificate and an OpenPGP subkey last 13 calendar months,** the length the certifier sets. In month 12 the root re-signs the same key; the new certificate overlaps the old one. When key material must change, the new key is requested like the first ([0006](/decisions/0006-keys-and-sealing/#rotation)).
- **A renewal re-signs the same key, and who does it depends on the root.** With a card root it needs a person at ritueel's side once a year, and the long warning is the protection. With a KMS root, `ritueel renew` re-signs unattended under the declared policy (`aws_kms.renewal`), which can extend trust and never create it, and the warning covers a broken scheduler. The table of what may run unattended is ritueel's ([what may run unattended](https://ritueel.id/learn/re-sign/#what-may-run-unattended)).
- **sluis warns before expiry:** a notice 60 days before, an alert 30 days before and a critical alert 14 days before. The warning is a metric, an alert rule and a line in `sluis key status` and `sluis doctor`. The lead time is long because a card renewal needs a person.
- **A stolen or lost board is a small event.** ritueel revokes the board's certificate in the root CRLs and drops its subkey from the next keyring package, and sluis stops using the key and its token certificate ([Root pins and the root list](/decisions/0024-root-custody-and-the-signing-api/#root-pins-and-the-root-list)).

### Root pins and the root list

- **sluis verifies a signed root list and never makes one, and the list is optional** ([the floor](/decisions/0024-root-custody-and-the-signing-api/#the-floor)). ritueel signs `root-list.json` as a detached JSON Web Signature in the general JSON serialisation (RFC 7515, section 7.2.1): `root-list.jws` beside it holds one signature for every signer, and the list may carry `removals`, the stored removal authorisations of roots that leave. The reader's format and its 11 checks, in order and with their codes, are ritueel's [How a host reads it](https://ritueel.id/reference/root-list/#how-a-host-reads-it); sluis implements them and passes the vectors. The list is a part of `TrustAnchors`, so store@ loads it with the rest of the config, and `sluis trust sync` fetches it at parity.
- **The signing rule is ritueel's, and sluis checks exactly this:** a list with the same roots carries one active root's signature; a list that changes the root set carries, for every root of the list it replaces, its signature or its stored removal authorisation, and every root it adds signs it ([Who signs](https://ritueel.id/reference/root-list/#who-signs)).
- **The list carries the trust sequence,** one integer that grows by one whenever any trust product changes. sluis takes a list only if a root it already trusts has signed it (or one of its initial pins, before it holds a list), the rule above holds, and its sequence is not lower than the one it holds. A list at the same sequence must be byte for byte the one held, or it is refused. The same sequence is what an answer's `trust_sequence` is compared with.
- **sluis pins the public keys of roots (SPKI hashes), never certificate fingerprints.** The list pins keys, so a root whose validity is extended gets a new certificate over the same key and no pin breaks.
- **The roots' certificates come from ritueel's CA bundle,** which carries the list's sequence in its first line and is checked against the list. `signer` takes the root certificate for the `x5c` chain of the key set from it.
- **The trust bundle needs no signature of its own.** It is a set of certificates, and each one chains to a root in the root list; the root list is what a root signs ([0022](/decisions/0022-workload-identity-and-host-enrolment/#the-trust-bundle)).
- **A host keeps its last good list.** The list is re-signed at least once a year and lasts 13 calendar months. When it expires with no newer one, the host keeps it, goes on trusting its roots and warns; it does not drop them. A list close to expiry is a warning on sluis's side and a renewal on ritueel's.
- **An intermediate is revoked by a CRL that each root signs,** valid for 25 months, so a root that signs every second year always has a current one. No certificate carries a distribution point, and ritueel's pipeline publishes the files. sluis does not sign or replace them. A relying party that wants to check an intermediate against a root's CRL configures the file, as with a leaf CRL ([0023](/decisions/0023-certificate-authorities/#revocation)); serving the roots' CRLs with the trust bundle comes with `sluis trust sync` ([#968](https://github.com/truvity/sluis/issues/968)).
- **The limits of root security are ritueel's to state:** changing the root set requires every current root, or a root's stored removal authorisation; any one root signs the rest. sluis's threat model points to ritueel's documents. How hosts receive the bundle is [0022](/decisions/0022-workload-identity-and-host-enrolment/#the-trust-bundle).

### The signing API

sluis signs four kinds of thing, each with a key bound to its purpose: artifacts through the signing API; tokens and the key set that verifies them; X.509 leaf and SSH certificates, by `ca` and `ssh-ca` ([0023](/decisions/0023-certificate-authorities/)); and, later, OpenPGP certifications of people's keys.

- **A caller, such as a CI job, proves its identity with an OIDC token.** Policy decides which repository, branch or workflow may use which key. sluis signs in place, records the signature in the audit log and returns it. The key is never shown.
- **The first stage returns an OpenPGP detached signature;** a raw signature and a Sigstore bundle come later, each with a key of its own. The action names and audit events live in code, like every other action ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-action-table-is-code-and-the-release-identifies-it)).
- **OpenPGP artifact signing arrives in stages:**

| Stage | What sluis signs |
|---|---|
| First working version | A detached, ASCII-armoured `.asc` signature over the content it is sent |
| Parity milestone | The `Release.gpg` and `InRelease` files of an apt repository, and the `repomd.xml.asc` of an rpm repository |
| Later | The header signature of each rpm package, and a stand-in for `gpg` that git can call (`gpg.program`), for CI |

#### Who does what

- **The signing API is a public Connect service of `exchange`,** reached through `entry`. `exchange` already verifies proofs (the `github-oidc` verifier driver is in the first working version, [0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)), asks `policy`, and calls `signer`; no new edge is needed.
- **The release-signing key belongs to `signer`,** the actor that signs, as a purpose of its own beside the token-signing key ([0006](/decisions/0006-keys-and-sealing/#key-purposes)). The two keys are never shared and have one user actor each. key@ holds the key and signs in place.
- **The flow is four steps:**
  1. The caller sends the content with its proof, a GitHub Actions identity token, in the `Authorization` header.
  2. `exchange` verifies the proof and asks `policy` to decide the action `artifact.sign` on the resource `SigningKey` `release-signing`, with the verified attributes of the job (repository, ref, workflow, environment) and the digest and length of the content as context.
  3. `policy` has key@ seal a **signing grant**: the decision, the policy digest, the key purpose, the SHA-384 of the content, the caller, and an expiry 60 seconds ahead ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)).
  4. `exchange` passes the grant and the content to `signer`. `signer` opens the grant at key@, refuses unless the key purpose, the content hash and the expiry match, writes the hash of the grant as a `SpentGrant`, builds the signature and has key@ sign it in place.
- **One grant signs once.** The `SpentGrant` is the marker of 0007 for a one-shot action: a second use of the same grant finds it and is refused. A repeat of the same request id within 24 hours returns the first outcome and needs no new grant.

#### The request and the response

```proto
service SigningService {
  rpc SignDetached(SignDetachedRequest) returns (SignDetachedResponse);
}

message SignDetachedRequest {
  string request_id = 1; // the caller's idempotency key
  bytes content = 2;     // 1 byte to 4 MiB
}

message SignDetachedResponse {
  string armored_signature = 1; // the .asc text
  string key_fingerprint = 2;   // the signing subkey, 40 upper-case hex characters
  string audit_id = 3;          // the id of the audit record of this signature
}
```

- **The caller names no key.** An installation has one release-signing key, in its release boundary only ([0006](/decisions/0006-keys-and-sealing/#key-purposes)), and the request is for that key. A second signing key adds a field, which is a compatible change ([Contracts and errors](/reference/contracts/#versions)).
- **The caller sends the content, not a digest,** up to 4 MiB, the limit of a Connect message. The signed files of apt and rpm repositories and a release's checksum file are far below it. An empty or larger body is `invalid_argument`.
- **The request id follows the rule for public methods:** a repeat within 24 hours returns the first outcome, signature included, and a reused id with other content is `failed_precondition` ([Every call](/reference/contracts/#every-call)).

#### The signature

- **It is an OpenPGP version 4 signature of type `0x00` (binary document),** with the public-key algorithm ECDSA (19) on P-384, the hash SHA-384 (10), made by the release subkey.
- **The hashed subpackets are the signature creation time and the issuer fingerprint (subpacket 33);** the one unhashed subpacket is the issuer key id (16). No other subpacket is written, and the signature does not expire. This is the packet rule of ritueel's ADR 0006, which its tools check.
- **The output is armoured** as RFC 9580, section 6 says, with the checksum line so that older readers accept it, and with no `Version` or `Comment` header. The creation time is `signer`'s clock, in UTC seconds.
- **The subkey signs; the primary does not.** The signature verifies against the release keyring that ritueel's tools build, which carries the primaries and every current subkey binding ([Release signing](/distribution/release-signing/#the-openpgp-release-key)).
- **`signer` builds the packets itself,** and key@ signs the signature input (the content, then the hashed fields and the trailer). key@ parses that structure before it signs, as it does for a certificate body ([0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place)).

#### When the API refuses to sign

- **The key's binding must be installed and unexpired.** `signer` signs only while the kind `OpenPgpBinding` holds the primary's certification of the subkey and the binding has not expired. Otherwise the answer is `failed_precondition`. In a development installation the binding is made by ritueel's software-root mode, so its signatures are for tests only (see [sluis holds no root](/decisions/0024-root-custody-and-the-signing-api/#sluis-holds-no-root)).
- **A caller without a valid proof is `unauthenticated`;** one that `policy` does not permit is `permission_denied`, with the uniform refusal of the edge ([Uniform refusals at the edge](/reference/contracts/#uniform-refusals-at-the-edge)). A repository, ref or workflow outside the policy looks the same as one that does not exist.
- **Every signature is audited,** as a key use: OCSF class 6003 API Activity, activity 99 "Sign", the key in `resources[]`, the caller as the acting party and the policy decision in the `security_control` profile ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-class-mapping)). `unmapped.sluis` carries the SHA-384 and the length of the content, never the content. The record is written before the response, and a signature whose record could not be written is not returned.

#### The first stage and the next

- **The first working version has this one method, `SignDetached`,** for a GitHub Actions proof. The parity stage adds the signing of `Release.gpg`, `InRelease` and `repomd.xml.asc` as uses of the same method ([#1074](https://github.com/truvity/sluis/issues/1074)); later stages are the rpm package header and a stand-in for `gpg` that git can call ([#1075](https://github.com/truvity/sluis/issues/1075)).
- **A raw ECDSA signature is not in this stage.** It would be made by a key of its own, because the same key under two formats is the cross-use that principle 3 rules out, and nothing in the first working version consumes one ([#1117](https://github.com/truvity/sluis/issues/1117)). A Sigstore bundle follows the same rule.

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
- A flaw in the parser of `entry` or in `exchange` can ask `signer` only for a signature that `policy` sealed for exactly that content, within a minute, and only once. To sign something else an attacker needs `policy` to agree, as for a credential.
- The policy sees the job's repository, ref and workflow, which is what a release key needs: "this workflow, on this ref, may sign" is a Cedar permit, not code.
- The cost of the signing API is a second key purpose behind `signer`, a slot on a node card ([0006](/decisions/0006-keys-and-sealing/#the-slot-plan)) and a key rule that lets `signer` open grants. A caller that must sign a large file signs its checksum file, which is how the packaging tools work already.
- The root-custody requirements moved to ritueel; sluis keeps requirements for the hand-off, the back-signature, expiry warnings, the root list, exclusive card access, keys born in place and the signing API: REQ-SUPPLY-016 for content, and [REQ-SUPPLY-019](/requirements/supply/#REQ-SUPPLY-019) to [REQ-SUPPLY-024](/requirements/supply/#REQ-SUPPLY-024).

## Roads not taken

- **Keep root ceremonies in sluis.** Root custody would sit next to the busiest code, and a user who only needs roots would have to adopt a signing system; the product boundary enforces the cleanest boundary in the model.
- **A development root inside sluis.** A plain CA tool already makes a throwaway root for a test, and ritueel's software-root mode is the other source; a root that exists in sluis can ship by mistake.
- **Always require a signed root list.** One mode, and rollback protection everywhere, but ritueel's format becomes a requirement on every CA, which is what the floor set out to remove. The floor path states what it lacks instead.
- **A shared library with ritueel.** It would tie two release trains together and make neither replaceable; a written profile with test vectors costs only a specification.
- **Pin the certificate of a root.** Every extension of a root's validity would break pinned hosts, and a pin alone gives no rollback protection.
- **Use `gpg` on the board for the back-signature.** `gpg` cannot bind an existing P-384 key as a signing subkey (tested 2026-10-31 with 2.2.27 and 2.4.7), and it sent wrong PINs to a test card.
- **A Sigstore bundle in the first version.** More to build before the first user, and apt and rpm do not read it.
- **Sign releases before the roots exist, with a provisional key.** A signature that a later root does not vouch for teaches users to trust a key that is then thrown away.
- **A trust log of sluis's own, appended by `sluis key install`.** The root list and the ceremony records that vouch for an intermediate are ritueel's, an installed certificate is a `KeyCertificate` and an audit event, and the certificates `ca` issues are in its issuance log ([0023](/decisions/0023-certificate-authorities/#issuance-log-and-revocation)); a fourth log would hold nothing the others do not.
- **Online OpenPGP certification in the first version, or never.** It needs strict policy and expiry rules before it exists, and never would leave company-wide keys manual with no follow of joiners and leavers.
- **A signing request that carries a digest.** It cannot produce an OpenPGP signature, because the signature hashes its own trailer after the data.
- **A `key` field naming the purpose.** With one signing key it carries nothing, and a field a caller can set invites a request for a key it should not name.
- **The signing API on `signer`.** `signer` would parse a caller's request and need an edge to `policy`; serving it from `exchange` reuses the edges that exist and keeps `signer` free of internet parsing.
- **A decision that `signer` takes itself.** It would make the actor that asks for the signature also the one that decides.
- **A signature without a grant.** It would rest on the word of `exchange` alone: a flaw in `exchange` could sign anything with the release key.
- **A raw signature from the OpenPGP subkey.** Two formats under one key allow one to be passed off as the other.
- **A token exchanged first, then a second call.** It adds a step and drops the job's attributes from the second decision; the first decision is the one with the facts.
- **A signature that does not wait for its audit record.** A signing service is found out by its records, so a signature without one is the failure to avoid.

## Follow-ups

- The signing API's later stages: [#1074](https://github.com/truvity/sluis/issues/1074), [#1075](https://github.com/truvity/sluis/issues/1075); release use and CI credentials: [#874](https://github.com/truvity/sluis/issues/874).
- A raw signature and a Sigstore bundle, each with a key of its own: [#1117](https://github.com/truvity/sluis/issues/1117).
- SSH CA key requests and the signed list of SSH CA keys on hosts: [#1072](https://github.com/truvity/sluis/issues/1072).
- The roots' CRLs served with the trust bundle, and the root list fetched by `sluis trust sync`: [#968](https://github.com/truvity/sluis/issues/968).
- DNS name constraints in ritueel's policy, so that ritueel also checks the DNS part of an intermediate's constraints, a ritueel change that the harness waits for: [truvity/ritueel#70](https://github.com/truvity/ritueel/issues/70).
