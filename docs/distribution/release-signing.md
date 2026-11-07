---
title: Release signing
description: What a sluis release carries (checksums and SBOMs), and the design for signing it, which is in Backlog: verification, the OpenPGP release key, CI uploads.
status: target
sidebar:
  order: 1
---

**No release artifact is signed in the first working version or in v1 parity** (the maintainer decided on 2026-11-07, [0013](/decisions/0013-release-train-packaging-and-distribution/#signing-and-checksums)). A release carries checksums and SBOMs, and the maintainer signs each tag by hand. The signing of release artifacts, keyless or OpenPGP, is in Backlog with the staff key and GPG work ([Roadmap](/roadmap/#later)). The rest of this page is the design for when it returns, and a row marked Backlog is made by no release yet.

The design: releases carry GitHub build-provenance attestations and keyless cosign signatures on images, made by the CI build with no stored key. Nothing is signed with a sluis key or with OpenPGP until [ritueel](https://ritueel.id) has held the root ceremony and its drill, because a signature that a later root does not vouch for teaches users to trust a key that is then thrown away. From then on, releases are signed through sluis's own signing API with a release subkey held in a cloud key service: detached signatures first, then signed apt and dnf metadata ([0024](/decisions/0024-root-custody-and-the-signing-api/#signed-releases)).

## What a release carries

| From | What | Verified with |
|---|---|---|
| The first release | A `.sha256` per file and a `SHA256SUMS` for the release | `sha256sum`, against the copy on GitHub Releases |
| Backlog | GitHub build provenance attestations for every artifact and image digest, and SBOM attestations bound to them | `gh attestation verify` |
| The first release | An SPDX JSON SBOM per archive and per image, made by syft | Any SPDX reader |
| Backlog | A keyless cosign signature on each image digest | `cosign verify` |
| The first release | A git tag for the release, signed with the maintainer's own OpenPGP key until the signing API signs tags | `git verify-tag` |
| Backlog, once the roots exist | `SHA256SUMS.asc`, a detached ASCII-armoured OpenPGP signature over `SHA256SUMS` | `gpgv` or `sqv` with the release keyring |
| Backlog | Signed apt metadata (`InRelease`, `Release.gpg`) and dnf metadata (`repomd.xml.asc`) ([#1074](https://github.com/truvity/sluis/issues/1074)) | apt with `signed-by`, dnf with `repo_gpgcheck=1` |
| Later | A header signature on each rpm package | dnf with `gpgcheck=1` |
| Later | The release tag signed by the release subkey, through a stand-in for `gpg` that git calls ([#1075](https://github.com/truvity/sluis/issues/1075)) | `git verify-tag` with the release keyring |

R2 serves the files and GitHub Releases is the immutable record; when they differ, the release is right. A provenance attestation says which workflow built a file. It is GitHub's statement, not a signature by a sluis key.

Sigstore says how a file was built, not who vouches for it: its trust rests on GitHub's OIDC identity and the public Sigstore instance, so it does not replace the OpenPGP release key ([0013](/decisions/0013-release-train-packaging-and-distribution/#signing-and-checksums)). GHCR has no OCI referrers API, so the attestations and signatures of an image are found through the fallback tag `sha256-<digest>`; a registry mirror must copy those tags too.

## How to verify

### A single file

```sh
# Example
sha256sum -c sluis_linux_arm64.tar.gz.sha256
```

This catches a damaged download. It doesn't prove who made the file, because the `.sha256` comes from the same place.

### A release, before it is signed

Take `SHA256SUMS` from the GitHub release and check each file against it:

```sh
# Example
gh release download v2.0.0 --repo truvity/sluis --pattern SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

This catches a damaged or swapped download when the list comes from the immutable GitHub release. Checking the build provenance with `gh attestation verify` is Backlog: no release carries an attestation yet.

### A release, once it is signed

```sh
# Example
gpgv --keyring ./sluis-release-keyring.gpg SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

There is one signature file, and it verifies against the keyring.

### apt and dnf packages

When signed repository metadata exists (Backlog), the package manager verifies the repository for you ([Packages](/distribution/packages/)).

- **apt** verifies `InRelease` (or `Release` with `Release.gpg`) against the keyring named by `signed-by`. A `NO_PUBKEY` or `BADSIG` error means the keyring or the metadata is not the one you set up.
- **dnf** verifies the metadata with `repo_gpgcheck=1`, and the metadata carries each package's checksum.

Refresh the keyring package when a repository starts failing after a subkey's expiry date.

### Images and charts

Use the digest, not a tag. Checking the provenance of an image with `gh attestation verify oci://ghcr.io/truvity/sluis/actor-entry@sha256:<digest> --repo truvity/sluis` is Backlog, like the rest of the signing.

A Helm chart pins its images by digest, so verifying the chart and installing it gives the images released with it.

## How a release is verified

This is the rule for when release provenance exists (Backlog); until then a verifier checks the checksums and the tag that the maintainer signed. A verifier that accepts a sluis release requires both of these, and either one alone is not enough ([0042](/decisions/0042-sluis-syncs-company-issued-openpgp-keys-to-staff-github-accounts/)):

1. **The signed release tag.** `git verify-tag` passes against the signer's key. A tag says who vouches for the release.
2. **The build provenance that names the tag's commit.** `gh attestation verify` passes for the artifact, and the commit it names is the commit the tag points to (`git rev-parse <tag>^{commit}`). The provenance says which workflow built the file from that commit.

| What is checked | What it closes | What it leaves open on its own |
|---|---|---|
| The signed tag | A tag made by someone who is not the signer | A build of a different commit under the tag's name |
| The provenance that names the tag's commit | A file built by another workflow or from another commit | Who vouches for the commit: a build of an unsigned commit has valid provenance |

- **Tags are signed by the release subkey once the signing API signs them.** That is the stand-in for `gpg` that git calls, the later stage of [0024](/decisions/0024-root-custody-and-the-signing-api/#the-signing-api) ([#1075](https://github.com/truvity/sluis/issues/1075)). Until it exists, the maintainer signs the tag with their own key, so the tag does not yet carry the trust of the release subkey. That is why the provenance is required beside it, and why a tag signed with the maintainer's key is replaced by one signed by the subkey when the gate exists.
- **The signature of the tag and the signature of the files are different.** The tag covers the commit. The files are covered by `SHA256SUMS` and its signature once the roots exist ([A release, once it is signed](#a-release-once-it-is-signed)).
- **A pull request cannot make either.** The signing API refuses to sign for a workload that comes from a pull request, and a workflow lint refuses `id-token: write` in any job that a pull-request trigger reaches, also through `workflow_call` ([REQ-SUPPLY-044](/requirements/supply/#REQ-SUPPLY-044)).

:::note[Proposed]
The exact command that compares the commit in the attestation with the tag's commit is written with the verification script ([#874](https://github.com/truvity/sluis/issues/874)); the rule above holds without it.
:::

## The OpenPGP release key

The OpenPGP key is a dedicated sluis release identity, not anyone's personal key.

- **The primaries are ritueel's.** There are two primary keys, one on each root card, used only at ritueel's yearly ceremony. They are redundancy, not two-person control. How they are made and kept is taught at [ritueel.id](https://ritueel.id/concepts/openpgp-release-keys/); sluis holds no primary and runs no ceremony.
- **A release subkey does the work.** For sluis's own releases it is an `ECC_NIST_P384` key of its own in a cloud key service (the release-signing purpose of key@, enabled in the release boundary only, [0006](/decisions/0006-keys-and-sealing/#key-purposes)), bound by a root primary, and CI reaches it through the signing API, so a release needs no card work. It lasts about 13 months; each year a new binding over the same subkey extends its expiry, and sluis warns 60, 30 and 14 days before. The subkey is held in a cloud key service, so it changes on an event, by the rule of [principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule) ([0006](/decisions/0006-keys-and-sealing/#rotation)).
- **Users verify with the keyring package,** which carries both primaries and every current subkey binding. A verifier that holds only one primary cannot check a subkey that the other bound. The keyring package is built with ritueel's tools and published in sluis's own apt and dnf repositories.
- **A subkey is revoked by the primary of the year.** A revoked subkey is dropped from the next keyring package, and its revocation signature is still published.
- **Finding the key.** The primaries' fingerprints are published on the project site and in the repository's `SECURITY.md`; compare them on both before you trust a keyring. Further channels (keys.openpgp.org, a Web Key Directory, DNS `OPENPGPKEY` records) and the verification tools to document are ritueel's research: [truvity/ritueel#28](https://github.com/truvity/ritueel/issues/28).

### How releases are signed

This is the design for when signing returns (Backlog). The signing API is v1 parity, but no release is signed through it until then. sluis signs as a service. CI proves its GitHub OIDC identity to the signing API, `policy` decides which repository, branch or workflow may use which key and seals a grant for it, sluis signs in place through key@ and records the signature in the audit log, and the key is never shown. CI holds no release signing key of its own. The project's releases are the API's first user; its contract is [0024](/decisions/0024-root-custody-and-the-signing-api/#the-signing-api), and the release work is [#874](https://github.com/truvity/sluis/issues/874). A file too large to send is covered by its checksum, and the checksum file is what is signed.

### What verifiers need

Measured on 2026-10-29 and 2026-10-31 with `gpg` and `gpgv` 2.2.27 to 2.4.8, `sqv` 1.1.0 to 1.5.0, apt 2.4 to 3.0 and rpm 6.0 (rpm-sequoia): every verifier accepts ECDSA P-384 signatures on version 4 keys.

- **`gpgv` needs a binary keyring.** It cannot read an armoured file. apt takes either a binary `.gpg` or an armoured `.asc` in `Signed-By`.
- **rpm imports armoured keys only.**
- **apt's `Release.gpg` must be armoured.** A binary detached signature fails with `NODATA` (apt 2.4, checked again on 2026-10-31).

## How CI uploads

CI has no static upload key and no release signing key.

1. The release workflow gets a GitHub OIDC token.
2. It exchanges that token with sluis.
3. sluis mints a short-lived Cloudflare R2 token scoped to the distribution bucket.
4. CI uploads the files with that token, and the token expires.

Only the workflow identity that the policy names can obtain the token, so a fork or a pull request can't publish.

## What a check does not prove

- A checksum taken from the same place as the file proves only that the download is whole. Take `SHA256SUMS` from the GitHub release, a second place.
- A signed tag alone does not show that the files come from its commit, and provenance alone does not show who vouches for that commit. Check both ([How a release is verified](#how-a-release-is-verified)).
- A signature shows who published the file and that it wasn't changed. It doesn't show that the code is free of bugs.
- The release subkey signs without a person present. If the signing API is compromised during the subkey's validity, a bad file can be signed. The primaries limit that to the subkey's life, and revoking the subkey ends it. The provenance attestation and the immutable release are independent checks that don't depend on the subkey.
- A new install trusts the keyring it first sees. Compare the fingerprints on a second channel.
