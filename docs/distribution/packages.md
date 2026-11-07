---
title: Packages and distribution
description: "How a sluis release is built, versioned and served: platforms, packages split by holder and module, and the apt and dnf repositories, zips, images and charts."
status: target
sidebar:
  order: 0
---

A sluis release publishes every artifact from `https://distribution.sluis.id/`, a Cloudflare R2 bucket, with no redirects. GitHub Releases holds the same files as the immutable record. Every artifact of a release carries the same version and ships together. The design is [0013](/decisions/0013-release-train-packaging-and-distribution/); how to check what you downloaded is [Release signing](/distribution/release-signing/).

## At a glance

- **One version for the whole repository.** A release is built with GoReleaser v2, open-source edition, which includes the Rust builds ([0013](/decisions/0013-release-train-packaging-and-distribution/#one-version)). The YubiKey driver and the build of key@ that links `piv-go` need cgo against pcsc-lite, so they are built in a native per-architecture CI job.
- **Packaging follows the runtime, for amd64 and arm64.** There are no build profiles, and `dev` is not a build; it is how the local installation is run ([Packaging per runtime](#packaging-per-runtime)).
- **Packages follow the holders and the modules.** A host installs the foundation (store@, key@ and exporter@), the modules it runs, and only the drivers it uses ([Packages by holder and module](#packages-by-holder-and-module)).
- **Two homes.** `distribution.sluis.id` is a Cloudflare R2 bucket in the same account as the sluis.id zone. Everything is served from R2 with no redirects, and GitHub Releases keeps the same files as the record.
- **Checksums and SBOMs from the first alpha, no signed artifact.** Every release from `v2.0.0-alpha.1` carries checksums and SBOMs. The signing of release artifacts, keyless or OpenPGP, is in Backlog (decided on 2026-11-07), and the maintainer signs each tag by hand ([Release signing](/distribution/release-signing/)).
- **Nothing is stable before v2.0.0.** Releases until then are `v2.0.0-alpha.N` pre-releases, with no `latest` tag on images or charts.
- **No static upload key.** Images and GitHub Releases are published with the workflow's own token. Uploads to R2 wait until a sluis installation can mint them: CI then exchanges its GitHub OIDC token with sluis for a short-lived R2 token ([How CI uploads](/distribution/release-signing/#how-ci-uploads)).
- **The website is separate.** `sluis.id` is served as static assets on Cloudflare Workers, deployed by GitHub Actions, with a small live status API beside it ([0014](/decisions/0014-the-site-is-static-on-cloudflare-workers/)). Only distribution is on R2.

### Why R2 and no redirects

apt and dnf handle redirects unreliably, and a redirect chain is one more place for a repository to be pointed somewhere else. Serving every path directly from one bucket keeps the URL a user pins and the file they get the same thing. GitHub Releases is the second copy, and the one to compare with if the first is in doubt.

## Supported platforms

| Distribution | Version | systemd | Packages from |
|---|---|---|---|
| Ubuntu | 26.04 LTS | 259 | the apt repository |
| Rocky Linux | the latest stable, 10.x | 257 (10.2) | the dnf repository |
| Amazon Linux | 2023 | 252 | the dnf repository |

- **All of them on amd64 and arm64.**
- **The systemd floor is 252,** the version in Amazon Linux 2023. Generated units may rely on what 252 provides, such as `LoadCredentialEncrypted=` and `ExecPaths=`.
- **Serverless and Kubernetes have no host distribution.** An executable that needs cgo is built against the oldest supported glibc, so the same binary runs in a package and in an image.
- **A board image older than the floor is a declared exception,** not a supported platform: the boards deploy refuses to write a credential on it (the units read `LoadCredentialEncrypted=`), and `sluis doctor` warns where its kernel fails the randomness checklist. The boards themselves run Ubuntu 26.04 and Rocky 10 since 2026-11-06 ([Bare-metal](/runtimes/bare-metal/#ubuntu-2204-boards-are-gone)), so no board needs the exception. Key material is never affected: it stays in the card.
- **No FIPS build in v2.0.** Every platform gets the same build, and the algorithms stay in the FIPS-approved set so that a variant can be added when a customer needs it ([0006](/decisions/0006-keys-and-sealing/#algorithms)).

## Packaging per runtime

There are no build profiles: the runtime decides the packaging, and every artifact is built for amd64 and arm64. `dev` is not a build; it is the local installation, which runs the published images under Docker Compose.

| Runtime | Packaging |
|---|---|
| [bare-metal](/runtimes/bare-metal/) | `.deb` and `.rpm` packages split by holder, module and driver, in apt and dnf repositories, and a tarball |
| [serverless](/runtimes/serverless/) | A zip per executable, a function per actor instance, at most three sluis layers per function |
| [kubernetes](/runtimes/kubernetes/) | One multi-arch OCI image per process, and one Helm chart with the images pinned by digest |

The install directory is the same in a package, a tarball and an image:

```text
/usr/libexec/sluis/{actors,drivers,node,vendor}/<short-name>
```

The adapters are actors. A driver sits in the private directory of its owner, `drivers/<owner>/<name>`, where the owner is the actor whose port it serves.

## Packages by holder and module

Every driver executable is a package of its own, so a host installs only what it runs. A driver belongs to one holder and is private to it ([0005](/decisions/0005-the-store/#drivers)), so what a host installs follows the holders and modules it runs.

| Package | Holds |
|---|---|
| `sluis` | The CLI, `sluis agent`, `sluis trust sync` with its timer ([Identity](/concepts/identity/)), and `sluis key request`, `install` and `status` |
| `sluis-node` | The node agent |
| `sluis-store`, `sluis-key`, `sluis-exporter` | The foundation: each holder with its units |
| `sluis-driver-<name>` | One driver executable, with the system packages it needs |
| `sluis-identity` | The identity module: the work actors other than `quota`, the first-party adapters included |
| `sluis-console` | The console's static bundle |
| `sluis-audit-writer` | The audit module: the writer and the witness |
| `sluis-audit-search` | The audit module: the indexer and the reader |
| `sluis-quota` | The quota module |
| `sluis-host` | The root host service, mainly for [SSH](/integrations/infrastructure-access/#ssh); it never listens on the network |
| `sluis-install-boards` | The meta-package of the boards installation |

Examples of driver packages:

| Package | Dependencies and contents |
|---|---|
| `sluis-driver-yubikey-piv` | Depends on pcscd, a CCID driver (`libccid`, `pcsc-lite-ccid`), libpcsclite (`libpcsclite1`, `pcsc-lite-libs`) and polkit (`polkitd`, `polkit`); Suggests `yubikey-manager`. On a node the card service serves key@ only ([0006](/decisions/0006-keys-and-sealing/#exclusive-card-access)) |
| `sluis-driver-rqlite` | Ships `rqlited` under `vendor/` |

Every dependency of every form, with the package names per family, is in the [runtime dependency matrix](/distribution/dependencies/).

- **A driver package depends on the package of its owner** and installs no service for an operator to start: the owner's unit starts the driver, and only the owner can open its socket ([0003](/decisions/0003-units-transports-and-fusion/#units)).
- **A module package depends on the foundation packages and on no other module,** and no package depends on a driver package it does not use. A host that runs the foundation with the audit module only installs no work actor of the identity module and no driver it does not run, and a KMS-only host installs no card driver and no pcscd.
- **Meta-packages exist only for the bare-metal installations that install from packages.** The local installation runs images and uses software keys by default, so it needs no package and no meta-package.
- **Template units only.** The packages ship `sluis-<actor>@.service` and `sluis-<actor>@.socket` and a systemd generator that creates the instances ([Bare-metal](/runtimes/bare-metal/#what-runs-where)). sluis generates no per-installation packages.
- **The console is a separate artifact,** a bundle of static files built once per release and served same-origin with the API: a directory from `sluis-console` on bare-metal, the bucket behind the API gateway on serverless, its own Deployment on Kubernetes. The audit console is a bundle of its own on the same train, served on the audit front's origin ([0028](/decisions/0028-audit-pieces/#the-audit-front), [#985](https://github.com/truvity/sluis/issues/985)).
- **The trust bundle reaches hosts through the `sluis` package.** `sluis trust enroll` turns on `sluis-trust-sync.timer`; the sync checks the bundle and the root list, writes the anchors and runs the distribution's trust update ([0013](/decisions/0013-release-train-packaging-and-distribution/#packaging-per-runtime)). On Kubernetes the bundle reaches pods through a trust-manager source or a ClusterTrustBundle.
- **Root ceremonies are not part of sluis.** They belong to [ritueel](https://ritueel.id). The release keyring package that apt and dnf verify with is built with ritueel's tools and published in sluis's own repositories, once the roots exist ([Release signing](/distribution/release-signing/#the-openpgp-release-key)).

## The R2 layout

The distribution site (#873), with its apt and dnf repositories, is v1 parity (decided 2026-11-07). The first working version publishes images, tarballs, checksums and SBOMs from GitHub Releases, and the layout below is the design for the site.

```text
apt/       dists/stable/{InRelease,Release,Release.gpg}
           dists/stable/main/binary-{amd64,arm64}/
           pool/
dnf/       {x86_64,aarch64}/{repodata/, packages}
           sluis.repo
bin/       <version>/<component>_linux_{amd64,arm64}.tar.gz
lambda/    <version>/{functions,layers,extensions}/sluis-<kind>-<name>_<version>_{arm64,x86_64}.zip
checksums/ <version>/SHA256SUMS, and SHA256SUMS.asc once releases are signed
keys/      the release keyring, once the roots exist
latest     pointer to the newest version
```

- The repository metadata files (`InRelease`, `Release.gpg`, `repomd.xml.asc`) are not signed, because the signing of release artifacts is in Backlog; a repository cannot be verified by its signature.
- `latest` points to the newest version. Pin a version in anything you automate.

## apt (Debian and Ubuntu)

The apt repository is v1 parity (decided 2026-11-07), with the rest of the distribution site.

Until releases are signed, download the `.deb` files and `SHA256SUMS` from the GitHub release and check them ([Release signing](/distribution/release-signing/#a-release-before-it-is-signed)). Once the apt metadata is signed, add the repository with the release keyring:

```sh
# Example
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/sluis-release.gpg] https://distribution.sluis.id/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/sluis.list
sudo apt update && sudo apt install sluis
```

The repository has one suite, `stable`, and one component, `main`. `signed-by` scopes the keyring to this one repository. How you get the keyring and check it is in [Release signing](/distribution/release-signing/#the-openpgp-release-key).

## dnf (Rocky Linux and Amazon Linux)

The dnf repository is v1 parity (decided 2026-11-07), with the rest of the distribution site.

```ini
# Example: /etc/yum.repos.d/sluis.repo
[sluis]
name=sluis
baseurl=https://distribution.sluis.id/dnf/$basearch
enabled=1
repo_gpgcheck=1
gpgcheck=0
gpgkey=file:///etc/pki/rpm-gpg/sluis-release.asc
```

`$basearch` is `x86_64` or `aarch64`. `repo_gpgcheck=1` verifies the signed `repomd.xml`, which carries each package's checksum. Header signatures on each rpm come later ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-signing-api)); then the file sets `gpgcheck=1` as well. Before the metadata is signed, verify downloaded `.rpm` files against `SHA256SUMS`.

## Binaries

Each executable is a tarball per architecture, with its checksum beside it. Use a tarball when you manage the units yourself.

| Part | Value |
|---|---|
| Name | `sluis-<kind>-<name>_<version>_linux_<arch>.tar.gz`, for example `sluis-actor-store_2.0.0-alpha.1_linux_arm64.tar.gz`; the command-line tool is `sluis_<version>_linux_<arch>.tar.gz` |
| `<kind>-<name>` | The name of the [image](#oci-images) of the same executable: `actor-<name>`, or `driver-<owner>-<name>` |
| Contents | The executable, under the file name its build gives it, and `LICENSE` |
| Beside it | A `.sha256` file; all of them are listed in the release's `SHA256SUMS` |

The executables are static: Go with cgo off, Rust as musl through cargo-zigbuild. The card driver links `libpcsclite` and is built in a native job, so it is not in this list yet ([#860](https://github.com/truvity/sluis/issues/860)). A tarball does not yet place the executable at its install path; the packages do, and so do the images.

The build is `.goreleaser.yaml`, which `just release-gen` writes from the tree: an actor or driver that merges joins the release, and CI fails while the file differs. `just release-snapshot` is a dry run of the whole build that needs no tag and publishes nothing; CI runs it on every pull request, and then checks every archive, its hash, that each executable is a static ELF of its architecture, and that it holds the release version.

## Lambda zips

The zips are under `lambda/<version>/` for `arm64`, the default, and `x86_64`, named `sluis-<kind>-<name>_<version>_<arch>.zip` on R2 and in the GitHub release alike. A function is one zip per actor instance; its functions, schedules, roles and invoke grants are derived from the actor registry ([0013](/decisions/0013-release-train-packaging-and-distribution/#packaging-per-runtime)).

- `functions/`: one zip per executable; the handler is the package's binary, renamed `bootstrap`, behind the kit's invoke adapter. A work function carries no driver. Only `entry` has a listener and uses the Lambda Web Adapter, pinned and vendored.
- `layers/`: at most three sluis layers: the edge layer (with the vendored adapter, for `entry` only), the drivers layer and the configuration layer, so at least two of Lambda's five stay free for the operator.
- `extensions/`: the drivers of a holder's function. One Rust extension implements the AWS ports the holder needs: for store@ the AppConfig, SSM and DynamoDB ports, for key@ the KMS port.

What a layer or an extension bundles is in the [runtime dependency matrix](/distribution/dependencies/). An installation verifies the zips and publishes the layers into its own account; sluis publishes no public layer ARNs. The YubiKey driver, `sluis-node`, rqlite and every driver that needs a disk or a long-running process are not published for Lambda ([Serverless](/runtimes/serverless/)).

## OCI images

One image per process, so a container can run its one executable only. Multi-arch images are on GHCR as `ghcr.io/truvity/sluis/<kind>-<name>`, for example `ghcr.io/truvity/sluis/actor-entry`, from the first working version. No image is named `sluis`: that name belongs to v1. The tag is the release version, with no `latest`; pull by digest, and find every digest of a release in its `release-images.txt`.

- The base is distroless `static`, or distroless with glibc and a pinned `pcsc-lite` for a cgo executable. What an image installs, and what stays on the host (pcscd, the CCID driver, polkit), is in the [runtime dependency matrix](/distribution/dependencies/).
- The executable sits at the package's path, `/usr/libexec/sluis/actors/<name>` or `/usr/libexec/sluis/drivers/<owner>/<name>`, byte for byte, and a label names its source package. A release test compares the images' binaries with the packages' files by hash.
- One image set serves the local installation and Kubernetes.

| Image | Holds |
|---|---|
| `actor-<name>` | The actor's executable |
| `driver-<owner>-<name>` | The driver's executable |
| `vendor-rqlite` | `rqlited`, the engine of the rqlite store driver on the local installation, at `/usr/libexec/sluis/vendor/rqlited`, from the release archive that `just rqlite-fetch` checks against its SHA-256. It is on a distroless base with glibc and a busybox, because the engine has no command for its health check |

The card driver has no image yet ([Gaps](/distribution/dependencies/#gaps)). The command-line tool is a tarball only.

```sh
# Example
docker pull ghcr.io/truvity/sluis/actor-entry@sha256:<digest>
```

### How the images are built and tested

`.goreleaser.yaml` builds each image with `dockers_v2` from the binaries of the same run, and `tools/gen/release` writes the Dockerfiles in `deploy/release/` with it: one `COPY` of one executable and an `ENTRYPOINT`, on the base that `deploy/local/Dockerfile` pins. Buildx adds no provenance or SBOM of its own to an image, so the one statement of provenance is the GitHub attestation ([Release signing](/distribution/release-signing/)).

`just release-rehearsal` runs the release as a tag does, minus the GitHub release, and pushes to a registry that it starts on a free loopback port, with no credential. CI runs it on every pull request. `tools/release check-images` then reads that registry and fails unless, for every image:

- the repository holds the release version as its only tag, so there is no `latest`, and no repository is named `sluis`;
- the index holds `linux/amd64` and `linux/arm64` and nothing else, and its digest is the one in `digests.txt`;
- the entrypoint is the install path, the user is the nonroot user of the base, and the labels name the image, the version and the source package;
- the layer the build added holds the executable and nothing else, and the executable is the file of the archive of the same architecture, hash for hash.

`tools/release release-images` writes `release-images.txt` from the digests: one line per image, `<repository>:<tag>@sha256:<digest>`.

### SBOMs

Each archive has an SPDX 2.3 JSON SBOM beside it, `<archive>.sbom.spdx.json`, and each image has one made from the registry by digest. syft makes them. It reads the Go modules from the build information of an executable and the Rust crates from the list that `cargo auditable` records in it (`tools/release/cargo-auditable.sh` is the tool GoReleaser's Rust builder runs). The archives' documents are listed in `SHA256SUMS` with the archives.

`tools/release check-sboms` validates every document in the rehearsal: the fields SPDX 2.3 requires of a document and of each package, unique ids, relationships that name elements the document has, syft as the creator, and at least one crate (`pkg:cargo/`) in the SBOM of a Rust executable or one Go module (`pkg:golang/`) in that of a Go one, so a build that recorded nothing fails. It is a structural check of the format, not a run of the SPDX project's own validator.

## Helm charts

From the parity milestone the chart is an OCI artifact at `ghcr.io/truvity/sluis/charts/sluis`, packaged by truvity/ocictl from the same build, and a chart's version is the release version. A chart pins every image by digest, so it installs exactly the images released with it.

- **One `sluis` chart** with a piece selector and the presets `install`, `audit-install`, `quota-install` and `kubernetes-dev`, and no subcharts, so a writer and a reader always come from one release. A holder's pod runs the holder's image with its drivers as native sidecar containers. The console runs as its own Deployment behind the same route as `entry`.
- **The cert-manager issuer** has a chart of its own, with its CRDs and RBAC. The certificate sidecar is an image plus a documented container snippet.

```sh
# Example
helm pull oci://ghcr.io/truvity/sluis/charts/sluis --version <version>
```

## Releasing

A release is a tag `v2.<minor>.<patch>` or `v2.0.0-alpha.<n>` that the maintainer signs and pushes. Nothing else makes one: no workflow creates a tag, and a pull request never runs the release workflow. The first versions are not signed beyond the tag: no keyless signature and no provenance attestation, until the OpenPGP part is decided (owner decision, 2026-11-07), so the workflow has no `id-token` permission.

Before the first tag, once:

- **ghcr.io.** The workflow's own token pushes the images, with `packages: write`. The first push creates one package per image, linked to this repository through the `org.opencontainers.image.source` label. A package starts private: open each of them in the organisation's package settings and change its visibility to public, or the local installation cannot pull them without a login.
- **Immutable releases.** Turn on "Immutable releases" in the repository settings so that a published release cannot change. `main` already protects its commits.

For each release:

1. Rename `## Unreleased` in `CHANGELOG.md` to the version, in a pull request that merges to `main`, and wait for the run of `Checks` on `main` for that commit to finish green.
2. Tag that commit and push the tag, one tag per push (GitHub starts no workflow for a push of more than three tags):

   ```sh
   # Example
   git tag -s v2.0.0-alpha.1 <commit on main>
   git push origin v2.0.0-alpha.1
   ```

3. The `Release` workflow runs three things in order. The gate refuses a commit that is not an ancestor of `main`, or whose run of `Checks` on `main` is not a finished success ([REQ-SUPPLY-032](/requirements/supply/#REQ-SUPPLY-032)). The release job runs `just release`: GoReleaser builds, archives and pushes, and creates the GitHub release as a draft; the checks of the rehearsal then run against what was published (the archives, the image list, the images by digest, the SBOMs); and only then does the draft become a public pre-release. A check that fails leaves a draft and the pushed images, and announces nothing.
4. Check the result: the release holds the archives, `SHA256SUMS`, a `.sha256` and an SPDX SBOM for each archive, `release-images.txt`, and an SBOM for each image.

The workflow has an empty permission block at its top, and only its `release` job can write ([REQ-SUPPLY-033](/requirements/supply/#REQ-SUPPLY-033), [REQ-SUPPLY-041](/requirements/supply/#REQ-SUPPLY-041)); its checkouts keep no credential ([REQ-SUPPLY-042](/requirements/supply/#REQ-SUPPLY-042)); and no cache is restored, so a release builds from the sources and the locked dependencies alone. Tests over the workflow files hold those rules.

## GitHub Releases

GitHub Releases is the immutable record. Each release holds the same files as the R2 version directory. If a file on R2 and a file on the release differ, the release is right.

## Compatibility

The artifacts of one release are built, tested and shipped together, and each also works with those of the previous release of the same major version, so a rolling deployment can run two neighbouring releases at once and a rollback needs no migration ([0015](/decisions/0015-evolution-and-compatibility/#n-and-n-1-inside-a-major-version)). Between releases, compatibility follows semantic versioning ([0013](/decisions/0013-release-train-packaging-and-distribution/#compatibility-between-releases), [#1022](https://github.com/truvity/sluis/issues/1022)).
