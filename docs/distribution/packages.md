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
- **Two homes.** `distribution.sluis.id` is a Cloudflare R2 bucket in the same account as the sluis.id zone. Everything is served from R2 with no redirects, and GitHub Releases keeps the same files as the record, with GitHub build provenance attestations.
- **Verifiable from the first alpha, signed with OpenPGP once the roots exist.** Every release from `v2.0.0-alpha.1` carries checksums, SBOMs, attestations and a keyless cosign signature on each image. Nothing is signed with OpenPGP before [ritueel](https://ritueel.id) has held the root ceremony and its drill ([Release signing](/distribution/release-signing/)).
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
- **A board image older than the floor is a declared exception,** not a supported platform: its units use plain `LoadCredential=` where `LoadCredentialEncrypted=` is missing, and `sluis doctor` warns where its kernel fails the randomness checklist. The exception ends when board images for the supported distributions exist ([#881](https://github.com/truvity/sluis/issues/881)). Key material is never affected: it stays in the card.
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
| `sluis-driver-yubikey-piv` | Depends on pcscd and pcsc-lite. On a node the card service serves key@ only ([0006](/decisions/0006-keys-and-sealing/#exclusive-card-access)) |
| `sluis-driver-rqlite` | Ships `rqlited` under `vendor/` |

- **A driver package depends on the package of its owner** and installs no service for an operator to start: the owner's unit starts the driver, and only the owner can open its socket ([0003](/decisions/0003-units-transports-and-fusion/#units)).
- **A module package depends on the foundation packages and on no other module,** and no package depends on a driver package it does not use. A host that runs the foundation with the audit module only installs no work actor of the identity module and no driver it does not run, and a KMS-only host installs no card driver and no pcscd.
- **Meta-packages exist only for the bare-metal installations that install from packages.** The local installation runs images and uses software keys by default, so it needs no package and no meta-package.
- **Template units only.** The packages ship `sluis-<actor>@.service` and `sluis-<actor>@.socket` and a systemd generator that creates the instances ([Bare-metal](/runtimes/bare-metal/#what-runs-where)). sluis generates no per-installation packages.
- **The console is a separate artifact,** a bundle of static files built once per release and served same-origin with the API: a directory from `sluis-console` on bare-metal, the bucket behind the API gateway on serverless, its own Deployment on Kubernetes. The audit console is a bundle of its own on the same train, served on the audit front's origin ([0028](/decisions/0028-audit-pieces/#the-audit-front), [#985](https://github.com/truvity/sluis/issues/985)).
- **The trust bundle reaches hosts through the `sluis` package.** `sluis trust enroll` turns on `sluis-trust-sync.timer`; the sync checks the bundle and the root list, writes the anchors and runs the distribution's trust update ([0013](/decisions/0013-release-train-packaging-and-distribution/#packaging-per-runtime)). On Kubernetes the bundle reaches pods through a trust-manager source or a ClusterTrustBundle.
- **Root ceremonies are not part of sluis.** They belong to [ritueel](https://ritueel.id). The release keyring package that apt and dnf verify with is built with ritueel's tools and published in sluis's own repositories, once the roots exist ([Release signing](/distribution/release-signing/#the-openpgp-release-key)).

## The R2 layout

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

- The repository metadata files (`InRelease`, `Release.gpg`, `repomd.xml.asc`) are signed from the parity milestone on; until then a repository cannot be verified by its signature.
- `latest` points to the newest version. Pin a version in anything you automate.

## apt (Debian and Ubuntu)

Until releases are signed, download the `.deb` files and `SHA256SUMS` from the GitHub release and check them ([Release signing](/distribution/release-signing/#a-release-before-it-is-signed)). Once the apt metadata is signed, add the repository with the release keyring:

```sh
# Example
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/sluis-release.gpg] https://distribution.sluis.id/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/sluis.list
sudo apt update && sudo apt install sluis
```

The repository has one suite, `stable`, and one component, `main`. `signed-by` scopes the keyring to this one repository. How you get the keyring and check it is in [Release signing](/distribution/release-signing/#the-openpgp-release-key).

## dnf (Rocky Linux and Amazon Linux)

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

Each component is a tarball per architecture at `bin/<version>/<component>_linux_{amd64,arm64}.tar.gz`, with its `.sha256` beside it, laid out like a package. Use a tarball when you manage the units yourself.

## Lambda zips

The zips are under `lambda/<version>/` for `arm64`, the default, and `x86_64`, named `sluis-<kind>-<name>_<version>_<arch>.zip` on R2 and in the GitHub release alike. A function is one zip per actor instance; its functions, schedules, roles and invoke grants are derived from the actor registry ([0013](/decisions/0013-release-train-packaging-and-distribution/#packaging-per-runtime)).

- `functions/`: one zip per executable; the handler is the package's binary, renamed `bootstrap`, behind the kit's invoke adapter. A work function carries no driver. Only `entry` has a listener and uses the Lambda Web Adapter, pinned and vendored.
- `layers/`: at most three sluis layers: the edge layer (with the vendored adapter, for `entry` only), the drivers layer and the configuration layer, so at least two of Lambda's five stay free for the operator.
- `extensions/`: the drivers of a holder's function. One Rust extension implements the AWS ports the holder needs: for store@ the AppConfig, SSM and DynamoDB ports, for key@ the KMS port.

An installation verifies the zips and publishes the layers into its own account; sluis publishes no public layer ARNs. The YubiKey driver, `sluis-node`, rqlite and every driver that needs a disk or a long-running process are not published for Lambda ([Serverless](/runtimes/serverless/)).

## OCI images

One image per process, so a container can run its one executable only. Multi-arch images are on GHCR as `ghcr.io/truvity/sluis/<kind>-<name>`, for example `ghcr.io/truvity/sluis/actor-entry`, from the first working version. No image is named `sluis`: that name belongs to v1. The tag is the release version, with no `latest`; pull by digest, and find every digest of a release in its `release-images.txt`.

- The base is distroless `static`, or distroless with glibc and a pinned `pcsc-lite` for a cgo executable.
- The executable sits at the package's path, byte for byte, and a label names its source package. A release test compares the images' binaries with the packages' files by hash.
- One image set serves the local installation and Kubernetes.

```sh
# Example
docker pull ghcr.io/truvity/sluis/actor-entry@sha256:<digest>
```

## Helm charts

From the parity milestone the chart is an OCI artifact at `ghcr.io/truvity/sluis/charts/sluis`, packaged by truvity/ocictl from the same build, and a chart's version is the release version. A chart pins every image by digest, so it installs exactly the images released with it.

- **One `sluis` chart** with a piece selector and the presets `install`, `audit-install`, `quota-install` and `kubernetes-dev`, and no subcharts, so a writer and a reader always come from one release. A holder's pod runs the holder's image with its drivers as native sidecar containers. The console runs as its own Deployment behind the same route as `entry`.
- **The cert-manager issuer** has a chart of its own, with its CRDs and RBAC. The certificate sidecar is an image plus a documented container snippet.

```sh
# Example
helm pull oci://ghcr.io/truvity/sluis/charts/sluis --version <version>
```

## GitHub Releases

GitHub Releases is the immutable record. Each release holds the same files as the R2 version directory, with the GitHub build provenance attestations. If a file on R2 and a file on the release differ, the release is right.

## Compatibility

The artifacts of one release are built, tested and shipped together, and each also works with those of the previous release of the same major version, so a rolling deployment can run two neighbouring releases at once and a rollback needs no migration ([0015](/decisions/0015-evolution-and-compatibility/#n-and-n-1-inside-a-major-version)). Between releases, compatibility follows semantic versioning ([0013](/decisions/0013-release-train-packaging-and-distribution/#compatibility-between-releases), [#1022](https://github.com/truvity/sluis/issues/1022)).
