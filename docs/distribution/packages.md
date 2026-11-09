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
| `sluis-cli` | The command-line tool at `/usr/bin/sluis`: `sluis agent`, `sluis trust sync`, and `sluis key request`, `install` and `status`. No dependency on systemd, so a workstation installs it alone |
| `sluis` | The foundation's `policy` and `entry` (whose executable the audit front also runs), with both units of `entry`, the identity front and the audit front, the timer of `sluis trust sync` ([Identity](/concepts/identity/)) and their units; depends on `sluis-cli` and on systemd |
| `sluis-node` | The node agent |
| `sluis-store`, `sluis-key`, `sluis-exporter` | The foundation: each holder with its units |
| `sluis-driver-<owner>-<name>` | One driver executable (for example `sluis-driver-store-rqlite`), with the system packages it needs; named like its [image](#oci-images) and its tarball |
| `sluis-identity` | The identity module: the work actors other than `quota`, `policy` and `entry`, the first-party adapters included |
| `sluis-console` | The console's static bundle |
| `sluis-audit-writer` | The audit module: the writer and the witness |
| `sluis-audit-search` | The audit module: the indexer and the reader |
| `sluis-quota` | The quota module |
| `sluis-host` | The root host service, mainly for [SSH](/integrations/infrastructure-access/#ssh); it never listens on the network |
| `sluis-install-boards` | The meta-package of the boards installation |

Examples of driver packages:

| Package | Dependencies and contents |
|---|---|
| `sluis-driver-key-yubikey-piv` | (not built yet: the card driver comes from the native job) Depends on pcscd, a CCID driver (`libccid`, `pcsc-lite-ccid`), libpcsclite (`libpcsclite1`, `pcsc-lite-libs`) and polkit (`polkitd`, `polkit`); Suggests `yubikey-manager`. On a node the card service serves key@ only ([0006](/decisions/0006-keys-and-sealing/#exclusive-card-access)) |
| `sluis-driver-store-rqlite` | Ships `rqlited` under `vendor/` (not built yet: the package holds the driver alone) |

Every dependency of every form, with the package names per family, is in the [runtime dependency matrix](/distribution/dependencies/).

- **A driver package depends on the package of its owner** and, in one case, recommends the driver package of another owner. The indexer's file driver reads the audit blob that the writer's file driver serves, so its unit requires the writer's driver, which is in another package; `sluis-driver-indexer-fs` has `Recommends: sluis-driver-writer-fs` at the exact version, in the plan as the one weak edge (`WeakEdges`) and the only one the check allows. A recommends is installed by default and may be left out, so the walk of REQ-SUPPLY-029 (an audit host installs no identity actor) follows it too; the meta-package of the boards installs both, and `sluis doctor` will name a missing one (not built yet). A driver package still depends on no other driver package, and no package depends on one. It installs no service for an operator to start: the owner's unit starts the driver, and only the owner can open its socket ([0003](/decisions/0003-units-transports-and-fusion/#units)).
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

### How the packages are built

`tools/release/packages` builds the `.deb` and the `.rpm` of every package, for amd64 and arm64, with the nfpm library, from the executables of the archives of the same run, byte for byte (`just release-packages`; the checks of its code are `just check-packages`). It is a Go module of its own, so nfpm and its dependencies are in no other build. The plan, the reader and the check are a library, `tools/release/pkgs`, with no dependency but the standard library and yaml (a test holds it to that); `tools/release check-packages` runs the check, so the job that publishes, which compiles `tools/release`, never links nfpm. GoReleaser's own `nfpms` step is not used: it writes `dependencies` as they are, so `{{ .Version }}` stays in the file, and both formats then ship a dependency that is never met (MEASURED 2026-11-07, GoReleaser 2.20.0).

- **The packages are the ones the images list and the actor registry give.** An executable of `deploy/release/images.yaml` joins a package without anyone listing it: the data and keys families are `sluis-store`, `sluis-key` and `sluis-exporter`; the work actors other than `quota`, `policy` and `entry` are `sluis-identity`; the audit family is `sluis-audit-writer` and `sluis-audit-search`; a driver is `sluis-driver-<owner>-<name>`; the package `sluis-cli` holds the command-line tool, at `/usr/bin/sluis` (which finds the store helper at `../libexec/sluis/actors/store` beside it) and depends on no systemd, and the base package `sluis` holds the foundation's `policy` and `entry`, which the exporter, the audit module and quota start with and whose executable the audit front runs, and depends on `sluis-cli` and systemd (decided 2026-11-08). A workstation installs `sluis-cli` alone; the CLI-only install was proven with `apt` on Ubuntu 26.04 and `dnf` on Rocky Linux 10 and Amazon Linux 2023, with no systemd added. A package with no executable is not built. Not built yet, and why: the card driver (the native job), `sluis-node`, `sluis-host`, `sluis-console` and the meta-package of the boards, and the units, users and directories, which come with the packaging of the units.
- **One version, mapped once.** `2.0.0-alpha.1` is `2.0.0~alpha.1` in both formats, because a tilde sorts before the release (dpkg, and rpm 4.10 and later), and a dash would be read as the revision of a `.deb`. Every dependency of a package on another package of the release is `= 2.0.0~alpha.1`: `sluis-store (= 2.0.0~alpha.1)` in a `.deb`, `sluis-store = 2.0.0~alpha.1` in an `.rpm`. A pre-release with a hyphen or a build metadata is refused.
- **The file names keep the dash:** `<name>_<version>_<arch>.deb` and `.rpm`, with the version as tagged and the `.rpm` architecture `x86_64` or `aarch64`. Whether GitHub keeps a `~` in an asset name is UNVERIFIED, and the package manager reads the version from the metadata, so the name does not need it. `SHA256SUMS` beside the packages lists them; adding it to the release's is the release job's.
- **One `.deb` serves Ubuntu 26.04, and one `.rpm` serves Rocky Linux 10 and Amazon Linux 2023,** whose rpm 4.16 is the floor: the payload is gzip, the file digests are SHA-256, and the check refuses a package that asks rpm for a feature that 4.16 lacks (the list is `rpm --showrc` on Amazon Linux 2023, MEASURED 2026-11-08). The same sixteen packages installed with `apt` and `dnf` on the three systems on that day, from a directory, with the dependencies resolved.
- **Files:** executables 0755, everything else 0644, directories 0755, all owned by root, no setuid, setgid or sticky bit, nothing in `/opt`, `/usr/local`, `/etc/sluis` or `/var/lib/sluis-state`. A package never deletes state or users (the maintainer decided on 2026-11-08), so a maintainer script starts, enables and deletes nothing. A package's users and directories are in `/usr/lib/sysusers.d/<package>.conf` and `/usr/lib/tmpfiles.d/<package>.conf`, so a script reads its own file and no other. The same inputs give the same bytes.

`tools/release check-packages` reads the built files back, with its own reader, which was compared with `dpkg-deb` and `rpm` for the same packages. It checks the version and the dependencies of each package (exact, in the syntax of the format, and only the external dependencies that [the matrix](/distribution/dependencies/) lists), the modes and owners, that each executable is the file of its archive and a static ELF of its architecture with the version in it, that the layering of the dependencies is the one of [Packages by holder and module](#packages-by-holder-and-module) (the CLI depends on nothing of the release, `sluis` on the CLI, the foundation on `sluis`, a module on `sluis` and the foundation and on no other module), that a host with `sluis` and the audit packages installs no identity actor (read from the executables the packages hold), that the maintainer scripts start, enable and delete nothing and name only files of their package, that a driver package holds no unit an operator can enable, and that a `.deb` and an `.rpm` of one package hold the same files, scripts and dependencies. The read-back is a closed set: a `.deb` has only the control fields the check reads (no `Provides`, `Conflicts`, `Replaces`, `Breaks`, `Pre-Depends` or custom field) and the three ar members; an `.rpm` has only the header tags it reads (no provides beyond itself, no conflicts, obsoletes, triggers, pretrans or posttrans), its payload is read and each file in it is the one the header lists, and its release is 1 (a `.deb` has no revision); directories only below the places a package installs into or above them. Every archive the reader inflates is read through a cap (1 GiB for a data archive or a payload, 8 MiB for a control archive), the sizes in the entries' headers are held to it and to their sum, a sparse entry is refused (its holes cost no byte of the stream), and an rpm header is held to a store of at most 64 MiB, to the data its counts point to, to sums of what its entries claim (strings at most a quarter of the store and 4096, and at most 262144; numbers at most the store and 4096, and at most 16 MiB), checked before a slice is built, and to one budget for the walks over its strings, so a crafted package is an error and not an exhausted job. A package has no maintainer script that the plan does not list, and the plan has none yet. The text of a planned script may run only what is on a short list (`exit`, `set -e`, `[`, `test`, `echo`, `true`, `systemctl daemon-reload`, `systemctl stop` or `try-restart` of a sluis unit, `systemd-sysusers` and `systemd-tmpfiles --create` on files of `/usr/lib`, and the words of `if` and `case`), with no command substitution, heredoc or redirect but to `/dev/null`; anything else is a refusal, and a list of refused words only explains it. The script is printable ASCII, newlines and tabs (a shell's blanks are the space and the tab; a no-break space, a form feed or a CR is a blank to Go's `strings.TrimSpace` and a word to a shell). The shape of the text is held to the part of the shell where reading it a line at a time is true: the first line is `#!/bin/sh`, with at most `-e` or `-eu`, because the rest of a shebang line reaches the interpreter; a `#` only starts a line (no comment after a command, no `$#`, no `${#a}`); no line ends with a backslash; no `$'` and no `$"`; a `${` is `${NAME}` and nothing else; and no quote is open at the end of a line. A test feeds every short line made of the pieces that bend the reading of the next line to the shells of the host (dash, sh, bash), after each a line that the lint takes for a comment and a shell would run, and asserts that nothing the lint accepts runs it. That is still text: it cannot see everything a shell can do, and the proof is the install tier. The proof is the install tier, which will watch the units and the state across install, upgrade, removal and reinstall.

### A throwaway repository for tests

`just release-repo` makes an apt repository and a dnf repository of the packages of `dist/packages` in `dist/repo`, `just release-repo-serve` serves them on a loopback address, and `just release-repo-smoke` installs `sluis-cli` and `sluis` from them in containers. **They are not the publication site.** The trees are unsigned (no `InRelease`, `Release.gpg` or `repomd.xml.asc`; a client is told to trust them with `[trusted=yes]` or `gpgcheck=0`), each carries `UNSIGNED-TEST-REPOSITORY.txt` to say so, and the server refuses any address that is not a loopback IP address. The site on R2 stays in v1 parity, signed ([The R2 layout](#the-r2-layout)).

- **The metadata is written in Go, from the packages themselves,** by `tools/release/repo`, with the standard library and the readers of `tools/release/pkgs`: no `createrepo`, `dpkg-scanpackages` or `apt-ftparchive`. The apt tree is `pool/main/<letter>/<name>/<file>`, `dists/stable/main/binary-{amd64,arm64}/{Packages,Packages.gz,Release}` and `dists/stable/Release` (SHA-256 and SHA-512 of every index file). The dnf tree is one directory per `$basearch` (`x86_64`, `aarch64`) with `Packages/` and `repodata/` (`repomd.xml`, `primary`, `filelists` and `other`, gzip, named by their checksum), with the header range, every dependency with its flags and version, and the file lists. The same packages and the same date give the same bytes.
- **The repository carries the bytes that were checked.** The builder refuses a package whose SHA-256 is not the one in the `SHA256SUMS` beside it, and a package the sums do not list. It then reads its own output back by another path (a parser of `Packages` and `Release`, and the XML decoder of the standard library) and fails on any disagreement with the files: a size, a hash, a count, a file that no index lists, a signature file, and a dependency on a package of the release that is not met in the tree of its architecture at the exact version.
- **It stays out of the job that publishes.** The code is `tools/release/repo`, the command is `packages repo` and `packages serve` in the module of the builder, and `tools/release` links none of it (`tools/release/imports_test.go` refuses the import). Nothing in it needs a token.
- **The smoke installs from the repository and from nothing else** (`tools/release/repo-smoke.sh`). For each of Ubuntu 26.04 (apt), Rocky Linux 10 and Amazon Linux 2023 (dnf), by digest, a container on the host network with nothing mounted installs `sluis-cli` alone (and no systemd comes with it), and another installs `sluis` alone, so that apt or dnf resolve `sluis-cli` at the exact version through the repository and take `systemd` from the distribution. Each then checks the installed version, the files, that no unit was enabled, and that the package manager names the repository as the source; with `SLUIS_SMOKE_EXPECT_VERSION` (the recipe sets it from `dist/release/metadata.json`) it runs `sluis version`. The log of the server must show the `.deb` or `.rpm` requests of both packages. The release rehearsal of CI runs it after `release-packages`.
- **What this does not prove.** Not an arm64 install (the arm64 trees are checked, never installed), not signed metadata, not what an upgrade, a removal or a reinstall does, not units or credentials (the containers have no running systemd), and not the site. The lifecycle belongs to the install tier.

## Binaries

Each executable is a tarball per architecture, with its checksum beside it. Use a tarball when you manage the units yourself.

| Part | Value |
|---|---|
| Name | `sluis-<kind>-<name>_<version>_linux_<arch>.tar.gz`, for example `sluis-actor-store_2.0.0-alpha.1_linux_arm64.tar.gz`; the command-line tool is `sluis_<version>_linux_<arch>.tar.gz` |
| `<kind>-<name>` | The name of the [image](#oci-images) of the same executable: `actor-<name>`, or `driver-<owner>-<name>` |
| Contents | The executable, under the file name its build gives it, and `LICENSE` |
| Beside it | A `.sha256` file; all of them are listed in the release's `SHA256SUMS` |

The executables are static: Go with cgo off, Rust as musl through cargo-zigbuild. The card driver links `libpcsclite` and is built in a native job, so it is not in this list yet ([#860](https://github.com/truvity/sluis/issues/860)). A tarball does not yet place the executable at its install path; the packages do, and so do the images.

The build is `.goreleaser.yaml`, which `just release-gen` writes from the tree: an actor or driver that merges joins the release, and CI fails while the file differs. GoReleaser only builds (`just release-build`, which runs it with `--skip=publish` and no token); it pushes nothing. Rust executables are built under `cargo auditable` with the build machine's paths remapped, as Go is built with `-trimpath`, and `tools/release check-dist` fails on an executable that holds the workspace path, is not a static ELF of its architecture, or lacks the release version.

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

GoReleaser does not build the images. `tools/release publish-images` builds each one with `docker buildx` from the archive of the same run (the file `SHA256SUMS` lists) and pushes it under the release version, in the job that holds the credentials. `tools/gen/release` writes the list, `deploy/release/images.yaml`, and the Dockerfiles in `deploy/release/`: one `COPY` of one executable and an `ENTRYPOINT`, on the base that `deploy/local/Dockerfile` pins. Buildx adds no provenance or SBOM of its own to an image. Nothing about an image is signed ([Release signing](/distribution/release-signing/)).

`just release-rehearsal` runs both halves of a release, minus the GitHub release, and pushes to a registry that it starts on a free loopback port, with no credential. CI runs it when a change can affect the release (see [Releasing](#releasing)). Before the first push, `tools/release preflight` fails if any image already has the release version as a tag that this run did not push (see "Running the failed job again" for how a run knows): a tag is not pushed over, as far as a check followed by a push can promise it (best effort, because a registry has no conditional push; `check-images` verifies the result). After the push, `tools/release check-images` reads the registry and fails unless, for every image:

- the release version is a tag of the repository, no tag floats (a tag that is no release version, such as `latest`, fails), and on the throwaway registry the version is the only tag; earlier releases beside it on ghcr.io are expected;
- no repository is named `sluis`;
- the index holds `linux/amd64` and `linux/arm64` and nothing else, and its digest is the one in `digests.txt`;
- every manifest, config and layer, the base's included, is the bytes of its digest;
- the image is the pinned base plus the build: the index, the manifest and the configuration have no field the build does not set; the manifest holds exactly the layers of the base that the Dockerfile pins by digest (read from its registry by that digest, its manifest and configuration checked against their digests), in order, and then the layers the build added; the configuration is the base's (`Env`, `User`, `WorkingDir`, and any `Volumes`, `ExposedPorts`, `Healthcheck` or other field, which must equal the base's or be absent) with the entrypoint and the labels of the release added; `rootfs.diff_ids` are the base's followed by the hash of what each added layer unpacks to;
- the entrypoint is the install path, the user is the nonroot user of the base, and the labels name the image, the version, the commit and the source package;
- the layers the build added hold the files the list names and nothing else, none of them writable, and the executable is the file of the archive of the same architecture, hash for hash. The images are built from those archives in the same job, so this proves the round trip through the registry (no layer or tag was changed on the way), not that the archive is what the sources produce. For `vendor-rqlite`, the file `just rqlite-fetch` verified, and its image carries rqlite's MIT notice, `/usr/share/doc/sluis/vendor-rqlite/LICENSE`).

`tools/release release-images` writes `release-images.txt` from the digests: one line per image, `<repository>:<tag>@sha256:<digest>`. It and the SBOM of every image are added to `SHA256SUMS`, which without signing is the one anchor of trust of a release, and `tools/release check-sums` checks that every line names a file with that hash. The build's own `SHA256SUMS` may not list them: `check-dist` refuses a line for the audit catalogue, the list of images or an image SBOM before anything is pushed, and `check-dist -late` accepts them after `sums-add`.

The layers the build adds may hold regular files only; a link or a device in one fails the check. The `history` of the configuration is not compared, and the base is read from `gcr.io` over the network at release time (the Dockerfile's digest is the pin; nothing else of the base is committed).

The registry client sends its token only to an HTTPS token endpoint on the registry's host or on `ghcr.io`. It reads at most 1,000 tags of a repository.

### SBOMs

Each archive has an SPDX 2.3 JSON SBOM beside it, `<archive>.sbom.spdx.json`, and each image has one made from the registry by digest. syft makes them. It reads the Go modules from the build information of an executable and the Rust crates from the list that `cargo auditable` records in it (`tools/release/cargo-auditable.sh` is the tool GoReleaser's Rust builder runs). The documents of the archives and of the images are listed in `SHA256SUMS` with the archives.

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

A release is a tag `v2.<minor>.<patch>` or `v2.0.0-alpha.<n>` that the maintainer signs and pushes. Nothing else makes one: no workflow creates a tag, and a pull request never runs the release workflow. Nothing in the release is signed beyond the tag (decided 2026-11-07): the workflow has no `id-token` permission, makes no keyless signature and no provenance attestation, and `SHA256SUMS` is the trust anchor of the files and the digests ([Release signing](/distribution/release-signing/)).

Before the first tag, once:

- **ghcr.io.** The workflow's own token pushes the images, with `packages: write`. The first push creates one package per image, linked to this repository through the `org.opencontainers.image.source` label. Nothing in the workflow makes a package public. GitHub documents a new package as private by default and offers no API to change that afterwards (the REST API for packages lists, gets, deletes and restores), yet the 23 packages that the first alpha created came out public, as do all the other container packages of the organisation, which are pushed from public repositories the same way. That is observed behaviour, not a documented guarantee, so the release checks it: before the GitHub release leaves draft, the job pulls every image by its digest without a credential, fails for each package that is not public, names it with the page where its owner changes the visibility (`https://github.com/orgs/truvity/packages/container/package/sluis%2F<name>/settings`, then Danger Zone, Change visibility, Public), and leaves the release as a draft. The owner then makes those packages public and runs the failed job again (`gh run rerun <run id> --failed -R truvity/sluis`); see "Running the failed job again" below.
- **Immutable releases.** Turn on "Immutable releases" in the repository settings so that a published release cannot change. `main` already protects its commits.
- **The tag rulesets on `v2.*`, applied by the owner.** `v2-tags-create` lets only the owner create a tag that matches `v2.*`, and `v2-tags-immutable` lets nobody update or delete one. Both exist. Without the first, anyone with write access to the repository could tag a branch whose copy of `release.yaml` has no gate: GitHub runs the workflow file of the tagged commit, so the gate lives in the file it protects and cannot stop that. What stops it is that only the owner can create the tag. There is no `environment: release` and no approval step, by the owner's decision.

For each release:

1. Rename `## Unreleased` in `CHANGELOG.md` to the version (`## 2.0.0-alpha.1`), in a pull request that merges to `main`, and wait for the run of `Checks` on `main` for that commit to finish green. The text of that section is the release's notes; a release with no such section fails.
2. Tag that commit and push the tag, one tag per push (GitHub starts no workflow for a push of more than three tags):

   ```sh
   # Example
   git tag -s v2.0.0-alpha.1 <commit on main>
   git push origin v2.0.0-alpha.1
   ```

3. The `Release` workflow runs three jobs in order:
   - **gate.** It refuses a ref that is not a tag of the form `v2.<minor>.<patch>` or `v2.0.0-alpha.<n>`, a commit that is not an ancestor of `main`, and one whose run of `Checks` on `main` is not a finished success ([REQ-SUPPLY-032](/requirements/supply/#REQ-SUPPLY-032)).
   - **build.** GoReleaser builds every executable, archive, checksum and SBOM with `contents: read` and no token, because it runs the build scripts and macros of every dependency. That limits a compromised dependency to the content of this release: it cannot use the write token on anything else. It does not make the content trustworthy, because what the build produces is what ships.
   - **release.** It has the write permissions and builds nothing. It downloads the build's files, checks that the download changed no tracked file of the tree (`git diff --quiet HEAD`; the tree is a trust anchor of the catalogue check), and trusts none of them: `check-dist -exact` refuses anything in the download that is not a regular file of the release, so a stray file or a directory named like an SBOM cannot reach `sums-add` and fail after the images are pushed; it checks them again against the configuration, requires `metadata.json` to name the tag's commit in full and a release version, and passes nothing else from the artifact to git or to a tag; it then checks the audit catalogue that the build made against the tagged tree and stops if it is not the catalogue of this version ([The audit catalogue](#the-audit-catalogue-of-a-release)); refuses a tag that already has a public release, pushes the images that are not at this version yet (an image that is there is kept only if an earlier attempt of this same run pushed it, and refused otherwise), runs the release test of the images against ghcr.io, makes the image SBOMs, adds the list of images, the audit catalogue and those SBOMs to `SHA256SUMS`, creates the GitHub release as a draft with every file (replacing the draft of an earlier attempt), checks that the draft holds them all, pulls every image by its digest with no credential ([REQ-SUPPLY-046](/requirements/supply/#REQ-SUPPLY-046)), and only then makes the release public (a pre-release for an alpha). The anonymous pull asks for the manifests and, with a `HEAD` request that follows the redirect to where the registry keeps blobs, for the configuration and every layer of each; it does not download the layers (`check-images` has read and hashed them).
4. Check the result: the release holds the archives, `SHA256SUMS`, a `.sha256` and an SPDX SBOM for each archive, `release-images.txt`, an SBOM for each image, and `audit-catalogue.yaml`.

### The audit catalogue of a release

The emitters of a release put its version in every audit record (`metadata.product.version`). The writer validates a record against the `AuditCatalogue` config document and refuses a record whose release is newer than the catalogue's, so that record is quarantined, not logged ([REQ-AUDIT-146](/requirements/audit/#REQ-AUDIT-146), [0030](/decisions/0030-audit-records-and-the-usage-stream/)). An installation that runs a release without that release's catalogue loses the audit records of its own services. The catalogue is therefore a part of the release.

- **What the release ships.** `audit-catalogue.yaml`, the document of the release: the action table of the tagged commit with the JSON Schema of every action's records, as the one item `default`, with `release` set to the version (the tag without the `v`). The build job makes it with `go run ./tools/gen/audit -catalogue audit-catalogue.yaml -release <version>` (its generator compiles third-party Go modules, which the job that holds the tokens must not run). The release job does not trust the file: before it pushes anything, `tools/release check-catalogue` stops the release unless the file is the catalogue of the local installation (`tests/installations/local/config/audit-catalogue.yaml`, which `just audit-check` holds equal to the generator's output on the commit the gate found green) with only the release replaced: the same policy version, the same actions and the same schemas byte for byte, and also the actions of the action table and the committed schemas (`kits/conformance/audit/schema`) as JSON. It reads the file as strictly as the writer does, with `yaml/v3` alone: one document, no alias, anchor, explicit tag or merge key, no field the item does not declare, a policy version, and schemas that are plain JSON (a duplicate key or a number that is not what it says fails). A file the build altered, or one made for another tree, fails there before anything is pushed, not as an audit outage after the operator publishes it. No empty action name passes. It is a release file, listed in `SHA256SUMS`. It is not signed: the release holds no key.
- **What the operator does with it.** Take `audit-catalogue.yaml` from the release and check it against `SHA256SUMS`. Put it in the config sources as the `AuditCatalogue` document, sign it with the publisher key like any config document (a `seq` above the last one), and publish it to the config source. store@ loads it with the next snapshot.
- **The order of an upgrade.** Publish the catalogue first. Then restart the writer, because it reads the catalogue only when it starts. Then roll the emitters to the new release. The other way round, the new emitters' records are refused until the writer restarts. The table only grows within a major version, so the catalogue of the newest release also holds for the records of every older one ([0030](/decisions/0030-audit-records-and-the-usage-stream/)).
- **The local installation from the published images.** The catalogue of a checkout names release `0.0.0`, so with `SLUIS_LOCAL_IMAGES=release` the harness signs the release's `audit-catalogue.yaml` instead (`SLUIS_RELEASE_CATALOGUE`, a file or an `https` URL), and refuses one that is not for the version of the images that run: the tag the pinned images carry, which must agree with `SLUIS_LOCAL_VERSION` if that is set too ([Local](/runtimes/local/#images)). The rehearsal does this on every run that touches the release, so its smokes, which read the audit trail, fail if the catalogue is missing or wrong.

**What a failure leaves.** The order of the release job is: check, push the images that are missing (recording each digest the moment it is pushed), check them, create the draft, pull the images anonymously, make the release public. A failure before the push leaves nothing. A failure after it leaves the images on ghcr.io, and a failure from the draft on leaves a draft as well. Nothing is announced. A tag is not pushed over, as far as a check followed by a push can promise it: the registry has no conditional push, so a push by someone else between the check and the push of this job is possible, and `check-images` then fails the release because the content is not the build's (best effort, not a guarantee).

**Running the failed job again** ([REQ-SUPPLY-037](/requirements/supply/#REQ-SUPPLY-037)). Run `gh run rerun <run id> --failed -R truvity/sluis`. It runs the `release` job again with the same files of the same `build` job, which is not run again, so nothing is rebuilt. The job is two stages of one recipe (`just release-publish push`, then `finish`) with a step between them that uploads `dist/pushed.txt` as the artifact `pushed-digests-<attempt>` of the run, whether the push passed or not. `publish-images` appends the digest of an image to that file as soon as the image is pushed. A later attempt downloads the artifacts of the attempts before it and keeps an image that is in the registry **only if its digest is the one recorded**: the artifact belongs to the run and only a job of this run can write it, so a tag that someone with the right to push packages put there is not kept. The job `build` is a job of this run too, and it runs the code of every dependency, so it could create an artifact named like a record. The release job therefore trusts a record only when no artifact named `pushed-digests-<n>` exists for its own attempt or a later one (it writes those itself, after this check), and every record of an earlier attempt was created after the build job finished, which is when the first job that could write one began (this relies on the runtime token of the Actions artifact service dying with its job: a step of the build job cannot leave something behind that writes later); any other name, or an older record, stops the job before it pushes anything. The API lists a job that `gh run rerun --failed` carried over once for each attempt, with the same end time, so equal end times count as one; a build job that really ran twice has two different ones, and no record is dated by that. The upload also fails, and does not overwrite, if the name is already taken. Such a tag, one nobody recorded, or a recorded one whose digest has changed, fails the job before the first push, naming it, and that version is not used again. `check-images` then verifies every image, kept or pushed, against the archives of this build and the pinned base. A draft of the earlier attempt is replaced: the job lists the releases of the tag again just before it deletes anything, refuses if any of them is public, reads each draft by its id once more, and deletes it by that id (not by its tag, which would resolve to a release the owner published in the meantime); a release that is public is never touched. Once the new draft is made, the job requires that the tag names exactly one release, a draft, reads its id once, and counts the files and makes it public by that id. The id comes from listing the releases right after the create, not from the response of the create call (`gh release create` prints a URL and `gh api -X POST` would also create a tag that is missing, which this job must never do); if the listing lags behind the create, the job fails closed with the draft in place, and running it again replaces that draft. The delete is not conditional (the API has no "delete if still a draft"), so a window of the length of one request remains between the last read of a draft and its delete, in which the owner could publish it by hand; it is a few milliseconds, and the check before it is what makes it that short, not a guarantee. So a run that stopped because a package was not public is finished by making the package public and running the failed job again. What it does not cover: a push step that is killed (a cancelled run, a runner that dies) after an image was pushed and before the artifact was uploaded leaves a tag that no record names, and the re-run refuses it; and if the cause is in the code and not in a package, the next attempt is the next version (`v2.0.0-alpha.2`), because the tag cannot be moved. How much of the idempotent push the workflow gives: images only. The chart is not built yet, so REQ-SUPPLY-037 stays partial.

**What a pull request runs.** `Checks` has a job, `release`, that runs `just release-rehearsal` (the two halves above against a throwaway registry, then the local installation from those images with both smokes). It takes about 30 minutes with a warm cache, so a pull request or a merge group runs its steps only when a changed file is on a list of the release machinery and its build inputs: the GoReleaser configuration, the packaging files, `Justfile`, `devbox`, the manifests, modules and lock files, the toolchain, the version stamp, `deploy/release`, `deploy/vendor`, `deploy/local`, `tools/release`, the local installation and the smokes, the two workflows, and the policy schema page that an actor embeds. The code of an actor or a driver is not on the list. That is a bet, not a proof: the job `arm64` builds every executable with the same toolchain and `code` and `smokes` test it, but they build the Rust workspace in one run, so Cargo unifies features across packages, and the release builds each package alone, with `cargo auditable` and remapped paths. A change that compiles only because a sibling enables a feature would pass them. The last step of the job `code` runs `just rust-check-isolated`, which checks each Rust package the change can affect alone (about 10 to 20 seconds each when warm, about a minute if every package is affected by a change to `Cargo.lock` or a kit); what it cannot catch shows first on the push to `main`, which always runs the full job, and the gate refuses that commit. A push to `main` always runs the job in full, and the gate above requires that run.

The workflow has an empty permission block at its top, and only its `release` job can write ([REQ-SUPPLY-033](/requirements/supply/#REQ-SUPPLY-033), [REQ-SUPPLY-041](/requirements/supply/#REQ-SUPPLY-041)); its checkouts keep no credential ([REQ-SUPPLY-042](/requirements/supply/#REQ-SUPPLY-042)); and no cache is restored, so a release builds from the sources and the locked dependencies alone. Tests over the workflow files hold those rules.

## GitHub Releases

GitHub Releases is the immutable record. Each release holds the same files as the R2 version directory. If a file on R2 and a file on the release differ, the release is right.

## Compatibility

The artifacts of one release are built, tested and shipped together, and each also works with those of the previous release of the same major version, so a rolling deployment can run two neighbouring releases at once and a rollback needs no migration ([0015](/decisions/0015-evolution-and-compatibility/#n-and-n-1-inside-a-major-version)). Between releases, compatibility follows semantic versioning ([0013](/decisions/0013-release-train-packaging-and-distribution/#compatibility-between-releases), [#1715](https://github.com/truvity/sluis/issues/1715)).
