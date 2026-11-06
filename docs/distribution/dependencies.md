---
title: Runtime dependencies
description: "The one matrix of what sluis needs outside its executables, in every form: packages, the boards deploy, container images, Kubernetes and Lambda."
status: partial
sidebar:
  order: 2
---

A sluis executable is static or nearly so, but the host or the image around it is not: the card driver needs a card service, a deploy needs `tar` on the board, a package needs a systemd that knows encrypted credentials. This page is the **one list** of those dependencies and of how each distribution form satisfies each of them. Package metadata, image contents and layer contents are checked against it ([0013](/decisions/0013-release-train-packaging-and-distribution/#packaging-per-runtime), `REQ-DEPLOY-038`); a change that adds a dependency to the code or the deploy adds its row here in the same pull request.

## What is built today

The package columns of the matrix are the specification for packages that do not exist yet. They are not an inventory.

| Form | Built today? | Where it is defined |
|---|---|---|
| Packages (`.deb`, `.rpm`) | No. The repository has no nfpm file; the build system is [#860](https://github.com/truvity/sluis/issues/860) | [Packages](/distribution/packages/#packages-by-holder-and-module) |
| Boards deploy (executables, generated units and a stage over ssh) | Yes | `deploy/boards/`, [Bare-metal](/runtimes/bare-metal/#deploy-and-prove-on-three-boards) |
| Container images | Local installation only: `deploy/local/Dockerfile` (distroless static, one executable) and `deploy/local/Dockerfile.rqlite`. The release images on GHCR are not built | [Local](/runtimes/local/), [OCI images](/distribution/packages/#oci-images) |
| Kubernetes chart | No ([#876](https://github.com/truvity/sluis/issues/876)) | [Kubernetes](/runtimes/kubernetes/#packaging-and-the-baseline) |
| Lambda zips, layers, extensions | No | [Lambda zips](/distribution/packages/#lambda-zips), [Serverless](/runtimes/serverless/) |

## How to read the matrix

- **Depends** is a package that does not work without the dependency, so the package manager installs it. **Recommends** is installed by default and may be left out. **Suggests** is never installed on its own. In an rpm these are `Requires`, `Recommends` and `Suggests`.
- **A dependency sits on the narrowest package that needs it.** The card service is a dependency of `sluis-driver-yubikey-piv`, not of `sluis`, so a KMS-only host installs no pcscd ([0013](/decisions/0013-release-train-packaging-and-distribution/#packaging-per-runtime)).
- **Board image** means the operating system image of the board must carry it. The boards deploy installs no package of the card path: it checks, and refuses naming the packages of the board's family before it writes a file. The one package it installs is rqlite.
- **Image** means the container image carries it. An image holds one executable at the package's path; a library goes into the base layer, and a daemon runs outside the container, on the host.
- **n/a** means the form never needs it.

## The matrix

The package cell reads `deb / rpm`. The rpm column covers Rocky Linux 10 and Amazon Linux 2023; a card is not used on Amazon Linux 2023.

| Dependency | Needed by | Packages (deb / rpm) | Boards deploy | Container image | Kubernetes | Lambda |
|---|---|---|---|---|---|---|
| **pcscd**, the smart-card service | the `yubikey-piv` card driver | Depends `pcscd` / `pcsc-lite` | Board image; checked, refused if missing | n/a: the daemon runs on the host and its socket is mounted. The card driver has no image yet | n/a: no card on Kubernetes | n/a: no card on Lambda |
| **CCID driver** for the reader | the card driver (through pcscd) | Depends `libccid` / `pcsc-lite-ccid` | Board image; checked, refused if missing | n/a: on the host | n/a | n/a |
| **libpcsclite**, the client library | the card driver, linked by cgo | Depends `libpcsclite1` / `pcsc-lite-libs` (pulled by pcscd; the dependency tool also derives it from the executable) | Board image, with pcscd; not checked on its own | The pinned `libpcsclite1` in a distroless base with glibc ([0013](/decisions/0013-release-train-packaging-and-distribution/#packaging-per-runtime)); not built | n/a | n/a |
| **polkit** | pcscd 2.x on Ubuntu 26.04 and Rocky 10 asks it about every client | Depends `polkitd` / `polkit` | Board image; checked where pcscd ships its policy file | n/a: on the host | n/a | n/a |
| **yubikey-manager** (`ykman`) | operations only: factory reset or rollback of a test card. No sluis code, script or unit calls it | Suggests `yubikey-manager` / `yubikey-manager` (EPEL; availability on Rocky 10 to be confirmed) | Operator's choice, on the workstation or the board; the deploy never uses it | n/a | n/a | n/a |
| **systemd 252 or later**, with `systemd-creds`, `systemd-sysusers` and `systemd-tmpfiles` | every unit: `LoadCredentialEncrypted=`, the generator, users and directories | Depends `systemd (>= 252)` / `systemd >= 252` | Board image; the deploy refuses a board below 252 or without `systemd-creds` | n/a: no systemd | n/a | n/a |
| **glibc 2.34 or later** | the card driver only; every other executable is static (musl) | Depends `libc6 (>= 2.34)` / `glibc >= 2.34`, derived from the executable | Board image; the native build and a test hold the executable to the symbols of 2.34 | A glibc base (distroless base, glibc 2.36) for the card driver; the others run on distroless static | n/a: the card driver does not run there | n/a: the executables are static |
| **tar** | the boards deploy: the stage reaches the board as a tar stream | n/a: the package manager unpacks its own packages | Board image; `boards-deploy` refuses a board without it, before it sends anything. Ubuntu 26.04 has it; the Rocky 10 image of the boards lacks it | n/a | n/a | n/a |
| **audit** (`ausearch`) | the denial check of an SELinux board (`boards-avc`, run at the end of a deploy and a smoke) | deb: n/a (AppArmor). rpm: Recommends `audit` on `sluis-install-boards` | Board image on an SELinux board; the check fails when SELinux is enforcing and `ausearch` is missing. The Rocky 10 image lacks it | n/a | n/a | n/a |
| **policycoreutils-python-utils** (`semanage`, `audit2why`) | work on the SELinux policy only; the deploy does not call them | rpm: Suggests `policycoreutils-python-utils`. deb: n/a | Operator's choice. The Rocky 10 image lacks it | n/a | n/a | n/a |
| **policycoreutils** (`restorecon`) and `selinuxenabled` | the labels after a deploy | Base system on Rocky 10; no dependency declared | Base system; the deploy warns when `restorecon` is missing | n/a | n/a | n/a |
| **rqlite 10.6.6** (`rqlited`) | the `rqlite` store driver, one node per board | `sluis-driver-rqlite` ships `rqlited` under `vendor/`, so there is no external dependency | `boards-rqlite` installs the upstream `.deb` or `.rpm`, pinned by sha256 in `deploy/boards/rqlite.pins`, and refuses a package whose digest differs | The pinned release archive (version and sha256 in the `rqlite-fetch` recipe of the Justfile) on a distroless glibc base, in `Dockerfile.rqlite` | n/a: DynamoDB is the engine | n/a: DynamoDB is the engine |
| **curl** | the boards script `boards.sh`, which asks the board's own rqlite node how many data-key wraps it holds (the guard of a key switch) | n/a | Board image. Ubuntu 26.04 has no curl by default, and nothing declares or checks it: **a gap** (see below) | n/a | n/a | n/a |
| **ca-certificates** and the trust update | `sluis trust sync` writes the anchors and runs `update-ca-certificates` or `update-ca-trust` | Depends `ca-certificates` / `ca-certificates` on `sluis` | Base system | The base carries the system roots; the bundle reaches pods and containers by a mount | The bundle comes from a trust-manager source or a ClusterTrustBundle | n/a |
| **OpenSSH server** (`sshd`) | `sluis-host` writes the principals bundle that `sshd` reads; `sshd` stays stock | Recommends `openssh-server` / `openssh-server` on `sluis-host` | Board image; key-only ssh is already what the deploy uses | n/a | n/a | n/a |
| **xdg-open** | the `sluis` CLI opens the browser for a sign-in | Suggests `xdg-utils` / `xdg-utils` on `sluis` | n/a: workstation | n/a | n/a | n/a |
| **Edge connector** | `entry`, the one process with a public listener | Not a dependency: the operator installs `cloudflared` from its vendor | The operator installs `cloudflared` | The local installation's forwarder is Caddy, pinned by digest in the Compose file; it is a test service, not a sluis component | The edge relay image of the chart, or a `cloudflared` sidecar | The pinned, vendored Lambda Web Adapter in the edge layer |
| **nftables** | the per-uid egress rules generated from the actor registry | Depends `nftables` / `nftables` on the package that ships the rules, once they ship (not built) | The firewall is the image's; the deploy does not touch it | n/a | n/a: a NetworkPolicy per callee, which needs a CNI that enforces it | n/a |
| **Cluster prerequisites** | the chart: Gateway or Ingress, cert-manager, a CNI that enforces NetworkPolicy, native sidecars, the `restricted` Pod Security level | n/a | n/a | n/a | Checked by the chart before it installs ([Kubernetes](/runtimes/kubernetes/#packaging-and-the-baseline)) | n/a |
| **Rust extension, configuration layer** | a holder's drivers on AWS (AppConfig, SSM, DynamoDB, KMS) | n/a | n/a | n/a | n/a | Built by sluis: the drivers layer carries the one Rust extension and the configuration layer the signed config. Not built |

The `audit` and `policycoreutils` rows serve the default mandatory access control of each family. [REQ-DEPLOY-033](/requirements/deploy/#REQ-DEPLOY-033) wants sluis to run with no SELinux or AppArmor denial under the distribution's own policy (SELinux enforcing on Rocky, AppArmor on Ubuntu); it is about compatibility, because the default policy does not confine sluis. [REQ-DEPLOY-042](/requirements/deploy/#REQ-DEPLOY-042) is the later step: the .rpm would ship an SELinux module and the .deb an AppArmor profile.

Three things have no row because nothing on a host satisfies them: the services a driver talks to (an AWS account, DynamoDB, NATS JetStream, PostgreSQL, a Cloudflare account) are the installation's dependencies ([Runtimes](/runtimes/#installations-nodes-and-dependencies)), the libraries a Rust or Go executable links in (SQLite is bundled, TLS is rustls) are in its file, and the shell tools the boards scripts run on a board (`bash`, `timeout`, `getent`, `sudo`) are part of every base image of a supported system.

## Floors and pins

| Dependency | Value | Where it is enforced |
|---|---|---|
| systemd | 252 (Amazon Linux 2023) | `credential_floor` in `deploy/boards/remote-lib.sh`; [Supported platforms](/distribution/packages/#supported-platforms) |
| glibc, for the card driver | 2.34 (Amazon Linux 2023). The build userland is Ubuntu 22.04 (glibc 2.35) and is not a supported platform | `TestNativeExecutablesStayWithinTheGlibcFloor`, `REQ-DEPLOY-032` |
| rqlite | v10.6.6, pinned by sha256 per asset | the `rqlite-fetch` recipe of the Justfile for the local installation; `deploy/boards/rqlite.pins` for the boards |

A change to a floor or a pin changes this page and the code in one pull request.

## Gaps

These are known and not fixed here. Each is a line to close, not a decision.

| Gap | Effect | How it closes |
|---|---|---|
| **No package, no release image, no chart and no Lambda artifact exists**, so no dependency of the package, Kubernetes and Lambda columns is declared in any file | The columns are a specification. A dependency cannot be missing from a file that does not exist | The build system ([#860](https://github.com/truvity/sluis/issues/860)) writes the nfpm definitions, image definitions and layers from this page; `REQ-DEPLOY-038` stays partial until they exist |
| **`curl` on the board** is used by `boards.sh` (the data-key count of a key switch) and is neither declared nor checked. Ubuntu 26.04 has no curl by default | On such a board the guard cannot read the count and refuses the switch (it fails closed), with an error about the command rather than the missing package | Read the count with the bash-only request that `boards-rqlite` already uses for rqlite's HTTP API, so the board needs no curl; until then install `curl` on the board |
| **The card driver has no container image** | The local installation's opt-in development card cannot run in a container yet | The image on a distroless glibc base with a pinned `libpcsclite1`, built with the release images; pcscd, the CCID driver and polkit stay on the host |
| **The deploy does not check `libpcsclite1` / `pcsc-lite-libs`** on its own | None in practice: pcscd depends on it on both families | Add it to the check if a board image ever ships pcscd without it |
| **rqlite has two sources today**: the upstream package that `boards-rqlite` installs, and `rqlited` under `vendor/` in the future `sluis-driver-rqlite` package | A board that gets the package later would have two `rqlited` | The deploy drops `boards-rqlite` for the package when the package exists |
| **`yubikey-manager` on Rocky 10** is UNVERIFIED: it is in Fedora and EPEL for earlier releases | A Suggests that cannot be satisfied is harmless, but the page must not promise it | Check the EPEL 10 repository when the rpm is built |

## Where the metadata lives

Nothing declares package dependencies yet. The only metadata that exists is read from the code and checked against this page:

- `check_card_prerequisites` in `deploy/boards/remote-lib.sh` names the card packages per family: `pcscd`, `libccid` and `polkitd` on Debian and Ubuntu, `pcsc-lite`, `pcsc-lite-ccid` and `polkit` on RHEL and Rocky.
- `credential_floor` in the same file is the systemd floor.
- `deploy/local/Dockerfile` and `deploy/local/Dockerfile.rqlite` are the only images; their bases are pinned by digest.
- `deploy/boards/Dockerfile.native` and `native-build.sh` are the build userland of the card driver, not a form that sluis ships.

`tools/gen/units` holds a test (`REQ-DEPLOY-038`) that fails when the card packages, the systemd floor, the glibc floor or the rqlite version in those files differ from this page.

Facts on this page were read from the repository and from the pages it links on 2026-11-06. The tar, audit and policycoreutils-python-utils facts of the Rocky 10 image were measured on 2026-11-06 (Rocky 10.2); the absence of curl on Ubuntu 26.04 was reported by the maintainer the same day and is UNVERIFIED here.
