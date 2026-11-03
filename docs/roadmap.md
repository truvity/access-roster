---
title: Roadmap
description: Where sluis v2 is going. A core of workforce sign-on and reconcilers, two later modules, the four milestones in order, and how installations are built.
status: page
---

The roadmap lives in the `Product milestone` field of the public [sluis v2 board](https://github.com/orgs/truvity/projects/9), and the [project status](/status/) page shows how far each milestone has got. This page says what each milestone is for and when it is done; the reasoning for the order is in [ADR 0011](/decisions/0011-runtimes-and-installations/#delivery-order).

v1 keeps its own roadmap on the [sluis v1 board](https://github.com/orgs/truvity/projects/10), on `master`. New feature requests target v2 ([ADR 0001](/decisions/0001-v1-and-v2-lines/)).

## Where v2 stands

As of 2026-11-02, v2 is in the design phase and has no code. What exists are the [decision records](/decisions/), the [requirements](/requirements/) and the design pages. Root custody lives in [ritueel](https://ritueel.id), a separate project also in design. The test harness certifies its intermediates with any certificate authority that signs a PKCS#10 request; ritueel's software-root mode is the certifier the CI runs when it exists ([#1071](https://github.com/truvity/sluis/issues/1071)).

## A core and two later modules

v2 has a core and two later modules. The core is workforce single sign-on and the reconcilers: milestones 1 and 2 below. The customer-identity module (CIAM) and the quota module are later layers, each packaged so that an installation runs it only if it needs it.

An installation is one of two kinds, and the two are distinct installations of the same product, each with its own boundary, keys and state:

- A **workforce installation** signs in the people of an organisation (its employees) and reconciles its systems. It runs the core.
- A **customer installation** adds the CIAM module and brokers an external customer-identity product for the end users of several products. The core is the same in both.

Each [decision record](/decisions/) of the later modules says which module it belongs to on its `Layer` line ([the format](https://github.com/truvity/sluis/blob/main/docs/decisions/README.md#format)), and the [decision index](/decisions/) shows it, and the [installations](/runtimes/installations/#reference-installation-shapes) page lists the shapes by layer.

## Core

The core is delivered in two product milestones, in this priority order.

1. **First working version.** The local installation, plus the foundations every installation stands on. The local installation is Docker Compose on a workstation: one container per actor, built from the published images ([#1123](https://github.com/truvity/sluis/issues/1123)), with the minimal drivers (embedded SQLite state, a SQLite index, a files blob, a local lock, a spool or direct transport), software keys by default, sign-in through the generic OpenID Connect upstream tested against a real identity provider ([#1106](https://github.com/truvity/sluis/issues/1106)), and the audit log with Search ([#1120](https://github.com/truvity/sluis/issues/1120), [#1121](https://github.com/truvity/sluis/issues/1121), [#1122](https://github.com/truvity/sluis/issues/1122); [The local installation](/decisions/0011-runtimes-and-installations/#the-local-installation)).
   - **The core actors** are `entry`, `session`, `console`, `exchange`, `signer`, `policy` and `ca`. They serve the basic OpenID Connect flow (discovery and the key set, authorization with PKCE, tokens, refresh, UserInfo and revocation, form post), passkeys and step-up ([#885](https://github.com/truvity/sluis/issues/885)), and the first stage of the signing API ([#890](https://github.com/truvity/sluis/issues/890)).
   - **Root custody** reaches the installation through the hand-off to ritueel's software-root mode ([#1066](https://github.com/truvity/sluis/issues/1066), [#1071](https://github.com/truvity/sluis/issues/1071)).
   - **The foundations** are the build and release train, the contracts and the permission manifest, the driver pattern, configuration and key custody.
   - **The milestone also holds** the distribution site ([#873](https://github.com/truvity/sluis/issues/873)), the published images with checksums, SBOMs and keyless provenance ([ADR 0013](/decisions/0013-release-train-packaging-and-distribution/#signing-and-checksums), [#1124](https://github.com/truvity/sluis/issues/1124)), workload identity ([#870](https://github.com/truvity/sluis/issues/870)), federation ([#963](https://github.com/truvity/sluis/issues/963)), the verifier drivers ([#965](https://github.com/truvity/sluis/issues/965)) and the conformance pipeline against the local installation ([#1100](https://github.com/truvity/sluis/issues/1100)).
   - **Done when** the example install file for local starts under Docker Compose from the published images, and the integration tests run against it in CI.
2. **v1 parity.** Everything v1 does, and the capabilities v2 adds beside it. Parity means that the workloads that use v1 today can be wired to the new sluis, possibly in a different way or with a different configuration, not that behaviour is identical. The milestone has two gates ([ADR 0015](/decisions/0015-evolution-and-compatibility/#the-v1-parity-milestone-has-two-gates)):
   - **v1-retirement gate.** The replacements of what v1 does. **Done when** every row of the [v1 parity checklist](/features/) is `Done` or `Changed` (with its decision), the lambda and kubernetes installations are built and tested ([installations](/runtimes/installations/)), the inventory of v1's relying parties is complete, and v1's audit and billing history is handled ([ADR 0029](/decisions/0015-evolution-and-compatibility/#v1s-history)). v1 is retired when this gate holds and the fact of [ADR 0001](/decisions/0001-v1-and-v2-lines/) holds.
   - **New-capabilities gate.** What v1 never did: the SSH CA, database certificates, host enrolment, trust sync, the cert-manager issuer, the peer witness and the boards installation. **Done when** each is built and tested; the installation that needs it delivers it, and it does not hold v1 back.
## Later layers

The later layers are delivered in two more product milestones, after the core and in this order. The core does not wait for them, and a workforce installation does not carry them.

3. **CIAM upstream.** Group single sign-on: the end users of several products of one group sign in once across all of them. sluis stays a broker and hosts no customer accounts: the customer-identity product is one more OpenID Connect upstream ([OIDC upstream](/integrations/oidc-upstream/), [ADR 0031](/decisions/0031-ciam-is-a-broker/)).
   - **Done when** the generic OIDC upstream ([#916](https://github.com/truvity/sluis/issues/916)) does claim mapping per upstream, `acr` and `amr` passthrough, step-up (RFC 9470) by re-authentication at the upstream, end-user subjects with their lifecycle ([#1024](https://github.com/truvity/sluis/issues/1024)), inbound and outbound back-channel logout and rate limits per connection, and the FAPI 2.0 Security Profile is served to clients that declare it ([#912](https://github.com/truvity/sluis/issues/912), [#929](https://github.com/truvity/sluis/issues/929), [#1025](https://github.com/truvity/sluis/issues/1025)). The capacity of the Kubernetes installation is measured before any figure is promised ([ADR 0037](/decisions/0037-capacity-is-measured-before-it-is-promised/), [#878](https://github.com/truvity/sluis/issues/878)).
4. **Quota.** `quota` as a front for installations: applications ask it to admit work before it runs, confirm or cancel the usage after, and push top-ups. It runs beside an installation or on its own ([ADR 0028](/decisions/0028-audit-pieces/), [ADR 0030](/decisions/0039-quota-allowance/#the-allowance)).
   - **Done when** quota meters by default and enforces per policy rule for chosen subjects or audiences, a request counts once however often it is retried, and under strict enforcement the admitted total never exceeds the limit under concurrent requests (REQ-QUOTA-001 and REQ-QUOTA-002; work item [#915](https://github.com/truvity/sluis/issues/915)).

## Delivery order

The tested [installations](/runtimes/installations/) are built in this order:

1. **local first,** with the foundations (milestone 1).
2. **Then boards, lambda and kubernetes, built and tested in parallel.** They start when the first working version is done, and none waits for another.
   - **boards.** Three single-board computers behind a Cloudflare tunnel, a YubiKey in each node, state and index on rqlite, and audit logs on R2 with the other nodes as peer witnesses ([Bare metal](/runtimes/bare-metal/)).
   - **lambda.** AWS Lambda.
   - **kubernetes.** The one tested Kubernetes installation ([Kubernetes](/decisions/0011-runtimes-and-installations/#kubernetes)).

EC2 is a possible bare-metal installation, not a delivery target, and not tested. Other installations are possible and untested. The order is reviewed when each installation ships, and ADR 0011 records any change.

## Later

Work planned after the parity milestone is marked Later on the board. It includes CIBA, in poll mode with a passkey on the approving device, once a real consumer exists ([#980](https://github.com/truvity/sluis/issues/980)); ACME for host certificates ([#978](https://github.com/truvity/sluis/issues/978)); device login ([#855](https://github.com/truvity/sluis/issues/855)); a FIPS build variant when a customer needs one ([#868](https://github.com/truvity/sluis/issues/868)); and other clouds and stores. Garage as the boards' blob store is backlog, because it ignores conditional writes ([#982](https://github.com/truvity/sluis/issues/982)).

## Where the work is tracked

The v1 features that v2 must match are issues labelled [`parity`](https://github.com/truvity/sluis/issues?q=is%3Aissue+label%3Aparity), listed on the [v1 parity checklist](/features/). Spike results are in the decision records they settled, such as [ADR 0012](/decisions/0012-the-language-follows-the-executable/#the-spikes-are-gates), and on the issue of each spike.
