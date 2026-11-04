---
title: Conformance
description: "How sluis proves the standards it claims: the OpenID Foundation test plans v2 targets, how they run in CI per installation, and when certification is planned."
status: target
sidebar:
  order: 1
---

A claim of conformance is only worth what the test behind it is worth. sluis claims a profile only when a published test suite passes it, keeps the proof in the repository, and runs the suite often enough that the claim stays true. The standards themselves are in the [register](/standards/). The umbrella issue is [#850](https://github.com/truvity/sluis/issues/850).

## Which plans v2 targets

The plan names are the OpenID Foundation's; the exact plan identifiers are confirmed against the current suite release before the work on each starts. v2 keeps parity with v1 on the first four.

| Plan | What it covers | Status |
|---|---|---|
| Config OP | The discovery document and the key set | First wave |
| Basic OP | The code flow with PKCE, the ID token, UserInfo and refresh, for static client registration with discovery | First wave |
| RP-Initiated Logout OP | `end_session`, `id_token_hint`, post-logout redirects; every logout submission must include it | First wave |
| Back-Channel Logout OP | The signed logout token, its two-minute expiry and no `nonce` | First wave |
| Form Post OP | `response_mode=form_post` for the code flow; the auto-submit page has a strict CSP with a per-response nonce | Second wave, in the same pipeline ([#979](https://github.com/truvity/sluis/issues/979)) |
| WebAuthn, with a browser virtual authenticator and a software authenticator library | The passkey ceremony | With passkeys ([#885](https://github.com/truvity/sluis/issues/885)) |
| Relying-party plans (Basic RP, Config RP and the logout RP plans that apply) | sluis as a client of an upstream provider, through the [generic OIDC upstream](/integrations/oidc-upstream/) | Later ([#930](https://github.com/truvity/sluis/issues/930)) |
| FAPI 2.0 Security Profile (Final) OP | The sender-constrained variants sluis supports (DPoP; mutual TLS only if added); needs PAR, `private_key_jwt`, DPoP, RFC 9207 and, for some variants, JAR | The customer-identity milestone, after parity ([#929](https://github.com/truvity/sluis/issues/929)) |
| FAPI 2.0 Message Signing OP | Signed requests and responses, on top of the Security Profile | With its first relying party ([#929](https://github.com/truvity/sluis/issues/929)) |
| CIBA, poll mode | Approval with a passkey on the approving device | Later: after the parity milestone, once a real consumer exists ([#980](https://github.com/truvity/sluis/issues/980)) |

The optional plans follow [ADR 0017](/decisions/0017-identity-and-sign-in/).

### The plans sluis does not claim

Users and auditors should not infer support from silence. These are not planned unless a decision changes them:

| Plan | Why not |
|---|---|
| Implicit OP and Hybrid OP | The implicit and hybrid response types are not served; code with PKCE replaces them. |
| Dynamic OP | Dynamic client registration is refused; Client ID Metadata Documents admit self-describing clients from allow-listed origins. |
| Session Management OP | A browser iframe mechanism. |
| Front-Channel Logout OP | Hidden iframes depend on third-party cookies, which browsers block. Back-channel logout is the path, and discovery does not advertise front-channel logout. |
| 3rd Party-Initiated Login OP | A sign-in starts at the client. Revisited if the console gets an app launcher. |
| FAPI 1.0 Advanced | Superseded by FAPI 2.0. |

A suite module may skip because the discovery document says a feature is not served. That is the intended outcome: **discovery is truthful**, and a skip is acceptable only when discovery explains it.

## How the tests run in CI

Conformance is a pipeline, not a ritual, because a run done by hand rots. The pipeline is [#931](https://github.com/truvity/sluis/issues/931), part of the first working version.

- **The suite** is a self-hosted instance of the open-source OpenID Foundation conformance suite.
- **Against the installations.** Each plan runs against the [local](/runtimes/#local) installation and the [lambda](/runtimes/#lambda) installation, through the [installation test harness](https://github.com/truvity/sluis/issues/877). The customer installation on [Kubernetes](/runtimes/#kubernetes) (EKS) runs the full set: OpenID Connect, FAPI 2.0 and the customer-identity plans ([0011](/decisions/0011-runtimes-and-installations/#kubernetes), [0038](/decisions/0038-fapi-2-profile/)). The cloud installations run only in a restricted private runner group with no pull-request trigger ([#891](https://github.com/truvity/sluis/issues/891)).
- **When.** On pull requests that touch protocol code, against the local installation; nightly and on every release, the full set against the lambda installation and against the Kubernetes (EKS) customer installation. A change that breaks a claimed plan fails CI.
- **The inputs.** sluis holds no accounts, even in tests. The harness signs people in through a real identity provider, Keycloak in a container on every pull request, and nightly against two free cloud tenants: Google Cloud Identity Free and Microsoft Entra ID Free ([ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)), and the harness clients and that provider's realm are declared in a reviewed file. Passkeys are tested with a browser's virtual authenticator and a software authenticator library. The product carries no test code: the server under test is the released build, and only configuration differs.
- **The outputs.** Logs and result bundles are archived per release. Result exports hold client secrets, so what is published is the plan, the variant, the version and the counts.
- **The attended steps.** Some modules end at a page the suite cannot judge, such as an error page the issuer must show. The pipeline either compares the page automatically or hands it to a reviewer; which, is settled in [#931](https://github.com/truvity/sluis/issues/931).

## What certification means, and when

Passing the suite on your own and **certification** are different things. In the OpenID Foundation's certification programme an implementer submits the suite's results for a **specific version** and **profile**, with a statement, and the Foundation lists the implementation as certified for it. A logout submission must include RP-Initiated Logout plus one other logout profile.

Certification is not a security audit, not a FIPS validation (sluis v2.0 has no FIPS build; see the [register](/standards/#crypto-and-compliance)), and not a promise about the next release. An external penetration test and a certification are conditions for calling a customer-identity profile production-ready.

The submission package and the self-certification statement are assembled by a script from a release's archived results, so a submission is a by-product of a release, not a separate project.

:::note[Proposed]
Certification comes after v2 passes the first-wave plans in CI on a tagged release, and not before v2 reaches parity with v1; there is no date ([#931](https://github.com/truvity/sluis/issues/931)). FAPI 2.0 certification follows when PAR, DPoP and `private_key_jwt` ship ([#929](https://github.com/truvity/sluis/issues/929)).
:::

## Conformance beyond OpenID

OpenID plans cover the protocol surface. Other suites cover what sits underneath.

- **The port conformance suite** ([#851](https://github.com/truvity/sluis/issues/851)). Every driver of every port of a holder passes the port's behavioural suite through its `conformance` command, in `kits/conformance`, per driver and per kit language (Go and Rust). A driver passes the suite or it is not a driver, and the in-memory engine passes it too ([0005](/decisions/0005-the-store/#drivers)). A new driver, or a fork's, is accepted when it passes.
- **The kits' conformance vectors** ([#861](https://github.com/truvity/sluis/issues/861)). The two kits, Go and Rust, pass one conformance suite ([0012](/decisions/0012-the-language-follows-the-executable/#the-rules), R9): Connect over Unix sockets with peer credentials, the typed store client, configuration from the generated JSON Schema, the CLI conventions and OpenTelemetry. One set of vectors runs against both, including which documents are valid under the generated JSON Schema ([Configuration](/concepts/data/#configuration)).
- **Minters.** A shared test for every credential-minter integration: create a credential, use it, let it expire, and sweep.
- **Policy tests** ([#852](https://github.com/truvity/sluis/issues/852)) for the grant naming, the matchers and the lifetimes.
- **The isolation vectors** ([#950](https://github.com/truvity/sluis/issues/950)). Every control of the [threat model](/security/threat-model/) has vectors in the [isolation area](/requirements/iso/) of the requirements catalogue. Each is an attempt that must fail at a named layer while the harness switches the other layers off. A vector that is refused even with every layer off is void, so a passing run proves each layer on its own.
- **The deny matrix.** The kind registry and the actor registry generate tests that prove an actor cannot do what they do not say: every pair of actors is tried against both layers of the call graph ([Architecture](/architecture/), [0003](/decisions/0003-units-transports-and-fusion/#the-call-graph)).

## How much of the catalogue an external suite checks

The [requirements catalogue](/requirements/) says, for each requirement, how it is verified. A requirement is **externally checked** when its verification includes a published conformance suite or a set of test vectors, rather than only a test of sluis's own or a manual review. The requirements lint computes the figures below from the catalogue and fails when they are stale.

<!-- coverage:begin (generated by site/scripts/check-requirements.mjs with its write-coverage flag; do not edit) -->
| Requirements | Externally checked | Share |
|---|---|---|
| All, not withdrawn (1112) | 229 | 20.6% |
| MUST (1072) | 213 | 19.9% |
<!-- coverage:end -->

## Where to follow it

[#850](https://github.com/truvity/sluis/issues/850), OpenID conformance; [#851](https://github.com/truvity/sluis/issues/851), the port suite; [#929](https://github.com/truvity/sluis/issues/929), FAPI 2.0; [#930](https://github.com/truvity/sluis/issues/930), the relying-party plans; [#931](https://github.com/truvity/sluis/issues/931), the pipeline; [#950](https://github.com/truvity/sluis/issues/950), the isolation vectors.
