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
| Basic OP | The code flow with PKCE (or the `nonce` for a confidential client that is set to it, [0021](/decisions/0021-clients/#the-client-declaration)), the ID token, UserInfo and refresh, for static client registration with discovery | First wave |
| RP-Initiated Logout OP | `end_session`, `id_token_hint`, post-logout redirects; every logout submission must include it | First wave |
| Back-Channel Logout OP | The signed logout token, its two-minute expiry and no `nonce` | First wave |
| Form Post OP | `response_mode=form_post` for the code flow; the auto-submit page has a strict CSP that allows its one script by hash, with a `form-action` of the redirect URI's origin | Runs with the first version as a public client, in the comprehensive plan (see below); the certification plan waits for confidential clients ([#979](https://github.com/truvity/sluis/issues/979)) |
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

## What runs today

The first working version runs the suite in CI against the local installation, as a **public client** (`client_auth_type=none`). **That proves flows, not a certification profile, and the first version cannot claim to be OpenID certified.** The Basic and Form Post certification plans fix a confidential client (`client_secret_basic` and `client_secret_post`), and confidential clients are v1 parity; so the run uses the suite's comprehensive plan `oidcc-test-plan` with `client_registration=static_client`, `response_type=code` and the two response modes, and the Config plan, which has no client variant.

- **The suite** is release v5.3.4 of the open-source suite, self-hosted: the Java application, MongoDB 6.0.13 and the suite's nginx, in containers, every image pinned by digest (`tests/conformance/compose.yaml`). No account, no secret, no call outside the runner except the image pulls.
- **How it reaches sluis.** A relay on the installation's Compose network gives the suite the issuer's name and carries its bytes to the forwarder, so the suite sees the forwarder's certificate, which it trusts through a JDK trust store with the harness CA added. The suite is a relying party of the released build; nothing in the product knows about it. Two public clients, `oidf-suite` and `oidf-suite-2`, are registered in the installation's configuration, with the suite's callback addresses as redirects.
- **The browser step.** The suite needs a person to sign in. Its own scripted browser cannot give a one-time code and keeps no cookie from one visit to the next, so a runner (`tests/conformance/runner`) takes the addresses the suite asks a person to visit and has alice sign in at the identity provider's forms (`kclogin`: password and a computed one-time code), in one browser per plan, so that the identity provider's session answers later modules without a form. It then delivers the redirect to the suite, and posts the fragment the way the suite's page script does. The modules that end on a page of sluis's own (an unregistered `redirect_uri` is never redirected to) run in a second suite plan whose scripted browser reads the page for its heading and files it as the evidence the suite asks a person for; their result is REVIEW, the best the suite gives a page.
- **The table.** `tests/conformance/expected.yaml` lists every module of every plan with the result it must end in. The runner fails on any difference, in either direction: a pass that fails, a fail that passes, a skip that runs, a pass that skips, a module that does not end in time, a module the table lacks or the suite lacks. A module expected to fail also carries the words its failure must contain and the conditions that fail, so a failure for another cause is a difference; a module expected to skip carries the suite's reason. **An unexpected skip never reads as a pass.** A change that moves a result edits the table in the same pull request, with the reason; `runner draft` prints a run as lines of the table for a new suite release.
- **The plan and the client are configuration.** Each plan of the table names the suite's plan, its variant (`client_auth_type` among them), its clients (`client`, `client2`: an id, and for a confidential client the name of an environment variable that holds the secret, never the secret) and any more of the suite's plan configuration (`config`). When the installation serves a confidential client, the certification Basic plan runs by adding a plan to the table with `plan: oidcc-basic-certification-test-plan` and the client's id and `secret_env`, and by registering the client's redirects; the runner, the relay and the gate do not change. Every module that is expected to fail or to skip says in `cleared_by` which planned work should make it pass, so the table shows the progress.
- **The runner's probes.** The suite sends a valid PKCE request or none, and reads a token response as JSON without looking at its type or at an error, so the runner asks for what the suite does not, as the same public client: no challenge, the method `plain`, an unsupported `response_type` and none at the authorization endpoint (each must come back as an error at the redirect with `iss` and the client's `state`), and at the token endpoint a wrong verifier, none, and the challenge used as the verifier (each must be refused as JSON that is not cached), and the right verifier (200, JSON, `no-store`, both tokens). A probe that fails fails the run. They use a public client, which always needs PKCE, so they stay true when a confidential client that may skip PKCE joins the plans.
- **The gate.** The Go tests in `tests/conformance/runner/gate_test.go` carry the requirement tags. Each says which conditions of which module the suite must have judged a success, and which probes must have passed; they skip without a run, and `run.sh` fails when one skips or does not pass.
- **The rows.** Seven rows are proved by the gate: REQ-AUTHN-002, 005, 030, 058 and REQ-TOKEN-010, 013, 030. **They stay `partial` for now** (`external-suite-not-run`), because `Conformance` is not a required check, so a red run cannot stop a merge, and a row is `done` only where a failing test would. The flip is part of the change that joins the job to the shared `checks` gate. Each row's verification says what exactly is measured: REQ-AUTHN-005 is one code response and five error responses, not every error; REQ-AUTHN-058 notes that a request-object error comes back as a GET in the form_post plan (a suite limit); REQ-TOKEN-013 is the code-flow ID token only, whose `aud` is the client's id as a string (measured in the suite's log).
- **What the suite shows today (2026-11-07, 73 module runs in three plans).** Four modules pass in the default and form_post plans together (the PKCE module and `oidcc-response-type-missing`, in each). Six end in REVIEW (the three error-page modules, in each). Thirteen skip, for a reason the table states: five scope modules and `oidcc-alternate-happy-flow`, because `scopes_supported` lists `openid` only (name and email claims wait for the upstream's claims allow-list, REQ-TOKEN-006), and the unsigned request object module, because sluis answers `request_not_supported`. Forty-nine fail in the two comprehensive plans and the Config plan has one failed module, each for a stated reason:
  - **PKCE (forty-two).** The suite's OpenID Connect Core modules send no `code_challenge`, except `oidcc-ensure-request-with-valid-pkce-succeeds`, and sluis requires PKCE with S256 on every code request (REQ-AUTHN-002), so the authorization endpoint answers `invalid_request` and the module ends at once. OpenID Connect Core does not require PKCE, so a certified Basic OP would have to accept these requests; sluis will not. These modules are the ones that exercise `auth_time`, `prompt`, `max_age`, UserInfo and refresh. The certification plans send no PKCE either. The owner decided on 2026-11-07 that a confidential client may skip PKCE when its request carries a nonce, by a per-client setting that is off by default (a public client always needs PKCE; REQ-AUTHN-002 stays a MUST for it). Once that client exists, the certification Basic and Form Post plans run unmodified with it, and the modules that wait on PKCE are judged on their own subjects; the table says so in `cleared_by`.
  - **RS256 (two).** `oidcc-discovery-endpoint-verification` fails on `OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported`: OpenID Connect Discovery requires RS256 among the ID token signing algorithms, and sluis signs ES384 only ([0006](/decisions/0006-keys-and-sealing/)); its per-audience RS256 exception is not built. The Config OP plan stays red for that one condition, and its other 27 conditions pass.
  - **No rotation (two).** `oidcc-server-rotate-keys` waits for an operator to rotate the signing key; the runner does nothing, as the suite's own CI does, and the module fails.
  - **A prompt module (two).** `oidcc-prompt-none-not-logged-in` expects `login_required` and gets the PKCE error first.
  - **Form post and request objects (one).** `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` in the form_post plan: the module puts `response_mode=form_post` inside the request object only, sluis refuses the object without reading it and answers `request_not_supported` in the query, and the module's form-post checks come before its skip. The module source says the suite expects an OP that refuses request objects to still answer in the form_post mode.
- **When and what it costs.** The workflow `Conformance` (`.github/workflows/conformance.yaml`) runs on a push to `main` and on a pull request that touches `entry`, `session`, `signer`, the upstream adapter, the protocol files, the installation's configuration or the runner. It is a workflow of its own, not a job of `Checks`, because a path-filtered job cannot be a required check. The run itself (the suite's start, the three plans of 73 module runs, the gate) took 1 minute 38 seconds on a development machine with the images already pulled (2026-11-07), because almost every module ends at the authorization endpoint; the first pull of the three images is the larger part of a cold run. The job also builds and starts the installation and the identity provider, as the `smokes` job does, so expect about as long as `smokes` plus five minutes; the CI figure is recorded in the pull request that added the workflow, and the run on `main` is the one to watch. **Who reads it:** the maintainer who merged the change, as for any run on `main` ([After the merge](/contributing/workflow/#after-the-merge)); a red run on `main` is looked at and reported before the next change starts. `Conformance` is not a required check: a path-filtered check cannot be one, and until the confidential client lands the owner keeps it outside the merge gate; when that client exists the job joins the shared `checks` gate. When the PKCE modules run for real (with the confidential client), the plans take longer: a module that signs in costs a few seconds, and a second one-time code in the same 30-second step waits for the next step.

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

The [requirements catalogue](/requirements/) says, for each requirement, how it is verified. A requirement is **externally checked** when its verification includes a published conformance suite or a set of test vectors, rather than only a test of sluis's own or a manual review. The site build computes the figures below from the catalogue, so they are never out of date.

[[coverage-table]]

## Where to follow it

[#850](https://github.com/truvity/sluis/issues/850), OpenID conformance; [#851](https://github.com/truvity/sluis/issues/851), the port suite; [#929](https://github.com/truvity/sluis/issues/929), FAPI 2.0; [#930](https://github.com/truvity/sluis/issues/930), the relying-party plans; [#931](https://github.com/truvity/sluis/issues/931), the pipeline; [#950](https://github.com/truvity/sluis/issues/950), the isolation vectors.
