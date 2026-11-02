# 0055 — FAPI 2.0 is a profile a client declares, with PAR, DPoP, private-key client authentication and its own signing algorithm, and sender constraint is declared per audience

**Status:** Accepted
**Layer:** CIAM module
**Date:** 2026-11-02

Proposal: [issue #1025](https://github.com/truvity/sluis/issues/1025).

## Context

Some relying parties of a customer-identity installation, a regulated entity's among them, need the FAPI 2.0 Security Profile: authorization by pushed request, tokens bound to a key, clients that authenticate with a key, the issuer in the response, and algorithms the profile allows. The work is split over [#912](https://github.com/truvity/sluis/issues/912) (the features), [#929](https://github.com/truvity/sluis/issues/929) (the conformance plans) and [#1025](https://github.com/truvity/sluis/issues/1025) (this record). The board holds all three in the customer-identity milestone while the roadmap lists FAPI under "Later" and its done-when does not name it. [0006](/decisions/0006-identity-issuers-audiences-and-sign-in/#optional-openid-flows) says FAPI 2.0 comes after the parity milestone, which is where the customer-identity milestone sits.

Two statements disagree on binding. Threat T-1 says tokens "are sender-constrained"; [0006](/decisions/0006-identity-issuers-audiences-and-sign-in/#subjects) and [0028](/decisions/0028-grants-come-from-a-declared-vocabulary-and-a-token-carries-fixed-claims-for-one-audience/#binding) say an audience that declares no binding gets a bearer token, because AWS web identity, the Kubernetes API server and Argo CD accept bearer JWTs only. FAPI 2.0 also does not allow ES384, which is sluis's default algorithm ([0012](/decisions/0012-cryptography-and-authority-keys/#algorithms)); [#912](https://github.com/truvity/sluis/issues/912) lists PS256, ES256 and EdDSA as the ones to support.

## Decision

### Binding is declared per audience

- **Each audience declares its binding: none, DPoP or mutual TLS.** None gives a bearer token without `cnf`, the default; DPoP gives a token with `cnf.jkt`; mutual TLS gives `cnf.x5t#S256`. A DPoP proof sent by a client whose profile does not use DPoP is refused ([REQ-TOKEN-012](/requirements/token/#REQ-TOKEN-012)).
- **T-1 is read that way.** A token is sender-constrained where its audience declares a binding; a bearer audience has the token's short lifetime as its only bound, and the threat model says so.

### The profile

A client or an audience may declare `profile: fapi2`. Then `sluis config check` requires, and the token and authorization endpoints enforce:

- **Pushed authorization requests (RFC 9126).** The authorization endpoint accepts only a `request_uri` from a PAR call; a `request_uri` is single-use and short-lived. A "PAR required" switch exists for the client and for the installation.
- **PKCE with S256, the authorization code flow only,** exact redirect URI matching, and the `iss` response parameter of RFC 9207.
- **Client authentication by `private_key_jwt`** or mutual TLS, never a client secret. The client's public key is in its record; sluis holds no key of the client, and the assertion rules of [REQ-CLIENT-017](/requirements/client/#REQ-CLIENT-017) to [REQ-CLIENT-019](/requirements/client/#REQ-CLIENT-019) (audience, lifetime of at most 60 seconds, a `jti` accepted once) are enforced as MUST for this profile.
- **A sender-constrained access token: DPoP first,** with the server-provided nonce the plan requires. Mutual TLS follows its own consumer ([REQ-CLIENT-014](/requirements/client/#REQ-CLIENT-014)).
- **Its own signing algorithm: ES256 first.** The profile's audience signs with an ES256 key of the boundary, a key of its own purpose beside the ES384 token key, in the key set under its own `kid`. PS256 and EdDSA are added when a client needs them and the key store offers them. The default stays ES384 ([REQ-TOKEN-019](/requirements/token/#REQ-TOKEN-019)). Algorithm keys are per boundary, never per tenant ([0047](/decisions/0047-a-customer-identity-installation-is-a-front-a-few-customer-boundaries-and-key-less-tenants/)).
- **Signed request objects (RFC 9101) are accepted** from a client of the profile that sends them. Response signing and signed introspection, the parts of FAPI 2.0 Message Signing, are built with the first relying party that requires them; until then discovery does not advertise them and a request object is refused as it is today.
- **Details the plan checks,** such as the exact nonce behaviour, are implemented as the pinned revision of the plan needs and recorded in the standards register.

### Claims of conformance

sluis claims a FAPI 2.0 plan only when it passes ([Conformance](/standards/conformance/)). The first plan is the FAPI 2.0 Security Profile OP plan for the variant above (DPoP, `private_key_jwt`, PAR); Message Signing follows with its relying party. sluis is not strong customer authentication ([REQ-CIAM-009](/requirements/ciam/#REQ-CIAM-009)).

### The roadmap and the board

The FAPI 2.0 Security Profile is in the customer-identity milestone: its done-when gains the profile for clients that declare it, [#912](https://github.com/truvity/sluis/issues/912), [#929](https://github.com/truvity/sluis/issues/929) and [#1025](https://github.com/truvity/sluis/issues/1025) stay in that milestone, and the roadmap's "Later" list drops FAPI.

## Consequences

- A regulated relying party gets the profile it asks for by declaring it, and nobody else pays for it: the default clients keep ES384 and bearer tokens.
- The profile adds an ES256 key per boundary that uses it, certified like the other token keys, so a yearly re-signing item per boundary that declares the profile.
- Clients of the profile hold keys, and a lost client key is that client's problem to rotate by a changed record.
- Requirements: [REQ-CLIENT-035](/requirements/client/#REQ-CLIENT-035), [REQ-CLIENT-036](/requirements/client/#REQ-CLIENT-036), [REQ-CLIENT-037](/requirements/client/#REQ-CLIENT-037), [REQ-CLIENT-038](/requirements/client/#REQ-CLIENT-038), [REQ-CLIENT-039](/requirements/client/#REQ-CLIENT-039), [REQ-CLIENT-040](/requirements/client/#REQ-CLIENT-040), [REQ-TOKEN-040](/requirements/token/#REQ-TOKEN-040), [REQ-TOKEN-041](/requirements/token/#REQ-TOKEN-041) are added.

## Roads not taken

- **Sender-constrained tokens for every audience.** AWS web identity, the Kubernetes API server and Argo CD accept bearer tokens only; they would stop working.
- **FAPI 2.0 as an installation-wide mode.** Every client would pay for the strictest profile, and the bearer relying parties would break.
- **ES384 under the profile.** The profile does not allow it, and a plan would fail.
- **Mutual TLS first.** It needs the edge to pass the client certificate to sluis, which a Cloudflare tunnel or a plain gateway may not; DPoP works behind any edge.
- **Message Signing now.** No relying party asks for signed responses, so it would be code without a consumer.
- **A key per client for the signing algorithm.** It is a key per tenant in effect; the key is per boundary.

## Follow-ups

- The profile, PAR, DPoP and `private_key_jwt` support: [#912](https://github.com/truvity/sluis/issues/912).
- The FAPI 2.0 conformance plans: [#929](https://github.com/truvity/sluis/issues/929).
