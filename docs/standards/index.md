---
title: Standards register
description: The RFCs, specifications and standards sluis v2 uses or plans to, grouped by area, with what each is used for and where it stands.
status: target
sidebar:
  order: 0
---

This is the register of the standards sluis builds on. Each row says which standard, what sluis uses it for, and where it stands in v2. How conformance is proved is on [Conformance](/standards/conformance/).

## How to read the status

| Status | Meaning |
|---|---|
| **Target in v2** | Part of the v2 design, in one of the product milestones ([Roadmap](/roadmap/)). |
| **Planned** | Intended, with an issue, but its role or design is not settled yet. |
| **Later** | Deliberately after the parity milestone, or until a named trigger or consumer. |
| **Not planned** | Deliberately not served. A row changes only by a decision. |
| **Reference only** | A document that informs a choice. sluis makes no claim of conformance to it. |

Every row is tied to a feature or a stated use, or says plainly that it is not planned or reference only. Issue numbers link to [github.com/truvity/sluis/issues](https://github.com/truvity/sluis/issues).

## OAuth 2.0 and OpenID Connect

| Identifier | Title | What sluis uses it for | Status | Notes |
|---|---|---|---|---|
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) | The OAuth 2.0 Authorization Framework | The authorization code and refresh grants and client authentication. | Target in v2 ([#775](https://github.com/truvity/sluis/issues/775), [#776](https://github.com/truvity/sluis/issues/776)) | Implicit, hybrid and client credentials are not served: a machine proves itself with a workload proof and a token exchange. |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) | Bearer Token Usage | Presenting the access token at `userinfo` and at resource servers. | Target in v2 | A bearer in the URL query is refused. |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) | Proof Key for Code Exchange (PKCE) | Binding a code to the client that asked. | Target in v2 | S256 only; `plain` is refused. Required for public clients. |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | Authorization Server Metadata | Discovery for OAuth clients, including MCP clients. | Target in v2 ([#774](https://github.com/truvity/sluis/issues/774)) | Served at the path-inserted URL too. |
| [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) | Device Authorization Grant | A person signs in on a machine with no browser. | Planned ([#855](https://github.com/truvity/sluis/issues/855)) | Headless CI and workloads use token exchange instead ([ADR 0017](/decisions/0017-identity-and-sign-in/)). |
| [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) | Token Exchange | A CI job or a workload trades its platform token for a sluis token, and a person trades a sign-in for another audience. | Target in v2 ([#782](https://github.com/truvity/sluis/issues/782)) | Access tokens only; an actor token is refused. Also the mechanism of machine enrolment and of a boundary's own sign-in. |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) | Resource Indicators | A client asks for a token for a declared resource, such as an MCP server. | Target in v2 ([#791](https://github.com/truvity/sluis/issues/791)) | The resource's registered client ID is the token's only `aud`. |
| [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) | Protected Resource Metadata | A resource server advertises sluis as its authorization server. | Target in v2 ([#822](https://github.com/truvity/sluis/issues/822), [#823](https://github.com/truvity/sluis/issues/823)) | Served by the Go library and the sidecar. |
| [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | Model Context Protocol, authorization section | sluis is the authorization server for MCP clients and servers. | Target in v2 ([#822](https://github.com/truvity/sluis/issues/822)) | Pinned to revision `2026-07-28`, the current one on 2026-11-02; sluis offers client ID metadata documents and no dynamic registration ([ADR 0021](/decisions/0021-clients/#mcp-authorization)). |
| [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) | Issuer Identification | The `iss` parameter in authorization responses. | Target in v2 | Required by some clients, and by FAPI 2.0. |
| [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) | Token Revocation | A client revokes its own refresh and access tokens. | Target in v2 ([#778](https://github.com/truvity/sluis/issues/778)) | A client can revoke only tokens it was issued. |
| [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) | OAuth 2.0 for Native Apps | The command-line sign-in on a loopback port. | Target in v2 | A loopback redirect may differ from the registered one in the port only. |
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) | Best Current Practice for OAuth 2.0 Security | The security checklist for the authorization server. | Target in v2 | Designed for a full claim: every item gets a negative test, and the claim is made when the tests exist. |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) | JWT Profile for OAuth 2.0 Access Tokens | The `at+jwt` type and claims for access tokens, so an ID token is never taken for an access token. | Target in v2 | The default access-token format conforms to the profile (REQ-TOKEN-001, REQ-TOKEN-023). |
| [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) | Pushed Authorization Requests (PAR) | Authorization requests sent by the back channel. | Target in v2, in the customer-identity milestone ([#912](https://github.com/truvity/sluis/issues/912)) | Required of a client of the FAPI 2.0 profile ([ADR 0038](/decisions/0038-fapi-2-profile/)). |
| [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101) | JWT-Secured Authorization Request (JAR) | Signed request objects. | Later | Needed for FAPI 2.0 Message Signing; until then `request_not_supported`. |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) | DPoP | Sender-constrained access tokens. | Target in v2, in the customer-identity milestone ([#912](https://github.com/truvity/sluis/issues/912)) | Declared per audience; required by the FAPI 2.0 profile ([ADR 0038](/decisions/0038-fapi-2-profile/#binding-is-declared-per-audience)). |
| [OIDC Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) | `private_key_jwt` client authentication | Confidential clients authenticate with a signed assertion. | Target in v2, in the customer-identity milestone ([#912](https://github.com/truvity/sluis/issues/912)) | Required of a client of the FAPI 2.0 profile. |
| [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) | OAuth 2.0 Step-up Authentication Challenge Protocol | Asking for a stronger sign-in for a high-privilege grant, and passing an upstream's `acr` and `amr` through. | Target in v2 ([#885](https://github.com/truvity/sluis/issues/885), [#916](https://github.com/truvity/sluis/issues/916)) | Each boundary sets its own freshness and verifies the passkey assertion over its own challenge ([threat model](/security/threat-model/)). |
| [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) | Token Introspection | Resource servers that cannot validate JWTs. | Later | Tokens are JWTs verified offline against the key set. A customer-identity deployment may need it. |
| [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) | Dynamic Client Registration | Registering clients over the wire. | Not planned | An endpoint that mints trust. [Client ID Metadata Documents](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) admit self-describing clients from allow-listed origins instead ([#792](https://github.com/truvity/sluis/issues/792)). |
| [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) | JWT Bearer Grant | | Not planned | Token exchange with a different spelling. |
| [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) | Rich Authorization Requests (RAR) | | Not planned | Refused with `invalid_request`. |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | OpenID Connect Core | Sign-in, ID tokens, UserInfo and the code flow. | Target in v2 | Query and form-post response modes. Implicit and hybrid flows, the `claims` parameter and request objects are not served. |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Discovery | The configuration document and key set every relying party reads first. | Target in v2 | Advertises only what is served. |
| [OpenID Connect Dynamic Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html) | Dynamic Registration | | Not planned | As RFC 7591. `registration` answers `registration_not_supported`. |
| [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | RP-Initiated Logout | `end_session`, with `id_token_hint` and registered post-logout redirects. | Target in v2 ([#779](https://github.com/truvity/sluis/issues/779)) | Asks the person first unless the hint names the signed-in person. |
| [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | Back-Channel Logout | A signed `logout+jwt` to clients that opt in. | Target in v2 ([#780](https://github.com/truvity/sluis/issues/780)) | Two-minute expiry, no `nonce`. |
| [OpenID Connect Core: third-party-initiated login](https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin) | Login initiated by another party | | Not planned | A sign-in starts at the client. Revisited if the console gets an app launcher ([ADR 0017](/decisions/0017-identity-and-sign-in/)). |
| [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html) | Front-Channel Logout | | Not planned | Back-channel logout is the path ([ADR 0017](/decisions/0017-identity-and-sign-in/)). |
| [OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html) | Session Management | | Not planned | A browser iframe mechanism. |
| [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html) | Form Post | Returning the authorization code in an auto-submitting form post, so it stays out of URLs. | Target in v2 ([#979](https://github.com/truvity/sluis/issues/979)) | For the code flow only, with a strict CSP and a per-response nonce on the auto-submit page. |
| [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html) | Financial-grade API 2.0 | A high-assurance profile: PAR, `private_key_jwt`, DPoP, issuer identification. | Target in v2, in the customer-identity milestone after parity ([#912](https://github.com/truvity/sluis/issues/912); conformance [#929](https://github.com/truvity/sluis/issues/929); [ADR 0038](/decisions/0038-fapi-2-profile/)) | A profile a client declares. Needs PAR, DPoP and `private_key_jwt`. Its algorithms, PS256, ES256 and EdDSA, are supported (section 5.4.1, checked 2026-10-29). |
| [FAPI 2.0 Attacker Model](https://openid.net/specs/fapi-attacker-model-2_0-final.html) | FAPI 2.0 Attacker Model | The threat model behind the Security Profile. | Reference only |  |
| [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | The OAuth 2.1 Authorization Framework (an IETF draft) | The direction of the OAuth consolidation. | Reference only | sluis follows RFC 9700 and the individual RFCs above, not the draft. |
| [OpenID Federation 1.0](https://openid.net/openid-federation-1-0-final-specification-approved/) | OpenID Federation | Trust between sluis installations and the metadata of self-describing clients. | Later | No claim until client metadata or peer trust needs it. |
| [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0-final.html) | FAPI 2.0 Message Signing | Signed requests and responses. | Later, with its first relying party ([#929](https://github.com/truvity/sluis/issues/929)) | Builds on the Security Profile and JAR. |
| [CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) | Client-Initiated Backchannel Authentication | A service asks for a person's approval on another device. | Later ([#980](https://github.com/truvity/sluis/issues/980)) | After the parity milestone, once a real consumer exists, in poll mode with a passkey on the approving device ([ADR 0017](/decisions/0017-identity-and-sign-in/)). |

## JOSE

| Identifier | Title | What sluis uses it for | Status | Notes |
|---|---|---|---|---|
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) | JSON Web Signature (JWS) | Every token sluis issues is a JWS. | Target in v2 | Verified with any standard library against the key set ([#869](https://github.com/truvity/sluis/issues/869)). |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) | JSON Web Key (JWK) | The published key set. | Target in v2 | Each entry carries an `x5c` chain down to the root ([Keys](/concepts/keys/)). |
| [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) | JSON Web Algorithms (JWA) | ES384 by default; the FAPI 2.0 set; RS256 for specific audiences. | Target in v2 | PS256 and RS256 are named exceptions to the no-RSA rule ([ADR 0006](/decisions/0006-keys-and-sealing/#named-exceptions)). PS256 on a YubiKey takes about 2.3 s per signature; PIV Ed25519 needs firmware 5.7 or newer. |
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) | JSON Web Token (JWT) | ID tokens, access tokens, workload tokens. | Target in v2 | |
| [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) | JWK Thumbprint | The `kid` of a signing key. | Target in v2 | |
| [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) | CFRG curves in JOSE (EdDSA) | Ed25519 signatures, one of the FAPI 2.0 algorithms. | Target in v2 | Not a default. |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) | JWT Best Current Practices | Algorithm pinning, `typ`, audience checks. | Target in v2 | A full claim. |
| [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964) | ML-DSA for JOSE and COSE | Post-quantum token signatures (`ML-DSA-65`). | Later ([#1029](https://github.com/truvity/sluis/issues/1029)) | Needs a JOSE library and a key store with ML-DSA. |

## PKI and certificates

| Identifier | Title | What sluis uses it for | Status | Notes |
|---|---|---|---|---|
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | X.509 Public Key Infrastructure Certificate and CRL Profile | The `ca` actor's certificates; the public keys in KMS are exported as SubjectPublicKeyInfo; roots are pinned by SPKI hash. | Target in v2 ([#913](https://github.com/truvity/sluis/issues/913)) | sluis holds intermediates only; the roots are [ritueel](https://ritueel.id)'s ([0024](/decisions/0024-root-custody-and-the-signing-api/#sluis-holds-no-root)). |
| [RFC 5280 §5](https://www.rfc-editor.org/rfc/rfc5280#section-5) | Certificate Revocation Lists | A static, published CRL. | Target in v2 | Short lifetimes are the main control; revocation lists back them. |
| [OpenSSH certificate format](https://datatracker.ietf.org/doc/draft-miller-ssh-cert/) | SSH Certificate Format (an IETF draft; OpenSSH's `PROTOCOL.certkeys`) | User and host certificates from the `ssh-ca` actor, the only SSH path in v2. | Target in v2 ([#925](https://github.com/truvity/sluis/issues/925)) | A key revocation list is published statically ([SSH](/integrations/infrastructure-access/#ssh)). |
| [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881) | ML-DSA in X.509 | Post-quantum certificate signatures. | Later ([#1029](https://github.com/truvity/sluis/issues/1029)) | |
| [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935) | ML-KEM in X.509 | Post-quantum key establishment keys in certificates. | Later ([#1029](https://github.com/truvity/sluis/issues/1029)) | |
| [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) | Automatic Certificate Management Environment (ACME) | Letting a machine ask the `ca` actor for a certificate. | Later, after the first release ([#978](https://github.com/truvity/sluis/issues/978)) | Until then hosts send a CSR to `ca` ([ADR 0023](/decisions/0023-certificate-authorities/)). |
| [RFC 7929](https://www.rfc-editor.org/rfc/rfc7929) | DANE Bindings for OpenPGP (OPENPGPKEY) | Publishing the release key in DNS. | Later | One of the publication channels that ritueel researches ([truvity/ritueel#28](https://github.com/truvity/ritueel/issues/28)); needs DNSSEC on the zone. |

## Workload identity

Machine identity follows SPIFFE. sluis is its own SPIFFE issuer; SPIRE is not deployed and is read as prior art. A trust domain is a boundary, so each environment has its own trust domain, bundle and issuer. The isolation controls that rest on these rows are in the [threat model](/security/threat-model/).

| Identifier | Title | What sluis uses it for | Status | Notes |
|---|---|---|---|---|
| [SPIFFE ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md) | The SPIFFE Identity and Verifiable Identity Document | The name of every machine identity: hosts, Kubernetes service accounts, actors and CI jobs. | Target in v2 | A full claim. Paths are `/host/<name>`, `/k8s/<cluster>/ns/<ns>/sa/<sa>`, `/sluis/<actor>` and `/ci/github/<org>/<repo>` ([Identity](/concepts/identity/)). |
| [SPIFFE Trust Domain and Bundle](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md) | The SPIFFE Trust Domain and Bundle | The per-environment trust bundle that hosts and workloads install. | Target in v2 | A full claim. Each certificate in the bundle chains to a root in the root list; a lower `spiffe_sequence` is refused. |
| [X.509-SVID](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md) | The X.509 SPIFFE Verifiable Identity Document | Host and workload certificates from the `ca` actor, and mutual TLS between actors of different boundaries. | Target in v2 ([#913](https://github.com/truvity/sluis/issues/913)) | A full claim. The SPIFFE ID comes from the requester's authenticated identity, never from the request. |
| [JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md) | The JWT SPIFFE Verifiable Identity Document | Workload tokens from the per-environment issuer, which also issues the tokens of actors on nodes. | Target in v2 | A full claim. `sub` is the SPIFFE ID. |
| [SPIFFE Federation](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md) | SPIFFE Federation | Exchanging bundles with the trust domains of other operators. | Later | Until then trust between installations is declared in config. |
| [SPIFFE Workload Endpoint](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_Endpoint.md) | The SPIFFE Workload Endpoint | A local endpoint that hands SVIDs to workloads. | Later | A workload gets its SVID by token exchange. |
| [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) | The SPIFFE Workload API | The API behind the Workload Endpoint, for standard SPIFFE client libraries. | Later | Comes with the Workload Endpoint. |

## TLS

| Identifier | Title | What sluis uses it for | Status | Notes |
|---|---|---|---|---|
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | TLS 1.3 | Raft peer traffic over mutual TLS; the edge connector's outbound connection. | Target in v2 | Go's TLS stack. Public TLS terminates at the edge. |
| [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024) | Post-quantum/traditional hybrid key agreement for TLS 1.3 | `X25519MLKEM768` and the other hybrids. | Later ([#1029](https://github.com/truvity/sluis/issues/1029)) | Follows what Go's TLS offers. |

## Signing and supply chain

| Identifier | Title | What sluis uses it for | Status | Notes |
|---|---|---|---|---|
| [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580) | OpenPGP | Detached signatures over release checksums, then signed apt and dnf metadata, through the signing API. | Target in v2 ([#874](https://github.com/truvity/sluis/issues/874), [#1074](https://github.com/truvity/sluis/issues/1074)) | Nothing is signed before ritueel's roots exist ([Release signing](/distribution/release-signing/)). apt and rpm accept ECDSA P-384 on version 4 keys (tested 2026-10-31). |
| [Sigstore cosign](https://www.sigstore.dev/) | Keyless signing and Sigstore bundles | A keyless signature on each image digest, made by the CI build with its GitHub OIDC token and no stored secret. | Target in v2 | It says how a file was built, not who vouches for it, so it does not replace the OpenPGP release key ([0013](/decisions/0013-release-train-packaging-and-distribution/#signing-and-checksums)). The signing API returns a Sigstore bundle later ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-signing-api), [#1117](https://github.com/truvity/sluis/issues/1117)). |
| [SLSA provenance](https://slsa.dev/spec/v1.0/provenance) | SLSA build provenance | GitHub build provenance attestations for each artifact. | Target in v2 ([#848](https://github.com/truvity/sluis/issues/848)) | Every release states the provenance level it claims (REQ-SUPPLY-008). |
| [SPDX](https://spdx.dev/) | Software bill of materials | An SPDX JSON SBOM per archive and per image, made by syft, with the Rust crates recorded by `cargo auditable`. | Target in v2 ([#848](https://github.com/truvity/sluis/issues/848)) | SBOM attestations are bound to the artifacts ([0013](/decisions/0013-release-train-packaging-and-distribution/#signing-and-checksums)). |
| [in-toto](https://in-toto.io/) | Attestation framework | The statement format of the provenance attestations. | Target in v2 ([#848](https://github.com/truvity/sluis/issues/848)) | The GitHub attestations are in-toto statements. |

## Crypto and compliance

| Identifier | Title | What sluis uses it for | Status | Notes |
|---|---|---|---|---|
| [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) | Security Requirements for Cryptographic Modules | The algorithms stay within the FIPS-approved set (P-384 ECDSA, AES-256-GCM, HKDF-SHA384, SHA-384, and the named exceptions), so that a FIPS build can be added. | Later: a build variant when a customer needs it ([#868](https://github.com/truvity/sluis/issues/868)) | **sluis v2.0 has no FIPS mode and no certified build, and makes no FIPS 140-3 claim** ([ADR 0006](/decisions/0006-keys-and-sealing/#algorithms)). The variant would use Go's FIPS module and `aws-lc-rs` in FIPS mode. |
| [NIST SP 800-90A](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final), [90B](https://csrc.nist.gov/pubs/sp/800/90/b/final), [90C](https://csrc.nist.gov/pubs/sp/800/90/c/final) | Random bit generation | Go's `crypto/rand` (the OS random source); `sluis doctor` checks the platform. | Target in v2 (the platform checks); the SP 800-90A generator comes with a FIPS variant | SP 800-90C does not require mixing in KMS or YubiKey randomness, so sluis does not. |
| [age](https://github.com/C2SP/C2SP/blob/main/age.md) | age encryption | Not used. The backup archive is encrypted under a key of its own in the FIPS-approved set, and has a reference page with test vectors. | Not planned | age uses X25519 and ChaCha20-Poly1305, which are outside the approved set, and the recovery recipient is P-384 ([0006](/decisions/0006-keys-and-sealing/#roads-not-taken)). |
| [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) | Hybrid Public Key Encryption (HPKE) | Encrypting a machine's enrolment end to end through the edge. | Target in v2 | The enrolment public key reaches hosts as a certificate in the trust bundle, issued by the boundary's intermediate. The suite follows the P-384 default. |
| [PIV (NIST SP 800-73)](https://csrc.nist.gov/pubs/sp/800/73/4/upd1/final) and the OpenPGP card | Smart-card interfaces on a YubiKey | Hardware-held keys for the intermediates and the node keys, including an OpenPGP signing subkey in a PIV slot. | Target in v2 ([#914](https://github.com/truvity/sluis/issues/914)) | The `yubikey-piv` driver, behind key@ with exclusive card access ([the slot plan](/decisions/0006-keys-and-sealing/#the-slot-plan)). The OpenPGP applet is not used on a node. |
| [TCG TPM 2.0](https://trustedcomputinggroup.org/resource/tpm-library-specification/) | Trusted Platform Module | Optional sealing and node identity. | Later ([#884](https://github.com/truvity/sluis/issues/884)) | Not part of the first release. |
| [Wycheproof](https://github.com/C2SP/wycheproof), CCTV and [x509-limbo](https://github.com/C2SP/x509-limbo) | Test vectors for cryptographic implementations and certificate path validation | Tests of the JOSE package and the `ca` actor. | Target in v2 ([#869](https://github.com/truvity/sluis/issues/869), [#913](https://github.com/truvity/sluis/issues/913)) | Test vectors, not a standard sluis conforms to. |
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) | ML-KEM, ML-DSA, SLH-DSA | The algorithms behind RFC 9964, 9881, 9935 and 10024. | Later ([#1029](https://github.com/truvity/sluis/issues/1029)) | Go's FIPS module v1.0.0 does not include ML-DSA. |
| [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final) | Transition to Post-Quantum Cryptography Standards | The timeline for the post-quantum plan. | Reference only | The trigger for the post-quantum rows: RSA, ECDSA and EdDSA deprecated after 2030, disallowed after 2035. |
| Post-quantum readiness | A single place for the post-quantum rows | ML-DSA certificates and tokens, the hybrid TLS key agreement, and the Merkle Tree Certificates log. | Later ([#1029](https://github.com/truvity/sluis/issues/1029)) | The rows that name this issue are taken up together. A post-quantum root is [ritueel](https://ritueel.id)'s. |
| [CNSA 2.0](https://en.wikipedia.org/wiki/Commercial_National_Security_Algorithm_Suite) | NSA Commercial National Security Algorithm Suite 2.0 | A secondary reference for parameter choices (ML-DSA-87, ML-KEM-1024). | Reference only | Linked to a secondary source. |

## Transparency and audit

sluis follows the published specifications and invents no format. The audit checkpoints, the witnesses and the issuance log of the `ca` actor use the C2SP family. See [Audit](/concepts/audit/).

| Identifier | Title | What sluis uses it for | Status | Notes |
|---|---|---|---|---|
| [C2SP signed-note](https://github.com/C2SP/C2SP/blob/main/signed-note.md) | Signed note | The envelope of an audit checkpoint. | Target in v2 | Audit checkpoints are signed with the P-256 log key over SHA-256 (signature type 0x02), as generic witnesses verify them; the issuance log's checkpoints use a P-384 key ([0006](/decisions/0006-keys-and-sealing/#named-exceptions)). |
| [C2SP tlog-checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md) | Transparency log checkpoint | The signed head of the audit log: size and root hash. | Target in v2 | |
| [C2SP tlog-tiles](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md) | Transparency log tiles | The layout of the log as static tiles in a blob store. | Target in v2 | Static objects, readable without a server. |
| [C2SP tlog-cosignature](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md) | Transparency log cosignature | A witness's signature over a checkpoint. | Target in v2 | Witness keys are Ed25519 or ML-DSA-44. |
| [C2SP tlog-witness](https://c2sp.org/tlog-witness) | Transparency log witness protocol | How a witness is asked to cosign a checkpoint. | Target in v2 | The `peer` and `external` witness drivers. A witness is optional. |
| [C2SP static-ct-api](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md) | Static Certificate Transparency API | The issuance log of the `ca` actor: every X.509 certificate it issues is logged, and the log is witnessed. | Target in v2 ([#913](https://github.com/truvity/sluis/issues/913)) | sluis runs its own log; it does not monitor the public ones. |
| [C2SP mtc-tlog](https://github.com/C2SP/C2SP/blob/main/mtc-tlog.md) | Merkle Tree Certificates log | The log format for Merkle Tree Certificates. | Later ([#1029](https://github.com/truvity/sluis/issues/1029)) | Comes with the post-quantum rows. |
| [RFC 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962#section-2.1) | Merkle hash trees | The tree over audit records and inclusion proofs. | Target in v2 | |
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) | JSON Canonicalization Scheme | Canonical audit records and usage facts: the bytes that are hashed, stored and returned. | Target in v2 | The writer checks that the bytes are canonical. |
| [OCSF](https://schema.ocsf.io/) 1.x | Open Cybersecurity Schema Framework | The audit record: every record is an OCSF event in a core class, with the sluis facts that OCSF has no attribute for in one `unmapped.sluis` object. | Target in v2 ([#841](https://github.com/truvity/sluis/issues/841)) | No OCSF extension in 2.0 ([ADR 0030](/decisions/0030-audit-records-and-the-usage-stream/)). The first release pins 1.9.0 (2026-08-03), current when checked on 2026-11-01. |
| [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905) | Network Time Protocol | The audit clock check. | Target in v2 | |
| [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) | Time-Stamp Protocol | An optional external anchor for sealed periods, from a time-stamp authority. | Later | A MAY (REQ-AUDIT-031); some compliance profiles ask for it. |

## Data and interfaces

| Identifier | Title | What sluis uses it for | Status | Notes |
|---|---|---|---|---|
| [JSON Schema 2020-12](https://json-schema.org/draft/2020-12) | JSON Schema | The schema of the bootstrap file, of Helm values and of external configs, generated from Protobuf; and the schemas of audit records, generated from each project's action table and enforced by the writer ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-action-table-is-code-and-the-release-identifies-it)). | Target in v2 | Generated from Protobuf, the only schema source, and compared with a golden file in CI. Protobuf with protovalidate is the authority in code; the schema is a derived subset for editors and `helm lint` ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf), [#1177](https://github.com/truvity/sluis/issues/1177)). |
| [ConnectRPC](https://connectrpc.com/), gRPC and Protobuf | Remote procedure calls | Every component boundary, and the public API; the same contract travels over a Unix socket, a Lambda invoke and an in-cluster call ([0003](/decisions/0003-units-transports-and-fusion/#transports)). | Target in v2 | A TypeScript client library on `connect-es` is a deliverable ([#917](https://github.com/truvity/sluis/issues/917)). |
| [OpenTelemetry](https://opentelemetry.io/docs/specs/otlp/) and OTLP | Traces and metrics | Each actor uses the OpenTelemetry API and SDK directly, with no telemetry port; OTLP over HTTP. | Target in v2 ([#836](https://github.com/truvity/sluis/issues/836)) | Standard `OTEL_*` variables; an allowlist redaction processor keeps secrets and personal data out. Logs go to stderr. |
| [W3C Trace Context](https://www.w3.org/TR/trace-context/) | Trace Context | Carrying a trace across processes. | Target in v2 | An audit record may carry the trace id, one way only. |
| [CloudEvents 1.0](https://github.com/cloudevents/spec) | CloudEvents (CNCF) | The usage stream: each usage fact of a metered action is a CloudEvents event, in the structured JSON format ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-usage-stream)). | Target in v2 ([#915](https://github.com/truvity/sluis/issues/915)) | 1.0.2 (2022-02-06) is the latest release, checked 2026-10-31. Not an envelope for audit records. |
| [FinOps FOCUS](https://focus.finops.org/) 1.4 | FinOps Open Cost and Usage Specification | Not used by sluis: sluis runs no finance export, and a product builds its billing from the usage log outside sluis ([0039](/decisions/0039-quota-allowance/#the-billing-log-is-outside-sluis)). | Not planned | 1.4 (2026-06-04) is current, checked 2026-10-31. sluis holds no prices. |
| [IETF Idempotency-Key header](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/) | The Idempotency-Key HTTP header field (an IETF draft) | Safe retries of the quota API. | Target in v2 ([#915](https://github.com/truvity/sluis/issues/915)) | A draft; the row follows it. |
| [WCAG 2.1 AA](https://www.w3.org/TR/WCAG21/) | Web Content Accessibility Guidelines | The sign-in and consent pages. | Target in v2 | |
| HTTP security headers and cookies ([RFC 6797](https://www.rfc-editor.org/rfc/rfc6797), CSP, cookie prefixes) | HSTS, Content Security Policy and cookie prefixes | The headers of the sign-in pages and the session cookie. | Target in v2 | Tested by sluis's own header suite. |

## Other

| Identifier | Title | What sluis uses it for | Status | Notes |
|---|---|---|---|---|
| [W3C WebAuthn](https://www.w3.org/TR/webauthn-3/) | Web Authentication | A generic WebAuthn relying party in sluis. Passkeys are the fast sign-in path and count as phishing-resistant MFA. | Target in v2 ([#885](https://github.com/truvity/sluis/issues/885), [ADR 0017](/decisions/0017-identity-and-sign-in/)) | A full upstream sign-in is still required every N days and for high-privilege grants. The relying-party ID is the registrable parent of the sluis hosts, with a strict allow-list of origins. Break-glass recovery uses passkeys only ([Break-glass recovery](/security/break-glass/)). |
| [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176) | Authentication Method Reference Values | The `amr` values that sluis emits and passes through from an upstream. | Target in v2 ([#885](https://github.com/truvity/sluis/issues/885), [#916](https://github.com/truvity/sluis/issues/916)) | Only the values sluis uses. |
| [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) | Universally Unique Identifiers (UUID version 7) | The record id of an audit message, set by the emitter; the writer removes duplicates by it ([0029](/decisions/0029-the-audit-log/#sealing)). | Target in v2 | A subject is not a UUID: it is 128 random bits in lower-case base32 ([0019](/decisions/0019-person-and-upstream-link/#assigning-a-subject)). |
| [RFC 2945](https://www.rfc-editor.org/rfc/rfc2945), [RFC 5054](https://www.rfc-editor.org/rfc/rfc5054) | SRP-6a | | Not planned | sluis stores no password; recovery uses passkeys only. |
| [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643), [7644](https://www.rfc-editor.org/rfc/rfc7644) | SCIM | Provisioning for AWS IAM Identity Center. | Later ([#918](https://github.com/truvity/sluis/issues/918)) | Together with a SAML identity provider. |
| [SAML 2.0](https://docs.oasis-open.org/security/saml/v2.0/) | Security Assertion Markup Language | sluis as a SAML identity provider, for AWS IAM Identity Center. | Later ([#918](https://github.com/truvity/sluis/issues/918)) | A SAML upstream is reached through a CIAM product that speaks OIDC. |
| [Cedar](https://www.cedarpolicy.com/) | Cedar policy language | The language of the `policy` actor, pinned to a version. | Target in v2 ([#892](https://github.com/truvity/sluis/issues/892)) | `policy` is written in Rust with the `cedar-policy` crate ([ADR 0007](/decisions/0007-policy-and-sealed-grants/)). |
| [OCI Image and Distribution specifications](https://opencontainers.org/) | OCI | Container images and Helm charts for the kubernetes runtime and the local installation. | Target in v2 ([#876](https://github.com/truvity/sluis/issues/876)) | Images are pinned by digest. |
| [Kubernetes API-server OIDC authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens) | OIDC for the Kubernetes API server | A cluster's API server trusts sluis for who a person or a CI job is; the client-go credential plugin signs a person in. | Target in v2 ([#818](https://github.com/truvity/sluis/issues/818), [#827](https://github.com/truvity/sluis/issues/827)) | An interface sluis conforms to, not one it owns. |
| [OpenPubkey](https://github.com/openpubkey/openpubkey) (`opkssh`) | Binding an SSH key to an ID token | | Not planned | sluis's own SSH CA is the only SSH path. |

## What is not on this page

Standards that sluis only passes through, such as the protocols of GitHub, Slack or AWS, are not listed: see the [integration pages](/integrations/). The standards that a feature touches are named on that feature's page.

The register changes with the design: a row's status changes in the pull request that changes the decision or schedules the work, and a claim of conformance is made only when its test passes ([Conformance](/standards/conformance/)).
