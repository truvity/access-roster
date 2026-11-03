# 0017 — Each boundary has its own issuer, a token has one audience, and people sign in with passkeys and step-up

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

v1 was one installation with one token issuer and one signing key set. Every relying party, in every environment, trusted the same key, so a compromised signer or a policy bug could mint a token for production as easily as for development.

v2 is a federation of boundaries ([0008](/decisions/0008-boundaries-and-tenants/)). One front installation gives people one sign-in URL, one console and one identity plane. Each environment boundary is its own installation with its own keys, joined to the front by declared trust. Company boundaries own directories, upstreams and people records, but hold no authority key. sluis hosts no end-user accounts and stores no passwords: people come from upstream directories ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)).

Constraints from outside:

- OpenID Connect requires `iss` to be an https URL, with discovery under it at `/.well-known/openid-configuration`, and not every relying party accepts an issuer with a path.
- A passkey belongs to a relying-party ID, a domain that the page's origin must equal or sit under, short of a public suffix.
- AWS IAM OIDC providers check `aud` against a list of client IDs; the default `sts.amazonaws.com` is the same for every account.
- Upstream multi-factor authentication on every sign-in is slow, and sluis cannot ask the upstream for a fresh factor on its own terms. WebAuthn, RFC 9470 (step-up) and RFC 8628 (device login) are the published answers.

Tokens are standard JWS and JWT, signed by the token-signing keys of [0006](/decisions/0006-keys-and-sealing/#the-token-signing-key). The actors are those of [0002](/decisions/0002-families-of-actors/#the-four-families).

## Decision

### Issuers

- **Each environment boundary has its own issuer, and the front has a group issuer.** An estate with management, development, staging and production environments has five issuers.
- **Company boundaries have no issuer.** They hold no authority key; the company is the claim `org` and a policy scope.
- **Each issuer has its own host, one host is one origin, and the issuer URL has no path.** The group issuer is `https://sluis.example.com`; a boundary issuer is `https://sluis.<env>.example.com`. A test installation lives outside these names.
- **Discovery and the JWKS are static documents**, one set per issuer, in a bucket of that boundary, so a relying party verifies tokens while the issuer's compute is down. The JWKS lists every active token key, each with its `x5c` chain; a next key appears only while a rotation is in progress ([0006](/decisions/0006-keys-and-sealing/#rotation)).
- **Lifetimes are set per issuer,** under the session classes of [0018](/decisions/0018-sessions/); the token lifetimes and their caps are in [0020](/decisions/0020-grant-vocabulary-and-token-claims/#lifetimes).

### Audiences

- **`iss` is the issuer URL. `aud` is exactly one registered `client_id`, never a URL.**
- **A resource indicator (RFC 8707 `resource=`) selects a registered client.** It is never copied into `aud`.
- **Between actors of different boundaries, `aud` is the target's SPIFFE ID**, and the call runs over mutual TLS ([0022](/decisions/0022-workload-identity-and-host-enrolment/#spiffe-identities)).
- **Client IDs are unique per issuer and readable, with the same name in every environment**, such as `kubernetes` or `argocd`. A client ID names the relying party that accepts the token.
- **An AWS role is a relying party, so each role is a client:** `aws:<account>:<role>`, where `<account>` is the account's name as the install file declares it (for example `aws:example-prod:deployer`), never the account number. The role's trust policy pins that `aud`, so which person or workload may assume which role is decided by sluis's policy and carried in the token, and AWS holds no per-person statement. Each account's IAM OIDC provider lists the client IDs of its roles.
- **A token exchange into a boundary uses that boundary's client ID at the group issuer.**
- **Every relying party pins both `iss` and `aud`.** sluis prints reference configuration for each kind of relying party, and the infrastructure code applies it.

### Subjects

- **`sub` is an opaque random ID, the same at every issuer.** sluis assigns it when it first sees a person: at a directory read where the upstream has a directory, so it is known before the first sign-in, and otherwise at the person's first sign-in. The first working version signs people in through the generic OpenID Connect upstream, sign-in only, so its subjects are assigned at first sign-in ([#1106](https://github.com/truvity/sluis/issues/1106)); directory sync, and with it the subject before the first sign-in, comes in the parity milestone ([#805](https://github.com/truvity/sluis/issues/805)). It is never an e-mail address or a directory account name. An upstream account is tied to a person by the issuer and a configured subject claim, never by e-mail ([0019](/decisions/0019-person-and-upstream-link/)).
- **The directory account and `email` are claims of their own.** Tokens carry `acr`, `amr` and `auth_time`, and `cnf.jkt` when the audience declares binding to a DPoP key; an audience that declares none gets a bearer token ([0002](/decisions/0002-families-of-actors/#the-four-families), [0020](/decisions/0020-grant-vocabulary-and-token-claims/#binding)).
- **A token carries only the grants of its own boundary.** Grants are names declared in a vocabulary and narrowed per audience, continuing v1 ADR 0010; the vocabulary, the claims of a token and its lifetimes are [0020](/decisions/0020-grant-vocabulary-and-token-claims/).
- **Workload tokens come from the same issuer.** A JWT-SVID has the boundary's URL as `iss` and the workload's `spiffe://` ID as `sub` ([0022](/decisions/0022-workload-identity-and-host-enrolment/#spiffe-identities)).
- **Pairwise subjects per sector exist only for a client that declares a sector,** and none does yet. The public `sub` above is what keeps one sign-in working across several sites; the pairwise design is [0034](/decisions/0034-end-users-and-upstream-signals/#pairwise-subjects).

### Passkeys

- **Passkeys are the fast sign-in path and count as phishing-resistant multi-factor authentication.** They are credentials of people who come from a directory; sluis stores only their public keys.
- **A full upstream sign-in, with the upstream's own multi-factor authentication, is still required** every N days and for high-privilege grants. Policy sets N and the rules.
- **The relying-party ID is the registrable parent domain**, `example.com`, because the boundary hosts are siblings of the group host. One passkey then works on every sluis host.
- **Every verifier keeps a strict allow-list of origins:** the group host and the boundary hosts, nothing else. An assertion from any other origin under the parent domain is refused.
- **Passkeys are tested from outside the product:** a browser's virtual authenticator and a software authenticator library drive the released binary. There is no test code in sluis.
- **Break-glass recovery uses passkeys only**: two attested hardware keys and one pinned synced passkey, recovery scope only ([REQ-AUTHN-066](/requirements/authn/#REQ-AUTHN-066) to [REQ-AUTHN-073](/requirements/authn/#REQ-AUTHN-073)); its record is [0043](/decisions/0043-break-glass-recovery-uses-passkeys-only/). Session classes and limits are [0018](/decisions/0018-sessions/).

### Step-up

- **`policy@<boundary>` decides which clients need multi-factor authentication** in each environment, and how fresh it must be ([0007](/decisions/0007-policy-and-sealed-grants/)).
- **Step-up follows RFC 9470.** A relying party or the boundary answers `insufficient_user_authentication` with the `acr_values` (and `max_age`) it needs, and the client signs in again with what was asked.
- **A customer's step-up is a re-authentication at the upstream,** with the same `acr_values` and `max_age`; sluis asks no customer for a passkey ([0018](/decisions/0018-sessions/#customers)).
- **The upstream's `acr` and `amr` pass through** the generic OIDC upstream, and `session@<boundary>` keeps the freshness of each person's authentication for its boundary.
- **Each boundary runs its own slim `entry@<boundary>` with no sign-in of its own**; its upstream is the group issuer. In a browser, `entry@<boundary>` is an OpenID Connect relying party of the group issuer: it signs the person in there with the authorization code flow and PKCE, as the confidential client named after the boundary, at one exact redirect (`https://<boundary host>/callback`), and the group issuer accepts no other redirect for that client ([REQ-SESS-043](/requirements/sess/#REQ-SESS-043)). The command-line path keeps the silent token exchange below. A boundary that demands fresh multi-factor authentication **verifies the passkey assertion itself**, against its own challenge, so a compromised front cannot act there.
- **In a browser, sign-in is transparent.** A person taps a passkey only where a boundary's policy demands it.
- **On the command line there is one `sluis login`**, at the group issuer. For each environment the CLI then exchanges that token silently (RFC 8693) at the boundary's own token endpoint. The front never sees a boundary's tokens.

### Directory outages

- **When the upstream directory cannot be read, sluis serves the cached group membership up to a bounded staleness window, then fails closed.** The window is set per installation under a maximum in code; past it, refresh and exchange are refused, never answered on a weaker basis.
- **A person disabled in the directory is refused at once.** Refresh and exchange stop for that person as soon as sluis learns it, whatever the window.
- Tokens already issued stay valid until they expire.

### Optional OpenID flows

sluis claims a conformance plan only when it passes, and discovery says only what is served ([Conformance](/standards/conformance/)).

- **Form post is supported** for the authorization code flow. `response_modes_supported` lists `query` and `form_post`; any other `response_mode` is refused with `invalid_request`. The auto-submit page carries a strict Content-Security-Policy with a fresh nonce, `form-action` limited to the redirect URI's origin, no framing and no caching. The Form Post OP plan joins the conformance programme.
- **Third-party-initiated login is not served.** A client's `initiate_login_uri` is not accepted. It comes back only if the console gets an app launcher.
- **Front-channel logout is not supported.** Back-channel logout, with RP-Initiated Logout, is the logout path; discovery does not advertise front-channel logout, and a registration that names a `frontchannel_logout_uri` is refused by the configuration check.
- **CIBA is Later, in poll mode only, and only when a real consumer exists, after the parity milestone.** The person would approve with a passkey on the approving device; a notification tap alone is not an approval. Until then discovery does not advertise CIBA and its endpoint is not served.
- **Device login (RFC 8628) is postponed** ([#855](https://github.com/truvity/sluis/issues/855)); the standards register lists it as planned.
- **FAPI 2.0 comes after the parity milestone,** in the customer-identity milestone ([0038](/decisions/0038-fapi-2-profile/)).

## Consequences

- A signer compromise stays in its environment: each relying party pins its own environment's issuer, so a development key cannot mint a production token.
- Five issuers mean five key sets and five sets of static documents to publish and rotate, and a DNS name and TLS certificate per host.
- A token is useful to exactly one relying party, and a token for one AWS role is refused by every other role, in that account or another. The cost is a client registration per relying party per environment.
- The CLI keeps a token per issuer under one sign-in. An outage of the front stops new sign-ins; tokens already issued keep verifying against the static JWKS.
- `sub` links one person across issuers without exposing an e-mail address, and does not change when the person is renamed.
- The broad passkey relying-party ID means any page under the parent domain could ask a browser for an assertion; the origin allow-list is therefore a security control and is tested as one. Moving sluis to another parent domain means new passkeys.
- Most sign-ins become one passkey tap that still counts as multi-factor authentication, and production can demand more than development without a code change.
- A directory outage longer than the staleness window stops sign-ins and exchanges for everyone in that directory. That is the cost of failing closed.
- Relying parties without a back-channel logout endpoint keep their sessions until they expire after a sign-out at sluis. A relying party using form post receives a cross-site POST, so it keeps its `state` check without relying on a `SameSite=Lax` cookie.
- The standards register and the [conformance page](/standards/conformance/) follow this record.
- Threats addressed: T-2, T-3, T-5, T-6, T-7 and T-21, see the [threat model](/security/threat-model/).

## Roads not taken

- **One issuer for every boundary.** What v1 does; one key accepted everywhere undoes the separation of environments.
- **An issuer per environment as a path under one host.** One certificate, but every relying party must accept a path, and the issuers would share one origin's cookies and policy.
- **Boundary hosts under the group host (`prod.sluis.example.com`).** It would narrow the passkey relying-party ID, but breaks the per-environment naming the rest of each environment uses.
- **An issuer per company.** Applications shared by every company would break, and it does not stop a development key from minting production tokens.
- **`aud` as a URL, several audiences, or `sts.amazonaws.com` for AWS.** Each lets a token for one party be replayed to another.
- **One AWS client per account (`aws-<account-alias>`).** A token for the account would then be accepted by every role that trusts the provider, so each role's trust policy would need per-person or per-group conditions.
- **The account number in the AWS client ID.** It names the account by a number nobody reads, and puts the number in every token and log line.
- **`sub` as the e-mail address or directory account.** Readable, but it changes on rename and puts personal data into every log line.
- **Upstream multi-factor authentication only, or checked once at the front.** Slow, and a compromised front could claim a fresh factor in every boundary.
- **A relying-party ID per host.** A person would register a passkey for every environment.
- **Serving the cached groups indefinitely during an outage.** No lock-out, but a removed person would keep access for as long as the directory is down.

## Follow-ups

- The generic OpenID Connect upstream for the first working version: [#1106](https://github.com/truvity/sluis/issues/1106); directory sync and subjects before the first sign-in: [#805](https://github.com/truvity/sluis/issues/805).
- End-user subject lifecycle: [0034](/decisions/0034-end-users-and-upstream-signals/), [#1024](https://github.com/truvity/sluis/issues/1024).
- FAPI 2 profile, in the customer-identity milestone after parity: [0038](/decisions/0038-fapi-2-profile/), [#1025](https://github.com/truvity/sluis/issues/1025).
- Device login: [#855](https://github.com/truvity/sluis/issues/855).
