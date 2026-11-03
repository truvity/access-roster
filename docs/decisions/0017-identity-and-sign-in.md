# 0017 — Each boundary has its own issuer, a token has one audience, people sign in with passkeys and step-up, and break-glass recovery uses passkeys held in config

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

v1 was one installation with one token issuer and one signing key set. Every relying party, in every environment, trusted the same key, so a compromised signer or a policy bug could mint a token for production as easily as for development.

v2 is a federation of boundaries ([0008](/decisions/0008-boundaries-and-tenants/)). One front installation gives people one sign-in URL, one console and one identity plane. Each environment boundary has its own keys and its own issuer, and is joined to the front by declared trust. A company is a tenant of an environment boundary ([0008](/decisions/0008-boundaries-and-tenants/#tenants)): it owns directories, upstreams and people records, but holds no authority key. sluis hosts no end-user accounts and stores no passwords: people come from upstream directories ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)).

Constraints from outside:

- OpenID Connect requires `iss` to be an https URL, with discovery under it at `/.well-known/openid-configuration`, and not every relying party accepts an issuer with a path.
- A passkey belongs to a relying-party ID, a domain that the page's web origin must equal or sit under, short of a public suffix.
- AWS IAM OIDC providers check `aud` against a list of client IDs; the default `sts.amazonaws.com` is the same for every account.
- Upstream multi-factor authentication on every sign-in is slow, and sluis cannot ask the upstream for a fresh factor on its own terms. WebAuthn, RFC 9470 (step-up) and RFC 8628 (device login) are the published answers.

Operators sign in through an upstream directory. When the directory is down, a federation is misconfigured or no upstream can vouch for anyone, they still need a way back in to repair it. That way in is the one exception to "no accounts", so it has to be narrow, visible, proven to work, and independent of the data that may be the thing that is damaged. v1 offered two recovery proofs: a Kubernetes ServiceAccount token checked by the API server, and an SRP-6a password that never crossed the wire ([#795](https://github.com/truvity/sluis/issues/795)). Both are reusable secrets, or depend on a system that may be the one that failed. WebAuthn gives a phishing-resistant proof whose private half never leaves its authenticator, and an attestation statement can show that an authenticator is hardware. The tooling that enrols such credentials was measured in a spike ([#1178](https://github.com/truvity/sluis/issues/1178)) on 2026-11-03: a hardware FIDO key, a PIV slot and a synced passkey were each enrolled and verified, and its findings are the decisions below.

Tokens are standard JWS and JWT, signed by the token-signing keys of [0006](/decisions/0006-keys-and-sealing/#the-token-signing-key). The actors are those of [0002](/decisions/0002-families-of-actors/#the-four-families).

## Decision

### Issuers

- **Each environment boundary has its own issuer, and the front has a group issuer.** An internal installation with kernel, devel, stage and prod boundaries has five issuers. A customer boundary has authority keys of its own, so it has an issuer of its own too.
- **A login domain is an issuer of its boundary, and shares the boundary's keys.** A client that names a login domain ([0035](/decisions/0035-customer-pages/#login-domains)) has the host of that domain as its issuer, with discovery and the key set served there from the boundary's static documents. Client IDs stay unique per boundary. A relying party pins the issuer of its client's domain.
- **A tenant has no issuer.** It holds no authority key ([0008](/decisions/0008-boundaries-and-tenants/#tenants)); the tenant is a scope of policy and the second dimension of an address.
- **Each issuer has its own host, one host is one web origin, and the issuer URL has no path.** The group issuer is `https://sluis.example.com`; a boundary issuer is `https://sluis.<env>.example.com`. A test installation lives outside these names.
- **Discovery and the key set are static documents,** one set per issuer, in a bucket of that boundary, so a relying party verifies tokens while the issuer's compute is down. The key set is the exportable kind `SigningRing`, which `signer` writes and exporter@ publishes as public material ([0009](/decisions/0009-export/#what-is-exportable)). It lists every active token key, each with its `x5c` chain; a next key appears only while a rotation is in progress ([0006](/decisions/0006-keys-and-sealing/#rotation)). The discovery document has no kind: IaC renders it from the boundary's config and publishes it beside the key set, because exporter@ exports only the kinds of [0009](/decisions/0009-export/#what-is-exportable).
- **Lifetimes are set per issuer** by the config kind `TokenLifetime`, under the session classes of [0018](/decisions/0018-sessions/); the token lifetimes and their caps are in [0020](/decisions/0020-grant-vocabulary-and-token-claims/#lifetimes).

### Audiences

- **`iss` is the issuer URL. `aud` is exactly one registered `client_id`, never a URL.**
- **A resource indicator (RFC 8707 `resource=`) selects a registered client.** It is never copied into `aud`.
- **Between actors of different boundaries, `aud` is the target's SPIFFE ID**, and the call runs over mutual TLS ([0022](/decisions/0022-workload-identity-and-host-enrolment/#spiffe-identities)).
- **Client IDs are unique per issuer and readable, with the same name in every environment**, such as `kubernetes` or `argocd`. A client ID names the relying party that accepts the token. How clients are declared is [0021](/decisions/0021-clients/#the-client-declaration).
- **An AWS role is a relying party, so each role is a client:** `aws:<account>:<role>`, where `<account>` is the account's name as the client's declaration gives it (for example `aws:example-prod:deployer`), never the account number. The role's trust policy pins that `aud`, so which person or workload may assume which role is decided by sluis's policy and carried in the token, and AWS holds no per-person statement. Each account's IAM OIDC provider lists the client IDs of its roles.
- **A token exchange into a boundary uses that boundary's client ID at the group issuer.**
- **Every relying party pins both `iss` and `aud`.** sluis prints reference configuration for each kind of relying party, and the infrastructure code applies it.

### Subjects

- **`sub` is an opaque random ID, the same at every issuer.** `session` assigns it when it first sees a person: at a directory read where the upstream has a directory, so it is known before the first sign-in, and otherwise at the person's first sign-in. The first working version signs people in through the generic OpenID Connect upstream, sign-in only, so its subjects are assigned at first sign-in ([#1106](https://github.com/truvity/sluis/issues/1106)); directory sync, and with it the subject before the first sign-in, comes in the parity milestone ([#805](https://github.com/truvity/sluis/issues/805)). It is never an e-mail address or a directory account name. An upstream account is tied to a person by the issuer and a configured subject claim, never by e-mail ([0019](/decisions/0019-person-and-upstream-link/)).
- **The directory account and `email` are claims of their own.** Tokens carry `acr`, `amr` and `auth_time`, and `cnf.jkt` when the audience declares binding to a DPoP key; an audience that declares none gets a bearer token ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#binding)).
- **A token carries only the grant names of its own boundary.** Grant names are declared in a vocabulary and narrowed per audience; the vocabulary, the claims of a token and its lifetimes are [0020](/decisions/0020-grant-vocabulary-and-token-claims/).
- **Workload tokens come from the same issuer.** A JWT-SVID has the boundary's URL as `iss` and the workload's `spiffe://` ID as `sub` ([0022](/decisions/0022-workload-identity-and-host-enrolment/#spiffe-identities)).
- **Pairwise subjects per sector exist only for a client that declares a sector,** and none does yet. The public `sub` above is what keeps one sign-in working across several sites; the pairwise design is [0034](/decisions/0034-end-users-and-upstream-signals/#pairwise-subjects).

### Passkeys

- **Passkeys are the fast sign-in path and count as phishing-resistant multi-factor authentication.** They are credentials of staff who come from a directory; sluis stores only their public keys, as the durable kind `StaffPasskey` that `session` writes, sealed in the person's tenant.
- **A full upstream sign-in, with the upstream's own multi-factor authentication, is still required** every N days and for high-privilege grant names. Policy sets N and the rules.
- **Staff passkeys and the ceremonies use one relying-party ID,** the shared sign-in domain declared in the config kind `FrontHost`. It is the registrable parent domain, `example.com`, because the boundary hosts are siblings of the group host, so one passkey works on every sluis host.
- **End-user passkeys for customers belong to the upstream.** A client's own login domain and its branding are [0035](/decisions/0035-customer-pages/)'s.
- **Every verifier keeps a strict allow-list of web origins:** the group host, the boundary hosts and their audit hosts ([0028](/decisions/0028-audit-pieces/#the-audit-front)), nothing else. An assertion from any other origin under the parent domain is refused.
- **Passkeys are tested from outside the product:** a browser's virtual authenticator and a software authenticator library drive the released binary. There is no test code in sluis.
- **Break-glass recovery has its own credentials,** held in config ([Break-glass recovery](/decisions/0017-identity-and-sign-in/#break-glass-recovery)). Session classes and limits are [0018](/decisions/0018-sessions/).

### Step-up

- **`policy@<boundary>` decides which clients need multi-factor authentication** in each environment, and how fresh it must be ([0007](/decisions/0007-policy-and-sealed-grants/)).
- **Step-up follows RFC 9470.** A relying party or the boundary answers `insufficient_user_authentication` with the `acr_values` (and `max_age`) it needs, and the client signs in again with what was asked.
- **A customer's step-up is a re-authentication at the upstream,** with the same `acr_values` and `max_age`; sluis asks no customer for a passkey ([0018](/decisions/0018-sessions/#customers)).
- **The upstream's `acr` and `amr` pass through** the generic OIDC upstream, `adapter-upstream-oidc`, and `session@<boundary>` keeps the freshness of each person's authentication for its boundary on the person's session chain ([0018](/decisions/0018-sessions/#session-chains)).
- **Each boundary runs its own slim `entry@<boundary>` with no sign-in of its own**; its upstream is the group issuer. In a browser, `entry@<boundary>` is an OpenID Connect relying party of the group issuer: it signs the person in there with the authorization code flow and PKCE, as the confidential client named after the boundary, at one exact redirect (`https://<boundary host>/callback`), and the group issuer accepts no other redirect for that client ([REQ-SESS-043](/requirements/sess/#REQ-SESS-043)). The command-line path keeps the silent token exchange below. A boundary that demands fresh multi-factor authentication **verifies the passkey assertion itself**, against its own challenge, so a compromised front cannot act there.
- **In a browser, sign-in is transparent.** A person taps a passkey only where a boundary's policy demands it.
- **On the command line there is one `sluis login`**, at the group issuer. For each environment the CLI then exchanges that token silently (RFC 8693) at the boundary's own token endpoint. The front never sees a boundary's tokens.

### Directory outages

- **When the upstream directory cannot be read, sluis serves the cached group membership up to a bounded staleness window, then fails closed.** The cache is the directory facts, temp kinds with a time to live of 24 hours by default and 7 days at most ([0019](/decisions/0019-person-and-upstream-link/#directory-facts-parity)). The window is set per installation under a maximum built into the release; past it, refresh and exchange are refused, never answered on a weaker basis.
- **A person disabled in the directory is refused at once.** Refresh and exchange stop for that person as soon as sluis learns it, whatever the window.
- Tokens already issued stay valid until they expire.

### Optional OpenID flows

sluis claims a conformance plan only when it passes, and discovery says only what is served ([Conformance](/standards/conformance/)).

- **Form post is supported** for the authorization code flow. `response_modes_supported` lists `query` and `form_post`; any other `response_mode` is refused with `invalid_request`. The auto-submit page carries a strict Content-Security-Policy with a fresh nonce, `form-action` limited to the redirect URI's web origin, no framing and no caching. The Form Post OP plan joins the conformance programme.
- **Third-party-initiated login is not served.** A client's `initiate_login_uri` is not accepted. It comes back only if the console gets an app launcher.
- **Front-channel logout is not supported.** Back-channel logout, with RP-Initiated Logout, is the logout path; discovery does not advertise front-channel logout, and a registration that names a `frontchannel_logout_uri` is refused by the configuration check.
- **CIBA is Later, in poll mode only, and only when a real consumer exists, after the parity milestone.** The person would approve with a passkey on the approving device; a notification tap alone is not an approval. Until then discovery does not advertise CIBA and its endpoint is not served.
- **Device login (RFC 8628) is postponed** ([#855](https://github.com/truvity/sluis/issues/855)); the standards register lists it as planned.
- **FAPI 2.0 comes after the parity milestone,** in the customer-identity milestone ([0038](/decisions/0038-fapi-2-profile/)).

### Break-glass recovery

- **Recovery accepts a passkey assertion and nothing else** ([REQ-AUTHN-066](/requirements/authn/#REQ-AUTHN-066)): no password, no recovery code, no ServiceAccount token. sluis stores only the credential ids and the public keys.
- **The recovery credentials are config,** the kind `BreakGlassPasskey`, which `session` reads from the snapshot. A restored or damaged store cannot lose, roll back or hold back a recovery credential, because none is durable data. A credential changes only by a reviewed, signed commit ([0005](/decisions/0005-the-store/#configuration-loading)).
- **A `BreakGlassPasskey` has one of three credential classes:** `hardware-fido`, `hardware-piv` or `synced`. Enabling recovery requires three registered credentials ([REQ-AUTHN-067](/requirements/authn/#REQ-AUTHN-067)):
  - **two hardware keys,** each of class `hardware-fido` or `hardware-piv`, each accepted only if its enrolment carried an attestation that was verified against the authenticator vendor's attestation roots ([REQ-AUTHN-068](/requirements/authn/#REQ-AUTHN-068)), so a software copy cannot be registered and the loss of one key is survived;
  - **one synced passkey,** class `synced`, accepted only by its pinned credential id ([REQ-AUTHN-069](/requirements/authn/#REQ-AUTHN-069)) and kept in a vault of its own, apart from the hardware keys, so the loss of both hardware keys is survived and no other passkey of the same account gets in. Its attestation is `none`, so the pin is the only proof, and the flags backup eligible and backup state are set.
- **A `hardware-fido` credential** is a WebAuthn credential whose packed attestation is verified to the pinned vendor root and whose model is certified in the FIDO Metadata Service (MDS3). Its assertions must show user presence and user verification, and its backup eligible and backup state flags must be clear.
- **A `hardware-piv` credential proves itself with a signature over `authenticatorData || SHA-256(clientDataJSON)`, in assertion shape,** because a PIV slot cannot speak WebAuthn. The key is generated on the device, and its attestation chain is verified to the same pinned root. User presence and user verification follow from the slot's attested policy, which must be PIN once or always and touch always; a slot with any weaker policy is refused at enrolment.
- **An enrolment is compared by its public key and its attestation chain, never by the bytes of its attestation certificate.** A PIV attestation certificate is re-issued on every request, so its bytes differ each time for the same key.
- **The enrolment tools only show the JSON to commit.** A command-line tool enrols a hardware key, `hardware-fido` or `hardware-piv`, and reads the public key of a PIV slot from its attestation. A page enrols the synced passkey: it runs on the shared sign-in domain over https, sends nothing (the content security policy sets `connect-src 'none'`) and stores nothing. The operator copies the JSON it shows into config and commits it.
- **The verify flow is the same checks for every class:** the credential id or the public key, the client data type, challenge and origin, the relying-party ID hash, the flags, and the signature. The signature counter is checked for `hardware-fido`, ignored for `hardware-piv`, and not used as a clone signal for `synced`, whose counter is 0.
- **A recovery session carries the recovery scope only** ([REQ-AUTHN-070](/requirements/authn/#REQ-AUTHN-070)), and gets no refresh token. The scope is the built-in break-glass policy, which grants beyond config, so linking it is a loosening: `session` has `exchange`, the owner of `PredefinedPolicyLinkTemporary`, write the link, and it expires, after 1 hour by default and 24 hours at most ([0007](/decisions/0007-policy-and-sealed-grants/#template-links)). It restores access: an operator repairs a connection, a federation or a tenant setting. Config, the recovery credentials among it, changes only by a commit, so recovery cannot change it ([principle 17](/principles/#17-where-a-thing-is-written-decides-its-class)).
- **Every use is audited, successful or refused** ([REQ-AUTHN-071](/requirements/authn/#REQ-AUTHN-071)). Recovery never waits for the audit path: the record is spooled locally and delivered when the path is back ([0029](/decisions/0029-the-audit-log/#retention)).
- **Every successful use raises an alert to the operators** ([REQ-AUTHN-072](/requirements/authn/#REQ-AUTHN-072)). An unexpected recovery is an incident until proven otherwise.
- **The runbook requires a drill every quarter** ([REQ-AUTHN-073](/requirements/authn/#REQ-AUTHN-073)): each credential is used once in a test of the full path, and the drill is itself audited and alerted.
- **Recovery runs on every runtime** and needs no cloud account and no cluster: `session` verifies the assertion against its own challenge, like any passkey. `sluis config check` warns when recovery is enabled without all three credentials.
- **Recovery is for sign-in to sluis only.** Emergency SSH access to hosts is the break-glass SSH CA that ritueel holds offline ([0023](/decisions/0023-certificate-authorities/#ssh)).

## Consequences

- A signer compromise stays in its environment: each relying party pins its own environment's issuer, so a development key cannot mint a production token.
- Five issuers mean five key sets and five sets of static documents to publish and rotate, and a DNS name and TLS certificate per host.
- A token is useful to exactly one relying party, and a token for one AWS role is refused by every other role, in that account or another. The cost is a client registration per relying party per environment.
- The CLI keeps a token per issuer under one sign-in. An outage of the front stops new sign-ins; tokens already issued keep verifying against the static key set.
- `sub` links one person across issuers without exposing an e-mail address, and does not change when the person is renamed.
- The broad passkey relying-party ID means any page under the parent domain could ask a browser for an assertion; the allow-list of web origins is therefore a security control and is tested as one. Moving sluis to another parent domain means new passkeys.
- Most sign-ins become one passkey tap that still counts as multi-factor authentication, and production can demand more than development without a code change.
- A directory outage longer than the staleness window stops sign-ins and exchanges for everyone in that directory. That is the cost of failing closed.
- Relying parties without a back-channel logout endpoint keep their sessions until they expire after a sign-out at sluis. A relying party using form post receives a cross-site POST, so it keeps its `state` check without relying on a `SameSite=Lax` cookie.
- No reusable secret exists for recovery: nothing to rotate, leak or phish, and nothing that depends on the system being recovered.
- Recovery needs three credentials committed before it is needed, and an operator who skipped that has no way back in but a restore. Adding or replacing a credential is a commit, which takes a review and a deploy; that is the price of keeping the credentials out of the data that a restore rewinds.
- Whoever holds a registered hardware key and can unlock it, or controls the synced passkey's vault, can open a recovery session. The recovery scope and its expiry bound what it can do, and the alert and the audit record make every use visible.
- The quarterly drill costs an operator's time four times a year; a recovery path that is never exercised fails when it is needed.
- The standards register and the [conformance page](/standards/conformance/) follow this record. The page [Break-glass recovery](/security/break-glass/) describes the recovery section.
- Threats addressed: T-2, T-3, T-5, T-6, T-7 and T-21, see the [threat model](/security/threat-model/).

## Roads not taken

- **One issuer for every boundary.** What v1 does; one key accepted everywhere undoes the separation of environments.
- **An issuer per environment as a path under one host.** One certificate, but every relying party must accept a path, and the issuers would share one web origin's cookies and policy.
- **Boundary hosts under the group host (`prod.sluis.example.com`).** It would narrow the passkey relying-party ID, but breaks the per-environment naming the rest of each environment uses.
- **An issuer per tenant.** Applications shared by every company would break, and it does not stop a development key from minting production tokens.
- **`aud` as a URL, several audiences, or `sts.amazonaws.com` for AWS.** Each lets a token for one party be replayed to another.
- **One AWS client per account (`aws-<account-alias>`).** A token for the account would then be accepted by every role that trusts the provider, so each role's trust policy would need per-person or per-group conditions.
- **The account number in the AWS client ID.** It names the account by a number nobody reads, and puts the number in every token and log line.
- **`sub` as the e-mail address or directory account.** Readable, but it changes on rename and puts personal data into every log line.
- **Upstream multi-factor authentication only, or checked once at the front.** Slow, and a compromised front could claim a fresh factor in every boundary.
- **A relying-party ID per host.** A person would register a passkey for every environment.
- **Serving the cached groups indefinitely during an outage.** No lock-out, but a removed person would keep access for as long as the directory is down.
- **Break-glass credentials as durable data.** A page could store them, but a damaged store would take the way in with it, and a restore would rewind them.
- **A recovery password, as v1's SRP-6a.** A reusable secret that must be stored, rotated and guarded, and the one password in a product that stores none.
- **Recovery codes.** Printed reusable secrets with the same problems, and no proof that a person holds them at the moment of use.
- **A ServiceAccount token checked by a cluster's API server.** Recovery would depend on the cluster, which may be the thing that failed, and would not exist on the other runtimes.
- **Hardware keys without attestation.** A software authenticator could then be registered as a hardware key.
- **Only hardware keys.** Losing both, or the place where both are kept, would leave no way back in; the pinned synced passkey covers that.
- **A recovery session with the operator's full scope.** It would turn the emergency door into a standing back door.

## Follow-ups

- The enrolment tools for the three credential classes, built to the findings of the spike measured on 2026-11-03: [#1178](https://github.com/truvity/sluis/issues/1178).
- The recovery sign-in, built in the parity milestone: [#795](https://github.com/truvity/sluis/issues/795).
- The generic OpenID Connect upstream for the first working version: [#1106](https://github.com/truvity/sluis/issues/1106); directory sync and subjects before the first sign-in: [#805](https://github.com/truvity/sluis/issues/805).
- End-user subject lifecycle: [0034](/decisions/0034-end-users-and-upstream-signals/), [#1024](https://github.com/truvity/sluis/issues/1024).
- FAPI 2 profile, in the customer-identity milestone after parity: [0038](/decisions/0038-fapi-2-profile/), [#1025](https://github.com/truvity/sluis/issues/1025).
- Device login: [#855](https://github.com/truvity/sluis/issues/855).
