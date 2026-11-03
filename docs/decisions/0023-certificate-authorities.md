# 0023 — The ca and ssh-ca actors are the X.509 and SSH certificate authorities, SSH uses only sluis's own CA, and databases get short-lived client certificates

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

sluis signs certificates as well as tokens. X.509 certificates serve hosts, workloads, databases and sluis's own mutual TLS. SSH certificates let people and machines log in to hosts and let clients trust a host's key.

v1 never signed an SSH key (v1 ADR 0004, on `master`). People used opkssh, machines and hosts used a secret store's SSH engine (v1 ADR 0011), and clients trusted host CAs through a managed known-hosts file (v1 ADR 0016). Database client certificates also came from a secret store. That spread trust and audit over several systems. v2 uses sluis's own CAs only; this record succeeds v1 ADR 0004, the SSH parts of v1 ADR 0011, and v1 ADR 0016.

Forces:

- **A certificate that carries authority leaks it.** A certificate listing every host group grows with the organisation, shows the topology, and hits OpenSSH's cap of 256 principals. `sshd` reads `AuthorizedPrincipalsFile` per account at each login, so the host can hold the authority and the certificate only the identity.
- **Not every device can run a service.** Baseboard controllers and KVM appliances run OpenSSH and nothing else; some routers do not support OpenSSH certificates.
- **PostgreSQL's `cert` method trusts its CA file** and maps a name to a role, so a workload certificate whose common name equals a role would log in as that role. PostgreSQL 14 and later match the whole subject with `clientname=DN`, and check revocation only when a CRL is configured.
- **The keys are decided elsewhere.** Each boundary has one X.509 intermediate and separate SSH user and host CA keys, all in `key-holder` or KMS ([0006](/decisions/0006-keys-and-sealing/#the-card-slot-map)); the intermediates are certified through the hand-off to ritueel ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)).

## Decision

### Two authorities, two actors

- **`ca@<boundary>` is the X.509 authority and `ssh-ca@<boundary>` the SSH authority.** They are separate actors because they hold different keys and serve different relying parties. Their language follows [0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table).
- **Each boundary has its own.** A host trusts exactly one sluis SSH CA, its environment's, plus the break-glass CA.
- **Issuance is bound to the requester.** The subject is the authenticated requester: a person's key from their sign-in, a workload from its exchanged proof, a host from its enrolment ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)). A request cannot name someone else.
- **`key-holder` signs only what each purpose allows**: for `ca` a parseable TBSCertificate within its constraints, for `ssh-ca` an OpenSSH certificate body ([0003](/decisions/0003-units-transports-and-fusion/#key-holder-is-the-one-mediator)).
- **Serials are random 128-bit numbers, and no ledger is kept** ([0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place)).

### X.509

- **`ca` issues every leaf from the boundary's one intermediate.** The trust domain is the boundary ([0022](/decisions/0022-workload-identity-and-host-enrolment/#trust-domains)), so there is one intermediate per trust domain and no intermediate per use. Uses are kept apart by certificate profiles: each profile fixes the key usages, the extended key usage and a subject or SAN form that no other profile can produce, and an intermediate carries name constraints where its relying parties need them. The profile of the intermediate itself is in ritueel's hand-off contract.
- **The leaf profiles are:** the host X.509-SVID, the workload X.509-SVID, sluis's own mutual-TLS certificates, the database client certificate (below), and the certificates cert-manager requests. The token-signing certificate is a non-CA profile of [0006](/decisions/0006-keys-and-sealing/#the-token-signing-key). Each profile's fields, the leaf lifetimes, the intermediates' name constraints and the CRL cadence are [0042](/decisions/0042-leaf-certificate-profiles-lifetimes-and-revocation/).
- **Clusters keep cert-manager and trust-manager.** `ca` signs for cert-manager through an external issuer, shipped as its own chart; the issuer accepts a CSR with an empty subject and takes the identity from the requester. sluis writes no Kubernetes object.
- **ACME (RFC 8555) comes after the first release** ([#978](https://github.com/truvity/sluis/issues/978)). Until then a host sends a CSR to `ca`'s issue call, through the enrolment API or the certificate module of `sluis-host`.

### SSH

- **A certificate carries identity only.** A person's carries `u:<person-key>`, the opaque person key; a machine's carries `w:<workload>`, named for the workload, not the instance.
- **The host holds the authority.** `sluis-host` writes `/etc/ssh/principals/<account>` from a signed bundle that Cedar policy computed. Each line has `expiry-time` set to the bundle's expiry, and `from=`, `command=` or `no-pty` where policy says so.
- **Grant principals `g:<account>@<group>` appear in a certificate in three cases only:** a host without the service (static mode), sluis's own hosts, which must not depend on sluis to be reached, and elevation (on request, with fresh MFA, for 15 to 60 minutes).
- **Break-glass is `bg:<scope>`, from an offline SSH CA that ritueel holds.** The host takes its public key from the list of SSH CA keys that ritueel publishes; its lines are written at install and never touched by the bundle. sluis's own SSH CA keys are anchors in that list, not a chain.
- **Principals carry a kind prefix**, so kinds cannot collide.
- **Policy has two actions:** `ssh.login`, standing access, evaluated when the bundle is built; `ssh.certify`, evaluated at signing, which sets the lifetime, the extensions, the source address and any `g:` grants.
- **Groups come from declared rules** over attested and declared attributes; the console can only narrow them. `attested`, `declared` and `assigned` attributes may grant; `reported` attributes and plain cloud tags may not ([0022](/decisions/0022-workload-identity-and-host-enrolment/#join-cases)).
- **Host names are declared for pets and derived for cattle**, plus aliases declared on a group. A host certificate never carries a name the host reported itself, and an alias two groups claim is refused.
- **Accounts:** role accounts by default (`ops` with sudo, `ops-ro`, forced-command accounts); per-person accounts opt-in per group, with stable UIDs, locked and never deleted when a person leaves. No one logs in as root. Appliances and small lab estates get sudo on `ops`; the data tier and tier 0 get elevation only.
- **Lifetimes are set by policy:** 12 hours for people, 15 minutes for elevation, 10 minutes for workloads by default. The key ID is `<installation>/<subject>/<session>`.
- **A stale bundle locks out normal logins.** After 24 hours without a fresh bundle the lines expire; each group can change the limit. Grant, elevation and break-glass lines are not in the bundle and keep working.
- **Hosts without the service:** static mode for OpenSSH devices that cannot run `sluis-host` (CA, principals and a long-lived host certificate written at install, the revocation list updated by hand); pinned host keys for devices without certificate support. Both stay hosts in sluis, so policy and inventory are complete.
- **`sluis-host` is a separate root service** under systemd. It never listens on the network: it fetches the bundle, verifies it, writes the files atomically and runs a reload hook. It fails static, keeping the last good bundle, and alerts when the revocation list or the host certificate gets old. It ships as signed deb and rpm packages.
- **`sshd` stays stock**, with `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`, `HostCertificate` and `RevokedKeys`. Clients trust a zone's host CA through a `@cert-authority` line per zone, which replaces v1's per-host known-hosts file.
- **SSH revocation is a key revocation list** (by serial and by key) that `sluis-host` keeps current. Standing access ends when the next bundle drops a line, so the KRL is for stolen keys and certificates.

### Database client certificates

- **Self-run PostgreSQL and CNPG get short-lived client certificates from `ca`**, under the database client profile:
  - the common name (CN) is the **database role**; the organisational unit (OU) is the **person or workload** that asked, filled by `ca` from the authenticated requester, never from the request;
  - the profile has client-authentication usage only and a fixed subject form that no other profile can produce;
  - the database matches with `clientname=DN` and a **fixed regular-expression map** on the full subject, so a certificate of any other profile matches no role, and the full subject lands in the database's log.
- **Policy decides which roles a requester may ask for**, and each role's lifetime under a maximum.
- **Some names are reserved:** `ca` never issues for a replication role (such as CNPG's `streaming_replica`) or the database's owner role.
- **The private key stays on the client**, which sends a CSR.
- **People and machines use the flows they already have.** The `sluis` CLI requests a certificate for a key on the person's machine and starts the database tool with the standard libpq variables; a machine presents its workload proof in a token exchange. In Kubernetes, certificates reach pods first through the cert-manager issuer (namespace identity, key in a Secret), then through the `sluis agent` sidecar (identity per pod, shipped as an image and a snippet).
- **The wiring of a particular database stays outside sluis.** `pg_hba` lines, ident maps, roles and grants live in that database's own repository; sluis documents the scheme and prints reference snippets.
- **RDS and Aurora use IAM authentication, outside sluis.** sluis makes no RDS token and holds no database credential; a small helper makes the token from AWS credentials that sluis provides through `credential_process`.
- **sluis's own data in PostgreSQL** follows the row-level security rules of [0003](/decisions/0003-units-transports-and-fusion/#postgresql-row-level-security).

### Issuance log and revocation

- **Every X.509 certificate is logged.** `ca` writes each certificate into a C2SP `static-ct-api` issuance log, witnessed like the audit log ([0029](/decisions/0029-the-audit-log/#witnesses)). The log has its own signing purpose ([0006](/decisions/0006-keys-and-sealing/#the-card-slot-map)).
- **Short lifetimes are the main control; `ca` publishes a static CRL** behind them, and a database that configures the CRL checks it.
- **Every certificate is audited:** the requester, the profile, the role where there is one, the serial, the validity and the public key hash.

## Consequences

- One SSH certificate works on every host of its environment, never reaches the 256-principal cap and shows nothing about the estate.
- Standing access is revoked by the next bundle, not by waiting for expiry. An outage longer than the staleness limit locks out normal logins, while grant, elevation and break-glass access keep working.
- Every host with standing access runs `sluis-host`; a host in static mode has a manual revocation list and CA rotation.
- The break-glass CA is a second trust root on each host, offline and guarded by ritueel.
- Two CA actors mean two sets of keys, profiles and conformance tests, and two things to publish: X.509 anchors and CRLs, SSH CA keys and KRLs.
- One intermediate per boundary keeps the slot map and the yearly re-certification small. The cost is that separation between uses rests on the profiles and the databases' fixed subject maps, which are therefore tested as security controls.
- No database password is shared or rotated by hand. Revocation is weak unless the database configures the CRL, so lifetimes stay short. The first Kubernetes path puts a key in a Secret, readable by anyone who can read the Secret, until the sidecar ships.
- `sluis config check` refuses a policy that uses `reported` attributes in a permit, and a `g:` grant outside the three allowed cases.
- To verify when built: the 256-principal cap; that `sshd` logs the key ID only at `LogLevel VERBOSE`; Cedar's datetime support for time-boxed grants; which `sshd` files are read per login and which need a reload.
- Threats addressed: T-8, T-9, T-19, T-20 and T-26, see the [threat model](/security/threat-model/).

## Roads not taken

- **opkssh as a second SSH path.** No CA key to protect, but a binary and policy files on every host, no host certificates and login audit left on each host.
- **A secret store's SSH or database engine.** The v1 path, but a second system with its own trust and audit and an admin credential for every database.
- **One `ca` actor for X.509 and SSH.** One process would hold two different authorities.
- **A separate intermediate per use (for example for databases).** Each costs a request, a certification, a card slot and a yearly renewal; profiles and fixed subject maps give the same separation.
- **Grant principals in every certificate.** Certificates would grow with the organisation, leak the topology and hit the 256 cap.
- **Bare user names, or principals prefixed by installation.** Any trusted CA could mint any name, or the prefix repeats what one CA per host already gives.
- **Reported attributes and cloud tags may grant.** Whoever can tag an instance could move it into a policy.
- **Lines that never expire, or `AuthorizedPrincipalsCommand` at each login.** A removed person keeps access on a host that stopped refreshing, or a moving part sits in the login path.
- **An emergency certificate from sluis as break-glass.** Useless when sluis is down, which is when break-glass is needed.
- **The person's name as CN mapped to a role, or PostgreSQL 18 OAuth.** A map per database listing people, or a validator module on every server plus device login, which is postponed.

## Follow-ups

- ACME in `ca`, after the first release: [#978](https://github.com/truvity/sluis/issues/978).
- Merkle Tree Certificates (`mtc-tlog`) on the post-quantum track: Later, [#1029](https://github.com/truvity/sluis/issues/1029).
