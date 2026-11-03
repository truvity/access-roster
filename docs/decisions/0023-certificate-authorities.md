# 0023 — The ca and ssh-ca actors are the certificate authorities; every leaf has a fixed profile and a short lifetime

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

sluis signs certificates as well as tokens. X.509 certificates serve hosts, workloads, databases and sluis's own mutual TLS. SSH certificates let people and machines log in to hosts and let clients trust a host's key.

v1 never signed an SSH key (v1 ADR 0004, on `master`). People used opkssh, machines and hosts used a secret store's SSH engine (v1 ADR 0011), and clients trusted host CAs through a managed known-hosts file (v1 ADR 0016). Database client certificates also came from a secret store. That spread trust and audit over several systems. v2 uses sluis's own CAs only; this record succeeds v1 ADR 0004, the SSH parts of v1 ADR 0011, and v1 ADR 0016.

Forces:

- **A certificate that carries authority leaks it.** A certificate listing every host group grows with the organisation, shows the topology, and hits OpenSSH's cap of 256 principals. `sshd` reads `AuthorizedPrincipalsFile` per account at each login, so the host can hold the authority and the certificate only the identity.
- **Not every device can run a service.** Baseboard controllers and KVM appliances run OpenSSH and nothing else; some routers do not support OpenSSH certificates.
- **PostgreSQL's `cert` method trusts its CA file** and maps a name to a role, so a workload certificate whose common name equals a role would log in as that role. PostgreSQL 14 and later match the whole subject with `clientname=DN`, and check revocation only when a CRL is configured.
- **Relying parties read certificates as they implement the standards.** An X.509-SVID has exactly one URI SAN, the SPIFFE ID ([SPIFFE X509-SVID](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)). TLS clients check a DNS or IP SAN. Many clients accept a certificate with no extended key usage for any use.
- **Revocation reaches few relying parties.** Most TLS and SPIFFE clients never fetch a CRL, and sluis runs no OCSP responder (REQ-PKI-008). A short lifetime is the control that works everywhere; a CRL helps only the relying parties that configure it, such as a database.
- **Name constraints are checked by verifiers, not by the issuer.** RFC 5280 constrains each name type separately: a type with no permitted subtree is unconstrained. ritueel's hand-off contract requires at least one permitted subtree, marked critical, in an intermediate request, and its certifier checks them against its policy. That policy lists URI hosts today; verifiers enforce the DNS subtrees below from the first certificate either way.
- **The keys are decided elsewhere.** Each boundary has one X.509 intermediate and separate SSH user and host CA keys, all held behind key@ ([0006](/decisions/0006-keys-and-sealing/#key-purposes)); the intermediates are certified through the hand-off to ritueel ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)). **Principle 2** asks for short leaves; **principle 5** for profiles that the consumers implement.

## Decision

### Two authorities, two actors

- **`ca@<boundary>` is the X.509 authority and `ssh-ca@<boundary>` the SSH authority.** They are separate actors because they hold different keys and serve different relying parties, and an installation does not fuse them ([0002](/decisions/0002-families-of-actors/#work-actors), [0003](/decisions/0003-units-transports-and-fusion/#fusion)). Their language follows [0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table).
- **Each boundary has its own.** A host trusts exactly one sluis SSH CA, its environment's, plus the break-glass CA.
- **Issuance is bound to the requester.** The subject is the authenticated requester: a person's key from their sign-in, a workload from its exchanged proof, a host from its enrolment ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)). A request cannot name someone else.
- **Issuance needs a grant that `policy` sealed.** The grant names the tenant and what it allows, and `ca` opens it at key@ ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). A request the grant does not cover is refused.
- **key@ signs only what each purpose allows:** for `ca` a parseable TBSCertificate within its constraints, for `ssh-ca` an OpenSSH certificate body ([0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place)). `ca` and `ssh-ca` hold no key; they ask key@ to sign in place.
- **Serials are random 128-bit numbers, and no serial ledger is kept** ([0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place)). The record of what was issued is the issuance log and the kinds below.

### What the authorities keep

- **`ca` writes `IssuedCertificate`, `Revocation`, `Crl` and `TrustBundle`; `ssh-ca` writes `IssuedSshCertificate`, `SshRevocation` and `Krl`.** Each kind has these actors as its one writer ([0004](/decisions/0004-the-data-model/#one-writer-per-kind)). An `IssuedCertificate` and an `IssuedSshCertificate` are durable and sealed, because the requester, the subject and the principals are personal data. The serial is the id, and a lookup by subject uses a keyed hash made by key@.
- **`Crl` and `Krl` are temp kinds derived from the revocations,** and `TrustBundle` is rendered by `ca` from `TrustAnchors` and `KeyCertificate`. They are public material and exportable: exporter@ publishes them to a bucket ([0009](/decisions/0009-export/#destinations)), so they are served while the issuer's compute is down.
- **`PkiProfile` is the config kind that says which profiles `ca` and `ssh-ca` issue for whom.** The shape of each profile is built in, and the lifetimes of [Leaf profiles](/decisions/0023-certificate-authorities/#leaf-profiles) are floors in code.

### X.509

- **`ca` issues every leaf from the boundary's one intermediate.** The trust domain is the boundary ([0022](/decisions/0022-workload-identity-and-host-enrolment/#trust-domains)), so there is one intermediate per trust domain and no intermediate per use. Uses are kept apart by certificate profiles: each profile fixes the key usages, the extended key usage and a subject or SAN form that no other profile can produce, and an intermediate carries name constraints where its relying parties need them. The profile of the intermediate itself is in ritueel's hand-off contract.
- **The leaf profiles are:** the host X.509-SVID, the workload X.509-SVID, sluis's own mutual-TLS certificates, the database client certificate ([Database client certificates](/decisions/0023-certificate-authorities/#database-client-certificates)), and the certificates cert-manager requests. The token-signing certificate is a non-CA profile of [0006](/decisions/0006-keys-and-sealing/#the-token-signing-key). Their fields and lifetimes are in [Leaf profiles](/decisions/0023-certificate-authorities/#leaf-profiles).
- **Clusters keep cert-manager and trust-manager.** `ca` signs for cert-manager through an external issuer, shipped as its own chart; the issuer accepts a CSR with an empty subject and takes the identity from the requester. `ca` writes no Kubernetes object.
- **The trust bundle is rendered by `ca`.** Its content and how hosts sync it are in [0022](/decisions/0022-workload-identity-and-host-enrolment/#the-trust-bundle).
- **ACME (RFC 8555) comes after the first release** ([#978](https://github.com/truvity/sluis/issues/978)). Until then a host sends a CSR to `ca`'s issue call, through the enrolment API or the certificate module of `sluis-host`.

### The intermediate's name constraints

- **Each environment's intermediate is name-constrained to that environment.** `sluis key request` writes critical name constraints into the request ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)), built from the boundary's declared names:
  - permitted URI: the boundary's SPIFFE trust domain ([0022](/decisions/0022-workload-identity-and-host-enrolment/#trust-domains));
  - permitted DNS: the boundary's public hosts (`sluis.<env>.example.com`), the environment's private zone under the reserved `.internal` top-level domain (for example `prod.example.internal`), and any further host zones the boundary declares;
  - permitted IP: only ranges the boundary declares; with none declared, the request excludes `0.0.0.0/0` and `::/0`, so no leaf of that intermediate can carry an IP address that verifies.
- **A development intermediate cannot vouch for a production name.** Each environment declares its own zone, and the intermediates of two environments permit disjoint names.
- **`ca` refuses a leaf outside its intermediate's permitted subtrees** before it asks key@ to sign, so a mistake is a refusal at the issuer and not a certificate that verifiers reject.
- **The intermediate's other fields** (path length, extended key usage, validity of about 13 months) are ritueel's hand-off contract and are not repeated here.

### Leaf profiles

Every leaf has a random 128-bit serial, `basicConstraints` critical with CA false, a critical `keyUsage` of `digitalSignature` only, and its subject key's algorithm as [0006](/decisions/0006-keys-and-sealing/#algorithms) allows. A profile fixes the rest, and no two profiles can produce the same certificate shape:

| Profile | Extended key usage | Names | Default lifetime | Maximum |
|---|---|---|---|---|
| Token signing (non-CA) | none | Subject `CN=token-signing, OU=<actor>@<boundary>`; no SAN | To the issuing intermediate's `notAfter` | The intermediate's `notAfter` |
| Workload X.509-SVID | `serverAuth`, `clientAuth` | Exactly one URI SAN, the workload's SPIFFE ID; empty subject | 1 hour | 24 hours |
| Host X.509-SVID | `serverAuth`, `clientAuth` | The host's URI SAN, plus its declared or derived DNS names ([SSH](/decisions/0023-certificate-authorities/#ssh)) | 24 hours | 7 days |
| sluis mutual TLS | `serverAuth`, `clientAuth` | Exactly one URI SAN, the actor's SPIFFE ID ([Names](/decisions/0002-families-of-actors/#names)) | 24 hours | 24 hours |
| Database client | `clientAuth` only | Subject `CN=<role>, OU=<requester>, O=sluis-database`; no SAN | Set by policy | 12 hours |
| cert-manager | `serverAuth`, and `clientAuth` when requested | DNS and URI names taken from the requester's identity, never from the request alone | The requested duration | 90 days |

- **The token certificate cannot serve TLS or issue.** It has no SAN and no CA flag, so a TLS client's name check fails and a path validator refuses it as an issuer. It is re-issued over the same key whenever its intermediate is renewed, so its `x5c` chain is never older than the intermediate.
- **Policy may shorten any lifetime, never lengthen it past the maximum.** The maxima are floors in code ([0006](/decisions/0006-keys-and-sealing/#floors-in-code)); `sluis config check` refuses a declared lifetime above one.
- **SSH certificate lifetimes** are in [SSH](/decisions/0023-certificate-authorities/#ssh).

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
- **SSH revocation is a key revocation list** (by serial and by key), the kind `Krl`, that `sluis-host` keeps current. Standing access ends when the next bundle drops a line, so the KRL is for stolen keys and certificates.

### Database client certificates

- **Self-run PostgreSQL and CNPG get short-lived client certificates from `ca`**, under the database client profile:
  - the common name (CN) is the **database role**; the organisational unit (OU) is the **person or workload** that asked, filled by `ca` from the authenticated requester, never from the request;
  - the profile has client-authentication usage only and a fixed subject form that no other profile can produce;
  - the database matches with `clientname=DN` and a **fixed regular-expression map** on the full subject, so a certificate of any other profile matches no role, and the full subject lands in the database's log.
- **Policy decides which roles a requester may ask for**, and each role's lifetime under a maximum.
- **Some names are reserved:** `ca` never issues for a replication role (such as CNPG's `streaming_replica`) or the database's owner role.
- **The private key stays on the client**, which sends a CSR.
- **People and machines use the flows they already have.** The `sluis` CLI requests a certificate for a key on the person's machine and starts the database tool with the standard libpq variables; a machine presents its workload proof in a token exchange. In Kubernetes, certificates reach pods first through the cert-manager issuer (namespace identity, key in a Secret), then through the `sluis agent` sidecar (identity per pod, shipped as an image and a snippet).
- **CNPG keeps a CA of its own for replication between its instances.** Its server certificates come from cert-manager, through the sluis-backed issuer, under the cert-manager profile. Client certificates for application roles come from the database client profile, and the server trusts sluis's chain for them beside the replication CA.
- **The wiring of a particular database stays outside sluis.** `pg_hba` lines, ident maps, roles and grants live in that database's own repository; sluis documents the scheme and prints reference snippets.
- **RDS and Aurora use IAM authentication, outside sluis.** sluis makes no RDS token and holds no database credential; a small helper makes the token from AWS credentials that sluis provides through `credential_process`.
- **sluis's own data in PostgreSQL** follows the row-level security rules of [0028](/decisions/0028-audit-pieces/#postgresql-row-level-security).

### Issuance log and revocation

- **Every X.509 certificate is logged.** `ca` emits each certificate as an entry of the issuance log through its audit emit port. The issuance log is a third log kind of the audit writer, beside the audit log and the usage log, and its entries and checkpoints are in the C2SP `static-ct-api` format: the writer tiles it, signs its checkpoints through key@ with the issuance-log key, and has it witnessed like the audit log ([0029](/decisions/0029-the-audit-log/#witnesses)). The key is enabled on use in every boundary that runs `ca` ([0006](/decisions/0006-keys-and-sealing/#key-purposes)). `ca` itself holds no blob credential.
- **Every certificate is audited:** the requester, the profile, the role where there is one, the serial, the validity and the public key hash.
- **Short lifetimes are the main control; revocation sits behind them** and is described in [Revocation](/decisions/0023-certificate-authorities/#revocation) for X.509 and in [SSH](/decisions/0023-certificate-authorities/#ssh) for SSH.

### Revocation

- **Each intermediate has one static CRL of its leaves,** the kind `Crl`: a full list with no delta, signed by the intermediate and published in the boundary's bucket beside the key set. A database that configures the CRL checks it.
- **The CRL is re-signed every 24 hours with a `nextUpdate` of 7 days,** and at once after a revocation. A relying party that misses a day of fetches keeps a valid list.
- **A revoked serial stays on the list until its certificate expires.** In practice that matters only for profiles longer than a day: the host X.509-SVID, the database client at its maximum, and cert-manager certificates.
- **Leaves carry no CRL distribution point and no OCSP address.** A relying party that checks revocation configures the CRL's URL, as PostgreSQL does with `ssl_crl_file`.
- **The intermediate itself is revoked by a root's CRL, which ritueel signs** (valid 25 months), not by this one ([0024](/decisions/0024-root-custody-and-the-signing-api/#root-pins-and-the-root-list)).

## Consequences

- One SSH certificate works on every host of its environment, never reaches the 256-principal cap and shows nothing about the estate.
- Standing access is revoked by the next bundle, not by waiting for expiry. An outage longer than the staleness limit locks out normal logins, while grant, elevation and break-glass access keep working.
- Every host with standing access runs `sluis-host`; a host in static mode has a manual revocation list and CA rotation.
- The break-glass CA is a second trust root on each host, offline and guarded by ritueel.
- Two CA actors mean two sets of profiles and conformance tests, two units, and two things to publish: X.509 anchors and CRLs, SSH CA keys and KRLs. On a 2 GB board two units cost memory: `ca` and `ssh-ca` hold 54.6 MiB together, so keeping them apart costs about 27 MiB per board, 1.4 % of it (MEASURED 2026-11-03, [0037](/decisions/0037-capacity-is-measured-before-it-is-promised/#board-capacity)).
- One intermediate per boundary keeps the slot map and the yearly re-certification small. The cost is that separation between uses rests on the profiles and the databases' fixed subject maps, which are therefore tested as security controls.
- A workload or actor certificate stolen from memory is useless within a day, usually within an hour, with no revocation needed. The cost is issuance load: every workload renews about every 40 minutes and every actor daily, which `ca` and key@ must carry ([0006](/decisions/0006-keys-and-sealing/#keys-per-board)).
- A misconfigured `ca` in one environment cannot produce a certificate that a verifier in another environment accepts for its names, provided the verifier enforces name constraints, which current TLS libraries do. Excluding all IP ranges by default means a host reached by address needs a declared range before it can get a certificate for it.
- No database password is shared or rotated by hand. Revocation is weak unless the database configures the CRL, so lifetimes stay short. The first Kubernetes path puts a key in a Secret, readable by anyone who can read the Secret, until the sidecar ships. The fixed database subject form and the `O=sluis-database` marker are what the regular-expression map in each database matches; they are tested as security controls.
- The issuance log needs no store of its own and no blob credential in `ca`: the audit writer carries it, with its tiles and witnesses.
- `sluis config check` refuses a policy that uses `reported` attributes in a permit, and a `g:` grant outside the three allowed cases.
- To verify when built: the 256-principal cap; that `sshd` logs the key ID only at `LogLevel VERBOSE`; Cedar's datetime support for time-boxed grants; which `sshd` files are read per login and which need a reload.
- Threats addressed: T-8, T-9, T-19, T-20 and T-26, see the [threat model](/security/threat-model/).
- Requirements: [REQ-PKI-043](/requirements/pki/#REQ-PKI-043) to [REQ-PKI-049](/requirements/pki/#REQ-PKI-049).

## Roads not taken

- **opkssh as a second SSH path.** No CA key to protect, but a binary and policy files on every host, no host certificates and login audit left on each host.
- **A secret store's SSH or database engine.** The v1 path, but a second system with its own trust and audit and an admin credential for every database.
- **One `ca` actor for X.509 and SSH.** One process would hold two different authorities, and key@'s purpose check would be the only separation between them.
- **A separate intermediate per use (for example for databases, workloads or cert-manager).** Each costs a request, a certification, a card slot and a yearly renewal; profiles and fixed subject maps give the same separation.
- **Intermediates without name constraints.** Any intermediate of any environment could then vouch for production names, and ritueel's contract requires a permitted subtree.
- **Grant principals in every certificate.** Certificates would grow with the organisation, leak the topology and hit the 256 cap.
- **Bare user names, or principals prefixed by installation.** Any trusted CA could mint any name, or the prefix repeats what one CA per host already gives.
- **Reported attributes and cloud tags may grant.** Whoever can tag an instance could move it into a policy.
- **Lines that never expire, or `AuthorizedPrincipalsCommand` at each login.** A removed person keeps access on a host that stopped refreshing, or a moving part sits in the login path.
- **An emergency certificate from sluis as break-glass.** Useless when sluis is down, which is when break-glass is needed.
- **The person's name as CN mapped to a role, or PostgreSQL 18 OAuth.** A map per database listing people, or a validator module on every server plus device login, which is postponed.
- **An OCSP responder.** An online service on the trust path for a control that short lifetimes already give; REQ-PKI-008 keeps it out until a record decides it.
- **A CRL distribution point in every leaf.** Few clients fetch it, and a client that does would make sluis's bucket a dependency of every TLS handshake.
- **Day-long workload certificates.** Simpler renewal, but a stolen workload key would stay useful for a day where an hour suffices for SPIFFE practice.
- **An extended key usage for the token certificate.** No registered EKU means "signs JWTs"; the missing SAN and CA flag already keep it out of TLS and issuance.
- **The issuance log as a durable kind written by `ca`.** It would have no tiles and no witnesses, so a certificate could be dropped from it unseen.
- **A blob credential for `ca`, to keep its own log.** It would make `ca` a fifth kind of credential holder, against [principle 16](/principles/#16-few-credential-holders).

## Follow-ups

- ACME in `ca`, after the first release: [#978](https://github.com/truvity/sluis/issues/978).
- Merkle Tree Certificates (`mtc-tlog`) on the post-quantum track: Later, [#1029](https://github.com/truvity/sluis/issues/1029).
- The X.509 CA actor that implements the profiles: [#913](https://github.com/truvity/sluis/issues/913).
- DNS name constraints in ritueel's policy, so that ritueel checks the DNS part of an intermediate's constraints: [truvity/ritueel#70](https://github.com/truvity/ritueel/issues/70).
