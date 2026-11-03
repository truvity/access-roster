---
title: PostgreSQL and SSH
description: "How people and workloads open PostgreSQL sessions and SSH logins with short-lived certificates from the ca and ssh-ca actors, not passwords or long-lived keys."
status: target
sidebar:
  order: 8
---

PostgreSQL and SSH are **client profiles**, not integrations: sluis calls nothing outside for them. They have no adapter, no connection and no credential of a vendor. The `ca` and `ssh-ca` actors sign short-lived certificates, each after `policy` sealed a grant for the request ([0023](/decisions/0023-certificate-authorities/#two-authorities-two-actors)); the database or the host decides what the certificate may do. Both actors hold no key: they ask key@ to sign in place.

## PostgreSQL

The `ca` actor signs a short-lived X.509 client certificate from the boundary's one intermediate, under the **database client profile**, and the database maps the certificate's subject to a role. The record is [0023](/decisions/0023-certificate-authorities/#database-client-certificates); the work is [#926](https://github.com/truvity/sluis/issues/926).

It covers PostgreSQL that you run yourself, including CloudNativePG (CNPG). **Amazon RDS and Aurora use IAM authentication, outside sluis** (below).

### What PostgreSQL access is for

- **An engineer opens a database session** to investigate an incident. One command checks their sign-in and groups, gets a certificate for a key made on their machine, and starts the session. Nothing needs rotating.
- **A migration job connects** from CI with a certificate for its workload identity, valid for minutes, for the role it is entitled to.
- **No database password is shared.** The certificate's subject names the role and who asked.
- **Access follows the directory.** Leave the group, and the next request is refused; the old certificate dies by itself.

### Kinds of PostgreSQL integration

None. A client profile has no process and no credential of its own. The certificate is signed by [`ca`](/concepts/families/), whose intermediate key stays on a card or in a KMS key behind key@. The client generates its own P-384 key, which never leaves the machine, and sends a certificate signing request.

### The database client profile

| Field | Holds |
|---|---|
| Issuer | The boundary's intermediate, the same one that issues the boundary's other leaf certificates |
| Common name (CN) | The **database role** |
| Organisational unit (OU) | The **person or workload** that asked, filled by `ca` from the authenticated requester, never from the request |
| Usage | Client authentication only, with a fixed subject form no other profile can produce |

Because one intermediate issues every leaf of the boundary, the separation is in the database's map: the server matches the full subject with `clientname=DN` and a **fixed regular-expression map**, so a certificate of any other profile matches no role, and PostgreSQL 14 and newer log the full subject, not only the role.

- **Reserved roles are never issued**: a replication role (such as CNPG's `streaming_replica`) and the database's owner role.
- **Short lifetimes are the main control.** PostgreSQL checks revocation only when a CRL is configured; `ca` publishes a static CRL, and a database that configures it checks it. The database client profile lasts at most 12 hours, and the CRL is re-signed every 24 hours with a `nextUpdate` of 7 days ([0023](/decisions/0023-certificate-authorities/#leaf-profiles)).
- **Every certificate is in `ca`'s issuance log** and in the audit record ([0023](/decisions/0023-certificate-authorities/#issuance-log-and-revocation)).

### What sluis asks PostgreSQL for

Nothing. The operator configures the database to trust the boundary's intermediate and to map subjects to roles. The wiring of a particular database (`pg_hba` lines, ident maps, roles and grants) lives in that database's own repository; sluis documents the scheme and prints reference snippets like these:

```text
# postgresql.conf
ssl = on
ssl_ca_file  = '/etc/postgresql/sluis-ca.pem'     # the boundary's intermediate and roots
ssl_crl_file = '/etc/postgresql/sluis-ca.crl'     # ca's static CRL, refreshed
# pg_hba.conf: match the full subject, so the log shows who it was
hostssl orders all 0.0.0.0/0 cert clientname=DN map=sluis
# pg_ident.conf: the fixed map; CN = role, OU = person or workload
sluis   "/^CN=([a-z_]+),OU=[^,]+,O=sluis-database$"   \1
```

sluis publishes its CA certificates and CRLs as static documents, so a server fetches them rather than copying by hand. The server's own TLS certificate may come from another CA; clients name its root in `sslrootcert`.

**CNPG** keeps its built-in per-cluster CA for replication between instances. The server certificates applications verify come from cert-manager through the sluis-backed issuer, and trust-manager distributes the trust bundle to the pods.

### Certificates in pods

1. **The cert-manager issuer backed by `ca`**, first: an identity per namespace, with the key in a Secret, readable by anyone who can read the Secret. The issuer has its own chart ([Packages](/distribution/packages/)).
2. **The `sluis agent` sidecar**, next: an identity per pod, with the key kept in the pod.

### RDS and Aurora

IAM database authentication on RDS and Aurora is **outside sluis**. sluis makes no RDS token and holds no database credential. A small helper makes the token from ordinary AWS credentials, which sluis provides through `credential_process` in the AWS configuration ([AWS](/integrations/cloud/#aws)).

### What policy controls for PostgreSQL

- **Who may ask for which role**: a group per database role, such as "members of `staging-db-orders-client` may get a certificate for the `orders` role".
- **The lifetime**, per role, under a maximum no request exceeds.
- **The subject** is always the authenticated requester; a request cannot name someone else.

### What is audited for PostgreSQL

Every certificate issued (the requester, the profile, the role, the serial, the validity and the public key hash) and every refusal with its reason. The private key never reaches sluis.

### PostgreSQL setup

Names are [illustrative](/integrations/#examples-are-illustrative).

1. Declare the database role and the groups that may ask for it.
2. Install the CA certificates and CRL on the database and add the map (above).
3. Give the engineer a committed, secret-free service file and the command.

```ini
# pg_service.conf, committed; no secret in it
[orders]
host=db.example.org
port=5432
dbname=orders
sslmode=verify-full
```

```text
$ sluis pg --service orders -- psql
```

The command uses the cached sign-in, requests a certificate, writes the key, certificate and CA to a private directory, and starts `psql` with the standard libpq variables (`PGSSLCERT`, `PGSSLKEY`, `PGUSER`, `PGSSLROOTCERT`). A machine presents its workload proof in a token exchange instead.

PostgreSQL 18's native OAuth is not used: it needs a validator module on every server and device login, which is postponed ([#855](https://github.com/truvity/sluis/issues/855)).

## SSH

SSH is a client profile like PostgreSQL. The **`ssh-ca` actor** signs user certificates and host certificates, each with a key of its own purpose that key@ keeps in a card slot or in KMS ([the key reference](/reference/keys/)). An installation that issues no SSH certificates has neither key. `ssh-ca` is separate from the X.509 `ca` because it is a different authority, and each environment boundary has its own ([Boundaries](/concepts/boundaries/)). The record is [0023](/decisions/0023-certificate-authorities/#ssh); the work is [#925](https://github.com/truvity/sluis/issues/925) and, for the host service, [#971](https://github.com/truvity/sluis/issues/971).

### What SSH is for

- **An engineer logs in to a host** with a certificate that expires the same day. `sshd` trusts the CA, and the host decides which account the person may use; there is no `authorized_keys` to edit.
- **A robot logs in from CI** with a certificate for its job, valid for minutes.
- **A client trusts a host without a first-connection prompt**: one `known_hosts` line trusts the host CA for a domain.
- **An administrator still gets in when sluis is down**, through the break-glass CA.

### Kinds of SSH integration

None. [`ssh-ca`](/concepts/families/) signs, `policy` decides who may log in where, and the host service `sluis-host` writes the result on each host.

### The certificate carries identity only

A user certificate says **who** is logging in, not **where** they may go.

| Principal | Meaning | Used for |
|---|---|---|
| `u:<person-key>` | A person, by the same opaque key as `sub` in a token | Every person |
| `w:<workload>` | A workload, named for the workload, not the instance | CI jobs and workloads |
| `g:<account>@<group>` | A grant | Only hosts without `sluis-host`, sluis's own hosts, and elevation |
| `bg:<scope>` | Break-glass | Signed by the break-glass CA only |

Each prefix is a kind, so kinds cannot collide, and each host trusts one sluis CA. The key id is `<installation>/<subject>/<session>`, and `sshd` logs it.

**The host holds the authority.** `sluis-host` writes `/etc/ssh/principals/<account>` from a bundle that Cedar policy computed. Each line carries `expiry-time` equal to the bundle's expiry, and `from=`, `command=` or `no-pty` where policy says so. Groups of hosts come from declared rules over attested and declared host attributes; the console can only narrow them.

### The break-glass SSH CA

Break-glass SSH access comes from an **offline SSH CA that ritueel makes and holds** ([ritueel](https://ritueel.id)), never from sluis: an emergency certificate from sluis would be useless when sluis is down, which is when it is needed. Hosts trust a list of SSH CA keys that ritueel publishes, signed by a root and carrying a version that only increases; a host refuses a list with a lower version ([#1072](https://github.com/truvity/sluis/issues/1072)). sluis's own `ssh-user` and `ssh-host` keys are anchors in that list, not a chain ([0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place)).

The `bg:` lines are written at install from that list and are never touched by the principals bundle, so they keep working when the bundle is stale. For a pet host, break-glass is this CA; cattle are replaced instead. Recovery of sluis itself is a different thing, with passkeys ([Break-glass recovery](/security/break-glass/)).

### sluis-host

`sluis-host` is a **separate root service** under systemd, mainly for SSH and small on purpose.

- It **never listens on the network.** It fetches the bundle, verifies it, writes the files atomically, runs a reload hook and keeps the last good bundle.
- It **fails static**: if sluis is unreachable, the last good bundle stays in force until it expires. It alerts when the revocation list or the host certificate gets old.
- **A stale bundle locks out normal logins** after 24 hours by default, adjustable per group. Grant, elevation and break-glass lines are not in the bundle and keep working.
- It ships in the `.deb` and `.rpm` packages as `sluis-host` ([Packages](/distribution/packages/)).
- A host joins with the host enrolment flow, and its host certificate follows from that identity ([Identity](/concepts/identity/)).

### What policy controls for SSH

- **Two Cedar actions.** `ssh.login` (person, host, account) is evaluated when the bundle is built; `ssh.certify` when a certificate is signed, and sets the lifetime, extensions, source address and any `g:` grants.
- **Accounts.** Role accounts by default: `ops` with sudo, `ops-ro`, and forced-command accounts. Per-person accounts are opt-in per group, with stable uids, locked and never deleted. Nobody logs in as root.
- **Elevation.** Appliances and small estates get sudo on `ops`; the data tier and tier 0 get **elevation only**: requested, with fresh MFA, for 15 to 60 minutes, as a `g:` principal.
- **Lifetimes.** By default 12 hours for people, 15 minutes for elevation, 10 minutes for workloads.
- **Names.** Declared for pet hosts, derived for cattle, plus aliases; never a name the host reported itself.
- **Attributes that may grant.** Attested, declared and assigned ones; reported attributes and plain cloud tags never grant, and `sluis config check` refuses a policy that uses them, or a `g:` grant outside the three cases.
- **Hosts without the service.** OpenSSH devices that cannot run `sluis-host` use a static mode with `g:` principals and a revocation list updated by hand; devices without certificate support use pinned host keys.

### What sluis asks SSH for

Nothing. `sshd` stays stock: the operator sets it to trust the user CA and read the principals files, and signs the host keys with the host CA.

```text
# /etc/ssh/sshd_config on a host (example)
TrustedUserCAKeys        /etc/ssh/sluis_user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
RevokedKeys              /etc/ssh/sluis_krl
HostCertificate          /etc/ssh/ssh_host_ed25519_key-cert.pub
LogLevel                 VERBOSE
```

```text
# a client's known_hosts, one line per domain (example)
@cert-authority *.example.org ecdsa-sha2-nistp384 AAAA...
```

The CA public keys and the key revocation list (by serial and by key) are published statically, and `sluis-host` keeps the list current. Standing access ends when the next bundle drops a line, so the revocation list is for stolen keys and certificates. The certificate format is OpenSSH's own ([Standards](/standards/)). Post-quantum SSH certificates are not offered.

Four details are checked when `ssh-ca` is built: the cap of 256 principals per certificate, that `sshd` logs the key id only at `LogLevel VERBOSE`, which files `sshd` rereads without a reload, and the date and time support Cedar needs for time-boxed grants.

### What is audited for SSH

Every certificate (the requester, the principals, the serial, the validity and the key fingerprint), every refusal, every bundle built, and each publication of the revocation list.

### SSH setup

Names are [illustrative](/integrations/#examples-are-illustrative).

1. Declare the role accounts, the groups and the `ssh.login` rules in the policy.
2. Install `sluis-host` on each host and enrol the host.
3. Configure `sshd` as above.
4. On the client, sign in once, then:

```text
$ sluis ssh login
$ ssh ops@build.example.org
```

Machines get user certificates through their workload identity. sluis's own SSH CA is the only SSH path, and hosts need no hardware key.
