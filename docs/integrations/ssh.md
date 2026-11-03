---
title: SSH
description: How people and robots log in to hosts with short-lived SSH certificates from the ssh-ca actor, with principals files written by sluis-host from policy.
status: target
sidebar:
  order: 9
---

SSH is a **client profile** like [PostgreSQL](/integrations/postgresql/): sluis calls nothing outside. The **`ssh-ca` actor** holds two SSH certificate authority keys, one for user certificates and one for host certificates, each with a slot of its own on a card ([the card slot map](/concepts/keys/#the-card-slot-map)) or a key of its own in KMS. An installation that issues no SSH certificates has neither. `ssh-ca` is separate from the X.509 `ca` because it is a different authority, and each environment boundary has its own ([Boundaries](/concepts/boundaries/)). The record is [ADR 0023](/decisions/0023-certificate-authorities/#ssh); the work is [#925](https://github.com/truvity/sluis/issues/925) and, for the host service, [#971](https://github.com/truvity/sluis/issues/971).

## What it's for

- **An engineer logs in to a host** with a certificate that expires the same day. `sshd` trusts the CA, and the host decides which account the person may use; there is no `authorized_keys` to edit.
- **A robot logs in from CI** with a certificate for its job, valid for minutes.
- **A client trusts a host without a first-connection prompt**: one `known_hosts` line trusts the host CA for a domain.
- **An administrator still gets in when sluis is down**, through the break-glass CA.

## Integration kinds

None. [`ssh-ca`](/concepts/actors/) signs, `policy` decides who may log in where, and the host service `sluis-host` writes the result on each host.

## The certificate carries identity only

A user certificate says **who** is logging in, not **where** they may go.

| Principal | Meaning | Used for |
|---|---|---|
| `u:<person-key>` | A person, by the same opaque key as `sub` in a token | Every person |
| `w:<workload>` | A workload, named for the workload, not the instance | CI jobs and workloads |
| `g:<account>@<group>` | A grant | Only hosts without `sluis-host`, sluis's own hosts, and elevation |
| `bg:<scope>` | Break-glass | Signed by the break-glass CA only |

Each prefix is a kind, so kinds cannot collide, and each host trusts one sluis CA. The key id is `<installation>/<subject>/<session>`, and `sshd` logs it.

**The host holds the authority.** `sluis-host` writes `/etc/ssh/principals/<account>` from a bundle that Cedar policy computed. Each line carries `expiry-time` equal to the bundle's expiry, and `from=`, `command=` or `no-pty` where policy says so. Groups of hosts come from declared rules over attested and declared host attributes; the console can only narrow them.

## The break-glass SSH CA

Break-glass SSH access comes from an **offline SSH CA that ritueel makes and holds** ([ritueel](https://ritueel.id)), never from sluis: an emergency certificate from sluis would be useless when sluis is down, which is when it is needed. Hosts trust a list of SSH CA keys that ritueel publishes, signed by a root and carrying a version that only increases; a host refuses a list with a lower version ([#1072](https://github.com/truvity/sluis/issues/1072)). sluis's own `ssh-user` and `ssh-host` keys are anchors in that list, not a chain ([ADR 0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place)).

The `bg:` lines are written at install from that list and are never touched by the principals bundle, so they keep working when the bundle is stale. For a pet host, break-glass is this CA; cattle are replaced instead. Recovery of sluis itself is a different thing, with passkeys ([Break-glass recovery](/security/break-glass/)).

## sluis-host

`sluis-host` is a **separate root service** under systemd, mainly for SSH and small on purpose.

- It **never listens on the network.** It fetches the bundle, verifies it, writes the files atomically, runs a reload hook and keeps the last good bundle.
- It **fails static**: if sluis is unreachable, the last good bundle stays in force until it expires. It alerts when the revocation list or the host certificate gets old.
- **A stale bundle locks out normal logins** after 24 hours by default, adjustable per group. Grant, elevation and break-glass lines are not in the bundle and keep working.
- It ships in the `.deb` and `.rpm` packages as `sluis-host` ([Packages](/distribution/packages/)).
- A host joins with the host enrolment flow, and its host certificate follows from that identity ([Identity](/concepts/identity/)).

## What policy controls

- **Two Cedar actions.** `ssh.login` (person, host, account) is evaluated when the bundle is built; `ssh.certify` when a certificate is signed, and sets the lifetime, extensions, source address and any `g:` grants.
- **Accounts.** Role accounts by default: `ops` with sudo, `ops-ro`, and forced-command accounts. Per-person accounts are opt-in per group, with stable uids, locked and never deleted. Nobody logs in as root.
- **Elevation.** Appliances and small estates get sudo on `ops`; the data tier and tier 0 get **elevation only**: requested, with fresh MFA, for 15 to 60 minutes, as a `g:` principal.
- **Lifetimes.** By default 12 hours for people, 15 minutes for elevation, 10 minutes for workloads.
- **Names.** Declared for pet hosts, derived for cattle, plus aliases; never a name the host reported itself.
- **Attributes that may grant.** Attested, declared and assigned ones; reported attributes and plain cloud tags never grant, and `sluis config check` refuses a policy that uses them, or a `g:` grant outside the three cases.
- **Hosts without the service.** OpenSSH devices that cannot run `sluis-host` use a static mode with `g:` principals and a revocation list updated by hand; devices without certificate support use pinned host keys.

## What sluis asks the vendor for

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

The CA public keys and the key revocation list (by serial and by key) are published statically, and `sluis-host` keeps the list current. Standing access ends when the next bundle drops a line, so the revocation list is for stolen keys and certificates. The certificate format is OpenSSH's own ([Standards](/standards/)). Post-quantum SSH certificates are not offered: the Go SSH library has no ML-DSA algorithm.

Four details are checked when `ssh-ca` is built: the cap of 256 principals per certificate, that `sshd` logs the key id only at `LogLevel VERBOSE`, which files `sshd` rereads without a reload, and the date and time support Cedar needs for time-boxed grants.

## What is audited

Every certificate (the requester, the principals, the serial, the validity and the key fingerprint), every refusal, every bundle built, and each publication of the revocation list.

## Setup

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
