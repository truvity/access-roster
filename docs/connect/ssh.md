# Connect SSH — people, machines and hosts

**Anchor:** the issuer, and only the issuer. access-roster mints the
tokens; it never signs an SSH key. The secret store (OpenBAO, or a Vault
that speaks the same API) builds the certificate authority, and each
host's own owner installs and configures the pieces that run there. Three
different problems share one issuer, because "who signs in" is one
question and "who runs the CA" is another
([ADR 0011](../decisions/0011-ssh-people-opkssh-machines-and-hosts-openbao.md)).

| Who | Authenticates with | Owner of that piece |
|---|---|---|
| a person | **opkssh** — an OpenID Connect ID token, verified straight into `sshd` | — |
| a machine (a CI job, a controller) | **accessctl bao ssh -mode=ca** (or `accessctl bao write ... sign/<role>`) — a short-lived OpenBAO-signed user certificate | — |
| a host | **a host certificate** from OpenBAO's SSH CA | — |

The [Who owns what](#who-owns-what) table at the end places every piece
against who builds it.

## People: opkssh

[opkssh](https://github.com/openpubkey/opkssh) (OpenPubkey SSH) admits an
OpenID Connect ID token straight into `sshd`, with no certificate
authority and no broker in between: the token itself, wrapped as an SSH
public key extension, is what `sshd` asks opkssh to verify. Versions and
file formats below are opkssh **v0.16.0**, cross-checked against
[openpubkey](https://github.com/openpubkey/openpubkey)
commit `3c7487c` (2026-09-21).

### The issuer side: a public client row

```yaml
clients:
  opkssh:
    kind: public
    redirects:
      - http://localhost:3000/login-callback
      - http://localhost:10001/login-callback
      - http://localhost:11110/login-callback
    requires:     [devel:build-worker:operator, devel:router:operator]
    signing_alg:  ES256           # or RS256 — never this installation's ES384 default
    display_name: opkssh
```

The three loopback ports are opkssh's own defaults (its browser flow
listens on whichever is free). `requires` is the ordinary gate: only a
caller in one of these groups gets a token from this client at all.

**`signing_alg` is not optional here.** OpenPubkey's verifier accepts
**RS256, PS256, ES256 and EdDSA** ID tokens and refuses anything else,
`ES384` — this installation's default
([ADR 0005](../decisions/0005-es384-signing-algorithm.md)) — included
(`providers/providerverifier.go`'s `verifyIDTokenSig`, which returns
`unsupported signature algorithm` for anything outside that switch).
Pinning `signing_alg: RS256` or `ES256` on this one client row, while
every other audience keeps signing ES384, is exactly what per-audience
signing algorithms exist for
([ADR 0009](../decisions/0009-a-default-signing-algorithm-and-per-audience-exceptions.md),
shipped v1.31.0) — see
[reference/policy.md#signing-algorithm-per-audience](../reference/policy.md#signing-algorithm-per-audience).
This is the fix [ADR 0004](../decisions/0004-ssh-opkssh-and-the-secret-stores-ca.md)
was waiting on.

### The client side: `~/.opk/config.yml`

```yaml
default_provider: access-roster

providers:
  - alias: access-roster
    issuer: https://access.example
    client_id: opkssh
    scopes: openid email profile groups
    redirect_uris:
      - http://localhost:3000/login-callback
      - http://localhost:10001/login-callback
      - http://localhost:11110/login-callback
```

`scopes` must include `groups` — without it the ID token carries no
`groups` claim, and every `oidc:groups:` rule on every server has nothing
to match. Generate the file's skeleton with `opkssh login --create-config`
and edit in this provider (opkssh README, "Client Config File").

### The server side

Install opkssh (`scripts/install-linux.sh` from the opkssh release, or
the platform installer for Windows), then:

```
# /etc/ssh/sshd_config
AuthorizedKeysCommand /usr/local/bin/opkssh verify %u %k %t
AuthorizedKeysCommandUser opksshuser
```

`opksshuser` is a low-privilege, no-login system account created for
exactly this — opkssh's own installer creates it. `sshd` reloaded.

```
# /etc/opk/providers — issuer, client_id, expiration policy
https://access.example opkssh 24h
```

**`24h` matches this issuer's session bound on purpose**
([ADR 0001](../decisions/0001-sessions-and-an-absolute-limit.md)'s
24-hour absolute limit) — opkssh's own default is also `24h`, so this is
one line to add per installation, not a value to tune.

```
# /etc/opk/auth_id — principal   identity                                        issuer
ops  oidc:groups:devel:build-worker:operator  https://access.example
```

`oidc:groups:<name>` reads the token's `groups` claim, and `<name>` is
one of this policy's internal group names — the same string `requires`
already names, nothing remapped
(opkssh README, "`/etc/opk/auth_id`"). Add lines by hand or with
`sudo opkssh add ops oidc:groups:devel:build-worker:operator access-roster`.

Every server needs outbound network reach to the issuer's discovery
document and JWKS endpoint: opkssh's verifier fetches the provider's
current signing keys itself
(`providers/providerverifier.go`), so it is a live dependency on every
verification, not a one-time fetch at install.

### Host groups in the vocabulary

Internal groups for SSH follow the same
**`<scope>:<thing>:<role>`** naming as every other grant
([reference/policy.md#naming](../reference/policy.md#naming)). The
vocabulary of `thing`s an installation names is its own — this guide's
`build-worker`, `router` and `edge-device` are illustrative, not
reserved words — and is versioned separately from the issuer itself
(v1.32.0). A kind of host
is the `thing`; a generic three-rung ladder — `user` for an everyday
login, `operator` for one that can also run day-to-day operations,
`admin` for one that administers the host — reads naturally as three
groups per host kind:

```yaml
groups:
  devel:build-worker:user:     { members: [team-eng@example.com] }
  devel:build-worker:operator: { members: [role-sre@example.com] }
  devel:build-worker:admin:    { members: [role-sre-lead@example.com] }
  devel:router:user:           { members: [team-net@example.com] }
  devel:router:operator:       { members: [role-netops@example.com] }
  devel:edge-device:user:      { members: [team-fleet@example.com] }
```

**Without a declared vocabulary, the ladder is a convention you build,
not something the issuer computes.** `groups` is a flat set — the whole
of the authorization a token carries, with no built-in widening absent
one
([reference/policy.md#groups--token-by-deep-merge](../reference/policy.md#groups--token-by-deep-merge)) —
so *"operator can do what user can, admin can do what operator can"*
is expressed by repeating a group across `auth_id` lines for the
principals each role should reach, not by one group implying another:

```
# principal   identity                                        issuer
ops   oidc:groups:devel:build-worker:user      https://access.example
ops   oidc:groups:devel:build-worker:operator  https://access.example
ops   oidc:groups:devel:build-worker:admin     https://access.example
root  oidc:groups:devel:build-worker:admin     https://access.example
```

Here anyone in `user`, `operator` or `admin` reaches the `ops` account,
and only `admin` also reaches `root` — the ladder lives in which lines
were written on this host, in `git`, same as every other rule.

**With a [declared vocabulary](../reference/policy.md#vocabulary)
(v1.32.0), the ladder is computed instead**, so one `auth_id` line per
login is enough. Declaring `build-worker`'s roles as explicit implies —
`roles: { user: [], operator: [user], admin: [operator] }` — means a
person in `devel:build-worker:admin` also holds `operator` and `user`,
so the same two accounts read:

```
ops   oidc:groups:devel:build-worker:user   https://access.example
root  oidc:groups:devel:build-worker:admin  https://access.example
```

## Machines: OpenBAO-signed short-lived SSH user certificates (recommended)

**`accessctl credential ssh` was removed in v1.34.0**
([ADR 0013](../decisions/0013-openbao-access-through-the-bao-cli.md)):
the commands below, `accessctl bao ssh -mode=ca …` and `accessctl bao
write ... sign/<role>`, are the same login, then the real `bao` binary,
rather than a dedicated subcommand. This page's shape (opkssh for
people, OpenBAO for machines and hosts) is unchanged; only which
accessctl command a machine runs is.

A CI job or a controller doing remote work over SSH is not a person at a
browser, so opkssh's interactive login does not fit it — except the one
case below. The recommended shape is the same broker
[connect/openbao.md](openbao.md) already documents for database and
client certificates, with SSH as one more kind it signs:

```
the job's own identity          the issuer                OpenBAO
 (a GitHub Actions OIDC          │                          │
  token, or a Kubernetes    ──exchange──▶ aud=openbao ──login──▶ jwt-roster / roster
  ServiceAccount token)                                     ssh/sign/<role>
                                                              │
                                                       a signed certificate
                                                        ── ssh-agent, or files
```

access-roster's documented contract routes every kind through the
issuer's exchange, never straight from the job's token to OpenBAO's JWT
mount — OpenBAO's JWT auth method could, in principle, trust a job's
issuer directly, but going through this issuer's exchange first is what
gives the certificate a subject the issuer's own audit trail agrees on,
and what makes the same policy `requires` gate SSH, the database role
and the client-certificate role alike.

### `accessctl bao ssh -mode=ca`, and `accessctl bao write` for files

Two shapes, from [cmd/accessctl/bao.go](../../cmd/accessctl/bao.go): an
interactive session, or a certificate written to a file for something
else to use.

```sh
accessctl bao --address https://openbao.example:8200 ssh -mode=ca -ns=staging -role=user deploy@build-worker.example
```

`bao ssh -mode=ca` is OpenBAO's own client-side SSH helper: it asks the
signing role named by `-role` for a certificate over a key it generates,
then runs `ssh` itself with it — agent handling, host key checking and
every other `ssh` behaviour exactly as when pointed at any other
CA-issued certificate. accessctl's own part ends at the login; `bao`'s
own flags (`-mode`, `-role`, `-namespace`, and anything else `bao ssh`
accepts) go after the subcommand, the same separation rule as any other
`accessctl bao` call.

```sh
accessctl bao --address https://openbao.example:8200 write -ns=staging -field=signed_key \
    ssh/sign/user public_key=@id_ci.pub > id_ci-cert.pub
scp -i id_ci ci@build-worker.example:backup.tar.gz .    # ssh reads id_ci-cert.pub beside id_ci automatically
```

`bao write ... -field=signed_key` is the shape for scp, git, CI and
Ansible: a public key already on disk (`ssh-keygen -t ed25519 -f id_ci
-N ''` makes one), signed into a certificate file named the way OpenSSH
looks for it (`<key>-cert.pub` beside `<key>`), with no ssh-agent and no
interactive session needed. `-field=signed_key` prints only that one
field's value, which is the CA-issued certificate and nothing else —
without it, `bao write` prints OpenBAO's whole response.

**The lifetime is the role's, never a flag's**: neither recipe sends a
TTL to OpenBAO; the signing role's `ttl` and `max_ttl` are the entire
answer, so shortening them shortens every certificate already in flight.
Which OS accounts a role signs for is `allowed_users`, not a flag —
`-role=admin` asks for the account that administers a host, granted
separately from the everyday `-role=user`
([connect/openbao.md](openbao.md#manager-side)).

In a job, the same two recipes run with the job's own GitHub Actions
OIDC token or Kubernetes ServiceAccount token exchanged the same way any
other `accessctl` command exchanges one
([connect/github-actions.md](github-actions.md),
[connect/kubernetes-cluster.md](kubernetes-cluster.md)) — no separate SSH
credential to provision. A job has no ssh-agent, so the `bao write`
recipe (a file it can pass to `ssh -i` or `scp -i`) is the one it uses;
`bao ssh -mode=ca` is for an interactive session at a terminal.

### The alternative for GitHub-only CI: opkssh

opkssh supports GitHub Actions' own OIDC token natively (`opkssh login
github`, with `https://token.actions.githubusercontent.com github oidc`
in the server's `/etc/opk/providers`, and `auth_id` lines keyed on the
job's `sub` — `repo:<owner>/<repo>:ref:<ref>`) — verified against opkssh
`docs/github-actions.md` at v0.16.0.

**Prefer it** when the caller is *only* ever a GitHub Actions job and
never anything else: one fewer hop (no exchange, no OpenBAO login), and
one file (`auth_id`) rather than two systems (policy plus an OpenBAO
role) to keep in sync. **Prefer `accessctl bao`'s recipes above** the
moment an in-cluster runner, a controller carrying a Kubernetes ServiceAccount
token, or any other workload identity this issuer already accepts as a
matcher needs the same access: opkssh's provider list has no equivalent
of this issuer's `service_account` matchers, so a second, parallel
authorization surface would have to be maintained on every host for that
population — the reason [ADR 0011](../decisions/0011-ssh-people-opkssh-machines-and-hosts-openbao.md)
keeps the broker rather than standardising every machine on opkssh.

## Hosts: host certificates from OpenBAO's SSH CA

A host's own key is the one thing here that must never be a person's
problem to rotate, which is what a certificate authority is for — this
side is unchanged by opkssh's arrival for people, and
[connect/openbao.md](openbao.md#manager-side) is its fuller reference.

**A signing role**, distinct from the user-certificate roles above:

```
bao write ssh/roles/host-devel \
    key_type=ca \
    cert_type=host \
    allowed_domains="build-worker.devel.example,router.devel.example" \
    allow_bare_domains=true \
    allow_subdomains=true \
    ttl=720h \
    max_ttl=720h
```

`cert_type=host` (as opposed to the `user` certificates above) and
`allowed_domains` are the two fields that make this role only ever able
to certify hosts, never a login.

**How a host proves itself, before it can ask for a certificate:**

| Host kind | Proves itself with | What is delivered |
|---|---|---|
| a cloud VM | OpenBAO's **AWS auth method** | nothing — the instance's own IAM role is the proof, no secret ever shipped to the host |
| bare metal, provisioned with a device identity | **cert auth**, against a certificate issued during provisioning | the device certificate, minted once, out of band |
| bare metal, no device identity yet | **AppRole**, a one-time bootstrap secret | consumed on first boot; the host's own OpenBAO token is what it holds after that |

**Renewal**, so a rotation is never a person's task: the **OpenBAO
Agent**, run alongside `sshd`, with auto-auth against whichever method
above fits the host and a template that writes the returned certificate
to the path `sshd` reads and then reloads it — or, where running a whole
agent process is more than a host needs, a `systemd` timer on a schedule
well inside the role's `ttl`, running `bao write
ssh/sign/host-devel cert_type=host public_key=@/etc/ssh/ssh_host_ed25519_key.pub`
and reloading `sshd` on success.

```
# /etc/ssh/sshd_config
HostKey         /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

**Clients trust the CA, not each host**, with one line added once per
domain rather than a `known_hosts` entry per host:

```
# known_hosts
@cert-authority *.devel.example ssh-ed25519 AAAA... 
```

the public key `bao read ssh/config/ca` (or `ssh-keygen -L -f
<cert>`) prints.

## Who owns what

| Piece | Owner |
|---|---|
| the issuer, opkssh's client row, and every internal group | access-roster |
| the SSH CA, its signing roles (user and host), which auth methods hosts use, the OpenBAO Agent or timer that renews a host certificate | the secret store's owners |
| opkssh installed and wired into `sshd` (`AuthorizedKeysCommand`), `/etc/opk/providers`, `/etc/opk/auth_id`, `HostCertificate` in `sshd_config`, and `known_hosts` on every client | each host's own owner |
