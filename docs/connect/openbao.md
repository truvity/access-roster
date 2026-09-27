# Connect a secret manager that mints certificates

**Anchor:** the issuer. A secret manager — OpenBAO, or a Vault that
speaks the same API — trusts it on a JWT auth mount and mints
**short-lived certificates** for things that speak neither OpenID nor a
cloud's own protocol: an SSH server, a database, a service that wants
mutual TLS. `accessctl bao <args…>` authenticates and runs the real
`bao` binary unchanged for SSH and machine certificates (and everything
else OpenBAO can do); `accessctl pg`/`psql` do the same and additionally
mint a Postgres client certificate
([ADR 0013](../decisions/0013-openbao-access-through-the-bao-cli.md),
[reference](../reference/accessctl.md#bao-authenticate-then-run-bao-unchanged),
[reference](../reference/accessctl.md#pg--psql-a-postgres-client-certificate-then-a-command)).
This replaces `accessctl credential`, removed in v1.34.0.

The contract between the two sides — the doors, the claims, the two
clients, the credential paths and every failure mode — is
[truvity/openbao's docs/integrations/access-roster.md](https://github.com/truvity/openbao/blob/master/docs/integrations/access-roster.md),
tested there against a real server; what this side must provide for it is
[integrations/openbao.md](../integrations/openbao.md).

Nothing here is a second identity system. The policy decides **who may
ask**; the manager's roles decide **what they get**; the certificate
carries the same subject the issuer's audit trail does.

## The shape

```
accessctl                the issuer               OpenBAO
  sign-in  ──exchange──▶ aud=openbao ──login───▶  the jwt mount's role
                                                  ssh/sign/<role>
                                                  pki/sign/<role>
  ssh-agent ◀──────────── the certificate ──────  one call, no TTL asked
```

One exchange, one login, one `sign`, and then the manager's token is
revoked. Every kind signs a key made on the caller's machine — a public
key for SSH, a CSR for the PKI kinds — so the private key never crosses
the wire and no role needs to offer `issue`. A session revoked in the console stops issuance within
the exchange's token cap, because every run exchanges afresh and nothing
is cached.

## Policy

One exchange client, and one group per thing that may be minted. The
client's `requires` is the whole answer to *who may ask*:

```yaml
groups:
  staging:ssh:user:         { members: [team-eng@example.com] }
  staging:ssh:admin:        { members: [role-sre@example.com] }
  staging:db:orders:client: { members: [team-eng@example.com] }
  staging:machine:gateway:  { members: [role-sre@example.com] }
clients:
  openbao:
    kind: static
    requires: [staging:ssh:user, staging:ssh:admin, staging:db:orders:client, staging:machine:gateway]
```

The group names follow the [naming rule](../design/trust.md#naming) as
everywhere else: environment, tier, then role. They are what the
manager's own policies bind to, so the groups in the token and the
policy that admits it cannot drift apart.

## Manager side

- **A JWT auth mount** per namespace, trusting the issuer's discovery
  document, with `bound_audiences: [openbao]` — the audience the exchange
  mints, and the only one it accepts. `accessctl` logs in on `jwt-roster`
  with the role `roster` unless `--mount` and `--login-role` say
  otherwise. Short token lifetimes: the login exists to make one call.
- **An SSH CA per environment**, with a role per group:
  - `allow_user_certificates: true`, `allow_host_certificates: false`;
  - `allowed_users` spelled out — the OS accounts that group may become;
  - a `key_id_format` naming the token's display name, so **every
    certificate carries the roster subject** and a line in an sshd log
    can be read against the issuer's audit trail;
  - `allow_user_key_ids: false`, so a caller cannot name itself;
  - `default_extensions` no wider than the group needs;
  - `ttl` and `max_ttl` short. `accessctl` never asks for a lifetime, so
    these two are the only answer, and shortening them shortens every
    certificate in flight.
- **A PKI role for database clients** (`db-client`), used through
  `pki/sign/db-client`: `key_type: ec` with `key_bits: 384` (or `any`) —
  `accessctl` sends a CSR for an ECDSA P-384 key — the common name is
  the roster subject (`use_csr_common_name` reads it from the CSR, and it
  is also in the request for a role that does not), client-auth extended
  key usage only, a short `max_ttl` — and on the database side a `pg_ident` map from that subject
  to a database role. The certificate is the credential; there is no
  password to rotate.
- **A PKI role for machine clients** (`client`), through
  `pki/sign/client`: the same key type, client-auth extended key usage, a
  short `max_ttl`, and whatever SAN the consumer matches on (the URI SANs
  are in both the CSR and the request, so `use_csr_sans` either way works).
- **Policies granting the sign path and nothing else.** No
  `read` and no `list` on role or configuration paths: a credential group
  has no business reading how its own role is defined.
- **An audit device**, so every signing is queryable by subject
  beside the issuer's own trail.

The roles are the installation's to create, and the revocation model is
the TTL: these leaves are short enough that no revocation list is kept,
which is a decision to write down rather than to discover.

## Person side

```sh
accessctl bao --address https://openbao.example:8200 ssh -mode=ca -role=user -namespace=staging deploy@host.example
                                         # an interactive session; ssh's own agent handling applies

accessctl psql --address https://openbao.example:8200 -ns staging -- -h db.example -d orders

accessctl bao --address https://openbao.example:8200 write -namespace=staging -field=signed_key \
    ssh/sign/user public_key=@key.pub > key-cert.pub    # for scp, git, CI and Ansible instead
```

`--address` names the manager, or `BAO_ADDR` in the environment
(`VAULT_ADDR` is read too); with neither, the command stops and says
which to set. For `bao`, the namespace is read out of `bao`'s own
`-namespace` (or `BAO_NAMESPACE`, then `VAULT_NAMESPACE`) — the flag
goes AFTER the subcommand, where `bao` has always accepted it; for
`pg`/`psql`, the same variable is read through `-ns` (or the same two
environment variables), a flag of accessctl's own since neither command
has a subcommand to attach it to. A database role kept in a project's
own namespace is reached the way the project's own OpenBAO layout
requires — see that project's own documentation for its namespace path.

A manager whose API certificate chains to a private root is reached by
naming that root: `--ca-cert <file>` (a PEM bundle), or `BAO_CACERT`
(then `VAULT_CACERT`), the flag first — the same variables the `bao` CLI
reads. The bundle is added to the system's roots for the connection to
the manager and nothing else, so there is no need to point
`SSL_CERT_FILE` at it, which would replace the roots of every connection
the command makes.

The SSH role is `user` unless `-role=admin` asks for the other one:
`user` for everyday logins as the account a host admits its ordinary
users as, `admin` for the account that administers it. The two are two
groups, granted separately, and which OS accounts each signs for is the
role's `allowed_users`, not a flag — this is `bao`'s own `-role` flag,
unchanged from OpenBAO's own CLI.

## Job side

The same commands run in a GitHub Actions job granted `id-token: write`:
the job's own identity token is exchanged instead of a sign-in, and the
`ci` rules decide which repository and ref may hold those groups
([github-actions.md](github-actions.md)). A job has no ssh-agent, so the
`accessctl bao write ... > key-cert.pub` recipe (or `accessctl psql`,
which needs no agent at all) is what it uses.

A job that needs one shared value is not one of the project's three
groups. It gets an identity of its own with `read` on the one path it
needs, so that what a pipeline can read is a line in the declaration
rather than the whole prefix.

## Sign in to OpenBAO

The console is not where a person reads the manager. To reach one, use the
manager's own OIDC login, `accessctl bao` (below), or the issuer as a broker
directly: the manager trusts the issuer, a person signs in to the issuer,
and the issuer vouches for them. The console no longer reads a store's
policies or groups (removed in v1.30.0, see
[decisions/0002-mission-boundary-tokens-and-memberships.md](../decisions/0002-mission-boundary-tokens-and-memberships.md)).

## `accessctl bao`, in full: any other OpenBAO command

The examples above cover SSH and machine certificates. `accessctl bao
<args…>` runs anything else OpenBAO can do the same way — `bao kv get`,
an engine this page does not mention — with the same exchange and
JWT-mount login, then the real `bao` binary, unchanged, with the login
handed to it as `BAO_TOKEN`
([ADR 0013](../decisions/0013-openbao-access-through-the-bao-cli.md)).

```sh
accessctl bao --address https://openbao.example:8200 kv get -ns=staging secret/app
accessctl bao --address https://openbao.example:8200 kv get -ns=staging -format=env secret/app > .env
accessctl bao --address https://openbao.example:8200 ssh -mode=ca -role=user ci@build-worker.example
accessctl bao --address https://openbao.example:8200 write ssh/sign/user public_key=@key.pub -field=signed_key > key-cert.pub
```

accessctl's own flags (`--address`, `--ca-cert`, `--mount`,
`--login-role`, `--audience`, `--issuer`, `--client`, `--forget`) go
BEFORE the bao subcommand; `bao`'s own — including `-namespace` (or its
shortcut `-ns`), which decides which namespace the login itself happens
in — go AFTER it, exactly where `bao` has always accepted them. The
token is cached under
accessctl's own config directory, never `~/.vault-token` and never bao's
own token helper file; `accessctl bao --forget` revokes and clears it.
Full reference: [reference/accessctl.md#bao-authenticate-then-run-bao-unchanged](../reference/accessctl.md#bao-authenticate-then-run-bao-unchanged).
