# Connect a secret manager that mints certificates

**Anchor:** the issuer. A secret manager — OpenBAO, or a Vault that
speaks the same API — trusts it on a JWT auth mount and mints
**short-lived certificates** for things that speak neither OpenID nor a
cloud's own protocol: an SSH server, a database, a service that wants
mutual TLS. `accessctl credential` is the courier
([reference](../reference/accessctl.md#credential-certificates-openbao-mints)).

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
accessctl credential ssh --env staging --principal deploy
ssh deploy@host.example                 # the agent offers the certificate

accessctl credential db --env staging \
    --host db.example --dbname orders --service orders
psql "service=orders"

accessctl credential client --env staging --out ./gateway.crt
```

`--address` names the manager, or `BAO_ADDR` in the environment
(`VAULT_ADDR` is read too); with neither, the command stops and says
which to set. The namespace is the environment's own, named for it —
`--env staging` works in `staging` — for every kind. `--namespace`, or
`BAO_NAMESPACE` (then `VAULT_NAMESPACE`), overrides it, the flag first;
a database role kept in a project's own namespace is reached with
`--project <project>`, which means `<project>/<env>`.

A manager whose API certificate chains to a private root is reached by
naming that root: `--ca-cert <file>` (a PEM bundle), or `BAO_CACERT`
(then `VAULT_CACERT`), the flag first — the same variables the `bao` CLI
reads. The bundle is added to the system's roots for the connection to
the manager and nothing else, so there is no need to point
`SSL_CERT_FILE` at it, which would replace the roots of every connection
the command makes.

The SSH role is `user` unless `--role admin` asks for the other one:
`user` for everyday logins as the account a host admits its ordinary
users as, `admin` for the account that administers it. The two are two
groups, granted separately, and which OS accounts each signs for is the
role's `allowed_users`, not a flag.

Each command prints the certificate's `key_id` or common name and its
serial — the handle for finding it in the audit trail — and never the
key.

## Job side

The same commands run in a GitHub Actions job granted `id-token: write`:
the job's own identity token is exchanged instead of a sign-in, and the
`ci` rules decide which repository and ref may hold those groups
([github-actions.md](github-actions.md)). A job has no ssh-agent, so
`--identity` is how it gets a usable certificate on disk.

A job that needs one shared value is not one of the project's three
groups. It gets an identity of its own with `read` on the one path it
needs, so that what a pipeline can read is a line in the declaration
rather than the whole prefix.

## Sign in to OpenBAO

The console is not where a person reads the manager. To reach one, use the
manager's own OIDC login or the issuer as a broker: the manager trusts the
issuer, a person signs in to the issuer, and the issuer vouches for them.
The console no longer reads a store's policies or groups (removed in v1.30.0,
see [decisions/0002-mission-boundary-tokens-and-memberships.md](../decisions/0002-mission-boundary-tokens-and-memberships.md)).
