# Connect PostgreSQL: short-lived client certificates

**Anchor:** OpenBAO's PKI engine. People and machines reach PostgreSQL —
including a CloudNativePG cluster — with a client certificate that lives
minutes, not a password that lives until somebody remembers to rotate it.
`accessctl psql` / `accessctl pg --` are the couriers
([reference](../reference/accessctl.md#pg--psql-a-postgres-client-certificate-then-a-command),
replacing `accessctl credential db`, removed in v1.34.0 —
[ADR 0013](../decisions/0013-openbao-access-through-the-bao-cli.md)).
This page is the database-specific half of
[connect/openbao.md](openbao.md), which covers the shared contract — the
exchange, the JWT mount, the manager-side PKI role shape — in full.

## The flow

```sh
accessctl psql --address https://openbao.example:8200 -ns staging -- -h db.example -d orders
```

Four steps, read from `cmd/accessctl/pg.go` and `cmd/accessctl/bao.go`:

1. **`accessctl` exchanges the sign-in for OpenBAO's own audience**
   (`--audience openbao` by default) — the same token exchange
   `accessctl bao` and `accessctl token` make (`openBAOLogin`, shared
   with `bao`, cached the same way).
2. **It logs in to OpenBAO's JWT mount** — `jwt-roster` in `-ns` (or
   `BAO_NAMESPACE`) unless overridden — presenting the exchanged token.
   The OpenBAO token this returns is cached, not revoked: `psql`/`pg` are
   meant to be run often, and a `bao` call at the same address, namespace,
   mount and login role reuses the same login.
3. **OpenBAO's PKI role issues a client certificate**, if nothing cached
   still has enough life left (five minutes' margin — wider than the
   login token's own, because a certificate may be used for a whole
   session rather than one round trip). `accessctl` generates an ECDSA
   P-384 key on this machine, builds a certificate request for it, and
   calls `pki/sign/<role>` (`-role`, `db-client` by default) — never
   `pki/issue/...`, so the private key never crosses the wire and the
   role only ever needs to offer `sign`. The common name asked for is the
   signed-in identity unless `--common-name` overrides it, carried both
   in the CSR and in the request body, for a role that reads either. No
   TTL is sent — see [what decides access](#what-decides-access), below.
4. **`accessctl` writes the key, the certificate and the CA file, and
   runs the command with libpq's own environment variables set.** Three
   files land under `<config>/credentials/<ns>/<role>/`: `client.crt`,
   `client.key`, `client-ca.crt`, all `0600` in a `0700` directory.
   `PGSSLCERT`, `PGSSLKEY`, `PGSSLROOTCERT` point at them, `PGSSLMODE` is
   `verify-full`, and `PGUSER` is the certificate's own common name — set
   only when the caller has not already chosen one (an explicit `-U`,
   `user=`, or a service file's own `user=`, always wins; see
   [reference/accessctl.md#the-environment](../reference/accessctl.md#the-environment)
   for what was verified about libpq's precedence here).

`-h`/`-d` above, or a `service=<name>` from a libpq service file, both
work: `accessctl` never touches connection parameters other than the
four it sets, and psql's own arguments pass through unchanged.

**The recommended repo pattern is a committed, secret-free service
file.** A repository that connects to the same database from more than
one script keeps its own `pg_service.conf` in git — host, port, dbname,
`sslmode=verify-full`; never a credential — and points `PGSERVICEFILE`
at it from its dev environment (`devbox.json`'s own `env`, or a
`direnv` `.envrc`):

```ini
# pg_service.conf, committed
[orders]
host=db.example
port=5432
dbname=orders
sslmode=verify-full
```

```sh
export PGSERVICEFILE=$PWD/pg_service.conf   # from devbox.json or .envrc
accessctl psql --address https://openbao.example:8200 -ns staging -- service=orders
```

`accessctl` never writes to this file — unlike the `pg_service` entry
`accessctl credential db` used to write, this one is the repository's
own, checked in, and reused by everyone who clones it; `accessctl` only
ever adds the certificate the service's `sslcert`/`sslkey`/`sslrootcert`
would otherwise have to name, through the environment instead.

## What decides access

**`accessctl` never asks for a lifetime.** No flag here can request a
longer- or shorter-lived certificate; the OpenBAO PKI role's own `ttl` and
`max_ttl` are the whole answer, so shortening the role shortens every
certificate already in flight. What decides *whether* the call succeeds
at all is OpenBAO policy on the login, gated on the `groups` claim the
exchanged token carries — one group per thing that may be minted, the
same shape [connect/openbao.md#policy](openbao.md#policy) describes for
every credential kind:

```yaml
groups:
  staging:db:orders:client: { members: [team-eng@example.com] }
clients:
  openbao:
    kind: static
    requires: [staging:db:orders:client]
```

Everything past the login — which common names the `db-client` role will
sign, and for how long — is the secret store's own policy and role
configuration, not this repository's. See
[connect/openbao.md](openbao.md#manager-side) for the PKI role shape
(`key_type: ec`, `key_bits: 384`, client-auth extended key usage, a short
`max_ttl`) and the secret store's own documentation for how a role and
its policy are declared.

## Server side

**Trust the PKI's CA for client certificates.** The server's client-CA
trust store is the same `issuing_ca` (or `ca_chain`) OpenBAO's PKI role
answers with — the file `accessctl` writes as `client-ca.crt`.

**`pg_hba.conf`: `hostssl … cert`, with a `pg_ident.conf` map from the
certificate's common name to the database role.** PostgreSQL's `cert`
authentication method is only available over `hostssl` (never
`hostnossl`), and is already equivalent to `trust` with
`clientcert=verify-full` — the client certificate is always required and
verified against the configured CA, so nothing extra has to be said for
that part. By default the requested database role must equal the
certificate's `CN` exactly; adding `map=<name>` to the `hostssl … cert`
line and a matching section in `pg_ident.conf` is what lets an issuer's
subject — an email address, or a job's `github-<owner>-<repo>` — become a
shorter, ordinary-looking database role name instead. See PostgreSQL's own
documentation for the exact syntax:
[client authentication with certificates](https://www.postgresql.org/docs/current/auth-cert.html)
and [`pg_ident.conf`](https://www.postgresql.org/docs/current/auth-username-maps.html).

**For CloudNativePG:** a cluster's own CA signs both the server and the
default `streaming_replica` client certificate; supplying your own client
CA replaces that trust store, and CloudNativePG's own documentation is
explicit that the two settings are paired, not independent — using a
custom CA to verify client certificates means specifying **both**
`clientCASecret` (the secret holding the CA's `ca.crt`) **and**
`replicationTLSSecret` (a `kubernetes.io/tls` secret with a certificate
already issued for the `streaming_replica` user), under
`spec.certificates` on the `Cluster` resource — because once you own the
client CA, CloudNativePG can no longer mint the replication client
certificate for you.
Source: [CloudNativePG — Certificates, "Client certificate"](https://cloudnative-pg.io/documentation/1.24/certificates/#client-certificate).
*Not verified against a live cluster; verify the exact field names
against the CloudNativePG version you run before applying this.*

## Why certificates, not OpenBAO's database secrets engine

OpenBAO (and Vault) also ship a database secrets engine, which mints
short-lived **passwords** by holding a privileged connection into the
target database and issuing `CREATE ROLE ... PASSWORD ...` on demand. That
engine needs two things this design avoids: OpenBAO must hold a
credential privileged enough to create and drop roles in **every**
database it serves, and OpenBAO's network must reach **every** cluster's
network to open that connection. The PKI engine needs neither: it signs a
certificate request offline, against a CA it already holds, and never
opens a connection to the database at all. The server trusts the CA once,
at `pg_hba.conf`/`clientCASecret` configuration time, and every
certificate after that verifies against a public key with no further call
to OpenBAO.

## Why not PostgreSQL 18's native OAuth, yet

PostgreSQL 18 added an OAuth authentication method, and libpq's own
implementation of it drives the OAuth 2.0 **Device Authorization Grant**
(RFC 8628) — the flow where a CLI prints a URL and a short code for the
person to open in a browser. `internal/issuer/storage.go` is explicit that
this issuer does not implement that grant at all: nothing in the storage
type satisfies `op.DeviceAuthorizationStorage`, "and that is the
mechanism by which the device flow is not served" — the library
type-asserts for it and refuses the grant when the assertion fails.
There is no device-flow endpoint here for libpq to drive, and the
issuer's own OIDC discovery document says so: `internal/issuer/provider.go`
deletes `device_authorization_endpoint` from it before it is served.

Separately, the server side needs a **third-party validator module**:
PostgreSQL 18 ships the framework (`oauth_validator_libraries`, and the
design guidance in
[Safely Designing a Validator Module](https://www.postgresql.org/docs/18/oauth-validator-design.html))
but no built-in validator — see
[OAuth Authorization/Authentication](https://www.postgresql.org/docs/current/auth-oauth.html).
Building or adopting one, and adding the device-authorization grant here,
are both real work. **Revisit later.**

## Revocation

There is no revocation list, here or on the OpenBAO side documented for
this flow — the leaves are short enough that one is not kept, the same
trade [connect/openbao.md](openbao.md#manager-side) states for SSH and
machine certificates. What ends access is the certificate expiring: the
role's `max_ttl` is the only ceiling, and shortening it shortens every
certificate already issued.

**PostgreSQL does not check the issuer at connect time.** `cert`
authentication verifies the presented certificate against the configured
CA and its own validity period; it does not call back to OpenBAO, and it
does not consult a certificate revocation list unless the server is
separately configured with `ssl_crl_file` (or `ssl_crl_dir`) — see
[SSL Support](https://www.postgresql.org/docs/current/ssl-tcp.html). A
certificate minted a second before OpenBAO's PKI role was tightened, or
before the identity's group membership was pulled, keeps authenticating
until it expires. Short `max_ttl` values are therefore the whole of this
design's revocation story, not a convenience on top of a revocation list.
