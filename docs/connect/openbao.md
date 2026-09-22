# Connect a secret manager that mints certificates

**Anchor:** the issuer. A secret manager — OpenBAO, or a Vault that
speaks the same API — trusts it on a JWT auth mount and mints
**short-lived certificates** for things that speak neither OpenID nor a
cloud's own protocol: an SSH server, a database, a service that wants
mutual TLS. `accessctl credential` is the courier
([reference](../reference/accessctl.md#credential-certificates-openbao-mints)).

The same trust carries a second thing, in the [second half](#and-holds-a-teams-secrets)
of this page: the values a team **shares while it develops**, read out of
a KV engine by `accessctl secrets env`. One mount, one exchange, one set
of groups; a different kind of answer.

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

## …and holds a team's secrets

The other thing the same door opens: the credentials a team shares while
it develops — the sandbox token every engineer's local stack needs, the
test account's password, the key for a third party's staging tenant. Not
minted, just held, and read by the people the policy already says are on
the project.

> A namespace is an environment. A project's engineers read its prefix;
> its deployers and approvers write it. A repository is a path under its
> project. Membership is the issuer's.

The manager side of this — the grants as code, the paths, how an owner
writes and rotates, how revocation works and what must never go in — is
[truvity/openbao's docs/team-secrets.md](https://github.com/truvity/openbao/blob/master/docs/team-secrets.md),
tested there against a real server, exactly as the contract page is. What
follows is only what this side does with it.

### Policy

No new group. The three a project already has are the three that read and
write its prefix, so there is one membership list rather than two:

| Group | `kv/data/{project}/*` | `kv/metadata/{project}/*` |
|---|---|---|
| `{env}:{project}:viewer` | `read` | `list`, `read` |
| `{env}:{project}:deployer` | `create`, `read`, `update` | `list`, `read` |
| `{env}:{project}:approver` | `create`, `read`, `update` | `list`, `read` |

The viewer's `list` on the metadata path is not decoration: `read` on the
data path alone tells nobody what there is to read, and a person would
have to know every variable's name already.

`data/` and `metadata/` are KV version 2's **API** paths and not the ones
`bao kv` prints. A policy written on `kv/{project}/*` — the path off the
command line — grants nothing at all, and its symptom is a `403` for
somebody who is plainly in the group, which sends people looking at the
issuer.

A workload that needs one of these values is none of the three: it gets
an identity of its own and one `read` on one path.

### The paths

```
kv/data/{project}/{purpose}/{repository}/{VARIABLE}
         orders    local-dev  checkout    API_TOKEN
```

**A repository is a path segment, not a grant.** The project's second
repository is a new segment under a prefix that is already granted: no
new group, no new policy, nothing to change at the issuer. That is the
property the layout is chosen for, and the thing to check first when
somebody proposes a group per repository.

**One variable per path**, holding one field, `value`. A rotation then
touches exactly the path that rotated, two people rotating two variables
do not race through a read-modify-write of one blob, and the list of
names is the metadata listing rather than something written down beside
it.

### Person side

```sh
accessctl secrets env --namespace staging \
    --prefix orders/local-dev/checkout --out .env
docker compose up            # env_file: .env
```

One exchange, one login, a listing and a read per leaf, and the token is
revoked on the way out. The file is `0600`, written by rename so a stack
starting during a fetch never reads half of it, and holds one
`KEY='value'` per leaf — the KEY being the leaf's last path segment.
**Ignore it in git.** Only the names are printed, never a value
([reference](../reference/accessctl.md#secrets-a-teams-shared-values-as-a-file)
has the flags, the quoting and the exit codes).

Two refusals are worth knowing before the first run:

- **`403` means membership, not the path.** The login succeeded; the
  groups in the token hold no policy on that prefix. The fix is at the
  issuer — someone puts you on the project — and not in OpenBAO.
- **A run that reads nothing fails.** An empty `.env` is the failure
  nobody notices: the stack starts, every variable is unset, and it reads
  as a service that is merely misconfigured. So nothing is written, and
  whatever file was there is left alone.

Rotation needs no fetch of its own: a deployer or an approver writes the
new value, and the next run of the same command picks it up.

### What never goes in

**Production values.** Every engineer on the project reads every value
under the prefix, there is no second person and no per-path approval, the
reading end is a laptop, and a value written by mistake stays readable in
its old version until an operator destroys it. Production credentials go
to a workload — one identity, one path, read by the thing that needs it —
and the reasons are written out in
[team-secrets.md §8](https://github.com/truvity/openbao/blob/master/docs/team-secrets.md#8-what-never-goes-in).

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

## Console side

The console can also *show* a store: its namespaces, the groups each one
admits, what those groups open, and what one person can reach. It is
**read-only**, and not by omission — the store's desired state is written
wherever you write it and applied by whatever applies it, so a console
that also wrote would make two custodians of one thing. A drift row links
to where the fix is made; it is never a button.

Declare the store in the deployment's values:

```yaml
secretManagers:
  - name: kernel
    address: https://openbao.internal
    namespaces:
      - name: devel
      - name: stage
```

`mount`, `role` and `audience` default to `jwt-roster`, `roster` and
`openbao`. A store behind a private root names the bundle as a
`caCertSecret: {name, key}` or, since 1.24.0, a `caCertConfigMap:
{name, key}` — the ConfigMap cert-manager's trust-manager already writes
into every namespace, so nothing has to be copied into a Secret. One or
the other, never both; the render refuses it with `name caCertSecret or
caCertConfigMap, not both: two bundles at one path is one of them
silently unused`. A namespace **is** an environment: the model is one
level deep, and `environment` exists only for a store that names its
namespaces differently.

### What it reads, and as whom

The reader is this service's own ServiceAccount: a projected token,
audienced at the exchange, traded at this issuer for the store's audience
exactly as a CI job's is. There is no second credential and nothing is
stored.

Grant it like any other job — one identity, one policy, one prefix — and
give it these paths and nothing else:

```hcl
path "sys/policies/acl"          { capabilities = ["list"] }
path "sys/policies/acl/*"        { capabilities = ["read"] }
path "identity/group/name"       { capabilities = ["list"] }
path "identity/group/name/*"     { capabilities = ["read"] }
path "identity/group-alias/id"   { capabilities = ["list"] }
path "identity/group-alias/id/*" { capabilities = ["read"] }
path "sys/auth"                  { capabilities = ["read"] }
```

**No KV path**, which is the point: the console shows who may reach which
prefix and can never show a value, however the page is later changed.

### The four states

What the page **expects** a namespace to hold is not every group of
that environment. A cluster's tier, a CI job's group, the console's own:
all are groups of the environment, and no secret store holds a policy
for any of them. So since 1.25.0 the expected list is the store's own
exchange audience — the groups the `openbao` client's `requires` admits,
which is exactly the set the store holds a policy for — narrowed to the
namespace's environment by the naming rule: a group whose first segment
is the environment belongs there; an `all:`-scoped group spans
environments and is legitimate wherever it appears, so it is drawn where
the store has it and never reported absent; a group of another
environment is neither. And a group admitted at two doors is two
identity groups in the store — the bare name and `<name>@<door>`,
carrying the same policy — which the page folds into **one row** with
both doors in its column, not a second group and not drift.

| state | what it means |
|---|---|
| `bound` | expected here, in the store, carrying a policy of its own name |
| `not applied yet` | expected here and not in the store — **not drift**: this side is already right and the store has yet to hear it |
| `not declared` | in the store and expected by nothing here, `all:` groups excepted. The row worth opening the page for |
| `cannot read` | the reader was refused. **Never** inferred from an empty answer |

That last one is why the page is worth building. An empty namespace and a
namespace nobody may read are identical in every way except the status of
the call, and reporting the second as the first sends somebody to look at
an apply that is fine. Prove it the same way: take the reader's policy
away and the page must say `cannot read`, not draw an empty environment.
