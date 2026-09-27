# OpenBAO — the issuer's side of the contract

OpenBAO trusts this issuer on two auth mounts per namespace, maps the
`groups` claim onto its identity groups by name, and signs the SSH and
database certificates `accessctl bao` and `accessctl pg`/`psql` ask for
([ADR 0013](../decisions/0013-openbao-access-through-the-bao-cli.md)).
**The contract,
end to end, lives with OpenBAO**:
[truvity/openbao docs/integrations/access-roster.md](https://github.com/truvity/openbao/blob/master/docs/integrations/access-roster.md).
It is proven there by a conformance test that runs a real OpenBAO server
against an issuer shaped like this one, and `pkg/model`'s `Roster` preset
builds the OpenBAO side of it. The how-to for an installation is
[connect/openbao.md](../connect/openbao.md).

This page is only what **this** side must provide for that contract to
hold. Each item is something access-issuer, `accessctl` or the policy
already does; a change here that breaks one breaks OpenBAO sign-in.

## The issuer

- **Discovery and keys reachable from OpenBAO.** The mount fetches
  `/.well-known/openid-configuration` and the key set when it is
  configured and when keys rotate. Tokens are signed with
  whatever `signingKey.certificate.algorithm` chose -- ES384 by default,
  RS256 for an RSA key -- and the discovery document says which. OpenBAO's
  JWT auth reads the key set, so it follows either; a configuration that
  pins `jwt_supported_algs` must name the same one.
- **`iss` is the issuer URL exactly.** It is OpenBAO's bound issuer: a
  trailing slash on one side and not the other refuses every login.
- **`sub` and `groups` in every token**, ID tokens included: `sub` names
  the entity (a person's is their address, and the database credential
  role checks it reads as one), and `groups` is the flat list of internal
  group names — the whole of the authorization, bound as it is. No
  `groups` scope is needed or advertised.

## The policy: two clients

```yaml
clients:
  openbao:
    kind: exchange
    ttl_cap: 15m
    requires: [all:openbao:operator, staging:ssh:user, staging:ssh:admin, staging:db:client, ci:release]
  openbao-ui:
    kind: confidential
    secret: openbao-ui-client
    redirects: [https://openbao.example/ui/vault/auth/oidc/oidc/callback]
    signed_out: [https://openbao.example/ui/]
    ttl_cap: 5m
    requires: [all:openbao:operator, staging:ssh:user, staging:ssh:admin, staging:db:client]
```

- **`openbao`** is the audience of every token presented at OpenBAO's
  `jwt-roster` login: `accessctl bao`, `accessctl pg`/`psql`, `accessctl
  token --audience openbao`, and CI jobs exchanging their own identity.
  Keep its cap short; it is only ever presented at the login.
- **`openbao-ui`** is the web UI's sign-in. OpenBAO holds its secret and
  redeems the code itself, so the secret must reach whatever applies
  OpenBAO's configuration. **One redirect** serves every namespace:
  OpenBAO carries the namespace in the OIDC state, never in the URL.
- **`requires` on the two are the same list, less the groups only jobs
  hold** (those are on `openbao` alone: a job has no browser). They are
  two doors to one set of OpenBAO identity groups, so a group admitted
  through one and refused at the other reads as a broken console rather
  than as a policy. Keep them equal by a test in the repository that owns
  the policy, not by review.
- **Every group OpenBAO holds a policy for** belongs in `requires`, named
  by the [naming rule](../design/trust.md#naming); a group missing here is
  refused at the exchange, before OpenBAO is reached (`accessctl` exit
  `4`).

## accessctl

- `bao` authenticates (logs in on `jwt-roster` as role `roster` with a
  token for `openbao` — `--mount`, `--login-role`, `--audience` override
  them) and then runs the real `bao` binary unchanged: `bao ssh
  -mode=ca` for an SSH certificate, `bao write pki/sign/<role>
  csr=@...` for a machine certificate, `bao kv get` for anything else.
  The login is cached rather than revoked, and `--forget` clears it.
- `pg`/`psql` share `bao`'s own login and additionally make **one**
  `pki/sign/<role>` call, over a CSR for an **ECDSA P-384** key with the
  subject as its common name. No TTL is ever sent either way.
- The namespace is `bao`'s own `-namespace` flag (or `BAO_NAMESPACE`) for
  `bao`; `-ns` (or `BAO_NAMESPACE`) for `pg`/`psql` — both read the SAME
  variable, just through a flag spelled for what each command is. Paths:
  `ssh/sign/<role>` and `pki/sign/<role>` (`bao`'s own syntax names
  these for itself); `pki/sign/<role>` for `pg`/`psql`. `--ca-cert` or
  `BAO_CACERT` adds a private root for the OpenBAO connection alone.
- Exit codes: `4` for a refusal (the issuer's, or OpenBAO's `403`), `5`
  for unreachable, `2` for usage ([reference](../reference/accessctl.md#exit-codes)).

## CI

A job with `id-token: write` exchanges its GitHub token for `openbao`
exactly as for any other audience, and the `ci` rules decide its groups
([connect/github-actions.md](../connect/github-actions.md)). The GitHub
Action writes kubeconfigs and AWS profiles only, so an OpenBAO login in a
job runs `accessctl token --audience openbao`, or `accessctl bao`/`pg`/
`psql` for a certificate, since a job has no agent to hand an SSH
certificate to and no interactive `psql` session to run.
