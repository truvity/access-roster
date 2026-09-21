# accessctl

```sh
accessctl login   --issuer https://access.example
accessctl whoami                             # who you are, and what it opens
accessctl setup                              # both of the next two

accessctl kubeconfig                         # a context per granted cluster
accessctl aws-config                         # a profile per granted cloud role

kubectl --context staging get nodes          # exec plugin: accessctl kube-token
aws --profile deployer@111122223333 sts get-caller-identity   # credential_process: accessctl aws

accessctl token --audience openbao              # one token for one audience, on stdout
accessctl github-token --app publisher --repository app --permission contents=read
accessctl exchange --audience k8s:staging < subject-token

accessctl credential ssh --env staging --principal deploy      # into the ssh-agent
accessctl credential db  --env staging --project example \
    --host db.example --dbname orders                          # a psql service entry
accessctl credential client --env staging --out ./gateway.crt  # a certificate and its key

accessctl secrets env --namespace staging \
    --prefix orders/local-dev/checkout --out .env   # a team's shared values, as a .env file
```

It exists for one reason: **the cloud CLI has no interactive login.**
kubectl has kubelogin for the same job; AWS has nothing that will open a
browser. So one small binary runs the flow once and then answers as a
credential process, and the rest share that login's cache.

`login` is authorization code with PKCE on a loopback port — the only
browser flow served. The client must be declared in the policy as
`kind: public` with a loopback redirect **and `sign_in_exchange: true`**:
that key is what lets the exchange take a sign-in's access token as a
proof, and without it every command after `login` is refused (exit 4).
The default id is `accessctl`.

Every command that names an audience takes `--audience`, `--issuer` and
`--client`, defaulting to what `login` wrote; `aws` also takes `--role`
for a role the audience does not encode.

`github-token` names a [catalogue App](../connect/github-apps-catalogue.md#minting-a-token)
instead: `--app <id>`, `--repository <name>` (repeatable, without the
owner; none asks for a token not narrowed to any, which only a grant of
every repository allows), `--permission <name>=<level>` (repeatable; none
asks for exactly what the grant allows), and `--json` to print
`{"token", "expires_at", "repositories", "permissions"}` — what GitHub
granted — instead of the bare token. It takes `--issuer` and `--client`
like the rest.

## `credential`: certificates OpenBAO mints

`accessctl credential <kind> --env <env> [--role <role>]`, where the kind
is `ssh`, `db` or `client`. Each one is the same four steps:

1. exchange the sign-in (or the job's own token) for `aud=openbao`;
2. log in on the JWT mount in that environment's namespace;
3. make **one** call — `ssh/sign/<role>` or `pki/sign/<role>` — over a
   key made on this machine;
4. deliver the result, and revoke the OpenBAO token on the way out.

**Nothing here chooses a lifetime.** No request carries a TTL: the role's
`ttl` and `max_ttl` are the whole answer, so shortening the role shortens
every credential in flight and no flag can ask for longer. What accessctl
does send is a public key (or a CSR over one), the principals or the
common name asked for, and nothing else — a role that will not sign them
refuses, which is the right place for that decision.

**The OpenBAO token is never written anywhere.** It lives in memory for
the length of one command and is revoked at the end; a mount that hands
out batch tokens refuses the revoke, which is not an error, because such
a token cannot be revoked and expires on its own.

Each kind prints what the audit trail will show — the certificate's
`key_id` or common name, and its serial or principals, and its expiry —
so a line in an sshd log, a row in the issuer's trail and OpenBAO's own
record of the signing can be read as one story about one subject. The
key is never printed.

### Flags

Every kind takes these:

| Flag | Default | |
|---|---|---|
| `--env` | — | **required.** The environment to mint in; it names the namespace and, for `db`, the service entry |
| `--role` | `user` (`ssh`), `db-client` (`db`), `client` (`client`) | the OpenBAO role on the kind's engine. Empty means the default |
| `--address` | `$BAO_ADDR`, then `$VAULT_ADDR` | the OpenBAO API, e.g. `https://openbao.example:8200` |
| `--namespace` | `$BAO_NAMESPACE`, then `$VAULT_NAMESPACE`, then the `--env` value | the OpenBAO namespace, sent as `X-Vault-Namespace` on every call |
| `--ca-cert` | `$BAO_CACERT`, then `$VAULT_CACERT` | a PEM bundle the OpenBAO connection trusts **in addition to** the system's roots |
| `--mount` | `jwt-roster` | the JWT auth mount to log in on |
| `--login-role` | `roster` | the role on that mount |
| `--audience` | `openbao` | the exchange client OpenBAO accepts; empty is refused |
| `--issuer`, `--client` | what `login` wrote | as for every other command |

And each kind its own, so that a flag of another kind is a usage error
rather than something quietly ignored:

| Kind | Flag | Default | |
|---|---|---|---|
| `ssh` | `--principal` | none | an OS account to ask the certificate for; repeatable. None sends none, and the role decides |
| `ssh` | `--identity` | none: the ssh-agent | write the key and certificate to files instead: a bare name means `~/.ssh/<name>`, a path with a separator (or `~/`) is taken as given |
| `db` | `--host` | — | **required.** The database host the service entry points at |
| `db` | `--dbname` | — | **required.** The database the service entry opens |
| `db` | `--port` | `5432` | |
| `db` | `--service` | the `--env` value | the psql service entry to write |
| `db` | `--project` | none | a project whose own namespace, `<project>/<env>`, holds the database role |
| `db`, `client` | `--common-name` | the signed-in identity | the common name to ask for: the sign-in's email (or subject), or `github-<owner>-<repo>` in a job |
| `client` | `--out` | — | **required.** Where the certificate goes; the key and the CA go beside it |
| `client` | `--uri-san` | none | a URI SAN to ask for; repeatable |

### Which role

Each kind signs with its ordinary role unless `--role` names another:
`user` for `ssh`, `db-client` for `db`, `client` for `client`. SSH has a
second, `admin`, which is never a default: `user` is for everyday logins
as a host's ordinary account, `admin` for the account that administers
it, and the two are granted separately. Which OS accounts each role signs
for is the role's `allowed_users`, not a flag here.

### Where it points: the order each value is read in

The first one that is set wins; a variable holding only whitespace counts
as unset.

| Value | 1st | 2nd | 3rd | Otherwise |
|---|---|---|---|---|
| the OpenBAO address | `--address` | `BAO_ADDR` | `VAULT_ADDR` | exit 2, naming the flag and the variable |
| the namespace | `--namespace` | `BAO_NAMESPACE` | `VAULT_NAMESPACE` | `<env>`; for `db` with `--project`, `<project>/<env>` |
| the extra roots | `--ca-cert` | `BAO_CACERT` | `VAULT_CACERT` | the system's roots alone |

**The namespace is the environment's own.** One namespace per
environment, named for it, holds every role this command signs with, so
`--env staging` works in `staging` for all three kinds. An installation
laid out otherwise says so with `--namespace` (or the variables), and a
database role kept in a project's own namespace is reached with
`--project`.

**The bundle is added, not substituted, and for OpenBAO alone.** It is
appended to the system's roots, so an OpenBAO whose certificate a public
CA signs still verifies; and only the connection to OpenBAO uses it — the
exchange at the issuer keeps the system's trust, so a bundle handed over
for OpenBAO cannot vouch for anything else. (`SSL_CERT_FILE` does the
opposite on both counts.) A bundle that cannot be read, or holds no PEM
certificate, exits 2 before anything is exchanged. A server the roots do
not verify exits 5 with a pointer to `--ca-cert` and `BAO_CACERT`.

### Keys, and where the files go

**Every key is made on this machine and none is sent.** OpenBAO receives
a public key or a certificate request, never a private key, and no call
in the command asks it to make one — so a role can offer `sign` alone.

| Kind | Key | Sent to OpenBAO | Delivered |
|---|---|---|---|
| `ssh` | Ed25519, made for this certificate alone | `ssh/sign/<role>`: the public key and `valid_principals`, nothing else | into the **ssh-agent**, with a lifetime the certificate's expiry sets, so the agent forgets it when it expires. With `--identity`: the private key `0600`, `<name>.pub` and the certificate `<name>-cert.pub` `0644`, where `ssh -i <name>` finds both |
| `db` | ECDSA P-384 | `pki/sign/<role>`: a CSR carrying the common name, and the common name again in the request | `<service>.crt`, `<service>.key` and `<service>-ca.crt`, all `0600`, under `<config>/credentials/<env>/` (a directory made `0700`); and a **psql service entry** for `psql "service=<service>"` |
| `client` | ECDSA P-384 | `pki/sign/<role>`: a CSR carrying the common name and the URI SANs, both repeated in the request | `<out>.crt`, `<out>.key` and `<out>-ca.crt`, all `0600`, with `.crt` or `.pem` taken off `--out` first; a missing parent directory is made `0700` |

The certificate that comes back is checked against the key before
anything is written: one issued for another key is refused rather than
left beside a key it does not match. The CA file is the chain OpenBAO
returned, or the issuing CA alone, and is not written when it returned
neither. The PKI key is PKCS #8 PEM, which libpq, OpenSSL and Go all read.
A PKI role must accept `key_type: ec` with `key_bits: 384`, or `any`;
the CSR and the request both carry the names, so a role with
`use_csr_common_name` or `use_csr_sans` works either way.

`<config>` is `accessctl` under the operating system's configuration
directory: `$XDG_CONFIG_HOME/accessctl` or `~/.config/accessctl` on
Linux, `~/Library/Application Support/accessctl` on macOS. The psql
service file is `PGSERVICEFILE` when that is set and `~/.pg_service.conf`
otherwise, created `0600`; it holds one block per service between
`# >>> accessctl <service> >>>` and `# <<< accessctl <service> <<<`
markers, so a
credential for a second database leaves the first entry alone. The
entry's `user` is the certificate's common name — the server maps it
through `pg_ident` — with `sslmode=verify-full`.

A key this tool did not write is **never** overwritten:
`--identity id_ed25519` is one keystroke away from a key somebody has
used for years, and a key counts as this tool's only when the `.pub`
beside it carries the `accessctl` comment. Each key, certificate and CA
file is removed and created afresh rather than truncated, so a file that
existed with a wider mode does not keep it.

### What each failure exits with

The codes are the [table below](#exit-codes); for `credential` they
mean:

| Code | When |
|---|---|
| `2` | no kind, an unknown kind, a flag of another kind; no `--env`, no address, `db` without `--host` or `--dbname`, `client` without `--out`; an empty `--audience`; a `--uri-san` that is not a URI; a CA bundle that cannot be read or holds no certificate; no common name to ask for |
| `3` | not signed in (on a laptop): run `accessctl login` |
| `4` | the issuer refused the exchange for `openbao`, or OpenBAO answered `403` — the login or the signing is not granted |
| `5` | the issuer or OpenBAO could not be reached, answered `5xx`, presented a certificate the roots do not verify, or answered a login with no token or a signing with no data |
| `1` | anything else: OpenBAO answered `404` (the mount or the role does not exist in that namespace — the message says so) or another status; the certificate was for another key; `--identity` names a key this tool did not write; no ssh-agent to add to |

## `secrets`: a team's shared values, as a file

`accessctl secrets env --namespace <env> --prefix <path> [--out .env]`

The values a team shares while it develops — the sandbox token every
engineer's local stack needs, the test account's password — read out of a
KV version 2 engine and written as a `.env` file. It is `credential`'s
sentence with a read where the signing is:

1. exchange the sign-in (or the job's own token) for `aud=openbao`;
2. log in on the JWT mount, in the namespace that is the environment;
3. list `<engine>/metadata/<prefix>`, walk into every name ending in `/`,
   and read each leaf at `<engine>/data/<...>`;
4. write the file, and revoke the OpenBAO token on the way out.

The listing is a `GET` with `?list=true` and not the `LIST` method.
OpenBAO routes both to the same handler, but `LIST` is not a method
everything between a laptop and an API is obliged to forward, and the
proxy that refuses it answers `405` — which would arrive as a failure
about the path rather than about the proxy.

**Nothing here decides who may read.** The exchange refuses before OpenBAO
is reached, and the groups in the token decide what the login opens after
it: reading a project's prefix is `{env}:{project}:viewer`, and
`{env}:{project}:deployer` and `{env}:{project}:approver` write it. A
`403` is reported as that, with the group named, because "permission
denied" on a path reads as a mistake in the path and almost never is
([the model](../connect/openbao.md#and-holds-a-teams-secrets)).

**A run that reads nothing fails**, and leaves whatever file was there
alone. An empty `.env` is the failure nobody notices: the stack starts,
every variable is unset, and it reads as a service that is merely
misconfigured, days later and never at the fetch.

**Only the names are printed**, to stderr, with the file and the count —
never a value, there or in any failure. Values go in the file and nowhere
else.

### Flags

| Flag | Default | |
|---|---|---|
| `--namespace` | `$BAO_NAMESPACE`, then `$VAULT_NAMESPACE` | **required.** The namespace, which is the environment. There is no default from anywhere else: a namespace guessed would read another environment's values into a file that does not say which |
| `--prefix` | — | **required.** The path under the engine whose leaves are read, e.g. `orders/local-dev/checkout`. Slashes on either end are trimmed; a `*` (how a policy spells *everything below*) and a `..` segment are refused |
| `--out` | `.env` | the file to write. Ignore it in git |
| `--engine` | `kv` | the KV version 2 mount the prefix lives on |
| `--address` | `$BAO_ADDR`, then `$VAULT_ADDR` | the OpenBAO API |
| `--ca-cert` | `$BAO_CACERT`, then `$VAULT_CACERT` | a PEM bundle trusted **in addition to** the system's roots, for this connection alone |
| `--mount` | `jwt-roster` | the JWT auth mount to log in on |
| `--login-role` | `roster` | the role on that mount |
| `--audience` | `openbao` | the exchange client OpenBAO accepts; empty is refused |
| `--issuer`, `--client` | what `login` wrote | as for every other command |

`env` is a subverb rather than `--format env` so that a second rendering
can have flags of its own, and so that there is no default rendering to
overwrite somebody's file in the wrong shape.

### The file

One line per leaf, sorted by name, under two comment lines naming the
prefix it came from. The KEY is the **leaf path's last segment**, so
`kv/data/orders/local-dev/checkout/API_TOKEN` is `API_TOKEN=…`; a segment
that is not the name of an environment variable (`[A-Za-z_][A-Za-z0-9_]*`)
is refused rather than mangled into one.

```
# Written by `accessctl secrets env` from kv/orders/local-dev/checkout in staging.
# Regenerate it rather than editing it, and do not commit it.
API_TOKEN='t0ken'
DATABASE_PASSWORD="it's a \$ecret # really"
```

**One path holds one variable**, in a field called `value`; a secret with
exactly one field of another name is read as that field, and one with
several fields and no `value` is refused with the field names, because
picking between them writes a value that is silently the wrong one. A
field that is not text is refused for the same reason. Two leaves of the
same name under one prefix are refused: a `.env` file has one line per
name and neither of them can be the one that wins.

**Nothing is written unquoted.** Four of the five characters worth
worrying about change the value when it is: a trailing space is trimmed,
a ` #` starts a comment, a `$` interpolates, and a leading quote makes
the rest of the line a quoted string. Quoted, all five survive — a space,
a `#`, a `$`, a quote and a newline each reach the container.

| Value holds | Written as | Why |
|---|---|---|
| anything but `'` or a line break | `'…'` | the single-quoted form is literal: no escapes, no interpolation, nothing to get wrong |
| a `'` or a line break | `"…"` with `\\`, `\"`, `\$`, `\n`, `\r` | single quotes have no escape for a `'` and cannot span a line break; the double-quoted form has both, at the cost of escapes |

The file is for a reader of the `env_file` syntax — Docker Compose,
`docker run --env-file`, the dotenv parsers. It is **not** for `source`: a
shell hands on a literal `\n` where Compose expands a line break, so a
value with one in it survives the first reader and is mangled by the
second.

It is written to a temporary file in the same directory, `0600` from the
moment it exists, and renamed over the old one, so a stack starting
during a fetch reads the whole old file or the whole new one and never
half of either. A second run rewrites it byte for byte unless a value
changed; a failed run leaves the previous file exactly as it was.

### What each failure exits with

| Code | When |
|---|---|
| `2` | no rendering, one that does not exist, a flag of another one; no `--namespace`; no `--prefix`, or one holding `*` or a `..` segment; no address; an empty `--audience`; a CA bundle that cannot be read or holds no certificate |
| `3` | not signed in (on a laptop): run `accessctl login` |
| `4` | the issuer refused the exchange for `openbao`, or OpenBAO answered `403` on the listing or a read — no group you hold opens that prefix |
| `5` | the issuer or OpenBAO could not be reached, answered `5xx`, presented a certificate the roots do not verify, or answered a login with no token |
| `1` | anything else: the prefix read **zero** keys; a leaf that is not one named value (several fields, a value that is not text, a name that is not a variable name, the same name twice, a latest version that was deleted); the engine does not exist in that namespace; the file could not be written |

## Installing it

Each release carries `accessctl_<version>_nix-flake.tar.gz`,
a Nix flake over that release's own archives; a repository adds its URL
with `#accessctl` to `devbox.json`
([design](../design/accessctl.md#installing-it)). The release's archives
are there too for a plain download.

## Where things are kept

`<config>/config.yaml` (`~/.config/accessctl/config.yaml` on Linux; see
[above](#keys-and-where-the-files-go) for the directory) holds the issuer
and the client id, written by `login`. `session.json` beside it holds the refresh token,
mode `0600`.

**A file rather than the OS keyring**, deliberately: a keyring is a
platform-specific dependency on every laptop and a prompt in the middle
of a `kubectl` call on some of them. This is the same secret a browser
already keeps in a cookie jar, and `login` replaces it in one command if
it leaks.

A rotated refresh token is written back. A refused refresh — revoked,
expired, or the account suspended — reads as *not signed in*, because
signing in again is the only answer.

## What it writes into files that are not its own

**The kubeconfig, through `kubectl config`** and never by rewriting the
file. A person's other contexts are none of this tool's business.

It writes the credential and the context; the **cluster entry is not
ours** — the API server's address and its CA come from the platform's own
kubeconfig or from `aws eks update-kubeconfig`, and inventing one would
be inventing an address to trust.

**The AWS config, between two markers.** Everything between
`# >>> accessctl >>>` and `# <<< accessctl <<<` is rewritten each run;
everything outside is left exactly as it was. Rewriting rather than
appending matters: a profile for a role somebody no longer holds must not
survive as an entry that fails only when used.

Each profile is `<role>@<account>` with
`credential_process = accessctl aws --audience aws:<account>:<role>`, and
holds no secret.

## In a job

The same files work unchanged in a GitHub Actions job granted
`id-token: write`. When `ACTIONS_ID_TOKEN_REQUEST_URL` and
`ACTIONS_ID_TOKEN_REQUEST_TOKEN` are set, `kube-token`, `aws`, `token`,
`github-token`, `credential` and `secrets` ask GitHub for the job's identity token — for the issuer's URL, the one
audience it accepts — and exchange that, presenting the audience as the
client, exactly as the GitHub Action does. There is no `login` in a job
and no cache: every call exchanges afresh. A repository that would rather
download nothing of ours uses the action, which is `curl` and `jq`
([../connect/github-actions.md](../connect/github-actions.md)).

## Exit codes

They are a contract: a wrapper should be able to tell *sign in again*
from *the issuer is down* without parsing English, and should know not to
retry a refusal.

| Code | Means |
|---|---|
| `0` | ok |
| `1` | anything the codes below do not name: read the message |
| `2` | usage: something in the command line is wrong |
| `3` | not signed in — run `accessctl login` |
| `4` | that audience, or that App's token, is not granted to you (for `credential` and `secrets`, also OpenBAO's `403`); retrying will not help |
| `5` | the issuer could not be reached (for `credential` and `secrets`, also OpenBAO); retrying might |
