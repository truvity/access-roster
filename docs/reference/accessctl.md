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

accessctl bao --address https://openbao.example:8200 kv get -format=env secret/app > .env
accessctl bao --address https://openbao.example:8200 ssh -mode=ca -role=user ci@build-worker.example
accessctl bao --address https://openbao.example:8200 write -field=signed_key \
    ssh/sign/user public_key=@key.pub > key-cert.pub

accessctl psql --address https://openbao.example:8200 -ns staging -- -h db.example -d orders
accessctl pg   --address https://openbao.example:8200 -ns staging -- pg_dump orders > orders.sql
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

**`accessctl credential ssh|db|client` was removed in v1.34.0**
([ADR 0013](../decisions/0013-openbao-access-through-the-bao-cli.md)):
`bao`, below, replaces `ssh` and `client`; `pg`/`psql`, further down,
replace `db`. Running any of the three now names its replacement.

## `bao`: authenticate, then run `bao` unchanged

`accessctl bao <args…>` exists only to put a valid OpenBAO token in front
of the real `bao` binary — it does not parse OpenBAO's own syntax, and
everything after accessctl's own flags is `bao`'s, unchanged
([ADR 0013](../decisions/0013-openbao-access-through-the-bao-cli.md)).

**The separation rule:** accessctl's own flags go BEFORE the bao
subcommand; `bao`'s own flags — including its `-namespace` (or bao's own
documented shortcut, `-ns`) — go AFTER it, exactly where `bao` has
always accepted them (`bao kv get -ns=dev secret/foo`). Parsing stops at
the first argument that is not one of accessctl's declared flags, which
for this command is the subcommand itself (`kv`, `ssh`, `write`,
`login`, ...) — an ordinary word, never a flag.

Accessctl's own flags: `--address`, `--ca-cert`, `--mount`
(`jwt-roster`), `--login-role` (`roster`), `--login-ns` (default: the
target namespace; then `$ACCESSCTL_BAO_LOGIN_NAMESPACE`), `--audience`
(`openbao`), `--issuer`, `--client` — the same resolution order (flag,
then `BAO_*`, then `VAULT_*`) `pg`/`psql`, below, use for the ones they
share. `--forget` revokes the cached token and removes it, needing no bao
command at all — with `--login-ns`, it clears the entry cached at that
login namespace.

**The login happens in the SAME namespace `bao` is about to operate
in, by default** — read out of `bao`'s own `-namespace`/`--namespace`, or
its shortcut `-ns`/`--ns` (wherever either appears among the arguments,
last one wins regardless of spelling), then `BAO_NAMESPACE`, then
`VAULT_NAMESPACE`, then root — because a token minted by logging in to
one OpenBAO namespace is only valid there and in its children, never in
a sibling.

**`--login-ns` (or `$ACCESSCTL_BAO_LOGIN_NAMESPACE`) logs in at a PARENT
namespace instead**, for an installation that keeps its logins at one
namespace while data lives in per-project children — see
[connect/openbao.md#logins-at-a-parent-namespace](../connect/openbao.md#logins-at-a-parent-namespace).
The target namespace must be `--login-ns` itself or a descendant of it
(a path-segment prefix, not a string prefix: `dev` is not a parent of
`devel`), checked before any exchange is made — a target the login
namespace does not cover is refused as a usage error rather than left to
fail later at OpenBAO as a permission-denied that reads as an outage.
`bao` itself still runs against its own target namespace unchanged;
`BAO_NAMESPACE` is never rewritten.

**The token is cached**, one file per OpenBAO address, LOGIN namespace and
subject, under `<config>/bao/<hash>.json`, `0600` — never
`~/.vault-token` and never bao's own token helper file. Keying by the
login namespace rather than the target is what lets `bao -ns=devel/a` and
`bao -ns=devel/b` share one login when `--login-ns=devel` covers both: it
is the same login either way. Offered until a
margin before its own expiry (the same margin the session's own access
token uses, `commands.go`'s `sessionTokenMargin`); a login whose answer
carries no lease at all is used for that one command and never cached,
the same rule the kubectl and AWS caches already keep for a credential
with no visible expiry.

**`bao` is run with `BAO_ADDR`, `BAO_TOKEN` and (when named) `BAO_CACERT`
set in the child's environment alone** — everything else the caller's
shell already has, `BAO_NAMESPACE` included, flows through untouched.
Wherever the platform allows it (every platform but Windows), the
process image is replaced (`syscall.Exec`) rather than run as a child, so
an interactive `bao ssh -mode=ca` or `bao login` gets the terminal
exactly as if it had been run directly; on Windows a child process
propagates the exit code the same way.

### `-format=env` on `kv get`

The one exception to "unchanged": `bao kv get ... -format=env` (also
`--format=env`, `-format env`, or `BAO_FORMAT=env`) does not exist
upstream yet. Until it does, accessctl runs `bao` once in JSON and
renders the dotenv itself:

- a string with none of `'`, CR or LF is `KEY='value'`;
- any other string is `KEY="value"`, with backslash, `"`, `$`, CR and LF
  escaped;
- a number or boolean is written as its own JSON text;
- `null` is `KEY=''` — an explicit empty value, not a dropped line;
- a nested object or array is refused, naming the field: there is no
  dotenv syntax for either, and flattening one would invent a shape the
  secret does not have;
- a key outside `[A-Za-z_][A-Za-z0-9_]*` is refused, naming the key: it
  is never renamed to make it fit;
- `-field` combined with `-format=env` is a usage error;
- bao's own errors and exit code pass through unchanged.

Detected once, cheaply, against the installed `bao`'s own `-format`
help: the day it lists `env` on its own, this stops intercepting and the
call is bao's own answer, unchanged.

### What each failure exits with

| Code | When |
|---|---|
| `2` | a flag accessctl does not recognise before the subcommand; no OpenBAO address; a CA bundle that cannot be read or holds no certificate; an empty `--audience`; no bao command and no `--forget`; `-field` combined with `-format=env`; `--login-ns` (or `$ACCESSCTL_BAO_LOGIN_NAMESPACE`) that does not cover the target namespace |
| `3` | not signed in (on a laptop): run `accessctl login` |
| `4` | the issuer refused the exchange for `openbao`, or OpenBAO refused the login |
| `5` | no `bao` on `PATH`; the issuer or OpenBAO could not be reached |
| bao's own | whatever `bao` itself exits with, once it is run — accessctl adds nothing on top and prints nothing of its own |

## `pg` / `psql`: a Postgres client certificate, then a command

`accessctl pg [flags] -- <command> [args…]` authenticates, mints (or
reuses) a Postgres client certificate, and runs `<command>` with libpq's
own environment variables pointed at it. `accessctl psql [flags]
[psql args…]` is the shorthand for `accessctl pg -- psql [psql args…]`.
This replaces `accessctl credential db`, removed in v1.34.0
([ADR 0013](../decisions/0013-openbao-access-through-the-bao-cli.md)).

**The separation rule is the same as `bao`'s.** accessctl's own flags go
before `--` (or before the first argument that is not one of them);
everything after is the command's own, unchanged. `psql`'s arguments
usually start with a flag (`-h`, `-d`), so `--` is needed there too
whenever the first one does; a bare positional argument (a database
name, `service=name`) does not.

```sh
accessctl psql --address https://openbao.example:8200 -ns staging -- -h db.example -d orders
accessctl pg   --address https://openbao.example:8200 -ns staging -- pg_dump orders > orders.sql
```

### Flags

| Flag | Default | |
|---|---|---|
| `--address` | `$BAO_ADDR`, then `$VAULT_ADDR` | the OpenBAO API |
| `--ca-cert` | `$BAO_CACERT`, then `$VAULT_CACERT` | a PEM bundle to trust, added to the system's roots |
| `-ns` | `$BAO_NAMESPACE`, then `$VAULT_NAMESPACE` | the OpenBAO namespace the PKI mount lives in, and where the certificate is signed |
| `--login-ns` | `-ns` itself; then `$ACCESSCTL_BAO_LOGIN_NAMESPACE` | the namespace to log in at, when it differs from `-ns` — must be `-ns` or a parent of it |
| `-role` | `db-client` | the OpenBAO PKI role to sign with |
| `-mount` | `pki` | the OpenBAO PKI mount |
| `--common-name` | the signed-in identity | the common name to ask for |
| `--audience` | `openbao` | the exchange client OpenBAO accepts |
| `--issuer`, `--client` | what `login` wrote | as for every other command |

`-ns` and `-mount` are spelled short, mirroring `bao`'s own
`-namespace`. **The authentication step is `bao`'s own**
(`openBAOLogin` in the source): the sign-in (or a job's own identity)
exchanged for `--audience`, then logged in to the JWT mount, in
`--login-ns` (`-ns` itself by default) — and it shares `bao`'s cache,
keyed by the LOGIN namespace, so a `bao` call and a `pg`/`psql` call that
agree on the address, login namespace, mount and login role reuse the
same login, even when their own target `-ns` differ (one a descendant of
the other, both descendants of the shared login namespace). The
certificate itself is always signed, and cached, in `-ns` — the target —
regardless of where the login happened; see
[connect/openbao.md#logins-at-a-parent-namespace](../connect/openbao.md#logins-at-a-parent-namespace).

### The certificate

**Reused while it has enough life left AND was minted for the same
common name, minted under a lock otherwise.** Cached at
`<config>/credentials/<address-hash>/<ns>/<role>/client.{crt,key}` (and
`client-ca.crt` when the role returns a chain), `0600` in a `0700`
directory — the private key never leaves this process except into that
file, and no TTL is ever sent, exactly like `bao`'s own login: the PKI
role's `max_ttl` is the only answer. The address is hashed into the
path so two OpenBAO installations sharing a namespace and role name
never share a leaf. The margin before reuse stops is five minutes (the
same one `aws_cache.go`'s `awsCacheMargin` uses), wider than the login
token's own minute-scale margin because a certificate is handed to a
connection that may keep using it for a while, not spent in one round
trip. The common name is resolved (`--common-name`, else the signed-in
identity) BEFORE the cache is read, and a cached leaf whose own
`CommonName` no longer matches is never reused — `--common-name other`,
or simply signing in as someone else, mints fresh rather than silently
handing over the previous identity's certificate.

The certificate returned is checked against the key before anything is
written, exactly as `accessctl credential` used to. A role that will
not sign the name asked for refuses, which is the right place for that
decision.

### The environment

**`PGSSLCERT` and `PGSSLKEY` are always set**, pointing at the
certificate above — there is no caller value for them that would make
sense to keep instead. **`PGSSLROOTCERT`, `PGSSLMODE=verify-full` and
`PGUSER` (the certificate's own common name) are set ONLY when not
already in the environment** — libpq treats every one of these strictly
as a default: an explicit connection-string keyword (`-U`, `user=`) or a
libpq service file's own setting (`PGSERVICEFILE`, or
`~/.pg_service.conf`, `service=<name>`) both outrank it, so a
repository's own committed service file, or a plain `-U`, still wins.
`PGSSLROOTCERT` is also skipped entirely when the role returned no
chain and no issuing certificate (no `client-ca.crt` was written), and
in general is a deliberate default rather than an authority: the PKI's
CA is not necessarily the CA that signed the database SERVER's own
certificate, so a server behind a different CA needs its root named a
different way (a repository's service file `sslrootcert=`, or the
caller's own `PGSSLROOTCERT`) — this only supplies what nothing else
already decided.
[connect/postgresql.md](../connect/postgresql.md) is the how-to,
including the server side and a committed, secret-free service file as
the recommended repo pattern.

### What each failure exits with

| Code | When |
|---|---|
| `2` | a flag accessctl does not recognise before `--`; no OpenBAO address; a CA bundle that cannot be read or holds no certificate; an empty `--audience`; `pg` with no command; `--login-ns` (or `$ACCESSCTL_BAO_LOGIN_NAMESPACE`) that does not cover `-ns` |
| `3` | not signed in (on a laptop): run `accessctl login` |
| `4` | the issuer refused the exchange for `openbao`, or OpenBAO refused the login or the sign |
| `5` | no `<command>` (or no `psql`) on `PATH`; the issuer or OpenBAO could not be reached |
| the command's own | whatever `psql` or the command itself exits with, once it is run |

## Installing it

Each release carries `accessctl_<version>_nix-flake.tar.gz`,
a Nix flake over that release's own archives; a repository adds its URL
with `#accessctl` to `devbox.json`
([design](../design/accessctl.md#installing-it)). The release's archives
are there too for a plain download.

## Where things are kept

`<config>/config.yaml` (`~/.config/accessctl/config.yaml` on Linux; see
[above](#keys-and-where-the-files-go) for the directory) holds the
**default** issuer and the client id, written by `login`.

The sign-in itself lives in `<config>/sessions/<issuer>-<hash>.json`,
mode `0600`: the refresh token, and since 1.25.1 the **access token of
the last refresh with its expiry** (`access_token`, `access_expires`).

**One file per issuer**, because a laptop belongs to more than one
estate. Until this split there was a single `session.json`, so signing in
at the second issuer replaced the first one's refresh token; `--issuer`
then selected the right endpoint and handed it the **wrong** token, which
the issuer refuses as `subject_token is invalid` — a message that reads
as expiry and is not. Separate files also mean two exec plugins for
different estates never rewrite the same file, which one file could not
promise however carefully it was written.

The name is derived from the issuer so the directory is readable; the
issuer is also stored **inside** the file and that is what a read checks,
so a name that collides fails closed as *not signed in* rather than
opening a session at the wrong estate. A `session.json` from before the
split is adopted by whoever asks first and replaced by the next `login`.

Nothing else changes: `config.yaml` still names the default issuer, so a
bare `accessctl whoami` behaves as it always did, and every context
`kubeconfig` writes already passes its own `--issuer`.

**A file rather than the OS keyring**, deliberately: a keyring is a
platform-specific dependency on every laptop and a prompt in the middle
of a `kubectl` call on some of them. This is the same secret a browser
already keeps in a cookie jar, and `login` replaces it in one command if
it leaks.

A rotated refresh token is written back. A refused refresh — revoked,
expired, or the account suspended — reads as *not signed in*, because
signing in again is the only answer.

**Why the access token is kept too.** A refresh **spends** the refresh
token: the issuer rotates it and refuses the old one, so two commands
refreshing at the same instant leave one of them holding a dead token,
and that reads as *not signed in* — for every audience at once. Keeping
the access token means a command with one still in hand presents it
instead of refreshing, and the moment a refresh is needed is taken under
the lock `<issuer>-<hash>.json.lock` beside that issuer's file, so eight callers waking at
once make one refresh -- per issuer, so a busy estate never makes the
other one wait. It is the weaker of the two secrets, short-lived
and unable to mint its successor, in the file that already held the
stronger one under the same mode; it is kept only when its lifetime is
known, and cleared otherwise.

**Two token caches, one file per credential**, for the same race one
level down — `kubectl` runs its exec plugin once per process, and every
provider process of a tool like Pulumi runs the credential process:

| Cache | Path | Keyed by | Offered until |
|---|---|---|---|
| `kube-token` | `<config>/kube/<hash>.json` | the issuer, the client id and the audience, hashed together — the same audience at another issuer is a different credential | a minute before the token's expiry, which is when client-go re-runs the plugin |
| `aws` | `<config>/aws/<hash>.json` | the audience and the role ARN, hashed — an account id is not something to scatter across a filesystem | five minutes before the credential's expiry, when the AWS SDK would refresh its own copy |

Each file is `0600` in a directory made `0700`, written to a temporary
name and renamed so a reader never sees half a token, with a lock file
`<hash>.json.lock` beside it that turns a cold start by many callers
into one exchange. **Every cache is advisory in every direction**: a
file that is absent, truncated, unreadable, expired, from an older
version of this command, or unwritable means *mint afresh*, and none of
them is ever an error. `login` does not touch them — it writes
`config.yaml` and that issuer's session file and nothing else — so a token cached
under the previous sign-in is offered until its expiry margin; a revoked
audience is refused by the relying party until then, and deleting the
`kube` and `aws` directories is how to force a fresh exchange. In a job
the same files are written wherever `kube-token` or `aws` runs, keyed the
same way; only the login cache is absent there.

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
`github-token`, `bao`, `pg` and `psql` ask GitHub for the job's identity
token — for the issuer's URL, the one
audience it accepts — and exchange that, presenting the audience as the
client, exactly as the GitHub Action does. There is no `login` in a job
and no login cache: every proof is the job's own token, exchanged afresh,
though `kube-token` and `aws` keep their per-credential caches
([above](#where-things-are-kept)) there as anywhere. A repository that would rather
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
| `4` | that audience, or that App's token, is not granted to you (for `bao`, `pg` and `psql`, also OpenBAO's `403`); retrying will not help |
| `5` | the issuer could not be reached (for `bao`, `pg` and `psql`, also OpenBAO); retrying might |
