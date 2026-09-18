# accessctl

```sh
accessctl login   --issuer https://access.example
accessctl whoami                             # who you are, and what it opens
accessctl setup                              # both of the next two

accessctl kubeconfig                         # a context per granted cluster
accessctl aws-config                         # a profile per granted cloud role

kubectl --context kernel get nodes           # exec plugin: accessctl kube-token
aws --profile power@1111 sts get-caller-identity   # credential_process: accessctl aws

accessctl token --audience openbao              # one token for one audience, on stdout
accessctl github-token --app publisher --repository app --permission contents=read
accessctl exchange --audience k8s:devel < subject-token

accessctl credential ssh --env staging --principal deploy      # into the ssh-agent
accessctl credential db  --env staging --project example \
    --host db.example --dbname orders                          # a psql service entry
accessctl credential client --env staging --out ./gateway.crt  # a certificate and its key
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
3. make **one** call — `ssh/sign/<role>`, `pki/sign/db-client`,
   `pki/sign/client` — over a key made on this machine;
4. deliver the result, and revoke the OpenBAO token on the way out.

**Nothing here chooses a lifetime.** No request carries a TTL: the role's
`ttl` and `max_ttl` are the whole answer, so shortening the role shortens
every credential in flight and no flag can ask for longer. What accessctl
does send is a public key, the principals or the common name asked for,
and nothing else — a role that will not sign them refuses, which is the
right place for that decision.

**The OpenBAO token is never written anywhere.** It lives in memory for
the length of one command and is revoked at the end; a mount that hands
out batch tokens refuses the revoke, which is not an error, because such
a token cannot be revoked and expires on its own.

Each kind prints what the audit trail will show — the certificate's
`key_id` or common name, and its serial — so a line in an sshd log, a row
in the issuer's trail and OpenBAO's own record of the signing can be read
as one story about one subject.

| Kind | Asks for | Delivers |
|---|---|---|
| `ssh` | a key pair generated for this certificate alone; `--principal` (repeatable) | the certificate and key into the **ssh-agent**, with a lifetime the certificate decides; or, with `--identity`, into `~/.ssh` as `<name>`, `<name>.pub` and `<name>-cert.pub` — the certificate beside the key, where `ssh -i <name>` finds both |
| `db` | an ECDSA P-384 key generated for this certificate alone, sent as a CSR; `--host`, `--dbname`, `--port`, `--service`; `--project` for a role in a project's own namespace | the certificate, key (`0600`) and CA under `~/.config/accessctl/credentials/<env>/`, and a **psql service entry** (`~/.pg_service.conf`, or `PGSERVICEFILE`) whose `user` is the certificate's common name, for `psql "service=<name>"` |
| `client` | the same, as a CSR; `--out`, `--uri-san` (repeatable) | `<out>.crt`, `<out>.key` (`0600`) and `<out>-ca.crt`, at the path the caller named |

`--identity id_example` (a bare name) means `~/.ssh/id_example`; a path
with a separator is taken as given. A key this tool did not write is
**never** overwritten — `--identity id_ed25519` is one keystroke away from
a key somebody has used for years.

The service file holds one block per service (`# >>> accessctl <name> >>>`),
so a credential for a second database leaves the first entry alone.

**Which role.** Each kind signs with its ordinary role unless `--role`
names another: `user` for `ssh`, `db-client` for `db`, `client` for
`client`. SSH has a second, `admin`, which is never a default: `user` is
for everyday logins as a host's ordinary account, `admin` for the
account that administers it, and the two are granted separately.

**Where it points.** `--address` names the OpenBAO API, or `BAO_ADDR`
(`VAULT_ADDR` is read too); with none of the three the command exits 2
and says how to set it. The namespace is the environment's own —
`--env staging` works in `staging` — for every kind, and the first of
`--namespace`, `BAO_NAMESPACE` and `VAULT_NAMESPACE` overrides it;
`--project <project>` on `db` reaches a role kept in `<project>/<env>`
instead.

**Which roots it trusts.** The OpenBAO connection verifies against the
system's roots. An installation that serves its API under a private root
is trusted by naming that root: `--ca-cert <file>`, a PEM bundle, or
`BAO_CACERT` (`VAULT_CACERT` is read too), the flag first. The bundle is
**added** to the system's roots, not put in their place, and it is used
for OpenBAO alone — the exchange at the issuer keeps the system's trust.
A bundle that cannot be read or holds no certificate exits 2 before
anything is exchanged, and a server the roots do not verify is refused
with a pointer to the flag.
`--mount`, `--login-role` and `--audience` name the JWT mount
(`jwt-roster`), its role (`roster`) and the exchange client (`openbao`)
for an installation that spells them differently.

**Installing it.** Each release carries `accessctl_<version>_nix-flake.tar.gz`,
a Nix flake over that release's own archives; a repository adds its URL
with `#accessctl` to `devbox.json`
([design](../design/accessctl.md#installing-it)). The release's archives
are there too for a plain download.

## Where things are kept

`~/.config/accessctl/config.yaml` holds the issuer and the client id,
written by `login`. `session.json` beside it holds the refresh token,
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
`github-token` and `credential` ask GitHub for the job's identity token — for the issuer's URL, the one
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
| `2` | usage: something in the command line is wrong |
| `3` | not signed in — run `accessctl login` |
| `4` | that audience, or that App's token, is not granted to you; retrying will not help |
| `5` | the issuer could not be reached; retrying might |
