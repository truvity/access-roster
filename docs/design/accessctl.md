# accessctl and the GitHub Action

**Status:** built; on laptops since 1.5.5 and inside GitHub Actions jobs since 1.4.0.

## Why a CLI at all

Two reasons used to justify a client binary; one survives. A broker's
client was needed because the identity provider could not exchange a CI
platform's token — that disappears, since the issuer's exchange is a
standard token-endpoint call any `curl` can make. What remains is that
**the cloud CLI has no interactive login**: a person needs something that
runs the browser flow once, exchanges for a role's audience, and answers
as a credential process. kubectl has kubelogin for the same job; the
cloud has nothing. So: one small CLI, with subcommands, because they share
a login cache and an issuer configuration.

## Subcommands

| Command | Does | Used by |
|---|---|---|
| `login` | authorization code with PKCE on a loopback port — the only browser flow served; caches the refresh token in a file with mode 0600. Its client is public and declares `sign_in_exchange: true`, the one thing that lets the exchange take a sign-in as a proof | people |
| `whoami` | the identity and what the policy grants it | people |
| `kubeconfig` | reads `/.access/grants`, writes a kubeconfig context per granted cluster, exec plugin `accessctl kube-token` (or kubelogin) | people |
| `kube-token` | a Kubernetes exec credential for one cluster audience; refreshes silently from the cached login | people |
| `aws-config` | writes a profile per granted cloud role with `credential_process = accessctl aws --audience aws:<account>:<role>` | people |
| `aws` | exchanges the cached login for the role's audience and answers the credential-process JSON | people |
| `token` | prints a token for one audience on stdout and nothing else, for a caller that is neither kubectl nor an AWS SDK: `accessctl token --audience openbao \| bao write -field=token auth/jwt-roster/login role=roster jwt=-`. The laptop sign-in, or the job's own token in CI | people, jobs |
| `github-token` | prints a GitHub App installation token of a catalogue App, `--app <id>`, narrowed by `--repository` and `--permission name=level`, under the catalogue's grants; `--json` prints what GitHub granted beside it. The laptop sign-in, or the job's own token in CI | people, jobs |
| `credential` | mints a short-lived certificate through OpenBAO: `credential ssh\|db\|client --env <env>`, one exchange for `openbao`, one login on the JWT mount, one `sign` call, delivered into the ssh-agent, a psql service entry or a named path. The laptop sign-in, or the job's own token in CI | people, jobs |
| `secrets` | reads a team's shared values out of OpenBAO's KV engine as a `.env` file: `secrets env --namespace <env> --prefix <path>`, the same exchange and login as `credential` with a listing and a read per leaf where the signing is; one variable per path, `0600`, written by rename, never a value printed. The laptop sign-in, or the job's own token in CI | people, jobs |
| `setup` | `kubeconfig` + `aws-config` in one go, then prints the Docker and CodeArtifact lines | people |
| `exchange` | the raw exchange: subject token in, token with the requested audience out | scripts |

**A job runs the same commands.** With `ACTIONS_ID_TOKEN_REQUEST_URL`
and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` set, `kube-token`, `aws`,
`token`, `github-token`, `credential` and `secrets` ask GitHub for the job's own identity token, minted for the
issuer, and exchange that, presenting the audience as the client the way
the action does. So one committed kubeconfig and one `aws.ini` serve a
laptop and a job alike, where a repository used to keep a second copy of
each for CI. The action below stays for a repository that would rather
download nothing of ours into a job.

## The GitHub Action

One action, at the repository root, toggled by its inputs. It prepares
exactly what is ours to prepare and stops:

```yaml
- uses: truvity/access-roster@v1.8.0   # pin a release; there is no floating v1
  with:
    issuer: https://issuer.example.internal
    audiences: k8s:staging, aws:111122223333:deployer, aws:444455556666:artifacts-reader
    kubeconfig: true                            # a context per k8s:* audience
    default-profile: deployer@111122223333
    region: eu-central-1                        # written into every profile
```

| Input | Effect |
|---|---|
| `issuer` | required |
| `audiences` | one exchange per audience; each client's `requires` decides. Optional when `github-app` is given |
| `github-app`, `repositories`, `permissions` | an installation token of a catalogue App, narrowed to those repositories (names, without the owner) and `name:level` permissions, under the catalogue's grants; output `github-token`, masked |
| `kubeconfig` | write a kubeconfig with one context per `k8s:<cluster>` audience, the cluster token as bearer |
| `default-profile` | export `AWS_PROFILE` |
| `region` | the region written into each profile |

For every `aws:<account>:<role>` audience it writes a profile named
`<role>@<account>` with `role_arn`, `web_identity_token_file` pointing at
the exchanged token, and the region. Outputs: the profile names, the
kubeconfig path, the tokens (masked). Inside: `curl`, `jq`, two files.
Nothing of ours is downloaded into the job.

**Everything downstream of an AWS credential is AWS's tooling and runs on
top of those profiles**: ECR login, CodeArtifact tokens, any other service.
The action does not wrap them, on purpose — many registries and many
artifact domains are just many profiles and many `--profile` flags, and no
version of ours moves when Amazon's tooling does. The recipes are in
[connect/registries-and-artifacts.md](../connect/registries-and-artifacts.md).

## `credential`: the broker for what OpenBAO mints

Three kinds of credential that nothing else in this tool can serve — an
SSH certificate, a database client certificate, a machine client
certificate — and one security model for all three. The command is a
courier, and the design is mostly a list of decisions it does **not**
make:

| Decided by | What |
|---|---|
| the exchange client's `requires` | who may ask at all. A session revoked in the console stops issuance within the exchange's token cap, because every run exchanges afresh |
| the OpenBAO role | the lifetime, the extensions, the key id, which principals and names are allowed. No request from here carries a TTL, so a role change reaches every credential in flight |
| the caller | which public key is signed, and which principals or names are asked for — a request, never a grant |

**The key is generated for the certificate, not decorated by it.** For
SSH the pair is made in the process, signed once, and handed to the agent
with the certificate's own lifetime; nothing long-lived survives the
expiry to be signed again by somebody else. The PKI kinds are the same:
an ECDSA P-384 key is made in the process, a CSR for it goes to
`pki/sign/<role>`, and the key is written beside the certificate that
comes back — never sent, so a role can offer `sign` alone and no call
exists that would have the manager make a key and put it on the wire.

**Nothing that could mint a second credential outlives the command.** The
OpenBAO token is held in memory and revoked on the way out; a batch token
refuses that revoke and says so, which is swallowed rather than turned
into a failed exit for a credential that was delivered — it was never on
disk and it expires on its own.

**Delivery is where each kind is actually consumed**: the ssh-agent (or
`~/.ssh`, certificate beside key, the way OpenSSH looks for it), a psql
service entry naming the files, or a path the caller gives. What is
printed is what an investigator needs — the `key_id` or common name, the
principals, the serial and the expiry — and never the key.

## Installing it

Every release carries `accessctl_<version>_nix-flake.tar.gz` beside the
archives: a Nix flake that fetches that release's archives by sha256
(linux amd64 and arm64, darwin arm64). A repository whose tools come from
devbox names it in `devbox.json`, and `devbox.lock` pins it:

```json
"https://github.com/truvity/access-roster/releases/download/v1.7.0/accessctl_1.7.0_nix-flake.tar.gz#accessctl": ""
```

Moving to a new version means changing the version in that URL. Anything
else downloads the archive for its platform from the release.

## `accessctl setup` on a laptop

The same boundary for people: one command that writes the kubeconfig
contexts and the AWS profiles for everything the policy grants, with
`accessctl aws` as the credential process behind each profile, and then
prints the lines it will not write for you — the Docker credential-helper
mapping and the CodeArtifact login commands. Idempotent; run it again
after a policy change.

## What it never does

No stored secrets and no cloud SDK inside. **What is on disk is
short-lived and advisory, except the refresh token.**
`sessions/<issuer>-<hash>.json` -- one file per installation, so a laptop
signed in at two estates keeps both -- holds the refresh token and, beside it, the access token of the last
refresh with its expiry — kept so that a command with one in hand does
not spend the refresh token for another exactly like it, because a
refresh rotates that token and two commands refreshing at once sign the
operator out of everything. `kube-token` and `aws` each keep one cache
file per credential under `<config>/kube/` and `<config>/aws/`, `0600`,
offered until shortly before expiry and dropped on any doubt, with a
lock file beside each so a cold start by many callers is one exchange
([reference](../reference/accessctl.md#where-things-are-kept)). None of
it can mint its own successor; the refresh token is the one thing that
can, and `login` replaces it. In a job there is no login cache — it
exchanges the job's own token afresh, prints what the consumer expects
and stops — and the two credential caches are written there as anywhere.
