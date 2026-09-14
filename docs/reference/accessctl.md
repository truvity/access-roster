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
accessctl exchange --audience k8s:devel < subject-token
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
`ACTIONS_ID_TOKEN_REQUEST_TOKEN` are set, `kube-token`, `aws` and `token`
ask GitHub for the job's identity token — for the issuer's URL, the one
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
| `4` | that audience is not granted to you; retrying will not help |
| `5` | the issuer could not be reached; retrying might |
