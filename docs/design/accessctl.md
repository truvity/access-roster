# accessctl and the GitHub Action

**Status:** designed 2026-09-07; built with the issuer.

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
| `login` | device or authorization-code flow against the issuer; caches the refresh token in the OS keyring or a file with mode 0600 | people |
| `whoami` | the identity and the grants the rules allow | people |
| `kubeconfig` | reads `/.access/grants`, writes a kubeconfig context per granted cluster, exec plugin `accessctl kube-token` (or kubelogin) | people |
| `kube-token` | a Kubernetes exec credential for one cluster audience; refreshes silently; in CI, exchanges the ambient platform token instead of a cached login | people and jobs |
| `aws-config` | writes a profile per granted cloud role with `credential_process = accessctl aws --audience aws:<account>:<role>` | people |
| `aws` | exchanges for the role's audience and answers the credential-process JSON; in CI, from the ambient platform token | people and jobs |
| `exchange` | the raw exchange: subject token in, token with the requested audience out | scripts, the action |

The CLI detects a CI platform by its environment (the identity-token
request URL and token) and switches from the login cache to token
exchange; the same kubeconfig and profile therefore work on a laptop and
in a job, which is how the existing broker client behaves.

## The GitHub Action

`truvity/access-roster/actions/exchange` installs `accessctl`, exchanges
the job's identity token for the audiences requested, and writes the
kubeconfig and the cloud profiles. A workflow deploying to one cluster
and one account:

```yaml
permissions:
  id-token: write
steps:
  - uses: truvity/access-roster/actions/exchange@v1
    with:
      issuer: https://issuer.example.internal
      audiences: k8s:devel, aws:111122223333:gitops-deployer
  - run: kubectl -n demo rollout status deploy/app
  - run: aws s3 ls
```

Policy is not in the workflow: the rules decide that `example-org/gitops`
on `refs/heads/master` may have those two audiences and a fork branch may
have none.

## What it never does

No stored secrets, no long-lived tokens on disk beyond the refresh token
in the keyring, no interactive prompts in CI, no cloud SDK inside — it
prints what the cloud CLI's credential process expects and stops.
