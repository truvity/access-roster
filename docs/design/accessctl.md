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
| `kube-token` | a Kubernetes exec credential for one cluster audience; refreshes silently from the cached login | people |
| `aws-config` | writes a profile per granted cloud role with `credential_process = accessctl aws --audience aws:<account>:<role>` | people |
| `aws` | exchanges the cached login for the role's audience and answers the credential-process JSON | people |
| `exchange` | the raw exchange: subject token in, token with the requested audience out | scripts, the action |

**Machines do not run the CLI.** A job's exchange is one call to the
issuer's token endpoint; the action below does it in shell. The CLI may
later learn to detect a CI platform's identity-token environment and act
as the kubeconfig exec plugin for jobs that outlive an exchanged token,
but that is an option for the day such a job exists, not part of the
shape.

## The GitHub Action

`truvity/access-roster/actions/exchange` is **shell only** — `curl` and
`jq`, no binary downloaded into the job. It requests the job's identity
token, exchanges it at the issuer for each audience requested, and writes
a kubeconfig with the cluster token and an AWS profile pointing at a
web-identity token file. A workflow deploying to one cluster and one
account:

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
in the keyring, no cloud SDK inside, and no place in a job — it prints
what the cloud CLI's credential process expects and stops.
