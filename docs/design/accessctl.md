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
| `whoami` | the identity and what the policy grants it | people |
| `kubeconfig` | reads `/.access/grants`, writes a kubeconfig context per granted cluster, exec plugin `accessctl kube-token` (or kubelogin) | people |
| `kube-token` | a Kubernetes exec credential for one cluster audience; refreshes silently from the cached login | people |
| `aws-config` | writes a profile per granted cloud role with `credential_process = accessctl aws --audience aws:<account>:<role>` | people |
| `aws` | exchanges the cached login for the role's audience and answers the credential-process JSON | people |
| `setup` | `kubeconfig` + `aws-config` in one go, then prints the Docker and CodeArtifact lines | people |
| `exchange` | the raw exchange: subject token in, token with the requested audience out | scripts |

**Machines do not run the CLI.** A job's exchange is one call to the
issuer's token endpoint; the action below does it in shell. The CLI may
later learn to detect a CI platform's identity-token environment and act
as the kubeconfig exec plugin for jobs that outlive an exchanged token,
but that is an option for the day such a job exists, not part of the
shape.

## The GitHub Action

One action, at the repository root, toggled by its inputs. It prepares
exactly what is ours to prepare and stops:

```yaml
- uses: truvity/access-roster@v1
  with:
    issuer: https://issuer.example.internal
    audiences: k8s:devel, aws:111122223333:gitops-deployer, aws:444455556666:artifacts-reader
    kubeconfig: true                            # a context per k8s:* audience
    default-profile: gitops-deployer@111122223333
    region: eu-central-1                        # written into every profile
```

| Input | Effect |
|---|---|
| `issuer`, `audiences` | required: one exchange per audience; each client's `requires` decides |
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

## `accessctl setup` on a laptop

The same boundary for people: one command that writes the kubeconfig
contexts and the AWS profiles for everything the policy grants, with
`accessctl aws` as the credential process behind each profile, and then
prints the lines it will not write for you — the Docker credential-helper
mapping and the CodeArtifact login commands. Idempotent; run it again
after a policy change.

## What it never does

No stored secrets, no long-lived tokens on disk beyond the refresh token
in the keyring, no cloud SDK inside, and no place in a job — it prints
what the cloud CLI's credential process expects and stops.
