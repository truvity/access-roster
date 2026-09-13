# Connect GitHub Actions

**Anchor:** the issuer, by exchange. A workflow holds no secret. It
requests its identity token, exchanges it at the issuer for the clients
its groups admit it to, and uses the result.



## Issuer side

```yaml
github:
  owners: [example-org]
```

That list is the trust boundary, not tuning. Anybody may run a workflow
in their own repository and get a perfectly valid token from GitHub's
issuer, so a signature and an expiry prove only that *a* job ran
somewhere; the owner allow-list is the whole of what makes one of them
ours, and an empty list verifies nothing rather than everything. The
audience a workflow must request is the issuer's own URL, and that is not
configurable: a token minted for a cloud provider is a valid GitHub
token, and one audience per relying party is what stops it being
replayed here.

## Policy

A job becomes a machine group by matcher; the clients it may obtain a
token for list that group:

```yaml
groups:
  ci-gitops:   { matchers: [{ github: { repository: example-org/gitops, ref: refs/heads/master } }] }
  ci-any-main: { matchers: [{ github: { owner: example-org, ref: refs/heads/* } }] }
lifetimes: { ci-gitops: 1h, ci-any-main: 1h }
clients:
  aws:111122223333:gitops-deployer: { kind: exchange, requires: [ci-gitops] }
  k8s:devel:                        { kind: public,   requires: [ci-gitops, engineer] }
  k8s:devel-readonly:               { kind: public,   requires: [ci-any-main] }
```

## Workflow side

```yaml
permissions:
  id-token: write
steps:
  # The action requests the job's identity token itself, for the issuer's
  # URL as audience, so nothing else in the job handles a token. The
  # `id-token: write` permission above is what lets it.
  - uses: truvity/access-roster@v1.0.0   # pin the release; there is no floating `v1` yet
    with:
      issuer: https://issuer.example.internal
      audiences: k8s:devel, aws:111122223333:gitops-deployer
      kubeconfig: true
      default-profile: gitops-deployer@111122223333
      region: eu-central-1
  - run: kubectl -n demo rollout status deploy/app
  - run: aws s3 ls
```

The action is shell only: one `curl` to `/token` per audience with
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
`subject_token=<the job's token>` and `audience=<one audience>`, then a
kubeconfig with the cluster token and a profile `<role>@<account>` per
cloud audience with `web_identity_token_file`. Nothing is downloaded into
the job.

## Or: the same files a laptop uses

A repository that has `accessctl` in its toolchain needs no action and no
second copy of its access files. The line a person's kubeconfig runs,

```yaml
exec:
  command: accessctl
  args: [kube-token, --audience, k8s:devel, --issuer, https://issuer.example.internal]
```

and the line a person's `aws.ini` runs,

```ini
[profile test]
credential_process = accessctl aws --audience aws:111122223333:test --issuer https://issuer.example.internal
```

work unchanged in a job granted `id-token: write`. When
`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` are
set, `accessctl` asks GitHub for the job's identity token — for the
issuer's URL, the one audience it accepts — and exchanges that, presenting
the audience as its client exactly as the action does. Anywhere else it
exchanges the cached sign-in. So one committed file serves both, and what
admits each is the target client's `requires`: list the people's groups
and the job's group together when both should reach it.

Keep credentials off a committed `[default]`: in a job it would shadow
the runner's own identity for every call. Select a named profile instead.

**Both targets go through the issuer, never directly.** A cluster trusts
one OIDC issuer and that is access-issuer, so a GitHub token can never be
presented to an API server; and cloud accounts trust the issuer's
audiences rather than GitHub's subjects, so the policy stays in one file
instead of in every account's trust policies.

**Token lifetime.** An exchanged token for a CI audience lives as long as
the issuer's client setting for CI says — long enough for a deploy or a
soak step. A job that must outlive it re-runs the action before the long
step.

**Registries and artifacts** — ECR, CodeArtifact, anything else on AWS —
run on top of the profiles the action wrote, with the official actions
and the AWS CLI: [registries-and-artifacts.md](registries-and-artifacts.md).
