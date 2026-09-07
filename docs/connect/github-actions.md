# Connect GitHub Actions

A workflow holds no secret. It requests its identity token, exchanges it
at the issuer for the audiences the rules allow, and uses the result.

## Issuer side

```yaml
proofs:
  github:
    - organisation: example-org
```

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
  - uses: truvity/access-roster@v1
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

**Both targets go through the issuer, never directly.** A cluster trusts
one OIDC issuer and that is access-issuer, so a GitHub token can never be
presented to an API server; and cloud accounts trust the issuer's
audiences rather than GitHub's subjects, so the policy stays in one rules
file instead of in every account's trust policies.

**Token lifetime.** An exchanged token for a CI audience lives as long as
the issuer's client setting for CI says — long enough for a deploy or a
soak step. A job that must outlive it re-runs the action before the long
step.

**Registries and artifacts** — ECR, CodeArtifact, anything else on AWS —
run on top of the profiles the action wrote, with the official actions
and the AWS CLI: [registries-and-artifacts.md](registries-and-artifacts.md).
