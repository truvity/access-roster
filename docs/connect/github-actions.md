# Connect GitHub Actions

A workflow holds no secret. It requests its identity token, exchanges it
at the issuer for the audiences the rules allow, and uses the result.

## Issuer side

```yaml
proofs:
  github:
    - organisation: example-org
```

## Rules

```yaml
- id: gitops-deploys
  when: { github: { repository: example-org/gitops, ref: refs/heads/master } }
  grant: { audiences: [aws:111122223333:gitops-deployer, k8s:devel] }
- id: any-repo-reads-devel
  when: { github: { owner: example-org, ref: refs/heads/* } }
  grant: { audiences: [k8s:devel-readonly] }
```

## Workflow side

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

The action is shell only: one `curl` to `/token` per audience with
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
`subject_token=<the job's token>` and `audience=<one audience>`, then a
kubeconfig with the cluster token and an AWS profile with
`web_identity_token_file`. Nothing is downloaded into the job.

**Both targets go through the issuer, never directly.** A cluster trusts
one OIDC issuer and that is access-issuer, so a GitHub token can never be
presented to an API server; and cloud accounts trust the issuer's
audiences rather than GitHub's subjects, so the policy stays in one rules
file instead of in every account's trust policies.

**Token lifetime.** An exchanged token for a CI audience lives as long as
the issuer's client setting for CI says — long enough for a deploy or a
soak step. A job that must outlive it re-runs the action before the long
step.

Runners inside the cluster keep their ServiceAccount and the cloud's pod
identity; they never need this flow.
