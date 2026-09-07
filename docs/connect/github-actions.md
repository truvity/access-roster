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

Without the action, the exchange is one `curl` to `/token` with
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
`subject_token=<the job's token>` and `audience=<one audience>`; the
action only saves the kubeconfig and profile plumbing.

Runners inside the cluster keep their ServiceAccount and the cloud's pod
identity; they never need this flow.
