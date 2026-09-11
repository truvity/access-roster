# Connect an AWS account, without Identity Center

**Anchor:** the issuer; the account trusts its JWKS and reads `aud`.

> **`accessctl` and the GitHub Action are not built yet (INF-649).**
> Everything on this page that names one describes what it will run, not
> what you can run today. The issuer side is real and can be set up now;
> the laptop and workflow side waits for the CLI.


## Account side, once

An IAM OIDC identity provider for the issuer URL, and per role a trust
policy that names the role's audience:

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::111122223333:oidc-provider/issuer.example.internal" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": { "StringEquals": { "issuer.example.internal:aud": "aws:111122223333:power" } }
}
```

One trust policy per role. No per-user statements, no group claims: for a
custom issuer the trust policy can see `sub`, `aud`, `amr` and `email`,
and the decision rides in `aud`. Add a `sub` condition when a role is for
one workload only.

## Policy

Each role is a client of kind `exchange`; `requires` says who may assume it:

```yaml
clients:
  aws:111122223333:power:           { kind: exchange, requires: [sre] }
  aws:111122223333:gitops-deployer: { kind: exchange, requires: [ci-gitops] }
```

## Person side

`accessctl setup` (or `aws-config` alone) writes a profile per granted
role, named `<role>@<account>`:

```ini
[profile power@111122223333]
credential_process = accessctl aws --audience aws:111122223333:power
region = eu-central-1
```

`accessctl aws` exchanges the cached login for that audience and calls
`AssumeRoleWithWebIdentity`; the cloud CLI sees ordinary temporary
credentials.

## Job side

The action with `audiences: aws:111122223333:gitops-deployer` exchanges
the job's GitHub token at the issuer and writes the profile
`gitops-deployer@111122223333` with `web_identity_token_file` pointing at
the result; the AWS CLI does the rest. The account trusts the issuer, not
GitHub: no direct GitHub provider is configured, and CI's entitlements
live in the policy.

## On top: every other AWS service

ECR, CodeArtifact, S3, anything: `--profile <role>@<account>`, or
`AWS_PROFILE`. Nothing here knows those services; see
[registries-and-artifacts.md](registries-and-artifacts.md) for the
registry and artifact recipes.
