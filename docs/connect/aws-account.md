# Connect an AWS account, without Identity Center

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

## Rules

```yaml
- when: { directory_group: platform-admins@example.com }
  grant: { audiences: [aws:111122223333:power] }
- when: { github: { repository: example-org/gitops, ref: refs/heads/master } }
  grant: { audiences: [aws:111122223333:gitops-deployer] }
```

## Person side

`accessctl aws-config` writes a profile per granted role:

```ini
[profile power@1111]
credential_process = accessctl aws --audience aws:111122223333:power
```

`accessctl aws` exchanges the cached login for that audience and calls
`AssumeRoleWithWebIdentity`; the cloud CLI sees ordinary temporary
credentials.

## Job side

The action with `audiences: aws:111122223333:gitops-deployer` exchanges
the job's GitHub token at the issuer and writes a profile with
`web_identity_token_file` pointing at the result; the AWS CLI does the
rest. The account trusts the issuer, not GitHub: no direct GitHub
provider is configured, and CI's entitlements live in the rules file.
