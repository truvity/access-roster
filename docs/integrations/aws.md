---
title: AWS
description: How people and CI jobs assume AWS roles with sluis as the OIDC provider, how AWS roles prove themselves to sluis, and how sluis's own actors reach AWS.
status: target
sidebar:
  order: 6
---

AWS appears in three directions, and it helps to keep them apart.

| Direction | Who proves what to whom | Mechanism |
|---|---|---|
| **Accounts trust sluis** | A person or a CI job proves its identity to sluis, then to an AWS account. | An IAM OIDC provider for sluis's issuer; `AssumeRoleWithWebIdentity` at STS. |
| **AWS roles prove themselves to sluis** | A Lambda function, container task or instance running as an IAM role calls a service that trusts sluis. | AWS outbound identity federation; a workload verifier in sluis checks the token. |
| **sluis's own actors reach AWS** | A sluis actor writes to its bucket or uses its key. | The boundary's workload issuer and `AssumeRoleWithWebIdentity` ([Identity](/concepts/identity/)). |

## What it's for

- **An engineer assumes a role in an account** with their normal sign-in, without an identity-centre product. `aws --profile deployer@123456789012 s3 ls` works because the profile asks sluis for a token and STS accepts it.
- **A CI job deploys** with a role limited to that job. It exchanges its CI identity token for a sluis token for one role's audience and assumes the role. No access key is stored in CI.
- **A Lambda function calls an internal service.** It asks AWS for an identity token for the service's audience; sluis verifies it and returns a token for the function's role and groups.
- **A sluis actor writes its audit archive to a bucket** with credentials from `AssumeRoleWithWebIdentity`, so a compromised node reaches only what the actors it runs may reach ([#870](https://github.com/truvity/sluis/issues/870)).

## Integration kinds

| Kind | What it does for AWS |
|---|---|
| `WorkloadVerifier` | Verifies an AWS outbound-federation token: the issuer is a declared account's, the audience matches, the signature checks against the account's key set, the token is fresh, the account in the role ARN matches, and the subject is a role ARN. It refuses assumed-role sessions, users and the account root. |

The other two directions need no integration process: the account trusts sluis's issuer (a client profile), and a cloud driver exchanges a workload token. AWS is not a `CredentialMinter`: STS mints the credentials, and sluis only issues the token STS accepts.

## What sluis asks the vendor for

Nothing long-lived: sluis holds no AWS access key for any direction. In each account the operator creates:

- an **IAM OIDC provider** for sluis's issuer URL (HTTPS, no port, no query);
- **one role per purpose**, whose trust policy names the audience, plus a `sub` condition when the role is for one workload.

For the verifier, sluis reads each account's public key set over outbound access to the AWS token hosts. Each account turns on outbound identity federation, and the role's policy allows it to ask for a token, limited to one audience, the ES384 algorithm and a short duration. AWS accepts ES384, sluis's default, so no RSA key is needed.

## What policy controls

- **Who may assume which role.** Each role is a client, and its `requires` names the groups that may ask for it. The decision rides in the token's `aud`, which the role's trust policy reads, so AWS holds no per-user statements.
- **For a workload:** matchers on account, role name and path.
- **Lifetime.** The shorter of the group lifetime and the client's cap, with no refresh token. A revocation reaches AWS when the token expires, so give the client a short cap.
- **Trusted accounts** for the verifier, as a declared list. An empty list verifies no AWS token.

## What is audited

- Every exchange: the proof (person, CI or workload), the audience, the outcome and the groups.
- Each refusal: a role in no group, an unknown audience, a token from an undeclared account. The caller sees one fixed answer for all of them.
- For sluis's own actors, CloudTrail records each `AssumeRoleWithWebIdentity`.

## Setup

See [the AWS pattern](/integrations/connecting/#aws-oidc-provider-and-role-trust); names and keys are [illustrative](/integrations/#examples-are-illustrative).

1. Run `sluis integrations render aws --account example-prod`. It writes the IAM OIDC provider and one trust policy per declared role, as a template for your infrastructure-as-code tool, so trust comes from the same file as the clients.
2. Apply it in the account, and declare the roles as clients with `requires`.
3. A person runs `sluis login`, then `sluis aws-config`, which writes a profile `<role>@<account>` per role they are granted.
4. A CI job uses the exchange action with `audiences: aws:<account>:<role>`, where `<account>` is the account's declared name (`example-prod` below), never its number ([ADR 0017](/decisions/0017-identity-and-sign-in/#audiences)).

```yaml
# /etc/sluis/install.yaml (example)
integrations:
  aws:
    example-prod:
      account: "123456789012"
      roles:
        deployer: { requires: [ci-platform] }
        power:    { requires: [sre] }
      verifier:                      # accept AWS roles as workloads
        issuer: https://<id>.tokens.sts.global.api.aws
        algs: [ES384]
```

```ini
# ~/.aws/config written by the command (example)
[profile deployer@example-prod]
credential_process = sluis aws --audience aws:example-prod:deployer
region = eu-example-1
```
