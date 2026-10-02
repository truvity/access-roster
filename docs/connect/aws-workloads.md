# AWS workloads (Lambda, ECS, EC2) via outbound identity federation

**Anchor:** the issuer; the AWS account's own published key set is the proof.

A workload that runs as an IAM role — a Lambda function, an ECS task, an
EC2 instance — can prove who it is to this issuer **without a stored
secret**, then exchange that proof for a short-lived token of the issuer's
for a client's audience, exactly as a CI job or a Kubernetes workload does
([service-to-service.md](service-to-service.md)).

The mechanism is AWS IAM *outbound identity federation*: the role calls
`sts:GetWebIdentityToken` and gets a JWT signed by its **account's**
issuer. The issuer verifies it against that account's published key set;
nothing here holds a credential for AWS, and nothing calls AWS except to
read a public JWKS.

This is the opposite direction from [aws-account.md](aws-account.md), where
the issuer's tokens let a *person* assume a role.

## What the token is, and what the verifier decides

AWS documents the token's claims
([Understanding token claims](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_token_claims.html)):
`iss` is a per-account `https://<id>.tokens.sts.global.api.aws`, keys are at
`<iss>/.well-known/jwks.json`, `sub` is the principal's ARN, `aud` is what
the role asked for, signed ES384 or RS256, and AWS's own claims sit under
`https://sts.amazonaws.com/` (`aws_account`, `org_id`, and for Lambda
`lambda_source_function_arn`).

A token is accepted only when **all** of these hold, and any failure after
the issuer is recognised is a final refusal:

- `iss` is a configured account's issuer (any other `iss` is somebody
  else's token and goes to the next verifier);
- the signature verifies against that issuer's key set, with an algorithm in
  the row's `algs` (never the one the token's header prefers). An unknown
  `kid` re-fetches the set, at most once per ten seconds;
- `aud` contains the configured audience, exactly;
- `exp` has not passed, `nbf` has, `iat` is not in the future, **and `iat` is
  no older than `maxAge`** (default 5 minutes) even if `exp` would allow an
  hour;
- the `aws_account` claim, the account in the role's ARN and the account of
  the row are all the same, and `org_id` equals the row's `orgId` if it sets one;
- `sub` is a role ARN, as below.

### The identity is the role

`sub` is parsed strictly as `arn:aws:iam::111122223333:role/<path><name>`. The
minted token's subject is `aws:<account>:role/<path><name>`
(`aws:111122223333:role/telemetry/otel-writer`). It does not change with the
session, the function or the instance, so an audit trail does not fragment.
Which function uses the role is the function's business: a Lambda token's
function ARN is passed to the policy (an optional `function` matcher) but is
never the subject.

AWS documents `sub` as "the ARN of the IAM principal that requested the
token", and every example it gives is the role ARN — never the
`arn:aws:sts::111122223333:assumed-role/<name>/<session>` form that
`sts:GetCallerIdentity` returns for the same caller. Nothing documents that
form as a subject, so it is **refused**. A session name is chosen by whoever
assumes the role, so a rule that depended on it would be a rule its caller
could write. Users, the account root, federated users, other partitions and
anything with a role name or path outside `[A-Za-z0-9_+=,.@-]` are refused
too.

## Operator steps

### 1. Enable federation in each account

Once per account, by the account's owner (an account-level IAM setting):

```sh
aws iam enable-outbound-web-identity-federation
aws iam get-outbound-web-identity-federation-info   # prints IssuerUrl
```

`IssuerUrl` — `https://<id>.tokens.sts.global.api.aws` — goes in the row
below. Without this, STS refuses with `OutboundWebIdentityFederationDisabled`.
`sts:GetWebIdentityToken` is called on the **regional** STS endpoint, and a
function in a VPC with no route out needs an STS interface endpoint.

### 2. Let the role ask for a token, for this audience only

```json
{
  "Effect": "Allow",
  "Action": "sts:GetWebIdentityToken",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "sts:IdentityTokenAudience": "https://access.example.com",
      "sts:SigningAlgorithm": "ES384"
    },
    "NumericLessThanEquals": { "sts:DurationSeconds": 300 }
  }
}
```

The audience is the issuer's own URL by default (`exchange.aws.audience`).
The condition is the account owner's guard that the role can mint a token
for nobody else; the issuer's audience check is the other half.

### 3. Add the account to the issuer

In the chart:

```yaml
exchange:
  aws:
    audience: ""          # default: the issuer URL
    maxAge: 5m
    accounts:
      - account: "111122223333"
        name: apps                      # the estate's word, for logs
        issuer: https://example-id.tokens.sts.global.api.aws
        orgId: o-example1234            # optional: require this organization
        algs: [ES384, RS256]            # optional: default both
        # jwksUri: ""                   # optional: default <issuer>/.well-known/jwks.json
```

The issuer needs egress to `https://*.tokens.sts.global.api.aws` (port 443)
to read each account's key set; the chart carries no egress rules, so that
belongs in the fleet's own egress policy, as it does for `api.github.com`.

The chart mounts it as a file and sets `AWS_FEDERATION_FILE`
([configuration reference](../reference/configuration.md)). **There is no
default account and an empty list verifies no AWS token**: any AWS account
can mint a valid token for a role of its own, so the row is what makes an
account yours. A bad row stops the issuer at start rather than skipping an
account whose roles would then fail with the wrong cause. Adding a row is a
rollout.

### 4. Write the matcher

```yaml
groups:
  otlp:billing:writer:
    matchers:
      - aws: { account: "111122223333", role: "billing-*" }
clients:
  otlp: { kind: exchange, requires: [otlp:billing:writer], ttl_cap: 15m }
```

The fields and glob rules are in the
[policy reference](../reference/policy.md#the-aws-matcher). `account` is
exact and required.

### 5. Exchange

The workload requests a token for the issuer's audience, then exchanges it
(the same request as in [service-to-service.md](service-to-service.md)):

```sh
TOKEN=$(aws sts get-web-identity-token --audience https://access.example.com \
          --signing-algorithm ES384 --duration-seconds 300 \
          --query WebIdentityToken --output text)

curl -u otlp: https://access.example.com/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  -d audience=otlp
```

The response's `access_token` has `sub=aws:111122223333:role/billing-api`,
`aud=otlp`, the groups the role holds and the roster's claim fragments, and
lives no longer than the shortest group lifetime and the client's `ttl_cap`.
No session or refresh token is created.

## What is recorded

Each exchange is a `roster.token.exchanged` record with `proof` `workload`
and the actor kind `workload`, whose id is the subject
(`aws:111122223333:role/billing-api`). Refusals — a role in no group — are
recorded too.

## What is given up

A token stays valid until its `exp` (at most `maxAge` after it was issued
here) even if the role is deleted or its permission to call
`sts:GetWebIdentityToken` is withdrawn, and the minted token is not
revocable either, which is why a client for this should carry a short
`ttl_cap`.
