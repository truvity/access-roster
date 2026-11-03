# Signing on AWS: the key and its policy

IAM statements and settings of the `kms-wrapped` signing ring, and the key policy of the deprecated library-created key. Rationale: [Signing on AWS](../../concepts/sluis/signing-on-aws.md).

## The role's grant

`Keys.Sign` (`keys.sign`) names the key by alias. The function's role, and the Kubernetes role when it signs, get on that key only:

```json
{
  "Sid": "SluisKeysSign", "Effect": "Allow",
  "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"],
  "Resource": "<the key's ARN>",
  "Condition": {
    "StringEquals": {"kms:EncryptionContext:instance": "<instance>", "kms:EncryptionContext:purpose": "sign"},
    "ForAllValues:StringEquals": {"kms:EncryptionContextKeys": ["instance", "purpose"]}
  }
}
```

There is no `kms:Sign` grant: the process wraps its own pairs. `instance` is the document's `instance` or `release`. The library writes no key policy, so the key must admit the role ([trust boundary](../../concepts/sluis/signing-on-aws.md#trust-boundary)).

Set `Keys.LegacySigningContext` (nil is true) false once the ring has rotated past entries written before local wrapping.

**The secrets key.** `Keys.Secrets` names the key that encrypts the SSM parameters (`secrets.kmsKeyId`). It grants `kms:Encrypt`, `kms:Decrypt` and `kms:GenerateDataKey` through SSM only, for `/sluis/<instance>/*` only.

## Configuration

```yaml
preset: aws-hybrid
keys:
  adapter: kms
  sign: alias/sluis-demo-sign        # or {key: alias/..., context: off | {..}}
signingKey:
  kmsWrapped:
    stateSecret: issuer/state-secret
    # algorithms: [ES384, RS256]     # the first is the default
    # rotateEvery: 24h
    # prepublish: 12h                # half of rotateEvery
    # retain: 65m
```

`Keys.Sign` writes `keys`; a document that names `keys` is refused. `signingKey.kmsWrapped.keyId` is the deprecated spelling of `keys.sign`. `stateSecret` is a secret name the library writes. `adapters.signing` takes the same `settings:`. Moving from `kms`: [Upgrade to v1.62](../../guides/sluis/upgrade/v1.62.md), step 6.

## Monitoring rotation

| Signal | Behavior |
|---|---|
| Issuer log | A failing rotation keeps the old key signing. ERROR at most hourly once the active key is 1.5 times `rotateEvery` old |
| Metric | `sluis_signing_key_active_since_timestamp_seconds`; alert past `rotateEvery + prepublish + margin` (26h by default) |
| Chart rule | `SluisSigningKeyRotationStalled`. Unset `alerts.rules.signingKeyRotationStalled.maxAgeSeconds` derives `rotateEvery` plus 2h from `config.signingKey` (`93600` for 24h), else 350 days |
| Lambda | No chart: load the rule below into vmalert or a PrometheusRule |

```yaml
- alert: SluisWrappedSigningKeyRotationStalled
  expr: time() - max by (algorithm) (sluis_signing_key_active_since_timestamp_seconds) > 93600
  for: 15m
  labels: {severity: warning}
  annotations:
    summary: 'The {{ $labels.algorithm }} signing key has been active for {{ $value | humanizeDuration }}: rotation is failing'
```

## Legacy: `WrappedSigning`, the library creates the key

Deprecated. The function's role, and the Kubernetes role when it signs, get on the key only:

```json
{
  "Sid": "SluisWrappedSigning", "Effect": "Allow",
  "Action": ["kms:GenerateDataKeyPairWithoutPlaintext", "kms:Decrypt"],
  "Resource": "<the key's ARN>",
  "Condition": {
    "StringEquals": {"kms:EncryptionContext:purpose": "sluis-signing"},
    "ForAllValues:StringEquals": {"kms:EncryptionContextKeys": ["purpose", "alg", "kid"]}
  }
}
```

### The key policy

`WrappedSigning.KeyArn` takes a possibly shared key; merge the statements below into it (`sluispulumi.WrappedKeyPolicyStatements(roleArns)`). Unset, the library creates a protected symmetric key with automatic rotation (alias `WrappedSigning.KeyAlias`, required) with this policy. It needs `LambdaArgs.KeyAdmins`, role ARNs.

| Sid | Effect | Principal | Action | Condition |
|---|---|---|---|---|
| `EnableIAMPolicies` | Allow | the account root | `kms:Decrypt`, `Encrypt`, `GenerateDataKey*`, `ReEncrypt*` and the upkeep actions (describe, list, tags, rotation) | none (IAM policies govern the use of the key) |
| `SluisKeyControlPlaneAdmins` | Allow | the account root | `kms:PutKeyPolicy`, `CreateGrant`, `RevokeGrant`, `DisableKey`, `ScheduleKeyDeletion`, `CreateAlias`, `UpdateAlias`, `DeleteAlias` | `aws:PrincipalArn` matches `KeyAdmins` |
| `SluisKeyControlPlaneAdminsOnly` | Deny | `*` | the same eight | `aws:PrincipalArn` matches none of `KeyAdmins`, and the caller is not an AWS service |
| `SluisSigningContextReserved` | Deny | `*` | `kms:Decrypt`, `kms:Encrypt`, `kms:ReEncrypt*`, `kms:GenerateDataKey*`, `kms:CreateGrant` | `kms:EncryptionContext:purpose` is `sluis-signing`, and `aws:PrincipalArn` is **not** one of the signing roles (the function's role, and `WrappedSigning.AdditionalSigningRoleArns`, the Kubernetes role) |
| `SluisSigningRolePurposeOnly` | Deny | `*` | `kms:GenerateDataKeyPairWithoutPlaintext`, `kms:Decrypt` | `aws:PrincipalArn` is a signing role, and `kms:EncryptionContext:purpose` is not `sluis-signing` |
| `SluisSigningRoleContextKeysOnly` | Deny | `*` | the same two | a signing role, and `ForAnyValue:StringNotEquals kms:EncryptionContextKeys` `["purpose","alg","kid"]` |
| `SluisSigningRoleNothingElse` | Deny | `*` | `NotAction` the same two | a signing role |

### The statements to merge

```json
[
  {
    "Sid": "SluisSigningContextReserved", "Effect": "Deny", "Principal": {"AWS": "*"}, "Resource": "*",
    "Action": ["kms:Decrypt", "kms:Encrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:CreateGrant"],
    "Condition": {
      "StringEquals": {"kms:EncryptionContext:purpose": "sluis-signing"},
      "ArnNotEquals": {"aws:PrincipalArn": ["<the function role's ARN>", "<the Kubernetes role's ARN, if it signs>"]}
    }
  },
  {
    "Sid": "SluisSigningRolePurposeOnly", "Effect": "Deny", "Principal": {"AWS": "*"}, "Resource": "*",
    "Action": ["kms:GenerateDataKeyPairWithoutPlaintext", "kms:Decrypt"],
    "Condition": {
      "ArnEquals": {"aws:PrincipalArn": ["<the same signing role ARNs>"]},
      "StringNotEquals": {"kms:EncryptionContext:purpose": "sluis-signing"}
    }
  },
  {
    "Sid": "SluisSigningRoleContextKeysOnly", "Effect": "Deny", "Principal": {"AWS": "*"}, "Resource": "*",
    "Action": ["kms:GenerateDataKeyPairWithoutPlaintext", "kms:Decrypt"],
    "Condition": {
      "ArnEquals": {"aws:PrincipalArn": ["<the same signing role ARNs>"]},
      "ForAnyValue:StringNotEquals": {"kms:EncryptionContextKeys": ["purpose", "alg", "kid"]}
    }
  },
  {
    "Sid": "SluisSigningRoleNothingElse", "Effect": "Deny", "Principal": {"AWS": "*"}, "Resource": "*",
    "NotAction": ["kms:GenerateDataKeyPairWithoutPlaintext", "kms:Decrypt"],
    "Condition": {"ArnEquals": {"aws:PrincipalArn": ["<the same signing role ARNs>"]}}
  }
]
```
