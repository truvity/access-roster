# The Pulumi library

Source: `deploy/pulumi`. Identifiers: [Go packages](../../sdk/go/sluis.md). Decided in [ADR 0037](../../decisions/0037-one-process-everywhere.md).

| Component | Type token | Creates |
|---|---|---|
| `NewStorage` | `sluis:aws:Storage` | The blob bucket |
| `NewStates` | `sluis:aws:States` | One DynamoDB table per module ([ADR 0072](../../decisions/0072-storage-layout-v5-module-first.md)) |
| `NewLambda` | `sluis:aws:Lambda` | Function, role, HTTP API, signing key, schedules. The main path |
| `NewBackup` | `sluis:aws:Backup` | The [backup function](#backup), its role, aliases, schedules and alarms; optionally the archive bucket |
| `NewRestore` | `sluis:aws:Restore` | The [restore function](#restore): `backup.role: restore`, its role, two aliases, the resource policy and an alarm |
| `NewKubernetesIdentity` | `sluis:aws:KubernetesIdentity` | The EKS Pod Identity role of the one pod |

Pass the provider with `pulumi.Providers(p)`. `RenderPorts` and `RenderPortsYAML` render `ports:`.

```go
store, _ := sluispulumi.NewStorage(ctx, "acme", &sluispulumi.StorageArgs{BucketName: "acme-prod-sluis"}, pulumi.Providers(awsProvider))
states, _ := sluispulumi.NewStates(ctx, "acme", &sluispulumi.StatesArgs{Modules: sluispulumi.ModuleSet{Instance: "acme"}}, pulumi.Providers(awsProvider))
ids, _ := sluispulumi.NewKubernetesIdentity(ctx, "acme", &sluispulumi.KubernetesIdentityArgs{
	ClusterName: "acme", ClusterArn: clusterArn, AccountID: accountID,
	Namespace:              "sluis",
	PermissionsBoundaryArn: boundaryArn,
	ServiceAccount:         "sluis",
	Storage:                store.Grant(),
	State:                  states.Grant(),
}, pulumi.Providers(awsProvider))
```

## Storage

| `StorageArgs` | Default | Meaning |
|---|---|---|
| `BucketName` | Required without `Blobs` | Bucket name; global |
| `Blobs` | None | `ExternalBlobs` for an S3-compatible endpoint (R2). One of `BucketName` and `Blobs`; with `Blobs` no bucket is created and `Versioning`, `ProtectedPrefixes`, `Tags` are refused |
| `Versioning` | Off | S3 versioning |
| `ProtectedPrefixes` | None | `Prefix` and `AllowedPrincipalArns`: a bucket-policy Deny of writes under the prefix to every other principal ([truststore](#the-edge-modules)) |
| `Tags` | None | On the bucket |

| Detail | Behavior |
|---|---|
| Outputs | `BucketName`, `BucketArn` (empty with `Blobs`), `Grant()` |
| Bucket | Protected, AES256, public access blocked, non-TLS denied |
| Old sealer | Run `pulumi state unprotect <urn>` on `<name>-sealer-key` and `<name>-sealer-alias` before the first apply |

| `ExternalBlobs` | Meaning |
|---|---|
| `Bucket`, `Endpoint` (https), `Region` (default `auto`), `PathStyle`, `Prefix` | The store |
| `CredentialsRef` | Address `internal/<module>/<name>`, for example `internal/google/blobs-r2`, or `external/cloudflare/<preset>`. It names the secret, never holds it. Set this or `CredentialsPreset`, not both |
| `CredentialsRef: external/cloudflare/<preset>` | The credential the Cloudflare module rotates for an R2 preset of `Installation.Cloudflare.Presets`: the preset must be declared, have an `endpoint`, keep `store: external` and be at the blobs' `Endpoint`. Every function that has the blobs reads that one `cloudflare/v1` document (`SluisBlobCredentials`); none holds the minter. The Cloudflare function mints for its own blobs, so it starts before the first rotation. This is the form for an installation with module functions. The adapter reads the document again with a third of its time left and once after a 403, and keeps nothing on disk. Choose `lifetime` longer than `rotation` plus the schedule's tick and five minutes (for example `lifetime: 1h`, `rotation: 20m`, a tick of 15m). Rotate the preset once (the first tick, or Rotate on the console's Cloudflare page) before the other functions switch to the address |
| `CredentialsPreset` | A key of `Installation.Cloudflare.Presets` with an `endpoint` (R2): sluis mints the store's credentials in process and the document gets `ports.blob.s3.credentials.preset`. No parameter and no `SluisBlobCredentials` grant. It works where the one function holds the minter (presets rendered into it, as on Kubernetes or without module functions); with module functions the presets are the Cloudflare module's, no other function can mint, and the library refuses it and names the `CredentialsRef` to use. Exclusive with `CredentialsRef` |

| With `Blobs` | Behavior |
|---|---|
| Document | Writes `ports.blob` (`adapter: s3`). A document naming `ports.blob`, `adapters.blobs` or `endpoint` is refused |
| IAM | With `CredentialsRef`: `ssm:GetParameter` on `/sluis/<instance>/<CredentialsRef>`, decrypted through SSM with `ParameterKeyArn`. With `external/cloudflare/<preset>`: the same grant on `/sluis/<instance>/external/cloudflare/<preset>`, nothing else under `external/cloudflare/` and no minter parameter. With `CredentialsPreset`: none |
| Seed | With `CredentialsRef`, the `s3-credentials/v1` parameter, out of band ([blobs on R2](../../guides/sluis/operate/blobs-on-r2.md)) |

## State

One [DynamoDB table](storage-layout.md#dynamodb-the-dynamodb-state-index-and-trigger-adapter) per module ([ADR 0072](../../decisions/0072-storage-layout-v5-module-first.md)).

| `StatesArgs` | Default | Meaning |
|---|---|---|
| `Modules` | Required | `ModuleSet`: `Instance`; `Tables` overrides a name (default `sluis-<instance>-<module>`) |
| `Only` | Every module | The modules that get a table |
| `KeyArn` | None | Customer-managed key for every table; otherwise the AWS-owned key |
| `Tags` | None | On every table |

| Detail | Behavior |
|---|---|
| Outputs | `Tables`, `TableArns` (by module), `Grant()` |
| Table | Protected, deletion protection, on-demand, point-in-time recovery, TTL on `expires`; only `pk` and `sk` declared; no secondary index |
| Grant | A role gets the tables of the modules it hosts |
| Ports | `PortsArgs.Tables` renders `ports.dynamodb.tables`; the document needs `secrets.layout: v5` beside it |

## Kubernetes identity

One role for the one pod ([switch the serving pod role](../../guides/sluis/operate/switch-serving-pod-role.md)).

| `KubernetesIdentityArgs` | Default | Meaning |
|---|---|---|
| `ClusterName` | Required | EKS cluster |
| `ClusterArn`, `AccountID` | Required | Pin the trust policy to the cluster |
| `Namespace`, `ServiceAccount` | Required | The one ServiceAccount; it takes one association |
| `Region` | Provider's | On each association |
| `PermissionsBoundaryArn` | None | Boundary of the role |
| `RoleNamePrefix` | Component name | Role and managed policy are `<prefix>-sluis` |
| `Description` | Generated | Policy description; a change replaces the policy |
| `Instance`, `Region`, `ParameterKeyArn` | None | With `Instance`, the role has the module paths of the layout (`internal/<module>/*`, `external/<module>/*`) and `internal/config/*` (read) under `/sluis/<instance>/`; `Region` becomes required |
| `Storage` | Required | `Storage.Grant()` |
| `State` | None | `States.Grant()`; nil for the `legacy` store |
| `SigningKeyArns` | None | `SigningKeyArn`, `SigningKeyRS256Arn`: allows `kms:Sign`, `kms:GetPublicKey` |
| `WrappedSigningKeyArn` | None | Symmetric key for `kms-wrapped` ([signing on AWS](../../concepts/sluis/signing-on-aws.md)). List this role in `WrappedSigning.AdditionalSigningRoleArns` |
| Outputs | n/a | `RoleArn`, `RoleName` |

The role trusts `pods.eks.amazonaws.com` for this cluster and ServiceAccount.

| Sid | Actions | Resource |
|---|---|---|
| `SluisBlobs` | `s3:GetObject`, `PutObject`, `DeleteObject` | Bucket objects |
| `SluisBlobList` | `s3:ListBucket` | The bucket; without it a missing key reads 403, not 404 |
| `SluisSigning` | `kms:Sign`, `kms:GetPublicKey` | Signing keys |
| `SluisWrappedSigning` | `kms:GenerateDataKeyPairWithoutPlaintext`, `kms:Decrypt` | Symmetric key; only with `kms:EncryptionContext:purpose` = `sluis-signing` and no context keys besides `purpose`, `alg`, `kid` |
| `SluisState` | `dynamodb:GetItem`, `PutItem`, `UpdateItem`, `DeleteItem`, `Query`, `Scan`, `DescribeTable` | The module tables |
| `SluisStateKey` | `kms:Encrypt`, `Decrypt`, `GenerateDataKey`, `DescribeKey` | The table key, only through DynamoDB (`kms:ViaService`) |

## Backup

| `BackupArgs` (`BackupCommon`) | Default | Meaning |
|---|---|---|
| Function | n/a | The release zip as the [backup function](backup.md) on layout v5 ([ADR 0072](../../decisions/0072-storage-layout-v5-module-first.md)); the configuration layer holds one `sluis-backup/v1` document |
| `Region`, `AccountID`, `Instance` | Required | Name the resources; the archive path is `backup/<instance>/` |
| `Package`, `PackageSHA256`, `PackageVersion`, `Artifacts`, `Release` | As `LambdaArgs` | The release zip, byte for byte |
| `Storage`, `BlobBucketName`, `BlobPrefix` | Required | The blob store: `ports.blob`. `BlobBucketName` is not needed with `Storage.External` |
| `State`, `TableNames` | Required | `States.Grant()` with all six tables; `ports.dynamodb.tables` |
| `ParameterKeyArn` (**required**), `MinterRefs` | `ParameterKeyArn`: none, and the plan is refused without it | `secrets.kmsKeyId`, and the key of the restore identity: a SecureString left to SSM would be encrypted with the AWS-managed key. `MinterRefs`: the Cloudflare minter parameters the backup role reads, read only |
| `ArchiveKeyAlias` | None | Deprecated. Backups are age-encrypted (format v2) and no role holds a KMS grant for the archive. While set it is held to an `alias/<name>`, rendered as `backup.key` for a binary of format v1, and `ArchiveKeyArn` names the key behind it |
| `ExtraRecipients` | None | `BackupArgs` only. Further age recipients (`age1...`) every backup is encrypted to, after the installation's generated one: an offline break-glass key is recommended. Each is parsed as an age X25519 recipient; an invalid one is refused, a repeat is dropped |
| `Archive` | Required | `Bucket`, `Prefix`, `Region`, `AccountID`, `Versioned` (true), `SSEKeyArn`, `RestoreRoleArn`, `Create` |
| `Archive.Create` | nil | `ArchiveBucketArgs`: `Mode` (**required**: `GOVERNANCE`, or `COMPLIANCE` with `AcknowledgeCompliance`; empty was `GOVERNANCE` and is refused, because COMPLIANCE cannot be undone and a default must not move the lock of a bucket that exists), `RetentionDays` (`Retention.MaxAge` in days), `Tags` |
| `Archive.BreakglassRoleArns` | **Required** with `Archive.Create` | Role ARNs (a `*` only in the hash of an SSO role's name) that alone may bypass the lock. The bucket's policy gets `SluisArchiveLockBreakglassOnly`: a Deny of `s3:BypassGovernanceRetention`, `s3:DeleteObjectVersion` and `s3:PutBucketObjectLockConfiguration` to every other principal (`ArchiveBucketGuardStatement`). Given for an existing bucket, the same statement is added to the `ArchiveBucketPolicy` output for the bucket's owner to apply. Include the role that applies the stack |
| `Retention` | 7; 720h | `Keep`, `MaxAge`: `backup.retention`. An Object Lock longer than `MaxAge` is refused |
| `AuditQueueURL` | None | `adapters.audit` sqs; without it the `log` adapter |
| `FunctionName`, `Function`, `LogRetentionDays` | `sluis-<instance>-backup`; 512 MB, 900 s; 30 | `Function.TimeoutSeconds` is 60 to 900 |
| `Schedule` | `cron(0 2 * * ? *)`; false | `Daily`, `Paused`. `ResumeRate` is deprecated and ignored: the `<function>-resume` schedule is gone (a run of format 2 does not pause), and an apply deletes it |
| `AlarmActionArns`, `PermissionsBoundaryArn`, `Tags` | None | Notified by the alarms; boundary of the roles |
| `Telemetry`, `AdditionalWebIdentityAudiences`, `CodeSigningConfigArn` | None | As `LambdaArgs`: the telemetry layer and its extra audiences (only with `Telemetry`), and the code signing configuration |

| Output | Meaning |
|---|---|
| `FunctionArn`, `FunctionName`, `RoleArn`, `RoleName`, `ConfigLayerArn` | Function, role and layer |
| `LiveAliasArn`, `AliasArns` | `live`, which the schedules invoke, and `live-console`, `live-admin`, `live-breakglass`; the alias is the caller class of a [module call](backup.md#calls) |
| `SchedulerRoleArn`, `ScheduleNames`, `ScheduleDLQArn` | `<function>-daily` sends `{"kind":"backup"}`; undelivered events go to the queue |
| `ArchiveBucketName`, `ArchiveBucketArn` | The archive |
| `ArchiveKeyArn` | Deprecated: the key behind `ArchiveKeyAlias`, empty when it is not set |
| `RestoreRecipient` | The `age1...` recipient of the installation's generated restore keypair. Public |
| `Recipients` | Every recipient of `backup.recipients`: `RestoreRecipient`, then `ExtraRecipients` |
| `RestoreIdentityParameter` | `/sluis/<instance>/internal/backup/restore-identity`, the SecureString parameter that holds the age identity |
| `ArchiveBucketPolicy` | The policy a bucket owner in another account applies, from `ArchiveBucketPolicyStatements` |
| `AlarmNames` | The three alarms below |

| Alarm | Fires when |
|---|---|
| `<function>-no-backup-36h` | The log line `a backup was written` is absent for 36 hourly periods; missing data counts |
| `<function>-failed-run` | The function's `Errors` is at least 1 in five minutes |
| `<function>-schedule-dlq` | The dead-letter queue holds a message |

| Backup role grant | Actions | Resource |
|---|---|---|
| `SluisTableBackup` | `GetItem`, `PutItem`, `UpdateItem`, `DeleteItem`, `Query`, `Scan`, `DescribeTable` | The backup table |
| `SluisCrossTable`, `…Parameters`, `…Blobs`, `…BlobList` (one statement per kind, the five modules in its resource list) | Read: `GetItem`, `Query`, `Scan`; `ssm:GetParameter`; `s3:GetObject` and the prefix's `ListBucket` | The other five modules' tables, `internal/<module>/*`, `external/<module>/*`, `<module>/` |
| `SluisCrossParametersList` | `ssm:GetParametersByPath` | `internal/*` and `external/*` of the instance, never the namespace roots: the export lists each module's parameters before it reads them by name. A listing decrypts nothing |
| `SluisMaintenanceDeny` | Deny `PutItem`, `UpdateItem`, `DeleteItem`, `BatchWriteItem`, `TransactWriteItems` | Every table, when the first key is `maintenance`. The role reads the flag and never writes it |
| `SluisArchiveObjects` | `s3:GetObject`, `PutObject`, `DeleteObject`, and `GetObjectVersion` on a versioned bucket | `<bucket>/<prefix>backup/<instance>/*` |
| `SluisArchiveList` | `s3:ListBucket`, and `ListBucketVersions` on a versioned bucket | The bucket, `s3:prefix` `<prefix>backup/<instance>/*` |
| `SluisArchiveSSEKey` | `kms:Decrypt`, `GenerateDataKey` | `SSEKeyArn`, through S3 only |
| `SluisDenyRestoreIdentity` | Deny `ssm:*` | The restore identity parameter. The role hosts the backup module, whose namespace the identity is in |
| `SluisDenyRestoreIdentityKey` | Deny `kms:Decrypt` | Any key, when the encryption context `PARAMETER_ARN` is the identity parameter: closes `GetParametersByPath`, which is authorised on the path |

### Keys

| Detail | Behavior |
|---|---|
| Format | v2 encrypts each backup with [age](https://age-encryption.org) to `backup.recipients`. The backup role holds no key that opens one |
| Keypair | `NewBackup` makes a 32-byte `random.RandomBytes` seed (secret in state, never rotated by an apply) and derives the X25519 identity and recipient from it |
| Recipients | The generated recipient, then `ExtraRecipients`, in the backup document. Keep an offline `ExtraRecipients` identity: it opens backups when the installation is gone |
| Identity | `AGE-SECRET-KEY-1...` in the byte codec (`{"value":"<base64>"}`), a SecureString at `/sluis/<instance>/internal/backup/restore-identity` under `ParameterKeyArn`. The restore document names it with `backup.identity: restore-identity` |
| Readers | The restore role, and the deployer: `SluisKeyAdminReads` lets `KeyPolicyOptions.Admins` decrypt it, as the provider does after create and on every refresh. The backup role is denied the parameter and its decryption (`SluisDenyRestoreIdentity`, `SluisDenyRestoreIdentityKey`); `SluisKeyPolicyStatements` adds `SluisKeyDenyRestoreIdentity` |
| Adoption | The parameter has `overwrite: true`: an apply whose earlier create succeeded in AWS adopts it, with the same value from the seed in state |
| Break-glass | `age-keygen -o breakglass.txt` offline; `age-keygen -y breakglass.txt` prints the recipient for `ExtraRecipients` ([guide](../../guides/sluis/operate/back-up-on-layout-v5.md)) |
| Rotation | `pulumi up --replace` on `<name>-restore-identity-seed` leaves older backups readable by an `ExtraRecipients` identity only |
| Deprecated | `KeyPolicyOptions` and `KeyPolicyArgs` `BackupArchive` and `RestoreArchive`, and `ArchiveGrant.KeyArn`, are accepted and add nothing |

| Helper | Renders |
|---|---|
| `BackupRoleStatements(env, ArchiveGrant)` | The role above, for an estate that builds its own |
| `ArchiveBucketPolicyStatements(grant, backupRoleArn, restoreRoleArn)` | The bucket policy for a bucket in another account; its owner also names the roles in the bucket key's policy |

### Restore

| `RestoreArgs` | Default | Meaning |
|---|---|---|
| `BackupCommon` | As `BackupArgs` | The same installation and archive. `NewBackup` of the same instance must be in the stack: it creates the restore identity this function reads. `Archive.Create` is refused: `NewBackup` makes the bucket. `FunctionName` defaults to `sluis-<instance>-restore` |
| `RestoreInvokers` | Required | `AdminRoleArns` and `BreakglassRoleArns`, at least one role each. A wildcard, an account root, a user, or a role in both lists is refused |
| `Function.TimeoutSeconds` | 900 | At least 180, twice `RestoreMargin` (90 s): the slice a restore keeps back before it pauses and continues itself |
| `Recipients` | None | `backup.recipients`: pass `Backup.Recipients` of the same instance. A restore compares each backup's sidecar with them, and an unverified restore (`allowUnverified`) is refused without them |
| `Verify` | None | `backup.verify` ([provenance](backup.md#provenance)): `Query` (https, or http on loopback), `TokenFile` (a file in the function's environment holding the query service's bearer token; the library provisions none), `Profile`, and one of `Observer` (the id the audit writer stamps on the backup function's records) and `AnyObserver`. Held to the restore's own rules at plan. Unset, every restore needs `allowUnverified` |

| Detail | Behavior |
|---|---|
| Function | The release zip with a document of `backup.role: restore`. No reserved concurrency, because `lease.restore:run` allows one restore at a time. No schedule |
| Aliases | `live-admin` and `live-breakglass` only. Both are asynchronous without retry |
| Resource policy | One `lambda:InvokeFunction` permission per invoker, on the alias of its class: administrators on `live-admin`, break-glass roles on `live-breakglass`. No unqualified permission, no service principal. Identity policies of other principals must not grant the invoke |
| Alarm | `<function>-invoked`: `Invocations` at least 1 in a minute |
| Policy size | The role's inline policy is near IAM's 10,240 characters; a long instance name can exceed it. The tests hold it on realistic ARNs |
| Outputs | `FunctionArn`, `FunctionName`, `RoleArn`, `RoleName`, `ConfigLayerArn`, `AliasArns`, `IdentityParameter`, `ArchiveKeyArn` (deprecated), `AlarmNames` |

| Restore role grant | Actions | Resource |
|---|---|---|
| `SluisTableBackup` | Table read and write | The backup table: `rec.backup.restore.*`, `lease.restore:*` and the `maintenance` flag |
| `SluisCrossTable`, `…Parameters`, `…Blobs`, `…BlobList` (one statement per kind, the five modules in its resource list) | Table read and write; `ssm:GetParameter`, `PutParameter`, `DeleteParameter`; `s3:GetObject`, `PutObject`, `DeleteObject` | The other five modules' tables, `internal/<module>/*`, `external/<module>/*`, `<module>/` prefixes, and the key through SSM |
| `SluisCrossCloudflareMinter` | `ssm:GetParameter` | The `MinterRefs` parameters; the backup role only, never the issuer (it asks the cloudflare function to mint) or a module role |
| `SluisArchiveObjects`, `SluisArchiveList` | `s3:GetObject`, `GetObjectVersion`; `ListBucket`, `ListBucketVersions` | `<bucket>/<prefix>backup/<instance>/*`. No put, no delete |
| `SluisRestoreIdentity`, `SluisRestoreIdentityKey` | `ssm:GetParameter`; `kms:Decrypt` through SSM | The restore identity parameter `internal/backup/restore-identity` and its encryption context. The only function role that reads it; the deployer reads it back through `SluisKeyAdminReads` |
| `SluisRestoreSelf` | `lambda:InvokeFunction` | Its own two aliases: a paused restore continues through the ARN it was invoked through |
| Maintenance flag | n/a | No `SluisMaintenanceDeny`: this role alone writes the flag in every table. `RestoreRoleStatements(env, grant, selfArns)` renders it |

## Ports configuration

`RenderPorts` never renders `create`, writes only the blob without `Tables` and refuses any `Adapter` but `dynamodb`.

```go
y, _ := sluispulumi.RenderPortsYAML(sluispulumi.PortsArgs{BucketName: "acme-prod-sluis", Region: "eu-west-1",
	Tables: map[sluispulumi.Module]string{sluispulumi.ModuleOIDC: "sluis-acme-oidc", sluispulumi.ModuleGoogle: "sluis-acme-google"}})
```

```yaml
ports:
  adapter: dynamodb
  blob:
    adapter: s3
    s3: {bucket: acme-prod-sluis, region: eu-west-1}
  dynamodb:
    region: eu-west-1
    tables: {google: sluis-acme-google, oidc: sluis-acme-oidc}
```

## Lambda

[AWS Lambda](lambda.md), [the concept](../../concepts/sluis/lambda.md).

```go
l, _ := sluispulumi.NewLambda(ctx, "access", &sluispulumi.LambdaArgs{
	Region: "eu-central-1", AccountID: accountID,
	Instance:      "acme",    // the SSM root /sluis/acme
	Package:       "dist/sluis-issuer_1.77.1_linux_arm64.zip", // or an https URL
	PackageSHA256: "<the release's digest, pinned here>",
	Installation:  installation, // *sluisconfig.Installation: the library renders both documents from it
	Storage:       store.Grant(),
	State:         states.Grant(),
	Audit: &sluispulumi.AuditArgs{
		WriterPackage: "dist/audit-writer-lambda_<version>_linux_arm64.zip", WriterPackageSHA256: "<its digest>",
		CatalogueDir: "dist/sluis-audit-catalogue", // the release's sluis-audit-catalogue bundle, unpacked
	},
	Schedule: sluispulumi.ScheduleArgs{GitHubOrgs: []string{"acme"}, SlackWorkspaces: []string{"T0ACME"}},
}, pulumi.Providers(awsProvider))
```

| Rule | Behavior |
|---|---|
| Package | Deployed byte for byte from a path or https URL. `PackageSHA256` is required and checked; pin it in source. Library minor or newer (1.63) |
| Configuration | Immutable layer `<prefix>-config` at `/opt/sluis`, rendered from `Installation`, loader-checked ([layer](lambda.md#configuration-is-a-layer)). A change publishes a new version |
| Endpoints | Refused unless `AllowEndpoints` |

### Inputs (`LambdaArgs`)

| Field | Default | Meaning |
|---|---|---|
| `Region`, `AccountID` | Required | Name the SSM parameters and function in the role policy |
| `Instance` | Required | Lower-case letters, digits, dashes; not `private` or `export`. SSM root `/sluis/<instance>` |
| `Package`, `PackageSHA256`, `PackageVersion` | Required, required, from the file name | Zip, pinned digest, release when the name does not say |
| `Installation` | Required without `Config` | The [installation document](installation-document.md). Rendered like `sluisctl render`; the library fills shape `lambda`, `Instance`, `Region`, `AccountID` and the function name when absent and refuses disagreement |
| `Config`, `Policy`, `PolicyPath` | Deprecated | Service document; policy or a layer directory (one of the last two). Removed after one minor; `NewLambda` warns |
| `AllowEndpoints` | false | LocalStack tests only; an R2 preset's endpoint needs no flag |
| `Storage`, `State` | Required | The grants; `State` is `States.Grant()` with the table of every module a function hosts |
| `TableNames` | `sluis-<instance>-<module>` | Table name per module in `ports.dynamodb.tables`; the same map as `StatesArgs.Modules.Tables` |
| `Artifacts`, `Release` | Unset | [Artifacts bucket](#artifacts-bucket) |
| `Audit` | Install | [Audit](#audit). Needs `Installation` |
| `AuditQueueArn` | None | Deprecated; exclusive with `Audit`. Required with `Config` |
| `ParameterKeyArn` | **Required**, unless `Keys.Secrets` names the key by alias | Customer key for SecureStrings, written as `secrets.kmsKeyId` in every function's document (a module document written by the estate in `Modules[<role>].Document` must name the same key, compared as text (the alias for `Keys.Secrets`, the ARN for `ParameterKeyArn`), or it is refused); another is refused. The role may use it through SSM only. With neither, the library refuses to build: the state secret, the recovery password and every parameter the services write (GitHub and Slack apps, Google keys, the sign-in client) would be encrypted with the AWS-managed key `alias/aws/ssm`, which every role with `ssm:GetParameter` on them can decrypt |
| `KeyAdmins` | Required while the library creates a KMS key (`Keys` nil, and `WrappedSigning` without `KeyArn`); refused with `Keys` | Deprecated with the keys it is for. Role ARNs (a `*` only in the hash of an SSO role's name) that alone hold the control plane of the library-created keys: key policy, grants, aliases, disabling and deletion. The keys carry a policy in which the root enables IAM for the key's use and upkeep and `SluisKeyControlPlaneAdminsOnly` denies the control plane to every other principal. Include the role that applies the stack |
| `CodeSigningConfigArn` | None | A Lambda code signing configuration (`artifact.NewCodeSigningConfig`) every function the library makes is put under. The release zips are not AWS Signer-signed: under an enforcing configuration the estate signs them first, or sets the configuration to warn |
| `Keys` | nil | [Keys the estate supplies](#keys-the-estate-supplies). Exclusive with the four deprecated key inputs |
| `SigningKeyAlias` | None, required unless `Keys` or `WrappedSigning` is set | Deprecated: ES384 key alias, such as `alias/sluis-<instance>-sign` |
| `SigningKeyRS256Alias`, `DisableSigningKeyRS256` | None, required unless `Keys`, `WrappedSigning` or `DisableSigningKeyRS256` is set; false | Deprecated: RSA key alias, such as `alias/sluis-<instance>-sign-rs256`; created unless disabled |
| `WrappedSigning` | nil | Deprecated: `KeyArn` (unset creates one), `KeyAlias` (none; required without `KeyArn`, such as `alias/sluis-<instance>-wrapped`). The asymmetric keys are not declared; `signingKey.kms` beside it is refused |
| `VerifyOnly` | None | `[]VerifyOnlyKeyArgs` of an earlier signer: `PEM` (one public key or certificate: ECDSA on P-384, or RSA of 2048 bits or more), `KeyID` (default RFC 7638 thumbprint), `Alg`, `Until` (required). Written to `/opt/sluis/verify-keys/<index>.pem` and `signingKey.verifyOnly`. Private keys, EC keys other than P-384, RSA keys under 2048 bits, duplicates, a mismatched `Alg` and zero `Until` are refused |
| `Recovery` | Enabled | `RecoveryArgs.Enabled` (`*bool`) writes `recovery.enabled`; the password parameter exists either way ([recovery](../../guides/sluis/operate/recover-on-lambda.md)) |
| `FunctionNamePrefix` | `sluis` | Names `<prefix>-scheduler`, `<prefix>-config` and the function default |
| `FunctionName` | `sluis-<instance>-issuer` | Function, role, policy and log group. `aws.functions` overrides it. A name kept from `sluis` or `sluis-http` replaces nothing (see the CHANGELOG upgrade note) |
| `Function` | 512 MB; 300 s; unreserved | `FunctionArgs`: `MemoryMB`, `TimeoutSeconds`, `ReservedConcurrency` (`*int`, at least 1) |
| `Modules` | None | `ModuleArgs` by `cloudflare`, `github`, `google`, `outline` or `slack`: `FunctionName` (default `sluis-<instance>-<module>`), `Package`, `PackageSHA256`, `MemoryMB`, `TimeoutSeconds` (default `Function`'s), `ReservedConcurrency`, `Document`. Every module function exists with or without an entry, except `outline`, which exists only with an outline document (the installation's `controllers.outline`). |
| `BackupFunctionName`, `RestoreFunctionName` | `sluis-<instance>-backup`, `-restore` | The names the issuer's role and the key policy use for the [backup](#backup) and [restore](#restore) functions |
| `TransitionRoles` | None | `Role` and `OldName`: an old IAM role name kept as a further principal of the renamed role in the key policy and the audit queue's policy. Remove it once nothing runs under the old name |
| `Function.ReservedConcurrency` | nil | A ceiling on concurrent environments. It costs nothing and is not provisioned concurrency. It bounds a [cold-start herd](../../guides/sluis/operate/survive-a-cold-start-herd.md). A cap set by hand is removed by the next apply unless set here |
| `LogRetentionDays` | 30 | Function log group |
| `AccessLogs` | nil (off) | `RetentionDays` (7). Declares log group `/aws/apigateway/<FunctionName>` and `$default` access logs: `requestTime`, `requestId`, `httpMethod`, `path`, `status`, `responseLatency`, `integrationLatency`. The query string, headers, address and identity are never logged. The applying principal needs `logs:CreateLogDelivery`, `logs:PutResourcePolicy` and related actions |
| `PermissionsBoundaryArn` | None | Boundary of the role and the scheduler's |
| `API.DomainName`, `.CertificateArn`, `.TruststorePEM`, `.TruststoreBucketName` | Deprecated | All four together keep the mutual-TLS domain with a warning. Move to the [edge module](#the-edge-modules) ([cutover](../../guides/sluis/migrate/move-the-domain-to-the-edge-module.md)) |
| `API.KeepDefaultEndpoint` | false | Keeps the `execute-api` endpoint for the acceptance suite; turn it off after, it bypasses the client certificate |
| `Schedule.GitHubOrgs`, `.SlackWorkspaces`, `.OutlineWorkspaces` | None | Targets, one schedule each. `OutlineWorkspaces` needs the outline function |
| `Schedule.OutlineRate` | `rate(2 minutes)` | The Outline workspaces' schedule |
| `Schedule.Rate` | `rate(5 minutes)` | EventBridge Scheduler expression |
| `Schedule.Paused`, `DirectoryRefresh.Paused` | false | Declares the schedules `DISABLED`, keeping roles and grants. `Paused` with `Disabled` is refused |
| `DirectoryRefresh.Rate`, `.Disabled` | `rate(15 minutes)`, false | Invokes `{"kind":"refresh"}` |
| `IssuerClients.Rate`, `.Disabled`, `.Paused` | `rate(15 minutes)`, false, false | With module functions: invokes the issuer with `{"kind":"clients"}`, the pass that settles the clients' generated secrets. `Paused` with `Disabled` is refused |
| `CloudflareRotation.Interval` (or `.Rate`), `.Disabled`, `.Paused` | 15 minutes (`rate(15 minutes)`), false, false | The tick, in whole minutes; `Interval` and `Rate` are exclusive. A credential rotates up to one tick after its `rotation` age, so every preset must satisfy `rotation + tick + 5m < lifetime` (checked for `Interval` and `rate(...)`, at load). Invokes `{"kind":"cloudflare"}`. Exists when `Installation.Cloudflare` declares any preset, `store: none` included: the pass rotates the stored presets and deletes every preset's expired tokens. A `store: none` preset gets no margin check and no `cloudflare.tick`. Declaring presets also grants SSM read on `internal/cloudflare/*`, read and write on `internal/cloudflare-minted/*`, write on `external/cloudflare/*` ([Cloudflare tokens](../../guides/sluis/cloudflare-tokens.md)) |
| `Check` | on (nil) | A post-deploy `aws.lambda.Invocation` of the live alias with `{"kind":"check"}`, after the function, its role policy and the parameters the stack writes exist. A declared secret that is missing, empty or malformed fails `pulumi up` with `check: N of M declared secrets are missing or invalid`, naming each address. Runs again when the function version or the declared names change. `false` leaves it out, for a CI step |
| `WebIdentityAudience` | Any | Restricts the audience of the role's web identity token |
| `AdditionalWebIdentityAudiences` | None | Extra exact audiences after it. Any code under the role can mint them. Empty, duplicate, or with empty `WebIdentityAudience`: refused |
| `Telemetry.LayerArn`, `.Env` | nil | The `otlp-lambda` layer; `Env` accepts `OTEL_*`, `OPENTELEMETRY_*`, the layer's `SLUIS_*` settings (the deprecated `ACCESS_ROSTER_*` prefix too), `AWS_LAMBDA_EXEC_WRAPPER` and nothing else. `OTEL_SERVICE_NAME` defaults to the function name. The layer's token comes from an issuer: one other than the function it observes keeps telemetry flowing while that function is saturated. The function drops what the layer refuses |
| `Tags` | None | On everything that takes tags |


<a id="layouts"></a>

### Module roles

| Detail | Behavior |
|---|---|
| Role grants | `ModuleRoleStatements` of the hosted modules (`oidc`, `github`, `slack`, `google`, `outline` with its document, and `cloudflare` with presets): their tables, `internal/<module>`, `external/<module>`, `<module>/` blob prefixes; `SluisMaintenanceDeny` on their tables; the `oidc` host is denied the recovery and conformance passwords (`SluisDenyPasswords`, `SluisDenyPasswordsKey`) |
| Parameters written | `internal/oidc/state-secret`, `recovery-password` and `recovery-verifier`; with `conformance.enabled`, also `conformance-password` and `conformance-verifier`. Each is the secret store's document (`{"value":"<base64>"}`). A verifier is derived from its password under a random salt kept with it ([ADR 0076](../../decisions/0076-password-sign-in-is-srp-for-recovery-and-conformance-only.md)) |
| Service document | `secrets.layout: v5` and `ports.dynamodb.tables`. A blob `CredentialsRef` is `internal/<module>/<name>`; `internal/google/<name>` is read by every process |
| Blobs from a preset | No role other than backup and the Cloudflare function reads the minter. A store whose credentials a preset rotates is read from `external/cloudflare/<preset>` (`CredentialsRef`) |
| Needs | `State.Tables` (`States.Grant()`) for the hosted modules |
| Removed | `Layout`, `Compat`, `MigrationRoleArn`, `NewState` and the legacy table: [upgrade to v1.77.1](../../guides/sluis/upgrade/v1.77.1.md) |

### Outputs

| Output | Meaning |
|---|---|
| `SigningKeyArn`, `SigningKeyID`, `SigningKeyAlias` | ES384 signing key |
| `SigningKeyRS256Arn`, `SigningKeyRS256ID`, `SigningKeyRS256Alias` | RS256 key; empty when disabled |
| `WrappedSigningKeyArn`, `WrappedSigningKeyAlias` | Symmetric key of `WrappedSigning` |
| `CodeSha256Matches` | Lambda's code hash equals the verified zip |
| `FunctionArn`, `FunctionName`, `RoleArn`, `RoleName` | Function and role |
| `AccessLogGroupName` | Empty without `AccessLogs` |
| `APIID`, `APIStageName`, `APIURL` | HTTP API; `APIURL` answers only with `KeepDefaultEndpoint`. `FrontDoor()` returns the first two and the component name |
| `DomainTarget`, `DomainHostedZoneID`, `TruststoreBucketName`, `TruststoreURI` | Empty unless the deprecated `API.DomainName` is set |
| `SchedulerRoleArn`, `ScheduleNames` | Scheduler role and schedules |
| `LiveAliasArn`, `LiveVersion` | Alias `live` and its version |
| `ConfigLayerArn` | Configuration layer version |
| `DeclaredParameters` | SSM names the documents declare, below the root, sorted; set whether or not `Check` is on |
| `StateSecretParameter`, `RecoveryPasswordParameter` | SSM parameters of the OAuth-state secret and the recovery password, `internal/oidc/...` |
| `RecoveryVerifierParameter`, `ConformancePasswordParameter` | The recovery account's SRP credential, and the conformance password with `conformance.enabled` (empty otherwise) |
| `Audit` | `*auditpulumi.Audit` the library installed; nil with `Use`, `Enabled: false` or `AuditQueueArn` |
| `AuditQueueURL`, `AuditQueueArn` | The publish queue; empty when audit is off |

### Artifacts bucket

`Artifacts` uploads the verified zip as is to a versioned bucket; function and layer use that object version.

| Input | Default | Meaning |
|---|---|---|
| `Artifacts.Bucket` | Unset (direct upload) | Must be versioned, else the apply fails |
| `Artifacts.Prefix` | `sluis/` | Keys are `<prefix><version>/<sha256>-<file name>` |
| `Release.ResolveChecksums` | false | Reads an empty `PackageSHA256` from `<BaseURL>/v<version>/checksums.txt` **after verifying it** against `checksums.txt.sigstore.json` beside it (sigstore-go): the certificate must be Fulcio's, issued by GitHub's OIDC issuer to the release workflow of `Release.SignerRepository` (default `truvity/sluis`) at the tag of that release, with a certificate timestamp and a Rekor entry; the same identity `hack/release-verify.sh` pins with cosign. A mirror carries the bundle byte for byte. Needs Sigstore's trusted root (TUF) at deploy time |
| `Release.TrustedRootJSON` | none | A pre-fetched Sigstore `trusted_root.json` to check the signature against, for a mirrored or air-gapped estate; take it from a verified source, never from the release's own mirror. Empty fetches the public-good root through TUF |
| `Release.UnverifiedChecksums` | false | Reads `checksums.txt` without checking its signature: the digest then proves only that the download is what the release page says. For an estate that cannot reach the trusted root; prefer a `PackageSHA256` taken from `hack/release-verify.sh` |
| `Release.Version` | From the file name | Names the release when `Package` is empty; `(devel)` is refused |
| `Release.BaseURL` | Project GitHub releases | For a mirror |

| Behavior | Rule |
|---|---|
| `Package` empty | Deploys the library's own release from `<BaseURL>/v<version>/sluis-issuer_<version>_linux_arm64.zip` (`NewBackup` and `NewRestore`: `sluis-backup_<version>_linux_arm64.zip`). A library at version X expects release X's zips. A pinned digest wins. `(devel)`, pseudo-versions and replaced modules are refused |
| Cache | `os.UserCacheDir()/sluis/artifacts`; `GITHUB_TOKEN` goes to github.com |

### Audit

`LambdaArgs.Audit` (`AuditArgs`) chooses where records go; a document naming another adapter is refused.

| `Audit` | The library |
|---|---|
| Unset | Installs audit beside the function with `github.com/truvity/sluis/audit/deploy/pulumi` at the same release, named `audit-<instance>` (`Name`). The function is the queue's only sender |
| `Use: &AuditUse{QueueURL, QueueArn}` | Sends to an existing installation. The URL is known when the program runs and in the function's region; `QueueArn` defaults to the URL's ARN |
| `Enabled: &false` | Installs nothing and grants no queue; the `log` adapter writes records to the log only |

| Install input | Meaning |
|---|---|
| `WriterPackage`, `WriterPackageSHA256` | Audit release `audit-writer-lambda_<version>_linux_arm64.zip` and digest; `Guards` holds it to the library release. Required |
| `CatalogueDir` | Directory the release's `sluis-audit-catalogue_<version>.tar.gz` unpacks to. Required. It travels in the writer's layer, and a catalogue version bump redeploys the writer |
| `Profiles` | Destination to framework profiles. Default `security: [history]` (`DefaultAuditProfiles`), preset `operational`: writer, archive, deduplication and queue intake, no notary, seal key, alarm or Object Lock. Others need `Presets` |
| `DeploymentYAML` | The whole deployment document. Exclusive with `Profiles` |
| `Notary`, `Keys`, `Alerts`, `Telemetry`, `Observe` | Passed through above operational |
| `Presets`, `AuditPreset` | One store per preset; never the blob bucket |

Missing inputs are refused before anything is created. A preset store is one of:

| Store | Behavior |
|---|---|
| AWS bucket created (`Create: true`) | Named `<name>-<account>-<region>-<preset>` unless `Bucket` is set; optional `Prefix`; `KeyAlias` is looked up, never created. SSE-S3 without `Keys.Archive` (`Archive.Encryption`: `kms`, `s3`, `aws-managed`). Object Lock (`ObjectLockMode`, `AcknowledgeCompliance`, `DefaultRetentionDays`) only for the attested preset |
| Existing AWS bucket (`Create: false`) | Grants only |
| S3-compatible (`Endpoint`) | No bucket created; `Bucket` required. Credentials come from the state store at `CredentialsAddress` (default `internal/archive/<preset>`), written by an operator, or, with `CredentialsRef: external/cloudflare/<preset>` and `Sluis{Root, KeyArn}`, are the R2 credentials a sluis installation rotates, granted as that one parameter. No Object Lock. `ReuseBlobStore` takes `Endpoint`, `Region`, `PathStyle` from `StorageArgs.Blobs`; naming the blob bucket is refused |

To adopt an existing audit stack, import it under the new component ([resource names](../../guides/audit/operate/archive-on-r2.md)).

### Keys the estate supplies

`LambdaArgs.Keys` (`KeysArgs`) takes aliases of symmetric keys you own; the library creates none, and the key policy must admit the function's role. A document naming `keys` is refused. To adopt library-created keys, supply their aliases and `pulumi state delete` the old `kms.Key` resources after unprotecting ([steps](../../guides/sluis/migrate/supply-your-own-signing-keys.md)).

| `Keys` field | Grant |
|---|---|
| `Sign` (required) | `kms:Encrypt`, `Decrypt`, `GenerateDataKey` with context `{instance: <Instance>, purpose: sign}` and no other context key. The runtime wraps ring key pairs locally; no `kms:Sign` |
| `Secrets` (optional) | The same actions through SSM only (`kms:ViaService` `ssm.<region>.amazonaws.com`), for the installation's parameters (`kms:EncryptionContext:PARAMETER_ARN` StringLike `…:parameter/sluis/<instance>/*`). Written as `secrets.kmsKeyId`, and set as `KeyId` on the parameters the library creates (the state secret, the recovery password); exclusive with `ParameterKeyArn` |
| Alias form | `alias/<name>` of a customer key. An ARN, a key id or `alias/aws/…` is refused. Re-pointing an alias moves the function at the next apply |
| `LegacySigningContext` (nil is true) | Also keeps `GenerateDataKeyPair` and `Decrypt` on `Sign` under `purpose=sluis-signing` for older ring entries (`WrappedKeyPolicyStatements` belongs in the key policy). Set false after the ring rotates |
| `RekeyOperatorStatements(region, account, instance, keyArn)` | For the role that runs [`sluis secrets rekey`](secrets.md#one-key): `ssm:DescribeParameters` on `*`, `kms:DescribeKey` on the account's keys in the region, `ssm:GetParameters` and `ssm:PutParameter` on `/sluis/<instance>/*`, and the `Secrets` key's grant above. `OperatorAuditStatements(queueArn)` adds `sqs:SendMessage` for its audit record |
| `SluisKeyPolicyStatements(KeyPolicyArgs)` | The statements of the shared key's policy, each `SluisKey…` Sid: a statement per function role (its hosted modules' parameters, through SSM), backup read-all and restore write-all, `external/*` for the External Secrets readers, admin seeds and reads, breakglass, and `{instance, purpose: sign}` for the roles that host `oidc` with three denies that hold the purpose to them. No catch-all deny on a use of the key. It ends with the key's control plane: `SluisKeyControlPlaneAdmins` allows `kms:PutKeyPolicy`, `kms:CreateGrant`, `kms:ScheduleKeyDeletion`, `kms:DisableKey`, `kms:RevokeGrant`, `kms:CreateAlias`, `kms:UpdateAlias` and `kms:DeleteAlias` to `KeyAdmins` and `Breakglass`, and `SluisKeyControlPlaneAdminsOnly` denies them to every other principal (AWS services acting on their own excepted). **`KeyAdmins` or `Breakglass` is required** (role ARNs, a `*` only in the hash of an SSO role's name: `CheckKeyAdmin`; `Admins` and `Breakglass` are held to the same rule); include the role that applies the stack. The estate's own root statement should delegate the upkeep (`kms:Describe*`, tags, rotation) and no longer `kms:*`. Concatenate your own statements and pass the lists to `KeyPolicyDocument`, which refuses a repeated Sid and a policy over 32 KiB |

| `SluisKey…` Sid | Principals | Grants, through SSM unless said otherwise |
|---|---|---|
| `SluisKeyRole<Role>` | each function role | `Encrypt`, `Decrypt`, `GenerateDataKey`, `DescribeKey` on its hosted modules' `internal/<module>/*` and `external/<module>/*` |
| `SluisKeyReadModule<Role>` | a role with `ReadModules` | `Decrypt` of those modules' parameters |
| `SluisKeySignInClientGoogle` | the google role | `Decrypt` of the sign-in client under `internal/oidc/signin/` |
| `SluisKeyReadAll<Role>`, `SluisKeyWriteAll<Role>` | the backup role; the restore role | `Decrypt` of every `internal/*` and `external/*` parameter; the same with `Encrypt` and `GenerateDataKey` |
| `SluisKeyMinter<Role>` | a role with `KeyRole.MinterRefs` (none today) that does not host `cloudflare` | `Decrypt` of the `MinterRefs` |
| `SluisKeyBlobCredentials<Role>` | each role that reads the external blobs' credential (`KeyRole.BlobCredentialsRef`, from `StorageArgs.Blobs.CredentialsRef`) and whose own statements do not reach it: on v5 with a stored preset, the issuer and the github, google, outline and slack roles | `Decrypt` and `DescribeKey` of that one parameter |
| `SluisKeyExternalReaders` | `ExternalReaders` | `Decrypt` of `external/*` |
| `SluisKeyAdminSeeds`, `SluisKeyAdminReads` | `Admins`, as ARN patterns | `Encrypt` and `GenerateDataKey` on any parameter; `Decrypt` of the state secret, the recovery password, on v5 the recovery verifier (and the conformance password and verifier when `Conformance` is on), and, with a backup role on v5, the restore identity |
| `SluisKeyBreakglass` | `Breakglass` | the four actions on any parameter |
| `SluisKeyDenyRestoreIdentity` | the backup role | Deny `Decrypt` where the encryption context `PARAMETER_ARN` is the restore identity |
| `SluisKeyDenyPasswords` | the roles that host `oidc` | Deny `Decrypt` where `PARAMETER_ARN` is `internal/oidc/recovery-password` or `conformance-password` |
| `SluisKeySign`, `SluisKeySignContextReserved`, `SluisKeySignDirectPurposeOnly`, `SluisKeySignDirectContextKeysOnly` | the roles that host `oidc`, directly | `{instance, purpose: sign}` and the three denies that hold the purpose to them |
| `SluisKeyRolesNothingElse` | the same, with `DenyOtherActions` | Deny every other action |

### Roles before the stack

| `RoleArgs` field or method | Meaning |
|---|---|
| Use | A stack that runs before the sluis stack (the shared key, the audit queue) derives role names without storage, tables or a digest. `LambdaArgs` and `Lambda` have the same methods |
| `Region`, `AccountID`, `Instance` | Required |
| `Installation`, `Blobs`, `FunctionName`, `Modules`, `BackupFunctionName`, `RestoreFunctionName`, `TableNames`, `TransitionRoles` | As in `LambdaArgs` |
| `Backup`, `Restore` | The stack creates `NewBackup`, `NewRestore`; only then is the role `Created` |
| `FunctionRoles()` | `FunctionRole`: `Role`, `Name`, `Arn`, `Also`, `Created`, `Viewer`; `Matcher()` is the access policy matcher |
| `Senders()`, `CreatedSenders()` | Role ARNs: all, or those the queue policy may name because the stack creates them or they already exist |
| `DeferredSenders(ctx)` | Queue senders as outputs. Call `Lambda(l)`, `Backup(b)` and `Restore(x)` after each component, or `Reject(err)` |
| `Roles()`, `ViewerRoles()`, `ViewerMatchers()` | `KeyRole` list, and the roles and matchers that read modules' records without hosting them |
| `KeyPolicyStatements(KeyPolicyOptions)` | `SluisKeyPolicyStatements` over `Roles()`. `KeyPolicyOptions` takes `ExternalReaders`, `Admins`, `Breakglass`, `KeyAdmins`, `DenyOtherActions` and `ReaderStatements`; `KeyAdmins` or `Breakglass` is required |
| `ExternalReaderRole.KeyStatement` | The statement of a role made by `NewExternalReaderRole` that decrypts its exact addresses. Pass it in `ReaderStatements` |

### The edge modules

`deploy/pulumi/edge/cloudflare` (package `edgecloudflare`) builds the mutual-TLS custom domain.

> **Deprecated:** use [`cloudflare/awsapigw`](https://github.com/truvity/edge/blob/master/docs/cloudflare/awsapigw.md).

```go
store, _ := sluispulumi.NewStorage(ctx, "access", &sluispulumi.StorageArgs{
	BucketName: "acme-sluis", Versioning: true, // the domain pins the truststore's version
	ProtectedPrefixes: []sluispulumi.ProtectedPrefix{edgecloudflare.Guard(cdRoleArn, operatorsAdminArn, breakglassArn)},
}, pulumi.Providers(awsProvider))
l, _ := sluispulumi.NewLambda(ctx, "access", lambdaArgs, pulumi.Providers(awsProvider))
front, _ := edgecloudflare.NewEdge(ctx, "access", &edgecloudflare.Args{
	FrontDoor:      l.FrontDoor(),
	DomainName:     "access.example.test",
	CertificateArn: originCertArn, // or Certificate: &edgecloudflare.CertificateArgs{...}
	TruststorePEM:  cloudflareOriginPullCA,
	Storage:        store, // or TruststoreBucket: ... for blobs on R2
}, pulumi.Providers(awsProvider))
```

| `edgecloudflare.Args` | Meaning |
|---|---|
| `FrontDoor`, `DomainName` | Required. The domain takes TLS 1.2 or later |
| `CertificateArn` or `Certificate` | One of the two. `CertificateArn` is a caller-supplied ACM certificate in the function's region. `Certificate` requests one with DNS validation and calls `CreateValidationRecord(ctx, record)` (`Name`, `Type`, `Value`) to create the record in your DNS |
| `TruststorePEM` | Required: CAs a client certificate chains to; for Authenticated Origin Pulls, Cloudflare's origin-pull CA |
| `Storage` or `TruststoreBucket` | One of the two |
| `PublicCache` | Optional; off by default. Builds a cache rule for the public documents and calls `CreateCacheRule(ctx, rule)` to create it in your zone. `TTL` defaults to 5 minutes (1 second to 1 hour, whole seconds); `Paths` defaults to `/keys` and the two `/.well-known` metadata documents |
| `Tags` | On what the edge creates |

| `Edge` output | Meaning |
|---|---|
| `DomainTarget`, `DomainHostedZoneID` | DNS target (CNAME or alias) |
| `CertificateArn` | Certificate in use |
| `TruststoreBucketName`, `TruststoreURI`, `TruststoreVersion` | Client-CA bundle location and pinned version |
| `PublicCacheRule` | The rule handed to `CreateCacheRule`; nil without `PublicCache` |

| Edge cache | Meaning |
|---|---|
| `edgecloudflare.PublicCacheRule(host, args)` | The same rule without a Pulumi engine, for a zone managed in another program |
| What it caches | The key set (`/keys`) and the OpenID and OAuth metadata documents, for requests with no `Origin` header. The edge TTL overrides the origin's `Cache-Control: public, max-age=300`, and a client is told that max-age. A removed key stays served for up to the TTL, hence the one-hour limit |
| `CacheRule` | `Expression` and `EdgeTTLSeconds`. Create it in the zone's `http_request_cache_settings` ruleset: action `set_cache_settings`, `cache: true`, `edge_ttl {mode: override_origin, default: EdgeTTLSeconds}`, `browser_ttl {mode: respect_origin}` |
| What it matches | `GET` and `HEAD` without an `Origin` header: the service echoes the caller's origin in `Access-Control-Allow-Origin`, and Cloudflare ignores `Vary: Origin` |

| Truststore | Behavior |
|---|---|
| Object | `truststore/client-ca.pem` in a versioned bucket; the domain pins the version, so a new PEM redeploys |
| Guard | The bucket policy denies write, delete and re-label under `truststore/` to everyone except the roles you name (`ArnNotEquals` on `aws:PrincipalArn`). Declare it on `StorageArgs.ProtectedPrefixes` with `edgecloudflare.Guard(...)`. With `Storage` the edge refuses an unversioned or unguarded bucket |
| Blobs on R2 | Leave `Storage` unset and give `TruststoreBucket` (`Name`, `ApplyPrincipalArns`): a small protected, versioned, encrypted, private, TLS-only S3 bucket with the same guard |
| Authenticated Origin Pulls | Turn on the zone's `tls_client_auth` in your own Cloudflare program, else the domain refuses every request. The DNS record for `DomainTarget` is also yours |

### More behavior

| Part | Behavior |
|---|---|
| Live alias | Every change publishes a version; alias `live` points at the newest. API, schedules, scheduler grant, self-invoke grant and the `invoke` trigger use it. Asynchronous invoke has no retries. Rollback repoints the alias |
| API | HTTP API (payload 2.0), `$default` route and stage. The `execute-api` endpoint is off unless `KeepDefaultEndpoint`. `Lambda.FrontDoor()` gives a front door the API id, stage and name |
| Schedules | `<prefix>-github-<org>`, `<prefix>-slack-<workspace>` and `<prefix>-outline-<workspace>` invoke `{"kind":"tick","controller":"github"\|"slack"\|"outline","target":"<id>"}` on the `live` alias of that module's function; a target is letters, digits and `- _ . :`, at most 40, with `:` becoming `-` in the name. `<prefix>-directory-refresh` invokes `{"kind":"refresh"}` on the Google function, `<prefix>-cloudflare-rotation` invokes `{"kind":"cloudflare"}` on the Cloudflare function, `<prefix>-issuer-clients` invokes the issuer. Without module functions every schedule targets the issuer. No retries |
| Scheduler role | `<prefix>-scheduler` may invoke only the aliases its schedules target. It trusts `scheduler.amazonaws.com` for this account and the `default` schedule group: `aws:SourceAccount` and `aws:SourceArn` (the group's ARN). The backup function's scheduler role has the same trust |
| `ExternalReadPolicy(ExternalReadPolicyArgs)` | IAM policy: `ssm:GetParameter` on exact `external/<kind>/<id>` ARNs under `/sluis/<instance>/`; with `SecretsKeyArn` or `ParameterKeyArn`, `kms:Decrypt` through SSM bound to those ARNs. Wildcards, prefixes, repeats and non-`external/` addresses are refused |
| `NewExternalReader(ctx, name, &ExternalReaderArgs{RoleName, Region, AccountID, Instance, Addresses, SecretsKeyArn, ParameterKeyArn})` | Attaches that policy to the role inline; output `PolicyJSON` |
| Related | [v1.76 upgrade](../../guides/sluis/upgrade/v1.76.md), [environment](lambda.md#environment), [IAM](lambda.md#iam-one-role), [signing on AWS](../../concepts/sluis/signing-on-aws.md), [key policy](aws-signing-key.md), [SSM root](lambda.md#instance-and-the-ssm-root) |

Upgrades: [v1.63](../../guides/sluis/upgrade/v1.63.md), [v1.62](../../guides/sluis/upgrade/v1.62.md). Releasing: [CONTRIBUTING](../../../CONTRIBUTING.md#releasing).
