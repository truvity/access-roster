# AWS

The AWS part of a Kubernetes installation as a Pulumi Go library,
`github.com/truvity/sluis/deploy/pulumi`, a module of its own so that Pulumi is
not in the root module's dependency graph. The infrastructure lives here, in a
versioned library next to the code it serves, and gitops only wires it: a stack
calls three constructors and renders the processes' configuration from the same
names.

**Nothing here is deployed by this repository.** The library is tested against
Pulumi's mocks (`just pulumi-test`): it declares the right resources with the
right arguments and creates none, and the `ports:` block it renders is validated
against the schemas in `schemas/config`. What has not happened is a run in an
account.

## The shape

Three components, each usable alone, so that an installation which keeps its
State on NATS simply omits the table:

| Component | Type token | Creates |
|---|---|---|
| `NewStorage` | `sluis:aws:Storage` | the blob bucket and the Sealer's KMS key with its alias |
| `NewState` | `sluis:aws:State` | the DynamoDB table of the DynamoDB adapter |
| `NewKubernetesIdentity` | `sluis:aws:KubernetesIdentity` | one EKS Pod Identity role per process |

and `RenderPorts` (`RenderPortsYAML`), which renders the `ports:` block.

```go
store, _ := sluispulumi.NewStorage(ctx, "kernel", &sluispulumi.StorageArgs{
	BucketName: "acme-kernel-sluis",
}, pulumi.Providers(awsProvider))
state, _ := sluispulumi.NewState(ctx, "kernel", &sluispulumi.StateArgs{
	TableName: "kernel-sluis",
}, pulumi.Providers(awsProvider))
ids, _ := sluispulumi.NewKubernetesIdentity(ctx, "kernel", &sluispulumi.KubernetesIdentityArgs{
	ClusterName: "kernel", ClusterArn: clusterArn, AccountID: accountID,
	Namespace:              "sluis",
	PermissionsBoundaryArn: boundaryArn,
	Serve:                  sluispulumi.ProcessArgs{ServiceAccount: "sluis"},
	GitHub:                 sluispulumi.ProcessArgs{ServiceAccount: "sluis-github"},
	Slack:                  sluispulumi.ProcessArgs{ServiceAccount: "sluis-slack"},
	Storage:                store.Grant(),
	State:                  state.Grant(),
}, pulumi.Providers(awsProvider))
```

The AWS provider is the caller's: pass `pulumi.Providers(p)` (or
`pulumi.Provider(p)`) as an option and the components' children use it. No
constructor makes a call to AWS to find out something it was not told.

## Storage

### Inputs (`StorageArgs`)

| Field | Default | Meaning |
|---|---|---|
| `BucketName` | required | The bucket's name. It is in the configuration, so it is known before anything is created, and a bucket name is global. |
| `Versioning` | off | S3 versioning. The bucket holds the controllers' last reports and the directory snapshots, which the next tick regenerates and which are never a credential; an ETag is the compare-and-swap's version. |
| `KeyAlias` | `alias/<name>-sluis` | The alias `ports.sealer.kms.keyId` names, so the configuration carries no generated ARN. Must start with `alias/`. |
| `KeyDescription` | says what the key is for | The key's description. |
| `Tags` | none | On the bucket and the key. |

### Outputs

`BucketName`, `BucketArn`, `KeyArn`, `KeyID`, `KeyAlias`, and `Grant()`, which is
what `NewKubernetesIdentity` takes as `Storage`.

### What is created

- **The bucket**, protected, encrypted with S3-managed keys (AES256: SSE-KMS
  under the Sealer's key would make two kinds of thing share one key, and the
  estate keeps one key per kind), with every public-access block on, and a bucket
  policy that denies every action to every principal when the transport is not
  TLS (`aws:SecureTransport` false) on the bucket and its objects. Versioning when
  asked for.
- **The Sealer's key**, protected: symmetric, rotation on, a 30-day deletion
  window, an alias, and AWS's default key policy, so the roles' policies are what
  grant its use and nothing else may. Losing it loses every sealed credential,
  which an operator must then connect again.

## State

The table of the DynamoDB adapter (`internal/port/dynamodb`, ADR 0027).

### Inputs (`StateArgs`)

| Field | Default | Meaning |
|---|---|---|
| `TableName` | required | The table's name (`ports.dynamodb.table`). |
| `KeyArn` | none | A customer-managed key to encrypt the table with. Absent, the AWS-owned key: free and needing no grant. |
| `Tags` | none | On the table. |

### Outputs

`TableName`, `TableArn`, and `Grant()` (the table's ARN and the key's, if any).

### What is created

One table, protected and with DynamoDB's own deletion protection, shaped as the
adapter's documentation says:

| Attribute | Type | |
|---|---|---|
| `pk` | S | the hash key: the first segment of the key (`ses`, `lease`, `rt`) |
| `sk` | S | the range key: the whole key |
| `rev` | N | the revision, written by the adapter on every write |
| `expires` | N | the TTL attribute, epoch seconds |

Only the two key attributes are declared; DynamoDB takes the rest schemaless.
Billing is on-demand, point-in-time recovery is on and TTL is on `expires`. The
adapter judges expiry itself on every read, so DynamoDB's own sweep, which can
be days late, is housekeeping and not a correctness matter. There is no
secondary index: the adapter's Index is items of the same table.

## Kubernetes identity

One EKS Pod Identity role per process, so that a grant for one is never a grant
for another.

### Inputs (`KubernetesIdentityArgs`)

| Field | Default | Meaning |
|---|---|---|
| `ClusterName` | required | The EKS cluster the associations are made in. |
| `ClusterArn`, `AccountID` | required | Pin each trust policy to the cluster: the source ARN and the source account EKS stamps on every assume. |
| `Region` | provider's | Set on each association. |
| `Namespace` | required | The namespace of the three ServiceAccounts. |
| `PermissionsBoundaryArn` | none | The boundary of every role. The estate's rule is that a role has one (gitops uses `pb@default`). |
| `RoleNamePrefix` | the component's name | Roles are `<prefix>-sluis-serve`, `<prefix>-sluis-github` and `<prefix>-sluis-slack`; each role's managed policy has the role's name. |
| `Serve`, `GitHub`, `Slack` | | A `ProcessArgs`: `ServiceAccount` (empty creates no role; required for `Serve`) and `Description` (the policy's, which IAM cannot change once set). |
| `Storage` | required | `Storage.Grant()`. |
| `State` | none | `State.Grant()`. Nil when the State is on NATS: the roles then carry no DynamoDB grant. |

### Outputs

`ServeRoleArn`, `ServeRoleName`, `GitHubRoleArn`, `GitHubRoleName`,
`SlackRoleArn`, `SlackRoleName`; empty for a role that was not asked for.

### What is created, per process

A customer-managed policy and a role with the same name, the attachment, and one
`PodIdentityAssociation` of the ServiceAccount with the role. The trust policy
lets `pods.eks.amazonaws.com` assume the role (`sts:AssumeRole` and
`sts:TagSession`) only for this account and cluster, this namespace and this one
ServiceAccount. A ServiceAccount takes one association, so two processes on one
ServiceAccount are refused.

### IAM, whole

Every role has the same grants; they are the whole of its policy.

| Sid | Actions | Resource |
|---|---|---|
| `SluisBlobs` | `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` | the bucket's objects |
| `SluisBlobList` | `s3:ListBucket` | the bucket (a read of an absent key is a 404 only with it, a 403 without) |
| `SluisSealer` | `kms:Encrypt`, `kms:Decrypt` | the Sealer's key, only when `kms:EncryptionContextKeys` is exactly `sluis:binding` (`ForAllValues:StringEquals`) and the key is present (`Null: false`) |
| `SluisState`, with State | `dynamodb:GetItem`, `PutItem`, `DeleteItem`, `Query`, `Scan`, `DescribeTable` | the table |
| `SluisStateKey`, with a table key | `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey`, `kms:DescribeKey` | the table's key, only through DynamoDB (`kms:ViaService`) |

`Null: false` is what makes the encryption context mandatory: `ForAllValues` is
also true of a request that carries no context at all. `Scan` is `sluis migrate`
and a listing by a prefix with no dot; `DescribeTable` is the start-up check and
the readiness probe. Nothing is granted on `*`.

The encryption-context key `sluis:binding` is what the KMS Sealer sends with
every wrap and unwrap. **The service's own constant is renamed in a separate
change, and the two must match:** this library requires a service release whose
Sealer sends `sluis:binding`, and a release that still sends the old key is
refused by these policies.

## The configuration

`RenderPorts` renders the `ports:` block of the file `serve` and both controllers
read, from names the components were given, so none waits for a resource:

```go
y, _ := sluispulumi.RenderPortsYAML(sluispulumi.PortsArgs{
	BucketName: "acme-kernel-sluis",
	KeyID:      sluispulumi.DefaultKeyAlias("kernel"),
	TableName:  "kernel-sluis",
	Region:     "eu-west-1",
})
```

```yaml
ports:
  adapter: dynamodb
  blob:
    adapter: s3
    s3: {bucket: acme-kernel-sluis, region: eu-west-1}
  dynamodb: {region: eu-west-1, table: kernel-sluis}
  sealer:
    adapter: kms
    kms: {keyId: alias/kernel-sluis, region: eu-west-1}
```

`create` is never rendered: the table is the infrastructure's, and the adapter
binds to it and checks it. Credentials are the platform's. Without `TableName`
no State adapter is written (the schema's default) and only the blob and the
sealer are. The NATS adapter's own block is the identity stack's: `RenderPorts`
refuses it. The tests hold the block to the schemas of all three binaries, so a
key renamed in `schemas/config` fails there.

## Switching the serving pod to its own role

The serving pod gets a role of its own, `<prefix>-sluis-serve`, replacing the
shared `kernel-access-issuer-audit` role (decision N9a). That role also carries
the audit-events writer's grants, which are the audit side's and are not in this
library. What gitops does at the switch:

1. Create the new stack from the library: the roles, the bucket, the key and the
   table are new `sluis` resources. **No state move is needed**: the earlier
   access-roster resources in eso-iam are empty and are deleted, not adopted.
2. A ServiceAccount takes one association. Delete the serving
   ServiceAccount's association with the old role in the same apply that creates
   the library's, or the create fails; the pod loses its credentials for the
   moment between them, so do it in a quiet window.
3. Keep the audit events' grants. Attach gitops's own managed policy for them to
   the library's serve role, with a `RolePolicyAttachment` on `ServeRoleName`,
   or give the audit writer another path: the library neither carries nor
   removes them.
4. Retire `kernel-access-issuer-audit` and its policy when the last object under
   its prefix has expired.

## Extension points

Left for the Lambda platform (the AWS half of ADR 0026), and named so that it
lands beside what is here without changing it:

- **`NewLambda`** (`sluis:aws:Lambda`): the functions, their execution roles and
  their packaging.
- **`NewAPIGateway`** (`sluis:aws:ApiGateway`): the HTTP front of the console and
  the issuer.

Both would take `Storage.Grant()` and `State.Grant()` as the identity does, so
the same grants apply to an execution role. Nothing of either exists yet.

## Releasing

The release workflow tags the library `deploy/pulumi/vX.Y.Z` at the release
commit, beside the `vX.Y.Z` that triggered it, which is how
`go get github.com/truvity/sluis/deploy/pulumi@vX.Y.Z` finds it. The job is
idempotent and treats an annotated or signed tag that peels to the release commit
as already there; a tag at any other commit fails the release.
