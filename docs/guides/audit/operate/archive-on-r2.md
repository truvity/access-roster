# Put the archive on an S3-compatible store

Store the archive on Cloudflare R2 or another store that speaks the S3 API at its own endpoint.

## Before you start

- A preset on an endpoint has no Object Lock, so it is `operational` or `standard`; `attested` is refused. Integrity rests on the objects' hashes and the notary's seals.
- AWS bucket settings (`key_alias`, `Create`, `Keys.Archive`) are refused on it. Set retention as lifecycle rules at the store.
- The store must support conditional writes (`If-None-Match`) and `ListObjectsV2` continuation.
- Credentials come from one of `credentials_ref` (preferred), static `credentials` or `credentials_preset`.

## Steps

1. Declare an R2 preset in sluis ([mint short-lived Cloudflare tokens](../../sluis/cloudflare-tokens.md)), which rotates it at `external/cloudflare/<preset>`. Name that address on the audit preset:

   ```yaml
   presets:
     operational:
       bucket: acme-audit
       prefix: operational/
       region: auto
       endpoint: https://<account>.r2.cloudflarestorage.com
       credentials_ref: external/cloudflare/audit-r2
   ```

   Each process rereads it every minute, before expiry, and on a 401 or 403.

2. On Lambda, give the functions the parameter:

   ```go
   auditpulumi.New(ctx, "main", &auditpulumi.Args{
       Presets: map[string]auditpulumi.PresetStorage{
           "operational": {
               Bucket:         "acme-audit",
               Prefix:         "operational/",
               Endpoint:       "https://<account>.r2.cloudflarestorage.com",
               CredentialsRef: "external/cloudflare/audit-r2",
           },
       },
       // The sluis installation's SSM root, and the key its SecureStrings are encrypted with.
       Sluis: &auditpulumi.SluisArgs{Root: "/sluis/main", KeyArn: "<sluis secrets key ARN>"},
       // ... Ingest, Writer; no Keys.Archive: the store encrypts at rest itself.
   })
   ```

   The library writes `archive: {sluisRoot: /sluis/main}` and grants `ssm:GetParameter` on that one parameter.

3. On Kubernetes, sync the document into a Secret and mount it as a directory:

   ```yaml
   apiVersion: external-secrets.io/v1
   kind: ExternalSecret
   metadata:
     name: audit-r2
   spec:
     refreshInterval: 1m
     secretStoreRef: {kind: ClusterSecretStore, name: sluis-ssm}
     target: {name: audit-r2}
     data:
       - secretKey: audit-r2
         remoteRef: {key: /sluis/main/external/cloudflare/audit-r2}
   ```

   ```yaml
   writer:            # and observe, query, jobs.notary, jobs.verify
     config:
       archive: {sluisDir: /etc/audit/sluis}
     secretMounts:
       - {secretName: audit-r2, mountPath: /etc/audit/sluis/external/cloudflare}
   ```

   Keep `refreshInterval` plus the kubelet's sync well under the sluis preset's `lifetime - rotation`. A `subPath` mount does not follow the rotation.

## Static credentials instead

Without sluis, write a token's pair as a SecureString, outside Pulumi:

```sh
aws ssm put-parameter --type SecureString \
  --name /audit/main/internal/archive/operational \
  --value "$(printf '{"accessKeyID":"%s","secretAccessKey":"%s"}' "$ID" "$SECRET")"
```

Name it with `credentials: internal/archive/operational` and set `archive.stateRoot: /audit/main`. `PresetStorage.CredentialsAddress` defaults to that address; `ArchiveCredentialsPaths` lists it.

## Minted credentials instead

`credentials_preset` makes every process mint its own token from a disabled prototype. The minter can mint anything the account owner can, so prefer `credentials_ref`.

```yaml
presets:
  operational:
    bucket: audit-example
    region: auto
    endpoint: https://<account-id>.r2.cloudflarestorage.com
    path_style: true
    credentials_preset:
      account: <account-id>
      minter: internal/cloudflare/main/minter   # below archive.stateRoot; cloudflare-minter/v1
      prototype: <id of the disabled prototype token>
      lifetime: 15m
```

The minter document and the refused prototypes are in [profiles](../../../reference/audit/profiles.md).

## Other store settings

Set `path_style: true` when the certificate does not cover a bucket subdomain, and `archive.ca` for a private CA. Set `region` as the store documents, often `auto`.

## Verify

Run `audit verify` on a range written after the change.

## Trap: the compressed-write checksum

R2 answers `403 SignatureDoesNotMatch` when the SDK picks the checksum of a `Content-Encoding` object, so the store sends its own SHA-256. To test another store, set `AUDIT_S3_COMPATIBLE_BUCKET` and `AUDIT_S3_COMPATIBLE_ENDPOINT` and run `internal/s3test`.

## Decided in

[0068 Storage is configured per preset](../../../decisions/0068-storage-is-configured-per-preset.md), [0070 Cloudflare tokens and R2 credentials](../../../decisions/0070-cloudflare-tokens-and-r2-credentials-by-prototype-clone.md).
