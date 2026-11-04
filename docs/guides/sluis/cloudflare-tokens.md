# Mint short-lived Cloudflare tokens and R2 credentials

Make sluis clone a disabled Cloudflare prototype token into expiring account tokens. R2 with static credentials needs none of this ([blobs on R2](operate/blobs-on-r2.md)).

## Before you start

- Set `secrets.source: ssm`.

- The minter can mint anything the account owner can (checked 2026-10-08). Only sluis's refusal list guards the account.

- Keep the minter under `internal/` as a KMS-encrypted parameter (`secrets.kmsKeyId`), readable only by the function's role or the Kubernetes identity.

- sluis refuses an active or missing prototype, and one granting token admin, Billing, Account Settings, Memberships or Access identity rights. `cloudflare.forbiddenPermissionGroups` only adds names. A refusal is audited as `roster.cloudflare.token.refused`.

| Preset key | Effect |
|---|---|
| `allowedPermissionGroups` | the prototype may grant only these groups, else `prototype_forbidden`; the forbidden list stays the floor. Prefer setting it |
| `maxLivePerCaller`, `maxLive`, `maxMintsPerCallerPerHour` | on-demand caps, defaults 10, 50 and 30. Over one the mint is refused (`caller_cap`, `preset_cap`, `rate_limited`), audited, and answered `access_denied` |
| Record of minted ids | an on-demand mint first deletes the preset's expired tokens; a record that still holds about 100 stored or 65 on-demand ids refuses the mint as `record_full` |
| Counting | from the preset's record of minted tokens and the mints under way in the process; a mint never lists the account |
| Caps between passes | soft: a token created and never recorded counts from the next pass, at most `ReconcileEvery` (10m) or one tick later; two replicas reading the record at once can overshoot together |
| Counting fails | a record that cannot be read fails the mint (fail closed) |

## 1. Create the minter token

Create an account API token with Account API Tokens Read and Write only. Keep it out of service documents, Pulumi inputs and command lines.

```sh
aws ssm put-parameter --type SecureString --name /sluis/<instance>/internal/cloudflare/main/minter \
  --value '{"schema":"cloudflare-minter/v1","token":"<the token>"}'
```

## 2. Create and disable a prototype

Create an account token with the rights a minted token should have, such as DNS Write on one zone. Then disable it with an update, since creation ignores `status: disabled`.

For R2, scope it to the resource key `com.cloudflare.edge.r2.bucket.<account-id>_default_<bucket>` (`_eu_` for the EU) with Bucket Item Read or Write.

## 3. Declare the preset and the grant

```yaml
cloudflare:
  accounts:
    main:
      id: <account-id>
      minter: internal/cloudflare/main/minter
  presets:
    dns-example:
      account: main
      prototype: <prototype token id>
      description: DNS edits on example.com for the release job
      lifetime: 1h
      rotation: 20m
    r2-archive:
      account: main
      prototype: <R2 prototype token id>
      endpoint: https://<account-id>.r2.cloudflarestorage.com
      lifetime: 1h
      rotation: 20m
```

`endpoint` makes a preset an R2 preset. `lifetime` sets each token's `expires_on`. `rotation`, shorter than `lifetime`, sets how often the stored credential is replaced.

```yaml
    dns-adhoc: # minted only on demand: nothing stored, no rotation
      account: main
      prototype: <prototype token id>
      description: DNS edits minted for one infrastructure run
      lifetime: 1h
      store: none
```

| Limit or rule | Value |
|---|---|
| Pass | every 15 minutes per preset by default (`CloudflareRotation.Interval`); a credential rotates up to one tick after its `rotation` age, so `rotation` + tick + 5m must be under `lifetime`; a due rotation reads the prototype, creates a token, stores it and deletes the expired ones; an R2 token is stored a minute after it is created, because R2 refuses a new token for up to about half a minute, and the credential it replaces stays valid meanwhile. All presets are ticked at once, so the waits overlap |
| `store` | `external` (default) rotates the token into `external/cloudflare/<preset>`. `none` is on-demand only: leave `rotation` out; the pass mints and stores nothing and only deletes its expired tokens; the Pulumi library checks no margin for it and still declares the schedule; the console shows `Store: none` and refuses `Rotate now` |
| Rotation timing | the first tick after `rotation` replaces the credential, so make `rotation` a multiple of the tick to rotate when intended (20m on a 15m tick rotates every 30m); the console calls it *due* until then and *overdue* past `rotation` + tick + 1m, taking the tick from `cloudflare.tick`, which the Pulumi library fills from `CloudflareRotation` (a minute when unset) |
| Cloudflare API | 1,200 requests per 5 minutes per user; past it Cloudflare blocks the API for 5 minutes |
| Tokens per account | 500; a 1h `lifetime` with a 20m `rotation` keeps about three live per preset |
| Token names | `sluis/<instance>/<preset>/<time>`; on demand `sluis/<instance>/<preset>/<caller>/<time>` |
| Sweep | deletes only expired tokens it recorded, under its own preset's prefix; the pass and each on-demand mint sweep |
| Reconcile | for a granted preset, the pass lists the account every `ReconcileEvery` (10m), records the preset's tokens the record lacks, and forgets entries for tokens Cloudflare no longer has; each is logged and counted in `sluis.cloudflare.record.drift` |

In the policy, grant a group per preset. Pin a CI job by `github` matchers, never by workflow name:

```yaml
groups:
  all:ci:release:
    matchers:
      - github:
          repository: example-org/example-repo
          ref: refs/tags/v*
          job_workflow_ref: example-org/example-repo/.github/workflows/release.yml@refs/tags/v*
cloudflare:
  grants:
    - group: all:ci:release
      presets: [dns-example, r2-archive]
```

## 4. Mint for a person

```sh
sluisctl login
sluisctl whoami                       # lists your granted presets
eval "export $(sluisctl cloudflare token dns-example)"
sluisctl aws-config                   # adds a profile r2-archive@r2 per R2 preset
aws --profile r2-archive@r2 s3 ls s3://example-archive/
```

The CLI caches under `<config>/cloudflare/` and mints again with a third of the lifetime left. `--no-cache` writes nothing to disk.

## 5. Mint for CI or a workload

A workflow with `permissions: id-token: write` signs in as the job:

```yaml
- run: echo "CLOUDFLARE_API_TOKEN=$(sluisctl cloudflare token dns-example --format json | jq -r .token)" >> "$GITHUB_ENV"
```

A pod fed `external/cloudflare/<preset>` by a secrets operator needs no identity. `--file` refuses an expired document:

```ini
[profile archive]
credential_process = sluisctl cloudflare r2 r2-archive --file /var/run/secrets/cloudflare/r2-archive.json
```

Blobs mint R2 credentials with `ports.blob.s3.credentials: {preset: r2-blobs}` or read `credentialsRef: external/cloudflare/r2-blobs`.

## 6. Verify

The stored credential is `external/cloudflare/<preset>` as `cloudflare/v1`. With the Pulumi library, declare `Installation.Cloudflare` ([Pulumi library](../../reference/sluis/pulumi-library.md)). The alert `SluisCloudflareRotationStale` fires past twice the rotation.

## Roll back

Delete a live token by id. If it was the stored one, the next pass mints a replacement. 

## Decided in

[ADR 0070](../../decisions/0070-cloudflare-tokens-and-r2-credentials-by-prototype-clone.md).
