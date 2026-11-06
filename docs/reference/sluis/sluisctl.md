# sluisctl

Commands, files and exit codes of `sluisctl`. Wrappers: [sluisctl-wrappers](sluisctl-wrappers.md). Concepts: [sluisctl](../../concepts/sluis/sluisctl.md).

```sh
sluisctl version                            # sluisctl <version> (also --version, -version)
sluisctl login   --issuer https://access.example
sluisctl whoami                             # who you are, and what it opens
sluisctl setup                              # both of the next two

sluisctl kubeconfig                         # a context per granted cluster
sluisctl aws-config                         # a profile per granted cloud role

kubectl --context staging get nodes          # exec plugin: sluisctl kube-token
aws --profile deployer@111122223333 sts get-caller-identity   # credential_process: sluisctl aws

sluisctl token --audience openbao              # one token for one audience, on stdout
sluisctl github-token --app publisher --repository app --permission contents=read
sluisctl exchange --audience k8s:staging < subject-token

sluisctl bao --address https://openbao.example:8200 kv get -format=env secret/app > .env
sluisctl bao --address https://openbao.example:8200 ssh -mode=ca -role=user ci@build-worker.example
sluisctl bao --address https://openbao.example:8200 write -field=signed_key \
    ssh/sign/user public_key=@key.pub > key-cert.pub

sluisctl psql --address https://openbao.example:8200 -ns staging -- -h db.example -d orders
sluisctl pg   --address https://openbao.example:8200 -ns staging -- pg_dump orders > orders.sql

sluisctl r2 --service-url https://r2-broker.example.com -- credentials --bucket example-bucket --prefix nix/

sluisctl backup status                          # through the issuer you signed in at; --direct uses your AWS credentials
sluisctl restore start 20261010T020000Z-3fa9c1 --confirm example --wait

sluisctl render --installation installation.yaml --out rendered/   # the service and policy documents
sluisctl policy render policy/ -o policy.yaml   # the one policy document an installation reads
sluisctl policy fragment check --ceiling ceiling.yaml access.yaml   # a company's own rows against its ceiling
```

## Commands

| Command | Does | Reference |
|---|---|---|
| `version` | this build's own version (also `--version`, `-version`) | below |
| `login` | sign in at the issuer, once, in a browser | below |
| `whoami` | who you are, and what your groups open | below |
| `setup` | `kubeconfig` and `aws-config` together | below |
| `kubeconfig` | a context per cluster you are granted | [what it writes](#what-it-writes-into-files-that-are-not-its-own) |
| `aws-config` | a profile per cloud role you are granted | [what it writes](#what-it-writes-into-files-that-are-not-its-own) |
| `token` | a token for one audience, on stdout | below |
| `github-token` | a GitHub App installation token, under the catalogue's grants | below |
| `kube-token` | a Kubernetes exec credential (run by `kubectl`) | [caches](#where-things-are-kept) |
| `aws` | an AWS credential-process answer (run by the AWS SDKs) | [caches](#where-things-are-kept) |
| `cloudflare token\|r2` | a Cloudflare API token, or R2 credentials as an AWS credential-process answer, minted for you | [below](#cloudflare-token-and-cloudflare-r2) |
| `exchange` | the raw exchange: a token in, a token for an audience out | below |
| `bao`, `r2` (deprecated), `psql`, `pg`, `ssh known-hosts` | authenticate, then run another program | [wrappers](sluisctl-wrappers.md) |
| `clients rotate\|show\|purge` | look after a generated client's secret | [clients](#clients-rotate-show-purge) |
| `backup run\|status\|list`, `restore preview\|start\|resume\|status` | through the issuer, or invoke the backup and restore functions | [backup](#backup-and-restore) |
| `recovery password\|verifier` | read a recovery or conformance password from SSM, or derive the SRP credential the service holds | [recovery](#recovery-password-and-recovery-verifier) |
| `render` | an installation in, the service and policy documents out | [render](#render-an-installation-in-the-two-documents-out) |
| `policy render` | the one policy document an installation reads, from its layers | [policy render](#policy-render-the-one-policy-document) |
| `policy fragment check` | a company's own access rows against its ceiling | [fragment check](policy-fragment.md#the-command) |

| Detail | Behavior |
|---|---|
| Source | `usage` in `cmd/sluisctl/main.go` |
| Shared flags | `--audience`, `--issuer`, `--client`; the client defaults to what `login` wrote. `aws` also takes `--role` |
| Issuer scheme | An issuer must be `https://`. `http://` is accepted for `localhost`, `127.0.0.1` and `::1` only. The sign-in callback on the loopback port ignores a request that does not carry the sign-in's `state` |
| Issuer choice | `--issuer`, else `$SLUISCTL_ISSUER`, else the `issuer:` key of `config.yaml` (these three pin the issuer), else the one issuer with a live session. When none is pinned and more than one issuer has a live session, the command exits 2 and lists them, rather than using the most recent login. A session counts as live if its file parses, holds a refresh token and does not record an expiry in the past. With no live session the last login is used, so the error is "not signed in". `login` without `--issuer` uses the pin, else the last login |
| `login` | Authorization code with PKCE on a loopback port. The policy client is `kind: public` with a loopback redirect and `sign_in_exchange: true`, else later commands exit 4. Then it saves the issuer's `/.well-known/sluis-configuration` in `backup:` of `config.yaml`, when the issuer serves one; a failure does not fail the sign-in |
| `version` | `sluisctl <version>`, or `sluisctl dev` without release ldflags, with commit and date when stamped. `--json` prints `{"version","commit","date"}`. No network, config or `HOME` |
| `token --show` | Prints the claims of the token it was just issued, not the token: `iss`, `sub`, `aud`, `groups`, `exp` and `iat` as UTC times, then any other claim under `claims`. Decoded locally, not verified; never the compact token or its signature. YAML, or `--format json` |
| `github-token` | `--app <id>`, `--repository <name>` (repeatable; none needs an all-repositories grant), `--permission <name>=<level>` (repeatable; none asks for the grant), `--json` prints `{"token","expires_at","repositories","permissions"}`. See [GitHub App tokens](../../guides/sluis/connect/github-app-tokens.md) |
| `credential ssh\|db\|client` | Removed in v1.34.0; the error names the replacement |
| Legacy identifiers | Renamed in v1.76, with a compatibility period: the default OIDC client id is `sluisctl`; with no `--client` and no `clientId:` in `config.yaml`, `login` asks the issuer whether it knows `sluisctl` and, on `invalid_client`, signs in as `accessctl` once, with a deprecation notice on stderr (an explicit id never falls back, and the session remembers the client it ran as). The kubeconfig user is `sluisctl:<cluster>`, and `sluisctl kubeconfig` renames an existing `accessctl:<cluster>` user in place, repointing its contexts. The managed file is `~/.ssh/known_hosts.d/sluisctl`, copied once from `accessctl` (the old file stays; marker `.migrated-from-accessctl`). Still read: env `ACCESSCTL_*` (`SLUISCTL_*` wins), config directory `accessctl` (copied once), AWS session-name fallback |
| Client migration | Register a `sluisctl` client (public, loopback redirect, same `requires`) beside `accessctl` in every estate's policy before workstations upgrade; retire `accessctl` one release later. A `clientId: accessctl` line that an older `login` wrote into `config.yaml` is an explicit value: delete it to move to `sluisctl` |

## cloudflare token and cloudflare r2

How-to: [Cloudflare tokens](../../guides/sluis/cloudflare-tokens.md).

| Command | Output |
|---|---|
| `cloudflare token <preset> [--format env\|json] [--lifetime <duration>] [--no-cache]` | `env` (default): `CLOUDFLARE_API_TOKEN=<token>`. `json`: `{"token","expires_on"}`. An R2 preset is refused with the command to use |
| `cloudflare r2 <preset> [--lifetime <duration>] [--file <path>] [--no-cache]` | `credential_process` JSON `{"Version":1,"AccessKeyId","SecretAccessKey","Expiration"}`, no `SessionToken`. `--file` reads a projected `cloudflare/v1` document, signs in to nothing and refuses an expired one |

| Detail | Behavior |
|---|---|
| Flags | Both take `--issuer` and `--client`; CI uses the job identity. `--lifetime` is at most the preset's |
| `--no-cache`, `SLUISCTL_CLOUDFLARE_NO_CACHE=1` | Neither reads nor writes the credential cache and takes no cache lock, so a minted token is never written to disk and every call mints a new one. Use it where a program execs `sluisctl` and the token must not outlive it. The flag or a true value of the variable (`1`, `true`) turns it on. The sign-in session cache is not a credential cache and is unchanged. `--file` caches nothing either way |
| Exit 4 | Not granted, or nonexistent |
| `aws-config` | Adds profile `<preset>@r2` per granted R2 preset: `credential_process = sluisctl cloudflare r2 <preset> --issuer <issuer>`, `endpoint_url`, `region = auto`, `request_checksum_calculation` and `response_checksum_validation = when_required`, `s3 =` with `addressing_style = path` |
| `whoami` | Lists granted presets |

## `render`: an installation in, the two documents out

```sh
sluisctl render --installation <file> --out <dir> [--check]
```

`render` writes `sluis.yaml` (`sluis/v3`) and `policy.yaml` (`policy/v2`) from an [installation](installation-document.md). The Pulumi library calls the same function ([ADR 0038](../../decisions/0038-estates-render-through-sluis.md)).

| Flag | Meaning |
|---|---|
| `--installation <file>` | The installation document. Required |
| `--out <dir>` | Output directory. Required |
| `--check` | Write nothing; print a line diff; exit `1` if any (a missing file counts) |

Output is deterministic and needs no network, session, `HOME` or secret. A failed render exits `1`, a bad command line `2`.

## `policy render`: the one policy document

```sh
sluisctl policy render [-o <file>] <file or directory>
```

`policy render` builds the one [policy document](policy-document.md) from layers, alone or as a directory read in name order. Without `-o` it writes to stdout. Name it in `policy.file`, or pass it as chart `policy` (without `apiVersion`) or Pulumi `Policy`.

| Layer | Form |
|---|---|
| Policy file | `version: 1` |
| Access document | `access:` and `overlay:`, reshaped into tables |
| Fragment | `apiVersion: sluis.truvity.github.io/policy/v2`: tables and the sections `exchange`, `apps`, `controllers` |

| Merge | Rule |
|---|---|
| Tables | By key; a key declared twice is an error naming the file |
| Lists, name lists | Concatenate, union |
| Scalars | Declared twice is an error |

The result passes every check the service runs at start. Exit codes as `render`.

## recovery password and recovery verifier

```sh
sluisctl recovery password --instance <name> [--account recovery|conformance] [--region R] [--profile P] [--show]
sluisctl recovery verifier [--account recovery|conformance]
```

| Command | Does |
|---|---|
| `recovery password` | Reads `/sluis/<instance>/internal/oidc/recovery-password` with your own AWS credentials, the SDK's default chain, and prints it decoded. `--account conformance` reads `internal/oidc/conformance-password`, which exists when `conformance.enabled` is set |
| `recovery verifier` | Reads a password from standard input and prints the account's SRP credential: the random salt, the verifier and the PBKDF2 rounds. Store it as the secret `recovery.verifierSecret` or `conformance.verifierSecret` names. For an installation that is not a Pulumi stack. Refuses a password that is weak or not printable ASCII |

| Detail | Behavior |
|---|---|
| `--instance` | Else `$SLUISCTL_INSTANCE`, else `backup.instance` in `config.yaml` |
| `--region` | Else the AWS configuration's, else `backup.region` in `config.yaml` |
| Output | Standard output must not be a terminal: pipe it or pass `--show` |

## Where things are kept

`<config>` is the OS user configuration directory (`~/.config/sluisctl` on Linux). Files are `0600` in `0700` directories, written then renamed. A cache that is absent, expired or unwritable means mint afresh.

| File | Holds |
|---|---|
| `<config>/config.yaml` | `clientId` and `lastIssuer` (the last sign-in, not a pin), written by `login`; `issuer:` pins the issuer and is only ever set by hand. A file written by an older release holds the last login under `issuer:`, which therefore counts as a pin until that line is removed |
| `<config>/sessions/<issuer>-<hash>.json` | One per issuer: refresh token, last access token and expiry. A stored issuer that disagrees with the lookup reads as not signed in. Rotated tokens are written back; a refused refresh reads as not signed in |
| `<config>/sessions/<issuer>-<hash>.json.lock` | A refresh holds it, so concurrent commands do not spend the refresh token twice |
| `<config>/session.json` | The single-issuer session of older releases, read for any issuer without its own file. Never deleted; a `login` writes that issuer's file, which wins |

| Cache | Path | Keyed by | Offered until |
|---|---|---|---|
| `kube-token` | `<config>/kube/<hash>.json` | the issuer, the client id and the audience, hashed together | a minute before the token's expiry, which is when client-go re-runs the plugin |
| `aws` | `<config>/aws/<hash>.json` | the audience and the role ARN, hashed | five minutes before the credential's expiry, when the AWS SDK would refresh its own copy |
| `cloudflare` | `<config>/cloudflare/<hash>.json` | the issuer, the client id, the preset and the lifetime asked for, hashed together | with a third of the credential's lifetime left (the lifetime is stored beside it) |
| `r2` | `<config>/r2/<hash>.json` | the issuer, the client id and the audience, hashed together | a minute before the token's expiry, the same margin `kube-token` uses |

A lock beside each file makes many callers one exchange. `login` touches no cache; delete a cache directory to force a fresh exchange.

## What it writes into files that are not its own

| Target | Behavior |
|---|---|
| kubeconfig | Through `kubectl config`. Writes the credential and context, not the cluster entry; the address and CA come from the platform's kubeconfig or `aws eks update-kubeconfig` |
| AWS config | Rewrites everything between `# >>> sluisctl >>>` and `# <<< sluisctl <<<` on each run. A profile is `<role>@<account>` with `credential_process = sluisctl aws --audience aws:<account>:<role>`; no secret |

## In a job

In a job granted `id-token: write`, `kube-token`, `aws`, `token`, `github-token`, `bao`, `r2`, `pg` and `psql` exchange the job's identity token ([GitHub Actions](../../guides/sluis/connect/github-actions.md)). No `login` or session cache; per-credential caches still apply.

## clients rotate, show, purge

```sh
sluisctl clients rotate <id> [--overlap 24h]   # a new secret; the old one stays valid for the overlap
sluisctl clients show <id>                     # metadata only, never a secret
sluisctl clients purge <id>                    # delete the record of a client no longer generated
```

| Detail | Behavior |
|---|---|
| Flags | `--issuer`, `--client`; `--overlap` is `0` to `168h`, default `24h`; `0` cuts the old secret at once |
| Caller | An operator with a token for the default client or `console` |
| `purge` | Reminds you to delete `clients/<id>/secret` by hand |
| Docs | [rotate a client secret](../../guides/sluis/operate/rotate-a-client-secret.md), [`/.access/client-secrets`](endpoints.md#client-secrets) |

## backup and restore

```sh
sluisctl backup run [--resume] | status | list [--limit N]
sluisctl restore preview <backup-id>
sluisctl restore start <backup-id> --confirm <instance> [--overwrite] [--note TEXT] [--wait]
sluisctl restore resume [--wait]
sluisctl restore status
```

| Detail | Behavior |
|---|---|
| Route | Signed in (the issuer from `--issuer`, `$SLUISCTL_ISSUER`, `issuer:` or the one live session), `backup run\|status\|list` and `restore preview\|status` go through the issuer with the login's token. No AWS credentials. `--direct` uses the caller's own AWS credentials, the SDK's default chain, so a profile from `aws-config` works. So do `--endpoint`, `--function`, `--profile`, `--region` and `--as breakglass`, which imply `--direct`. Without a login every command is direct. See [routes](backup.md#routes) |
| Always direct | `restore start` and `restore resume` never go through the issuer, so a restore works when the issuer is broken or lost. They never read the issuer's document either: the target is `--endpoint`, else the environment, else the copy saved at login, and `--confirm` is held to `--instance`, `$SLUISCTL_INSTANCE` or the saved `backup.instance`, never to the document |
| Issuer refusals | `contended` is an outcome, not an error. `4` for a group the policy does not name (`backup run` needs `backup.runGroups`) or a role short of viewer or operator; `3` when not signed in; `5` when the issuer cannot be reached. `--direct` is the way round an issuer without a backup module |
| Endpoint | For everything but `restore start` and `resume`: `--endpoint`, else `$SLUISCTL_BACKUP_ENDPOINT` or `$SLUISCTL_RESTORE_ENDPOINT`, else the issuer's live [document](backup.md#discovery), else `backup.endpoint` or `backup.restoreEndpoint` in `config.yaml`, which `login` saves. A failed fetch says so on stderr and uses the saved copy. A Lambda function ARN is the only transport implemented; another scheme exits 2 |
| Old names | `--function` is a deprecated alias of `--endpoint`. `$SLUISCTL_BACKUP_FUNCTION`, `$SLUISCTL_RESTORE_FUNCTION` and the `function` and `restoreFunction` keys still work, as an `arn:` endpoint or a bare function name |
| Saved | `backup.instance` and `backup.region` too. Addresses, no secret. `--region` overrides the region, which is otherwise the endpoint's |
| Class | `--as admin` (default) or `breakglass`: every direct call goes through the alias `live-<class>` |
| Backup | Module calls `backup.run` (direct: synchronous; through the issuer: started, then `backup.status` is read until the run ends, up to 16 minutes, or `--no-wait` prints `started`; `--resume` answers `idle` since format 2), `backup.status`, `backup.list`. Verifying a backup is `sluis backup verify`, with the backup document ([backup](backup.md#commands)) |
| `--json` | The same shape on both routes. Through the issuer, `retention` in `backup status` holds the counts in the text, not the ids of the backups removed |
| `restore preview` | Counts per module and section. Direct, a synchronous restore event with `preview`, names in `--json`; through the issuer, never names, and a refusal without its cause |
| `restore start` | Refuses unless `--confirm` equals the instance (`--instance`, `$SLUISCTL_INSTANCE`, `backup.instance` as `login` saved it, else the issuer's live document). Sends the event asynchronously with `by` set to the caller's `sts:GetCallerIdentity` ARN, then looks up the run and prints its id. `--wait` polls `restore.status` every 5 seconds until `completed`, or `failed` (exit 1) |
| `backup run --resume` | Only continues a paused run, and since format 2 none pauses: it answers `idle` and starts no backup. Kept for old scripts |
| `restore resume` | Does nothing when no restore is unfinished |
| IAM | Direct only: `lambda:InvokeFunction` on the function's `live-admin` or `live-breakglass` alias; a refusal exits 4 |
| Output | Text, or `--json`; never a secret |

## Exit codes

| Code | Means |
|---|---|
| `0` | ok |
| `1` | anything else: read the message. For `clients`: a client not generated, without a record, still declared, or busy |
| `2` | usage: bad command line or overlap |
| `3` | not signed in: run `sluisctl login` (a `401`) |
| `4` | audience or App token not granted; for `backup` and `restore`, AWS or the function refused the caller; for `bao`, `pg`, `psql` also OpenBAO's `403`. Do not retry |
| `5` | issuer unreachable; for `bao`, `pg`, `psql` also OpenBAO. Retry may help |

## Installing it

Add the release's `sluisctl_<version>_nix-flake.tar.gz` URL with `#sluisctl` to `devbox.json` ([concepts](../../concepts/sluis/sluisctl.md#installing-it)).
