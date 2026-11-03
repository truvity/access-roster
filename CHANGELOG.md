## Unreleased

### Fixed

- **audit: a credential read moments after its rotation is no longer refused once and given up on.** The v1.79.4 retry after a 401 did not take effect at a rotation: a writer that had been idle read the new `credentials_ref` document within a second of it being written, R2 answered 401 because it does not accept a token Cloudflare has just created for a second or two (up to about 2.3 s measured), the reread found the same document, and the request was not sent again (`replaced=false`), so about a third of rotations sent a batch back to its queue. The old credential was still valid throughout, and the document was already written: neither the rotation's order nor a cache was the cause. `cloudflare.StoredProvider.Reauthenticate` now waits until a refused credential that did not change is `StoredConfig.Settle` (default 5 s) old since it was first read, or the context ends, and answers true so the request is sent once more; a refusal of an older credential is the answer, as before. It also compares the secret, not only the access key id, so a credential rotated in place, keeping its id, counts as replaced. `cloudflare.DefaultSettle` in the storage module. **Upgrade:** none.

## v1.80.2

A patch release: a wrapped signing key is published 12 hours before it signs instead of 15 minutes, so a verifier that caches the key set for an hour no longer refuses the new key's tokens after each daily rotation; and the key set and the metadata documents carry `Cache-Control: public, max-age=300`. Also dependency updates (`sigstore-go` v1.4.0) and CI tooling. Upgrade notes: an installation that sets `signingKey.kmsWrapped.prepublish` keeps its value; raise it to at least its verifiers' longest key-set cache, or remove it.

### Fixed

- **A wrapped signing key is published 12 hours before it signs, not 15 minutes.** `signingKey.kmsWrapped.prepublish` unset was `signingKey.activationDelay` (15m), so a verifier that caches the key set for longer (an hour is common) rejected every token signed with the new key for up to the rest of its cache after each daily rotation, with "no keys found" for the new `kid`; the key set and the tokens were correct throughout. Unset is now half of `rotateEvery` (12h with the default 24h), never shorter than `activationDelay`: longer than any key-set cache seen, and still below `rotateEvery`, which the start requires. `retain` is unchanged (`lifetimes.token` plus 5m): a verifier's cache does not lengthen it, since a cached copy holds more keys, not fewer. The key set now holds two keys per algorithm at a time (four with ES384 and RS256) instead of mostly one, three per algorithm only while `retain` is longer than `rotateEvery` minus `prepublish`. A key already pending keeps the activation it was recorded with; the next rotation is published 12h ahead. **Upgrade:** an installation that sets `prepublish` keeps its value; raise it to at least the longest key-set cache of its verifiers, or remove it.
- **The key set and the metadata documents say how long they may be cached: `Cache-Control: public, max-age=300`.** `/keys`, `/.well-known/openid-configuration` and the RFC 8414 metadata carried no `Cache-Control`, so a client guessed, and an edge cache's TTL was invisible to it. The header goes on a `200` to a `GET` or `HEAD` only; errors carry none, and the credential endpoints keep `no-store`. Five minutes is a third of the shortest default pre-publish (`activationDelay`, 15m), so a go-oidc verifier, which refetches on an unknown `kid` only once its copy has expired, has the new key before it signs. The edge library's public-paths cache rule (default TTL 5m, overriding the origin) is unchanged. A key that signs at once, the first of a newly configured algorithm or of a cutover, may now be refused for up to five minutes by a verifier that fetched the key set just before and honours the header; before, such a verifier refetched at once. **Upgrade:** keep the pre-publish (`prepublish` for wrapped keys, `activationDelay` for file and KMS keys) well above five minutes plus any edge TTL in front of the issuer.

## v1.80.1

A patch release: dependency updates, with no change in behaviour. `github.com/truvity/policy` moves from v1.54.1 to v1.55.0 in the root module, `audit`, and both `deploy/pulumi` modules; the TypeScript lock files, the pinned CI actions and the other non-major Go dependencies move with it. Upgrade notes: none.

### Changed

- **Non-major dependency updates.** `github.com/truvity/policy` v1.55.0, `github.com/truvity/cnpg/v2` v2.38.0 and `gemaal` v0.26.5 in `audit`, the pinned `truvity/ci-actions` v3.8.0, and the refreshed lock files of `frontend`, `audit/ts`, `audit/react` and `ts`. **Upgrade:** none.
- **Renovate tidies every Go module after a Go dependency update.** A post-upgrade task runs `hack/tidy-modules.sh` (`just tidy-modules`), because the modules replace one another by path and a bump left the `go.sum` of the others stale. Development tooling only. **Upgrade:** none.

## v1.80.0

A minor release: a CI job identity may run on pull requests, read only (`refs/pull/*/merge`); and go-jose v4 and chi v5 move to patched versions (three go-jose and one chi advisory). Upgrade notes: an installation that declares job identities calls `ValidateGitHubPullRequestGrants` beside `ValidateGitHubJobs` and `ValidateGitHubAppGrants`.

### Security

- **go-jose v4 4.1.4 -> 4.1.6 in `audit/deploy/pulumi` and `third_party/zitadel-oidc`** ([GHSA-mgcc-cww5-fp2q](https://github.com/advisories/GHSA-mgcc-cww5-fp2q) high, [GHSA-4w3g-jfj2-cw2q](https://github.com/advisories/GHSA-4w3g-jfj2-cw2q) and [GHSA-vvm8-gf78-28g4](https://github.com/advisories/GHSA-vvm8-gf78-28g4) medium; fixed in 4.1.6 and 4.1.5).
- **chi v5 5.3.2 -> 5.4.0 in the root module, `deploy/pulumi` and `third_party/zitadel-oidc`** ([GHSA-j6qf-3m9c-vwj3](https://github.com/advisories/GHSA-j6qf-3m9c-vwj3), medium).

### Added

- **A CI job identity may run on pull requests, read only.** `policy/compile` admits a job pinned to `ref: refs/pull/*/merge` with `events: [pull_request]`: its matchers pin the repository, the merge ref, the event and the workflow files, without `ref_type`. A pull request runs the files it proposes, so the new `ValidateGitHubPullRequestGrants` refuses a grant to such a job of any permission above `read`, or of a repository pattern (`*`, `lib-*`): the job reads a short list of named repositories, such as the private modules a build downloads. `pull_request` on a branch or tag ref, and the other `pull_request_*` events, stay refused; `pull_request_target` is unchanged. `GitHubJobIsPullRequest` says whether a job is one. **Upgrade:** an installation that declares job identities calls `ValidateGitHubPullRequestGrants` beside `ValidateGitHubJobs` and `ValidateGitHubAppGrants`.

### Fixed

- **`hack/test-release-gate.sh` no longer commits into the real repository when run from a pre-push hook.** The hook's `GIT_DIR` overrode `git -C`, so the test's commits landed in the repository being pushed. The script now unsets git's repository variables.

## v1.79.4

A patch release: the audit writer rereads its credential after a 401 as after a 403, so an S3-compatible store that answers 401 for a rotated key no longer fails a batch at each rotation; and pushing a v1 release tag now rebuilds the documentation site. Correction to v1.79.3: its notes give about 0.5 to 1 s for an on-demand Cloudflare mint; measured, a warm mint takes about 1.3 to 1.4 s, of which Cloudflare's GetToken and CreateToken take about 1 s. Upgrade notes: none.

### Changed

- **Pushing a v1 release tag rebuilds sluis.id; master no longer publishes the documentation site.** sluis.id is built from the `main` branch (`.github/workflows/site.yaml` there), which builds this documentation into /v1/ from the latest v1 release tag. A new workflow, `.github/workflows/site-v1.yaml`, starts that build when a tag `v1.X.Y` is pushed; module tags and pre-releases do not start it. `.github/workflows/pages.yaml`, already disabled, is removed. The documentation sources, `mkdocs.yaml` and the `hack/` scripts the build uses stay on master. **Upgrade:** none.

### Fixed

- **The audit store reads its credential again after a 401, not only after a 403.** An S3-compatible store can answer 401 rather than 403 for a key that was rotated away, at the moment the rotated credential replaces it. The archive store of an audit profile with `credentials_ref` or `credentials_preset` reread its credential only on 403, so on 401 it kept the revoked one: the writer failed the batch (listing `holds/`, the seal probe's head or the put) and the queue delivered it again. Nothing was lost. A 401 is now treated as a 403: the credential is read again and the request is sent once more, never twice. The rotated document is read with `state.WithFreshRead`, so a caching store never hands back the credential that was just refused. Each reauth is logged as a warning, `s3store: the store refused the credentials; reauthenticated`, with `status`, `operation` and `replaced`, and a retry that fails again as `s3store: the request failed again after the reauth`; neither carries a credential. **Upgrade:** none.

## v1.79.3

A patch release: faster Cloudflare mints. An on-demand mint of a `cloudflare:<preset>` audience counts its caps from the preset's record of minted tokens instead of listing every token in the account, and the pass of each granted preset holds the record against Cloudflare's list every `ReconcileEvery`. Upgrade notes: the record holds about 65 on-demand tokens, so a preset whose `maxLive` is above about 60 is refused as `record_full` before `preset_cap`; lower such a `maxLive` to 60 or less to keep the refusal's reason. Watch the new metric `sluis.cloudflare.record.drift` for corrections the pass makes.

### Fixed

- **An on-demand Cloudflare mint counts its caps from the record of minted tokens, not from Cloudflare's list: about 0.5 to 1 s instead of 2.3 to 7 s (performance).** Every mint of a `cloudflare:<preset>` audience listed every token in the account, all pages, to count `maxLivePerCaller`, `maxLive` and `maxMintsPerCallerPerHour`, since the 10 s cache of that list was always stale at a few mints an hour. A mint now counts from the preset's record (`internal/cloudflare/minted/<preset>`), which it already read, and from the mints under way in the process, and never lists the account. An on-demand entry of the record now carries a 12-character digest of its caller and its mint time, so the record holds about 65 on-demand tokens rather than about 100; a preset whose `maxLive` is above about 60 is refused as `record_full` before `preset_cap`. The process-wide lock now guards only the process's own count, with nothing read or called under it. The pass of a preset the policy grants holds the record against Cloudflare's list every `ReconcileEvery` (10 minutes, the time kept in the record): it records the preset's tokens Cloudflare has and the record lacks, such as one whose recording and deletion both failed, and forgets the entries for tokens Cloudflare no longer has. Each correction is logged and counted in the new metric `sluis.cloudflare.record.drift` (`preset`, `kind`: `unrecorded` or `gone`). The caps are therefore softer between passes: a token created and never recorded counts from the next pass, not from the next mint. A record that cannot be read still fails the mint. A mint's trace no longer holds a `cloudflare ListTokens` span; the pass's trace does, once every `ReconcileEvery`. **Upgrade:** none. An on-demand token minted before the upgrade has no caller in the record and counts toward the caps from the first pass after it, at most one tick later. During a rolling upgrade an older replica that writes the record drops the callers it does not know, and the next pass fills them in again.

## v1.79.2

A security release for [GHSA-m7q8-643q-pjjf](https://github.com/truvity/sluis/security/advisories/GHSA-m7q8-643q-pjjf) (medium). Upgrade from any version up to 1.79.1. Upgrade notes: before upgrading, check that no client in the policy uses a plain `http://` redirect or signed-out URI to a host other than 127.0.0.1, [::1] or localhost, since such a policy is now refused at load, and that no public client sends a client secret to `/token`. Tokens issued before the upgrade stay valid until they expire.

### Fixed

- **Bearer and token-endpoint checks are stricter (GHSA-m7q8-643q-pjjf).** `/.access/grants` and `/.access/client-secrets/` accept only an access token whose session or sign-in is still live, never an ID token. A token redeemed without a session stops at `/userinfo` once its sign-in ends. The ID token's `aud` is the client alone. Token exchange refuses `actor_token` and any `requested_token_type` other than an access token. A public client that sends a `client_secret` to `/token` gets `invalid_client`. A policy with a plain `http://` redirect or signed-out URI to a non-loopback host is refused at load. **Upgrade:** check the policy's `redirects` and `signed_out` for plain `http://` to a host other than 127.0.0.1, [::1] or localhost, and that no public client is configured with a client secret.

## v1.79.1

A patch release: alerts that stop paging falsely, and traces of the Cloudflare mint. `SluisTickStale` and `SluisTickSeriesStale` read the tick counter instead of the last-success gauge, which on Lambda mixes the stamps of every warm environment and paged a healthy target as stale. A Cloudflare credential mint is recorded as its own route, `token_mint`; `SluisTokenEndpointSlow` leaves mints out and needs 100 requests in 30 minutes, and a new warning, `SluisTokenMintSlow`, the 13th rule, watches the mints. Each call to Cloudflare's API is now a span, with one child span per attempt. Upgrade notes: the chart renders the new rule, so route or silence `SluisTokenMintSlow` as a warning; a silence on the old `SluisTickStale` summary text must match the new one; a rule or panel of your own that reads `route="token"` no longer sees Cloudflare mints.

### Added

- **Each call to Cloudflare's API is a span, and each attempt a child span.** A Cloudflare mint spent seconds the traces could not place. The Cloudflare module's client (`internal/cloudflare/cfapi`) now opens `cloudflare <Method>` for `ListTokens`, `GetToken`, `CreateToken`, `DeleteToken` and `PermissionGroups`, and under it one `cloudflare <HTTP method>` span per attempt with `http.response.status_code`, `error.type` and `http.request.resend_count`, so a retry shows as its own span. A listing carries the pages it read and the entries it returned (`sluis.cloudflare.pages`, `sluis.cloudflare.listed`), the three new keys of the exporter's allowlist. No span carries the URL, the account, a token's id, name or value; a test holds that before any filter. **Upgrade:** none.

### Fixed

- **`SluisTokenEndpointSlow` leaves Cloudflare mints out and needs enough requests; mints have their own rule, `SluisTokenMintSlow`.** A token exchange for a Cloudflare credential (an audience `cloudflare:<preset>`) mints while the caller waits, through the Cloudflare module and Cloudflare, and takes seconds. Those mints were about 1% of the token endpoint's requests, the p99 over ten to sixty requests in ten minutes was the slowest of them, and the warning flapped. The request metrics and the span now record such a request as `route="token_mint"`: the token endpoint renames the request once it has read the form (`telemetry.SetRoute`). `issuer.Route`, and with it the migration freeze, still says `token`, so a freeze behaves as before: it admits the exchange, and the frozen Cloudflare module refuses the mint with 503 `maintenance`. `SluisTokenEndpointSlow` reads `route="token"` only, over `alerts.rules.tokenLatency.window` (now 30m, was a fixed 10m), and fires only with at least `minRequests` (100) requests in it, since below that a p99 is the slowest single request; the threshold (2s), severity and `for` are unchanged. The new warning `SluisTokenMintSlow` (`alerts.rules.tokenMintLatency`, the 13th rule) fires on a p95 of mints over `thresholdSeconds` (10) in `window` (1h) with at least `minRequests` (5) mints. The request-duration histogram gains 30 s and 60 s buckets, so a quantile can read above 10 s. The overview's token latency panel adds the mints' p95. **Upgrade:** the chart renders the new rule; route or silence `SluisTokenMintSlow` as a warning. A release that disables every rule by name must also disable `tokenMintLatency`. A dashboard or rule of your own that reads `route="token"` no longer sees Cloudflare mints; read `route=~"token|token_mint"` for both.

- **`SluisTickStale` and `SluisTickSeriesStale` read the tick counter, so a Lambda controller that ticks no longer pages as stale.** Both rules read the last-success gauge, `sluis_tick_last_success_timestamp_seconds`. Each process holds that gauge in memory, and on Lambda every warm environment of a function exports its own under the same labels, so the series takes whichever environment exported last. An environment that last succeeded hours ago kept sending its old stamp, the age swung between minutes and well over an hour, and the critical rule fired for a target with ok ticks every quarter hour. `SluisTickStale` now fires for a live target, one with a `sluis_ticks_total` sample in the last `liveWindow` (15m), that has had no ok tick (`increase(sluis_ticks_total{outcome="ok"}[...])`) in the last `maxAgeSeconds` (3600); a target with no ok series at all fires too. Its summary now reads "No successful <kind> of <target> in the last 3600s". `SluisTickSeriesStale` fires for a target whose tick counter was seen in the last two hours and not in the last `liveWindow`. Values, labels, severities and `for` are unchanged. On the overview dashboard, "Seconds since the last ok tick, by target" becomes "Ok ticks in the last hour, by target", and the "Targets not ticking" stat counts live targets with no ok tick in an hour, both from the counter. The gauge is still exported; the telemetry reference now says it is per process and not for alerting across environments. **Upgrade:** none. A silence or route that matched the old summary text must match the new one.

## v1.79.0

A minor release: the Outline controller, a module of its own. An Outline wiki's admins, groups and collections now follow the policy, and nothing changes for an installation that does not configure it. Upgrade notes. **Every estate gets a new protected DynamoDB table, `sluis-<instance>-outline`, on its next apply, and `BackupArgs` requires it**, so the backup module covers the table from the first apply. There is a new function and module, `sluis-<instance>-outline`, with its own role; the issuer may only invoke its console alias. There is a new image, `ghcr.io/truvity/sluis/sluis-outline`, and a new Lambda zip of the same name. The audit catalogue moves to 1.23.0 (the `roster.outline_*` actions), so the audit installation receives it. The Outline controller stays in dry run until `controllers.outline.enabledWorkspaces` lists a workspace. Beyond a pilot, the API key's user should be a dedicated account, not a person.

### Added

- **The Outline controller: an Outline wiki's admins, groups and collections follow the policy.** Outline's own group sync is a paid feature that reads Google's or Microsoft's API, so nothing in a self-hosted Outline followed the policy. A new `outline.workspaces.<key>` table names a workspace by a key we choose, its admin role (`roles.admin`), the addresses never demoted, removed or suspended (`ignore`, the API key's owner among them), an optional `client` it signs in through, and its collections by name with the internal groups granted `read`, `read_write` or `admin`, an `extend` or `strict` mode, an optional `adopt` and an optional `directory` (a connected directory's primary domain) every bound group must come from. The controller keeps one Outline group per bound internal group, filled with the people who hold it; makes holders of the admin role admins and every other account a member; creates or adopts each collection and grants its groups, and in a strict collection removes the grants and direct members the policy does not name; suspends an account the directory authoritatively no longer has, or that reaches none of the client's required groups, and reactivates one it has back. An answer the directory cannot vouch for may add a person to a group, never one that makes its holders admins, and nothing is removed, demoted or suspended on it. Breakers hold, until an operator confirms the fingerprint, removals over half of a group or a collection, more than one demotion or the last admin's, and more than three suspensions. A collection whose `directory` its groups reach outside is held. Public sharing and member settings, cross-company single-document shares (read hourly) and Slack integrations on company collections are reported and never changed. Every workspace is a dry run until `controllers.outline.enabledWorkspaces` lists it; a workspace whose API key's user is no longer an admin is held whole. The controller is a module of its own, the only holder of the workspaces' API keys: `sluis outline` and the chart's `modules.outline` on Kubernetes, the function `sluis-<instance>-outline` (zip and image `sluis-outline`) on Lambda, with its own document (`sluis-outline/v1`), role, table, secrets (`internal/outline/workspaces/<workspace>/<ref>`), blob prefix (`outline/`) and schedule (the library's `Schedule.OutlineWorkspaces`, every two minutes). It reads the console as the roster controllers' workload, as the Slack module does. The console's SYSTEMS, Outline page and `OutlineService` call it (`outline.remote`) to connect a workspace (URL and an admin's API key, checked with Outline), show each workspace's report, confirm a breaker and ask for a pass. The installation document's `controllers.outline` renders the module's document and the issuer's route. Audit catalogue 1.23.0 adds the `roster.outline_*` actions. Reference: [Outline](docs/reference/sluis/outline.md); guide: [connect and enable an Outline workspace](docs/guides/sluis/enable-outline-workspace.md); decision: [ADR 0077](docs/decisions/0077-the-outline-controller-is-a-module-of-its-own.md). **Upgrade:** none; with no `controllers.outline` and no `modules.outline` nothing runs. The audit installation receives catalogue 1.23.0.

## v1.78.3

A patch release: a faster, bounded audit-writer init and a quieter tick alert. The audit writer's start-up now uploads its catalogues several at a time and no single S3 request can hold it, through two new optional archive keys, `archive.attemptTimeout` and `archive.maxAttempts`, which default to 2 s and 3 for the writer and the writer Lambda. The tick alert is split: `SluisTickStale` is critical only for a target that still reports, and the new `SluisTickSeriesStale` warning, the 12th alert rule, covers a series that stopped, with a new chart value `alerts.rules.tickStale.liveWindow`. Upgrade notes: the chart renders the new rule, so route or silence `SluisTickSeriesStale` as a warning; there is no other action.

### Fixed

- **The audit writer's start-up writes its catalogues several at a time, and no single S3 request can hold it.** Every start re-archives each catalogue it runs with: the document, then one object per extension schema. That was one conditional put after another, about 80 with two roster catalogue versions, so a function start took about 3 s, and with no bound on a request one slow S3 answer could carry it past the 10 s init limit of the writer Lambda. The catalogue document is still written, and compared, first and alone, so a conflicting version still writes no schema; its schemas then go 8 at a time (`writer.Config.CatalogueParallel`), and the first failure stops the rest and is returned naming its key. A key already taken is still success. The archive's requests take two new keys, `archive.attemptTimeout` and `archive.maxAttempts`: an attempt that stalls (connecting, the TLS handshake, waiting for the headers, a pause in the body) fails after `attemptTimeout` and is retried, up to `maxAttempts`, with at most 500 ms between attempts. The writer and the writer Lambda default to `2s` and 3, so a request that stalls on every attempt fails in under 8 s rather than waiting; every other process keeps the SDK's own unless its file sets them. Start-up now logs one line per step with its `duration_ms`: the Lambda's `config_load`, `profiles`, `s3_clients`, `catalogues_load`, `dedupe_client`, `otel_start` and `writer_open`, and the writer's own `holds`, `ensure_catalogues` (with `objects` and `existed`) and `record_compositions`. **Upgrade:** none; the writer's new defaults apply without a configuration change.

- **`SluisTickStale` is critical only for a target that still reports, and a series that stopped is a warning, `SluisTickSeriesStale`.** The rule looked back two hours, so a target that was renamed, removed or relabelled left a series that paged as critical, with `@here` pings, for the hour between the threshold and the end of that window. The critical rule now reads only a series with a sample in the last 15 minutes (`alerts.rules.tickStale.liveWindow`), so it means a controller that runs and does not succeed; the threshold, severity and `for` are unchanged. The new warning `SluisTickSeriesStale` (`alerts.rules.tickSeriesStale`, `for` 5m) fires for a series seen in the last two hours and not in the last `liveWindow`, with `kind` and `target` labels and the summary "probably renamed or removed; check the policy", and leaves by itself two hours after the last sample. A controller gone for good still leaves silence after two hours, which only `absent(...)` sees. **Upgrade:** the chart renders the new rule; route or silence `SluisTickSeriesStale` as a warning. A release that disables every rule by name must also disable `tickSeriesStale`.

## v1.78.2

A patch release: the log noise of the issuer's auth request lines, the dashboards, the 2026-10-18 security review's hardening items, and the cnpg v2.35.0 bump. One behaviour change: during a migration freeze (`sluis maintenance on`) `/token` is now served read-only, answering a token exchange and a refresh as documented, where it refused them with `maintenance` before. Upgrade notes: (1) an existing audit archive bucket (neither `Create` nor `Adopt`) makes `pulumi preview` warn until its policy carries `ArchiveLockGuard`, and the deploy role needs `s3:GetBucketPolicy` and `s3:GetBucketObjectLockConfiguration` on the bucket or the warning says the policy could not be read; (2) the next apply rewrites the key policies, because `kms:CreateAlias`, `kms:UpdateAlias` and `kms:DeleteAlias` are now administrator-only, so a role that manages a library key's alias must be a key administrator; (3) a Google address is pinned to Google's `sub` at its next sign-in, and a deliberately recreated Google account needs its pin key (`issuer:signin-subject:google:<hex SHA-256 of the address>`) deleted from the issuer's shared state, for which there is no command yet; (4) in a split Lambda rollout a console sign-in may fail once and succeed on retry; (5) tag a release only after master's CI on the release commit has started, as the new release gate waits for that run to pass and refuses otherwise.

### Security

- **A release is published only from a commit on master whose CI passed.** The release workflow's `gate` checked only that every `go.mod` was pinned, so a `v*` tag on any commit, reviewed or not, published binaries, images, charts and packages. Before any other job runs, `gate` now also runs `hack/release-gate.sh`, which refuses the tag unless its commit is an ancestor of `origin/master` and master's own CI run on that commit (`ci.yaml`, for the push to master) concluded `success` with its `check` check run `success` too. A run still in progress is waited for, up to an hour; no run, a failed, cancelled or unfinished one, or an answer it cannot read refuses the release. To keep that run, a push to master no longer cancels the CI of the push before it: each master commit runs in its own concurrency group, while a pull request's newer push still cancels its older run. `hack/test-release-gate.sh` covers the cases in `release-chain`. The workflow's default permissions are now none, and the gate job holds `contents: read`, `actions: read` and `checks: read`.
- **The release and CI jobs keep no Git credential in the checkout, and `npm ci` runs without the publish token.** Every `actions/checkout` in `ci.yaml`, `release.yaml`, `security.yaml` and `pages.yaml` sets `persist-credentials: false`; none of them pushes with Git. The `npm` release job builds and tests the three TypeScript packages in a step without `NODE_AUTH_TOKEN`, so the install scripts of their dependencies never see a credential that can publish `@truvity` packages, and publishes in a step of its own with `--ignore-scripts`. **Upgrade:** none; for whoever cuts a release, tag the release commit once master's CI on it has started, and the gate waits for it to pass.

- **A Google sign-in is checked against its own nonce, and an address stays with the Google account that first signed in with it.** The issuer's sign-in sent no OpenID Connect `nonce`, and took the address alone from the ID token. It now sends a `nonce` derived from the sign-in's state, and refuses an ID token that does not carry it back, so a code obtained for another sign-in cannot complete this one; the console's own Google sign-in does the same. The first sign-in with an address also records Google's stable account id (`sub`) in the issuer's shared state, under `issuer:signin-subject:google:<hex SHA-256 of the address>`, and a later sign-in with that address from another account is refused with `403`, audited with `reason_code: subject_changed` and counted in `login.failures`. That is an address deleted in Google Workspace and given to a new account, which would otherwise inherit every grant of the old one. A state that cannot be read or written refuses the sign-in (`subject_unchecked`, `503`). Go: `backend/google.IdentifyAccount` returns the address and `sub` and checks the nonce; `Identify` is deprecated and checks none. **Upgrade:** none for most installations: each address is pinned by its next sign-in, and nothing is migrated. When a person's Google account is deliberately recreated under the same address, an operator deletes that address's key from the issuer's shared state, and the next sign-in pins the new account. In a split Lambda deployment, a console sign-in started while the issuer and the Google function run different releases may fail once; it succeeds when started again.

- **The audit library reports an existing archive bucket whose policy does not guard its lock, and `NewArchiveBucket` can write the guard.** The lock guard (`ArchiveLockGuard`: a Deny of `s3:BypassGovernanceRetention`, `s3:DeleteObjectVersion` and `s3:PutBucketObjectLockConfiguration` to every principal but the break-glass roles) was written only into a bucket the library creates or adopts. A preset's existing bucket (neither `Create` nor `Adopt`) is its owner's, so any role with a broad S3 allow could delete a version of the archive there. Before deploying, `New` now reads each existing AWS bucket's policy and, for the `attested` preset, its Object Lock configuration, and by default warns when the policy has no statement equivalent to the guard (`HasArchiveLockGuard`) or cannot be read, and when the attested bucket has no Object Lock. `Archive.ExistingBucketLockGuard: require` refuses to deploy without the guard instead, and `off` does not look; missing Object Lock is only ever reported, since no apply can turn it on. `ArchiveBucketArgs.BreakglassRoleArns` makes `NewArchiveBucket` write `ArchiveLockGuard` beside its TLS-only statement; unset, the policy is unchanged and the program warns. **Upgrade:** nothing fails. An estate whose preset names an existing bucket sees warnings in `pulumi preview` until the bucket's policy carries the guard; the deploying role needs `s3:GetBucketPolicy` and `s3:GetBucketObjectLockConfiguration` on the bucket, or the warning says the policy could not be read. To close the gap, add `ArchiveLockGuard(bucketArn, breakglassRoles)` to the bucket's own policy (with `NewArchiveBucket`, set `BreakglassRoleArns`), then set `Archive.ExistingBucketLockGuard: require`. Object Lock on an existing bucket is the owner's, through AWS support.

- **The key administrators alone may create, retarget or delete an alias of a key whose policy the libraries write.** `kms:CreateAlias`, `kms:UpdateAlias` and `kms:DeleteAlias` join the key's control plane in both Pulumi libraries (`KeyControlPlaneActions`): the `...ControlPlaneAdmins` statement allows them to the named administrators and the `...ControlPlaneAdminsOnly` deny takes them from every other principal, and the account root no longer delegates them to IAM as upkeep. An alias is how a writer names a key (SSM SecureStrings by `alias/...`), and AWS needs the action on the key as well as on the alias, so a role with a broad `kms:*` allow could before retarget the alias and send new writes to a key of its choosing. This covers `SluisKeyPolicyStatements`, `KeyControlPlaneStatements` and `KeyControlPlaneDeny`, the keys `NewLambda` creates, and audit's `SealKeyPolicy` and `DigestKeyPolicy`. **Upgrade:** the next apply rewrites the key policies. Any role that manages an alias of these keys must be among the key administrators (`KeyAdmins`, `Breakglass`, the `admins` of audit's key policies); the role that applies the stack already is. An estate that writes its own key policy from `KeyControlPlaneDeny` gets the new actions with the library.

### Fixed

- **The issuer's "auth request" log lines say what was wrong, and a missing `client_id` is a warning.** The OpenID library's line for a refused `/authorize` request carried no `error`, `client_id` or `path`, so 17 ERROR lines in one evening could not be told from one another. The line now carries `error` (the OAuth code), `reason`, `cause` when there is one, `client_id` when the request names one, and `path`; it never carries the query, `state` or a PKCE challenge, so the `oidc_error` value, which carried `state`, is gone from these lines. A request with no `client_id` or no `redirect_uri` is the caller's mistake and logs at WARN; an error with a server error anywhere in its chain, such as a store that failed during the client lookup, still logs at ERROR. The response is unchanged. A refusal sluis itself logs at `/authorize` also carries `redirect_uri`, without its query or fragment, when the client is one the policy declares. The change is in the patched copy in `third_party/zitadel-oidc`, which now differs from upstream in three files. **Upgrade:** none.

- **The GitHub function warns once that internal groups are unconsumed, not on every invocation.** "internal groups are declared but nothing consumes them" was logged each time the function assembled the controller, 216 times in 6 hours for the same two groups. It is now logged once per process for each distinct set of groups, with the same words and the `groups` field, and again if the policy changes the set. **Upgrade:** none. Whether those two groups need a consumer is an estate decision, not a code one.

- **The overview dashboard's token-endpoint panel reads the token route, and a migration freeze serves the read-only grants at `/token`.** The route label named `/oauth/token` as `token`, the library's default path, but the issuer serves the endpoint discovery names, `/token`, so every token request was counted as `other` and the "Token endpoint latency" panel and `SluisTokenEndpointSlow` (both select `route="token"`) read nothing. `/token` is now the `token` route. The same name gates the migration freeze, which is meant to answer a token exchange and a refresh read-only: at `/token` it refused them with `maintenance` like every other grant, because the route was `other`; now it serves them as `sluis maintenance on` documents. Maintenance for a restore and every other grant are unchanged. **Upgrade:** none. Token traffic moves from `route="other"` to `route="token"`; a panel or rule that counted it under `other` sees it leave.

- **The lease contended and lost counters and the GitHub rate-limit wait counter exist at zero.** A counter reaches the store only once it has been added to, so `sluis_leases_contended_total`, `sluis_leases_lost_total`, `sluis_leases_skipped_total` and `github_roster_rate_limited_total` were absent until the first event, and their dashboard panels read "no data" instead of 0; `increase()` over a series that starts at 1 also misses that first event, which `SluisLeaseLost` counts. Each is now added to by zero at a kind's first lease, and the wait counter at the first GitHub call, for each of `retry_after`, `primary` and `secondary`. **Upgrade:** none.

- **The dashboards show Lambda cold starts, init duration, init timeouts and AWS call errors.** A cold start that ran into the 10 second init limit left no trace in either dashboard. A new `sluis-lambda` dashboard ("sluis Lambda - $cluster") reads the platform's `INIT_REPORT` events from the log store: cold starts, init duration (p99 and longest), and inits that ended in `timeout` or `error`, by function. The overview and the audit dashboard each gain an "AWS SDK calls" row: `client_call_errors_total` by service and exception, and the share of calls that failed for a reason other than an ordinary conditional outcome. There is no alert on init timeouts: the chart's rules are over metrics, and one timeout is a bad cold start. **Upgrade:** the dashboards release renders the third dashboard; `dashboards.datasources.logs`, already required, is the uid its datasource variable defaults to.

- **`SluisTickStale` no longer fires for a series that stopped reporting.** The rule looked back a day, so a target that was renamed, removed from the policy, or relabelled left a series that kept the alert firing, as critical, until it was a day old. It now looks back two hours: a running controller reports the gauge on every export, so a live target that stalls still keeps a series whose stamp ages past the threshold and fires, while a series that stopped reporting leaves the rule two hours after its last sample. The threshold, severity and `for` are unchanged. A controller gone for good now leaves silence after two hours, which only `absent(...)` sees, as the health guide says. **Upgrade:** none; the chart renders the new expression.

- **Re-check on a catalogue or runner GitHub App finds an installation made directly on GitHub.** The installation id was recorded only by the setup redirect the console's Install flow ends in, so an owner who installed the App on GitHub itself left it at "created, not installed" for good, and no token could be minted for it. Re-check, on the Apps page and on the catalogue page, now asks GitHub as the App where it is installed when the App is created and recorded as not installed. An installation on the organisation the declaration names is recorded exactly as the setup redirect records it: the same record and keys, the cached answer dropped, and the App shown as installed. It is audited as `roster.catalogue_app.installed` or `roster.runner_app.installed`, with the operator who pressed Re-check as the actor and the reason `found by re-check`. An App installed nowhere stays as it was, with no error; an installation on any other account is ignored; GitHub failing to answer is shown as the App's reason and records nothing. Only a Re-check looks, never opening a page, and nothing runs it on a schedule: it is an action an operator asks for, not a repair pass. The organisation controller App is not covered. **Upgrade:** none; the audit catalogue does not change.

## v1.78.1

Two changes and a documentation update. The policy can limit which clients an identity may exchange for (`exchange_limits`; nothing changes without it), and `sluisctl cloudflare r2` and `cloudflare token` remember a refusal and no longer retry a 429, which ends the mint storm a runner over its cap caused. The conformance results include a second installation.

### Added

- **An identity can be limited to some exchange audiences: the policy's `exchange_limits`.** A client's `requires` names groups, so every identity in a shared group could exchange for every client that group opens. A limit names one identity by a matcher of any kind, `aws`, `service_account`, `github`, `email` or `email_domain`, and lists the clients its proof may be exchanged for: `exchange_limits: [{match: {aws: {account: "111122223333", role: "sluis-*", path: "/"}}, clients: [otlp]}]`. A matching proof asking for any other audience is refused with `invalid_target`, the same answer as an unknown audience, and audited with the reason code `exchange_limited`. Several matching limits allow the union of their clients; a proof no limit matches is unchanged, and a limit grants nothing a client's `requires` does not. The load refuses a limit naming an undeclared client, an empty `clients` or a malformed matcher. Limits from several policy files add up. The limit is checked on the proof alone, before the directory is asked, so it holds through any group the identity is later put in and through a group rename. The policy schema, the installation document's `access` section and the chart's values schema accept the table, and `config.Bootstrap.ExchangeLimits` renders it from an estate's own workload list: each `BootstrapExchangeLimit{ServiceAccounts, RoleARNs, Clients}` row becomes one limit per workload. Reference: [exchange limits](docs/reference/sluis/policy-clients.md#exchange-limits). **Upgrade:** none; with no `exchange_limits` every exchange is decided as before.

### Fixed

- **`sluisctl cloudflare r2` and `cloudflare token` remember a refusal and no longer retry a 429, which fed a mint storm.** Used as an AWS `credential_process`, the command is run again for every request of the program that called it. It cached a credential but never a refusal, so a caller over its Cloudflare cap, which the issuer answers with `access_denied`, asked the issuer afresh for every S3 operation, thousands in a CI job. Its HTTP layer also retried each Cloudflare edge 429 four times, so the edge's rate limit stayed tripped for every other caller of `/token`. Now a refusal of 4xx, `caller_cap` and the other policy refusals and a 429 alike, is written as a small `<cache>.refused` marker beside the credential cache, with the time, its kind (the OAuth error code, or `rate_limited`) and a wait: the answer's `Retry-After` if it had one, between 1 second and 10 minutes, otherwise 30 to 60 seconds, jittered. While the marker is fresh the command exits at once with the issuer's sentence on stderr and no request, with the same exit code as the refusal (not granted, or unreachable for a 429, which may pass). A success deletes the marker. A 429 is returned at once by the token HTTP client and is not retried; 5xx answers and network errors are still retried with jittered exponential back-off, and are not remembered. `--no-cache` writes no marker. **Upgrade:** none. `tokens.Exchanger` reports a non-200 as a `*tokens.RefusalError` (still `tokens.ErrRefused`, same text) carrying `Status` and `RetryAfter`.

### Changed

- **The conformance results include a second, independent installation.** The README results table and [conformance findings](docs/concepts/sluis/conformance-findings.md) record the 2026-10-21 run on v1.77.5 with suite 5.3.3: Basic OP 23 passed, 4 warning, 4 review, 4 skipped, 0 failed; RP-Initiated Logout 3 passed, 8 review, 0 failed. The warnings are the four accepted ones. Back-Channel Logout and Config were not run there. No behaviour changes.

## v1.78.0

Dependencies refreshed, and connect-go v2. The generated Go packages move to connect-go v2, which breaks Go programs that import them, so this ships as a minor. The wire protocol and the proto contracts do not change: Connect, gRPC and gRPC-Web clients of any version, the console and every non-Go consumer are unaffected.

### Breaking (Go API)

- **Breaking: the generated Go packages are connect-go v2.** `gen/...` (`sluisv1connect`, `directoryrosterv1connect`, `accessissuerv1connect`, `directoryv1connect`) and `audit/sdk/gen/audit/v1/auditv1connect` are generated for `connectrpc.com/connect/v2` v2.0.1, so a Go program that imports them moves to connect-go v2 with this version. **Upgrade:** `go get connectrpc.com/connect/v2@v2.0.1` (and `connectrpc.com/otelconnect@v0.12.0` if you use it). A client is `xv1connect.NewXServiceClient(connect.NewClient(connecthttp.NewTransport(httpClient, baseURL)))`; a call takes and returns the messages, with no `connect.NewRequest` and no `.Msg`; request headers are set on `ctx, info := connect.NewClientContext(ctx)` with `info.RequestHeader().Set(...)`. A server is `connect.NewServer(interceptors...)`, `xv1connect.RegisterXServiceHandler(server, impl)` and `connecthttp.Mount(mux, server)`, and a handler reads headers from `connect.CallInfoForServerContext(ctx)`. A handler's error that is not a `*connect.Error` reaches the client as a bare code; wrap it with `connect.NewError(code, err.Error()).WithCause(err)` to keep sending its text. The [connect-go v2 migration guide](https://github.com/connectrpc/connect-go/blob/main/docs/v2-migration.md) and its `connect-go-v2-migrate` tool do most of the work.
- **Breaking: `audit/sdk` follows.** `telemetry.ConnectOptions()` and `telemetry.ConnectClientOptions()` are now `telemetry.ConnectServerInterceptor()`, passed to `connect.NewServer`, and `telemetry.ConnectClientInterceptor()`, passed to `connect.NewClient`. `sink.NewClient` takes a `connecthttp.HTTPClient` and `connecthttp.Option`s, and `emit.Registration.HTTP` is a `connecthttp.HTTPClient`. An `*http.Client` still fits both. **Upgrade:** rename the two telemetry calls and pass them where the comments say.

### Changed

- **Dependencies are refreshed.** Go: `toolchain go1.27.3` in every module (crypto/x509 security fixes), and every Go dependency at its latest, including aws-sdk-go-v2, OpenTelemetry 1.47, grpc 1.84, `golang.org/x`, google.golang.org/api 0.306, urfave/cli 3.14, cenkalti/backoff v7, Pulumi sdk 3.270, pulumi-aws 7.51.1, pulumi-random 4.21.4, truvity/policy 1.54.1, cnpg 2.33.1 and gemaal 0.26.2. A stack built with the Pulumi libraries resolves pulumi-aws 7.51.1. TypeScript: `@truvity/audit` depends on intl-messageformat 12, which needs TypeScript 5.4 or later in a consumer that compiles against its types, and on `@bufbuild/protobuf` ^2.16.0 and `@connectrpc/connect` ^2.2.0. `@truvity/audit-react` raises its peer floors to the same two versions, and `@truvity/sluis` takes jose 6.2.13. The services behave as they did: errors, interceptors, read limits and mounts are kept as connect-go v1 had them.

## v1.77.5

Two fixes. A catalogue GitHub App with `export: true` that the split GitHub function installs is exported again. On-demand Cloudflare presets are swept again: the Pulumi library declares the Cloudflare rotation schedule whenever a preset is declared, `store: none` ones included, and an on-demand mint sweeps expired tokens itself and refuses with `record_full` rather than overflow the record. An estate whose presets are all `store: none` gets one new schedule.

### Fixed

- **A catalogue GitHub App with `export: true` that the GitHub function installs is exported again.** In a split deployment the console's GitHub operations run in the GitHub function, and its stores were not told which Apps the policy exports, nor their labels or the App an organisation uses. Creating and installing an exported catalogue App there kept its key as an internal credential, `internal/github/apps/<id>/<ref>`, and never wrote `external/github/<id>`. The function now configures its stores from the policy through the same helper as the one process, so the installed App's key is written to `external/github/<id>` and no internal credential is kept beside it. **Upgrade:** none for new Apps. An App installed on an affected build keeps working, because the mint still reads its internal credential, but nothing exports it on its own: write its `external/github/<id>` document by hand, or disconnect and recreate the App.
- **On-demand Cloudflare tokens are swept again, and an on-demand mint no longer fails with `record the minted token: ssm: value exceeds the 8 KiB parameter limit`.** Since v1.76.7 the Pulumi library left out the `<prefix>-cloudflare-rotation` schedule when every preset was `store: none`. On Lambda that schedule is the only thing that deletes expired tokens, so the record of minted ids, `internal/cloudflare/minted/<preset>`, only grew. At about 104 ids it filled its 8 KiB parameter, and every mint after that created a token, failed to record it and deleted it. The library now declares the schedule whenever `Installation.Cloudflare` declares a preset, under the same name, so nothing is replaced. Its description now says it also deletes expired tokens. A `store: none` preset still gets no margin check and no `cloudflare.tick`. The minter also guards the record on its own. An on-demand mint first sweeps the preset when its record holds an expired id or at least 64 ids. An expired id is forgotten only once Cloudflare has deleted the token or no longer has it. A record that still has no room for another id refuses the mint as an on-demand limit with the reason `record_full`, audited as `roster.cloudflare.token.refused`, before Cloudflare is asked to create a token. **Upgrade:** none. With only `store: none` presets the next apply adds one EventBridge schedule and the scheduler role's invoke of the Cloudflare function's `live` alias. With a stored preset it changes the schedule's description in place. Both update the function code. The first mint or tick after the upgrade deletes the expired tokens the record holds.

## v1.77.4

Two fixes: the console's GitHub App "Create" button works again, and the Pulumi library no longer renders `backup.region`, so an estate's backup and restore documents change and their functions get a new version. The Pulumi libraries move to sigstore-go v1.2.2 and its dependencies to clear Dependabot security alerts (#734; no code change). The conformance results for v1.77.2 are published.

### Fixed

- **The console's GitHub App "Create" button works again.** The console's `Content-Security-Policy` had `form-action 'self'`, which stopped the browser POSTing the App manifest to `https://github.com/organizations/<org>/settings/apps/new` (or the user's equivalent), so the button answered `BeginGitHubAppConnect`, then did nothing. The console's signed-in shell now sends `form-action 'self' https://github.com`, GitHub's web origin and nothing else; every other directive is unchanged, and so are the sign-in page, the assets, the API and the issuer's policies. Installing an App, and connecting Slack, Google or Cloudflare, navigate the whole page and are not affected by the policy.
- **The Pulumi library no longer renders `backup.region`, which backup format 2 ignores and warned about.** `NewBackup` and `NewRestore` rendered `backup.region` from the required `Region` into the backup document, so the backup function logged `the backup document sets keys that backup format 2 ignores; remove them` with `keys: ["backup.region"]` on every run. The key is now rendered only beside the deprecated `backup.key` (while `ArchiveKeyAlias` is set), which is what a binary of format v1 reads it with. `Region` is still required: it names the secrets, the tables, the audit queue and the archive target. A document that still sets `backup.region` loads, with the warning, as before. **Upgrade:** none; the next apply of an installation that rendered the key publishes a new configuration layer version for each of its backup and restore functions once, and a new function version.

### Documentation

- **The conformance results are published for v1.77.2.** The README results table and [conformance findings](docs/concepts/sluis/conformance-findings.md) record the 2026-10-20 run on suite 5.3.3: Basic OP 23 passed, 4 warning, 4 review, 4 skipped, 0 failed; RP-Initiated Logout 3 passed, 8 review; Back-Channel Logout 2 passed. The four Basic warnings are accepted and explained there. No behaviour changes.

## v1.77.3

One configuration change and one addition to the audit Pulumi library, and the documentation refreshed for v1.77.2. A service document with `secureCookies: false` and an https issuer no longer loads; its upgrade note says what to remove ([upgrade to v1.77.3](docs/guides/sluis/upgrade/v1.77.3.md)).

### Changed

- **Configuration that now fails validation: `secureCookies: false` with an https issuer URL.** The service document is refused when it loads, on Lambda and in a cluster, when `secureCookies` is `false` and `issuerURL` or `publicRootURL` is https. The error reads `secureCookies: false is refused when issuerURL is https: session cookies would be sent without the Secure flag; remove secureCookies`. An installation document's `issuer.secureCookies` is refused the same way when it is rendered, so `sluisctl render`, `sluis check` and a Pulumi preview fail before a function is deployed. The chart already refused it with `route.host`. Plain http with `allowInsecure`, and `secureCookies: true` on either scheme, are unchanged. **Upgrade:** remove `secureCookies: false` when serving https.

### Added

- **`audit/deploy/pulumi` builds the settings of an archive bucket the estate owns.** `NewArchiveBucket` declares the bucket (protected, never force-destroyed), versioning, SSE-KMS under a given key (SSE-C blocked), a public access block, owner-enforced ownership, the TLS-only policy and the archive lifecycle (Glacier IR at 30 days and Deep Archive at 365 under `records/<profile>/` for each profile, incomplete multipart uploads aborted after 7, no expiry; the days are arguments), under the caller's options. The `Aliases` hook returns the `pulumi.Alias` values of each resource by its AWS type token, so an estate that made these resources as children of an older component keeps every URN and physical name. Additive; `New` and its presets are unchanged. See [AWS Pulumi library](docs/reference/audit/aws-pulumi-library.md).

### Documentation

- **The documentation is refreshed for v1.77.2.** The README gains a Standards and conformance section with the conformance results. The site's landing page, its weekly link check and its dead links are fixed. The explanations and tutorials reach v1.77 and add a [security model](docs/concepts/sluis/security-model.md). The how-tos gain upgrade pages for [v1.77](docs/guides/sluis/upgrade/v1.77.md), [v1.77.1](docs/guides/sluis/upgrade/v1.77.1.md), [v1.77.2](docs/guides/sluis/upgrade/v1.77.2.md) and [v1.77.3](docs/guides/sluis/upgrade/v1.77.3.md), and the reference pages are corrected against the code. The 2026-10-20 conformance run on v1.77.1 is recorded in [conformance findings](docs/concepts/sluis/conformance-findings.md). No behaviour changes.

## v1.77.2

Fixes from the 2026-10-20 OpenID conformance run. One change in behaviour for relying parties, under Changed: the ID token and `/userinfo` return `email` and the names only for their scopes; its upgrade note says what to add.

### Added

- **The conformance account's userinfo answers the `profile` scope with what the account has.** With `profile` granted, `/userinfo` for a conformance sign-in carries `name` (`OpenID conformance test account`) and `preferred_username` (`conformance`, the username it signs in with). It answered `sub` alone, so the suite's `VerifyScopesReturnedInUserInfoClaims` listed every `profile` claim as missing. The ID token is unchanged, and so is userinfo without `profile`. The account has no address, so `email` still adds nothing. A token now records how its sign-in was proved, which is how userinfo knows the account. A token minted before this release answers as before until it expires. For a person, the address gives `email`, `email_verified` and `preferred_username`, and the directory gives `name`, `given_name` and `family_name`, each under its scope as Changed below says. `middle_name`, `nickname`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale` and `updated_at` have no source and are never returned, so the `profile` warning stays ([conformance findings](docs/concepts/sluis/conformance-findings.md)).

### Changed

- **The ID token and `/userinfo` return `email` and the names only for the scopes granted (OpenID Connect Core 5.4).** `email` and `email_verified` need the `email` scope. `name`, `given_name`, `family_name` and `preferred_username` need `profile`. `sub`, `groups` and the policy's other claims arrive as before, and so do `sid` and `acr`. Both answers read the scopes granted: the sign-in's for an ID token, kept by a refresh that names no `scope` (RFC 6749 6), and the access token's for `/userinfo`, whatever the userinfo request says. A scope the issuer does not serve, such as `groups`, is still dropped and never refused. The access token is unchanged and carries the names for any scope. An exchange mints an access token only, so it is unchanged too. `sluisctl login` asks for `openid email offline_access`. A session saved by an older `sluisctl` keeps working, and one without an address names the person by `sub`. **Behaviour change for relying parties:** a client that asked for `openid` alone and read `email` or a name from the ID token or `/userinfo` gets `sub` and `groups` only. **Upgrade:** add `email` to the client's scopes to keep the address, and `profile` to keep the names. A session opened before the upgrade keeps the scopes it was granted, so it loses a claim at its next refresh unless its sign-in asked for the scope. For `kubectl oidc-login` with the username claim `email`, add `--oidc-extra-scope=email` ([connect a Kubernetes cluster](docs/guides/sluis/connect/kubernetes-cluster.md)).

- **The OpenID library moves from `github.com/zitadel/oidc/v3` v3.51.13 to v3.51.16, still with the ID token's `client_id` line removed (`third_party/zitadel-oidc`).** Upstream's authorization endpoint now refuses a `code_challenge_method` other than `plain` or `S256` when a challenge is sent, and a code bound to such a method no longer verifies. sluis already refused every method but `S256`, and a challenge with no method, before the library sees the request, so `/authorize` answers as it did; tests now pin an unknown method, a lower-case `s256`, a challenge with no method, and a method with no challenge. The library's relying party now makes its PKCE verifier from 32 random octets (RFC 7636 4.1), which sluis does not use, and a failed key-set fetch keeps its underlying error, with the same text. `deploy/pulumi` and its Cloudflare module build against upstream v3.51.16.

### Fixed

- **An ID token no longer carries `client_id`.** OpenID Connect Core names an ID token's client by `aud` and `azp`, and `client_id` is a JWT access token claim (RFC 9068), so access tokens keep it. The OpenID library set it on both, and the conformance suite warned about it. sluis now builds a copy of `github.com/zitadel/oidc/v3` v3.51.16 with that one line removed, in `third_party/zitadel-oidc`, wired in by a `replace` in `go.mod`. Discovery's `claims_supported` no longer lists `client_id`. A relying party that read `client_id` from an ID token reads `azp` instead. Only sluis's own binaries change: a Go module that imports sluis packages still builds against the upstream library.

- **Discovery lists the conformance account's `acr` while the account is on.** `acr_values_supported` named the directory and recovery classes only, and a conformance sign-in's ID token carries `urn:truvity:sluis:acr:conformance`. A client that asked for every listed class therefore got back one it had not asked for: the suite's `oidcc-ensure-request-with-acr-values-succeeds` warned "acr value in id_token is not (one of the) requested values". With `conformance.enabled` the list now ends with `urn:truvity:sluis:acr:conformance`; without it discovery is unchanged. `acr` is still the class the sign-in met (directory, recovery or conformance), whatever `acr_values` asks for: a requested class the sign-in did not meet is never claimed, and tests pin both cases for every sign-in method. The `claims` parameter is not read, so no request makes `acr` essential. [ADR 0076](docs/decisions/0076-password-sign-in-is-srp-for-recovery-and-conformance-only.md) is amended to match; see [conformance findings](docs/concepts/sluis/conformance-findings.md).

- **A reused authorization code revokes the access token its first redemption issued, not only the session.** RFC 6749 4.1.2 says a server should revoke what a code already issued when the code is presented again. A reuse ended the session the code opened, but a client that asked for no `offline_access` opens none, so its access token went on answering at `/userinfo`: the OpenID conformance module `oidcc-codereuse-30seconds` warned with a 200 where it expects a 4xx. A redemption now leaves a tombstone of the code, `issuer:code-spent:<sha256 of the code>` (`oidc` table, partition `code-spent`), naming the client, the access token's `jti` and the session id. It holds no code and no token, and lives as long as that access token (at least the code's 5 minutes). A second presentation answers `invalid_grant` as before and now deletes the access token's record, so `/userinfo` answers `401 invalid_token`, and ends the session, so every refresh token of it stops refreshing and a `backchannel_logout_uri` is told. A reuse after the code itself has expired, while the tombstone stands, revokes the same way; after the tombstone has gone it is refused and revokes nothing. The tombstone is written with the store's conditional create (DynamoDB's conditional `PutItem`, Valkey's `SET NX`), so of two redemptions racing one code exactly one succeeds; the other is refused and revokes what the first issued. A redemption that fails before its tokens are minted (a wrong verifier, another client) still leaves the code redeemable. The refusal's `refused` log line carries `status=400` and `revocation`: `revoked`, `nothing_live`, `failed`, or `no_record` for a code redeemed before tombstones; `sluis.reuse_detected{kind="authorization_code"}` counts it as before. No audit record is written for it, as before. *Cost:* a code redeemed with `offline_access` makes the same number of writes as before (the tombstone replaces the `issuer:code-session:<request>` note, which is no longer written or read); one without it makes one conditional write more. *Deploy:* no table, index or IAM change; the tombstone is an item of the `oidc` table the issuer already writes. During a rolling upgrade, a code redeemed on an older replica and reused on a newer one is refused and revokes nothing. Access tokens remain JWTs: a relying party that verifies one offline accepts it until `exp`, and introspection is still not served.

- **`/end_session` refuses an `id_token_hint` it cannot accept, before it asks anything.** A hint is now verified first: this issuer as `iss`, a signature by one of its own keys, and every `aud` and `azp` a declared client or a client document the allow-list admits. Anything else answers `400` `invalid_request`, the refused page for a browser and the OAuth error for a program, with a `refused` log line that carries `status=400` and `reason=id_token_hint invalid`. It ended at the *Sign out?* page before: the issuer read the unverified `aud`, looked it up as a client (a URL there was resolved as a client document, and refused in a log line without a status), and then asked. The conformance module `oidcc-rp-initiated-logout-bad-id-token-hint` (HS256, the issuer's own URL as `aud`) got the page that asks where the specification wants an error. A hint that does not verify now reaches no client lookup, so no client-document fetch. An expired hint this issuer signed for one of its clients is still accepted, as RP-Initiated Logout 1.0 allows. *Behaviour:* a relying party that sends a hint naming a client this installation does not have gets the error page, not the page that asks.

- **`hack/conformance_drive.py` presses *Sign out* where a step wants the successful logout page.** Since v1.77 the issuer asks before an RP-initiated sign-out that carries no hint for the browser's own sign-in, so `oidcc-rp-initiated-logout-no-params` and `-only-state` uploaded a screenshot of *Sign out?* instead of *Signed out*. For a step whose expectation is `ExpectSuccessfulLogoutPage`, the driver now presses the button and photographs the page it lands on. For a step that wants an error page it never presses it.

## v1.77.1

v1.77.1-rc.2 as it stands: no change since it. Its notes are under v1.77.1-rc.2 and v1.77.1-rc.1 below.

## v1.77.1-rc.2

### Breaking

- **Storage layout v4, its migration and the compatibility switches are removed ([ADR 0072](docs/decisions/0072-storage-layout-v5-module-first.md), point 6).** An installation must run layout v5 before it upgrades; see [upgrade to v1.77.1](docs/guides/sluis/upgrade/v1.77.1.md). Removed: the secrets layout v4 (`internal/config/...`, `internal/credentials/<kind>/<id>/<ref>`) and its reader, so an `ssm` `secrets` section must now say `layout: v5` (an absent layout meant v4 and is refused); the single DynamoDB table (`ports.dynamodb.table`, `adapters.state.settings.table`, the installation's `aws.table`), so the `dynamodb` adapter takes `tables`, one per module, on every platform; the layout v4 key mapping (`internal/port/keys_v4.go`); `sluis migrate v5` (`plan`, `copy`, `verify`, `prune`: run it with v1.77.0); the `directory` name of the Google domain in `sluis migrate --skip` (use `google`); `sluis serve` (use `sluis issuer`); the fallback of `sluisctl recovery password` to the layout v4 parameter `internal/config/recovery/password`; and, in the Pulumi library, the `Layout` switch (`LayoutV4`, `LayoutV5`, `LayoutV4V5`) of `LambdaArgs` and `RoleArgs` and `CompatArgs` with `Compat` on `LambdaArgs` and `StatesArgs`; with them the legacy table (`StatesArgs.Legacy`, `LegacyStateArgs`, `States.Legacy`, `States.LegacyBackupArn`, `LegacyBackupArnOutput`, `LegacyBackupRetentionDays`), the single table (`NewState`, `StateArgs`, `State`, `StateType`, `StateGrant.TableArn`, `PortsArgs.TableName`), `LambdaArgs.MigrationRoleArn` and its inline policy, `KeyPolicyArgs.Layout`, and the v4 parameter names `StateSecretParameterName`, `RecoveryPasswordParameterName` and `ConfigParameterPrefix` (the `...V5` names stay). The library always does what `Layout: LayoutV5` with no `Compat` did, so a layout v5 installation's preview is unchanged once the arguments are deleted. A Kubernetes installation whose secrets are in another store than SSM (`openbao`, `memory`) keeps the credentials sluis writes at the layout v5 address, `credentials/<module>/<kind>/<id>/<ref>` (it was the v4 kind, such as `credentials/github-org/<org>/<ref>`): copy them before the upgrade, keeping the `<ref>`. The chart's cases on the single table now name the module tables, and the chart no longer refuses `ports.dynamodb.tables` beside a secrets store that is not SSM. The audit catalogue keeps the `sluis migrate v5` records, so the archive of past runs still reads.
- **Breaking: audit database URLs must be `sslmode=verify-full` with the server CA mounted, and the database password must come from a file.** (i) A database URL names `sslmode=verify-full` (or none) and a CA file (`sslrootcert=` or `PGSSLROOTCERT`): mount the server's CA with the chart's `trust` values (`trust.configMap` and `trust.key`) and use the host name the server certificate carries, for a CloudNativePG cluster its `-rw` Service. `sslmode=require` is refused when the file loads. (ii) `passwordSecret` needs `secrets.source: file`; `ssm` and `env` (including a version 1 `passwordEnv`) are refused when the file loads, because the database client re-reads the password file for every new connection and a password read once would fail new connections after a rotation. In the chart, replace `secretEnv` with `secretFiles` and set `secrets: {source: file, root: /etc/audit/secrets}`. An in-cluster install whose URLs say `sslmode=require` must switch before taking this release. See [prepare the database](docs/guides/audit/operate/prepare-the-database.md).
- **The audit Postgres connections follow the truvity/cnpg client contract (`pgclient`, truvity/cnpg v2.29.0).** Every pool (`audit-writer`, `audit-observe`, `audit-query`, the `audit` jobs and the `--database` flags of `migrate`, `reindex` and `purge`) is built by one constructor from the URL's parts: `verify-full` only, the CA file the URL's `sslrootcert` or `PGSSLROOTCERT` names, and an optional `sslcert`/`sslkey`. `sslmode` other than `verify-full` is refused when the file loads; a missing CA file, a second host and a URL parameter the client does not use (`passfile`, `host`, `options`) are refused when the process starts. With `secrets.source: file` the password file is read again for every new connection, and the CA, certificate and key too, so a rotated Secret is used within the 30-minute connection lifetime; the first connection and the start-up schema checks retry a connection-class error (a switchover) with backoff; `audit migrate` retries the schema and the grants, which are idempotent. `audit-query`'s readiness check is the client's `Health` (`select 1`, 2 s). `PGPASSWORD` and `CNPG_CLIENT_PASSWORD_FILE` are never read. **Deploy:** a database URL needs a CA file now (`sslrootcert=...` or `PGSSLROOTCERT`, mounted from the cluster's server CA Secret), and a host name the server's certificate carries; `sslmode=require` is refused. See [prepare the database](docs/guides/audit/operate/prepare-the-database.md).

### Added

- **The audit chart's `migrate` takes `secretMounts`, like the other components.** The template already mounted them and the values schema refused them, so the migration Job could not be given the CA a database client now needs when it is a Secret and not a ConfigMap (`trust`). The default is empty and a render without it is unchanged.
- **Each `/authorize` request leaves one info line saying whether it carried PKCE.** The line is `authorization request` with `pkce=true|false`, `pkce_method` (the method named, `plain` when a challenge named none) when there is a challenge, `client_id`, and the request's method, path, user agent and request id. The challenge and the verifier are never logged. It shows which clients still send no challenge before `pkce: required` is set on them.
- **`NewRestore` renders `backup.recipients` and `backup.verify`.** `RestoreArgs.Recipients` (pass `Backup.Recipients` of the same instance) is the restore document's `backup.recipients`, which an unverified restore needs to compare the sidecar with; `RestoreArgs.Verify` (`Query`, `TokenFile`, `Profile`, and one of `Observer` and `AnyObserver`) is its `backup.verify`, held at plan to the rules the restore applies at start. Both are optional and render nothing when unset, so an existing stack is unchanged. The library provisions no query token: `TokenFile` names a file the function's environment provides. Not yet: the audit writer's `senders` table is still not rendered by the audit library, so on Lambda no record carries the backup function's observer until it is, and a verified restore there needs `AnyObserver` meanwhile ([#697](https://github.com/truvity/sluis/issues/697)).
- **A test pins that revocation takes effect at the issuer at once.** After `/revoke` of a refresh token, or `/end_session`, the next `/userinfo` with the grant's access token answers `401 invalid_token` and the next refresh `invalid_grant`. After `/revoke` of an access token alone, `/userinfo` refuses it at once and its refresh token keeps working (RFC 7009 2.1 lets a server revoke both; this one does not). No behaviour changed. The remaining lag is outside the issuer: a relying party that verifies the JWT offline accepts it until `exp` ([endpoints](docs/reference/sluis/endpoints.md)).

### Fixed

- **`KubernetesIdentity` with `Instance` grants the layout v5 SSM paths.** The pod's role still held the paths of layout v4 (`internal/credentials/*`, which no v5 installation writes, and a bare `external/*`) and none of the `internal/<module>/*` paths a pod on `secrets.layout: v5` reads, so a pod on the `ssm` source was denied them. It now holds read and write (with the history) on `internal/<module>/*` and `external/<module>/*` for each module, the Cloudflare module's internal side with `Cloudflare`, and the read of `internal/config/*` the `ssm` source still uses, and the customer-managed parameter key for exactly those. The arguments do not change; `CloudflareOnDemandOnly` has no effect now (the module's external paths are granted whatever the presets store).
- **The reference no longer says the legacy store, Valkey, `apps.github.runnerTiers` and `apps.github.catalogue` are removed.** The descriptions of `ports.adapter: legacy`, `valkey`, `apps.github.runnerTiers` and `apps.github.catalogue` (the configuration and policy schemas, the chart values schema and the reference pages generated from them, the adapter table, the chart `values.yaml` comment and the legacy-store tutorial) said they were removed in v1.75 and v1.77. None was: `legacy` is the default adapter and ships, `valkey` is read, and the two App sections are still read as `apps.github.apps` entries with a warning. Each now says deprecated and still read. The start-up warnings say the same (the legacy store and `valkey` are `deprecated since v1.74.0 and still shipped`; the App sections `are deprecated, and still read as apps.github.apps`). Behaviour is unchanged.
- **The administrators' key-policy reads name the SRP parameters the stack writes.** On layout v5 the library writes `internal/oidc/recovery-verifier` and, with the conformance account on, `internal/oidc/conformance-password` and `internal/oidc/conformance-verifier` as SecureStrings, and the Pulumi provider decrypts each one after create and on refresh. `SluisKeyAdminReads` named none of them, so under a customer-managed secrets key an apply failed on `kms:Decrypt` unless the estate added a statement of its own. They are in `SluisKeyAdminReads` now (the conformance ones only when `Installation.Conformance.Enabled`; `KeyPolicyArgs.Conformance` for a caller of `SluisKeyPolicyStatements`). *Behaviour:* an estate's hand-added statement for the same parameters can be removed.
- **A `code_challenge` with no `code_challenge_method` is refused as `plain` is.** Without a method a challenge is `plain` (RFC 7636 4.3), and the library verified it so, while discovery lists `S256` only and `plain` itself was already refused. It is `invalid_request` before any sign-in page now. *Behaviour:* a client that sent a challenge without a method, and redeemed the code with the challenge itself as the verifier, must send `code_challenge_method=S256` and a hashed challenge; one that sent an S256 challenge without the method could not redeem its code before either.
- **The shared key's policy admits every function that reads the external blobs' credential.** With blobs on an S3-compatible store and `StorageArgs.Blobs.CredentialsRef` (such as the `external/cloudflare/<preset>` the Cloudflare module rotates), each role was granted the parameter in IAM, but `SluisKeyPolicyStatements` admitted only the roles whose own parameters held it. Under a customer-managed secrets key, the issuer and the github, google and slack functions could not decrypt the credential the Cloudflare module wrote, and an estate had to add the rows itself. `SluisKeyBlobCredentials<Role>` now allows `Decrypt` and `DescribeKey` of exactly that parameter, through SSM, for each reader whose own statements do not cover it. `KeyRole.BlobCredentialsRef` carries it, and `LambdaArgs`, `Lambda` and `RoleArgs` (`KeyPolicyStatements`, `Roles`) fill it in. *Behaviour:* the key policy grows by one statement per such reader. Remove any rows the estate added by hand for the same parameter, or keep them under a Sid of their own.
- **`hack/release-verify.sh` runs from a relative path.** It changed into the assets' directory and then called `hack/check-zips.sh` (and read `release-images.txt`) relative to `$0`, so `just release-verify` and `hack/release-verify.sh vX.Y.Z` failed at the zip check. The script's own directory, `RELEASE_VERIFY_DIR`, `RELEASE_IMAGES_FILE` and `RELEASE_ZIPS_FILE` are made absolute before the change. `just release-check` defaults `KO_DOCKER_REPO` to `ghcr.io/truvity/sluis` for the root config, which goreleaser refuses without one, and to `ghcr.io/truvity/audit` for `audit/`'s, as the release workflow sets them.

## v1.77.1-rc.1

### Breaking

- **The recovery password is no longer presented, and the service no longer reads it (layout v5).** A password in a form, a JSON body or a `Bearer` header at `<console>/login/recovery` answers `400` without being read, so the one-line `curl` runbook is gone for the password (a cluster's token keeps its bearer). The sign-in page proves the password with SRP-6a and never sends it; the service holds a salt and a verifier. On layout v5 the renderer names `recovery.verifierSecret: recovery/verifier` and no longer `recovery.passwordSecret`; the Pulumi library writes `internal/oidc/recovery-verifier` beside the password, and the issuer's role is **denied** `internal/oidc/recovery-password` and `conformance-password` (role policy and key policy). Layouts v4 and v4+v5 derive the verifier from the password in memory and are otherwise unchanged. **Consumers:** on Lambda, where recovery is on by default, the issuer's `/login` shows its chooser (the provider button and a collapsed *Password sign-in*) instead of forwarding straight to the only provider, as it already does where a cluster has recovery; the service and the library must be the same version; a password door at the issuer's own `/login` signs in as `system:serviceaccount:<ns>:<recovery.serviceAccount>` (`sluis:recovery` where there is none), so the policy needs a `service_account` matcher for it in the group the console client requires (a cluster already has the bootstrap row). [ADR 0076](docs/decisions/0076-password-sign-in-is-srp-for-recovery-and-conformance-only.md).

### Added

- **The issuer's `/login` offers a password sign-in on Lambda and in a cluster, by SRP-6a, for the recovery account and a conformance test account.** RFC 2945's protocol over RFC 5054's 3072-bit group, SHA-256 (RFC 5054 says SHA-1; the deviation, `K` and the proofs are in the ADR; Appendix B's vectors pass through the same code, and a pinned known-answer vector, computed independently, passes in Go and in the page's script). `x` is stretched with 600000 rounds of PBKDF2-HMAC-SHA256, recorded in the credential (`iterations`) and sent to the page with the salt; the salt is random and independent of the password (a salt made from it would have let anyone who starts a sign-in test guesses). The server spells the username (lower case, trimmed) and the page uses its spelling; passwords are never trimmed. `sluisctl recovery verifier` and a hub that derives a verifier from a password refuse one that is too weak (under 128 estimated bits, under 20 characters, not printable ASCII); the hub logs an ERROR at start and is not ready while its password is. A self-hosted script (`/login/srp.js`, WebCrypto and `BigInt`, no inline script) does the client half; `POST /login/srp/start` and `/login/srp/finish` the server's, with the server's `b` kept in the State for two minutes and one use (`srp.<handle>`, never backed up), so any container answers the second request. An unknown username gets a stable decoy; refusals are throttled per source as before. The recovery account keeps all its rules (operator by policy, `acr` recovery, durable audit record, the recovery switch); a sign-in by password records the method `recovery-password` and says `amr` `["pwd"]` (RFC 8176) where a recovery token's says `swk`. The **conformance** account is new: off unless `conformance.enabled`, offered only for clients the policy marks **`harness: true`** (a new client key, refused on `exchange`), holding no group (the service refuses to start if the policy makes it an operator; the console never takes it), `acr` `urn:truvity:sluis:acr:conformance`, `amr` `["pwd","conformance"]`, recorded as `roster.person.signed_in` with `how: conformance` (the catalogue is unchanged), and shut by the recovery switch as well. New keys `recovery.verifierSecret`, `conformance.enabled`, `conformance.verifierSecret`; a Lambda stack on layout v5 generates the conformance password and verifier and has outputs `RecoveryVerifierParameter` and `ConformancePasswordParameter`. `sluisctl recovery password --account conformance` reads the password, and `sluisctl recovery verifier` makes the credential of one for an installation that is not a stack. `hack/conformance_drive.py` drives the page. See [run conformance](docs/guides/sluis/run-conformance.md) and [recover on Lambda](docs/guides/sluis/operate/recover-on-lambda.md).
- **The issuer's `refused` log line says which request it refused.** It carried the reason, the status and the request id, so a run of "the authorization request was not started in this browser" could not be told apart as one broken client or a link going round. Every refusal the issuer logs (a page, a plain-text answer, an OAuth error and the library's own sentences it rewrites) now also carries `method`, `path` without its query, `client_id` when the query, an already-read form, HTTP Basic or the pending authorization names one, and `user_agent`, cut to 200 characters. A refusal that already named its client as `client` or `client_id` keeps that field and is not given a second. The query string, `state`, `nonce`, codes and challenges, the authorization request's id, cookies and tokens are never logged. See [endpoints](docs/reference/sluis/endpoints.md).

### Security

- **The issuer and the console send `Strict-Transport-Security: max-age=31536000` on a response that arrived over https.** Until now the header came from whatever sat in front; a scan found an issuer behind a zone that added none. It is sent when the connection is TLS, when the request is an API Gateway event on Lambda, or when the configured public URL is https and the request is for its host and no `X-Forwarded-Proto: http` says the front hop was plain. It is never sent over http, to `localhost`, `*.localhost` or a loopback address, and never with `preload`. A header the response already carries is kept, and no `X-Forwarded-Proto` value turns it on. `hsts.maxAge` (default `8760h`; `0s` sends none) and `hsts.includeSubDomains` (default `false`: an issuer on an apex or parent domain would otherwise pin every sibling subdomain to https) tune it, in the service document and the installation document. See [endpoints](docs/reference/sluis/endpoints.md#hardening). *Behaviour:* a browser that has seen the header uses https for the host for a year, and for every subdomain of it only with `hsts.includeSubDomains: true`; a host that cannot answer https is unreachable from it.

### Fixed

- **`sluis secrets rekey` compares keys by their resolved ARN, not their spelling.** It decided whether a SecureString was already under `secrets.kmsKeyId` by comparing strings (an alias with its alias ARN, nothing else), but SSM reports `KeyId` as it was written: an alias, an alias ARN, a key id or a key ARN. With `kmsKeyId: alias/...`, parameters reported by key ARN were taken for needing a rewrite (and with the key ARN configured, the alias-reported ones were), so the run read them with decryption, which the operator role may not be allowed, and failed after the `started` audit record. It now resolves every distinct reported `KeyId` and the configured one once per run with `kms:DescribeKey` and compares the key ARNs; `alias/aws/ssm` resolves too and is another key. A key `DescribeKey` refuses is compared by spelling, and a parameter under one that the spelling does not settle is listed as **unknown** and left alone; `--include-unknown` re-writes it. A configured key KMS does not know stops the run before anything is read. The dry run prints each reported spelling, the ARN it resolved to and how many parameters are under it, and `already under the key` counts all of them. `RekeyOperatorStatements` gains `SluisRekeyDescribeKey` (`kms:DescribeKey` on the account's keys in the region); a role built from the earlier statements needs it, or its parameters under another spelling are unknown. See [secrets](docs/reference/sluis/secrets.md#one-key).

## v1.77.0

v1.77.0-rc.2, which ran overnight on a canary installation, plus one release fix. Its notes are under v1.77.0-rc.2 and v1.77.0-rc.1 below.

### Fixed

- **The release's modules job fetches only this repository's modules directly.** `hack/build-as-consumer.sh` used `GOPROXY=direct` for every dependency, so a third-party module was cloned from its own VCS; on v1.77.0-rc.2 one such clone hung the job for two hours. Third-party modules now come through the public proxy (`GONOPROXY=github.com/truvity/sluis`), and each build and vet is held to `BUILD_TIMEOUT` (600s) so a stuck fetch fails one attempt of the retry loop.

## v1.77.0-rc.2

### Security

Fixes from the 2026-10-18 review of the issuer and its sign-in. Relying parties that behave correctly see no change; the rows marked *behaviour* are the ones that can.

- **The session service takes a bearer only from a live sign-in at the console or `sluisctl`.** `ListSessions` and `RevokeSessions` (`sluis.v1` and the legacy `accessissuer.v1`) used to accept any access token this issuer had signed, including a relying party's own, and with `groupsScoping: report` every group is in every token, so any client's token could act as an operator. The bearer is now read as the other operator endpoints read it: the access token of a client in `sluisctl`, `accessctl`, `sluis-console` or `console`, which the issuer holds a record of, under a session that is still live and is not an agent's. An ID token, another client's token, a workload's exchange and a token whose session ended are refused (`unauthenticated`). *Behaviour:* a caller that presented some other client's token to the session service is refused. The console's own cookie and in-process path are unchanged.
- **`/revoke` ends only what the authenticated client was issued.** The value is resolved as a refresh token (through its pointer) or as the id of an access token this issuer signed, and only a token whose session or record names the client that authenticated is revoked (RFC 7009 section 2.1). It no longer falls back to treating any string as a session id, which let a public client end any session whose `sid` it had seen. A token of another client is answered `200`, as a token that does not exist is, and left alone. *Behaviour:* a client that revoked a session it did not hold the refresh token for, or with another client's token, no longer does.
- **A request that repeats a security parameter is refused with `invalid_request`.** `client_id`, `redirect_uri`, `response_type`, `scope`, `code_challenge`, `code_challenge_method`, `resource`, `state`, `nonce`, `post_logout_redirect_uri` and `id_token_hint`, in the query, the body or both, on `/authorize`, `/token`, `/revoke`, `/introspect` and `/end_session` (RFC 6749 section 3.1). The checks in front of the library read the first value and the library the last. *Behaviour:* two `resource` values at `/authorize` or `/token` are `invalid_request` (they were `invalid_target`); nothing is redirected for the refusal.
- **A refreshed ID token keeps `acr` and `amr` of its sign-in.** A recovery session's first ID token carried `acr=urn:truvity:sluis:acr:recovery`; after a refresh it carried none and `amr=["pwd"]`, so a relying party that gates on the recovery class was bypassed by the first refresh. A refresh now repeats the class and `amr` the sign-in reported (`swk` for recovery, none for a directory sign-in). *Behaviour:* refreshed ID tokens of a directory sign-in no longer say `amr=["pwd"]`, which no sign-in here is; a session recorded before the sign-in method was kept (and an exchange's session) carries no `acr`, as before.
- **The token-exchange decisions the issuer holds between two library calls are forgotten after two minutes.** The per-process map grew by an entry for every exchange the process had answered.
- **A Google sign-in needs a verified address.** The ID token must carry `email_verified: true` and a `sub`. `google.oauthClient.hostedDomains` (new, optional) names the Workspace domains a person may sign in from, and the sign-in must carry an `hd` that is one of them; unset asks nothing of `hd`. Identity is still the address, because keying by Google's `sub` would orphan every existing link. See [the Google module on Lambda](docs/reference/sluis/lambda.md). *Behaviour:* an account whose address Google has not verified can no longer sign in.
- **The GitHub Actions verifier can pin the numeric ids.** `exchange.github.ownerIds` and `exchange.github.repositoryIds` (new, optional, in the policy document and the installation document) require the token's `repository_owner_id` and `repository_id` to be among them, in addition to the owner names. A login can be renamed, or taken by someone else after an organisation is deleted; an id cannot. Unset asks nothing of the id. See [policy document](docs/reference/sluis/policy-document.md).
- **Recovery refusals are counted per source.** The issuer's `/login/recovery` and the console's recovery password stop answering a source after 5 (issuer) or 10 (console) refused proofs in a minute, with `429`, and every source together after 100; a success clears its source. The console's single global counter let anyone shut break-glass out with ten wrong proofs. The source is the address the deployment's proxies vouch for (`audit.forwardedForTrustedHops` on the console; the audit middleware's address on the issuer), and the count is per process, so on Lambda it is per warm container. A new login-failure reason, `recovery_throttled`, is counted. *Behaviour:* a script that retries a wrong recovery proof more than 5 times a minute from one address is answered `429`.
- **The recovery TokenReview must report the audience it was asked for.** `kube.ReviewToken` already asked for one; it now also refuses an authenticated answer whose `status.audiences` holds none of them, as its comment claimed (a mounted token authenticates for the API server's own audience, which an API server that is not audience-aware reports as an empty list).
- **An authorization request is bound to the browser that started it.** `/authorize` sets the cookie `__Host-sluis_authreq` (`sluis_authreq` without secure cookies; HttpOnly, SameSite=Lax, 30 minutes) holding a MAC of the request id under a key derived for the purpose, at most eight requests at once. `/login`, `/login/<provider>/start`, the silent completion from a browser's sign-in, and `/authorize/callback` require it. Before, whoever opened `/login?auth=<id>` with a live sign-in completed the request as themselves: an attacker could start `/authorize`, send the victim the link, and the victim's silent sign-in completed the attacker's request, with the code going to the attacker's redirect. **Behaviour change:** a sign-in link opened in a browser other than the one that started it, or after its cookie expired or was cleared, answers `400` "This sign-in was started in another browser"; open the application again from that browser. A relying party that opens `/authorize` in one browser and hands the address to another no longer works. `prompt=none` from a browser without the cookie, such as a frame in another site, is still answered `login_required` at the client's redirect. This closes the case of a link sent to the victim. It does not close an attacker who sends the victim straight to `/authorize` with a redirect the attacker registered as a client-document client; a consent interstitial for document clients is the follow-up.
- **The issuer refuses to start with a browser session store and no sign-in state key.** The binding above and the sign-out confirmation both need the key, and without it the first would be off. `issuerapp` always sets one; `issuer.HandlerWithSignIn` and `SignInRoutes` refuse the combination, and `issuer.Handler` draws a key for its process.
- **Every response of the issuer and the console carries `Content-Security-Policy`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`.** The policy is `default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'`, so the sign-in, recovery and consent forms cannot be framed. `'unsafe-inline'` styles are for the pages' own `<style>` and the console's component library; no inline script is allowed except the consent page's own, by nonce. The recovery form and the consent page leave out `form-action`, because a browser holds the redirect back to the application to it. **Behaviour change:** a page that embeds the console or a sign-in page in a frame, or a proxy that adds its own `Content-Security-Policy`, now meets these. The console's `/assets/` directory is a `404`, not a listing.
- **Requests are bounded.** A request body over 2 MiB is refused with `413`, and a connect message over 2 MiB (the audit services: 4 MiB) with `resource_exhausted`, as is the session service's. The token endpoint's pre-read of a form is 1 MiB, down from 10. The servers hold a 10 s header, 60 s request, 20 min response and 2 min idle timeout, and a 64 KiB header block (the audit services: a 5 min response). The response timeout is long because a backup is one synchronous call of up to 16 minutes. See [endpoints](docs/reference/sluis/endpoints.md#hardening). **Behaviour change:** a client that sends a larger body, or holds a request open for over a minute, is cut off.
- **The protocol endpoints no longer reflect the asking `Origin` with `Access-Control-Allow-Credentials: true`.** `/keys`, `/userinfo`, `/token`, `/revoke`, `/end_session` and discovery answer `Access-Control-Allow-Origin: *` and never allow credentials: they are reached with a bearer, a client credential or a code, never a cookie. **Behaviour change:** a browser application that called these endpoints with `credentials: "include"` must stop doing so; it never needed to.
- **`/logout` asks before it signs anybody out.** `GET /logout` shows a page with a *Sign out* button and ends nothing, so a link, a frame or a redirect from another site cannot sign a visitor out. The button POSTs a token bound to the sign-in cookie; a POST without it answers `400` and ends nothing. A browser with no sign-in goes straight on. **Behaviour change:** the console's sign-out is one click more, and a script that POSTs `/logout` directly must fetch the page first.
- **`/end_session` no longer lets a bare `client_id` end agent-class sessions.** Agent connections survive a browser sign-out (ADR 0040); a link to `/end_session?client_id=<agent client>` ended them anyway, because the named client was never spared. Only the audience of a verified `id_token_hint` names a client now. The request still signs the browser out. Without an `id_token_hint`, `/end_session` itself remains a GET that signs the browser out, as RP-initiated logout specifies. Request bodies stay at 2 MiB for every console call: the largest, `ImportGitHubLinks`, is about 200 bytes a record.
- **Discovery says what the issuer does, and the authorization endpoint refuses what it does not.** `claims_supported` lists every claim a token carries (`auth_time`, `nonce`, `acr`, `amr`, `azp`, `at_hash`, `sid`, `given_name`, `family_name`, `preferred_username`, `client_id` beside the old list), and `response_modes_supported` is `["query"]`. `response_mode=form_post`, which the library honoured and the new content security policy broke, and `fragment` are refused with `invalid_request`; `request_uri` is `request_uri_not_supported` and `registration` is `registration_not_supported` (OpenID Connect Core 6.2, 7.2.1), in the redirect when the client registered the `redirect_uri`. `/oauth/introspect`, `/introspect` and the device authorization routes, which the library mounted and answered `{"active":false}` or an error, are `404`. RS256 stays listed while an RS256 key is published. *Behaviour:* a client that sent `response_mode=form_post` or `fragment`, or a `request_uri` or `registration` it expected to be ignored, now gets an error; a client that called `/introspect` with a client credential got `active: false` for every token and now gets `404`.
- **`/userinfo` answers a bearer failure as RFC 6750 asks.** A request with no token is `401` with `WWW-Authenticate: Bearer realm="<issuer>"` and no `error`; a token that is unknown, or whose session ended or was revoked, is `401` with `error="invalid_token"` (the library said `403` and `{}`); a failure of the issuer's own store stays a `5xx`. `access_token` in the URL query is refused with `400 invalid_request` (RFC 9700 4.3); the `Authorization` header and the form body of a `POST` are unchanged. *Behaviour:* a client that sent the token in the query must use the header.
- **An `id_token_hint` is answered only by the person it names.** A browser signed in as someone else is not completed silently: `prompt=none` is `login_required`, otherwise the person signs in again, and a sign-in that is still not the hinted person is refused to the client as `login_required`, not completed as them (OpenID Connect Core 3.1.2.1).
- **A native client's loopback redirect may differ from a registered one in the port only.** The library compared path and query alone, so `https://localhost:1/cb` matched a registered `http://127.0.0.1/cb`. Scheme, path and query are compared now, the host must be `127.0.0.1`, `[::1]` or `localhost` (not another 127.x address or an IPv4-mapped one), and the port a number (RFC 8252 7.3). `policy/compile` `ValidateURLs` refuses an `http://` redirect or landing page that is not on a loopback address (`::1` counts as one). *Behaviour:* a native client that registered `http://127.0.0.1/cb` and asked with another scheme is refused.
- **A Client ID Metadata Document that declares anything but `none` is refused.** `token_endpoint_auth_method` of `client_secret_*`, `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth` or any other value, or a `client_secret`, makes the document invalid instead of being ignored: a document client is public, and the issuer holds no secret, key or certificate for it.
- **The back-channel logout token carries `exp`,** two minutes after `iat` (Back-Channel Logout 1.0 2.4 requires it).
- **`/end_session` asks before it signs anybody out, unless its `id_token_hint` names the person this browser is signed in as.** `GET` shows a page with a *Sign out* button, naming the application when `client_id` is a declared client, that keeps the request's `client_id`, `post_logout_redirect_uri`, `state` and hint and ends nothing; the button `POST`s a token bound to the sign-in cookie, and a `POST` without it answers `400` (RP-Initiated Logout 1.0 2). A hint of anyone else, expired or not, no longer ends a victim's sign-in: it gets the page. The hint's `sub` is read before its signature is checked only to decide whether to ask; the library verifies it before anything ends. A browser with no live sign-in is not asked, and a deployment with sign-ins and no confirmation key answers `503`. A `post_logout_redirect_uri` the client did not register is refused before the page, and a native client's loopback one may differ from a registered one in the port only (RFC 8252 7.3). *Behaviour:* a sign-out chain that ends at `/end_session` with no hint, or with a hint of another person, such as an oauth2-proxy `rd` with `client_id` only, shows the page and waits for the click; send the person's own `id_token_hint` to skip it.

Audit pipeline, Cloudflare minter, client documents and `sluisctl`, from the same review:

- **The audit writer stamps what arrives on a queue from what SQS sets.** The writer Lambda and a writer that consumes `consume.sqs` kept the `observer`, `recorded_at` and `origin_hash` of a message body when the hash still described it. The hash proves the record is unedited, not who stamped it, and SQS delivers what its sender chose, so any principal allowed to send could attribute a record to another observer and back-date it. The stamp is now made from the two things SQS sets and the sender cannot choose: `recorded_at` is the message's `SentTimestamp`, and the observer is what the message's `SenderId` maps to in the new optional `senders` table of the writer Lambda's file and of `consume.sqs` (the unique id of the role, `AROA...` from `aws iam get-role --query Role.RoleId`, or a whole `SenderId`; a role ARN is not accepted, because a message carries the id and not the ARN). A sender not named, or no table, is recorded with no observer id, as before. A NATS consumer still keeps the receiver's stamp. This is a fix of the code to what [the SQS path](docs/concepts/audit/authn-authz.md#on-the-sqs-path) always said (records on the queue are attributed to the writer, not to the sender), not a change for a deployment that relied on the doc; one that relied on the old behaviour to keep a receiver's verified observer through SQS loses it, since the receiver's stamp was never verified by the writer.
- **A record is held to the source its caller is listed for.** When the writer's workloads file lists workloads, `SinkService.Write` refuses, by id, a record whose `source` is not the one the verified caller (issuer and subject) maps to, and a caller not listed writes nothing; the rest of the batch goes on. Before, any caller whose token verified could write a record of any source whose catalogue was known. The refusal is logged (`caller`, `source`). Tenant and actor are not bound: the file carries neither. *Behaviour:* a deployment that lists some workloads and sends from an unlisted service account, or one with a record of another source, now gets `rejected` entries; list the account with its source. A deployment that lists none, or accepts anonymous writes, is as before.
- **A refused audit read is recorded.** `Search`, `Facets`, `Get` (and `Resolve`, and a refused `Tail` ordering) answered a denied caller and left no record, contrary to `SECURITY.md`. They now record `audit.search`, `audit.facets`, `audit.get` or `audit.pseudonym.resolved` as a failure whose reason is the refusal. The same caller refused the same way is recorded once a minute, so a loop of denied calls cannot flood the trail. The dedupe key is the issuer, the subject and the action, plus the profile only when the caller's own grants name it: the profile and the record id a refused caller asks for are its own to choose, so they are in the record and not in the key. A caller occupies at most 64 keys, the table 4096, and the reason and ids written are cut. Only an authorization refusal is recorded, not a failure of the authorizer.
- **An export is collected by the issuer and subject that asked for it, while they may still export.** `GetExport` compared the subject alone; a job now remembers the issuer (`by_issuer`; jobs written before are held to the subject until they expire) and the caller's current `export` grant on the profile is checked again. Issuing the link is recorded (`audit.export.completed`, the collector as the actor) before the link is returned, and no link is issued when it cannot be. CSV cells beginning with `=`, `+`, `-`, `@`, a tab or a carriage return are written with a leading `'` so a spreadsheet does not run them. *Behaviour:* an export whose asker lost the grant is no longer collected, and a CSV opened as data shows a quote before such a cell.
- **`auth.Effective` no longer lends a time window to another tenant.** A time-boxed grant over one tenant, unioned with an unbounded grant over another, read as both tenants for every period. A grant that another covers (its tenants over its window) is now set aside, and the grants that remain must share one window or the request is `denied`. *Behaviour:* a caller holding a time-boxed grant over one tenant and an unbounded grant over another on the same profile and operation is refused, where it was read as both unbounded. Give the second grant the same window, or widen the first.
- **The Cloudflare minter caps what it mints on demand, and a preset can name the permission groups it is for.** Per preset, `maxLivePerCaller` (default 10), `maxLive` (50) and `maxMintsPerCallerPerHour` (30), counted from the names of the tokens Cloudflare lists as live and from what this process minted, so they hold across replicas and invocations as soft caps: each process counts the list Cloudflare gave it up to 10 seconds ago plus its own mints (in flight ones included, one admission at a time), so replicas and Lambda containers can overshoot together, and a list that fails fails the mint. A mint over one is refused (`ErrLimit`; audited as `roster.cloudflare.token.refused` with the reason `caller_cap`, `preset_cap` or `rate_limited`; the exchange answers `access_denied`, the console `resource_exhausted`). `allowedPermissionGroups` (new, optional, per preset) limits the prototype to the groups it names; the built-in forbidden list stays the floor and a name does not lift it. See [Cloudflare tokens](docs/guides/sluis/cloudflare-tokens.md). *Behaviour:* an on-demand loop beyond the defaults is refused; raise the limits on the preset. Unset `allowedPermissionGroups` asks nothing new. A mint now costs one more call to Cloudflare, listing the account's tokens.
- **Client documents and back-channel logout connect only where they should.** A client document is fetched with a dialer that refuses loopback, private, link-local (the metadata services), carrier-grade NAT and reserved addresses where the socket connects, after the name resolves, so a host that answers a public address to a lookup and a private one to the connection is refused. IPv6 is held to `2000::/3` after IPv4-mapped, NAT64 and 6to4 addresses are judged by the IPv4 address they embed, which refuses `::/96`, Teredo and the other odd ranges. It uses no proxy from the environment and follows no redirect. A failed fetch is remembered for a minute and answered again unasked, and one host is fetched from at most 30 times a minute whatever the ids, which can delay an uncached legitimate document of a busy host. The back-channel logout post follows no redirect and refuses loopback and link-local; private ranges stay allowed because the policy may declare a service in the cluster. `allowInsecure` lifts both guards only together with an issuer URL on loopback; `allowInsecure` alone, which a production document can set, lifts nothing. A document's `client_name` is cleaned as a declared client's display name is held to: no controls, bidirectional overrides or formatting characters, cut to 64 characters on a character boundary. See [endpoints](docs/reference/sluis/endpoints.md#hardening). *Behaviour:* a document on a private or loopback address is refused; a corrected document is picked up up to a minute after a failed fetch; a deployment that reached the fetch through `HTTPS_PROXY` no longer does.
- **`sluisctl` refuses an `http://` issuer except on loopback, and its login callback ignores a request without the state.** An issuer from `--issuer`, `$SLUISCTL_ISSUER` or `config.yaml` must be `https://`; `http://` is accepted for `localhost`, `127.0.0.1` and `::1`. The loopback listener of `sluisctl login` ended the sign-in with an error on any `?error=` and on a wrong `state`, so anything that could reach the port could abort it; it now answers `400` and goes on waiting unless the state matches (compared in constant time), and the issuer's own refusal, which carries the state, still ends it.

Infrastructure-library findings of the 2026-10-18 audit (A2, A5 bucket side, B4, and the C items on trust and configuration), in `deploy/pulumi`, `audit/deploy/pulumi` and the shared `artifact` package.

- **The control plane of a KMS key is the administrators' alone (A2).** A key policy that gave the account root `kms:*` or `Create*`/`Put*` handed `kms:PutKeyPolicy` and `kms:CreateGrant` to every IAM principal with such an allow (a power role, a controller role, the StackSet roles), and any of them could rewrite the policy, decrypt the wrapped signing keys and forge tokens, or give itself `kms:Sign` on the seal key and forge audit seals. `SluisKeyPolicyStatements` ends with `SluisKeyControlPlaneAdmins` (an allow of `kms:PutKeyPolicy`, `kms:CreateGrant`, `kms:ScheduleKeyDeletion`, `kms:DisableKey` and `kms:RevokeGrant` to the administrators) and `SluisKeyControlPlaneAdminsOnly` (a deny of the same five to every other principal, AWS services acting on their own excepted); the data-plane statements are unchanged byte for byte. `SealKeyPolicy` no longer lets the root `Create*`/`Put*`/`Delete*`/`Update*`/`Revoke*`/`Disable*`, allows the control plane to the administrators only, and denies `kms:Sign` to every principal but the notary (`NoSealButTheNotary`); `DigestKeyPolicy` replaces the root's `kms:*` with `kms:Sign`, `kms:Verify` and the upkeep, and holds the control plane the same way. The remote signing keys and the wrapped signing key that the library creates carried the default policy (`kms:*` to the root) and now carry the same statements. The comment that said the administrator cannot use the key is corrected: the administrator could, by changing the policy first. New exported `KeyControlPlaneActions`, `KeyControlPlaneStatements`, `KeyControlPlaneDeny` and `CheckKeyAdmin`.
- **An administrator, break-glass or operator role is one role (C).** `KeyPolicyArgs.Admins`, `Breakglass` and the new `KeyAdmins` are role ARNs: the account's root, a user, a wildcard account, a bare `*` and `role/*` are refused. The one wildcard kept is the hash of an SSO role's name (`AWSReservedSSO_Admin_*`, at least four literal characters) and the region of an SSO role's path. `ExternalReaderRoleArgs.TrustPrincipalArn` refuses the account's root (it was an "exact" ARN and the widest principal there is). `RestoreInvokers` now refuses what its message said it refused: `role/*` and `?` passed because only `*` as a whole was caught. `Observe.TrustedPrincipalArn` refuses the account's root, wildcards and session ARNs, and requires `Observe.ExternalID` when the principal is in another account than the archive's.
- **Every SecureString is encrypted with the installation's key (A1 library side, A2).** The state secret, the recovery password and the restore identity fell back to the AWS-managed key `alias/aws/ssm` when `Keys.Secrets` and `ParameterKeyArn` were empty, and so did every parameter the services write (the module documents then had no `secrets.kmsKeyId`): any role with `ssm:GetParameter` could decrypt them, which is why 35 of the installation's parameters were on `aws/ssm`. `LambdaArgs` and `BackupCommon` refuse to build without a customer key; the key is the `secrets.kmsKeyId` of every function's document, and a module document the estate writes (`Modules[<role>].Document`) must name it. This change does NOT rewrite the parameters that exist: those on `alias/aws/ssm` stay there until `sluis secrets rekey` or a rotation writes them under the key. A module document the estate writes is compared with the key id as text (`Keys.Secrets` is an alias, `ParameterKeyArn` an ARN): write the same form the library holds.
- **The archive's lock is the break-glass roles' alone (A5, bucket side).** The backup archive bucket's policy (and the `ArchiveBucketPolicy` output for a bucket in another account) and the audit archive buckets' policies deny `s3:BypassGovernanceRetention`, `s3:DeleteObjectVersion` and `s3:PutBucketObjectLockConfiguration` to every principal but the break-glass roles. The audit writer's put into `records/` is allowed only with `s3:if-none-match: *`, which the store sends on every put: a record can be added and never replaced, whether or not the bucket has Object Lock. `s3:PutObjectLegalHold` stays on the writer (it places the hold on the record of a held tenant).
- **Release digests are verified (B4).** `Release.ResolveChecksums` (and the digests the libraries resolve for the library's own release) read `checksums.txt` only after verifying it against `checksums.txt.sigstore.json` with sigstore-go: the certificate must be Fulcio's, issued by GitHub's OIDC issuer to the release workflow of `truvity/sluis` at exactly the tag of the release, with a certificate timestamp and a Rekor entry (what `hack/release-verify.sh` pins). A replaced release page or a mirror can no longer supply both the zip and its digest. `LambdaArgs`, `BackupCommon` and the audit `Args` take an optional `CodeSigningConfigArn`, and `artifact.NewCodeSigningConfig` makes the Lambda code signing configuration. `Release.TrustedRootJSON` supplies a pre-fetched Sigstore trusted root for a mirrored or air-gapped estate.
- **The schedulers' trusts name their schedule group (C).** The scheduler roles' trust policies carried `aws:SourceAccount` alone (the audit scheduler's carried nothing): any schedule of the account could ask the role to invoke its aliases. They now also carry `aws:SourceArn` of the schedule group the installation's schedules are in (`arn:aws:scheduler:<region>:<account>:schedule-group/default`). EventBridge Scheduler presents the group's ARN and not the schedule's (AWS, "Confused deputy prevention in EventBridge Scheduler"), so a condition on a schedule or a name prefix would never be true.

Backups, from the same review (finding A5, decision D682):

- **A restore proves a backup is the one the backup function made, against the sealed audit trail.** A backup is age-encrypted to public recipients with an unsigned sidecar, so anyone with `PutObject` on `backup/<instance>/` could plant one that a restore accepted, and a restore writes every module's table. `roster.backup.completed` now carries the object's key, size and SHA-256, the sidecar's SHA-256 and the SHA-256 of each recipient (catalogue 1.21.0, `object_key`, `object_size`, `object_sha256`, `sidecar_sha256`, `recipients`). Before it reads the identity, a restore (`sluis restore preview|start`, the `{"kind":"restore"}` event, `restore.preview`) asks the audit query service for the record and requires that it exists, that a record was stamped by the backup function's observer (another observer's record is ignored and logged, so a junk record cannot make a backup unrestorable), that every such record of the backup agrees (all pages of the search are read; more than 200 records refuse it), that its hashes, key, size and recipients are those of the fetched backup, and that the hour holding it is sealed. Otherwise it is `refused` with the reason `unverified`. It is configured in the restore document: `backup.verify.query` (https, or http on loopback), `tokenFile`, and `observer` (the id the audit writer stamps on the backup function's records) or an explicit `anyObserver: true`, which lets any sender of audit records vouch for a backup and logs a warning at start; see [backup](docs/reference/sluis/backup.md#provenance). A restore that paused is continued against the hashes it began with. **Behaviour change:** a restore depends on the audit pipeline. With `backup.verify` unset, with the query service unreachable, with the record lost in delivery, or for a backup made before this release (its record has no hashes), a restore is refused until `--allow-unverified` is passed. A backup is restorable once the notary has sealed the hour of its record, up to about an hour and a quarter after the run. The deployment library does not render `backup.verify` yet: a Lambda restore needs `allowUnverified` until it does. Not checked yet: the signature of the seal (`audit verify --root` does), and that the seal covers the record's object, not only that a seal exists for the hour.
- **`--allow-unverified` (event field `allowUnverified`) goes ahead without the record, for the day the audit pipeline is down, and is itself kept in the trail first.** It covers a backup with no record, an hour not yet sealed, and a trail that cannot be asked. It never covers a record that disagrees with the backup (`mismatch`), which is evidence of tampering. It needs `backup.recipients`. The new action `roster.restore.unverified` (catalogue 1.21.0, delivery `block`, with the reason and the caller's own `by`) is written before the restore begins, and the restore is refused as `unaudited` when it cannot be, unless `--allow-unaudited` (`allowUnaudited`) is also passed, which logs the detail at error level instead; with no audit trail connected the decision cannot be kept either. The caller's `by` is limited to 256 bytes and cleaned of control characters. `roster.restore.started` and `.completed` carry `unverified` and `verification`. A run begun by an earlier release, continued with the flag, is pinned to the bytes verified then. A preview with the flag is logged, not recorded. `sluis backup verify` now says it does not check provenance.
- **A restore compares the sidecar's recipients with `backup.recipients`.** When the restore document lists recipients, a backup whose sidecar lists any other set is refused (`recipients`), and no flag overrides it. This catches a backup written before the recipients changed. It is not a defence against forgery: the recipients are public keys, and a forger lists them. An unverified restore without `backup.recipients` is refused. *Behaviour:* after the recipients change, an older backup is refused until the earlier list is set.
- **The audit record builder no longer drops a value of a type it does not know.** An `int64` was dropped without a word, so `roster.backup.completed` never carried `records`. It now carries it, and an unknown type is logged at error level and recorded as text; a test fails any constructor that builds one.
- **A code issued against a PKCE challenge is redeemed with its `code_verifier`, whatever the client.** The OpenID library asked for the verifier only of a client that authenticates with nothing, or when one was sent, so a confidential client that had sent a challenge could drop the verifier and redeem the code with its secret alone. A token request for such a code without a `code_verifier` is now `invalid_grant` (RFC 7636 4.6); one with a verifier is judged as before, and a code issued with no challenge to a client that does not require PKCE is unchanged.

### Breaking

- **`SluisKeyPolicyStatements`, `KeyPolicyOptions` and `RoleArgs.KeyPolicyStatements` need `KeyAdmins` or `Breakglass`**, role ARNs: a policy with no administrator could not be changed again. Name the role that applies the stack and the break-glass role. The estate's own root statement should delegate the key's upkeep and no longer `kms:*`; the new statements deny the control plane to the rest. The role that applies the stack must ALREADY be in `KeyAdmins` or `Breakglass` (or matched by a pattern in them) when the first apply with the new policy runs: the stack is the one that calls `PutKeyPolicy`, and the new Deny refuses it otherwise, leaving only the account root's break-glass path. `Admins`, `Breakglass` and `KeyAdmins` accept role ARNs only: a pattern that named an account, a user, `role/*` or the root is refused.
- **`auditpulumi.SealKeyPolicy(root, notary, admins)` returns `(string, error)`** and `DigestKeyPolicy(account, admins)` returns `(string, error)`; `DigestKeyArgs.KeyAdmins` is required. The key policies change on the next apply (a `PutKeyPolicy` by the role that applies the stack, which must be an administrator).
- **`LambdaArgs.KeyAdmins` is required while the library creates a KMS key** (the deprecated `Keys` nil path), and refused with `Keys`.
- **A customer key for the secrets is required:** `LambdaArgs.Keys.Secrets` or `ParameterKeyArn`, and `BackupCommon.ParameterKeyArn` (backup and restore). The estate passes its secrets key alias.
- **`Archive.BreakglassRoleArns` is required** with `BackupCommon.Archive.Create` and with a bucket the audit library creates or adopts (`AuditArchiveArgs.BreakglassRoleArns` for the installed audit); refused where the audit library manages no bucket. The role that applies the stack must be in it, as it changes the lock configuration.
- **`ArchiveBucketArgs.Mode` is required with `Archive.Create`.** Empty was GOVERNANCE and is now refused: COMPLIANCE cannot be undone, and a default must not move the lock of a bucket that exists. Say `GOVERNANCE` (what a bucket made before this release has) or `COMPLIANCE` with `AcknowledgeCompliance`.
- **`Release.ResolveChecksums` verifies the signature,** and needs `checksums.txt.sigstore.json` beside `checksums.txt` (a mirror copies it) and Sigstore's trusted root at deploy time. `Release.UnverifiedChecksums` keeps the old behavior; `artifact.ResolveSHA256` takes the `*Release`. The three modules that import `artifact` gain sigstore-go and its dependencies.
- **`Observe.TrustedPrincipalArn` from another account needs `Observe.ExternalID`,** and `RestoreInvokers` and `ExternalReaderRoleArgs.TrustPrincipalArn` refuse the forms above. `NewAudit` looks up the account (and, with the notary, the region) when `AccountID` and `Region` are empty.

### Removed

- **The old `access-roster` packages are retired and deleted from GitHub Packages (2026-10-18).** The release workflow no longer publishes the build a second time as `@truvity/access-roster`. Deleted: the containers `ghcr.io/truvity/access-roster/{access-issuer,github-roster,slack-roster,resource-proxy,access-roster}`, the chart `oci://ghcr.io/truvity/charts/access-roster` and the npm package `@truvity/access-roster`. Use `ghcr.io/truvity/sluis/{sluis,resource-proxy}`, `oci://ghcr.io/truvity/charts/sluis` and `@truvity/sluis`. See [0035](docs/decisions/0035-renamed-to-sluis.md).

### Changed

- **The conformance harness runs against an installation on AWS Lambda.** `hack/conformance-plans.sh` reads the four client secrets from SSM (`SECRETS=ssm`, `INSTANCE`) and takes the suite's address from `SUITE`; `hack/conformance_drive.py` signs in with the recovery password (`RECOVERY=password`, `RECOVERY_PASSWORD_CMD`) and no longer needs a kube context for it. The Kubernetes names stay the defaults. `hack/conformance-config.sh` stops the suite and exits 0 when it finishes. See [run conformance](docs/guides/sluis/run-conformance.md).

### Added

- **An operator can turn the recovery sign-in off from the console, and only off.** Settings gains a *Recovery sign-in* section with a **Disable recovery** button, shown to an operator who signed in through the identity provider while recovery can be used, with a confirmation. `sluis.v1` and `directoryroster.v1` `AccessService` gain `GetRecovery` (operator) and `DisableRecovery`. The server refuses a recovery sign-in (the console's or the issuer's), a workload, an identity with no address, a viewer and an operator of one directory. Nothing turns recovery on again from the console, the API or `sluisctl`: that is a change of the configuration. The turn-off is the State record `rec.recovery.off` (kind `recovery`, oidc table, permanent), a set of the `recovery.generation` values disabled that only grows, so a cold start or a redeploy of the same document stays off, a disable from a container on an older generation cannot re-enable a newer one, and a generation never disabled turns recovery back on. Every container reads the record at most every 3 seconds. Once off, the console's recovery page and post, the issuer's recovery form and post, a recovery sign-in cookie, an access token minted under a recovery sign-in (the new private claim `sluis_recovery`, read by `identity.Verified.Recovery` and checked by the console), a code or a refresh token from a recovery sign-in are all refused, and the sweep that follows ends the recovery sign-ins, revokes the client sessions and sends back-channel logout to the clients that declare one. A State that cannot be read refuses recovery and ends nothing; a State that does not support the record (legacy) has no switch. An access token a resource server verifies offline lives out `lifetimes.token`. An address a gateway puts in `login.forwarded.emailHeader` is now the source `forwarded-header` and cannot turn recovery off. `DisableRecovery` works while the oidc table is under maintenance. A backup does not carry the record and a restore does not write it. The legacy State adapter cannot keep it and refuses the action. Catalogue 1.22.0 adds `roster.recovery.disabled`, recorded durably after the switch with the counts; if the trail is down the disable stands, the service logs an ERROR and the response says the record is pending. New optional key `recovery.generation` (string, default `""`); consumers need render nothing to adopt this release. See [turn off recovery](docs/guides/sluis/operate/turn-off-recovery.md) and [ADR 0075](docs/decisions/0075-recovery-is-turned-off-from-the-console-and-on-by-configuration.md).
- **A client can be made PKCE-required: `clients.<name>.pkce` (`required` or `optional`).** A public client has always needed a PKCE challenge, and a confidential one could leave it out. `pkce: required` on a confidential client refuses `/authorize` without an S256 `code_challenge` (`invalid_request`, before any sign-in page, as for a public client) and a code redeemed without its `code_verifier` (`invalid_grant`), as OAuth 2.1 and RFC 9700 2.1.1 ask of every client; `plain` stays refused for all. A public client is always `required`: declaring `optional` on one, any value but the two, or any value on an `exchange` client fails the load. Absent is `optional` for a confidential client, so **nothing changes unless you declare it**, and the OpenID Basic OP conformance clients, which send no challenge, stay as they are. A client that describes itself by document is public and unchanged. The field is in the policy digest, the JSON schema, the generated policy reference, the access document (`pkce` on a client) and `compile.AudienceClient.PKCE`. Declare `required` on every confidential client other than the conformance ones. See [PKCE](docs/reference/sluis/policy-clients.md#pkce).

## v1.77.0-rc.1

### Breaking (chart)

- **Breaking: `renders: dashboards` renders grafana-operator objects, not ConfigMaps for a sidecar.** It renders one `GrafanaFolder` (`sluis`, under the cluster's folder) and a `GrafanaDashboard` for each of `sluis-overview` and `audit-overview` (the audit trail's, in the same folder), in the release's namespace. `dashboards.namespace`, `folder`, `sidecarLabel`, `sidecarLabelValue` and `labels` are gone, and `dashboards.clusterFolderUID` and `dashboards.datasources.{metrics,logs}` are required. The estate must: delete the `grafana-dashboards-app` and `access-roster-alerts` Argo CD apps; install a dashboards release and an alerts release (`renders: alerts`) in the namespace `sluis` of the cluster that holds Grafana, with the cluster's folder uid and the Grafana's datasource uids; and set `alerts.namespaceLabel: k8s_namespace_name` with `alerts.namespace: lambda` for the Lambda function's series. See [Install telemetry](docs/guides/sluis/operate/install-telemetry.md).
- **Breaking: the `AccessRoster...` alerts are retired, with the old access-roster dashboard.** Every rule is the `Sluis...` one only (11 rules, one group `sluis`), including `AccessRosterNoSigningKeyPublished`, which is `SluisNoSigningKeyPublished`. A route, a silence or an inhibition on an `AccessRoster...` name must move. `charts/sluis/dashboards/access-roster-overview.json` and its generator `hack/dashboards/access-roster-overview.py` are deleted; `sluis-overview.json` is now edited by hand.

### Added

- **`sluisctl backup run|status|list` and `restore preview|status` go through the issuer, with the sign-in `sluisctl login` holds.** The issuer forwards them to the backup module over the transport the installation already uses, as the caller class `console`; no AWS credentials are needed. `sluisctl backup run` then reads the status until the run ends (`--no-wait` skips that). The console's `BackupService` gains `RunBackup` and `GetRestorePreview` (under `sluis.v1` and the legacy `directoryroster.v1`), and accepts the access token of a live `sluisctl` sign-in as a bearer for that service only: the issuer holds a record of the token, the session is live and not an agent's, and an ID token or another client's token is refused. Who the token names is asked of the directory and the policy as for a browser session. `RunBackup` needs a group that the policy's new `backup.runGroups` names (unset lets nobody; the operators group is not implied), starts the run asynchronously and answers at once (`started`, or `contended` while a run goes or after the same person's last start), is refused while the backup module is under maintenance, and is recorded by the existing `roster.backup.completed` and `.failed` actions with the person as the actor. `GetRestorePreview` is the operator's and answers counts per module and section, never a record's name. The backup module's `backup.run` now also admits the `console` class (`RunRequest` gains `by`, believed from that class only), and the restore function registers `restore.preview` for `console`, `admin` and `breakglass`. `restore start` and `restore resume` stay direct, with the caller's own credentials, so a restore works when the issuer is broken or lost. See [backup: routes](docs/reference/sluis/backup.md#routes).
- **The issuer serves `/.well-known/sluis-configuration` to a person signed in at `sluisctl`, and answers `404` to everyone else.** The document holds `issuer`, `instance`, `backup.endpoint`, `restore.endpoint` and `region`; an endpoint is a URI whose scheme names the transport, and `arn:aws:lambda:<region>:<account>:function:<name>` is the only one `sluisctl` reaches (`k8s://` and `https://` are reserved). A function named by a bare name, or by a cluster URL, is not listed. `sluisctl login` saves it in `backup:` of `config.yaml` as `endpoint`, `restoreEndpoint`, `instance` and `region`. See [discovery](docs/reference/sluis/backup.md#discovery).
- **`sluisctl backup` and `restore` take `--issuer`, `--endpoint` and `--direct`.** The endpoint is, in order: `--endpoint`, `$SLUISCTL_BACKUP_ENDPOINT` or `$SLUISCTL_RESTORE_ENDPOINT`, the issuer's live document, the copy saved at login; for the commands that may fetch, a failed fetch says so on stderr and uses the saved copy. `restore start` and `restore resume` never read the issuer's document: the target is `--endpoint`, the environment or the copy saved at login, and `restore start --confirm` is held to `--instance` or the instance saved at login. An endpoint scheme `sluisctl` cannot reach is a usage error. `login` also keeps the access token that comes with the code, so the first command presents it instead of spending the refresh token.
- **`backup.runGroups` in the policy document** names the groups whose holders may start a backup through the issuer. It is held to the policy's groups. See [policy](docs/reference/sluis/policy.md).
- **Trace sampling is set by the standard OpenTelemetry variables; the default is unchanged.** `OTEL_TRACES_SAMPLER` and `OTEL_TRACES_SAMPLER_ARG` name any of `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off` and `parentbased_traceidratio`, and replace the built-in default (`parentbased_always_on`, every root trace kept). All AWS SDK spans are kept; sampling is the lever for volume. A test covers a rate of 0 (a root is dropped, a child of a sampled remote parent is kept) and the default. Log lines keep `trace_id` for unsampled traces and carry `trace_flags`, so a Grafana derived field can link only sampled ones. See [Telemetry](docs/reference/sluis/telemetry.md).
- **AWS SDK calls are spans and client metrics.** Every AWS client (DynamoDB, S3 and R2 blobs, SSM, KMS, STS, SQS, Lambda invoke; the audit module's too) is built with `awsotel.Providers()` (`storage/awsotel`), which gives it the SDK's own OpenTelemetry adapters, `smithyoteltracing` and `smithyotelmetrics`, over the process's global providers. Each call is a child of the span in its context: `<Service>.<Operation>` with ten child spans (serialize, resolve, sign, send, retry attempts), so expect about eleven spans per call and one more per retry. Sampling is unchanged. The span allowlist gains `rpc.system`, `rpc.service`, `aws.request_id` and `http.status_code`; the endpoint and peer attributes stay out. A test fails when a `NewFromConfig` does not use the helper. See [Telemetry](docs/reference/sluis/telemetry.md).
- **The Lambda server span carries `faas.invocation_id`** (the Lambda request id, OpenTelemetry semantic convention) on module calls and API Gateway requests. The `traceparent` was already continued; X-Ray is not enabled.
- **Backend log lines carry the trace context: `trace_id`, `span_id` and `trace_flags` (W3C hex).** `telemetry.LogHandler` adds the three fields to every record logged with a context that holds a valid span, and nothing to a record without one. It wraps the JSON handler of the Lambda functions (`lambdaapp.Logger`), the Kubernetes services (`module.Logger`) and the resource proxy; stdout stays the only sink and there is no OTel logs SDK. sloglint's `context: all` already requires the `...Context` variants. The Lambda logger's comment no longer says the OTLP layer collects function logs: it forwards only platform events. See [Install telemetry](docs/guides/sluis/operate/install-telemetry.md).
- **`alerts.namespaceLabel`** (default `namespace`) names the label that carries the namespace on the series the rules read, so one rule set serves both the pods' series and the Lambda function's (`k8s_namespace_name="lambda"`).
- The dashboards are `uid`-scoped to the cluster (`<clusterFolderUID>-sluis-overview`, `<clusterFolderUID>-sluis-audit`, at most 40 characters), with `allowCrossNamespaceImport`, the shared Grafana's `instanceSelector` by default and Argo CD sync waves 0 (folder) and 1 (dashboards).

### Changed

- **Signed in, `sluisctl backup run|status|list` and `restore preview|status` go through the issuer instead of invoking the functions.** Pass `--direct` for the old behavior, with your own AWS credentials. `--endpoint`, `--function`, `--profile`, `--region` and `--as breakglass` imply it, and so does having no login. A script that relied on a login being ignored here, and that is not granted a group in `backup.runGroups` (for `run`), now exits 4. `--json` of `backup status` through the issuer reports the last prune's counts, not the ids of the backups it removed.

### Deprecated

- **`--function`, `$SLUISCTL_BACKUP_FUNCTION`, `$SLUISCTL_RESTORE_FUNCTION` and the `function` and `restoreFunction` keys of `backup:` in `config.yaml`** are the old names of `--endpoint`, `$SLUISCTL_BACKUP_ENDPOINT`, `$SLUISCTL_RESTORE_ENDPOINT`, `endpoint` and `restoreEndpoint`. They still work, as an `arn:` endpoint or a bare function name; `--function` warns on stderr.

### Fixed

- **The KMS sign call runs under the request's context.** `kms:Sign` was called with a fresh background context, so its span started a new trace instead of being a child of the request. The signer now passes the request's context (keeping the sign timeout) to the KMS client. Startup adoption of a key and a warning log in the key ring keep a background context: neither is on a request path.
- **The backup and restore roles' inline policies stay under IAM's 10,240 characters for a long instance name.** The cross-grants were five statements per kind, one per module, and the policy grew with the instance name (every ARN carries it): the restore role passed the limit at an instance name of about 6 characters, the backup role at about 9. A grant on several modules is now one statement per kind (`SluisCrossTable`, `SluisCrossParameters`, `SluisCrossBlobs`, `SluisCrossBlobList`) with the modules in its resource list; the permissions are the same, and a grant on one module (the issuer's) keeps its `SluisCross<Module>...` Sids. For a 32-character instance name the restore policy goes from 11,519 characters to 8,623 and the backup policy from 11,414 to 9,170. A test renders both roles for such a name and checks the limit. The role policies change once on upgrade; a tool that matches the `SluisCross<Module>Table` Sids of these two roles matches the new ones.
- **The module roles' blob grants follow `BackupArgs.BlobPrefix` (`ports.blob.s3.prefix`).** The runtime puts the prefix before every key (`<prefix>/github/reports/`), but `SluisCross*Blobs`, `SluisCross*BlobList` and the role's own blob statements named `github/*` without it, so an installation with a blob prefix was denied. `ModuleEnv.BlobKeyPrefix` carries it, and the backup and restore roles set it from the plan. A test renders the policy with a prefix and checks that the bare module prefix is no longer granted.
- **The resource proxy's audit line cleans every caller-supplied string where it writes it (CodeQL #111's pattern).** `internal/resourceproxy/audit.go` logged `rec.method` and `rec.tool` as they were recorded, relying on the parser having cleaned them. The writer now strips line breaks and control characters and caps the length, as it already did for the path, subject, email, name and client. The helper `internal/modcall` added in v1.76.6 (`logValue`) moved to the shared `internal/logsafe` package and both packages use it.
- **A supplied verify-only key is the estate's kind of key: ECDSA on P-384, or RSA of 2048 bits or more.** v1.76.5 made `deploy/spec.CheckVerifyKey` call the issuer's `ParseVerifyOnlyKey`, which took ES256, ES512 (P-256, P-521 keys) and RSA of any length. The parser now refuses an EC key on any curve but P-384 and an RSA key under 2048 bits, in every encoding (PUBLIC KEY, RSA PUBLIC KEY, certificate, JWK), and `signingKey.verifyOnly[].alg` is `ES384` or `RS256` in the schema. `deploy/pulumi`'s `LambdaArgs.VerifyOnly` check holds the same rule, and the agreement test between `deploy/spec` and the issuer still holds. RSA of 2048 bits or more stays accepted: the previous issuer's RS256 key (relying parties such as Kargo pin it) is published as verify-only for the overlap of a cutover, as the estate's installations do. That key is the old issuer's own pair, not a third party's. A P-256 or P-521 verify-only key now stops the start and the render.

## v1.76.10

### Added

- **`config.MarshalInstallation` writes the installation document in one canonical form, and `config.CheckInstallation` compares a committed file with it.** The form has `apiVersion` first, every other key sorted, a two-space indent, block style and durations as `1h` or `15m` (the access tables' `1h0m0s` too). Unset fields and empty lists are left out; a section that is set but empty is kept. `MarshalOptions.Header` is a comment block the caller owns. An installation that the loader or `Render`'s checks would refuse is not written, so the output always loads, and loading it gives an installation that writes the same bytes. `CheckInstallation` returns whether the file is equal and a line diff when it is not, for an estate's `--check` mode. See [Write one](docs/reference/sluis/installation-document.md#write-one).
- **`config.FromAccess` builds the installation's `access` section from an access document.** It takes the derived part (`policy.Access`) and a `config.Bootstrap`, typed rows for the recovery ServiceAccount, the viewers, the controllers' ServiceAccounts or Lambda role ARNs, and the exchange probe, and returns the `config.Access` an installation holds. The rows fold into their groups after the derived matchers, as `policy.AccessDocument.Policy` does for an overlay. `Bootstrap.GenerateSecrets` writes confidential clients' secrets as `{generate: true}` and `Bootstrap.Claims` carries the claims table the access document lacks. A malformed row, a workload listed twice, and a controllers or probe group or probe client that the access document also declares are refused. A test edits each field of `policy.Access` and requires the section to change, so a field added without a mapping fails. See [Build the installation's access section](docs/reference/sluis/installation-access.md).
- **`audit/deploy/pulumi` builds the audit digest signing key and the archive grants of a shared key.** `NewDigestKey` declares the `ECC_NIST_P256` signing key in the backup account and its alias under the caller's options, with `DigestKeyPolicy` (the backup account's root administers, nobody else is named). The description is caller-supplied and verbatim, because KMS takes it at creation only. `KeyLogicalName`, `AliasLogicalName`, `AliasName`, `KeyAliases`, `AliasAliases`, `KeyImport` and `AliasImport` let an estate that built the key by hand keep every URN and physical name. `ArchiveKeyPolicyStatements` returns the three archive statements (`AuditReadersOpenTheArchiveThroughS3`, `AuditRolesUseTheArchiveThroughS3`, `OperatorRewritesTheArchiveThroughS3`) for a shared key's policy from typed roles, operator, bucket ARN and region. Both are additive. See [AWS Pulumi library](docs/reference/audit/aws-pulumi-library.md).

## v1.76.9

### Deprecated

- **`deploy/pulumi/edge/cloudflare` is deprecated in favour of truvity/edge.** The front door is `github.com/truvity/edge/v3/cloudflare/awsapigw` (truvity/edge v3.2.0) and the cache rule is `PublicPathsCache` in `github.com/truvity/edge/v3/cloudflare/rules`. The module's `go.mod`, `NewEdge`, `Args`, `PublicCacheArgs` and `PublicCacheRule` carry `Deprecated:` notices; nothing else changes. The module is removed after v1.77. See [the front door](https://github.com/truvity/edge/blob/master/docs/cloudflare/awsapigw.md).

## v1.76.8

### Added

- **A blob store can read the credential the Cloudflare module rotates: `ports.blob.s3.credentialsRef: external/cloudflare/<preset>`.** `ExternalBlobs.CredentialsRef` takes the same address in `deploy/pulumi`. The blob adapter reads that `cloudflare/v1` document (the access key is the token's id), reads it again with a third of its time left and once after a 403, and keeps nothing on disk. The library checks that the preset is declared, has an `endpoint`, keeps `store: external` and is at the blobs' endpoint (against `Installation.Cloudflare.Presets`, so it also works when the presets are the Cloudflare module's own document and the other functions use `cloudflare.remote`), grants each function that has the blobs a read of that one parameter and nothing else under `external/cloudflare/`, and renders the Cloudflare function's own blobs with `credentials.preset` so it starts before the first rotation. See [Pulumi library](docs/reference/sluis/pulumi-library.md) and [Cloudflare tokens](docs/guides/sluis/cloudflare-tokens.md).

### Changed

- **`ExternalBlobs.CredentialsPreset` is refused with module functions.** The preset is then the Cloudflare module's, and no other function holds a minter or the preset, so v1.76.7's output could not start in them. The error names the `CredentialsRef` (`external/cloudflare/<preset>`) to use. Installations whose presets are in the one function (no module functions) are unchanged.

### Removed

- **Module roles no longer hold the Cloudflare minter's read or the write of what it keeps for `credentials.preset` blobs.** `SluisCrossCloudflareMinter` is the backup role's alone, and `SluisCrossCloudflareMinted`, `SluisParameterKeyMinted` and the key policy's `SluisKeyMinted<Role>` are gone. `ModuleEnv.OpensPresetBlobs` and `KeyRole.OpensPresetBlobs` are deprecated and have no effect.

## v1.76.7

### Added

- **`deploy/pulumi`: `ExternalBlobs.CredentialsPreset` lets sluis mint the blob store's R2 credentials.** Name an R2 preset of `Installation.Cloudflare.Presets` instead of a `CredentialsRef` (exactly one of the two): the library renders `ports.blob.s3.credentials.preset`, declares no parameter and no `SluisBlobCredentials` read, and refuses a preset the installation does not declare or that has no `endpoint`. Both `store: none` and `store: external` presets work, as the blobs mint on demand and never read the stored credential. See [Pulumi library](docs/reference/sluis/pulumi-library.md).

- **`sluisctl cloudflare token --no-cache` (and `cloudflare r2 --no-cache`), or `SLUISCTL_CLOUDFLARE_NO_CACHE=1`.** The commands cached each minted credential under `~/.config/sluisctl/cloudflare/` so a repeat call cost no exchange. With the flag or the variable set they neither read nor write that cache and take no cache lock: the token is never written to disk, and every call mints a new one. Use it where a program execs `sluisctl` and the token must not outlive it. See [sluisctl](docs/reference/sluis/sluisctl.md).

- **A Cloudflare preset can be on-demand only: `cloudflare.presets.<name>.store: none`.** The default, `external`, is today's behaviour: the rotation mints the preset into `external/cloudflare/<preset>`. With `none` the tick never mints or stores it, nothing for it appears in SSM, and `rotation` is left out; a token is minted only through the exchange (`sluisctl cloudflare token <preset>`) for a caller the grants allow, and its expired and revoked tokens are still swept. The console shows the store mode and offers no rotate for it, and the Pulumi library grants nothing on `external/cloudflare/*` and schedules no rotation when every preset is `none`. See [Cloudflare tokens](docs/guides/sluis/cloudflare-tokens.md) and [ADR 0070](docs/decisions/0070-cloudflare-tokens-and-r2-credentials-by-prototype-clone.md).

## v1.76.6

### Fixed

- **Log fields from callers can no longer forge log lines (CodeQL go/log-injection #111).** The log of a refused or failed module call carries the method from the request, the transport's request id and the caller's subject; each is now stripped of line breaks and other control characters and bounded to 256 bytes before it is logged. The message and the keys are unchanged, and an ordinary value is logged as before.

## v1.76.5

### Added

- **`audit/deploy/spec`: the audit deploy names and checks without the Pulumi SDK.** The names `audit/deploy/pulumi` gives an installation's AWS resources (`ComponentRoleName`, `InstallationComponents`, `ArchiveBucketName`) and the checks of the values an estate hands it (`CheckName`, `CheckRolePath`, `CheckLockMode`, `CheckProfile`, `CheckBucketPrefix`, `CheckTelemetryURLs`, `CheckExtensionLayer`) are importable by tooling that must not link a cloud provider SDK. A test in `audit/deploy/pulumi` holds the two equal.

- **`deploy/spec`: the deploy names and checks without the Pulumi SDK.** The names the deploy libraries give AWS resources (`BucketName`, `KubernetesRoleName`, the instance, function-name and key-alias patterns) and the checks of the values an installation hands them (`CheckInstance`, `CheckBucketPrefix`, `CheckCloudflareRotation`, `CheckVerifyKey`, and the `ChartSecret` shape of the chart's `secrets` value) are importable by tooling that must not link a cloud provider SDK. `deploy/pulumi` holds the two equal in a test. `CheckVerifyKey` does not parse keys itself: it calls the issuer's own `ParseVerifyOnlyKey`, so the check and the running issuer cannot disagree, and a test feeds the same inputs to both.

- **Rendering and loading the same documents again is remembered.** `config.Render`, `config.RenderModules`, `config.ValidateModule` and `config.ModuleSecrets` hold the documents they produce or read to their JSON schemas and decode them, which costs seconds on a realistic estate, and a stack calls them again with the same installation on every `NewLambda`. The outcome of each check, error included, is now remembered by a hash of the bytes it is a function of (bounded to the newest 256 outcomes, safe for concurrent use, computed once when callers ask at the same time), as is what `NewLambda` decodes from its rendered documents. Results and error messages are unchanged: a caller still gets its own copy of every slice it is handed. A repeated render of one installation goes from about 130 ms to 4 ms in `BenchmarkRender`.

### Changed

- **Lambda functions flush metrics at most once a minute per instance.** Every invocation flushed the meter and tracer providers together, and with cumulative temporality each metric flush re-sent every total, which made up most of an installation's Lambda telemetry egress (about 8 GB a day of DataTransfer-Out on one estate). Traces are still flushed on every invocation. Metrics are flushed on an instance's first invocation and then only when a minute (`metricsInterval`) has passed since its last successful metric flush; a skipped flush loses nothing, because the next one carries the totals, and the only loss is the last minute before the platform retires an instance. The failure backoff is unchanged, and a failed flush does not count as a metric flush. The audit Lambdas flush on their own and are not changed. Tests hold the first flush, the skip inside a minute with traces still flushed, the flush after it, and the backoff.

- **`NewBackup` no longer creates the `<function>-resume` schedule; an apply deletes it.** Since backup format 2 a run does not pause, and the only answer to `{"kind":"backup","resume":true}` is `idle`, so the schedule invoked the function every five minutes for nothing. An apply of this version deletes the EventBridge schedule `<function>-resume` (the resource `<name>-resume`) of an installation that has one; the scheduler role, its policy and the dead-letter queue stay, because the daily schedule uses them. `ScheduleNames` now lists the daily schedule alone. `BackupScheduleArgs.ResumeRate` is deprecated: it is accepted and ignored, even an invalid value, so no estate stops compiling, and `DefaultBackupResumeRate` is deprecated and unused. The backup function still answers `{"kind":"backup","resume":true}` with `idle` for one release, for a schedule still in flight, and `sluisctl backup run --resume` still answers `idle`. Tests hold that the resume schedule is not declared and that the daily one is unchanged.

### Fixed

- **`keys.archive` is described as deprecated and ignored.** The schema called it "Long-term storage", the audit module's wording from the shared keys schema, although since v1.76.1 the backup module ignores it (as `backup.key` and `backup.region`). The description now says so, at its source in `internal/config/schema`; the generated schemas, the chart's values schema and the configuration and chart-values references follow.

- **Wording of backup format 2 and of one function per module.** The `charts/sluis/examples/backup-v5.yaml` header described the sealed archive of format 1 and now names the age-encrypted `<id>.tar.gz.age` and the `<id>.json` sidecar. The port-adapters reference no longer says the console function is the only one that reads `internal/config/*`, and the high-availability page renames "The controllers in the one process" to "The controllers and the rollout" (the old anchor still works).

## v1.76.4

### Added

- **`policy/compile`: the access-model derivation as a library.** An installation resolves its access file into a `compile.Model`, states its naming decisions in `compile.Conventions` and calls `compile.Roster` and `compile.BuildVocabulary` for the policy's `groups`, `lifetimes`, `github`, `slack`, `people` and `vocabulary` tables. The GitHub job and App rows, the workload and AWS account rows and the relying-party URL rules (`compile.Endpoints`) come with their validation, and `ValidateAudiences`/`ValidateClaims` run the policy's own rules against the derived tables. A rung with a session duration but no population names no lifetime and does not lower the default (the issuer refuses a lifetime for an undeclared group). Additive: nothing in the service imports it.

- **The Cloudflare edge module can cache the public documents at the edge.** `edgecloudflare.PublicCacheRule(host, args)` builds a Cloudflare cache rule for `/keys`, `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` (`PublicCacheArgs.Paths` to change them): `GET` and `HEAD` only, an edge TTL of 5 minutes by default (`TTL`, 1 second to 1 hour), and only requests without an `Origin` header, because the service echoes the caller's origin in `Access-Control-Allow-Origin` and Cloudflare ignores `Vary: Origin`. The new optional `Args.PublicCache` makes `NewEdge` build the rule and call `PublicCache.CreateCacheRule(ctx, rule)` to create it in the estate's zone; the module still holds no Cloudflare credential. `Edge.PublicCacheRule` exposes the rule. Tests hold the expression, the Origin exclusion, the defaults and limits, the refusals (host and path characters, TTL bounds, duplicates, a missing callback), and that nothing is created before a refusal.

## v1.76.3

### Changed

- **The backup role lists the module paths it exports.** The export walks every module's `internal/<m>` and `external/<m>` with `GetParametersByPath` (recursive, no decryption) before it reads each secret by name, and IAM authorises a listing against the bare path ARN, which the `/*` of `SluisCross<M>Parameters` never covers; the backup role held the list on its own module only, so the first real backup failed with `AccessDeniedException` on `ssm:GetParametersByPath` for `internal/oidc`. The role now holds `SluisCrossParametersList`: `ssm:GetParametersByPath` on `parameter/sluis/<instance>/internal/*` and `external/*`, the same reach its key grant `SluisKeyReadAll<Role>` already has, and never the namespace roots. A statement per module on the bare paths would push the role's inline policy past IAM's 10,240 characters on a realistic installation, so the grant is the two namespaces. A listing decrypts nothing: `SluisDenyRestoreIdentity` and `SluisDenyRestoreIdentityKey` are unchanged, and the backup module's own secrets are still not exported. The restore role gets no list: it reads and writes secrets by name. Tests evaluate every AWS call of a backup run (the maintenance gate, the lease and run records, the export of each module's table, secrets and reports, the archive object and sidecar with its SSE key, the audit record, retention) against the rendered role and key policies, hold what stays refused (the restore identity, the namespace roots, another module's writes, the maintenance flag), and hold the backup and restore role policies within IAM's inline limit on realistic ARNs.

## v1.76.2

### Changed

- **The deployer reads the restore identity back.** `NewBackup` creates the restore identity as a SecureString, and the AWS provider decrypts it after create and on every refresh, but `SluisKeyAdminReads` named only the state secret and the recovery password, so an admin role with no other path to the key was refused `kms:Decrypt` and the apply failed after the parameter existed in AWS and before it was recorded in state. `SluisKeyAdminReads` now also covers the restore identity's `PARAMETER_ARN` (layout v5 with a backup role), under the same `KeyPolicyOptions.Admins` principals and SSM `ViaService`. `SluisKeyDenyRestoreIdentity` and the backup role's IAM denies are unchanged: only the backup role is denied; admins and the restore role read it. Admins could already read the break-glass identity, so this adds no recovery capability. The parameter keeps `overwrite: true`, so an apply whose earlier create succeeded in AWS adopts it (the value derives from the seed in state and is identical). Tests hold the grant, the unchanged deny, that no other statement names the parameter, and `overwrite`.

## v1.76.1

### Changed

- **Every S3 and R2 upload carries a precomputed SHA-256 checksum.** AWS refuses a `PutObject` on an Object Lock bucket without `Content-MD5` or an `x-amz-checksum-*` header, and the adapter sent neither (it keeps the SDK's `WhenRequired`, because R2 refuses the streaming `aws-chunked` trailer). `put` now computes SHA-256 over the whole body and sends it as `x-amz-checksum-sha256`; no `aws-chunked` encoding and no `x-amz-trailer` is used. This applies to every target: the backup archive and the live blobs (`ports.blob.s3`). The new `checksum` key of `ports.blob.s3` and `backup.target` is the escape hatch for a store that refuses SHA-256: `sha256` (the default), `md5` (sends `Content-MD5`) or `none`. Tests run the real SDK client against an `httptest` server and hold the header, the absence of the trailer and of `aws-chunked`, the hash's dependence on the body, and the other two modes.

- **Backup keys are age keys generated per installation (format v2); the archive KMS grants are gone.** `NewBackup` generates the installation's restore keypair (a `random.RandomBytes` seed, so an apply never rotates it), renders the recipient into the backup function's document as `backup.recipients`, and keeps the identity as a SecureString parameter at `/sluis/<instance>/internal/backup/restore-identity` (the secret store's byte codec, encrypted with `ParameterKeyArn`). `NewRestore` renders `backup.identity: restore-identity` and its role is the only one that reads the parameter: the backup role is explicitly denied it, and the decryption of its value, and `SluisKeyPolicyStatements` adds `SluisKeyDenyRestoreIdentity` to the key policy. The backup role holds no KMS grant for the archive (`SluisArchiveKey` is removed from both roles). New outputs of `Backup`: `RestoreRecipient`, `Recipients`, `RestoreIdentityParameter`; of `Restore`: `IdentityParameter`. New `BackupArgs.ExtraRecipients []string` adds estate-supplied `age1...` recipients, validated as age X25519 recipients. `ArchiveKeyAlias` is now optional and deprecated (rendered as `backup.key` only while set, and `ArchiveKeyArn` still names its key); `KeyPolicyOptions.BackupArchive` and `RestoreArchive`, `KeyPolicyArgs.BackupArchive` and `RestoreArchive` and `ArchiveGrant.KeyArn` are accepted and add nothing, so no estate stops compiling. The document keys `backup.recipients` and `backup.identity` and `ports.blob.s3.checksum` are in the schemas.

  **UPGRADE NOTE:** the next apply of an estate that deploys the backup creates the restore identity (a `RandomBytes` and an SSM parameter) and drops the archive KMS statements from the roles. Add an offline break-glass recipient in `ExtraRecipients` (`age-keygen`, keep the identity off the platform): it opens the backups when the installation, its parameter store and the restore function are gone. Rotating the seed makes older backups readable only by an `ExtraRecipients` identity. An estate that shares one KMS key with the archive may delete its hand-written archive statements; `BackupArchive` and `RestoreArchive` can be dropped. An estate that deploys `NewRestore` needs `NewBackup` of the same instance in the stack (it creates the identity parameter).

- **Backups are one age-encrypted `tar.gz` per backup (format 2).** Format 1 sealed many 8 MiB chunks with AES-GCM under a KMS data key, with our own key derivation and MAC: bespoke cryptography, a KMS key whose loss made every backup unreadable, and nothing but sluis could open one. A backup is now `backup/<instance>/<id>.tar.gz.age` and, written last as the completion marker, the plain sidecar `backup/<instance>/<id>.json` (object key, size, SHA-256, recipients and per-module counts, never a secret). Inside, a PAX tar holds `manifest.json` first (the SHA-256 of every member and the counts), then per module `state.jsonl`, `secrets.jsonl` and one file per blob under `blobs/`. It is compressed with gzip and encrypted with age to the X25519 recipients in `backup.recipients`, so it opens without sluis: `age -d -i key.txt <id>.tar.gz.age | tar xz`. The backup role holds only public keys; the restore role reads the age identity from its own secret, `internal/backup/restore-identity` by default (`backup.identity`, the byte codec `{"value":"<base64>"}`), checks the object against the sidecar and every member against the manifest before the first write. A run is one invocation: the `{"kind":"backup","resume":true}` schedule and `sluis backup run --resume` answer `idle`. Retention deletes the sidecar first, then the object; a refused delete is counted, not retried. The backup module's own secrets are no longer exported. `sluis backup verify <id> [--identity <file>]` checks a backup read-only. No format 1 backup was kept anywhere, so there is no reader for it. Tests hold the round trip, a flipped or truncated byte, a manifest or member that disagrees, a wrong identity, two recipients, the deterministic member order against a golden tar, the blob-key escaping, the sidecar written last and the retention order. [ADR 0073](docs/decisions/0073-backup-format-2-age-encrypted-tar.md) records the decision.

  **UPGRADE NOTE:** backups are now age-encrypted, and an estate must set `backup.recipients` (at least one `age1...` public key from `age-keygen`) before the backup function starts; store the matching identity as the restore role's `restore-identity` secret, and keep a second identity offline. `backup.key`, `backup.region` and `keys.archive` are deprecated and ignored for one release (a warning at start). The Helm chart now requires `backup.recipients` when `backup.enabled` and no longer requires an archive key. The Pulumi library generates the recipient and the identity (the entry above).

## v1.76.0

### Changed

- **A layout v5 installation no longer declares the v4 state secret and recovery password parameters unless `Compat.KeepV4` is set.** The Pulumi library kept `internal/config/issuer/state-secret` and `internal/config/recovery/password` beside the v5 pair until `Compat.DropV4`, although nothing reads them on v5, so every v5 estate carried two secrets it had to remember to drop. On `Layout: "v5"` the library now declares only the v5 pair; `v4` and `v4+v5` (whose roles still read the v4 pair) are unchanged. `Compat.DropV4` is deprecated and kept for source compatibility: a no-op on v5, still refused on `v4` and `v4+v5`. The new `Compat.KeepV4` keeps the v4 pair on v5 for an estate that still needs it during a migration; it is refused with `DropV4` and with `RetireLegacyTable`, and `RetireLegacyTable` no longer needs `DropV4`. Tests hold the default, `KeepV4`, `DropV4` on v5, the refusals, the unchanged v4 layouts and the preview shape of each step.

  **UPGRADE NOTE:** an estate on layout v5 that did not set `DropV4` will see its next apply delete the two v4 parameters from AWS (they are no longer read on v5). To keep them, set `Compat: &CompatArgs{KeepV4: true}`.

## v1.76.0-rc.7

### Added

- **`cloudflare.tick`: how often the rotation looks at the presets.** A credential rotates on the schedule's tick, up to one tick after its `rotation`. The Pulumi library now writes the tick of `CloudflareRotation` (its `Interval`, a plain `rate(...)`, or the 15m default) into the service document when the installation leaves `cloudflare.tick` out; a cron `Rate` leaves it for the installation to state, and an installation's own value is kept. The console's Cloudflare list carries it as `CloudflarePreset.rotation_tick_seconds`, a minute when unset (the Kubernetes loop's). The Cloudflare guide says to make `rotation` a multiple of the tick to rotate when intended.

- **`sluisctl recovery password`: the recovery password of a Lambda installation, decoded.** On layout v5 the password is at `/sluis/<instance>/internal/oidc/recovery-password`, stored by the secret store's byte codec as `{"value":"<base64>"}`, so an operator in an outage had to know to decode two layers by hand. The command reads the parameter with the caller's own AWS credentials (`--instance`, `--region`, `--profile`), decodes it and prints the password and nothing else, with a newline, on standard output. It refuses to print to a terminal unless `--show` is given, before it reads anything, so a pipe (`| pbcopy`) works and a casual display does not. An installation still on layout v4 (the text itself at `/sluis/<instance>/internal/config/recovery/password`) is read when the v5 parameter does not exist. Tests hold the decode of both forms and its failures, the fallback, a refusal that is not mistaken for a missing parameter, and the terminal refusal. [Recover on Lambda](docs/guides/sluis/operate/recover-on-lambda.md) gives the path, the encoding and the command.

### Changed

- The console's recovery sign-in now works on the Sessions pages and reads the Audit page calmly. Sessions are listed and
  ended through the console itself, as the person signed in to it, instead of by the browser with an issuer cookie that
  a recovery sign-in does not have (it was refused with "sign in first" on #/sessions and on every person and client
  page). Directory sign-ins are unchanged. The Audit page tells a recovery sign-in that the trail is read as a person
  the directory admits, with a 403 rather than a 502 and "HTTP 502", and mints and calls nothing.

- **A holder's "through ..." reason no longer links a matcher to a provider group.** The group page's "People in it now" linked every reason to the provider group page, including the words of a matcher such as "signed in at tsarev.id", whose page asked the hub for a group of that name and got `invalid_argument: hub: address has no domain`. A domain now leads to the People list filtered by it (`#/people?domain=...`), a "signed in as" address to that person, a workload matcher to nothing, and only a provider group to its page.

- **The console no longer calls a healthy Cloudflare credential "past its rotation".** It showed a warning ("Past its rotation (20m); the next tick replaces it.") and a "pending, past rotation" badge whenever the stored credential was older than `rotation`, but rotation only happens on the tick, so with a 20m `rotation` and a 15m tick every credential was "past rotation" for up to a tick of every cycle while perfectly healthy. A credential past `rotation` is now **due**, in a neutral style ("Due: past its rotation (20m); the rotation runs every 15m, and the next tick replaces it."), and **overdue**, a warning, only past `rotation + tick` and a minute of slack; past twice the rotation it is still "not rotating" and the alert still fires. Tests hold each boundary, a tick longer than the rotation, and an older server that sends no tick.

- **`TestATimeoutIsRetriedOnce` no longer races a sleep against a timeout.** Its slow first attempt slept 300ms against a 100ms client timeout, and the retry had the same 100ms, which a loaded runner missed ("Client.Timeout exceeded while awaiting headers"). The first attempt is now never answered until the test ends (so it times out whatever the load) and the retry is answered at once under a 2s budget; the test also holds that exactly two calls were made and that the first took its whole budget to time out.

- **The people filter by GitHub link works when the GitHub module is a function of its own.** `#/people?github=linked` and `?github=not-linked` answered `failed_precondition: nobody can link a GitHub account in this deployment` on a Lambda installation, although the link App had linked accounts: the links are the GitHub module's records and the issuer's console opens none, so it read "no link store" as "no links anywhere". The console now asks the module (a new console method, `console.list_link_logins`, which answers the console class alone and returns the logins of the links that count, or says the module keeps no links); the precondition stays for a deployment that keeps links nowhere.

- **A GitHub App's "Recent tokens" no longer fails on a Lambda installation.** `ListGitHubAppTokens` was forwarded to the GitHub module, which mints the installation tokens but keeps no record of them: the ring of recent requests is written by the issuer, which decides each mint, so the module answered "this deployment mints no installation tokens here" for every App. With the module remote the console now asks it only which App the id names and whether the person may operate it, and answers from the issuer's ring (a ring in function memory, which says since when it has been kept, as it always did). The route contract test also holds every GitHub console method to reaching the module or being answered at the issuer on purpose, with a reason, so this class of gap fails a test.

### Documentation

- [Recover on Lambda](docs/guides/sluis/operate/recover-on-lambda.md) named the layout v4 path for the password; it now names the layout v5 parameter and its encoding.

## v1.76.0-rc.6

### Changed

- **The Google module's console actions that reach Google work on a warm function, and a module call that fails says why.** The Google function opened its module on the first console call of a container with that invocation's context and kept it for the rest of the container's life. Lambda cancels an invocation's context when the invocation returns, and the Google clients fetch their access tokens with the context they were opened with, so every later call that reached Google (**Refresh** and **Probe**) failed at once with "the Google module failed" while the scheduled refresh, which opens its own module per invocation, kept working. The module is now opened with the call's values and not its cancellation (the Slack function too). The failure was also silent: the module told the caller `internal` and logged nothing, so a module server now logs a call it refuses or fails (module, method, code, the cause, and the Lambda request id), and the console service keeps the cause of a failure it reports as `internal`. The same stale context made a console **Probe** record the workspace as `failing`, and nothing on Lambda renewed that health (the probe loop only runs in a process that has one), so the directory stayed non-authoritative and the operators it vouches for were shown as viewers; the scheduled `{"kind":"refresh"}` event now also probes every workspace. A contract test holds every module's function to registering each method the issuer calls on it, read from the constants the module's wire declares.

- **The audit writer no longer puts an object into an hour that is already sealed.** A seal is never rewritten and the notary never revisits an hour, so an object that landed in a sealed hour (writer clock behind the notary's, a put that finished after settle, a restore) was covered by no seal and showed only as a count/root mismatch in `audit verify`. Before each put the writer now looks for the hour's seal and, if there is one, puts the object into the first later hour without one (logging `sealed_hour_redirect`); the key's hour is ingest time, so readers and `verify` are unaffected, and if the seal cannot be probed the object is written where the clock says (`seal_probe_failed`). The writer's role gains `s3:GetObject` on `seals/` (read only): an estate that renders its own writer policy must add it, otherwise the guard logs `seal_probe_failed` and does nothing. Decision in ADR 0061.

- **The console no longer says "Not sealed yet" about records whose seal the query service cannot look up.** `sealOf` took any failure of the seal lookup, and the absence of an archive (an `audit-query` configured without `archive`, deliberately, to keep the archive credential off the caller-facing pod), for "no seal", so every record of such an installation showed "Not sealed yet" and an expired archive credential read the same. `Provenance` now carries `seal_unknown`: set when there is no archive to ask or the lookup failed (logged with the seal key), clear when the archive answered, including "no such object", which is still "not sealed yet". The console shows no seal chip when it is set. Observe does not record seal verification in the index, so `verified_at` is still empty from the query service. Tests hold the nil archive, a missing seal, a failing archive and the chip.

- **The console says where an App's key is kept in the words of the store that keeps it.** The Apps page always said "Kubernetes Secret" and, on a Lambda installation, that "this deployment keeps no state in Kubernetes", because only the Kubernetes stores could name a place; the stores of the ports (SSM, OpenBao) named none. `GitHubApp` now carries `secret_place` (the secrets adapter and the stable address beneath which the App's key is written, such as `/sluis/<instance>/internal/github/apps/<id>/`, to which each write adds a fresh ref), and the page labels it "Kubernetes Secret", "SSM parameter", "OpenBao path" or, for an adapter it does not know, "Secret store entry". The Kubernetes Secret's keys are listed for a Kubernetes Secret only, and the other "keeps no state in Kubernetes" notices now say the deployment has no store for its state. `GitHubApp.secret` still carries a Kubernetes Secret's name.

- **The audit chart takes annotations for the workload objects themselves.** Every Deployment and CronJob it renders (`writer`, `receiver`, `query`, `observe`, `jobs.notary`, `jobs.verify`, `jobs.purge`, `jobs.clockSync`) now takes `annotations`, rendered on the object's own `metadata`, and the chart takes `commonAnnotations` for all of them (a component's own win). Until now only the pod template carried annotations, which a controller such as Stakater Reloader does not read, so an estate running it with `autoReloadAll` could not stop the indexer and the notary being rolled on every rotation of a short-lived archive credential, though they reread it themselves (`archive.sluisDir`). The defaults are empty and no render changes; set `reloader.stakater.com/auto: "false"` under `observe.annotations` and `jobs.notary.annotations` to opt out (see the chart values reference, "Reloader").

- **The audit queue's policy the library writes waits for the module roles.** With `Audit` installing the audit library, the queue's policy named the GitHub, Slack, Google and Cloudflare roles as plain strings while those roles were declared after the queue, so on a first apply SQS could be asked to accept a policy that names a role that does not exist yet. The module roles are now outputs of the module functions' role resources, as the issuer's already was, so the policy is applied after them. Nothing else moves.

### Added

- **Key policy statements for the backup archive's context (`KeyPolicyOptions.BackupArchive`, `RestoreArchive`).** An archive sealed under the estate's shared key (`ArchiveGrant.KeyArn` is that key) is held to its encryption context `{instance, purpose: archive}` by the key policy, and the library rendered none of it, so an estate wrote the statements itself. With `BackupArchive` the policy admits the backup role to Decrypt and GenerateDataKey under that context and no other context key (`SluisKeyArchive`, an allow for the account root narrowed by `aws:PrincipalArn`, so the role may not exist yet), reserves the purpose to the archive roles (`SluisKeyArchiveContextReserved`) and holds them to it (`SluisKeyArchiveRolesPurposeOnly`); `RestoreArchive` adds the restore role with Decrypt only (`SluisKeyArchiveRestore`). A role kept under a transition name is covered. Off by default, so no policy moves; `KeyPolicyArgs` takes the same two fields. Tests decide every principal, action and context against the statements an estate writes by hand.

- **The audit writer is updated before the sluis functions, by the library.** A release whose audit catalogue moves emits records under the new version from its first invocation, and a writer that does not hold that catalogue dead-letters them, so the writer goes first. An estate with the installation in its own stack forced that with a transformation on the Lambda's children. Now the issuer's function and every module function depend on the writer: the one the library installs (`Audit` unset or installing), or the resources named in the new `AuditUse.DependsOn` (`pulumi.ResourceArray{pulumi.NewResourceInput(writer)}`, or an output that carries them) for an installation that exists. Only the functions wait, and no input of theirs changes, so a deploy that does not move the catalogue updates exactly what it did before. `ModuleFunctionArgs.FunctionDependsOn` is the same for a function built on the module builder.

- **`RoleArgs`: the role lists from the names alone.** A stack that exists before the sluis stack (the foundation stack with the shared key's policy, the audit stack with the ingest queue's) had to build a `LambdaArgs` full of stand-ins (tables, a package digest, a queue) only to ask for the principals, because `Senders`, `Roles`, `ViewerRoles` and `KeyPolicyStatements` validate the whole args. `RoleArgs` holds what the names depend on (region, account, instance, layout, the installation, the function name overrides, the transition roles, and whether the stack creates the backup and restore components) and answers the same four, equal to the full args' for the same names. `FunctionRoles` lists every function once, with its name, ARN and whether the stack creates it, so nothing repeats a default function name; `ViewerMatchers` and `FunctionRole.Matcher` give the access policy's matcher rows (account, role name, path `/`) for the viewer roles and for any one role. `LambdaArgs.RoleArgs()` and `Lambda.RoleArgs()` convert.

- **Queue senders that exist: `RoleArgs.CreatedSenders` and `DeferredSenders`.** SQS refuses a queue policy that names a role that does not exist, and `Senders` lists every function's role, the restore function's that no stack of an estate may create included. `FunctionRole.Created` says which roles the stack creates (the issuer's and the module functions' that host a module, and the backup and restore roles only when `RoleArgs.Backup` and `Restore` say the stack makes those components); `CreatedSenders` is their ARNs and the old names a transition keeps, which exist already. A stack that makes the queue before the sluis stack calls `RoleArgs.DeferredSenders(ctx)`: the created roles are outputs for `IngestArgs.Senders`, resolved by `Lambda(l)`, `Backup(b)` and `Restore(r)` once the components are declared (`Reject(err)` releases them), so the queue policy is applied after the roles. The rule: a policy names a role that is `Created` only after that role, and a role that is not `Created` only if it exists some other way.

## v1.76.0-rc.5

### Changed

- **The module roles use the secrets key, the blob credential's key and the minter of a preset's blobs.** With `Keys.Secrets` only the issuer's role held the secrets key, so the GitHub, Slack, Google and Cloudflare functions could not read or write a SecureString under it; each module role now holds it through SSM for exactly its own parameters (and the Google role the sign-in client's), as `ParameterKeyArn` always did. With external blobs and `ParameterKeyArn` the blob credential's key statement shared its Sid with the role's own and was dropped (on the issuer, the other way round): it has a Sid of its own, `SluisBlobCredentialsKey`, so both survive. A module whose document opens blobs from `credentials.preset` mints in its process and now holds the minter's read, the write of the minted records and stored credentials, and the matching key statements (`KeyRole.MinterRefs` and `OpensPresetBlobs` carry it to the shared key's policy); no other role does.

- **The issuer lists only the tables it opens, and a controller's run-now reaches its own function.** The issuer's `ports.dynamodb.tables` named every module's table and its readiness probe describes each one, but its role could describe only its own, so a probe against a peer's table was denied; the document now lists the issuer's table and the Google snapshot's, and the snapshot grant adds `dynamodb:DescribeTable` (still no Scan, no write). The GitHub and Slack module documents chose the `memory` trigger, so "run a pass now" from a controller inside the function reached nobody and waited for the next tick; they now choose `invoke` on their own function and each role holds `lambda:InvokeFunction` on that function's `live-console` alias (the alias the adapter qualifies with) and nothing else. Contract tests pin both, and that every schedule the library makes sends a kind its function takes.

- **Every Lambda function the library creates exports telemetry as the issuer does.** `LambdaArgs.Telemetry` put the OpenTelemetry layer and its `OTEL_*` environment on the issuer's function alone, so the GitHub, Slack, Google, Cloudflare, backup and restore functions (the ones that do the work) exported nothing. With `Telemetry` set, each of them now gets the telemetry layer first and the configuration layer last, the same `OTEL_*` settings, and `OTEL_SERVICE_NAME` defaulting to the function's own name unless `Telemetry.Env` sets it; the layer, environment and validation (`Telemetry.Env` holds telemetry settings only) are one helper for all of them. The layer authenticates with an AWS-minted web identity token, so each module role also holds `sts:GetWebIdentityToken` for `AdditionalWebIdentityAudiences` (after the console's audience on the roles that call the console), and only when `Telemetry` is set; unset, no function changes. `BackupArgs` and `RestoreArgs` (`BackupCommon`) take `Telemetry` and `AdditionalWebIdentityAudiences` for the same, `ModuleEnv.TelemetryAudiences` renders the grant, and a contract test finds every function the library creates and holds it to all of this. An estate that passes `Telemetry` to `LambdaArgs` needs no change: its module functions pick it up on the next apply (a new version of each function); pass the same two values to `Backup` and `Restore` to cover them.

## v1.76.0-rc.4

### Changed

- **The Cloudflare module function answers its rotation schedule.** Since the module moved out of the issuer in rc.2, the schedule's `{"kind":"cloudflare"}` event went to the Cloudflare function, which never registered the pass and answered "this function has no cloudflare section": no preset rotated, and a credential with a 1h lifetime expired an hour after the upgrade (its consumers, such as an audit writer reading its archive credential, then failed at start). The function now runs one pass over every preset on that event (`App.TickAll`); a preset that did not rotate fails the event, as on the issuer. Tests hold the function to the event and to naming the failed preset.

- **The module functions' roles and aliases follow one routing table.** On rc.3 the GitHub and Slack functions could not ask STS for the web identity token they prove themselves to the console with (`sts:GetWebIdentityToken`: AccessDenied, so every pass failed), and the Cloudflare function had no `live-console` alias, which the issuer's console calls (`ResourceNotFoundException`). The library now derives both from `ModuleCalls()` (the `CrossGrants` invokes and `ConsoleCallers`): each function gets the alias of every caller class that calls it, and each role that authenticates to the console with its token gets the `SluisWebIdentity` statement, on the console audience (`WebIdentityAudience`) exactly as the issuer's. `ModuleEnv.WebIdentityAudience` is the audience for estates that render `ModuleRoleStatements` themselves. New contract tests hold every row of the table to its alias, its qualified invoke grant and its token grant.

- **The post-deploy check builds every adapter the function builds.** The `sluis-<module>-check` invocation read the declared secrets and nothing else, so a Google module document with no `adapters` block passed it ("declared secrets present") and the function then failed its first directory-refresh tick with `audit adapter "sqs" needs settings.queueURL`. The check event of the issuer, GitHub, Slack, Google and Cloudflare functions now first builds, from the function's own document, the adapters it builds at start and in a tick: State and the module's table, the blobs, the secrets, the trigger, the audit sink (the plan's `audit` choice applied as `audit.FromPlan` does, and the `sqs` publisher constructed) and, for the issuer, the signing adapter's settings. A missing setting fails the check with the setting named (`adapters: audit adapter "sqs" needs settings.queueURL`), before any secret is read. The build reaches nothing that mutates: a DynamoDB table is bound and never created, a trail is constructed and the catalogue never registered, and a blob whose credentials a Cloudflare preset mints is validated and left unopened. A test builds each rendered module document of both installations and holds the check to refusing the document without `adapters.audit`.

- **The Google module function now carries the audit adapter.** Its document had no `adapters` section, so the preset's `sqs` audit adapter had no queue and the function refused at start and in a directory-refresh tick ("audit adapter sqs needs settings.queueURL"): the directory could not be vouched for and sign-in was refused. The Google document now names the same `adapters.audit` (and the in-process trigger) as the other modules. A test resolves each module document's adapter table, as the function does at start, and holds every concern to its settings.

## v1.76.0-rc.3

### Changed

- **Every module function now carries the blobs port, and the Google module reads its sign-in client.** In rc.2 only the Google module document got `ports.blob`, so the GitHub, Slack and Cloudflare functions exited at start ("blobs adapter needs settings"); and the Google role and key policy did not grant `internal/oidc/signin/*`, which the module holds for sign-in and consent. Both are fixed; regenerate the key policy from this release.

## v1.76.0-rc.2

### Added

- **A warm Lambda instance keeps the secrets it read.** The stores every module reads its documents from (`internal/secretstore`, over `storage/state/ssm`) read through an in-memory cache, per process and bounded to 512 documents, for `secrets.readCache` (default 5 minutes; `0s` is off; `SLUIS_SECRETS_READ_CACHE_TTL` overrides it). A write, failed or not, drops the key's copy; a copy is not kept past the `expires_on`, `access_expires` or `refresh_expires` the document states; a 403 on an R2 credential read from a document re-reads it from SSM before the retry. The aim is under 1.5k `kms:Decrypt` a day where it was about 9k. `sluis_secret_reads_total{result="hit|miss"}` counts the reads. See `secrets.readCache` in the [configuration reference](docs/reference/sluis/configuration.md).

### Changed

- **The Cloudflare rotation ticks every 15 minutes, and the tick is a setting.** `CloudflareRotation.Interval` (whole minutes, default 15m; `Rate` stays for a cron expression, exclusive with it) replaces the `rate(1 minute)` default, cutting the lease writes and credential reads of an idle pass fifteenfold. The rotation logic never assumed a minute (a preset is due once `rotation` has passed since it was minted), so a credential rotates up to one tick late. The library now refuses, at load, a preset where `rotation + tick + 5m` (`CloudflareConsumerSyncMargin`) is not under `lifetime`, for `Interval` and `rate(...)` schedules, so a credential cannot expire before its replacement is synced. Presets with a short lifetime (the old 15m/5m example) need a shorter `Interval` or a longer lifetime; the worst-case remaining lifetime at hand-over is `lifetime - rotation - tick`.

### Removed

- **The old `access_issuer_*` and `access_roster_*` metric names are no longer published.** Every metric is recorded under its `sluis_*` name only: `access_issuer_http_requests_total` is `sluis_http_requests_total`, `access_roster_ticks_total` is `sluis_ticks_total`, and so on for the port, HTTP duration, lease, tick (including `tick_last_success_timestamp_seconds`), token, login (including `login_successes_total`), `reuse_detected_total` and signing-key families. **Consumers must read `sluis_*`:** move dashboards and rules before upgrading. The chart's alerts, both dashboards and the golden renders select `sluis_*` only (the `sluis.dual` helper is gone). `telemetry.legacyMetrics` and `SLUIS_LEGACY_METRICS` are removed: delete the key from your values. The cookies `access_issuer_sso` and `__Host-access_roster_recovery` are wire values and keep their names.

## v1.76.0-rc.1

**Upgrading from v1.75: follow the [v1.76 upgrade guide](docs/guides/sluis/upgrade/v1.76.md).**

### Added

- **The release matrix is held to the module registry.** Every module of `config.ZipModules()` (issuer, cloudflare, github, google, slack, backup) has exactly one arm64 Lambda zip with its module pinned, one module image and one `cmd/sluis-<module>`, and `checksums.txt` lists the zips; the `github-mint` and `accessctl` artifacts are gone. `internal/releasecheck` asserts the lists equal the registry and that only `sluisctl` is a Nix flake, and `hack/check-zips.sh` (so `release-verify`) now refuses an orphan `sluis-*_linux_arm64.zip`. The Pulumi library's default package names come from `config.ZipName`, the same constant, so a pin of `<version>` resolves every module zip.
- **The Google console and sign-in are the Google module's.** The Workspace service (list, connect by consent or by service-account key, reconnect, served domains, synced groups, probe, refresh, disconnect) moves from the console into `internal/googleapp/console`, with the `Connector`, `KeyConnector`, `CredentialReopener` and `SignInConnector` seams; the console is a proxy that checks the role and calls the module as the caller class `console` (`google` methods `console.list_workspaces`, `begin_connect`, `reconnect`, `complete_consent`, `upload_key`, `set_served_domains`, `set_synced_groups`, `probe`, `refresh`, `disconnect`). The sign-in is `google.identify` and `google.sign_in_url`, class `issuer`: a console method called as `issuer`, or `identify` as `console`, is refused. The module owns the OAuth client secret, the keys, the workspace records and the refresh writer, answers a refused call with `not authorised` (the reason is in its log), and records the connections to the audit trail from its own role; its document takes `audit` and `google.publicURL`, and `config.RenderModules` writes `google.oauthClient`, `google.publicURL` and `audit` into it. The issuer keeps the snapshot read and the consent callback, which verifies the signed state and forwards the `code` to `google.complete_consent` once (the platform's retry is off, `modcall.WithoutRetry`, deadline about 25 s). A key upload passes through the issuer in memory, never logged, at most 64 KB. With no `google.remote` the same code runs in process through `modcall.Local`. **Google sign-in now depends on the Google function.** It has no provisioned concurrency, so the first sign-in after idle pays a cold start; the issuer bounds each call at 25 s and shows a "Sign-in unavailable" page when it does not finish. See [the Google module's calls](docs/reference/sluis/lambda.md#the-google-modules-calls). The issuer's role may invoke `live-console` of the Google function, which now has that alias.
- **`roster.access.explained` records every operator look-up of access.** Catalogue 1.19.0. It carries the actor, the subject looked up, the outcome and counts of groups, clients and admitted clients, never group names. A refused look-up is recorded as denied.
- **`sluisctl token --show` prints your own issued token's claims.** After a normal issue for `--audience`, it decodes the token locally and prints `iss`, `sub`, `aud`, `groups`, `exp` and `iat` (UTC times) and other claims under `claims`, as YAML or with `--format json`. It never prints the token or its signature.
- **Plumbing for moving the console's provider operations into the modules.** `internal/consolecall` carries a console operation as a proto-JSON envelope, `{caller:{actor,roles,workspaces}, msg}`, over `modcall`; a refusal a person should read is a `Problem{summary,detail,hints}` in the reply, and any other failure is the transport's coded error with no detail. `consolecall.Handle` registers a method (named `console.*`) for the caller class `console` only and overrides any other `Allow`; `consolecall.Proxy[Req,Resp]` is the console's side; `consolecall.List()` raises a listing's bound to 2 MiB (default 256 KiB); `consolecall.Violations` is the lint that every console method is `Allow("console")` only. `internal/consoleauthz` has the console's gates (`RequireRole`, `RequireWorkspace`, `RequireAnywhere`, `RequireOwner`, `RequireOrg`) over the caller snapshot, with the same rules and messages as the console's. `ConsoleDeps.Modules` (`consolecall.Callers`) holds a caller per module (GitHub, Slack, Google), each defaulting to the in-process `modcall.Local`. `modcall.Server.Methods` lists what a server registered. Nothing moves yet: no console operation uses these, and the boundaries rule that `internal/server` imports none of a moved provider's packages beyond the module's console door applies to each provider as its last operation moves.

- **`github.remote`, `slack.remote` and `google.remote` route a call to that module.** The `sluis/v3`, `controller-github/v2` and `controller-slack/v2` documents take one section per module, each shaped exactly like `cloudflare.remote` (`{function|url, audience, tokenFile}`): a module named by `function` is invoked through its `live-<class>` Lambda alias, one named by `url` is called on its Kubernetes Service with the pod's projected token (`tokenFile`, default `/var/run/secrets/sluis/<module>/token`), and one with no `remote` stays in the process. A remote that names both, or neither, is refused at load. The sections are additive: a document without them behaves as before, and `cloudflare.remote` is unchanged. `internal/modcall/dial.Dial(ctx, cfg, class, local)` builds the router from them (`dial.FromTargets(doc.Targets())`); the Lambda client is compiled in only with the `lambda` build tag, so a Kubernetes build carries none and refuses a function.
- **The module registry knows the GitHub, Slack and Google modules.** `lambdaapp.ModuleOf` now selects a module by the document's apiVersion: `controller-github/v2` is the GitHub module's, `controller-slack/v2` the Slack module's, `sluis-google/v1` the Google module's and `sluis-backup/v1` the backup module's; `sluis/v3` with `cloudflare.serve` stays the Cloudflare module's, and any other document is the issuer's. A zip built for one module refuses every other module's document, and a build pinned to `github`, `slack` or `google` runs only that module's command. No function for the three modules is built yet.
- **The Google module, `sluis google`.** A new `sluis-google/v1` document (`schemas/config/sluis-google.schema.json`, `config.LoadGoogle`) configures the hub's refresh writer as a process of its own: the storage it keeps its workspaces and the refresh lease in (the `google` table on layout v5), the workspaces it declares or that the console connected (`google.workspaces`, `google.oauthClient`), and the refresh, freshness and probe intervals (`google.refreshInterval`, `google.freshnessWindow`, `google.probeInterval`). `sluis google --config <file>` runs the refresher and the prober, and `sluis google tick <workspace> --config <file>` refreshes one workspace once under its lease, leaving it to another runner that holds the lease and standing still while the module is under maintenance. The module writes the directory snapshots in the blob store on a schedule and never on a request; the issuer reading them alone, with no refresh at sign-in, follows in a later change. The package is `internal/googleroster/app`; `internal/module/google` wraps it, and `module.Unsplit` and `module.ErrNotSplit` are gone because no module is left without a process of its own. `hub.Hub` gains `RefreshWorkspace` and `Workspaces`. No Lambda function for the module is built yet.
- **With `google.remote` the issuer only reads the directory's snapshots.** Its hub adopts and reopens no workspace, starts no refresh or probe loop, and a sign-in that finds a snapshot due, stale or missing an address makes no call to the directory and invokes nothing; the Google module's schedule refreshes (`hub.UseReader`, `app.Config.Reader`). A local install with no remote keeps refreshing in process. The workspace wiring the Google module copied from the issuer is now one package, `internal/hubwire`.
- **The GitHub and Slack modules are Lambda functions of their own.** `cmd/sluis-github` and `cmd/sluis-slack` run the controllers' `tick` and `run` passes (one target per invocation, under its lease), answer `check` for their own kinds of secret only (the two declare none, so a controller's check no longer reports the policy's client secrets), and serve no HTTP and no module call. A `run` for a target the policy does not declare ends cleanly without assembling a controller. A `controller-github/v2` or `controller-slack/v2` document takes a `secrets` section, which a function reads its secrets store from.
- **The GitHub function serves the installation-token mint.** `internal/lambdaapp/githubfn` registers the `github` module's `mint_installation` method for the issuer's class only (`live-issuer`; a console or any other class is refused as forbidden) beside its `tick` and `run` passes, so one function, one role and one concurrency limit serve both (D-v176-7 a). It reads the same `controller-github/v2` document and holds its ports for the life of the function.
- **The Google module is a Lambda function of its own.** `cmd/sluis-google` (built with `-ldflags -X .../internal/version.Module=sluis-module=google`) answers `{"kind":"refresh"}` for every workspace and `{"kind":"refresh","workspace":"<id>"}` for one, each under the workspace's lease in the module's own table, and `{"kind":"check"}` for the secrets of its own kinds only (the workspaces' keys and the OAuth client), where the issuer's keys and the policy's client secrets are not reported. The result of a refresh now carries `paused` for a workspace left alone under maintenance; a failed or unknown workspace fails the invocation. It serves no HTTP, no tick or run and no module call (`google.identify` is not part of it yet), and a zip pinned to another module, or given another module's document, refuses to start. The `sluis-google/v1` document gains `DeclaredSecrets` for the check, and `deploycheck.Own` and `deploycheck.CheckDeclared` let a function check a list of its own.
- **The issuer function hosts only what is not another function's.** With `github.remote`, `slack.remote` or `google.remote` set, `issuerfn` no longer assembles that module's controller or refreshes its directory, and with `cloudflare.remote` it no longer ticks the presets; a module with no remote stays in the process, as the demonstration and the tests have it. With `github.remote` set the issuer's `apps.Minter` is a `githubtokens` client dialled to that function as the caller class `issuer`, with a 10 second deadline per mint.
- **The console's run-now invokes the module's `live-console` alias.** `invoke.Trigger` sends the asynchronous `run` event to `adapters.trigger.settings.github` or `.slack` qualified with the alias `live-console`, not to the issuer function; name the function without an alias.
- **The `refresh` event is now `clients`.** `{"kind":"clients"}` reconciles the generated client secrets and nothing else. `{"kind":"refresh"}` is still accepted for one release and also refreshes the directory where the process hosts it.
- **The Pulumi library has a generic module-function builder.** `newModuleFunction` makes one module's function from the release zip: a configuration layer with the module's own documents, a log group, a role whose policy the caller renders (from `ModuleRoleStatements`), a published function, the aliases `live` and `live-<class>` per caller class, an asynchronous invoke config with no retries, and, when asked for, the post-deploy check. `NewBackup` and `NewRestore` now build on it in place of `buildFunction`, with no resource change: the logical and physical names are the ones they had, and `TestBackupOnTheModuleFunctionBuilderChangesNoResource` holds the backup's resource shape (0 to create, 0 to replace in a preview). Nothing is deployed differently by this change; it is the base for a function per module.
- **An IAM deny matrix for the Pulumi library's roles, and the evaluator it runs on.** `deploy/pulumi/internal/iameval` is a small test-only evaluator of AWS policy documents: Allow and Deny, action and ARN globs, `StringEquals`, `StringLike`, `ArnEquals`, `ArnLike` and `Null` (with `ForAnyValue:` and `ForAllValues:`), `dynamodb:LeadingKeys`, `kms:ViaService` and `kms:EncryptionContext:*`, qualified and unqualified Lambda ARNs, and an identity policy and a key policy evaluated together; it refuses an operator or construct it does not model instead of guessing. `TestEveryRoleIsRefusedWhatItIsNotGranted` renders every v1.75 role (the issuer with and without the Cloudflare minter, backup, restore, and the module-pattern roles) and checks, for each of `Modules()`, that it is refused another module's `internal/<m>/` and `external/<m>/` parameters, writes to another module's table, another module's blob prefix, `kms:Decrypt` for another module's `PARAMETER_ARN`, the sign context (unless it hosts oidc), any function or alias it is not granted, and every write to the maintenance partition, beside the matching allow rows. The matrix fails if it has fewer rows than a pinned count. `TestCrossInvokeGrantsTheQualifiedAlias` records a finding and is skipped (TODO V11a): `CrossInvoke` grants the unqualified function ARN while every module call invokes the `live-<class>` alias. No library behaviour changes.
- **The Pulumi library makes a function and a role per module, and its cross-invoke grants are qualified.** `LambdaArgs.Modules` (keyed by `ModuleFunctions()`: cloudflare, github, github-mint, google, slack) configures each module function's name, zip, memory, timeout, reserved concurrency and document; `NewLambda` always makes the five beside the issuer's (there is no switch that leaves a module in the issuer), named `sluis-<instance>-<module>` by default, on `newModuleFunction`, each with the aliases `live` and `live-issuer`, the post-deploy check, and no platform retry of a pass (a synchronous module call, such as the github mint, is not an event and is unaffected). They need the per-module tables (`Layout` `v5` or `v4+v5`); `v4` keeps the one function. The roles come from `ModuleRoleStatements` and the same module constants as the code: the issuer's role hosts the oidc module, reads the github, slack and google tables and the Google snapshots, and invokes `live-issuer` of the four module functions and `live-console` of the backup (`LambdaArgs.BackupFunctionName`), nothing else. The audit queue names the module roles as senders. Outputs `Functions`, `RoleArns` and `AliasArns` are keyed by `issuer` and the module functions. `packageName` accepts the github, github-mint, slack and google zips. The issuer's own function is not renamed here, and the module functions' documents carry only their `apiVersion` until the per-module documents land. **Fixed in this change:** `CrossInvoke` granted the unqualified function ARN, which a module call (always on `live-<class>`) is denied; it now grants `function:<fn>:live-<class>` and no other qualifier. The previously skipped `TestCrossInvokeGrantsTheQualifiedAlias` runs, and a policy golden per role is held in `testdata/role-*.policy.json`.
- **`config.RenderModules` writes the documents of an installation that runs a function per module.** Beside [Render]'s policy document it returns the issuer's service document, which calls each module by its function (`github.remote`, `slack.remote`, `google.remote` and, where a preset is declared, `cloudflare.remote`, each the function's name: the caller's class picks the `live-<class>` alias; the `invoke` trigger names the github and slack functions), and a document for each module function: `controller-github/v2` for `github`, `controller-slack/v2`, `sluis-google/v1` (the declared workspaces, the `freshness` intervals and the bucket the snapshots are kept in) and `sluis/v3` with `cloudflare.serve` (the accounts, the presets and the policy's grants; none where no preset is declared). Each opens only its own table (`ports.dynamodb.tables`, `ModuleOptions.Tables` or `sluis-<instance>-<module>`; the readiness probe describes every table a document lists), reads its secrets as layout v5, names the issuer's policy file where it reads a policy, and holds what the module owns: the controllers, the declared workspaces and the Cloudflare accounts and presets are no longer in the issuer's document. `aws.functions` names the module functions (default `sluis-<instance>-<module>`; refused: an unknown module, a bad name, a name used twice or the issuer's). `ValidateModule` loads a module's document as its function does and `ModuleSecrets` lists the secrets it declares: the sets are disjoint but for the blob store's credential. `google.oauthClient` is not rendered: the Google sign-in client stays the issuer's until the sign-in after the split is decided.
- **The Pulumi library makes a function and a role per module, and its cross-invoke grants are qualified.** `LambdaArgs.Modules` (keyed by `ModuleFunctions()`: cloudflare, github, github-mint, google, slack) configures each module function's name, zip, memory, timeout, reserved concurrency and document; `NewLambda` always makes the five beside the issuer's (there is no switch that leaves a module in the issuer), named `sluis-<instance>-<module>` by default, on `newModuleFunction`, each with the aliases `live` and `live-issuer`, the post-deploy check, and no platform retry of a pass (the mint-only github function, which a caller waits for, retries). They need the per-module tables (`Layout` `v5` or `v4+v5`); `v4` keeps the one function. The roles come from `ModuleRoleStatements` and the same module constants as the code: the issuer's role hosts the oidc module, reads the github, slack and google tables and the Google snapshots, and invokes `live-issuer` of the five module functions and `live-console` of the backup (`LambdaArgs.BackupFunctionName`), nothing else; the mint-only function reads the github module and writes none of it (`CrossReadModule`). The audit queue names the module roles as senders. Outputs `Functions`, `RoleArns` and `AliasArns` are keyed by `issuer` and the module functions. `packageName` accepts the github, github-mint, slack and google zips. The issuer's own function is not renamed here, and the module functions' documents carry only their `apiVersion` until the per-module documents land. **Fixed in this change:** `CrossInvoke` granted the unqualified function ARN, which a module call (always on `live-<class>`) is denied; it now grants `function:<fn>:live-<class>` and no other qualifier. The previously skipped `TestCrossInvokeGrantsTheQualifiedAlias` runs, and a policy golden per role is held in `testdata/role-*.policy.json`.
- **`config.RenderModules` writes the documents of an installation that runs a function per module.** Beside [Render]'s policy document it returns the issuer's service document, which calls each module by its function (`github.remote`, `slack.remote`, `google.remote` and, where a preset is declared, `cloudflare.remote`, each the function's name: the caller's class picks the `live-<class>` alias; the `invoke` trigger names the github and slack functions), and a document for each module function: `controller-github/v2` for `github` and for the mint-only `github-mint` (which asks nothing of the console and so has no `console` proof), `controller-slack/v2`, `sluis-google/v1` (the declared workspaces, the `freshness` intervals and the bucket the snapshots are kept in) and `sluis/v3` with `cloudflare.serve` (the accounts, the presets and the policy's grants; none where no preset is declared). Each opens only its own table (`ports.dynamodb.tables`, `ModuleOptions.Tables` or `sluis-<instance>-<module>`; the readiness probe describes every table a document lists), reads its secrets as layout v5, names the issuer's policy file where it reads a policy, and holds what the module owns: the controllers, the declared workspaces and the Cloudflare accounts and presets are no longer in the issuer's document. `aws.functions` names the module functions (default `sluis-<instance>-<module>`; refused: an unknown module, a bad name, a name used twice or the issuer's). `ValidateModule` loads a module's document as its function does and `ModuleSecrets` lists the secrets it declares: the sets are disjoint but for the blob store's credential. `google.oauthClient` is rendered once the Google module holds the sign-in client (see the Google console entry).
- **`NewLambda` feeds each module function the document `RenderModules` wrote for it.** With `LambdaArgs.Installation` on a layout with module functions (`v5`, `v4+v5`), a function's configuration layer holds its own `sluis/sluis.yaml` (and the policy document, `sluis/policy.yaml`, where it decides by one: all but the Google module) in place of the `apiVersion`-only placeholder; the issuer's document calls the functions (`<module>.remote`), and a run-now trigger starts the controllers' own. The library adds to them what it supplies: the Google module's `ports.blob` of an external store. `aws.functions` and `LambdaArgs.Modules[<module>].FunctionName` name the same function and are said once (a disagreement is refused naming the argument). A function's post-deploy check re-runs when the secrets its document declares change (`ModuleSecrets`). The Cloudflare module has a function only where the installation declares a preset: its document would not load otherwise, and the deploy's check would fail; the audit queue names its role only then. With the deprecated `Config` and `Policy` the documents stay the `apiVersion` alone (the right one for each module now: `controller-github/v2`, `controller-slack/v2`, `sluis-google/v1`, `sluis/v3`), which a function refuses to start on.
- **The Pulumi library makes a function and a role per module, and its cross-invoke grants are qualified.** `LambdaArgs.Modules` (keyed by `ModuleFunctions()`: cloudflare, github, github-mint, google, slack) configures each module function's name, zip, memory, timeout, reserved concurrency and document; `NewLambda` always makes the five beside the issuer's (there is no switch that leaves a module in the issuer), named `sluis-<instance>-<module>` by default, on `newModuleFunction`, each with the aliases `live` and `live-issuer`, the post-deploy check, and no platform retry of a pass (a synchronous module call, such as the github mint, is not an event and is unaffected). They need the per-module tables (`Layout` `v5` or `v4+v5`); `v4` keeps the one function. The roles come from `ModuleRoleStatements` and the same module constants as the code: the issuer's role hosts the oidc module, reads the github, slack and google tables and the Google snapshots, and invokes `live-issuer` of the four module functions and `live-console` of the backup (`LambdaArgs.BackupFunctionName`), nothing else. The audit queue names the module roles as senders. Outputs `Functions`, `RoleArns` and `AliasArns` are keyed by `issuer` and the module functions. `packageName` accepts the github, github-mint, slack and google zips. The issuer's own function is not renamed here. **Fixed in this change:** `CrossInvoke` granted the unqualified function ARN, which a module call (always on `live-<class>`) is denied; it now grants `function:<fn>:live-<class>` and no other qualifier. The previously skipped `TestCrossInvokeGrantsTheQualifiedAlias` runs, and a policy golden per role is held in `testdata/role-*.policy.json`.
- **Each schedule of the Pulumi library targets the `live` alias of the module that runs it.** With the module functions (`Layout` `v5` or `v4+v5`), `Schedule.GitHubOrgs` ticks `sluis-<instance>-github:live`, `Schedule.SlackWorkspaces` `sluis-<instance>-slack:live`, `DirectoryRefresh` the google function's `live` and `CloudflareRotation` the cloudflare function's `live`; a new `IssuerClients` schedule (`LambdaArgs.IssuerClients`, default `rate(15 minutes)`, `Disabled` and `Paused` as the others, `{"kind":"clients"}`) invokes the issuer's `live`. The logical and physical names of the existing schedules are unchanged, so a preview updates their targets in place and replaces none; only `<name>-issuer-clients` is created. There is still one scheduler role and one policy, which now names exactly the aliases its schedules invoke (none when none is declared). `Layout` `v4` keeps every schedule on the one function and makes no clients schedule. The issuer must answer `{"kind":"clients"}` before an estate leaves the schedule enabled on a deployed issuer older than that handler: set `IssuerClients.Disabled` until then.
- **The Pulumi library generates the shared key's policy for every role, and returns the role lists an estate feeds from.** `LambdaArgs.KeyPolicyStatements(KeyPolicyOptions)` (also on the built `Lambda`) renders `SluisKeyPolicyStatements` over the issuer, the five module functions, the backup and the restore, so an estate composes the key policy from the library rather than writing roles by hand; the roles are named by ARN derived from their names, so the key can be made before the functions. A role that reads modules without hosting them can be given `SluisKeyReadModule<Role>` (`KeyRole.ReadModules`): `kms:Decrypt` and `DescribeKey`, through SSM, of exactly those modules' parameters. `Senders()` (roles that emit audit records and OTLP), `Roles()` and `ViewerRoles()` (roles that read modules without hosting them) are returned by `LambdaArgs` and `Lambda`, for the audit ingest senders, the OTLP writers and the viewer matchers. `LambdaArgs.TransitionRoles` keeps the old IAM name of a renamed role (the issuer) as a further principal of the same role while the switch is made: the key policy, the sign context included, and the audit queue admit both names; `LambdaArgs.RestoreFunctionName` names the restore function. `NewExternalReaderRole` makes a reader role for exact `external/<kind>/<id>` addresses, trusted by the caller's own trust policy (IRSA, Pod Identity, the External Secrets Operator) or one exact principal, with the policy of `ExternalReader` and the key-policy statement it needs (`KeyStatement`, merged through `KeyPolicyOptions.ReaderStatements`); a wildcard, a prefix or a missing trust is refused. Tests hold a key-policy golden for a plain and a switching installation (8.6 and 9.6 KiB of KMS's 32 KiB), that no role without the oidc module reaches the sign context, and that a reader role grants exactly its addresses.
- **The chart renders one workload per module with `split: true`.** New values `split` (default `false`, which keeps today's single Deployment and leaves every existing render unchanged) and `modules.<m>.{enabled,replicas,resources,image,serviceAccount,config}` for `issuer`, `github`, `slack`, `google` and `cloudflare` (`rpcPort` and `audience` for the three that answer calls). Each enabled module gets a Deployment, a ServiceAccount `<full name>-<module>` and a ConfigMap `<full name>-<module>-config` holding its own document; github, google and cloudflare get a Service on `/rpc`. The controllers' Role is bound to the github and slack accounts only, and the three callees' accounts are bound to `system:auth-delegator` for the TokenReview of a caller's projected token. The issuer's document is `config` without `controllers`, plus `calls.modules.<module>` (`url`, `audience`, `tokenFile`) for each enabled callee, and the issuer pod projects one token per audience. The release's Service and routes stay on the issuer. `split` is refused with `documents.service`, and with a `config.controllers` section whose module is off. `split: false` is deprecated and goes in v1.77. See `charts/sluis/values.yaml` and the `split-minimal` golden case.
- **Reworked to D-v176-9: the chart has the per-module model only.** The `split` value and the single Deployment are gone. The chart always renders the issuer, and each of github, slack, google and cloudflare when `modules.<module>.enabled`: a Deployment, a ServiceAccount, a ConfigMap `<full name>-<module>-config`, a PodDisruptionBudget and, with `networkPolicy.enabled`, a NetworkPolicy; github, google and cloudflare also get a Service on `/rpc`. This supersedes the entry above where they differ. The issuer's document routes with the per-module `github.remote`, `google.remote` and `cloudflare.remote` (`url`, `audience`, `tokenFile`), not `calls.modules`, and a `config.<module>.remote` that is also enabled as a module is refused. The release's ServiceAccount, ConfigMap and Deployment are now `<full name>-issuer`'s (the issuer keeps `serviceAccount.name` and `serviceAccount.awsRoleArn` when set), and every pod reports as `sluis-<module>`. `documents.service` still renders the issuer's document verbatim, with the controllers it names in the issuer's pod; no other module can be enabled with it.
- **The chart adds a NetworkPolicy, a PodDisruptionBudget and an issuer HPA per module.** `networkPolicy.enabled` renders one policy per module: the issuer takes the gateway, `networkPolicy.clients` and the controllers' pods; github, google and cloudflare take `/rpc` from the issuer's pods alone; slack takes no ingress. Egress (`networkPolicy.egress`, on unless `egress.enabled: false`) is DNS, the module's peers, HTTPS to `egress.https` and `egress.extra.<module>`. `modules.<module>.podDisruptionBudget` (on, `maxUnavailable: 1`; `minAvailable` instead if given) and `modules.issuer.autoscaling` (an autoscaling/v2 HPA, off) are new. The chart refuses an enabled module with no document section (`config.controllers.<kind>` or `modules.<kind>.config` for github and slack, `modules.<module>.config` for google and cloudflare), a `config.cloudflare` beside the cloudflare module, both budget fields, a `minAvailable` that allows no eviction, and an HPA with no request to follow, with `replicas` set, or with `maxReplicas` under `minReplicas`. New golden cases: `all-modules` (was `split-minimal`) and `hardened`.
- **The release builds and publishes the Lambda zips and module images of the github, slack and google modules.** `.goreleaser.yaml` builds `sluis-github` (which also serves the issuer's token mint), `sluis-slack` and `sluis-google` as arm64 `bootstrap` zips pinned to their module, beside the issuer, cloudflare and backup zips; `hack/release-zips.txt` and `hack/release-images.txt` list them, so each zip is checksummed and each image signed and attested. `just lambda-size` holds each bootstrap to a budget of its own. `hack/check-zips.sh` now matches a pin exactly, so the `github` zip is not taken for carrying the pin of `github-mint`. The release build needs `cmd/sluis-github`, `cmd/sluis-github-mint`, `cmd/sluis-slack` and `cmd/sluis-google`, which arrive with the units that split those modules.
- **A container-free Lambda end-to-end harness, `internal/lambdaapp/lambdatest` (tests only).** An httptest server speaks the Lambda Invoke API and routes `FunctionName` plus `Qualifier` to in-process `lambdaapp.Function` handlers; the qualifier reaches the function as the invoked ARN's alias, so the caller class (`live-<class>`) is derived as on the platform. State is the in-memory port, secrets a small SSM fake, GitHub `githubfake`. One scenario runs on today's code (the issuer's `check` event); the v1.76 scenarios are listed as TODOs in the test file. Nothing in a release artifact changes.
- **The Slack workspace pages run in the Slack module.** Connecting, disconnecting and reading a workspace, changing its owner, asking for a pass and confirming removals are `slack.console.begin_workspace_connect`, `complete_workspace`, `disconnect_workspace`, `change_owner`, `request_pass`, `get_status` and `confirm_removals`, served by `internal/slackapp/console` to the caller class `console` alone. The console keeps the browser's half: it authenticates, signs the install's state and pins the browser, and renders the callback's page. With `slack.remote` unset it calls the module in its own process (`modcall.Local`), as before. The owner rule runs in the module on the caller's snapshot (`internal/consoleauthz`), the pass notification is the module's own tick request for the Slack controller, and a callback forwards the code to `complete_workspace` once, with a 25 s deadline and no retry by the transport (`modcall.WithoutRetry`; the Lambda client sends it with one attempt), because Slack's code is single use. `modcall.Target.MaxBytes` raises the bound for a module whose methods list. Nothing changes on the wire to the browser.
- **On Kubernetes the GitHub and Slack modules serve the issuer on `/rpc` (`github.serve`, `slack.serve`).** The module's process listens on `serve.address` (`:8081` when unset) beside its controller loop and answers `POST /rpc` with the `github.console.*` methods and `mint_installation` (GitHub) or the `slack.console.*` methods (Slack), as the Cloudflare module does. A call carries a projected ServiceAccount token minted for `serve.audience` (the module's name when unset), checked with a TokenReview, and its subject must be one of `serve.issuers` (`system:serviceaccount:<namespace>:<name>`, at least one): that subject holds both the `issuer` and the `console` class, since one pod makes both calls, and any other subject, including a ServiceAccount of the same name in another namespace, is a 401 and reaches no method. The class comes from the verified subject, never the payload (`modcall.WithSubjectClasses`). `serve` with `remote` is refused, and so is `serve` in the issuer's document. The chart (per-module only, D-v176-9) makes slack a module that answers calls: a Service and an `rpc` port, `<module>.serve` written into the github and slack documents with the issuer's account, `slack.remote` in the issuer's document, a projected token on the issuer for each audience, an `system:auth-delegator` binding, and, with `networkPolicy.enabled`, a NetworkPolicy that takes `/rpc` from the issuer's pods alone (slack took no ingress before). New values: `modules.slack.rpcPort` and `modules.slack.audience`. This supersedes the entry above where it says the Kubernetes chart keeps the Slack pages in the issuer. The golden cases `all-modules`, `hardened`, `full`, `controllers-ha`, `migrated` and `telemetry` change. See `docs/reference/sluis/kubernetes-objects.md`.
- **The Cloudflare listener lets in the issuer's real ServiceAccount (`cloudflare.serve.issuers`).** It used the ServiceAccount's name as the caller class, so the chart's `<release>-issuer` account was never the `issuer` class. The listener now runs on `internal/modserve` like github and slack: `cloudflare.serve` takes `issuers` (`system:serviceaccount:<namespace>:<name>`, which the listener requires; the chart writes the issuer's account), that subject holds the `issuer` and `console` classes, and any other subject is a 401. `modcall.ClassOfSubject` is removed: a subject is no longer read as a class from its ServiceAccount's name.
- **The Slack catalogue pages run in the Slack module.** Listing the declared Apps, creating one, installing it and finishing its install are `slack.console.list_apps`, `create_app`, `install_app` and `complete_catalogue`, served to the caller class `console` alone. The module holds the Apps' client secrets and bot tokens. The console signs the install's state and adds it to the authorize URL the module returns, and its callback route forwards the code once, with a 25 s deadline and no retry. A module that does not answer is a page that says the install may or may not have finished, never a 5xx. The directory facts a source or an owner is checked against come through a `Directory` seam the console answers from its hub.
- **The Slack channel pages run in the Slack module.** Listing, creating, updating and deleting a console channel, and the same four for a Slack Connect channel, are `slack.console.list_channels`, `create_channel`, `update_channel`, `delete_channel` and `list_shared_channels`, `create_shared_channel`, `update_shared_channel`, `delete_shared_channel`, served to the caller class `console` alone. The module owns the channel records, checks the owner rule on the stored workspace, archives a channel in Slack on request, and asks the Slack controller for a tick itself after each write, naming the controller. The trail still names each listed person by a minted `directory_user` identifier and never by address. The boundaries test now forbids `internal/server` from importing any `internal/slackapp` package beyond `internal/slackapp/console`, the module's console surface.
- **The Slack function serves the console's Slack pages, and the console sends the directory facts a call needs.** `sluis-slack` answers `slack.console.*` on its `live-console` alias to the class `console` and to no other, opening the module's stores on the first call; the Pulumi library gives the function that alias and the issuer the grant to invoke it. A module reads no directory: the envelope of a console call carries `directory`, built by the console from the hub it holds: the connected directories (at most 256) for owner choices and the owner rule, the groups of each for the channel pickers (at most 4000), and, by lowercase address, whether each source or listed person of the request is a group or an active user of a connected directory (at most 2000). The module refuses facts that are oversized, name a directory twice or none, or place an address in a directory they do not list, and refuses a source or person the facts say nothing of. The Kubernetes chart keeps the Slack pages in the issuer for now: the Slack process has no `/rpc` listener yet.

- **Organisation connect is the GitHub module's.** `github.begin_connect`, `complete_create`, `complete_install`, `disconnect_organisation`, `change_organisation_owner` and `request_pass` run in the new `internal/githubapp/console` (the handlers of the console's `github_connect.go`, `github_owner.go` and `github_pass.go`, moved with their history), served over `modcall` to the caller class `console` only; the console keeps authentication, the coarse role and the snapshot of who is calling (`consolecall.Caller` now also carries the actor's source and the connected directories the console knows, since the module reads no directory record), and the module runs the owner rule on that snapshot (`internal/consoleauthz`; the rule itself is `internal/ownerrule`, shared with Slack). The provider callbacks `/connect/github/callback` and `/connect/github/setup` stay routes of the issuer: it verifies the signed state and the browser's cookie and forwards the one-time `code` to `complete_create` and `complete_install` with a 25 second deadline and no retry, because GitHub's code is single use; the session key never leaves the issuer, so the module returns URLs carrying a placeholder where the issuer signs the next state. A refusal a person should read crosses as a `Problem` (now with a Connect `code` and, for a callback page, an HTTP `status`); anything else is told in fixed words with the reason in the log. `consolecall.HandleJSON` and `ProxyJSON` register and call a method over plain Go values. With `github.remote` the console calls the github function as `live-console`, and that function registers the methods on the server that serves the mint; with none the module is served in the process. The module sends its own tick after a write, naming its controller. The shared `connection.Store` is the connections interface.
- **The Apps view, the GitHub page and an App's webhook are the GitHub module's.** `github.list_apps`, `get_app`, `list_app_tokens`, `check_app`, `rotate_app_webhook`, and with them `get_status` (the GitHub page) and `check_catalogue_app`, run in `internal/githubapp/console` (the Apps model and its views, the short cache of what GitHub says of an App, the webhook rotation with its ping, and the status page, moved with their history). The console proxies them as the class `console`; its Begin and Disconnect for any App ask the module which kind of App an id is, and whether the caller may operate it, before running the flow. The module reads the connected directories from the caller snapshot the console sends (`consolecall.Caller.Directories`) and its own address from `Origin`, so the github function needs neither a copy of the directory nor of the console's URL in its document. The console builds the module in its own process, over its own stores, the first time a GitHub page is asked, unless `github.remote` names another function; that function (`internal/lambdaapp/githubfn`) serves the console methods on the server that serves the mint, for the class `console` (`live-console`) only. The store interfaces (`catalogueapp.Store`, `runnerapp.Store`, `link.AppStore`, `link.Links`, `connection.ConfirmationStore`, `status.ReportReader`) are declared beside their records.
- **Catalogue and runner Apps are connected, installed and disconnected by the GitHub module.** `github.begin_catalogue_connect`, `complete_catalogue_create`, `complete_catalogue_setup`, `disconnect_catalogue_app` and, for a tier's runner App, `begin_runner_connect`, `complete_runner_create`, `complete_runner_setup`, `disconnect_runner_app` run in `internal/githubapp/console`, with the catalogue App's webhook secret made and set there. The four provider callbacks (`/connect/github/catalogue/{callback,setup}` and `/connect/github/runner/{callback,setup}`) stay routes of the issuer, which verifies the signed state and the browser's cookie and forwards the one-time code with a 25 second deadline and no retry; a page the module cannot finish is told as a refusal of the module's (with its HTTP status), or in fixed words with the reason in the log. The module asks again, against the caller snapshot, whether whoever finishes a flow may still operate the organisation.
- **The link App and people's links are the GitHub module's, and the console imports nothing of GitHub's App code.** `github.begin_link_app_connect`, `complete_link_app`, `disconnect_link_app`, `link_page`, `link_complete`, `confirm_removals` and `import_links` run in `internal/githubapp/console`, with `begin_app_connect` and `disconnect_app` (any App by its id) dispatching in the module. The link page and its callback stay public routes of the issuer with no session: the issuer signs the state, pins it to the person's browser with the link cookie, verifies both on the way back and forwards only the one-time `code` (or GitHub's refusal) to `link_complete`, which exchanges it, asks GitHub who the account is and which addresses it verifies, asks which of those the directory vouches for, and keeps the link. Each client address gets 20 requests a minute on the three link routes (a 429 page, and the module is not asked), and the module finishes at most 60 links a minute whoever asks. The module reads no directory: `import_links` and `link_complete` ask `Deps.Directory`, which is the authorizer in the process that hosts the console and the console's own `Explain` (as the roster controller identity) in the github function. The shared server's boundaries rule now holds for GitHub: `internal/server` imports `internal/githubapp/console` and no other package of `internal/githubapp` (`consoleDoor`), and `ConsoleDeps` names the catalogue and the mint ring through that package.
- **The module isolation is proved in IAM and end to end (v1.76 E-IAM).** The deny matrix gains the issuer's rows (writes and reads on the github, slack, google and cloudflare tables, the `github/`, `slack/` and `google/` blobs, every non-oidc parameter with the key use that opens it, and each lambda alias) and the converse rows for the four provider roles, all generated from the module constants. A code-level test holds every provider method's `Allow` to `console` or `issuer`, so a console method called as the issuer is forbidden. An end-to-end test (`internal/rosterapp`) runs the issuer with `github.remote`, `slack.remote`, `google.remote` and `cloudflare.remote` over the Lambda transport to the real module handlers: one console page per module, the GitHub link in two calls with the second sealed, the Google identify at sign-in and the GitHub mint, with the issuer holding none of their stores. The issuer dials the Cloudflare remote through `rosterapp.Config.Dial`, as it does the others.

### Changed

- **The GitHub console reads the directory through the call's directory facts, the one mechanism Slack uses (v1.76).** The GitHub module never reads the directory and never calls back into the issuer for it: the issuer resolves what a method needs and sends it in the envelope (`consolecall.Envelope.Directory`). The connected directories (for choosing an owner) go with every GitHub console call; the addresses of an import go as `Users`. A link is finished in two calls, because GitHub names the account's addresses only after the one-time code is spent: the module stops after the exchange, answers with the addresses to resolve and a state sealed under the link App's client secret (two minutes, opaque to the issuer), and the issuer calls again with the facts. `Caller.Directories`, `ghconsole.Deps.Directory` and the github function's own `Explain` client are removed; the roster controllers' `Explain` (group `all:sluis:roster-controller`) is unchanged. `UserFact` gains `in_domain` and `authoritative`.
- **One GitHub function serves both the organisation passes and the installation-token mint (D-v176-7 a).** The issuer's `apps.Minter` dials the github function's `live-issuer` alias; its console methods stay on `live-console` and its schedules on `live`. The github role gains nothing for it: the mint decrypts the github parameters the role already reads, and no other module's. The deny matrix is checked against the github role alone and has no mint role rows.
- **Breaking: the Lambda functions and their roles are named `sluis-<instance>-<module>` (D-v176-2 b).** The issuer's default name moves from `sluis` (`FunctionNamePrefix`) to `sluis-<instance>-issuer`, as the github, slack, google, cloudflare and backup functions already are; `Installation.AWS.Functions` takes the keys `issuer` and `backup` beside the modules, and `aws.functionName` is kept for estates that set it. **Upgrade note.** An estate may keep its name by setting `FunctionName` (or `aws.functions.issuer`) to the one it has (`sluis`, `sluis-http`): nothing is replaced. An estate that takes the default has the issuer's function, role, role policy, log group and asynchronous invoke config replaced, create-before-delete (D-v176-3 a); the API integration, the schedules and the invoke grants are updated to the new function in the same apply, so there is no downtime, and tables, parameters, keys and buckets do not change. The resources keep their identity through `pulumi.Aliases`: their logical names are now `<name>-issuer`, `<name>-issuer-role` and `<name>-issuer-policy` (aliased from `<name>-http*`). Set `LambdaArgs.TransitionRoles` for that apply so the key policy and the audit queue admit both role names, and remove it once the old role is gone. Add the new role to the foundation key policy, the audit senders and the viewer matchers before the apply (the `sluis-http` entries stay until it is done). The old log group is not deleted by the library's own intent (the issuer's log group is `RetainOnDelete` from now on); on the first rename it goes with the replaced resource unless one earlier apply pinned the old name, so export what you need first. `OTEL_SERVICE_NAME`, alarms and dashboards that name the old function follow the new name.
- **Breaking: `Explain` (sluis.v1 and directoryroster.v1 `AccessService`) is for operators and the roster controllers only.** An operator may look anyone up and each look-up is audited; a workload in the group `all:sluis:roster-controller` (the GitHub and Slack controllers; the policy's `service_account` or `aws` matchers place them there, and an installation must) is served, unrecorded; any other workload is treated as a person, whatever role it holds. A viewer, or a person asking about themselves, is refused with `not authorised` and the refusal is audited as denied. The console shows a person's effective access and the Rules "Test a proof" box to operators only.
- **Breaking for callers that relied on the defaults: the Pulumi library's `LambdaArgs.SigningKeyRS256Alias` and `LambdaArgs.WrappedSigning.KeyAlias` have no default.** They defaulted to `alias/sluis-signing-rs256` and `alias/sluis-signing-wrapped`. While the library creates the RS256 key (`Keys` and `WrappedSigning` unset, `DisableSigningKeyRS256` false), `NewLambda` refuses an empty `SigningKeyRS256Alias`; when it creates the wrapping key (`WrappedSigning` set, `KeyArn` unset) it refuses an empty `WrappedSigning.KeyAlias`. Each error names the field. Set them, for example to `alias/sluis-<instance>-sign-rs256` and `alias/sluis-<instance>-wrapped`, or supply the keys with `Keys` or `WrappedSigning.KeyArn`, which are unaffected. `DefaultSigningKeyRS256Alias` and `DefaultWrappedSigningKeyAlias` are removed. An existing estate that kept the defaults sets `SigningKeyRS256Alias: "alias/sluis-signing-rs256"` and `KeyAlias: "alias/sluis-signing-wrapped"` to keep its keys. The wrapped-signing path and the wrapped entries' encryption context (`purpose: sluis-signing`) are unchanged.
- **`sluisctl` signs in as the client `sluisctl` by default, and falls back to `accessctl` once.** With no `--client` and no `clientId:` in `config.yaml`, `login` asks the issuer's token endpoint whether it knows `sluisctl`; if it answers `invalid_client`, `login` signs in as `accessctl` and says on stderr that this is deprecated. An explicit id never falls back. The session records the client it ran as, so refreshes and exchanges keep using it, and `login` no longer writes a defaulted id into `config.yaml`. **Before upgrading workstations, each estate registers a `sluisctl` client** (`kind: public`, the loopback redirect, the same `requires`) beside `accessctl` in its policy; `accessctl` is retired one release later. A `clientId: accessctl` line written by an older `login` counts as explicit: delete it to move to `sluisctl`. The `full` chart case declares both.
- **`sluisctl kubeconfig` writes `sluisctl:<cluster>` users and renames old ones.** An existing `accessctl:<cluster>` user that runs `kube-token` is rewritten as `sluisctl:<cluster>` (keeping its audience and issuer, pointing at the running binary), every context that named it is pointed at the new user, and the old user is removed. Running it again changes nothing.
- **The managed SSH known-hosts file is `~/.ssh/known_hosts.d/sluisctl`.** When only `known_hosts.d/accessctl` exists, the default path is copied once (the old file stays, `.migrated-from-accessctl` is written beside the new one). `sluisctl ssh known-hosts` says to change an `~/.ssh/config` that still names the old file. `--file` is unchanged.
- **The issuer no longer reads another module's data (v1.76 E-FIN).** With a provider module another function's (`github.remote`, `slack.remote`, `google.remote`, `cloudflare.remote`), the issuer opens none of its stores, blobs, credentials or maintenance gate; every console operation, the mint and the sign-in are asked over modcall. The module in the process (demonstration, tests, no `<module>.remote`) is unchanged. The Pulumi library's issuer role (grants from the same constants as the code, D295 a) loses: the `CrossReadTable` grants on the github and slack tables; the `SluisCrossCloudflareMinter` statement and the issuer's key use on the minter's credential reference; the issuer's SSM and parameter-key reads on every module but oidc. Its Google access is the snapshot alone, a new `CrossReadSnapshot` verb: table `GetItem` and `Query` (no `Scan`, no `DescribeTable`) and `google/` blob `GetObject`. Invoke grants are alias-qualified only: `:live-console` on github, slack, google, cloudflare and backup, and `:live-issuer` on github (mint), google (identify) and cloudflare (mint); the `slack:live-issuer` grant is removed, and `cloudflare:live-console` added. The issuer-role golden and the deny matrix follow. **Upgrade note.** No estate-side change is expected, because the library owns the grants: the next apply narrows the issuer's role policy, and the maintenance banner of the github, slack and cloudflare modules is no longer read by the issuer. An estate that attached its own policy to the issuer role for a provider table or parameter should expect the console to ask the module instead.

- **Only the cloudflare function holds the Cloudflare minter's parameter (v1.76 E-IAM).** The github, slack and google module roles no longer carry the minter statement, and `ModuleRoleStatements` gives it to a role that hosts the backup module and to no other. The issuer's peers narrow to the Google snapshot: `rosterapp.IssuerPeers` no longer lists `github` and `slack`, and with `google.remote` the issuer's view of the Google module's records is read only (`port.ReadOnlyState`, `port.ReadOnlyBlob`) whatever its role would allow.

### Removed

- **The separate `github-mint` module is folded into `github`, in the same unreleased line that added it.** Removed: `cmd/sluis-github-mint`, `internal/lambdaapp/githubmintfn`, `config.ModuleGitHubMint`, `lambdaapp.ModuleGitHubMint`, `RoleGitHubMint`, `DefaultMintMemoryMB` and `DefaultMintTimeoutSeconds`, the `sluis-github-mint` zip, image and archive from the goreleaser build, the release matrix and the zip and image lists, and `github-mint` from `aws.functions`. An estate that deployed a `sluis-<instance>-github-mint` function (a release candidate of this line) sees that function, its role, policy, log group, aliases, check and configuration layer deleted by the next apply, with nothing else changed: no table, parameter or key is touched. Delete any `aws.functions.github-mint` entry first, as the installation schema now refuses it; the key policy, the audit senders and the viewer matchers that named the `github-mint` role should drop it too.
- **The `accessctl` alias binary is no longer shipped; use `sluisctl`.** The `accessctl` build, the `accessctl_*` archive and the `accessctl` Nix flake are gone from the release, and `sluisctl` no longer prints the deprecation notice for the old name. Point devbox packages, download URLs and Nix flake inputs at `sluisctl_*`.

### Security

- **A refused caller is told "not authorised" and a request id, and nothing about why.** Every refusal from the issuer's OAuth endpoints, its sign-in and sign-out pages, the console's sign-in, the operator calls, the ConnectRPC services and the directory listener now says `not authorised (request <id>)` (`invalid request` for a malformed request, `server error` for a fault of ours; `Not authorised. Reference: <id>` on a page). It no longer names the client, audience, group or address, quotes a raw error, or reveals that recovery is turned off. Every response carries `X-Request-Id`: a well-formed one from the caller (8 to 64 letters, digits and `.` `_` `:` `-`) is kept, and otherwise one is generated. An operator finds the reason in the log (`request_id`) and in the audit trail (`context.request_id`) under that id. An unknown client and a wrong secret are one answer, and so are an unknown audience and one the proof is refused (`invalid_target`); `invalid_client` is `401` with `WWW-Authenticate` when the client sent an `Authorization` header and `400` when it did not (it was `401` for both). A subject token the library cannot verify is `invalid_grant` (it was `invalid_request`). Clients that matched on a description (`unknown client`, `the refresh token is not live`) must match on `error`. The audit catalogue is 1.20.0: a refused token exchange or sign-in (`roster.token.exchanged`, `roster.person.signed_in`, `roster.recovery.signed_in`) records `reason_code`, `audience`, `missing_requires`, `held_groups`, `admitted`, `admitted_by` and `directory`. A refused exchange now always leaves one record, including an unknown audience and a subject token the issuer would not accept, which left none. `AccessService.Explain` still names the groups behind its answer to a caller who may ask; that is decided separately.

## v1.75.0

### Changed

- **A function's role may list its own modules' parameter paths, so the hourly look for orphaned client secrets no longer fails on AWS.** `ModuleRoleStatements` granted a module's parameters as `.../external/<module>/*` and `.../internal/<module>/*`, but SSM authorises `GetParametersByPath` against the bare path ARN (`.../external/<module>`), which `/*` does not match. The issuer role was therefore refused the listing of `external/oidc` on every tick (CloudTrail, kernel estate: 4 an hour), `Secrets.List` returned the error, and `clientcreds.ReconcileOrphans` logged "the stored client secrets could not be listed, so orphans are not looked for" at WARN and returned: a stored client secret whose client had left the policy was neither marked `orphaned` nor reported (`client_secret.orphaned` audit record and its metric), so nothing told the operator to purge it. Creating and rotating the generated clients' secrets was unaffected. Each hosted module now carries a `SluisParametersList<Module>` statement allowing `ssm:GetParametersByPath` on exactly its own two bare path ARNs (`internal/<module>`, `external/<module>`) and nothing else; the get, put and delete grants keep `/*`. Cross-grants (`read-all`, `write-all`) are unchanged. An estate takes it by bumping the library and redeploying.
- **A Slack hold is audited once per transition into held, identified by a stable reason code, not by its sentence.** `roster.slack_action.held` was keyed by channel, person, change and the reason's free text, and some reasons carry counts that move while the hold stays the same hold (the removal limit's "4 of 7 members" becomes "5 of 8" as people come and go), so a hold that sat unchanged was audited again on every pass for as long as the counts kept moving. `reconcile.Held` now carries a `Code` (`reconcile.Code*`, such as `removal-limit-channel`, `no-slack-account`, `archived`) and its key is channel, person, change and code; the sentence stays in the audit record's reason. A hold whose code changes is audited again; a sentence that changes under the same code is logged at info and not audited. The keys the previous process persisted in the workspace report (`recorded`) carry the old sentences, so the first pass after the upgrade audits each current hold once more. The cold-start seed itself (the report's `recorded`, read back from the store) was sound and is now held by a test over cold-starting ticks. The GitHub roster is not affected: its held-row key is team, address, login, action and state, with no free text.

## v1.75.0-rc.13

### Changed

- **Every run-now event names its controller, including the ones a controller's own watch sends.** On v1.75.0-rc.12 the GitHub and Slack controller functions still handed a requested pass (a catalogue App created or installed in the console, which asks the organisation for a pass) to the trigger with no policy loaded, and that trigger sent `{"kind":"run","target":"<name>"}` with no `controller`; for a name that is both a Slack workspace and a GitHub organisation the function refused it (ERROR "an event names no controller and its target is declared for more than one") and the two controllers contended for one lease. The senders now name the controller they concern through `port.NotifyController` (the controllers' watches, the Slack Connect hand-off, and each console write to a GitHub organisation or a Slack workspace send one event, to that controller only), and the trigger's fallback for a target it cannot classify names each configured controller instead of none. `TestEveryEventNamesItsController` and `TestNoControllerlessNotify` fail on any `invoke.Event` literal without `Controller` and any controllerless `Notify` call outside the trigger adapters.
- **A Slack channel's individually listed people are recorded under a minted identifier, not their address.** `roster.slack_console_channel.created|updated|deleted` and the Slack Connect `roster.slack_shared_channel.*` records named each listed person as a `directory_user` target by address, which the audit writer refuses when external identifiers are declared opaque ("reads as something that names a person by itself"); the batch was retried from the queue and refused again. The target is now `du_` and 128 bits of the SHA-256 of the lower-cased address (`audit.DirectoryUserID`), the same for one person in every record. The catalogue (1.18.0) is unchanged; its description of the target type still says "by address". `TestNoPersonTargetReadsAsAnAddress` holds every record of every action to the writer's rule for person targets. Records already refused and retried from the queue stay refused until the queue's batch is dropped; only records written after the deploy carry the minted identifier.

## v1.75.0-rc.12

### Changed

- **A tick or run-now event names its controller, so a name that is both a Slack workspace and a GitHub organisation is synced by both.** The one function picked the controller from the event's target alone, asking the policy whether a Slack workspace declared it before whether a GitHub organisation did. For a name that is both, the per-organisation GitHub schedule `{"kind":"tick","target":"<name>"}` therefore ran the Slack controller, which collided with Slack's own lease (`outcome=contended`), and the organisation's GitHub membership was not synced. It is a regression of the one-function layout, not of one release candidate: before v1.63.0 there was a function (and role) per controller and each schedule invoked its own, so the target never had to say; the single function and the target-only routing arrived together in v1.63.0 (2026-10-05). It went unseen while no name was both, and an estate whose name is both has had no GitHub sync for it since it deployed a release with the function (observed on v1.75.0-rc.11). Now the events carry `"controller":"github"|"slack"` and the function routes by it alone: an unknown controller, and a target the policy does not declare for the named controller, are refused with an error. An event without `controller` (a schedule an older library rendered) still routes when exactly one controller declares its target, and is refused, logged at ERROR with both controllers, when both do, instead of guessing. The Pulumi library's per-target schedules (`ScheduleArgs.GitHubOrgs`, `SlackWorkspaces`) send `{"controller":"github"|"slack","kind":"tick","target":"<id>"}`, under the same schedule names, so a deploy updates each schedule's input in place and replaces nothing; the console's run-now (`invoke.Trigger`) sends the same field, and for a name both controllers declare it invokes each. **Estates must deploy the library change so that their schedules carry the field; until they do, a name that both controllers declare is not synced on GitHub (the legacy tick is refused, with an ERROR in the function's log), and a name only one declares works as before.**
- **An App's `events` that GitHub's manifest would refuse are refused when the configuration loads.** An App declared with `events: [package, registry_package, pull_request]` loaded, and the console's Create then failed on GitHub with "Default events unsupported: package". `package` is a legacy organisation and repository webhook event that GitHub Apps cannot subscribe to; the load now refuses it, naming the App and the event (`package`: use `registry_package`, permission packages: read). An event is also refused when its permission is not declared at read or above: `push`, `create`, `delete`, `release` need `contents`; `pull_request` `pull_requests`; `registry_package` `packages`; `workflow_run`, `workflow_job` `actions`; `issues` `issues`; `check_run`, `check_suite` `checks`; `deployment` `deployments`; `status` `statuses`. Other events are not checked. A catalogue that declares only covered events loads as before.

### Removed

- **`claim_merge` is removed; a policy that declares it is refused.** Translating groups into a consumer's filters belongs to the consumer.
- **Per-audience scoping of `claims.<group>` fragments (added in rc.9) is removed.** A token again carries every held group's fragments, and enforce scoping narrows only `groups`.

## v1.75.0-rc.11

### Added

- **The backup and restore functions start when the audit records go to SQS: the library renders the queue under the name the runtime decodes.** On v1.75.0-rc.9 `NewBackup` and `NewRestore` wrote `adapters.audit` as `sqs` with `settings: {queue: <url>}`, but the `sqs` audit adapter's settings are `queueURL`, `region`, `endpoint` and `timeout` and are decoded strictly, so every invocation of an installation that sends audit over SQS stopped at start with `adapters.audit.settings: settings: json: unknown field "queue"` (`Runtime.ExitError`). The documents now carry `queueURL` and `region`, the same as the issuer's. Only the SQS case was affected; an installation with no `AuditQueueURL` renders the `log` adapter and started. Nothing the runtime accepts changed; an estate takes this by bumping the library and the release pin together.
- **A test runs each runtime's loader over every document the library renders.** `TestEveryRenderedDocumentLoadsInItsRuntime` (`deploy/pulumi`) renders the issuer, backup and restore documents for each audit variant (sqs installed, sqs given, sqs named by the estate, log) and each blob (S3, external) and state (one table, a table per module) variant, and `internal/renderedcheck` loads each with its function's loader and applies the audit adapter to the audit configuration, opening no store. `store.Config.Plan` and `backup/app.Config.AuditConfig` expose the adapter plan and the audit configuration without opening anything.
- **The audit catalogue declares `team` for `roster.github_owner.reported`, and a guard holds every constructor to the catalogue.** The GitHub controller reports an organisation owner it will not remove against the team the pass was working on, and that record carries a `team` target, which the catalogue (1.17.0) did not declare for the action: the audit emitter refused it (`targets[0]: action roster.github_owner.reported is not declared to act on "team"`) and the record was dropped, every pass. The catalogue is 1.18.0 and the action's target types are `organisation`, `team` and `github_account`, like the other GitHub member actions. The audit records are not retried: the dropped ones are not recoverable. Two tests now hold the code to the document: one reads the source for every exported constructor that returns a record and fails on one that `every()` does not exercise, and one runs each constructor that takes a `Member` over every shape of Member (with and without a team, with and without a login) against the catalogue.
- **The installation sets `controllers.github.appNames`.** The installation document's `controllers.github` takes `appNames` (`{org: name}`) next to `appRefs`, and rendering copies it into the policy document's `controllers.github.appNames`, where it is held to the same checks (at most 34 characters, bound organisations only). An estate that renders its policy from the installation (`sluisctl render`, `config.Render`, the Pulumi library) could not set the names before: the render refused `appNames` as an additional property.

### Changed

- **Blobs sit under their module's prefix, so a module's role is granted all it uses.** On layout v5 the Pulumi library grants a function role `<module>/*` of the bucket, but the GitHub and Slack controllers' reports were at `reports/github/` and `reports/slack/` and the hub's cache at `google/`, so on an S3 bucket every controller pass logged "the last report could not be read" (403) and the console's GitHub page could not list its reports. The reports are now `github/reports/<target>` and `slack/reports/<target>` and the cache `google/cache/<workspace>`, all defined once in package `blobprefix` and taken from there by the code, the backup export and restore, the migration and the IAM policy; a test fails on a blob prefix spelled anywhere else and on one the rendered roles (the module's host, backup, restore) do not cover. Nothing is copied: the controllers write the reports again on the next pass, and `sluis migrate v5` copies a source's `reports/github/` and `reports/slack/` to the new prefixes. The old root-level `reports/github/`, `reports/slack/` and `snapshots/` objects can be deleted (`aws s3 rm --recursive s3://<bucket>/<prefix>reports/` and `.../snapshots/`; `prune` works on parameters and does not touch the bucket). An R2 store with a bucket-wide token was not affected. The policy needed no change: the module prefix was already granted, so the function needs the new release.

- **The console's Cloudflare page calls the Cloudflare module, and the issuer's process no longer reads the minter credential refs for it.** The module answers six more methods to the caller class `console` alone: `status` (the whole page: accounts with the id redacted to its last four characters, and per preset its prototype, stored credential and live tokens), `list_presets`, `accounts`, `rotate_preset`, `revoke_token` and `credential` (an on-demand mint for the signed-in person, whom the console vouches for). `rotate_preset` returns the new token's id and expiry only, never a value; the issuer, the controllers and every other class are refused with `forbidden` before a method runs, and `mint` stays the issuer's. With `cloudflare.remote` set the console is given a client that calls the module as `console` (on Lambda the `live-console` alias; on Kubernetes the class of the token's subject), in the same process in which the issuer calls it as `issuer`; without it the console uses the in-process module (`rpc.NewLocal`), with the same answers and the same errors. A refused prototype crosses with its detail, and any other failure reaches the page by kind only. `internal/server` no longer imports the minter. The released envelopes of the six methods are under `internal/modcall/testdata/released/v1.76` and are replayed like those of v1.75.

## v1.75.0-rc.10

### Added

- **The organisation App's name and the link App's name are settings.** `controllers.github.appNames` (`{org: name}`) names the App created for an organisation bound by the `github` table, and the `purpose: link` entry of `apps.github.apps` takes `name`; both are at most 34 characters (GitHub's limit) and are refused over it, and `appNames` for an unbound organisation is refused too. The defaults are unchanged (`<org>-access-roster` and `<owner>-access-roster-link`), so a document that sets neither behaves as before. The manifest the connect flows send carries the configured name, and the console's App rows show an App's recorded slug once it exists (so an App renamed on GitHub's create page reads correctly), and the declared or default name before that. An App already created keeps the name it has.

## v1.75.0-rc.9

### Changed

- **Behaviour change under `groupsScoping: enforce`: a token carries only the claims fragments of the groups it keeps.** The fragments (`claims.<group>`) of every held group were merged into the token before its audience was known, so a token scoped to one client still carried the grants of groups it had dropped from `groups`. `scopeClaims` now rebuilds the fragment claims from the kept groups' fragments alone, with the same merge (lists union, maps recurse), in the ID token, the access token, `/userinfo` and a token exchange. A relying party that read a claim set by a fragment of a group its `requires` and `groups:` override do not keep stops seeing it: add the group's pair to its `requires` or the thing to its `groups:` override before turning `enforce` on, or on upgrade for an estate already on it. `report` and `off` are unchanged. See [0006](docs/decisions/0006-groups-claim-scoped-per-audience.md). Removed again in v1.75.0-rc.12 (see Removed there).
- **The compare-and-swap on login state no longer hashes a value with SHA-1.** `valkey.Revision` is now the SHA-256 of the value, compared in Go against a read of the key, and the swap and delete scripts re-check the exact bytes they were given instead of computing `sha1hex` in Lua. A revision is held only between a read and the write that follows it and is never stored, so what is written to Valkey does not change. A test covers the Gone, Moved and Done outcomes of both operations (`TestSwapAndDropIfCompareTheRevision`).
- **An `invalid_target` redirect at `/authorize` is built from the redirect URI the client registered, not from the request's.** The refusal still redirects only when the request's `redirect_uri` passes the library's own check, and still carries `error`, `error_description` and `state`. The `Location` now takes its scheme, host, path and query from the registered entry; for a loopback address on another port (native clients) only the port comes from the request, and only when it is a number. A `redirect_uri` that matches no registered entry gets the page as before. `TestAnInvalidTargetIsRedirectedOnlyToARegisteredURI` covers the exact, loopback, unregistered and no-client cases.

- **Breaking for callers that relied on the default: the Pulumi library's `LambdaArgs.SigningKeyAlias` has no default.** It defaulted to `alias/sluis-signing`, the name of the deprecated wrapped-signing path. While the library creates the signing key (`Keys` and `WrappedSigning` unset), `NewLambda` now refuses an empty `SigningKeyAlias` with an error that names the field; set it, for example to `alias/sluis-<instance>-sign`, or supply the keys with `Keys`, which is unaffected. `DefaultSigningKeyAlias` is removed. An existing estate that kept the default sets `SigningKeyAlias: "alias/sluis-signing"` to keep its key. The examples in the docs, the chart examples, the schema descriptions and the e2e fixture name purpose-named aliases (`alias/sluis-<instance>-sign`, `-audit-seal`, `-audit-archive`) instead of `alias/sluis-signing`, `alias/audit-seal` and `alias/audit-archive`.

### Added

- **`claim_merge` joins named list claims into one string instead of unioning them.** Groups' fragments that each carry one conjunct of a filter, such as `vm_access.logs_extra_stream_filters`, were unioned into a list, which vmauth turns into repeated query args that VictoriaLogs ANDs, so two grants returned no rows. A policy now declares `claim_merge.<dotted path>` with `join`, optional `prefix` and `suffix`, and `as` (`list`, the default, or `string`); the strings of every merged group are sorted, de-duplicated, joined and wrapped, e.g. `_stream:{A or B}`. The join runs on the groups a token carries, so under `groupsScoping: enforce` it sees only the kept groups, on every token path; with no contributing group the key is absent. Load refuses an empty `join`, an unknown `as`, a malformed path, and a fragment that sets a declared path to anything but a list of strings.
- **Connecting a GitHub organisation from the console works on layout v5.** The App GitHub creates is kept as a catalogue App (its key at `internal/github/apps/<id>/<ref>`) and the organisation's record names it (`app_ref`), the shape `sluis migrate v5` gives an organisation. Before, the create callback failed with "on layout v5 the key is the App's, not <org>'s; name the App in app_ref", so a fresh connect and a reconnect after Disconnect were impossible. The App's id is its GitHub slug (`<org>-access-roster` when the slug cannot be an id); a `controllers.github.appRefs` entry still wins and then nothing is made. The install step records the installation on that App. Disconnect on layout v5 now also deletes the organisation's own App and its key, not an App another organisation or `appRefs` names. Layout v4 and Kubernetes are unchanged. The Apps list no longer shows an App an organisation names as a leftover to disconnect; the organisation's controller row stands for it. A failed callback wrote nothing, so no cleanup is needed.
## v1.75.0-rc.8

### Added

- **The backup and restore functions start from the document the Pulumi library renders: the module builds no trigger adapter, and the document names none that needs a function.** On v1.75.0-rc.6 and rc.7 `NewBackup` rendered the `sluis-backup/v1` document with `preset: aws-serverless` and no `adapters.trigger`, so the preset's `invoke` trigger (the issuer's run-now notification to the controller functions) was planned with no function to invoke, and every invocation, the daily run and the resume ticks, stopped at start with `adapters.trigger: invoke: invoke: no function: set github, slack or both`; `NewRestore` rendered the same document. The backup never notifies a controller. Now the library writes `adapters.trigger: memory` in both documents, and the runtime does not build the plan's trigger for the backup module (`store.Config.NoTrigger`), so a document without it starts too. A test renders both documents through `NewBackup` and `NewRestore` and runs the module's startup over them (`TestTheRenderedBackupAndRestoreDocumentsStartTheModule`, with `TestTheRenderedBackupDocumentStartsTheModule` in `internal/backup/app`). An estate takes this by bumping the library and the release pin together; nothing else changes.

## v1.75.0-rc.7

### Added

- **An operator's command is audited or it refuses: `sluis maintenance on|off`, `sluis migrate v5 copy` and `sluis migrate v5 prune` deliver their audit record synchronously, before the change, and stop when it cannot be delivered.** The record was asynchronous: on 2026-10-11 a freeze ran with the operator's role denied `sqs:SendMessage` on the audit queue, the send failed in the background ("audit record dropped and is not in the trail"), and the freeze went ahead with nothing in the trail; `prune` recorded nothing. Now `roster.maintenance.changed` is a `block` action, kept before the flag is set or lifted (a second, failed-outcome record follows if the change then fails), and a delivery that fails refuses the command, names the queue (or writer) and the principal AWS denied, and changes nothing. A real `prune` records the new `roster.secrets.pruned` before the first delete (`phase` started: the installation, the plan hash, the counts and the names of the parameters to delete, never a value) and again when it ends (`phase` completed, or a failed outcome); a real `copy` that has something to write records the new `roster.migration.copied` the same way (counts, and by name the destination items `--overwrite` replaces). A copy with nothing to write, a `--dry-run` and `status` record nothing. The records go to the audit destination of the `--to` configuration (`maintenance`: `--config`). `--no-audit` is the break-glass: the command goes ahead, prints a warning, and writes the same record to stderr as JSON. The operator's role needs `sqs:SendMessage` on the audit queue: the Pulumi library has `OperatorAuditStatements(queueArn)` for it. The audit catalogue is 1.16.0: `roster.secrets.pruned`, `roster.migration.copied`, and `delivery: block` for `roster.maintenance.changed`.

- **One estate KMS key for every sluis SecureString: the Pulumi library keys the parameters it creates with `Keys.Secrets`, and `sluis secrets rekey` moves the rest.** The runtime already encrypted what it writes (credentials, exports) with the document's `secrets.kmsKeyId`, in both layouts, and `Keys.Secrets` already wrote that key into the document and granted `kms:Encrypt`, `kms:Decrypt` and `kms:GenerateDataKey` through SSM (`kms:ViaService`, and `kms:EncryptionContext:PARAMETER_ARN` under `/sluis/<instance>/*`). The two parameters the library creates (the state secret and the recovery password, in both layouts) were keyed only by `ParameterKeyArn`, so with `Keys.Secrets` they stayed on the AWS-managed `alias/aws/ssm`: they now take the `Keys.Secrets` alias as `KeyId`. Unset, nothing changes. `sluis secrets rekey --config <file> [--dry-run] [--json] [--include-recent] [--no-audit]` re-writes every SecureString below `secrets.root` whose key is not `secrets.kmsKeyId`: it lists with `DescribeParameters`, reads ten at a time with decryption and writes each back with the same name, value, tier and description (`PutParameter`, overwrite, `KeyId`), paced between batches and with a doubling wait when SSM throttles, and prints names, versions and counts, never a value. A write is a new version with the same value; earlier versions keep the key they were written under until SSM drops them (it keeps 100), so a secret that must leave the old key is rotated. A parameter modified within `secrets.grace` is left for a later run (its previous version is a rotated client secret's overlap; `--include-recent` writes it anyway), one that changes under the run is skipped or reported with both versions, and a second run finishes what is left. A real run is audited: `roster.secrets.rekeyed` is delivered before the first write and the run refuses, writing nothing, if it cannot be; `--no-audit` is the break-glass (a warning, and the record on stderr as JSON). The Pulumi library has `RekeyOperatorStatements(region, account, instance, keyArn)` for the operator's role. The audit catalogue is 1.17.0: `roster.secrets.rekeyed`.

## v1.75.0-rc.6

### Added

- **The module image job builds the console bundle first.** `hack/module-images.sh` ran `ko build` on `./cmd/sluis` without `frontend/dist`, which the binary embeds and goreleaser's `before` hook builds, so v1.75.0-rc.6's `module-images` job failed with `frontend/embed.go: pattern all:dist: no matching files found` and pushed nothing. The script now runs `just console` when `frontend/dist` is empty, in `publish` and in `check`.

- **The per-module container images are built by `hack/module-images.sh` (ko), and `just release-lint` pushes them to a throwaway registry and asserts the names.** v1.75.0-rc.5 published none of `ghcr.io/truvity/sluis/sluis-issuer`, `sluis-cloudflare` and `sluis-backup`: goreleaser's ko pipe replaces the `repositories` of every entry with `$KO_DOCKER_REPO` whenever that is set (the shared release workflow always sets it), so the three entries, all built from `./cmd/sluis`, pushed to `ghcr.io/truvity/sluis` and the last one won, the tag and `latest` included; `attest-oci` then found no `sluis-*` package to sign. They are now a `module-images` job of the release workflow, one `ko build --bare` each with its own repository and its module pinned (`hack/ko-modules/.ko.yaml`), from the `sluis-*` lines of `hack/release-images.txt`, so a pushed image is a signed image. The check fails on a missing tag, on a repository other than the listed ones, and on two modules with one digest. The images no longer carry the `org.opencontainers.image.*` labels goreleaser set; GHCR links each package to this repository by the push from this workflow.

- **`sluis migrate v5 prune` deletes the layout v4 parameters a migration has carried.** `copy` never deletes from the source, so after the 7 days hundreds of v4 parameters (`internal/credentials/*`, `internal/cloudflare*`, `internal/blobs/*`, `external/*`) were left that `Compat.DropV4` does not remove. `prune --from <v4> --to <v5>` first runs the comparison of `verify` and refuses unless every source item with a v5 address is `same`: one `new`, `different`, `refused` or `missing` item and nothing is deleted. It then deletes only the parameters whose v5 copy was found equal, and keeps and lists the rest: the ones the migration does not carry on purpose (`internal/config/valkey/password`); an organisation's credential goes once the App that holds its key on v5 is found equal by hash, and is kept as unverified until then, the 2 the Pulumi library owns, names that are also v5 names when both sides share a root, and any it did not verify. `--dry-run` prints both lists and a plan hash; a real run needs `--confirm-plan <hash>` of that dry run, so a changed installation needs a new one. Parameters go ten to a request (`DeleteParameters`, through a new optional `state.BatchDeleter` that the SSM store implements), half a second apart, with a doubling wait while SSM throttles; each batch is an audit line on stderr with names and counts, never a value. The records of the legacy table are not deleted: the table retires as a whole, and the report counts them. `--json` prints the report.

- **`Compat.RetireLegacyTable` in the Pulumi library retires the legacy DynamoDB table after the v4 parameters are gone.** It needs `Layout: "v5"` and `Compat.DropV4` (the function refuses it otherwise, and `NewStates` refuses it without `DropV4`), and the same `Compat` goes on `StatesArgs`. With `Legacy` still set, that apply exports the legacy table to a private, encrypted bucket the library creates, which expires the export after 30 days (`pre-v5-retire-<table>-<date>/`, stack output `legacyTableBackupArn`, `States.LegacyBackupArn`), and only then turns off the table's deletion protection and unprotects it in the state, so `pulumi state unprotect` is not needed. The migration role loses its read of the legacy table. The apply after, `Legacy` is left out of `StatesArgs` and the table is deleted: the engine cannot unprotect and delete one resource in one update, so it is two applies. The provider has no on-demand DynamoDB backup resource, so the backup is a table export from point-in-time recovery, complete before the table is touched, and refused with a message naming point-in-time recovery while the live table has it off (the library declares it on, so an earlier apply has set it); `aws dynamodb import-table` restores it into a new table.

## v1.75.0-rc.5

### Changed

- **A process on layout v5 reads the blob credential from the blob owner's address, `internal/google/<name>`, whichever module it runs.** `ports.blob.s3.credentialsRef` was refused unless it was in the process's own module, so the issuer (the oidc module, which also hosts the hub and the console) stopped at start with `internal/google/blobs-r2 is the google module's, and this process runs the oidc module`, while the library and `sluis migrate v5` required that very address: an estate with its blobs on an S3-compatible store (R2) could not run on layout v5. The blob port is shared (the directory snapshots, the controllers' reports, the backup), so its credential has the one home the blob prefix has, the google module's, and the runtime now reads that address from any module's process. A credential in another module's prefix is still refused, and the role of each function still names that one parameter and no other. Nothing moves: an estate that ran `sluis migrate v5` has the credential at `internal/google/blobs-<name>` already and needs no new copy, and the library's `V5CredentialsRef` and `sluis migrate v5`'s mapping are unchanged. A test renders the library's v5 document for an estate with external blobs and runs the runtime's start checks over it.

### Added

- **The release publishes a container image per module: `ghcr.io/truvity/sluis/sluis-issuer`, `sluis-cloudflare` and `sluis-backup`, and the chart can run them with `image.perModule: true`.** Each is the `sluis` binary built with its module name pinned (`-X .../internal/version.Module=sluis-module=<module>`), multi-arch (amd64, arm64) on the same base image as `sluis`, and refuses another module's commands. They are in `hack/release-images.txt`, so the release workflow's `attest-oci` signs them and attaches provenance and an SBOM by digest, `hack/release-verify.sh` checks them, and `internal/releasecheck` holds the set to the Lambda zips. With `image.perModule: true` the issuer Deployment runs `sluis-issuer` and the backup CronJobs and the restore Job run `sluis-backup`, at the same tag; the default stays the one `sluis` image and every existing render is unchanged. The Cloudflare image has no chart object yet.
- **A migration freeze that does not take the issuer offline: `sluis maintenance on|off|status --config <file>`.** `on` sets the maintenance flag (state `migration`) in every table of the installation (the one table on layout v4, each module's on v5) and returns when every replica has seen it. The issuer then answers every write of state with `503` and `Retry-After: 30` (sign-in, codes, device codes, revocation, sign-out, client secrets, the console's changes, the controllers' ticks), and keeps answering discovery, the key set, userinfo, introspection, the grants listing, the console's reads, and `POST /oauth/token` for a token exchange and a refresh. Those two write nothing: a refresh returns the refresh token it was given instead of rotating it, and neither records the access token it mints, so `sluisctl token`, `aws` and `kube-token`, the Pulumi program and the AWS provider keep signing in during the freeze, and the `{"kind":"check"}` event keeps answering; no reserved concurrency is changed. A restore's flag (`restoring`) still refuses every request that writes, the token endpoint included. `off` lifts the flag; one a restore holds needs `--force`. `sluisctl` reports a `5xx` on a refresh as the issuer being unreachable instead of "not signed in", and keeps the session. `sluis migrate v5 copy` accepts a frozen source as the proof of a stopped writer (waiting until every replica has seen the flag), warns when only `--i-have-stopped-writers` vouches for it, never copies the flag (the destination starts out of maintenance), and refuses a destination that holds one. The Pulumi library has `MaintenanceOperatorStatements`: get, put and delete on the `maintenance` partition of the tables and the table key through DynamoDB, for the operator's role; the function roles keep `SluisMaintenanceDeny`. The audit catalogue is 1.15.0: `roster.maintenance.changed`. See the [v1.75 upgrade](docs/guides/sluis/upgrade/v1.75.md).

## v1.75.0-rc.4

### Changed

- **`sluis serve` is a deprecated alias of `sluis issuer`.** It runs the same module and says in the log that the command is `sluis issuer`; it goes in the next release. `sluis console` (a "not yet split" stub) is removed: the console is part of the issuer's process.
- **Breaking: the single Lambda zip `sluis-lambda_<version>_linux_arm64.zip` is no longer published, and the Pulumi library's default artifacts are the per-module zips.** `LambdaArgs` (the issuer function) defaults to `sluis-issuer_<version>_linux_arm64.zip`, and `NewBackup` and `NewRestore` to `sluis-backup_<version>_linux_arm64.zip`; a Cloudflare module function needs `sluis-cloudflare_<version>_linux_arm64.zip` named in `Package`. A library at version X expects release X's per-module zips, so an estate moves the library version and the release pin together, and re-pins `PackageSHA256` for each zip. An explicit `Package` is still taken as it is, and the library still accepts the `sluis-lambda_` name of releases before 1.75. `cmd/sluis-lambda` is removed.

### Added

- **The release publishes one Lambda zip per module: `sluis-issuer_<version>_linux_arm64.zip`, `sluis-cloudflare_<version>_linux_arm64.zip` and `sluis-backup_<version>_linux_arm64.zip`.** Each holds `bootstrap` alone, built with its module name pinned (`-ldflags -X .../internal/version.Module=sluis-module=<module>`), so a zip refuses to start as another module or on another module's document. The backup zip is also the restore function (`backup.role: restore`). Every zip is in `checksums.txt`, has an SBOM and a provenance attestation like the other assets. `hack/check-zips.sh` holds the set to `hack/release-zips.txt` (present once, `bootstrap` alone, pinned, checksummed); the release workflow runs it before it signs anything, and `hack/release-verify.sh` runs it on a downloaded release. The providers get a zip each from v1.76, one per release; until then they run in `sluis-issuer`. `just lambda-size` builds every zip's binary against the size budget. The Pulumi library accepts the per-module zip names as `Package`.
- **`sluis-issuer`, `sluis-cloudflare` and `sluis-backup`: one Lambda entry point per module.** `cmd/sluis-issuer` is the issuer, the signer and the console in one process (the signer is `internal/signer`, in that process; no signer binary exists or will be built), `cmd/sluis-cloudflare` is the Cloudflare module's function and `cmd/sluis-backup` is the backup module's, which is also the restore function with `backup.role: restore`. Each main calls `lambdaapp.StartModule(<module>)`, which refuses a document that is another module's and a build whose `internal/version.Module` (set with `-ldflags -X` to `sluis-module=<module>`) names another module. Each function's code is its own package (`internal/lambdaapp/issuerfn`, `backupfn`, `cloudflarefn`) registered with `internal/lambdaapp`, so a binary holds the modules it imports and no others; `internal/boundaries` holds each closure to that and refuses a `cmd/sluis-signer`.
- **The chart renders a layout v5 installation and the backup module.** `config.secrets.layout: v5` with `config.ports.dynamodb.tables` renders as it is written (the chart refuses one without the other, and refuses `secrets` beside v5, whose secrets are in SSM; with `secrets.source: ssm` it projects no Secret even for confidential clients). `backup.enabled` renders a CronJob for `sluis backup run` and one for `sluis backup prune` (`backup.prune`), with `backup.config` as the `sluis-backup/v1` document in the ConfigMap `<release>-backup-config`; the pods are labelled `<name>-backup`, so the service's Service and NetworkPolicy never select them, and they run as `<release>-backup` (`backup.serviceAccount`, IRSA or Pod Identity). The chart refuses a document without `backup.target`, a key, layout v5 or tables, and one with `backup.role: restore`. `restore.enabled` renders one Job, never a CronJob, as `<release>-restore`: `sluis restore start <backupId> --confirm <confirm>`, with `overwrite`, `by` and `note`, or `resume`; it is refused unless `confirm` is `backup.config.instance`. `telemetry.legacyMetrics`, `config.console.backup` and the maintenance flag need no chart value. `charts/sluis/examples/backup-v5.yaml` is a whole installation. Per-module Deployments stay out until the processes are split; the v4 layout renders as before.

## v1.75.0-rc.3

### Fixed

- **`POST /token` answers an unknown `client_id` with 400 `invalid_client`, or 401 when the client authenticated with HTTP Basic, instead of 500 `server_error`.** This holds for the `refresh_token`, `authorization_code` and token-exchange grants, as RFC 6749 §5.2 asks. An unknown audience in a token exchange stays `invalid_target`.

### Changed

- **The Pulumi library writes the v5 state secret and recovery password as the secret store's document.** On layout `v5` and `v4+v5`, `internal/oidc/state-secret` and `internal/oidc/recovery-password` hold `{"value":"<base64>"}`, the form the issuer and the hub read there (`StoresV5`), with the same text as the v4 parameters inside. They were plain values until now, which the issuer could not read on v5 and which `sluis migrate v5 plan` refused as unreadable. A stack that already wrote the plain value is rewritten on the next apply; the plan says so when it meets one. The v4 parameters are unchanged.
- **`ExternalBlobs.CredentialsRef` on `Layout: "v5"` must be a v5 address.** A layout v4 ref such as `internal/blobs/r2` is refused with the address to use, `internal/google/blobs-r2`, where `sluis migrate v5` copies the secret; `V5CredentialsRef` returns it. `v4` and `v4+v5` keep the v4 ref in the document. The [upgrade guide](docs/guides/sluis/upgrade/v1.75.md) has the step.
- **`sluis migrate v5 plan|copy|verify` print the JSON report on stdout and the summary on stderr.** The report went to stderr with the summary, as everything of the command's own writer does, so `> report.json` was empty.

### Added

- **The Pulumi library deploys the restore function: `NewRestore`.** A second function from the same release zip, with a document of `backup.role: restore`, the aliases `live-admin` and `live-breakglass` and a 900 second timeout (at least twice the 90 second `RestoreMargin`). Its role writes every module's table, including the `maintenance` flag that no other role may write, every module's parameters and blob prefixes, reads the archive and its key without writing either, and invokes its own aliases so a paused restore continues. The resource policy allows `RestoreInvokers` only: administrator roles on `live-admin`, break-glass roles on `live-breakglass`, no unqualified invoke. There is no reserved concurrency (the restore lease allows one at a time), no schedule, and an alarm on any invocation. `RestoreRoleStatements` renders the role for an estate that builds its own.
- **Layout v5 names the issuer's per-identity single sign-in set.** The Index set `issuer:sso-of:<identity>` is `oidc/sso-of/<identity>` on layout v5, as the other session sets are, so `sluis migrate v5 plan` no longer refuses it on an installation with sign-ins, and the backup export and the restore engine include it. Layout v4's own addresses are unchanged. A test holds every Index set the issuer writes to an address on layout v5.
- **The Pulumi library deploys the backup function: `NewBackup`.** The release zip becomes the backup function with a `sluis-backup/v1` document in its configuration layer (`secrets.layout: v5`, `ports.dynamodb.tables` for the six modules, `ports.blob`, `backup.target`, `backup.key`, `backup.retention`), a 900 second timeout and the aliases `live`, `live-console`, `live-admin` and `live-breakglass`, so a module call carries its caller class. Its role is `ModuleRoleStatements` for the `backup` role (read of every module, write of the backup table, the maintenance flag read and never written) plus the archive: put, list, get and delete under `<prefix>backup/<instance>/`, and `kms:Decrypt` and `kms:GenerateDataKey` on the archive key under the context `{instance, purpose=archive}`. `Archive.Create` makes the bucket (versioned, Object Lock with a default retention that may not exceed `retention.maxAge`, 720h by default); a bucket in another account gets the `ArchiveBucketPolicy` output for its owner. EventBridge Scheduler sends `{"kind":"backup"}` daily and `{"kind":"backup","resume":true}` every five minutes, with a dead-letter queue, and three alarms watch for no completed backup in 36 hours, a failed run and an undelivered event. `BackupRoleStatements` and `ArchiveBucketPolicyStatements` render the policies for an estate that builds its own.

## v1.75.0-rc.2

### Changed

- **`sluis migrate v5 copy --skip issuer` runs while the source is live and needs no `--i-have-stopped-writers`.** That is the first of the two passes: the issuer's sessions, tokens and key ring are the fast-changing data, and the final `copy --overwrite --i-have-stopped-writers` catches up the provider records this pass copies. A copy that includes the issuer still needs the flag and is refused without it. The live pass's report carries `"live": true` and a note, repeated on stderr, that a final pass is required. Its closing verify does not fail the copy: what changed on the live source meanwhile is reported in the `verify` section and in a note, and the exit status is 0.

### Added

- **`sluisctl backup run|status|list` and `sluisctl restore preview|start|resume|status`.** They invoke the backup and restore functions with the caller's own AWS credentials (the SDK's default chain, so a profile written by `sluisctl aws-config` works), not through the issuer or the console. The function is `--function`, else `$SLUISCTL_BACKUP_FUNCTION` or `$SLUISCTL_RESTORE_FUNCTION`, else `backup.function` or `backup.restoreFunction` in `config.yaml` (`backup.region` and `backup.instance` too); `--as admin|breakglass` (default admin) picks the `live-<class>` alias for every call. `backup` calls the module methods `backup.run`, `backup.status` and `backup.list`; `restore status` calls `restore.status`. `restore preview` is a synchronous restore event and prints counts, never values. `restore start <id>` refuses unless `--confirm` equals the installation's name, sends the event asynchronously with `by` set to the caller's `sts:GetCallerIdentity` ARN, finds the run it made and prints its id; `--wait` polls `restore.status` until the run completed (exit 0) or failed (exit 1). `restore resume` does nothing when no restore is unfinished. `--json` prints the answer; a refusal by AWS or the function exits 4.
- **The console's Backups page: the latest run, the archive, retention, an unfinished run's progress, the latest restore and the modules under maintenance.** It sits under Admin beside Audit and Settings, is read-only, and says that a restore is started with `sluisctl` by an administrator or the break-glass role. `sluis.v1.BackupService` (and `directoryroster.v1.BackupService`) adds `GetBackupStatus`, `ListBackups` and `GetRestoreStatus`, which call `backup.status`, `backup.list` and `restore.status` as the caller class `console` (`internal/backup/rpc.Client`); there is no RPC that starts a backup or a restore. The page is off until the service document sets `console.backup` (`function` or `url` for the backup module, `restoreFunction` or `restoreURL` for the restore function, `audience`, `tokenFile`); then `whoami` carries `backup`. The change is additive (`buf breaking` is clean).
- **`sluis migrate v5` carries an organisation connected with its own App, and `appRefs` is optional.** On layout v4 an organisation's credential is its App's key. The plan, copy and verify now name the App an organisation uses on layout v5 in this order: the `controllers.github.appRefs` entry (an override; one that names an App with another GitHub App id than the installing one is still refused), then the source's catalogue or runner App that has the App id the organisation is installed by, then a new catalogue App made of the organisation's own: its id is the App's slug (held to the catalogue id rules; a slug that cannot be one is refused and `appRefs` names the way out), its record and key are the organisation's, and organisations installed by one App share it. The made App is a new item in the plan, is written before the organisations, and `verify` compares its key like any other. The key is kept once, at `internal/github/apps/<id>/<ref>`, and the organisation's record names it (`app_ref`). On layout v5 an organisation whose stored record names an App is written again without an `appRefs` entry (an entry still overrides). `config.Installation.Controllers.GitHub.AppRefs` renders `controllers.github.appRefs` into the policy document.
- **The Sessions page names clients and resources, and groups identical sessions.** The console lists a heading per person, then one row per client and resource with a count, opening to the individual sessions with their scopes and their own revoke. A client shows its display name (the policy's, or a URL client's `client_name` as the issuer already resolves it) with the id on hover; a resource shows the policy's name for it or its host. A session older than five minutes that was never refreshed is marked *never used*, and *Client contains* also matches the name and the resource. `sluis.v1.Session` gains `client_name`, `resource`, `resource_name` and `scopes` (additive; the issuer already stored `resource` and `scopes`, so older sessions show them too, or "unknown" where none was recorded).
- **The backup module: `sluis backup run|list|status|prune` and a scheduled Lambda function.** `internal/module/backup` replaces the "not yet split" stub. A run takes `lease.backup:run` in the backup module's table, creates the writer with the `archive` key (`backup.key`, the short way to set `keys.archive`; kms), exports the installation (`internal/backup/export`) and writes `rec.backup.run.<id>` before it starts and after every unit, with the export's checkpoint, so a run stopped by the function's time limit pauses (under three minutes left) or is cut off and the next run continues it for up to 24 hours instead of starting over. The id is the UTC start time and a random suffix, path-safe and sortable; the creator is `sluis-backup <version>`. A completed run is pruned by retention (`backup.retention`: the 7 newest always, others when older than 30 days), manifest first, and the chunks of a run that never wrote a manifest go after 7 days; the last pass is `rec.backup.retention`. The module has its own document, `apiVersion: sluis.truvity.github.io/sluis-backup/v1` (`schemas/config/sluis-backup.schema.json`), with `backup.target` (the S3 bucket; an Object Lock bucket is the intended one), `backup.key`, `backup.retention` and the `ports`, `secrets` and `audit` it reads the installation through. The Lambda function takes `{"kind":"backup"}` and `{"kind":"backup","resume":true}` and the methods `backup.status`, `backup.list` (console, admin, breakglass) and `backup.run` (admin, breakglass). The audit catalogue is 1.14.0: `roster.backup.completed`, `.failed`, `.pruned` and `roster.restore.started`, `.completed`, `.failed` (the restore ones are emitted by the restore function). A backup does not carry the module's own run records. See [backup](docs/reference/sluis/backup.md).
- **The restore engine and its preview (`internal/backup/restore`).** `restore.Preview` verifies an archive and reports, per module and section, how many records would be created, overwritten, left as they are, skipped because they have expired, or skipped because a module regenerates them (leases, notifications, gates, caches, dedupe records and the maintenance record), with the names of the records that change and, for an overwrite, the version the destination holds; it never carries a value and writes nothing. `restore.Apply` verifies the whole archive before the first write, refuses a destination that holds a different value unless `Overwrite` is set, then writes State with `Put` (the remaining lifetime is the archive's expiry less the clock now; an expired record is skipped), Index sets with `Add`, secrets as documents and blobs reassembled from their parts, and reads everything back. Modules are written with `oidc` last, and inside it the signing key ring last of all. A record that does not belong to its module is refused. A run that stopped is continued by calling `Apply` again: what is already equal is not written.
- **The restore function: `backup.role: restore`, `sluis restore preview|start|status` and the `{"kind":"restore"}` event.** The backup zip is also the restore function (ADR 0072, point 10); `backup.role` (`backup` by default) picks which, and `sluis restore` is the restore role on the command line. A restore takes `lease.restore:run` in the backup module's table, so a second start is refused while one runs, writes `rec.backup.restore.<id>`, sets the maintenance flag in every module's own table, waits 15 seconds for the modules' cached view of it, and calls `restore.Apply`. Maintenance is lifted only when Apply returned and its read-back matches; a verify that differs, a destination that holds different data without `overwrite`, an archive that does not belong, a key or a store error leave every module closed and the record says why. The event `{"kind":"restore","backup":"<id>"}` (invoked asynchronously) does the work in its own invocation, pauses 90 seconds before the deadline and starts the next invocation itself (`{"kind":"restore","resume":true}`, through the same alias); `overwrite` is passed only when the administrator asked, `preview` answers what a restore would do and writes nothing. `restore.status` (console, admin and break-glass) reads the latest restores and the modules still under maintenance; nothing else of the restore is a module call. A restore is audited as `roster.restore.started`, `.completed` and `.failed`. `sluis restore start` needs `--confirm <instance>`. The restore role needs `lambda:InvokeFunction` on its own alias.

## v1.75.0-rc.1

### Changed

- **`sluis migrate v5 copy --overwrite` makes the destination's state secret fingerprint match the source's, absence included.** When the source's issuer never signed anyone in it has no `issuer:kms:state-secret-fingerprint` record, while a destination issuer that started before the copy and signed somebody in holds one for its own state secret; the copy used to leave it, and the destination's first sign-in failed with a fingerprint mismatch. That record is now a different item (`guard`) in the plan and in `verify`, so a copy without `--overwrite` stops with the conflict, and with `--overwrite` it deletes the destination's record.
- **The Pulumi library switches layouts with `LambdaArgs.Layout`.** `v4` (the default) keeps the role and the document as they were, except that the module tables created beside the legacy table are no longer granted on it. `v5` gives the function's role only the v5 grants for the modules it hosts (the tables, `internal/<module>` and `external/<module>` parameters and blob prefixes of `oidc`, `github`, `slack`, `google`, and `cloudflare` with presets, and the maintenance deny on their tables) and writes `secrets.layout: v5` and `ports.dynamodb.tables` into the service document; `v4+v5` gives both sets for the migration window and keeps the v4 document. `v4+v5` and `v5` also write the state secret and the recovery password at `internal/oidc/state-secret` and `internal/oidc/recovery-password` with the value of the v4 parameters, from the same generators, so a first apply creates two parameters and deletes or replaces none. The v4 parameters stay until `Compat.DropV4` (with `Layout: v5`). A role that mints blob credentials from a Cloudflare preset without hosting the module reads the minter parameter on v5. `MigrationRoleArn` attaches a read-only grant on the legacy table to the role that runs `sluis migrate v5`. `StateSecretParameterNameV5`, `RecoveryPasswordParameterNameV5` and `ConfigParameterPrefixV5` name the v5 addresses.
- **The Pulumi library creates a table per module and keeps the legacy table.** `NewStates` creates `sluis-<instance>-<module>` (or the names in `ModuleSet.Tables`) for the six modules: on-demand, point-in-time recovery, TTL on `expires`, deletion protection, protected. `StatesArgs.Legacy` declares the single table exactly as `NewState` did, at the same URN, so an existing stack previews only the new tables as creates; the legacy table is protected and dropping the argument is refused by the engine until `pulumi state unprotect`. `StateGrant` gains `Tables`, `LambdaArgs.State` and `KubernetesIdentityArgs.State` take it, and, with `LambdaArgs.Layout` `v5` or `v4+v5`, the role is granted the module tables. `PortsArgs.Tables` renders `ports.dynamodb.tables` for layout v5; the document stays on `table` until the layout is switched.
- **The audit Pulumi library sets the telemetry layer's settings under `SLUIS_*`.** The functions get `SLUIS_ISSUER`, `SLUIS_AUDIENCE`, `SLUIS_OTLP_ENDPOINT` and `SLUIS_OTLP_AUDIENCE`, which the `otlp-lambda` layer reads first, and still get the four `ACCESS_ROSTER_*` names with the same values for a function that runs a layer older than the one that reads `SLUIS_*`; they are removed in v1.76, and `Telemetry.OmitLegacyEnv` drops them earlier. The `AUDIT_OTLP_*` names the library set until now are gone: no layer ever read them. Functions are updated in place on the next apply.
- **`Telemetry.Env` accepts the layer's `SLUIS_*` settings.** The `otlp-lambda` layer reads `SLUIS_ISSUER`, `SLUIS_AUDIENCE`, `SLUIS_OTLP_ENDPOINT`, `SLUIS_OTLP_AUDIENCE` and its other settings first and the `ACCESS_ROSTER_*` spelling as a fallback, and the Pulumi library lets a deployment set either; only the layer's own names pass, so `SLUIS_CONFIG` and the other `SLUIS_*` variables of sluis are still refused. Set the `SLUIS_*` names in new deployments. The `ACCESS_ROSTER_*` spelling is accepted until v1.76; a layer from before the one that reads `SLUIS_*` reads only the old names, so set both while one may still run. Neither the chart nor the library sets any of these itself.
- **Cookies are named `sluis_*`; the old names are still read.** The console session, the flow cookies and the issuer's browser session are written as `sluis_session`, `sluis_connect`, `sluis_login`, `sluis_link`, `sluis_recovery`, `sluis_agent_consent` and `sluis_sso` (with `__Host-` in front when cookies are Secure, as before). A request carrying only the old name (`access_roster_session`, `access_roster_connect`, `access_roster_login`, `access_roster_link`, `access_roster_recovery`, `access_roster_agent_consent`, `access_issuer_sso`) is read as before, so nobody is signed out by the upgrade; the new name wins when both arrive. Setting or clearing a cookie also clears the old name. The old names are read for one release.
- **Meter instrumentation scopes and the tracer are named `github.com/truvity/sluis/...`.** The remaining scopes (`githubapp`, `rails`, `http`, `issuer`, `slackroster`, `githubroster`, `port`) and the tracer name followed the others.
- **The docs check refuses every old product name outside history.** `hack/check-docs-hygiene.py` now bans `access-roster`, `access-issuer`, `github-roster`, `slack-roster`, `githubroster`, `slackroster`, `directoryroster`, `accessctl` and `access-proxy` (in any case, with `-` or `_`) in every Markdown page and `Chart.yaml`, audit's included, except in the CHANGELOG, the ADRs and `testdata/released/` fixtures. `hack/docs-hygiene-allow.tsv` keeps only wire values that still exist in v1.75, each with its reason. The pages that used the old names say `sluis`: the group names in the examples are `all:sluis:operator` and `all:sluis:viewer`, and the metrics are `sluis.*`.
- **The issuer and console read their secrets from the `oidc` module on layout v5.** With `secrets.layout: v5` the sign-in state secret, the recovery password, the Google sign-in client, the console session key and the delivered client secrets are `internal/oidc/state-secret`, `recovery-password`, `signin/<provider>/client-id` and `client-secret`, `console-session-key` and `clients/<id>`, whatever names the document gives the first two; the generated clients' records stay `external/oidc/<id>`. The console no longer asks for a Secrets port on v5, which is unset there, and the state secret's fingerprint is kept in the `oidc` table. Layout v4 reads and writes the paths it always did.
- **The provider modules keep their credentials at the layout v5 addresses (ADR 0072).** With `secrets.layout: v5` a Google Workspace's key is `internal/google/workspaces/<id>/key`, a person's GitHub link tokens `internal/github/links/<id>/<ref>`, a Slack workspace's credential `internal/slack/workspaces/<team>/<ref>` and a catalogue Slack App's `internal/slack/apps/<id>/<ref>`; an organisation has no key of its own (it names an App). The Cloudflare minter, its record of minted tokens (`internal/cloudflare/minted/<preset>`) and the stored credentials run on v5 too, so `cloudflare` no longer needs the layout-v4 stores. `ports.blob.s3.credentialsRef` and `credentials.preset`, which a layout v5 installation refused, now work: the static document is `internal/<module>/<name>` and a process reads its own module's. Layout v4 is unchanged.
- **The GitHub console and its controllers handle GitHub Apps as one kind.** `internal/server` serves the link, controller, runner and catalogue Apps from one handler, and the per-kind calls (`BeginGitHubCatalogueAppConnect`, `BeginGitHubRunnerAppConnect`, the matching Disconnect and Check calls, and the sections of `GetGitHubStatus`) are answered by the same code. The `.proto` is unchanged: every RPC keeps its name and `GitHubApp` already carries `purpose`, so a client written for the earlier calls reads what it read. The console shows one Apps list with a Purpose column; `/github/runners` opens it. An App created from the console is written through the one store with the labels `apps.github.apps` declares.
- **GitHub Apps are one declared list: `apps.github.apps`.** The policy document declares every GitHub App in one list of `{id, purpose, labels, export, org, tier}` entries, where `purpose` is `link` (the id `link`), `catalogue` (the catalogue App's own fields: `permissions`, `events`, `webhook`, `grants` and the rest) or `runner` (a `tier`, and an `org` for one organisation; the id is `runner-<tier>` or `runner-<tier>-<org>`). It replaces `apps.github.runnerTiers` and `apps.github.catalogue`, which are still read for this release: each is turned into an entry of the list with a deprecation warning (`sluisctl policy render` writes the list only), and both are removed in v1.77. `labels` (at most 16 short lower-case names) are written to the App's record, replacing the record's own when the list declares any; `export` decides whether a link or catalogue App is exported (the `ExportGitHubApps` callback now reads the list). `controllers.github.appRefs` (`{org: App id}`) names the catalogue App an organisation uses, and on storage layout v5 `portstore` fills `app_ref` of an organisation's record from it. The list is held to its rules at load: a `purpose`, one link App, a runner entry with a valid `tier`, no entry repeated, and an `appRefs` entry for an organisation the policy binds and an App declared for it. The chart renders `githubApps.catalogue` as `purpose: catalogue` entries of the list, so its policy checksum changes and the pods roll once on upgrade. The console, the controllers and the API still read the catalogue and the tiers through the same accessors and are unchanged.
- **modcall: the call carries the caller's trace and deadline, is bounded in size, and a callee answers the previous version.** The envelope gains `traceparent`, `tracestate` and `deadline` (Unix milliseconds) beside `v`; the caller starts a client span and the callee a server span that continues the trace, on Local, HTTP and Lambda alike. The callee bounds the method's context by the deadline, refuses a call that arrives after it with the new code `deadline_exceeded`, and the caller does not send one whose context is already done. A request or a result is bounded to 256 KiB per method (`modcall.DefaultMaxBytes`); a method raises its own with `modcall.MaxBytes`, up to 5 MiB, under Lambda's 6 MB limit, and the transport callers (`HTTPCaller.MaxBytes`, `lambdacall.Caller.MaxBytes`) are set to match. An oversize request is `bad_request`, an oversize result `internal`, and neither echoes the payload; the HTTP listener reads at most 5 MiB plus the envelope in place of 1 MiB. A callee accepts version 1 and 2 and answers in the request's own version (`Response.V`, absent for 1; the version 2 fields on a version 1 request are ignored); fields it does not know are tolerated. The released envelopes of the Cloudflare module's `mint` and `granted` are committed under `internal/modcall/testdata/released/v1.75/` and replayed by every later release.
- **The issuer asks for GitHub installation tokens through a module port.** Once the issuer has decided the grant, the token is minted by a `githubtokens.Minter` (`internal/githubapp/githubtokens`): `InProcess`, today's code (read the App's record and key, sign its JWT, call GitHub), and a `modcall` pair for the `github` module's `mint_installation` method, answered only to the `issuer` caller class. The issuer uses the in-process minter unless `issuer.GitHubApps.Minter` is set, so nothing changes in a deployment and no function, alias or IAM statement is added; the pair is the seam the GitHub split will use, and is exercised over `modcall.Local`. `unavailable`, `scope` and `upstream` refusals cross the boundary as codes and come back as the issuer's `ErrGitHubAppUnavailable`, `ErrGitHubScope` and `ErrGitHubUpstream`, which are now the same values as the port's; what GitHub or the key said never crosses. The released envelope is committed as `internal/modcall/testdata/released/v1.75/github.mint_installation.json`.
- **The SSM secrets source reads one parameter per name, when it is first used.** It made one recursive `GetParametersByPath` of `internal/config/` when the process first needed a secret and again every five minutes, so a start paid for every parameter under the prefix whether it used them or not. Now `NewSSM` makes no call, a name is read with a single decrypted `GetParameter` on first use (callers that arrive together make one read), and its copy is read again once it is older than `secrets.refresh`, whose default is now `1m` (it was `5m`). An absent name is remembered for 30 seconds, a failed read keeps the copy until the existing 24-hour limit, and the source still fails closed after it. A cold start of the Lambda function made two `GetParameter` calls here (the console's session key and the recovery password) where it made three calls, two of them page reads; the entry on lazy secrets below takes those two away. The roles already hold `ssm:GetParameter` on `internal/config/*`, so no policy changes. An installation that set `secrets.refresh` keeps its value.
- **No module reads a secret as it starts: each is read by the request that needs it, and read again after 30 seconds.** A cold start of the Lambda function makes no SSM call at all, on layout v4 or v5, and answers its first request (discovery) without one; this is a test (`internal/lambdaapp/coldstart_test.go`) that counts the calls of a recording SSM. The reads moved to first use:
  - the console's session key (created if absent) when a session or a sign-in state is first signed or checked;
  - the recovery password when the first recovery proof arrives; a password that cannot be read, or is empty, refuses every proof until it can;
  - the Google sign-in client when `/authorize` first sends a browser to Google, and again when it comes back;
  - the declared OAuth client of the console when a request first asks for it (the settings page, a connect flow);
  - a client's delivered secret when the client first authenticates;
  - a declared workspace's key when the workspace is first used. A workspace the store already holds exactly as declared is attached without a read; one that is new or declared differently is adopted at start as before, which reads its key once;
  - the state secret's fingerprint check at the first sign-in, under the `state-secret-check` lease, and again after 5 minutes. Where `signingKey.kms` or `signingKey.kmsWrapped` is set, the secret's value is read with the signing keys, on first use (see the entry below);
  - the GitHub and Slack controllers no longer read the session key when they open (they check only that a Secrets adapter is configured).

  A typo in a secret now fails the request that needs it, not the start, and a missing recovery password no longer stops the console. Check the declared names at deploy time (`sluis check`, which follows in this release). `issuerapp.Deps.SkipStartSecretsPass` and `rosterapp.Config.SkipStartSecretsPass` are removed: the generated clients' secrets are settled by `App.Run` before it serves and by the schedule's refresh, and assembling the issuer settles none, so a function sets nothing. A named client secret is cached for 30 seconds by the resolver, so a source that does not cache (layout v5's) is no longer read on every token request.
- **The KMS signing modes open their keys on first use in the Lambda function: a cold start reads no state secret and calls no KMS.** With `signingKey.kms` or `signingKey.kmsWrapped` the signing keys are built over the state secret (their seed) and opening them calls KMS (`kms:GetPublicKey`, or the unwrapping of the recorded keys), so the zero-call cold start of the entry above did not hold for either. The function now answers its first requests without them: the discovery document lists the configured algorithms (until the keys are open, then the published ones) and costs nothing. The keys are opened by the first of these, which reads the state secret once and calls KMS: a token signed, a request for the key set (`/keys`, which lists the open rings' public keys, so that request pays), a sign-in state signed or checked, or the state secret's fingerprint check. The open is single-flight (requests that arrive together share one read and one set of KMS calls) and a failed open is not remembered, so the next request tries again. `internal/lambdaapp/coldstart_test.go` counts SSM and KMS calls of a KMS-wrapped function on layouts v4 and v5. A service that serves for long (`App.Run`) still opens its keys before it serves, so a fault in them stops the start; `issuerapp.Config.LazySigningKeys`, which only the Lambda function sets, is what defers them. A typo in the state secret's name now fails the request that first needs a key, not the start.
- **The issuer holds no signing key: the tokens the OpenID library mints are signed by the signer.** An ID token (and a JWT access token the library builds itself) is now signed through `internal/signer` with a new `id_token` purpose, bounded by the deployment's token lifetime like an access token; the library is given an opaque signer, not a private key. Kids, key set, algorithms (ES384 by default, RS256 where pinned) and token contents are unchanged. `issuer.NewStorage` takes a `signer.Signer` and its read-only `signer.Directory` instead of keys, and key rotation is fed to the key rings by the wiring rather than through the storage.
- **Breaking: the chart's `exports.openbao.*` values are now `adapters.openbao.*`.** The key named the layout v3 exports, which no longer exist; it only configures the CA bundle and the projected login token of the `openbao` secrets adapter. `exports.openbao.caBundle` becomes `adapters.openbao.caBundle`, `exports.openbao.token.audience` becomes `adapters.openbao.token.audience` and `exports.openbao.token.expirationSeconds` becomes `adapters.openbao.token.expirationSeconds`. The mount paths and the rendered objects are unchanged. A values file that still sets `exports` is refused by the schema.
- **`/authorize` refuses PKCE `plain`, and a public client that sends no `code_challenge`.** Discovery lists `S256` only, but the library accepted `plain` (a challenge that is the verifier itself) and let a public client omit the challenge. Both are now a 400 `invalid_request` before the sign-in page. A confidential client may still omit PKCE; if it sends a method, it must be `S256`. Breaking for a client that relied on either.
- **A token request's `resource` must be within the grant's.** At the code exchange and at a refresh, a `resource` other than the one the grant was authorized for is refused with 400 `invalid_target` (RFC 8707 2.2). It was validated as a declared resource and then ignored, so a client could name one resource and receive a token for another. Naming the same resource, or none, works as before. Breaking for a client that sent a different `resource` at the token endpoint.
- **Discovery no longer advertises what is not served.** The library filled `introspection_endpoint` and its two `introspection_*` members, and the RS256 default for `revocation_endpoint_auth_signing_alg_values_supported`, `token_endpoint_auth_signing_alg_values_supported` and `request_object_signing_alg_values_supported`. Introspection is refused (the tokens are JWTs verified offline), no client authenticates with a signed JWT, and no request object is read. Those members are removed from OpenID discovery and from the RFC 8414 document. The signing algorithms of tokens stay in `id_token_signing_alg_values_supported` and the key set.
- **Client ID metadata documents: a path is required, dot segments are refused, refusals are named, and `Cache-Control` is honoured.** A client document URL must have a path component (a bare origin is refused) and no dot segments, plain or percent-encoded (draft-ietf-oauth-client-id-metadata-document 3). `/authorize` answers a document URL that cannot be used with a 400 naming the reason (origin not admitted, no path, a fetch that failed, a document that disagrees with its own id), instead of the library's "unable to retrieve client by id". A fetched document is reused for its `max-age`, held between 1 minute and 24 hours (`no-store`, `no-cache` and `max-age=0` take the minute); with no header it is still 10 minutes. Breaking for a client whose id was a bare origin or carried dot segments.
- **Authorization responses carry `iss` (RFC 9207).** Every redirect back to a client from `/authorize`, the success one with a `code` and the error ones alike, now has `iss=<issuer>` appended, and discovery and the RFC 8414 document advertise `authorization_response_iss_parameter_supported: true`. A client that talks to more than one authorization server can check it to refuse a response sent by another (the mix-up attack). The `form_post` response mode is not covered.
- **A refused `resource` at `/authorize` goes back to the client as `invalid_target`.** When the request names a `redirect_uri` that the client has registered (the same check the library makes before it sends a code there), a `resource` that is malformed, repeated or not declared is answered by a redirect carrying `error=invalid_target`, an `error_description` and the client's `state` (RFC 8707 2), instead of a 400 page. A client that is misconfigured now learns it from the response it is waiting for instead of hanging. With no client, no `redirect_uri` or one that is not registered, the 400 page is shown as before, so nothing is ever redirected to an address nobody registered.
- **The Google module is `google` in storage, not `directory`: the hub's snapshot blobs and the migration's domain.** The hub's per-workspace snapshot is the blob `google/<workspace>` (it was `snapshots/<workspace>`), on S3, in the in-memory port and in the legacy Valkey blob adapter. It is a cache the hub rewrites on its next refresh and is never migrated, so the first read after the upgrade finds no snapshot and answers "not yet written"; the old `snapshots/` objects are not read again and can be deleted. In `sluis migrate` the domain is `google` in `--skip`, in the report and in `AllDomains`; `directory` is still accepted by `--skip` for this release (with a warning) and is removed in v1.76. The Go `Directory` interface and the console's Directories page keep their names. The layout 5 kind (`workspace` of `google`), the parameter `internal/google/workspaces/<id>/key` and the Pulumi roles' `google/*` blob grant were added by the module vocabulary and path builders above.

### Breaking

- **Breaking for consumers that pin the old value: tokens carry `acr` `urn:truvity:sluis:acr:directory` or `urn:truvity:sluis:acr:recovery`**, not `urn:truvity:access-roster:acr:*`. A relying party, role rule or policy that compares `acr` against the old spelling must accept the new one (or both) before this release is deployed. For one release, discovery's `acr_values_supported` lists both spellings, a request whose `acr_values` names the old spelling is still honoured, and the token answers in the new one; `issuer.NormalizeACR` reads either.
- **Breaking (direction): secrets layout v5 is available, opt-in in v1.75; layout v4 is deprecated.** `secrets.layout: v5` (and `LambdaArgs.Layout: v5` in the Pulumi library) puts each module's tables, parameters and blobs under its own `internal/<module>` and `external/<module>` addresses; v4 stays the default in v1.75 and is removed in a later release. Moving a live installation is `sluis migrate v5 copy`.
- **Breaking (modcall): the envelope is version 2 and the transport says who is calling.** A request carries `v` (2; absent is read as 1, a newer one is refused), and the caller class is set by the transport, never by the request: `modcall.Local.As(class)` in process, the verified token's ServiceAccount name (or `modcall.WithClasses`) on Kubernetes, and on Lambda the alias the function was invoked through, `live-<class>` (`lambdacall.AliasOf`, `ClassOf`). A method registered with `modcall.Allow("issuer", "console")` answers only those classes and refuses the rest with `forbidden`; a `caller` written in the payload or the envelope is ignored. The Cloudflare module's `mint` is limited to `issuer` and `granted` to `issuer` and `console`, and the issuer's `cloudflare.remote.function` is now invoked through `live-issuer` instead of `live`: the callee function needs that alias and an invoke permission on it before the issuer is upgraded.
- **Breaking: `sluisctl` refuses to guess the issuer when two sessions are live.** A command given no `--issuer`, with no `$SLUISCTL_ISSUER` and no `issuer:` in `config.yaml`, used the issuer of the most recent `login`, so a laptop signed in at two issuers got the wrong one, with an error that read as an expiry. Now, with more than one live session and nothing pinned, it exits 2 and lists the issuers, naming `--issuer`, `$SLUISCTL_ISSUER` and the `issuer:` key. With exactly one live session the command uses it. `login` no longer writes `issuer:` (it writes `lastIssuer:`, which pins nothing), so `issuer:` is only ever set by hand; a `config.yaml` from an older release still holds the last login there, and keeps pinning it until you delete that line. `login` without `--issuer` is unchanged.
- **audit: `credentials_preset` is refused unless the installation acknowledges the minter's custody.** The mode puts the Cloudflare minter in every process that reads the archive (the Lambda writer and notary, in-cluster observe, query and jobs), and a minter can mint any right its creating user holds, so anyone able to act as those roles or service accounts holds that power. The chart now refuses a preset with `credentials_preset` unless `acknowledgeMinterCustody: true` is set in values. The Pulumi library refuses a `PresetStorage.CredentialsPreset` unless `Args.AcknowledgeMinterCustody` is true. Both errors name the preset and point at `credentials_ref`, the mode to prefer since v1.74.0-rc.4. An installation that keeps `credentials_preset` sets the acknowledgement; one that moves to `credentials_ref` sets nothing. See [upgrade audit to v1.75](docs/guides/audit/upgrade/v1.75.md).

### Removed

- **Breaking: secrets layout v3 and `transition`.** `secrets.layout` accepts `v4` only, which is also the default; `v3` and `transition` are refused at load. The `ssm` Secrets adapter is the layout-v4 stores and no longer keeps `private/` or `export/` parameters; the SSM secrets source reads `<root>/internal/config/<name>` only. A Cloudflare minter or a `credentialsRef`/`credentials.preset` blob no longer checks the layout, only that the secrets are the `ssm` source's. **Upgrade note:** an installation must already run `secrets.layout: v4` (and have deleted v3) before it upgrades to this release. One still on v3 or `transition` first moves on v1.74.x (v1.74.1 or later) with `sluis migrate secrets-layout`: [the steps](docs/guides/sluis/upgrade/v1.74.md).
- **Breaking: `sluis migrate secrets-layout`, `sluis migrate ssm-layout` and the destination-layout notes of `sluis migrate`.** `sluis migrate` still copies a legacy in-cluster store or any other storage into a destination; a destination on the `ssm` source is written in layout v4, and the report no longer carries a note about the layout or a `DEPRECATED` warning for v3.
- **Breaking (Pulumi library): the layout-v3 parameters and grants.** The issuer's state secret and the recovery password are written at `/sluis/<instance>/internal/config/...` (`StateSecretParameterName`, `RecoveryPasswordParameterName`, `ConfigParameterPrefix`), where the service reads them, and not at `private/config/...`. The value is the same, so the first apply adopts the v4 copies `sluis migrate` already wrote (`overwrite` is set), then deletes the old ones at the end: [upgrade to v1.75](docs/guides/sluis/upgrade/v1.75.md). The roles lose their grants on `private/credentials/*` and `private/config/*`, and `PrivateParameterPrefix` and `CredentialsParameterPrefix` are gone.
- **audit: the `provider` shape of the `keys` block.** `keys.provider`, `keys.local` and `keys.transit` are gone from the configuration schemas (`audit-writer`, `audit-writer-lambda`, `audit-query`, `audit-notary`) and from the chart values; a file that still has them is refused. Migration: name the keys by purpose through the storage port. `keys: {adapter: local, instance: <name>, pseudonym: <key>, rootFile: <file>}` replaces `provider: local`, and `keys: {adapter: transit, instance: <name>, pseudonym: <key>, openbao: {...}}` replaces `provider: transit` (the `openbao` block moves up one level). The transit adapter keeps a key per tenant for the `pseudonym` purpose, so `audit key destroy` erases a tenant on it. The local adapter has no key directory, so the writer's key-directory binding and the chart's local-directory refusal are gone with it. Frozen version 1 configuration files that carry `keys.provider` no longer load; move them to version 2.
- **audit: the deprecated `keys/` constructors.** `keys.Local`, `keys.NewLocal`, `keys.Transit`, `keys.NewTransit`, `keys.TransitSigner` and `keys.NewTransitSigner` are removed from `github.com/truvity/sluis/audit/keys`. Migration: open the storage port (`github.com/truvity/sluis/storage/keys`) and wrap it with `keys.NewPortProvider` and `keys.NewPortSigner`. `keys.KMSSigner` stays.
- **audit: the `signer.transit` block of `audit-notary` and `--transit-key` of `audit key public`.** Migration: `keys: {adapter: transit, instance: <name>, seal: <key>, openbao: {...}}` in place of `signer: {transit: {key, openbao}}`.
- **audit: the `--key-provider`, `--key-root`, `--key-dir` and `--transit-*` flags of `audit key destroy`.** Migration: `--writer-config <file>` reads the writer's `keys` block.
- **audit: the old `presets:` refusal in the deployment document.** A profile's `presets:` key is now an unknown field like any other, no longer refused with a message that names `frameworks:`.

### Added

- **The Pulumi library renders the sluis statements of the shared key's policy.** `SluisKeyPolicyStatements(KeyPolicyArgs)` returns the Allows and Denies an estate's one symmetric key needs for sluis, with unique `SluisKey…` Sids: each function role through SSM for its hosted modules' `internal/<module>` and `external/<module>` parameters; backup (Decrypt) and restore (Encrypt, Decrypt) over all of `internal/*` and `external/*`; the External Secrets readers on `external/*` only; the operator's seeding and its reads of the state secret and recovery password; the emergency roles; and the sign purpose under `{instance, purpose: sign}` for the roles that host `oidc`, with the three denies that reserve it. They are about sluis's roles and the sign purpose only, so an estate's seal, operator purposes and state bucket keep working beside them. `KeyPolicyDocument` joins the lists, refuses a repeated Sid and a document over KMS's 32 KiB. `DenyOtherActions` adds the deny that keeps a sign role to the key's three calls. An estate replaces its hand-written sign and parameter statements with the helper and keeps key administration and its other usages.
- **The Pulumi library checks the declared secrets after the deploy.** `NewLambda` adds an `aws.lambda.Invocation` of the function's live alias with `{"kind":"check"}`, which depends on the alias, the role's policy and the parameters the stack writes, so it runs once they exist. A secret the documents declare that is missing, empty or malformed fails `pulumi up` with the function's error, `check: N of M declared secrets are missing or invalid`, and the addresses. It is triggered by the function's version and a hash of the declared names, so it runs again on every new version and when a declaration changes. It is on by default; `LambdaArgs.Check` set to false leaves it out. The new output `DeclaredParameters` lists the declared names (`internal/config/<name>` on layout v4) whether or not the check is on, for an estate that checks in a CI step. `config.DeclaredSecrets` is the set the check and the output use.
- **The backup archive format and its encryption (`internal/backup`).** A backup is `backup/<installation>/<id>/manifest.json` plus chunked, sealed objects `state/<module>/<n>`, `secrets/<module>/<n>` and `blobs/<module>/<n>`. The manifest lists the format version, the installation, the id, the storage layout, the creator, and per module and section the record count and each chunk's size and SHA-256. Every record, State item, secret value and blob alike, is inside a chunk sealed with AES-256-GCM; the manifest holds no secret. One data key per backup is generated by the `archive` key (a KMS alias or an OpenBao transit key, under its unchanged encryption context) and kept wrapped in the manifest; the chunk keys and the manifest's HMAC are derived from it, and each chunk's authenticated data names its installation, backup, section, module and number, so a changed, moved, dropped, added or reordered chunk, or a changed manifest, is refused, and a key that may not decrypt fails before any chunk is read. A reader opens the current format and the one before it; the released archive is committed under `internal/backup/testdata/v1` and opened by every later release. The package is the format only: nothing writes a backup yet.
- **The backup exporters (`internal/backup/export`).** `export.Run` reads an installation on layout v5 through the ports into a backup writer, per module: every State record the module owns with the lifetime it has left, and for `oidc` every Index set; every secret under `internal/<module>` and `external/<module>` at any depth; and the objects under the module's blob prefixes (the controllers' reports), an object over 8 MiB split into parts that `export.Assembler` puts back and checks against its size and SHA-256. It leaves out leases, notifications, gates, caches, dedupe records and the maintenance record, which a restore manages itself. A record is one JSON object with a version and a type (`state`, `index`, `secret`, `blob`) that `export.Decode` reads and refuses when it is another version, another section's or has a field it does not know; secret values are in no record outside a sealed chunk and the run logs counts only. A run is a fixed list of units (one key family, one secret namespace or one blob prefix of a module); after each one it hands a checkpoint to the caller, and a stopped run continues from the last with `backup.Resume` and `Options.Resume`, reading the unfinished unit again, so the order an adapter lists records in does not matter. To find nested secrets `storage/state` gains the optional `Walker` capability and `state.ListAll`, implemented by the memory, SSM, S3 and OpenBao stores; and `port.StatePrefixes5` and `port.SetPrefixes5` name the key families each module owns. Nothing schedules a backup yet.
- **Maintenance mode: every module refuses writes while its own table carries the maintenance flag.** The flag is the record `rec.maintenance` (`state`, `since`, `by`, `reason`) in each module's own DynamoDB table; no module reads another's. A module reads it through `internal/maintenance`, cached for 10 s, and a flag it cannot read refuses writes and allows reads. The issuer answers 503 with `Retry-After` on `/authorize`, `/oauth/token`, `/revoke`, `/end_session` and the sign-in and sign-out pages, and keeps answering discovery, `/keys`, userinfo and introspection, so tokens already issued stay valid and verifiable. The console refuses every write RPC of a module under maintenance with `Unavailable`, refuses the pages that store a record on return from GitHub, Slack or a directory, and shows a banner (`whoami` carries `maintenance`); the pages stay readable. The GitHub and Slack controllers and the issuer's key and client-secret leases skip their ticks, counted by `sluis.leases.skipped` (and `access_roster.leases.skipped` while the legacy names are on), not logged, and reported as the outcome `maintenance` in the Lambda event result, apart from `contended`; the directory refresh stands still; the Cloudflare minter refuses mints, rotations, revocations and sweeps under the code `maintenance`, and the issuer turns it into a 503. Only the restore function writes the flag (`maintenance.Write`, `maintenance.Clear`).
- **Pulumi: only the restore role can write the maintenance flag.** The statement that let every role read a `maintenance` partition of the backup table is gone, because each module reads the flag from its own table. Every role but `restore` now carries an explicit `SluisMaintenanceDeny` of `PutItem`, `UpdateItem`, `DeleteItem`, `BatchWriteItem` and `TransactWriteItems` on the `maintenance` partition of the tables it holds, whatever else it is allowed; the restore role writes it through its own and its cross-grant table statements. The Pulumi tests evaluate the rendered statements the way IAM does.
- **`sluis check` and the `check` event verify the declared secrets at deploy time.** Secrets are read when first used, so a name that is missing or mistyped fails a request and not the start. `sluis check --config <file>` computes the set the service document and its policy declare (`config.DeclaredSecrets`: the recovery password, the state secret where `signingKey.kms` or `kmsWrapped` is set, the Google sign-in client, each seeded client secret, each declared workspace key, each Cloudflare minter, `ports.blob.s3.credentialsRef`), reads each from SSM on layout v4 or v5, prints its address and version, and exits non-zero for one that is missing or empty, or for a state secret that is not hex or base64 of at least 32 bytes with at least 8 distinct ones. The Lambda event `{"kind":"check"}` runs the same check and fails the invocation with the addresses that failed; the Cloudflare module's function checks its minters only. Output holds addresses, versions and fixed reasons, never a value. Secrets sluis creates at run time (the console session key, a GitHub or Slack App's credential) are not declared and not checked.
- **`sluis migrate v5 plan` shows what a move to layout v5 would do.** `sluis migrate v5 plan --from <v4 config> --to <v5 config>` opens the layout v4 installation and the layout v5 one and prints, per module (`oidc`, `github`, `slack`, `cloudflare`, `google`), which records, secrets and reports are new, the same, different or refused on the destination, with names and versions and never a value. It writes nothing to either side. The mapping is one table (`internal/migrate/v5map.go`): every v4 logical key and parameter name has its module, kind, id and v5 name, and `ports.blob.s3.credentialsRef` `internal/blobs/r2` becomes `internal/google/blobs-r2`, under the module that owns the blob prefix. The plan refuses what layout v5 cannot carry: an organisation with no App named in `controllers.github.appRefs` (or whose installation belongs to another App), runner Apps whose tier and organisation join to one id, a directory backend other than `google`, an unreadable record, and a record or secret over a size limit. `--sessions skip` plans the key ring and the state secret's fingerprint only; the flags of `sluis migrate` are unchanged.
- **`sluis migrate v5 copy` and `verify` move a layout v4 installation to layout v5 and check it.** `copy --from <v4 config> --to <v5 config> --i-have-stopped-writers` writes what the destination lacks, reads both sides again and verifies; it writes an organisation naming its App (`app_ref`, from `controllers.github.appRefs`) after the Apps, and a static S3 credential at its new reference. It is idempotent: a re-run writes nothing the destination holds equal. It stops before any write when an item is refused or the destination holds a different value (`--overwrite` replaces it), and it never deletes from the source. `--dry-run` reads and writes nothing. The two passes are a first `copy --skip issuer` while the source runs and a final `copy --overwrite` with the writers stopped. `verify` writes nothing and compares per module: secrets by a hash that does not depend on their version, records by value, an organisation by its record and the App it names. Reports list copied, same, different and refused per module and never a value.
- **The console's and the issuer's Connect services are also served as `sluis.v1`.** A new proto package `sluis.v1` carries the messages and services of `directoryroster.v1` and `accessissuer.v1` unchanged, field for field and number for number, and every service answers on `/sluis.v1.<Service>/<Method>` as well as on its old path, from the same handler (`WorkspaceService`, `SettingsService`, `AccessService`, `GitHubService`, `SlackService`, `SlackChannelService`, `SlackSharedChannelService`, `SlackAppService`, `CloudflareService`, and the issuer's `SessionService`). The console calls the new path first and repeats a call at the old one when the server says the service does not exist (Connect `unimplemented`, or a 404 that is not a Connect error), so a new console still works against an older server; any other answer, `not_found` included, is returned as it is and never retried. A test compares every `sluis.v1` file with its old counterpart, and `buf breaking` against master finds nothing. Metrics and traces of a call keep the old procedure name for this release. This is the dual window: the old packages and paths are removed in v1.76.
- **`sluis migrate v5 copy` and `verify` carry the issuer: the key ring, sessions and refresh tokens.** In the final pass (the writers stopped) `copy` writes the issuer's records to the `oidc` table: the key ring's entries and tombstones byte for byte (the KMS context is unchanged, so they are never opened or wrapped again, and the published key set stays the same), the state secret's fingerprint record, sessions, refresh tokens with the markers of the spent ones (a token spent before the copy stays spent), single sign-on records, codes in flight, request records and the Index sets (an Index set that differs is made equal). Each record is written with the lifetime it had left when it was read, less what passed before it was written; one whose lifetime ran out first is skipped and counted as `expired` in the report. `--sessions skip` (on `plan`, `copy` and `verify`; default `copy`) carries the key ring and the fingerprint only, so people sign in again; `--skip issuer` still leaves the issuer for the second pass. The source is never changed. The DynamoDB adapter's per-module `Tables.Router()` now lists State records and Index sets with their remaining lifetime, so a layout v5 destination can be read.
- **Metrics, alerts and dashboard under the `sluis` name, beside the old ones (the dual-name window of the rename).** Every `access_issuer.*` and `access_roster.*` metric is also recorded as `sluis.*`, the same type, unit and labels, so the cardinality per name is the one it was: `sluis_http_requests_total`, `sluis_http_request_duration_seconds`, `sluis_tokens_issued_total`, `sluis_login_failures_total`, `sluis_login_successes_total`, `sluis_reuse_detected_total`, `sluis_spent_mark_ahead_total`, `sluis_dead_refresh_token_hits_total`, `sluis_signing_keys_published`, `sluis_signing_key_active_since_timestamp_seconds`, `sluis_signing_key_transitions_total`, `sluis_kms_signatures_total`, `sluis_ticks_total`, `sluis_tick_duration_seconds`, `sluis_tick_last_success_timestamp_seconds`, `sluis_leases_acquired_total`, `sluis_leases_contended_total`, `sluis_leases_lost_total`, `sluis_leases_held` and `sluis_port_operation_duration_seconds`. The old names are recorded while `telemetry.legacyMetrics` is true (the chart's value, the `SLUIS_LEGACY_METRICS` variable; **on by default in v1.75**); v1.76 removes the old names and the setting. The chart's rules render under two names each, `AccessRoster...` and `Sluis...` (22 in all), and every expression is `(<sluis_ names>) or (<old names>)`, so a rename never silences one. A new `sluis-overview` dashboard (uid `sluis-overview`) has the panels of `access-roster-overview`, each query selecting both names; the old dashboard stays until v1.76. The chart's `OTEL_SERVICE_NAME` is now `sluis` (it was `access-issuer`): a query that selects the old `service_name` must select both. The `github_roster.*` and `slack_roster.*` metrics are unchanged. [Telemetry](docs/reference/sluis/telemetry.md).
- **Layout v5 is selectable: `secrets.layout: v5` and `ports.dynamodb.tables` (docs/decisions/0072).** `ports.dynamodb.tables` names one table per module (`oidc`, `github`, `slack`, `cloudflare`, `google`, `backup`) beside `table`, which stays the layout v4 setting; exactly one is required. `secrets.layout` accepts `v5` beside `v4`. The pair goes together: tables with the `ssm` source on `v4`, `v5` with a single `table`, or both table settings are refused at load and at start, naming the keys. `store.Open` binds a table per module (`Config.Module`, `Config.Peers`, `Config.As`): a binary's State is its own module's table, wrapped so a write of another module's key is `port.ErrNotOwner`, and each peer is a read-only view; the issuer binary is the `oidc` module with the peers `google`, `github` and `slack`, the GitHub and Slack controllers and the Cloudflare module each hold their own. A process with no module gets the router over every table, for the migration and the backup. `Stores.ForModule(own, peers...)` gives a module that still runs inside another binary its own table, and `Stores.Tables` and `Stores.V5` (the module-first secrets, `secretstore.OpenV5`) are exposed. The in-memory adapter splits by module on layout v5 as well. The domain stores read a record that belongs to a peer through that peer's view (`portstore.Base.Peer`), and a read of a module with no grant is `portstore.ErrNoPeer`, not "not found". `observe.Set` keeps `Module` and observes the peers (`peer_get`, `peer_list`), and the memory adapter's registry factories take a `module` setting. A listing that spans two modules (`ws.` covers slack and google) is `ErrUnsupported` on the router: list `ws.dir.`. Layout v5 does not run an installation yet: the callers still read secrets by their layout v4 names (the Secrets port is unset on `v5`), the S3 `credentialsRef` and `credentials.preset` and the Cloudflare minter refuse `v5`, and the module-first names move with the following change.
- **DynamoDB: one table per module (docs/decisions/0072).** `dynamodb.Config.Tables` names a table for each module (`DefaultTables(instance)` gives `sluis-<instance>-<module>`), and `dynamodb.OpenTables` binds them. A module's table holds that module's records under layout 5 (the kind without the module prefix, as `internal/port/layout5.go` locates them) and has its own `lease` and `notify`; `Watch`, `Notify`, `Subscribe` and `ExportState` act on that table alone. `Tables.Set(own, peers...)` returns the own State wrapped in `port.Owned` and a `port.ReadOnly` view over each peer's table, so a write of another module's key is `port.ErrNotOwner` before any request and a peer read goes to the peer's table only. Opening makes no AWS call unless `Create` is set: a missing table surfaces at the readiness probe (`Tables.Ping`, which names the module) and at first use as `ErrUnavailable`. The layout 4 `Table` is unchanged and still checks its table at start; setting both is refused. The store does not use the tables yet. `porttest.Env` gains `RecordPrefix` and `PermanentPrefix` so the suite can run against a table that holds one module. `Tables.Router()` is one State and Index over all the tables, for what crosses modules by design (migration, backup, a test of a whole flow); a grant measured through it costs the same requests as over one table, on the fake and on LocalStack (`hack/dynamodb-conformance.sh` requires both and the suite on every module's table).
- **`port.Set` carries the module it serves and read-only views of its peers.** `Set.Module` names the module whose records `State` holds, and `Set.Peers` holds a `port.StateReader` (Get and List, no write method) for each module a named cross-grant lets the process read (ADR 0072). `port.Owned` wraps a `State` so that a write of a key that layout 5 locates in another module returns the new `port.ErrNotOwner` and reaches nothing; a key of no module (leases, notifications) is the table's own. The memory adapter gains `memory.NewModules`, one store per module, whose `Set(own, peers...)` is wired that way, and `portstore.Base` carries the module and its peers. Nothing selects them yet: the DynamoDB table per module and the configuration come in the next units.
- **GitHub Apps are one kind in storage: an id, a purpose and labels (docs/decisions/0072).** The link App (id `link`), a catalogue App (its own id) and a runner App (`runner-<tier>-<org>`) share one id space and one record shape: `purpose` (`link`, `catalogue` or `runner`, set on every write; a record without one is read with the purpose its key implies) and `labels` (at most 16 short lower-case names). `portstore.GitHubApps` lists and reads them as one kind, and the three typed stores keep their methods, so callers do not change. On layout v5 (`portstore.Base.WithV5`) an App's credential is `internal/github/apps/<id>/<ref>`, under a fresh ref per write, and an exported App is `external/github/<id>`; layout v4 is unchanged. A catalogue id of `link` or beginning `runner-` is refused where the record is written, and two runner Apps whose tier and organisation join to one id are refused at the second write. An organisation's record may name its App with `app_ref`, and its credential is then that App's key, kept once; on layout v5 an organisation without `app_ref` is refused. Layout 5 now addresses a runner App as `runner-<tier>-<org>` (it was `runner/<tier>/<org>`), the id its exported document has had since ADR 0041. Nothing selects layout v5 yet.
- **The sluis client and thing names are accepted beside the old ones.** The client-secrets endpoint takes a token minted for `sluisctl` or `sluis-console`, as well as `accessctl` and `console`. A policy that names only `all:sluis:operator` and `all:sluis:viewer` no longer has them reported as unconsumed groups. A vocabulary may declare `things.sluis`. The names the hub writes are unchanged: `ScopedGroup` and `GroupOperators` still emit the `access-roster` spelling.
- **The Pulumi library: the module model and a statement list per role.** `Module` (oidc, github, slack, cloudflare, google, backup), `ModuleSet` (table `sluis-<instance>-<module>` by default, overridable per module) and `ModuleRoleStatements` render one role from the modules its function hosts: their `internal/<module>/*` and `external/<module>/*` parameters with the key through SSM for exactly those, their tables and blob prefixes, the audit queue, the role's log group, and the named `CrossGrants` (the issuer reads the google, github and slack tables and invokes their functions; backup reads everything; restore writes everything and `RestoreInvokeStatement` names who may invoke it). Nothing is wired into `NewLambda` yet.

- **Storage layout 5, step one: the modules and where every key lives.** `internal/port` names the modules (`oidc`, `github`, `slack`, `cloudflare`, `google`, `backup`) and locates every State key and Index set as a module, a kind and an id (`Locate5`, `LocatePrefix5`, `LocateSet5`, `Kinds5`): `github-org` is the kind `org` of `github`, a directory workspace is `workspace` of `google`, the issuer's records are `request`, `code`, `token`, `sso`, `session` and so on of `oidc`, and every GitHub App is the one kind `app` keyed by its id. The leases, notifications and generic families belong to no one module and are held by every table. The layout 4 mapping is unchanged and frozen (`keys_v4.go`); nothing reads the new one yet.

- **`internal/secretstore`: the layout v5 path builders, one view per module.** `FromStoreV5` gives `OIDC`, `GitHub`, `Slack`, `Cloudflare`, `Google` and `Backup` internal views and the `external/oidc`, `external/github`, `external/slack` and `external/cloudflare` views; an address is `internal/<module>/<name>` or `external/<module>/<name>`, with no `config` or `credentials` level (`oidc/state-secret`, `oidc/recovery-password`, `oidc/console-session-key`, `oidc/signin/<provider>/{client-id,client-secret}`, `oidc/clients/<id>`, `github/apps/<id>/<ref>`, `google/workspaces/<id>/key`). A view has methods for its own module's names only, and `CheckModuleRef` refuses another module's address. `external/oidc/<client>` is byte-identical to layout v4. Nothing selects the layout yet; layout v4 stays readable.
- **The hub's own groups are read under the `sluis` spelling too: `all:sluis:{operator,viewer}` and `<workspace>:sluis:{operator,viewer}` beside the `access-roster` ones.** The console's roles, the workspace scopes, the client-secrets endpoint and the sessions service accept either, and a policy that names both holds the union, so a grant can be moved group by group. `sluisctl render` already passed group names through; it now has a test for both spellings. The `access-roster` spelling is deprecated and goes in v1.76; until then a policy needs no change, and the one-time rewrite of grants to the new name can be done per installation at any point once it runs this release. `policy.ThingSluis`, `policy.IsOperators`, `policy.IsViewers` and `policy.ScopedGroupOf` are the new names in Go; `policy.GroupOperators`, `policy.GroupViewers` and `policy.ScopedGroup` still name the old spelling.
- **`storage/keys/transit` and audit: a transit key per tenant for the pseudonym purpose, and erasure by destroying it.** `MAC` for the `pseudonym` purpose is now transit's `hmac` on a key of the tenant's own, named `<key>.pseudonym.<escaped tenant>` (`<key>` is the configured pseudonym key name) and created on first use through `encrypt`, so the writer's role needs `create`/`update` on `encrypt/<key>.pseudonym.*`, `update` on `hmac/` of the same and `read` on `keys/` of it, and nothing on `decrypt`, `rotate`, `config` or `trim` (only resolve decrypts). The tenant is escaped by `transit.EscapeTenant`: `a-z`, `0-9` and `-` stand for themselves and every other byte, `_`, `.`, `/`, `@` and upper-case letters included, becomes `_` and two lower-case hex digits, so two tenants never share a key name, and a name over 128 characters is refused, not cut. `Key.Destroy` (the eraser's role: `read`, `create` and `update` on `keys/<key>.pseudonym.*`) rotates the key once, requires a version past 1 to encrypt and decrypt, and trims version 1; the key stays as the tombstone and is found before any create, so a destroyed tenant gets no fresh key, and a tenant destroyed before it was seen has a key made and destroyed at once. `Key.Destroyed` reads it. New optional backend capability `keys.TenantCipherBackend` with `Key.EncryptFor`, `Key.DecryptFor` and `Key.PerTenantCipher`: audit's `PortProvider` seals and opens an identifier under the tenant's key where the backend has one, so destroying the tenant makes its sealed identifiers unreadable by cryptography and no conceal key is needed on transit. The keys of the removed `provider: transit` shape (`<prefix>.<purpose>.<tenant>`) are not reused: the names differ, so an installation that moves from it makes new pseudonyms. The other purposes, the seal key and the kms backend are unchanged. `openbaotest.FakeTransit` is an in-process engine for tests.
- **Token-exchange token types: `urn:sluis:params:oauth:token-type:{github-installation-token,cloudflare-token}` are accepted beside the `urn:access-roster:params:...` ones.** The issuer answers a request under either spelling and returns the one that was asked as `issued_token_type`, so a client sees no change. The `urn:access-roster:` spellings are deprecated and are removed in v1.76; `tokens.TypeSluisGitHubInstallationToken` and `tokens.TypeSluisCloudflareToken` name the new ones, `tokens.IsGitHubInstallationToken` and `tokens.IsCloudflareToken` match either, and `tokens.Exchanger`, `sluisctl` and the GitHub Action still ask for the old spelling, so they keep working against an issuer older than this release. A caller moves to the new spelling once its issuer runs this release.

- **The signing key ring, the KMS-wrapped signing and the KMS keys moved into `internal/signer` (docs/decisions/0071).** `KeyRings`, `SigningKey`, `WrappedSigning` and the KMS key readers are now `signer.*` (the issuer's exported names are gone); the ring publishes `signer.PublicKey` rather than the OIDC library's key type, so the signer imports no OIDC package. Kids, key sets, the wrapped-key format, the shared-state keys and the rotation schedule are unchanged. A boundary test keeps the issuer from naming the ring's internals.
- **A "Rotate webhook secret" button on a GitHub App's page.** For a catalogue App that declares a webhook, an operator confirms in a dialog; the console then calls `RotateGitHubAppWebhook` and shows whether GitHub still differs from the declaration. The page also shows when the secret was last set.
- **`internal/signer`: the issuer signs through a narrow in-process interface (docs/decisions/0071).** `Sign(ctx, Request{Purpose, Algorithm, Payload})` and `PublicKeys(ctx)` replace the issuer's direct use of the key ring for the console mint and the back-channel logout token, and for the key set. The signer fixes the JWT `typ` from the purpose, refuses a purpose it was not configured with, and refuses a payload whose `exp` minus `iat` is above the purpose's maximum (the deployment's token lifetime for access tokens; a logout token carries no `exp`). The KMS backend and the `keys.sign` key are opened in `internal/signer`, and the import-boundary test now lets only that package import `storage/keys/{kms,local,transit}` and keeps it free of HTTP, cookie, session and OIDC protocol packages. Kids, key sets, tokens and algorithms are unchanged.
- **`sluis` is a multi-call binary on urfave/cli v3 (docs/decisions/0071).** The root command gets the module subcommands `issuer`, `console`, `github`, `slack`, `cloudflare`, `google` and `backup`. `issuer` runs what `sluis serve` runs, `github` and `slack` run the controller's loop alone, and a module with no process of its own yet (`console`, `cloudflare`, `google`, `backup`) answers `not yet split` and exits 1. `serve`, `controller`, `tick` and `migrate` are unchanged, and so is the Lambda binary. The root `--help` text is now generated.
- **An import-boundary test pins the module boundaries that hold today.** Only the issuer's process (the future signer) imports the signing-key adapters; the GitHub, Slack and Cloudflare packages import neither the issuer front end nor each other; the issuer library imports no process.

- **`cmd/sluis` builds for Lambda with `-tags lambda,lambda.norpc`.** The Lambda build carries no Kubernetes, NATS or Valkey storage, and `sluis migrate` answers that it is not part of that build. The untagged build is the Kubernetes one and is unchanged. `cmd/sluis/imports_test.go` holds each build to its platform's adapters, as `cmd/sluis-lambda` already did for its own. `cmd/sluis-lambda` stays the released Lambda entry for now.

- **`sluis github` and `sluis slack` are single-module processes with a `tick <target>` form.** Each runs its controller's loop without the "deprecated" warning that `sluis controller <kind>` keeps, and `sluis github tick <target>` ticks once, as `sluis tick github <target>` does. The roles are `internal/module` implementations (`Run`, `Tick`) that the commands call; `console`, `cloudflare`, `google` and `backup` are placeholders that answer `not yet split`. The existing commands run the same code and are unchanged.

- **`sluis cloudflare` runs the Cloudflare STS minter alone, with a `tick <preset>` form.** `sluis cloudflare --config <file>` looks at the document's `cloudflare.presets` once a minute and rotates the stored credentials that are due, sweeping the expired tokens it minted; `sluis cloudflare tick <preset> --config <file>` does that for one preset once, under its lease, and exits 0 when another runner holds it. The process holds the Cloudflare minter credential and nothing of the issuer, the directory hub or another provider; it reads the same service document and needs `secrets.source: ssm`. The on-demand token exchange, the console and `sluisctl` still reach the minter inside the issuer's process, and `sluis serve` and the Lambda `{"kind":"cloudflare"}` schedule rotate as before. The import-boundary test now holds the Cloudflare module apart from the issuer front end and the other providers, and lists the packages outside the Cloudflare ones that may still import the minter.

- **`internal/modcall`, the transport of calls between modules (docs/decisions/0071).** A typed call (module, method, JSON payload) with a coded error, served by a `Server` and made through one `Caller` interface with three transports chosen by configuration: in this process (`Local`, the default and what every single-process deployment keeps), HTTP to a Kubernetes Service with a bearer the callee verifies (`HTTPCaller`, `Server.Handler`), and `lambda:InvokeFunction` of the callee's `live` alias (`lambdacall`). Nothing calls through it yet; a module is moved onto it in its own change.

- **`cloudflare.remote`: the on-demand Cloudflare exchange can call the Cloudflare module instead of holding the minter.** A service document that sets `cloudflare.remote` (`function` for a Lambda function's `live` alias, or `url` for a Kubernetes Service with `audience` and `tokenFile` for the projected token) declares no accounts or presets, and its token exchange and `/.access/grants` call the module's `mint` and `granted` methods over `internal/modcall`. A document without it keeps the minter in the process, exactly as before. The issuer package no longer imports the minter, and the boundary test's exemption list loses it. The module's side of the transport (a listener and the Lambda event route) is a later change; the console's Cloudflare page still needs the local minter.

- **The Cloudflare module answers other modules' calls (`cloudflare.serve`), so `cloudflare.remote` has a server to reach.** On Kubernetes, `sluis cloudflare` also listens on `cloudflare.serve.address` and serves `POST /rpc` (the `mint` and `granted` methods) to a caller whose projected ServiceAccount token was minted for `cloudflare.serve.audience` (the module's name when unset), checked with a TokenReview; a call without a valid bearer is a 401 and reaches no method. `GET /healthz` answers without a credential. On Lambda, a function whose document sets `cloudflare.serve` is the Cloudflare module's function and answers `{"kind":"rpc"}` events through `lambdacall.Serve`; every other function, the issuer's among them, refuses them. API Gateway events, scheduler ticks and the existing event kinds behave as before. The chart and the Pulumi wiring (a Deployment and Service, a separate function, `lambda:InvokeFunction`) are a later change.

- **The lambda build of `cmd/sluis` is a Lambda entry too.** Started by the Lambda runtime (no arguments, `AWS_LAMBDA_RUNTIME_API` set) it serves API Gateway events and scheduler ticks through the same dispatch as `cmd/sluis-lambda`, now one function, `lambdaapp.Start`, that both mains call. Elsewhere the command line is the entry, and the Kubernetes build has no event dispatch. `cmd/sluis-lambda` remains the released Lambda binary until the release moves; its behaviour is unchanged.

## v1.74.3

v1.74.2 was tagged without its module pins and has no release.

A patch for sluis on Lambda with generated client secrets: a cold start no longer reads one SSM record per generated client. See [survive a cold-start herd](docs/guides/sluis/operate/survive-a-cold-start-herd.md).

### Changed

- **A Lambda start no longer settles the generated clients' secrets.** Every new environment read one SSM record per `secret: {generate: true}` client at start, about twenty calls for an installation with that many, and wrote the ones that were missing. After a deploy all environments start cold at once; SSM throttled them, the init ran past Lambda's 10 seconds (`Runtime.ExitError`) and requests failed for 10 to 60 seconds. The start now reads none of them: the token endpoint reads a client's record when the client first authenticates and reuses it for 30 seconds (a refused secret is read again at most every 5 seconds, so a rotation still propagates), and the scheduled refresh settles the secrets, as it already did. A generated client that has neither a record nor an input secret authenticates after the first refresh (at most 15 minutes after the first deploy); until then it is refused. A server process (Kubernetes) still settles them at start. The configuration read is unchanged: 40 parameters are 4 pages of 10.

## v1.74.1

A patch for sluis on Lambda behind a proxy with many clients: a herd of cold starts no longer fails on a throttled SSM, and telemetry no longer delays a response. See [survive a cold-start herd](docs/guides/sluis/operate/survive-a-cold-start-herd.md).

### Added

- **The Pulumi library: `LambdaArgs.Function.ReservedConcurrency` (`*int`).** The function's reserved concurrency: a ceiling on the environments that run at once. Nil leaves the function unreserved, as before. A ceiling costs nothing, is not provisioned concurrency, and bounds a herd of cold starts. An estate that capped the function by hand sets the cap here, or the next apply removes it. Zero and negative values are refused. See [survive a cold-start herd](docs/guides/sluis/operate/survive-a-cold-start-herd.md).

### Fixed

- **A herd of Lambda cold starts no longer fails on a throttled SSM.** After an outage, clients behind a proxy returned at once; every new environment read its configuration from SSM, SSM answered `ThrottlingException`, the SDK gave up after 3 attempts, and the start failed (`sluis could not start`, a 500 that clients retried). The SSM clients the service reads its configuration and secrets with now make 6 attempts with full-jitter backoff (100 ms doubling to 1 s, at most 3.4 s of delays in all), and one read of the configuration is bounded at 6 seconds, inside a Lambda init's 10. A start also lists nothing any more. It proved the Secrets port answers by listing every stored credential, and it now reads the console's session key, which it needs anyway. It looked for orphaned client secrets by listing every generated client's record, which is now the scheduled pass's alone (the 5-minute tick on a server, the directory refresh on Lambda). A start reads SSM once for the session key and once per page of its configuration. A test counts it against a fake SSM: 5 calls before and 3 after, for 16 parameters, and the listings grew a page per 10 records.
- **A Lambda invocation waits at most one second for telemetry, and only once per backoff.** The flush before an invocation returns had a 3-second deadline, and the OTLP exporter retried a refused export until that deadline. While the telemetry layer had no token (the issuer it exchanges with was saturated) every invocation took 3.0 s more. The exporters no longer retry on Lambda, the flush is bounded at 1 second, and after a failed flush the next ones are skipped for 5 seconds, doubling to 5 minutes, until one succeeds. Telemetry is dropped rather than delay a response.
- **The console's setup step names this installation's recovery password parameter.** *Turn off the recovery password* showed `/sluis/private/config/recovery/password` whatever the instance and secrets layout. It now shows the parameter the running service reads, for example `/sluis/<instance>/internal/config/recovery/password` on layout v4, from the new `GetPolicyResponse.recovery_password_location`.

## v1.74.0

The code of v1.74.0-rc.4, proven on a live installation. The changes since v1.73.0 are in the release candidates' sections below, newest first.

### Added

- **audit: the chart and the binaries are held to each way a preset's credentials are given.** A chart test renders an install with every component for each credential mode (AWS, `credentials`, `credentials_preset`, `credentials_ref` with `archive.sluisDir`, and with `archive.sluisRoot`). It loads each rendered configuration with its binary's own loader and plans the archive of every process that opens one. It also holds the rotated credential's mount to a directory on exactly those processes. A notary before v1.74.0-rc.4 refuses the rendered file with `archive: additional properties 'sluisDir' not allowed`; the test fails the same way should a schema drop the field. The R2 guide says so, and the configuration reference names the processes that take `archive`.

### v1.74.0-rc.4

#### Added

- **audit: `credentials_ref` refuses a document for another endpoint.** At every read, a `cloudflare/v1` document whose `endpoint` is not the preset's (scheme and host compared without case, a trailing slash ignored), or that has none, is refused with an error naming its address and both endpoints. A credential already held from a matching document is kept while it is valid, as for any failed read. `cloudflare.StoredConfig.Endpoint` and `cloudflare.SameEndpoint` in the storage module.
- **audit: read the R2 credentials sluis rotates, `credentials_ref`; audit no longer needs a Cloudflare minter.** A preset of the deployment document at an `endpoint` may name `credentials_ref: external/cloudflare/<preset>`: the `cloudflare/v1` document a sluis installation rotates for one of its R2 presets (ADR 0070). The process reads it below the new `archive.sluisRoot` (the sluis installation's SSM root, with the process's own identity) or `archive.sluisDir` (a directory a secrets operator projected it into), reads it again within a minute and before it expires, and once more after a 403 (one read per 30 seconds); an expired document is refused, naming where it was read. Nothing is minted and no minter is read. Exclusive with `credentials` and `credentials_preset`. The audit Pulumi library takes `PresetStorage.CredentialsRef` and `Args.Sluis{Root, KeyArn}` (required with a `CredentialsRef`, refused without), writes `archive.sluisRoot` into both functions' configuration, and grants the writer and the notary `ssm:GetParameter` on exactly `<Sluis.Root>/external/cloudflare/<preset>` and `kms:Decrypt` on `Sluis.KeyArn` through SSM, and nothing of a minter; `ArchiveCredentialsPaths` names that parameter. The chart mounts the Secret with each component's `secretMounts` and refuses `credentials_ref` without an `endpoint` or beside another source. The shared code is `cloudflare.StoredProvider` in `github.com/truvity/sluis/storage/cloudflare`. `credentials_preset` keeps working, and its docs now say it puts the minter in every process that reads the archive; `credentials_ref` is the mode to prefer. See [put the archive on R2](docs/guides/audit/operate/archive-on-r2.md).

#### Changed

- **`just docs-check` fails on the documentation budget.** `hack/check-docs-budget.py --fail` turns the page word limits, the per-directory ceilings in `hack/docs-budget.tsv`, sentence length and the banned phrases into errors, and the hygiene check fails on retired product names outside its allowlist. A list item (`- `, `* `, `1. `) counts as a sentence of its own, so bullets need no blank line between them. The site was cut by tab to fit: see [docs/WRITING.md](docs/WRITING.md).

#### Fixed

- **The audit writer starts again on an archive written by v1.74.0-rc.1 or older: the common catalogue is 2.2.0.** v1.74.0-rc.2 and rc.3 changed the common catalogue's `data_schema` URLs (to `https://truvity.github.io/sluis/schemas/audit/v1/common/`) without a new version, so their writers refuse an archive written by rc.1 or by audit v0.11.0 to v0.16.0, which holds the original 2.1.0, and exit with `writer: catalogue audit 2.1.0: writer: the archive holds a different catalogue under this version: catalogue/audit/2.1.0 holds 7830 bytes (sha256 c8e31974…) and this writer has 7872 (…)`. The changed document is now **2.2.0**; a writer on this release registers `catalogue/audit/2.2.0` beside 2.1.0, which is untouched, and the old URLs still resolve. No configuration changes. To stop it recurring, the new package `github.com/truvity/sluis/audit/sdk/catalogue/released` holds every catalogue in the repository (audit's `common.yaml`, sluis's `roster.yaml`, and any added later, found by walking the tree) to the exact bytes of each released version in `testdata/released/` beside it: a document that differs from the record of its version, a version without a record, a rewritten or removed record, and a changed `.json` schema beside the document (now pinned in `SHA256SUMS` as `<stem>-<version>/<file>`) each fail the tests of both the root and the audit module. The roster check compared parsed YAML; it now compares bytes, as the installation does.

### v1.74.0-rc.3

#### Fixed

- **The Lambda bootstrap is back to 52 MB (v1.74.0-rc.2: 116 MB), under the 100 MiB deploy/pulumi accepts.** rc.2's `bootstrap` (115,736,736 bytes) was refused by deploy/pulumi (`larger than 104857600 bytes unzipped`), because cloudflare-go's root client links every Cloudflare service. The Cloudflare minter's client (`internal/cloudflare/cfapi`) now makes its five calls (tokens get, create, delete, list, permission groups) over plain `net/http`, and cloudflare-go is no longer a dependency; behaviour is unchanged, except that a token create is retried only when rate limited (a 5xx might have created it). The arm64 bootstrap is 52,494,496 bytes (rc.1: 51,380,384); the `sluis` binary, which links the same client, sheds the SDK too. New recipe `just lambda-size`, part of `build` and so of CI: it builds the bootstrap with the release's flags and fails above an 80 MiB budget, naming deploy/pulumi's limit.
- **deploy/pulumi renders a document with Cloudflare R2 presets.** It refused every `endpoint` in the service document unless `AllowEndpoints` (a LocalStack switch) was set, so an R2 preset's `cloudflare.presets.<name>.endpoint` (ADR 0070), the S3 endpoint handed to clients with the minted credentials, made an installation's Cloudflare section unrenderable. That one path is exempt, like the library's own `ports.blob` endpoint; every other `endpoint` (`secrets.endpoint`, `ports.dynamodb.endpoint`, ...) is still refused without `AllowEndpoints`. The audit library has no such refusal and is unchanged.

### v1.74.0-rc.2

#### Added

- **GitHub Apps with an active webhook (preview).** A catalogue App may declare `webhook:` with a `url` (Argo CD) or a `kargo` receiver (`base`, `receiver`, `project`) and `events`. sluis generates the webhook secret, sets it on GitHub right after the App is created, keeps it beside the App's key (optional `webhook_secret` in `github/v1`), and compares GitHub's hook URL, content type and secret presence in the drift check. `RotateGitHubAppWebhook` rotates it without overlap: it keeps the new secret, waits for the new target to accept a signed ping, then tells GitHub the secret (and a Kargo receiver's derived URL) in one call, restoring the previous secret on failure. New audit action `roster.catalogue_app.webhook_changed` (catalogue 1.13.0). Off unless an App declares `webhook:`; not yet verified against real GitHub; no console button yet; existing Apps must be disconnected and recreated to get an active webhook. See [Delivering events](docs/guides/sluis/connect/github-apps-catalogue.md#delivering-events).
- **Release supply chain: SBOMs, keyless signatures and attestations.** Every archive (the Lambda zips, the binaries, the two bundles) gets an SPDX SBOM from syft (`sboms:` in both goreleaser configs; audit's ko-built SBOM tag is off, so the two configs agree). A new `attest` job of the release workflow signs the combined `checksums.txt` (sluis and audit lines) with keyless cosign, publishes `checksums.txt.sigstore.json`, and attests the build provenance of every release asset; `attest-sboms` binds each SBOM to its archive, and `attest-oci` signs every pushed image and Helm chart by digest and attaches provenance (and, for images, SBOM) attestations in the registry, from one list, `hack/release-images.txt`. Keyless certificates and signatures are recorded in Sigstore's public transparency log. `just release-verify VERSION` (`hack/release-verify.sh`) checks the checksums, the cosign bundle and `gh attestation verify` for each asset and image; `just release-lint` (in `check` and `release-check`) runs `goreleaser check` on both configs, `actionlint`, and a test that verification fails on a tampered asset. devbox gains `cosign`, `syft` and `actionlint`. See [Verify a release](docs/guides/sluis/operate/verify-a-release.md).
- **The Pulumi library: adopt an existing archive bucket and leave its lifecycle alone, `PresetStorage.Adopt`.** A preset with `Create` owns its bucket and derives a lifecycle from the profiles' retention (an expiration, a noncurrent-version expiration, no Deep Archive step before it); without `Create` the bucket is outside Pulumi. `Adopt: true` imports an existing bucket by name (`Protect`, `RetainOnDelete`) and manages its versioning, default encryption, public-access block, ownership controls and bucket policy (the TLS-only deny, replacing the bucket's policy as a whole), and declares **no lifecycle resource**, so an estate whose archive must never expire keeps its own rules (none that expire). Object Lock is not touched. Refused with `Create`, with `Endpoint` and for a bucket another preset names. Because the library cannot read the lifecycle it leaves alone, `Adopt` is refused when a profile kept in the preset has a fixed minimum retention unless `AcknowledgeLifecycle: true` states that the estate's lifecycle and lock keep objects that long. The `Create` path is unchanged. See [the library reference](docs/reference/audit/aws-pulumi-library.md#lifecycle).
- **audit: `credentials_preset` mints a preset store's R2 credentials for the process (stacked on the Cloudflare core).** A preset of the deployment document whose store is at an `endpoint` may name `credentials_preset: {account, minter, prototype, lifetime}` instead of the static `credentials` (exclusive with it; the static path stays the default and needs no Cloudflare account). The process reads the `cloudflare-minter/v1` document at `minter` in the state store, clones the disabled prototype with it, renews with a third of the lifetime left and records the ids it minted so the expired tokens are deleted. A 403 from the store is sent once more after new credentials are minted (once per request, one mint per 30 seconds: `s3store.Options.Reauth`). The audit Pulumi library (`PresetStorage.CredentialsPreset`) grants the writer and the notary read on exactly the minter address and read and write on exactly `cloudflare-minted/<preset>` below the state root, only for a preset that uses it. The shared code is the new package `github.com/truvity/sluis/storage/cloudflare` of the storage module (the one module both the root and audit import): the token shapes, the naming, the prototype checks and the built-in refusal list, R2's secret derivation, a stdlib HTTP client for the account and `Provider`, an `aws.CredentialsProvider`. The root module's `internal/cloudflare` re-exports it, so the refusal list exists once.
- **sluis as the STS for Cloudflare tokens and R2 credentials (core).** A `cloudflare` section of the service document (`accounts` with a minter at `internal/cloudflare/<account>/minter`, `presets` with a disabled prototype token, `lifetime`, `rotation` and, for R2, `endpoint`) and `cloudflare.grants` in the policy document (a `group`, which for a CI job is a group declared with `github` matchers, with `presets`). `internal/cloudflare/minter` clones the prototype's policies and condition into an account token that expires, on a schedule (a loop in a cluster, `{"kind":"cloudflare"}` on Lambda) writing `external/cloudflare/<preset>` (`cloudflare/v1`, R2 as access key and the SHA-256 of the value), and on demand for a granted caller. A prototype that is active, missing, or grants token admin, billing, account settings, memberships or Access identity providers is refused at every mint and when a cluster service starts (an audit event, a log line and the counter `sluis.cloudflare.prototype.refused`); the built-in list cannot be shortened, `cloudflare.forbiddenPermissionGroups` only adds to it. The minter can mint anything the account owner can, so its custody is the owner's. The sweep deletes by the ids it recorded, not by listing. New audit actions `roster.cloudflare.token.minted|refused`, `roster.cloudflare.tokens.swept`, `roster.cloudflare.token.revoked` (catalogue 1.12.0), the alert `AccessRosterCloudflareRotationStale` and the `sluis.cloudflare.*` metrics. `ports.blob.s3.credentials: {preset}` lets the blob adapter mint its own R2 credentials, exclusive with `credentialsRef`, which stays the default and needs no `cloudflare` section. The on-demand exchange, `sluisctl cloudflare` and the console follow. See [mint short-lived Cloudflare tokens and R2 credentials](docs/guides/sluis/cloudflare-tokens.md).
- **The console's Cloudflare page.** A **Cloudflare** entry under Systems where the service document has a `cloudflare` section (`whoami` says `cloudflare: true`). Anyone signed in sees the presets the policy grants their groups and can **Get a token** or **Get credentials** (R2), shown once and held only in the dialog, with the `sluisctl` and AWS `credential_process` hints. A viewer sees the accounts (ids by their last four characters), each preset's lifetime and rotation, its prototype as read live (disabled, ACTIVE, forbidden permission or missing, with the reason), the stored token's id, mint time and expiry with a warning past one rotation and an error past two, and the on-demand tokens still live. An operator can **Rotate now** and **Revoke** a live token, each behind a confirmation and recorded under their name. New `CloudflareService` in `proto/directoryroster/v1/cloudflare.proto` (`ListCloudflare`, `RotateCloudflarePreset`, `RevokeCloudflareToken`, `ListMyCloudflarePresets`, `GetCloudflareCredential`); no response but the last carries a token's value. The minter gains `Accounts`, `CheckPreset`, `Stored` and `RotateNow`, and `Live` names the caller and mint time. On-demand minting calls the minter directly until the token exchange lands. See [the console](docs/concepts/sluis/console.md).
- **Cloudflare credentials on demand: the exchange and `sluisctl cloudflare`.** `/token` serves RFC 8693 with `requested_token_type=urn:access-roster:params:oauth:token-type:cloudflare-token` and `audience=cloudflare:<preset>` (optional `lifetime` in seconds, at most the preset's): a person's sign-in or a CI job's GitHub token is verified by the chain every exchange uses, the policy's `cloudflare.grants` decide (a CI job is a group declared with `github` matchers, evaluated like every other group), and the minter clones the prototype into a token named for the caller. The answer carries `token`, or for an R2 preset `access_key_id`, `secret_access_key` and `endpoint`, with `expires_on`; an unknown preset and one not granted are the same `invalid_target`. `/.access/grants` also lists the granted presets. `sluisctl cloudflare token <preset> [--format env|json]` prints `CLOUDFLARE_API_TOKEN=...` or JSON; `sluisctl cloudflare r2 <preset>` prints an AWS `credential_process` answer; both cache under the config directory (0600) and renew with a third of the lifetime left, and `--file` reads the `cloudflare/v1` document a secrets operator projected, with no sign-in. `sluisctl aws-config` writes an R2 profile per granted preset (`endpoint_url`, `region = auto`, `when_required` checksums, path-style addressing) and `whoami` lists the presets. See [mint short-lived Cloudflare tokens and R2 credentials](docs/guides/sluis/cloudflare-tokens.md).
- **The Pulumi library: the Cloudflare rotation schedule and the grants it needs (stacked on the Cloudflare core).** `Installation.Cloudflare` (accounts, presets and grants, `github.com/truvity/sluis/config`) renders into the service document's `cloudflare` and the policy document's `cloudflare.grants`, and a grant for a preset nobody declared is refused. When an installation declares presets, `NewLambda` adds an EventBridge schedule invoking the function with `{"kind":"cloudflare"}` (`LambdaArgs.CloudflareRotation`, default `rate(1 minute)`, `Disabled` and `Paused` as for the directory refresh), and the function's role reads `internal/cloudflare/*` (the minter credentials, never written), reads and writes `internal/cloudflare-minted/*` (the record of minted ids) and writes `external/cloudflare/*` (the stored credentials), with the secrets key used through SSM for the same parameters. `KubernetesIdentityArgs.Cloudflare` gives a pod the same. Without presets nothing is added. No AWS grant is needed for the Cloudflare API itself.
- **The Pulumi libraries publish function versions and route every caller through the alias `live`.** The sluis function and audit's writer and notary publish a version on each change; the HTTP API integration and its (qualified) invoke permission, the schedules' targets, the scheduler role's invoke grant (the alias ARN, not `:*`), the function's own invoke grant, audit's writer event source and notary schedule all use the alias, and asynchronous-invoke configuration is set on it. The `invoke` trigger names `<function>:live`: **`sluisctl render` of the Lambda shape now writes `adapters.trigger.settings` as `<function>:live`**. The API, its stage and the domain mapping are not replaced. New outputs `LiveAliasArn`, `LiveVersion` (sluis) and `WriterLiveAliasArn`, `NotaryLiveAliasArn`, `WriterLiveVersion`, `NotaryLiveVersion` (audit).
- **The Pulumi libraries ship code through an artifacts bucket: `Artifacts`, `Release`, `CodeSha256Matches`.** `LambdaArgs.Artifacts` (and the audit library's `Args.Artifacts`) uploads the verified release zip as it is, and the configuration layer as a deterministic zip, to the estate's versioned bucket at `<prefix><version>/<sha256>-<name>`; the function and the layer are created from the object version with `SourceCodeHash`. An unversioned bucket is refused at apply. Unset, the code is uploaded with the function as before. `Release.ResolveChecksums` reads an empty digest from the release's `checksums.txt`; with no `Package` the library deploys its own release (its module version from the build information, or `Release.Version`), digest from `checksums.txt` unless one is pinned (a pinned digest always wins); a development build, a pseudo-version or a replaced module is refused. Downloads are cached by SHA-256 and use `GITHUB_TOKEN` for github.com. New outputs `CodeSha256Matches` (and `WriterCodeSha256Matches`, `NotaryCodeSha256Matches`). `LambdaArgs.Audit.WriterPackage` and its digest may be left empty. The shared code is the new package `github.com/truvity/sluis/audit/deploy/pulumi/artifact`. See [Deploy from a mirrored release](docs/guides/sluis/operate/deploy-from-a-mirrored-release.md).
- **audit: a stalled indexer is visible.** `audit-observe`'s `/readyz` also fails (check `passes`; `/healthz` is untouched, so the pod is not restarted into a crash loop) once `readiness.failedPasses` passes in a row failed (default 3) or no pass succeeded for `readiness.staleIntervals` intervals (default 3). New series `audit_observe_passes_total{outcome}` and `audit_observe_pass_since_success_seconds`, and chart alerts `AuditIndexStalled` (no successful pass for 15m, `alerts.rules.indexStalled.maxAgeSeconds`, to be kept at three polls) and `AuditIndexPassesFailing` (over half of the passes in 30m, at least 3), unit-tested. A failing pass is logged with the object and the reason once for each distinct error and again only every half hour, as is an object that was not indexed. A release check holds the newest released catalogue of each source to the reader's validator. The incident behind it: a writer on v1.74.0-rc.1 registered a catalogue with `category` and no `profiles`, an older indexer rejected it every pass, the pod stayed Ready and nothing alerted.

#### Changed

- **Breaking (audit): readers must run the writer's release or a newer one; v1.74.0 changes the catalogue shape.** The roster catalogue 1.11.0 declares `category` on an action and no `profiles`, which the `catalogue.schema.json` of earlier releases requires, so an older `audit-observe` or `audit-query` refuses it and the index stalls behind its cursor. Upgrade the readers first and the writer last: [upgrade audit to v1.74](docs/guides/audit/upgrade/v1.74.md).
- **audit: the default poll of `audit-observe` is 5 minutes (was 30 seconds).** `interval` (config schema, chart values and the [configuration reference](docs/reference/audit/configuration-observe-query.md)) is the bound on a lost wake-up; without a `wake` (SQS or NATS) a record is searchable after the longer of `settle` and the time to the next pass, at worst `interval`; with a wake the woken pass reschedules for when the object is old enough, so the delay is about `settle` whatever `interval` is. Set `interval` back if five minutes is too slow. The schema default and `observe.DefaultInterval` are held equal by a test. It also stops a failing pass from re-reading the archive twice a minute.
- **Log attribute keys are `snake_case` throughout, and a few were renamed.** `sloglint` now enforces typed attributes, constant messages and `snake_case` keys, so these keys changed: `configMap` to `config_map`, `serviceAccount` to `service_account`, `signIn` to `sign_in`, `inCluster` to `in_cluster`, `seenAt` and `activateAt` to `seen_at` and `activate_at`, `rotateEvery`, `tokenLifetime`, `refreshLifetime`, `holdWindow`, `exchangeAudience`, `sessionKeySecret` and `oauthClientSecret` likewise, `apiVersion` to `api_version` in the audit writer's deployment warnings, and `source` (a reserved key) to `event_source` / `principal_source`. Three messages that carried a variable part now have a constant message and the variable part as an attribute (`warning`, `why`, `reason`, `what`). The audit log line's dotted `audit.*` keys are a documented contract and are unchanged. Anything that matches these keys in a log query or alert needs the new spelling.
- **Sign-in and authorization log lines name a pseudonymous `subject`, not the address.** "authorization refused", "sign-in refused", "sign-in could not be resolved" and the sign-in success lines logged `email`; they now log `subject`: the first 8 bytes of an HMAC-SHA256 of the principal's stable subject (or of the address where there is none) under a per-process random key (the same person correlates within one process only). The audit trail still carries the real identity. Log messages are lowercased (`sloglint` `msg-style`), so six messages changed spelling.
- **`storage/logattr` replaces `internal/logsafe`:** `SafeString`, `SafeStrings` and `SafeError` build log attributes for untrusted values (line breaks, control and bidirectional-control characters removed, length capped), and are used at more sites.
- **Breaking (audit): `@truvity/audit/react` is the package `@truvity/audit-react` (ADR 0042 §10).** The hooks (`AuditProvider`, `useSearch`, `useTail`, `useAccess`, `useFacets`, `useRecord`, `useAudit`) and the default MUI `AuditView` move out of `@truvity/audit`, whose `./react` export and optional `react` and `@mui/material` peer dependencies are gone: it is now a framework-free query client. `@truvity/audit-react` (sources in `audit/react/`) depends on `@truvity/audit` at exactly the same version, has `react` (>=19), `@mui/material` (>=7), `@bufbuild/protobuf` and `@connectrpc/connect` as peer dependencies, and is published to GitHub Packages with the other two TypeScript packages at each release tag's version. Replace `import { AuditProvider, AuditView } from "@truvity/audit/react"` with `from "@truvity/audit-react"` and add the package. The console installs `@truvity/audit` and `@truvity/audit-react` from the checkout instead of the `truvity/audit` v0.6.1 git dependency, and `just deps` builds the three TypeScript packages before installing it.

#### Deprecated

- **The legacy store and Valkey** (`ports.adapter: legacy`, the default, which keeps state in the namespace's ConfigMaps and Secrets, and the `valkey` section) are deprecated in v1.74.0 and removed in v1.75, with the module split. Behaviour is unchanged; the service logs one warning at start when it opens the legacy adapter or `valkey` is set, and the schema, the chart values and the docs say so. Move off it with `sluis migrate` (see [migrate the secrets layout](docs/guides/sluis/upgrade/v1.74.md) and [migrate the State](docs/guides/sluis/migrate/migrate-state.md)).
- **`sluisctl r2`** (the wrapper that runs `r2broker`) prints a deprecation notice and goes with the broker: use `sluisctl cloudflare r2 <preset>`, which needs no broker.

### v1.74.0-rc.1

#### Added

- **Blobs on an S3-compatible store: `ports.blob.s3.credentialsRef`.** With `endpoint` set, the S3 Blob adapter signs with static credentials read from the installation's secrets store at an `internal/<kind>/<id>` address (layout v4 or transition) instead of the SDK's default chain: a small versioned document, `s3-credentials/v1` (`access_key_id`, `secret_access_key`; JSON Schema under `schemas/internal/`). They are read at start and again after a 403, at most once a minute, and never logged. `region` defaults to `auto` with a `credentialsRef`; any address that is not `internal/<kind>/<id>`, or a `credentialsRef` without `endpoint`, is refused at load. The Pulumi library no longer strips `credentialsRef` before its loader check. See [Keep the blobs on an S3-compatible store](docs/guides/sluis/operate/blobs-on-r2.md).
- **The Pulumi library: blobs on an S3-compatible endpoint (R2), `StorageArgs.Blobs`.** `ExternalBlobs{Bucket, Endpoint, Region, PathStyle, Prefix, CredentialsRef}` replaces the bucket: the library creates none and grants no S3 IAM, writes `ports.blob` into the service document, and grants the function's role (and the Kubernetes identity's) `ssm:GetParameter` on the one parameter the `internal/<kind>/<id>` address `CredentialsRef` names. No credential is an input, so none is in the Pulumi state. Exactly one of `BucketName` and `Blobs`. Pair it with the edge's `TruststoreBucket` for the truststore. `Storage.Grant()` carries the external store.
- **The Pulumi library: keys the estate supplies, `LambdaArgs.Keys`.** `KeysArgs{Sign, Secrets, LegacySigningContext}` names symmetric keys by alias; the library creates none, resolves each alias with `aws.kms.LookupAlias` and grants `kms:Encrypt`/`Decrypt`/`GenerateDataKey` on the key behind `Sign` under the runtime's context `{instance, purpose: sign}`, never `kms:Sign`. `Secrets` is the SSM store's key: written as `secrets.kmsKeyId`, granted through SSM only for the installation's parameters (`kms:ViaService`, `PARAMETER_ARN`), and exclusive with `ParameterKeyArn`. The older `{purpose: sluis-signing}` grant stays by default (`LegacySigningContext`), until the ring has rotated past the old entries. The service document gets `instance` and the `keys:` block. `instance` and `keys` are held to the service-document schema; `ports.blob.s3.credentialsRef` is written for a runtime whose schema carries it, and is held to that schema with the rest of the document.
- **The Pulumi library: reader policies for exact `external/` addresses.** `ExternalReadPolicy` returns the IAM document (`ssm:GetParameter` on those parameters, `kms:Decrypt` on the secrets key through SSM for exactly those parameters, no wildcard), and `NewExternalReader` attaches it to a role.
- **The Pulumi library installs audit by default: `LambdaArgs.Audit`.** With an `Installation`, `Audit` decides where the service's audit records go. Unset (or set without `Use`), the library calls the audit Pulumi library of this repository (`github.com/truvity/sluis/audit/deploy/pulumi`, the same release) beside the function: the `operational` preset derived from `Profiles` (default `security: [history]`; `Preset` may name a stronger one), an archive of its own (an AWS S3 bucket named `<name>-<account>-<region>`, SSE-S3 without an archive key; or an S3-compatible store with `Archive.Endpoint`, or `Archive.ReuseBlobStore` to take the endpoint from `StorageArgs.Blobs` while keeping a bucket and credentials of its own), the function's role as the one sender its ingest queue accepts, the function granted `sqs:SendMessage` on exactly that queue, and `aws.auditQueueURL` written into the service document. `Audit.Use{QueueURL, QueueArn}` sends the records to an installation that exists and installs nothing; `Audit.Enabled: false` installs and grants nothing and writes the `log` audit adapter (the runtime validates each record and logs it, and keeps it nowhere else). The roster catalogue stays delivered with the audit writer's package: `Audit.CatalogueDir` is the unpacked `sluis-audit-catalogue` bundle, shipped in the writer's configuration layer, and an install without it, the writer's zip or its digest is refused before anything is created. New outputs `Audit`, `AuditQueueURL` and `AuditQueueArn`. `deploy/pulumi/go.mod` (and the Cloudflare edge module's) gain a require on `github.com/truvity/sluis/audit/deploy/pulumi` at `v0.0.0` with `replace` directives for it, `audit` and `audit/sdk`, which the release pin script (`hack/pin-pulumi-require.sh`) pins to the release.
- **`storage/keys`: erase a tenant, `Key.Destroy`; `audit key destroy` works on the port.** `Key.Destroy(ctx, tenant)` removes the per-tenant secret behind `MAC` and leaves a tombstone, so `MAC` for that tenant then returns `keys.ErrDestroyed` instead of minting a new secret (a second, unrelated pseudonym for the same person); it is idempotent, touches no other tenant, and `Key.Destroyed` reports it. The optional backend capability is `DestroyBackend`. On `kms` the wrapped key is deleted from the state store with all its versions behind a tombstone written first (`kms.ErasableStore`, which `kms.FromState` gives; another replica stops within `kms.DefaultMACKeyTTL`, a minute). `local` remembers it in memory (tests). **`transit` does not erase** and returns `ErrUnsupported`: its pseudonym key is one transit key for the installation, and a key per tenant would need create and delete rights the writer's policy deliberately lacks; put `pseudonym` on `kms`. The keys conformance suite checks destroy, idempotence and isolation of other tenants. audit: `PortProvider.Destroy` calls it, `Pseudonym`, `Seal` and `Open` return `ErrDestroyed` afterwards, and `audit key destroy --writer-config <writer.yaml>` opens the keys the writer does. Sealed identifiers are refused, not shredded (one conceal key for the installation). See [erase a tenant's keys](docs/guides/audit/operate/erase-a-tenants-keys.md).
- **The Pulumi library's custom domain is split out into an edge module: `github.com/truvity/sluis/deploy/pulumi/edge/cloudflare`.** A module of its own (package `edgecloudflare`), so the core never depends on a front door: `NewEdge` builds the regional API Gateway custom domain with mutual TLS, its mapping to the API, the truststore and, if asked, the ACM certificate. The truststore is ONE versioned object, `truststore/client-ca.pem`, in the installation's blob bucket, which the domain pins by version; the bucket policy denies every write, delete and re-label under `truststore/` to every principal except the apply identities you name (the CD role, the operators' admin role, a break-glass role), so the functions, which write the rest of that bucket, cannot replace the client CA. `Args.CertificateArn` takes a certificate the caller supplies; `Args.Certificate` requests one with DNS validation through a callback that creates the record in the estate's own DNS, so the edge holds no DNS credential and imports no Cloudflare provider. For blobs on an S3-compatible store (R2), API Gateway cannot read a truststore from the blob store: `Args.TruststoreBucket` makes the edge create a small S3 bucket of its own for it, with the same guard. Authenticated Origin Pulls remains the estate's zone setting. `edge/aws` is a later module. The release workflow tags the edge at the same version as the core.
- **Core: `Lambda.FrontDoor()`, `Lambda.APIStageName`, and `StorageArgs.ProtectedPrefixes`.** `FrontDoor` is what an edge module takes (the API id, its stage, the component's name for aliases). `ProtectedPrefixes` is a bucket-policy Deny on writes under a key prefix for every principal but the listed ones, in the bucket's one policy; `Storage` now reports `Versioned` and `ProtectedPrefixes`.
- **audit: the audit trail component moves into this repository, under `audit/`.** A snapshot of truvity/audit at v0.16.0, without its history. It stays independently usable: its own Go modules (`github.com/truvity/sluis/audit`, `.../audit/sdk`, `.../audit/deploy/pulumi`; the SDK is wired to the root with `v0.0.0` and a `replace` until a release pins it), the Pulumi library, the SDKs, the documentation (`docs/audit/`, its old changelog is `audit/CHANGELOG.md`), the images (`ghcr.io/truvity/audit/*`, names unchanged) and the Helm chart, now `charts/audit`. audit never imports sluis: a depguard rule and `audit/internal/independence` hold that. Its recipes are `just audit-*`, its toolchain is the root `devbox.json` (plus nodejs, openssl and postgresql), its CI jobs run in `ci.yaml` and are skipped on a pull request that touches nothing audit covers, and the leak canary now scans `audit/` too. The module path changes from `github.com/truvity/audit` to `github.com/truvity/sluis/audit`, so an importer rewrites its imports when it moves. Releases of audit from this repository, and archiving truvity/audit, follow separately.
- **`keys.sign`: the wrapped signing ring wraps its keys under a key asked for by purpose.** The service document gains `keys` (`adapter: kms`, `sign: alias/...`, the shared block of `storage/keys`, by alias only; the long form `{key, context}` is accepted) and `instance`, which the default encryption context `{instance, purpose: sign}` binds. New ring entries are generated here, wrapped under it and record the context they were made under; entries written by earlier releases carry no record and are opened with `{purpose: sluis-signing, alg, kid}`, without being re-wrapped. The installation document takes `keys` too and, with `signingKey.kmsWrapped` and no `keys`, defaults to `alias/sluis-<instance>-sign`.
- **audit: the archive on an S3-compatible store (Cloudflare R2), and keys by purpose through the storage port.** `archive.bucket.endpoint` already addressed a store that is not AWS; now the region defaults to `auto`, **Object Lock is refused on an endpoint** (`lockMode: none` only; the lock is an AWS S3 guarantee another store does not make), and `archive.credentials: {root, address}` reads the store's static credentials, a JSON object `{accessKeyID, secretAccessKey}`, from the installation's `internal/` address of its state store (SSM through `storage/state`), so no secret is in the file or in the stack's state. The precomputed SHA-256 checksum for compressed writes (R2 refuses an SDK-chosen checksum with a `Content-Encoding`) is kept and now has a wire-level test against the real SDK client. The `keys:` block takes the storage port's shape (`adapter: kms|transit|local`, then `seal`, `pseudonym`, `conceal`, `archive`, aliases only, `state` for the kms pseudonym secrets); the notary takes `keys.seal` in place of `signer` (exactly one). `audit/keys` gains `PortProvider` and `PortSigner` over the port, and `Local`, `Transit`, `TransitSigner` and `KMSSigner` are marked `Deprecated:` (kept: they take an ARN or P-256 key). The Pulumi library **creates no key**: `Keys{Archive, Seal, Pseudonym, Conceal, Instance}` name the estate's keys by alias, resolved with `kms.LookupAlias`; the writer's grants on the pseudonym and conceal keys are conditioned on the encryption context the storage KMS backend sends; `SealKeyPolicy` is the seal key's policy for the estate to apply; pseudonym keys are accepted only at the attested preset or for a profile that pseudonymises. New `Archive.Endpoint`, `StoreRegion`, `PathStyle`, `CredentialsAddress`, `State{Root, KeyArn}` and the output `ArchiveCredentialsPath`; with an endpoint the library creates no bucket and the roles get no S3 or archive-key statement. `audit` now imports the `storage` module (the one exception to "audit never imports sluis"; it imports nothing of sluis). See [archive on R2](docs/guides/audit/operate/archive-on-r2.md).

#### Deprecated

- **`LambdaArgs.AuditQueueArn`** (an audit installation the estate installed itself, its queue URL written in the installation) keeps working, unchanged, and is the only way with the deprecated `Config`. Set `Audit` instead; with `Installation` an unset `AuditQueueArn` no longer errors, it installs audit.
- **`LambdaArgs.SigningKeyAlias`, `SigningKeyRS256Alias`, `DisableSigningKeyRS256` and `WrappedSigning`** (the keys the library creates) are accepted for one more release with a warning, unchanged (no diff), and removed after it. Supply the keys with `Keys`; it is exclusive with them.
- **`sluis migrate` into a destination on `secrets.layout: v3`** is accepted for one release, with a warning; write layout v4.
- **`LambdaArgs.API.DomainName`, `CertificateArn`, `TruststorePEM` and `TruststoreBucketName`, and the outputs `DomainTarget`, `DomainHostedZoneID`, `TruststoreBucketName` and `TruststoreURI`.** They are accepted for one release, all four together or none, and while set `NewLambda` still builds the domain and its truststore bucket exactly as before (same resources, same names, no diff) and logs a warning. Unset, `NewLambda` builds the API alone, with no domain, no certificate and no truststore, and the outputs are empty. `API.KeepDefaultEndpoint` stays: it is the API's. An existing stack moves to the edge module without replacing the custom domain (the edge's domain and mapping are aliased to the core's): [the steps](docs/guides/sluis/migrate/cutover.md#moving-a-stack-from-the-core-librarys-domain-to-the-edge-module), including `pulumi state unprotect` of the old truststore bucket, which was protected.
- **`signingKey.kmsWrapped.keyId`** is replaced by `keys.sign`. An alias is mapped onto it with a warning for this release; an ARN or a key id is refused. It is no longer required.
- **`signingKey.kms` (direct asymmetric KMS signing)** logs a warning at start. Move to the wrapped ring and keep the old public keys under `signingKey.verifyOnly` for the overlap (docs/concepts/sluis/signing-on-aws.md).

#### Changed

- **Breaking (audit): compliance "presets" are framework profiles.** `audit/presets/` is `audit/profiles/`, the Go package `preset` is `profile` (`preset.Preset` is `profile.Framework`), the meta-schema `preset.schema.json` is `profile.schema.json`, and in the deployment document the key under each profile that lists its framework profiles is `frameworks:`, not `presets:` (`profiles: {security: {frameworks: [security]}}`). A document that still says `presets:` is refused with a message that names `profiles:`; chart values, the Pulumi `DeploymentYAML` and the `audit validate --presets` flag (now `--profiles`) follow. The record the writer keeps of a composition names its framework profile versions under `frameworks`, so the first start after an upgrade records one `audit.preset.changed` for each framework profile in use. The event `audit.preset.changed` and its target type keep their names: a catalogue's action names are archived. "Preset" is reserved for install presets (and the grant presets of the query service, which are another thing). `which-profiles-to-compose.md` now matches the files: `security` and `billing-nl` run with `object_lock_mode: none`.
- **Breaking: the exports are retired (ADR 0041).** The exports controller, `ports.export` (the `Export` port and its OpenBao adapter), the policy document's `exports` section, the Lambda `{"kind":"exports"}` event and its schedule, the `access_roster.export.*` metrics, the `AccessRosterExportFailing` and `AccessRosterExportStale` alerts (`alerts.rules.exportFailing`, `exportStale`), the dashboard's exports row and the recovery bundles' copies are gone. A document that still names `exports` or `ports.export` is refused at load, with a message pointing to `<root>/external/<kind>/<id>`: a consumer reads the typed document there, with its own grant. The public `config` package loses `Export` and `Installation.Exports`; the Pulumi library loses `LambdaArgs.Exports` (`ExportsArgs`, `DefaultExportsSchedule`), the `<prefix>-exports` schedule, the `export/*` grants of the function's role and `ExportReadPolicy` with its `ExportReadPolicyJSON` output, and gains the function role's grants on `internal/` and `external/` (with `ssm:GetParameterHistory`). An instance may not be named `internal` or `external`. The chart keeps `exports.openbao.caBundle` and `.token.audience`, which mount the `openbao` secrets adapter's CA and token. Layout v3's `export/` parameters are not written any more; `sluis migrate secrets-layout` reads and deletes them.
- **Layout v4 types and contract (`internal/secretstore`), first part of the move.** `Internal` and `External` over `state.Store` with a typed `state.Value` per address, the three external documents (`oidc/v1`, `github/v1`, `slack/v1`) with JSON Schemas under `schemas/external/` and golden tests, and `secrets.layout: v3 | transition | v4` in the `ssm` secrets source (default `v3`; nothing reads it yet, so no behaviour changes). A catalogue GitHub App id may no longer begin `runner-`, which names a runner App's document. The root module now requires the `storage` module. See ADR 0041 (the secret contract).
- **Layout v4: the callers move (`secrets.layout: transition | v4`).** The Secrets port is mapped to `internal/` and `external/` (`internal/secretstore`), the SSM secrets source reads `<root>/internal/config/`, and the Apps' exported credentials are `github/v1` and `slack/v1` documents with ids from the App's record. A generated or operator-seeded client secret is the `oidc/v1` document, rotated with one write; the token check accepts the current or the previous secret (`secrets.grace`, default 24h) and reads the pair fresh once before it refuses. A catalogue GitHub App gains `export` in the policy. `transition` writes v3 and v4 and reads v4 first. The default stays `v3`; the exports controller still runs.
- **Breaking (audit): install presets, derived from the profiles.** `operational` (writer, archive, deduplication, intake; no notary, seal key, Object Lock or pseudonym keys; alarms off), `standard` (adds the notary, its seal key and the alarms) and `attested` (adds compliance Object Lock and the pseudonym keys). Every framework profile file states `min_preset` (required by `profile.schema.json`), and the preset is the highest of them over the profiles an installation composes, `operational` when nothing is chosen. The deployment document, the chart (`preset`) and the Pulumi library (`Args.Preset`) may name a stronger one; a weaker one is refused naming the profile that needs more (`profile.Deployment.ResolvePreset`, applied wherever the deployment is composed). The Pulumi library creates no notary, seal key, schedule or alarm under `operational` and refuses `Notary.Package` or `Alerts.EndpointURL` there, `Archive.ObjectLockMode` defaults to what the preset says (compliance for `attested`, which refuses a weaker mode; `NONE` below it) instead of being required, `Writer.DeploymentYAML` is parsed and its profiles must be shipped framework profiles, an installation with no writer here sets `Preset` itself, and the component exports `Preset`. The chart's `profiles` default is empty, which renders one `history` profile and is `operational` (audit for yourself): an estate that needs the notary or a framework's controls names its profiles (`security: {frameworks: [security]}`), and the chart no longer refuses an empty `profiles`. It refuses `jobs.notary.enabled` under `operational`, and `renders: alerts` too (the alert rules are the standard preset's: give that release `preset: standard` or the write path's profiles); its billing check now reads `frameworks`.
- **Layout v4: `sluis migrate secrets-layout --to v4` and `--delete-v3`.** The first copies every v3 item to its v4 address (`internal/...`, and the `oidc/v1`, `github/v1` and `slack/v1` documents at `external/<kind>/<id>`), reads each back and compares; it is idempotent and resumable, a differing document at an address is a refusal naming both revisions, and `--dry-run` prints addresses and never a value. The second removes the v3 items as a later step and refuses unless `secrets.layout` is `v4` and every item has its v4 address. `sluis migrate` from the legacy in-cluster store writes straight into v4 when the destination says `secrets.layout: v4`, under its key alias; a ring is copied as it is with each entry's wrap context. [The steps](docs/guides/sluis/upgrade/v1.74.md).
- **Breaking (audit): destinations as prefixes, routed by category.** Each profile of the deployment document is a destination of the one archive bucket: `categories` (the action categories it takes), `key_alias` and an optional `preset`. A catalogue declares a `category` per action, `profiles` on an action is deprecated (and no longer required when a category is given), and the writer stores a projection of the one record per destination that takes its category; a category nobody takes is reported once. `catalogue.MissingCategories` takes the destination's categories. Object Lock is the writer's only for a destination whose preset is attested, on S3 only: an attested destination on an S3-compatible endpoint or an archive with no lock is refused at start, and a destination below attested writes objects it can clear even in a locked bucket (a governance trial of the lock now means `preset: attested` on the destination). The Pulumi library takes the destinations from `Writer.DeploymentYAML` (`Archive.Profiles` is optional), writes a lifecycle rule per prefix that expires its objects when a fixed retention ends (Glacier steps only before it), and looks up the key behind each destination's `key_alias` (the estate supplies it; the library creates no key) and grants it to every role that reads or writes the archive, conditioned on the storage backend's encryption context (the lookup is the one the `Keys` aliases use); on an archive at an S3-compatible endpoint, where the library creates no bucket or lifecycle and `Keys.Archive` is refused, a destination's `key_alias` is refused too, and the per-prefix lifecycle applies only to the bucket the library creates. The library refuses `Archive.ObjectLockMode` other than `NONE` on an archive with no attested destination, and anything but `COMPLIANCE` on one that has one (unset is compliance), which supersedes the install-presets entry's allowance of a stricter lock below attested and of governance at attested. The sluis roster catalogue does not declare categories yet: the root module still builds against the published audit SDK, which does not know the field.
- **Breaking (audit): storage is configured per install preset ([ADR 0068](docs/decisions/0068-storage-is-configured-per-preset.md)).** An installation names the presets it uses under `presets:` in the deployment document, and each preset has a store of its own: `bucket`, `prefix`, `region`, `endpoint` (empty is AWS S3, set is an S3-compatible store such as R2), `path_style`, `credentials` (the address of an endpoint's static credentials below the process's `archive.stateRoot`) and `key_alias` (AWS only). A profile's preset (the highest `min_preset` of its framework profiles, or a stronger `preset` it asks for) must be configured, or the document is refused naming both; its records, seals and compositions are stored in that preset's bucket. Object Lock is a property of the preset's bucket: compliance for `attested`, on S3 only (an `attested` preset with an `endpoint` is refused), none for every other. The notary, seal key, alarms and pseudonym keys turn on when any configured preset needs them. Removed: the deployment's installation-wide `preset:` and `profiles.<name>.key_alias`, the process configuration's `archive.bucket`, `prefix`, `lockMode`, `kmsKey`'s role as the only key and `credentials` (the `archive` block is now `{stateRoot, ca, kmsKey}`; `audit-observe` and `audit-notary` take `deployment`; a version-1 file that names the bucket is refused with a pointer to `presets`), `profile.Deployment.ResolvePreset`/`Derive`, `cli.OpenArchiveFrom`/`PlanDestinations`/`OpenDestinations` and `writer.Config.Destinations`. New: `profile.PresetStorage`, `Deployment.CheckStorage` and `Features`, `store/routed` (the presets' stores addressed as one archive, so the indexer, query service and notary read every preset's store), `cli.PlanPresets` and `cli.OpenArchive`. The audit chart takes `presets` in place of `preset`, and the audit Pulumi library `Args.Presets` (`PresetStorage{Bucket, Prefix, Region, Endpoint, PathStyle, CredentialsAddress, KeyAlias, Create}`) in place of the single `Archive` bucket and endpoint; `LambdaArgs.Audit.Archive` is replaced by the same `Presets`.

## v1.73.0

### Changed

- **The Pulumi library's `ParameterKeyArn` now also encrypts what the function writes at run time.** Until now it keyed the two parameters Pulumi creates and the IAM grants, but the function's own writes (its credentials and exports) were encrypted with the AWS-managed `aws/ssm` key, readable by any principal in the account allowed `ssm:GetParameter`. With `ParameterKeyArn` set, the library writes `secrets.kmsKeyId: <ParameterKeyArn>` into the service document, from a `Config` and from an `Installation`, and the `ssm` secrets adapter encrypts with it. A document that names another key (`secrets.kmsKeyId`, `adapters.secrets.settings.kmsKeyId`) is refused naming the field; the same value is accepted. Unset, the document is byte-identical. The root module gains `secrets.kmsKeyId` (`ssm` source only; the adapter's `kmsKeyId` setting may repeat it, naming another is refused), so the library and the binary are released at the same version. **Estates that set `ParameterKeyArn` must re-write the parameters the function created before this release** (under `<root>/private/credentials/` and `<root>/export/`): they are on `aws/ssm` until written again.

## v1.72.0

### Changed

- **`sluisctl` keeps its local state in `<user config dir>/sluisctl` (`~/.config/sluisctl` on Linux) instead of `.../accessctl`.** Sessions, `config.yaml` and the credential and token caches all move; the deprecated `accessctl` name uses the same directory. The first run that finds the new directory empty and the old one populated copies the old files across (modes kept, never widened past 0600/0700; nothing already in the new directory is replaced), prints one line on stderr, and leaves the old directory in place for you to delete. The copy is built in a staging directory and renamed into place, so a failed or concurrent run never leaves a half-built directory. An older `accessctl`/`sluisctl` build run afterwards updates only the old directory. Deleting `~/.config/sluisctl` copies the old state again unless `~/.config/accessctl` is removed too. The OIDC client id, the `accessctl:` kubeconfig user prefix and the wire protocol are unchanged.

## v1.71.0

### Added

- **The Pulumi library's Lambda role can mint web identity tokens for further audiences: `LambdaArgs.AdditionalWebIdentityAudiences`.** For code that runs in the function and needs its own AWS-minted token, such as an OpenTelemetry layer authenticating to a collector through the issuer's token exchange (`exchange.aws.audience`, typically the issuer URL). The entries are appended, after the console audience, to the exact `ForAllValues:StringEquals` condition on `sts:IdentityTokenAudience`; the console audience stays first and required. Empty entries, duplicates (the console audience included) and use while `WebIdentityAudience` resolves empty are refused. Unset, the role's policy is byte-identical, so an existing stack shows no diff. This gives up "the role mints a console bearer and nothing else": any code running with the function role, its layers and their dependencies included, can mint a token for every audience listed, so a policy rule that matches the role for an exchange must grant only what that audience's consumer needs. `docs/reference/sluis/lambda.md` now shows the `ForAllValues:StringEquals` the code emits, where it showed `ForAnyValue`.

## v1.70.0

### Added

- **The Pulumi library's Lambda shape publishes an earlier signer's public keys as verify-only: `LambdaArgs.VerifyOnly`.** An estate moving an existing issuer onto the Lambda shape can keep the tokens the old issuer signed verifying for the overlap after the switch, as the chart's `signingKey.verifyOnly` does on Kubernetes. Each `VerifyOnlyKeyArgs` is a `PEM` (one `PUBLIC KEY`, `RSA PUBLIC KEY` or `CERTIFICATE` block, RSA or ECDSA), an optional `KeyID` and `Alg`, and a required `Until`. The configuration layer holds each at `/opt/sluis/verify-keys/<index>.pem` (`VerifyOnlyKeyPath`), and the library writes `signingKey.verifyOnly` into the service document naming them, with `kid`, `alg` and `until` in RFC 3339, whether the document is rendered from an `Installation` or given as `Config`. A private key (or anything that says PRIVATE), two keys in one PEM, the same key or `kid` twice, an `Alg` the key does not sign with and a zero `Until` are refused before anything is published, and the error never quotes the key. `signingKey.verifyOnly` is the library's on Lambda: a `Config` or an `Installation` that names it is refused, since the files it names are not in the layer. A stack that sets no `VerifyOnly` publishes the same layer as before.
- **The Lambda shape's schedules can be declared paused: `Schedule.Paused`, `Exports.Paused`, `DirectoryRefresh.Paused`.** A paused schedule is declared with EventBridge Scheduler's `state: DISABLED`, and everything else stays: its expression and target, the scheduler's role and the function's grants, the `export/*` read and write included. An estate preparing a cutover deploys the destination with its controllers' ticks, the exports and the directory refresh paused, and turns them on with one setting whose preview changes only each schedule's state. Unset, a schedule declares no state (the default, enabled), so an existing stack shows no change. `Paused` with `Disabled` is refused.

## v1.69.0

### Added

- **Audit catalogue 1.10.0; the audit writer deploys first.** `roster.person.signed_in` carries the `class` of the session the sign-in opens (`interactive` or `agent`) and its computed `deadline`; `roster.session.ended` carries `spared`, the client ids of the agent sessions a sign-out left running. Recording is best effort, so an audit installation must hold catalogue 1.10.0 before the issuer that emits it is deployed: one on Kubernetes registers it when the service starts; a Lambda audit writer needs the new catalogue release asset (`roster-1.10.0.yaml` and its schemas) first.
- **Agent-class sessions: `session: agent` on a client, and on `client_documents`, for software that holds its own refresh token and works in the background, such as MCP hosts** ([ADR 0040](docs/decisions/0040-agent-class-sessions.md)). An agent client's refresh chains are held to the service configuration's new `lifetimes.agent` instead of the installation's `lifetimes.refresh` and `lifetimes.absolute`: an idle limit of `336h` (14 days), an absolute limit of `720h` (30 days) from `auth_time`, and a mandatory `30m` cap on every access and ID token. A resource's `absolute_cap` is only ever a ceiling for an agent chain, and the client's, `client_documents`' and the resource's `ttl_cap` still shorten its tokens. The class is decided once, when the authorization completes, from the installation's policy and never from a client document (a recovery sign-in is always interactive), and is recorded on the session with the chain's `deadline`. A later policy or configuration change can shorten an agent chain at its next refresh, including a shorter `lifetimes.agent.refresh` for a chain already idle past it, but never lengthen it past that deadline or change its class; a chain recorded before this release, or by an older replica during a rollout, is interactive. `lifetimes.agent` is refused at load when its `absolute` is above `2160h` (90 days) or not positive, its `refresh` is above its `absolute` or not positive, or its `access` is above `1h` or not positive. Also refused at load: `session` on an `exchange` client, and `session: agent` with `sign_in_exchange: true`. Warned at start: `session: agent` on a client with `signed_out` or `backchannel_logout_uri`. Rolling back past this release needs `session` and `lifetimes.agent` removed first, since an older binary refuses the keys; revoke each agent client's sessions with the per-client revoke (or the new revoke for everybody) before rolling back, since an older release reads them as interactive and would end them only at its own limits.
- **An agent connection is made only on a consent page, accepted in the person's own browser** (ADR 0040, decision 6). An agent-class authorization never completes silently: after the person signs in, or from the browser's existing sign-in, they are shown a page naming the client, the origin of a document client, where it returns to, that it is a background connection, its computed deadline and who is signed in, and the connection is made only when they press *Allow*. The accept is bound to the request, the person, their sign-in and the browser (a cookie of its own, `__Host-` when cookies are secure), re-checks the sign-in, and is verified where every sign-in completes, so a start link sent to somebody else, an accept posted from another browser, or the page in a frame completes nothing. The page is served with `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY`. `prompt=none` for an agent client is answered `consent_required`, and the chooser is shown for one even when a single directory is configured. New login metric values: `access_issuer.login.failures` reason `consent_refused`, and `access_issuer.login.successes` method `agent_consent`.
- **A person's browser sign-out keeps their agent sessions running** (ADR 0040, decision 7). `/logout` and `/end_session` end the browser's sign-in and its interactive sessions, and leave agent sessions alone: they are not revoked, their clients get no Back-Channel Logout (not even the subject-only token), and they stay filed under the ended sign-in, where revoking that browser still reaches them. When `/end_session` names an agent client, by `client_id` or by the audience of its `id_token_hint`, that client's sessions under the sign-in end too. The signed-out page says that agent connections were kept and links to *sign out everywhere*. Another person signing in in the same browser still ends everything the first opened, agent sessions included, and a browser sign-in past its absolute limit still spares every live chain. Every revoke ends agent sessions as before: *sign out everywhere*, the per-client and per-browser revokes, `Issuer.Revoke`, reuse detection, and removal from the directory.
- **A person's own sign-out everywhere comes in three** (ADR 0040, decision 7 as amended): `RevokeSessionsRequest` gains `scope`. *Sign out all browsers and apps* (`REVOKE_SCOPE_INTERACTIVE`) ends every browser sign-in and interactive session and keeps agent sessions; *Disconnect all agents* (`REVOKE_SCOPE_AGENTS`) ends every agent session and keeps the browsers; *Sign out everything* (`REVOKE_SCOPE_EVERYTHING`, the default, and any value the issuer does not know) is the previous *sign out everywhere*, the lever for a suspected compromise. A scope narrows only a person's own revoke: an operator's revoke of somebody else ends every class whatever scope it names. Back-Channel Logout goes to exactly the sessions that end. `roster.session.revoked` names the scope (`every_browser_and_app`, `every_agent`, `everywhere`) and, for the scoped two, `ended_class` and `kept_class`. A person's own page in the console offers the three, *Sign out everything* first.
- **The consent page's *Allow* is inert until the page has been visible and focused for 500 ms**, and again whenever it is hidden or loses focus,, by a nonce'd inline script the page's `Content-Security-Policy` names; without JavaScript an agent connection cannot be allowed. **An authorization request already completed is no longer completed again as another person or under another sign-in.**
- **The console shows each session's class and deadline, groups a person's sessions by sign-in, and an operator can end one client for everybody.** `accessissuer.v1.Session` gains `session_class` and `deadline` (additive); `RevokeSessionsRequest` gains `every_identity`, which with a `client_id` and no identity ends that client's sessions for every identity, operator-only and audited as `roster.session.revoked` with scope `client_every_identity`. A person's page groups sessions under the sign-in that opened them, marks one that has ended as a signed-out browser whose agent connections were kept, and offers *End this browser*; a client's page offers *End for everybody*.
- **A refresh token whose chain has ended is named once in the log, and, once confirmed dead, refused from memory with no State read** ([ADR 0040](docs/decisions/0040-agent-class-sessions.md), decision 10). A host looping on a dead refresh token cost two to four State reads per presentation, and nothing but the library's generic `request error` line said which client it was. The refusal now also logs a WARN, `refused a refresh token that names no live session`, once per cache entry, with the client id the request named (through `logsafe`, since it is unauthenticated; empty for a client that authenticates with `private_key_jwt`, which names itself only in its assertion) and `token_fingerprint`, the first 8 hex of an HMAC-SHA-256 of the token under a key derived with HKDF and a label of its own from the secret the sign-in state is derived from (a random per-process key where there is none); the token is never logged. These WARN lines are limited to 30 a minute across all tokens, and the next one says how many were held back (`suppressed`). A terminal state read consistently (no pointer and no legacy rotated record, or a pointer whose session record is absent) makes an entry in an in-process LRU of 4096 entries keyed by the full HMAC, and the entry is CONFIRMED only by a second such verdict read at least 60 s after the first: an absence caused by expiry can be overtaken by another replica's conditional write built a moment earlier (the DynamoDB adapter decides expiry by its replica's clock, to the second), so one verdict is never trusted alone, and any verdict that is not dead, or a failed read, undoes the entry. A confirmed entry is refused before any State read for a fixed 5 minutes and counted in the new `access_issuer.dead_refresh_token_hits`; it still counts in `access_issuer.reuse_detected`. A grace-window replay, a spent token in the tolerance band, a reuse in a live session, a record still stored past its end and a failed read never make an entry, and nothing does over a State that keeps no revisions. A dead token costs 2 reads until it is confirmed (it was 4), 0 after.

### Changed

- **The DynamoDB adapter now caps every operation at its own 15 s timeout, whatever deadline the caller's context carries.** A context that already had a deadline was passed through unchanged, so on AWS Lambda, where the invocation's deadline can be as far off as the function's timeout, nothing bounded an operation, its SDK retries or the default HTTP client at 15 s. Each call now runs under `context.WithTimeout` of 15 s; the earlier of the two deadlines still wins, so a shorter caller deadline is honoured. A loop over pages (`List`, a prefix scan, the exports, a `Watch` poll, the members of a set) applies the cap to each page rather than to the whole loop, so a long listing is not cut by its total and a Lambda invocation's long deadline no longer lets a single page run on. Table creation applies it per call and keeps its own 90 s wait for the table to become active. This matters because the refresh-token negative cache ([ADR 0040](docs/decisions/0040-agent-class-sessions.md), decision 10) confirms a dead verdict after 60 s on the assumption that no conditional write stays in flight longer than 15 s plus margins, and a rotation slower than the 30 s reuse grace makes a client's own retry look like a reuse. A DynamoDB call that needed longer than 15 s now fails as unavailable instead of completing. A caller with no deadline that iterates a large table (`List`, `ExportState`, `Members`, `ExportIndex`, the `Watch` snapshot) is now bounded per page but not in total, and a `Watch` poll can overrun its interval rather than fail.
- **`client_documents.ttl_cap` now caps a document client's access tokens, not only its ID tokens.** The token endpoint looked a client's `ttl_cap` up among declared clients only, so a document client's access token lived `lifetimes.token`.
- **A token exchange of a sign-in (`sign_in_exchange`) refuses an access token whose session is agent-class**, whatever the client's row says now: a recorded class outlives a policy change.
- **The session index sets are kept for `max(2 × lifetimes.refresh, lifetimes.agent.absolute)` (30 days by default) on every Add**, so that an interactive session's Add never shortens a set an agent session is in on an engine whose set expiry is the whole set's (memory, Valkey). A refresh still adds a session again once its last Add is one refresh window old, so a membership lost out of band comes back within that window. An interactive session's id stays in the sets longer, and a listing, or a step-up's refile, that meets one whose record is gone drops it. A spent refresh token's mark in an agent chain is kept until the chain's recorded deadline.
- **Behaviour change: a refresh whose person the directory authoritatively reports suspended or not found ends the session, and a refresh the issuer cannot decide answers 500 `server_error`** ([ADR 0040](docs/decisions/0040-agent-class-sessions.md), decision 5). A refresh whose person the directory reported not live was refused and nothing else: nothing was deleted or audited, so the chain lingered until it idled out. Now, once the library has matched the authenticated client to the session's (a copy of the token presented by another client ends nothing), the session is deleted at the revision read, then its listing and the token's pointer, `roster.session.refresh_refused` is written with the reason `the directory says this account is not live`, the client's back-channel logout is sent, and the refresh is refused with 400 `invalid_grant`, for every class; of a burst of presentations only the one whose delete ended the session audits and announces it. A refresh the directory cannot vouch for (no authoritative answer and nothing held), or one whose session could not be read from the store, used to reach the client as 400 `invalid_grant`, because the OpenID library answers every error of its first reading of a refresh token that way, which told a client to give up during an outage. It is now 500 `server_error`, and nothing is ended or audited, so the client tries again.

### Deprecated

- **A `read_only` resource's `absolute_cap` above `lifetimes.absolute`** ([ADR 0033](docs/decisions/0033-a-longer-absolute-limit-for-read-only-resources.md)'s lengthening) is deprecated in favour of `session: agent`. It is still honoured, with a warning at start naming the resources and `session: agent`; a later minor release refuses it, marked **Breaking:**. Migrate by marking the clients that need a longer chain `session: agent`, then removing `absolute_cap` from those resources or lowering it to at most `lifetimes.absolute`. `absolute_cap` as a shortening cap stays.

## v1.68.0

### Added

- **The issuer serves OAuth 2.0 Authorization Server Metadata (RFC 8414) at `/.well-known/oauth-authorization-server`**, so an MCP client that probes it no longer gets a 404. It is OpenID discovery narrowed, not a second document: the same corrected values (`response_types_supported`, `grant_types_supported`, and the rest), the same content type, caching and CORS behaviour, and the same refusals for other methods and paths, kept to `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `scopes_supported`, `response_types_supported`, `grant_types_supported`, `token_endpoint_auth_methods_supported`, `revocation_endpoint` and its auth methods, `introspection_endpoint` and its auth methods, `code_challenge_methods_supported`, and the extension `client_id_metadata_document_supported` (only when the installation admits client ID metadata documents). OIDC-only members (`userinfo_endpoint`, `end_session_endpoint`, `acr_values_supported`, the ID token members) stay in discovery. `registration_endpoint` is listed only if discovery has one, which this issuer does not. An issuer URL with a path is served at the well-known segment followed by that path, as RFC 8414 section 3.1 inserts it. No gateway or Lambda route change is needed: both already forward every path.

### Changed

- **A Lambda invocation's kind and target, a request path, a panic and the errors logged beside them, and the Valkey retry warning's key and error, now go through `logsafe`.** The values come from the invocation payload, the request or the server, and could carry a line break into a log record; `logsafe.Value` and `logsafe.Error` remove it with the replacer the code scanner recognises (CodeQL `go/log-injection`). Log messages and keys are unchanged; a value that never held a line break is logged as before, and one that did now has it removed instead of replaced by a space.
- **Ending a sign-in now removes the set of clients it involved, and "sign out everywhere" removes the sign-in from the global index.** `State.Delete` removes values only, so `issuer:sso-clients:<id>` stayed in place until its lifetime ran out and `Involved` kept naming clients of a sign-in that had ended; it is now emptied member by member through the set operations, in memory and on every port adapter alike, with no change to the State or Index contract. Ending a sign-in with N involved clients makes N more operations than before (one read of the set and N removals instead of one delete). Ending all of a person's sign-ins no longer leaves each id in the global `issuer:sso` set until a listing finds it dangling: each sign-in costs N + 1 more operations (the clients set as above, and one more removal). Refresh and grant paths are unchanged.
- **"Sign out everywhere" now sends back-channel logout to every client the sign-ins involved, as an ordinary sign-out does.** The sessions the revoke ends are announced as held (with their session id), and clients signed in with `openid` alone, known only to the sign-in's set of involved clients, are announced by subject; one logout token per client and sign-in, best effort, through the same announcer. Previously nobody was told on this path. Cost: when an announcer is wired, one more read per sign-out everywhere (listing the identity's sessions before they are revoked); the set of involved clients is read once, for both the announcement and the drop. Every running chain is revoked in the same call, so none is spared.
- **A logout token sent at "sign out everywhere" names the identity as stored.** Clients signed in with `openid` alone were told the caller's spelling of the identity as `sub`, which differs in case from what their ID token carried when the request was not lowercase; it is now the sign-in record's identity, or the same normalisation the store applies. No operation is added.
- **Back-channel logout tokens are delivered concurrently, at most 8 at a time.** They went one after another with a 5 s timeout each, in the request path, so an unreachable client added 5 s per client and sign-in to a sign-out; it now adds 5 s once. All posts are still waited for before the call returns, each keeps its timeout and its log line, and a failure never fails the sign-out. Ordinary sign-out and "sign out everywhere" both benefit. No change in operations on the store.
- **Behaviour change: the console on the issuer's origin applies the issuer's sign-in checks on every request, and ends a sign-in that fails them.** The console used to accept any live browser sign-in (the issuer's SSO cookie) for the rest of the sign-in's own lifetime (up to 12 h by default), so a sign-in past the absolute session limit, or one whose person the directory had since suspended or removed, kept opening the console while every other client was already refusing it. It now asks the same function the issuer's silent sign-in asks, so the two cannot drift. A sign-in past the absolute limit (`auth_time` plus the installation's absolute limit, the one the console's own client is held to) is refused and ended with the same cascade as at `/authorize`: the clients signed in under it without a refresh token are sent a logout token, sessions still inside their own limit are left alone, nothing is audited, and the browser's cookie is cleared. A person the directory no longer admits (suspended, not found, or not vouched for with nothing held for them) is refused, the sign-in is ended and the cookie cleared, with the same warning in the log (`browser session is no longer admitted`) and no audit record, as at `/authorize`. A directory that cannot be reached is answered from the issuer's hold window (last-known standing, 4 h by default), exactly as for a silent sign-in: an admitted person keeps the console inside the window, and the sign-in ends past it or for someone nothing is held for. A recovery sign-in has no directory to ask and is held to the absolute limit only. Not being in a group that grants a console role still does not end a sign-in: the console refuses those calls by role, as before, and a silent sign-in to a client the person is not entitled to also keeps the sign-in. A console request now makes 4 State reads (was 3: the new one is the eventually consistent revision read of the last-known groups every refresh already pays), no writes, and one directory resolution and one snapshot read, as before: the issuer's check and the console's authorizer share one answer per request (`hub.OneAnswerPerRequest`), held to the grant-cost budget as `console request`. `issuerapp.Deps.UseSignedIn` and `server.ConsoleServerDeps.SignedIn` now take the `http.ResponseWriter` too, so an ended sign-in's cookie can be cleared.
- **Behaviour change: the issuer's session service holds a browser's sign-in cookie to the same check.** `ListSessions` and `RevokeSessions` (`accessissuer.v1.SessionService`, what the account page and the console call at the issuer's host) authenticated a cookie by asking only whether it named a live sign-in, so an operator's sign-in past the absolute limit, or a copy of its cookie, could go on listing every session and revoking anyone's until the record expired, and a person the directory had suspended or removed was still served as themselves, without their groups. The cookie is now judged by the decision the issuer's silent sign-in and the console make (one function): past `auth_time` plus the installation's absolute limit, or a person the directory does not admit (suspended, not found, or not vouched for with nothing held), the cookie proves nobody and the call is refused with `unauthenticated`; a bearer token, where one is sent, is still checked on its own. Inside the hold window an unreachable directory is answered from the last-known groups, as before. The service refuses such a cookie and does not end the sign-in; the issuer's pages and the console end it on the browser's next visit. A cookie call costs what it did: 7 State reads for a person listing their own sessions, no writes, one directory resolution (held to the grant-cost budget as `session service call`).
- **A recovery sign-in is recognised by how it was made, not by the shape of its subject.** The silent sign-in and the console skipped the directory for any sign-in whose subject had no `@`, and the console and the session service evaluated one whose subject read as a ServiceAccount (`system:serviceaccount:<ns>:<name>`, `k8s:<ns>:<name>`) as that ServiceAccount, which an installation that recovers through the console makes an operator. They now go by the method the sign-in recorded when it began (`recovery`); a sign-in made through an identity provider is a person whatever its subject looks like, is asked of the directory, and is never the recovery account. Recovery sign-ins themselves are unchanged.
- **Behaviour change: tokens and refreshes evaluate a subject as a ServiceAccount only for a recovery sign-in.** The code exchange, the ID token, the access token's claims, the client's `requires` at sign-in and at every refresh evaluated any subject that read as a ServiceAccount (`system:serviceaccount:<ns>:<name>`, `k8s:<ns>:<name>`, `<cluster>:k8s:<ns>:<name>`) by the policy's `service_account` matchers, without asking the directory, so a sign-in through an identity provider whose subject happened to read as one was given whatever the policy grants that ServiceAccount (for the recovery ServiceAccount, typically the operators' group) in every token and refresh. They now go by how the sign-in was made: the authorization request carries it, and a per-client session records it when it is opened (new optional field `method` in the `ses.<person>.<sid>` record, a provider's kind or `recovery`, written with the record a code exchange already writes and read with the record a refresh already reads, so a refresh still costs 4 writes, 4 reads and one directory lookup). A recovery sign-in is evaluated as its ServiceAccount, as before; anybody else is asked of the directory, whatever their subject looks like. Token exchange is unchanged: its grant is decided from the verified proof, and a session it opens keeps the subject this issuer minted from that proof, as a ServiceAccount only when it names one and has no `@` (a person trading their own sign-in is a person, even with an address such as `k8s:ns:x@corp.example`). A session opened before the upgrade has no `method` and is evaluated as a person: a recovery sign-in's per-client sessions from before the upgrade stop refreshing (the directory knows no such person) and sign in again; a person's are unaffected. During a rolling upgrade an older replica opens sessions without the field, with the same effect.
- **The console's own recovery sign-in form is accepted only from the browser it was served to.** The standalone console's `POST /login/recovery` took a form-posted proof with no state, so whoever held a valid recovery proof could post it from a page of theirs and sign a victim's browser into the console as the ServiceAccount (a login CSRF). The console's sign-in page (`GET /login`) now embeds a signed state, bound to recovery, in the recovery form and sets a recovery cookie of its own (`__Host-access_roster_recovery`, `access_roster_recovery` without Secure cookies; HttpOnly, SameSite=Lax, 10 minutes) to it; a form post is refused with 400 ("this sign-in did not start in this browser") unless the cookie equals the state, compared in constant time (`access.RecoveryStartedHere`, beside `access.LoginStartedHere` for the provider callbacks), and the state verifies as a recovery state. The console's provider callback now refuses a recovery state in turn. The post body is limited to 16 KiB before anything is read (413 beyond it); the standard library would otherwise read up to 10 MiB of form, or 32 MiB of multipart. The cookie is cleared once the proof is accepted. The programmatic channels are unchanged and need no page, since another site cannot send them without a CORS preflight this console never answers: a bearer (`Authorization: Bearer <proof>`, the one-line curl) and a JSON body. A JSON body is now read only under a `Content-Type` of `application/json`: read regardless, a cross-site `text/plain` post carrying JSON was the same forgery. Anything else is a form: `curl -d proof=…` without the page's state and cookie is refused (use the bearer), and the proof is no longer read from the query string. A console built without a state codec (no real deployment) offers no recovery form; the bearer still works.
- **A sign-out after a step-up now ends what was opened before the step-up.** When the same person signs in again in the same browser (a step-up, `prompt=login`, `max_age`), the sign-in the browser held is ended, but the per-client sessions opened under it stayed filed under its id, while a sign-out revokes the sessions filed under the sign-in the browser holds; so they survived the person's sign-out and ran on to their own end, and their clients were never told. The sessions are now carried over to the new sign-in: each of the person's live sessions filed under the old sign-in is re-filed under the new one (written over the revision read, so a refresh or revocation racing it is never undone, and keeping the store lifetime it had), and the clients the old sign-in was used at are added to the new one's, so a later sign-out revokes them and sends their Back-Channel Logout as it does for the rest. Nothing is revoked, announced or audited by the step-up itself, as before. The old sign-in's clients are read, then it is ended, then its sessions are moved, so a code redeemed under it either files its session before the move or finds the sign-in ended and ends its own. Carrying is best effort: a session that cannot be moved is logged and left where it was, and the others are still moved. Over a State that keeps no revisions nothing is moved (every adapter the issuer ships keeps them), since a plain write there could bring back a session revoked meanwhile. The same person's sessions in other browsers are not touched. A step-up costs `2 + N` State reads and `C + M` writes more, where N is the number of the person's sessions in the index, M the number moved and C the number of clients the old sign-in was used at; a refresh and a silent sign-in cost nothing more. An authorization code completed under the old sign-in and redeemed after the step-up is refused at redemption (see the next entry): its client starts again and completes silently under the new sign-in.
- **An authorization code completed under a browser sign-in that has since ended opens nothing, and a sign-out ends the sign-in before its sessions.** A silent sign-in reads the browser's sign-in and then completes the request, and the relying party redeems the code a moment later. A sign-out in another tab used to revoke the sessions filed under the sign-in, tell the clients (Back-Channel Logout, up to 5 seconds each), and only then end the sign-in, so the sign-in and its cookie stood through all of that; a code redeemed anywhere before the end opened a session filed under a sign-in that then no longer existed, which no later sign-out could reach, or, for a client that asked for `openid` alone, an ID token from a sign-in that would never announce its end. Both sides are now ordered so that this cannot happen. A sign-out (and every other end of a sign-in: another person signing in in the same browser, the absolute session limit) ends the sign-in first, then lists and revokes its sessions and tells the clients; what is revoked, announced and audited is unchanged. A code redemption files its session first and then reads the sign-in; when the sign-in has ended it revokes the session it just filed and answers `invalid_grant`. Either that read comes after the end, or the session was filed before the sign-out listed them, and the sign-out revokes it. A code that opens no session (a client that asked for `openid` alone, or a request whose every scope the client may not ask for) is held to its sign-in before its access token is minted: the client is recorded among the sign-in's clients first and the sign-in read after, so the code is refused or the client is told at sign-out, except for a sign-out whose two adjacent store calls (reading the clients, ending the sign-in) straddle both. Ending a sign-in, and carrying a step-up's sessions over, is no longer cancelled with the request that asked for it: a browser that disconnects once the sign-in has ended no longer leaves its sessions unrevoked, or unmoved, under it. That work runs on the request's values without its cancellation, bounded at 30 seconds, and the audit record is now written before the clients are told, which runs last, each Back-Channel Logout bounded by its own 5-second timeout. The relying party starts again and the browser, signed out, signs in interactively. This covers every completion, silent or interactive (a code completed under a sign-in that another person's or a step-up replaced before it is redeemed is refused the same way). An `authorization_code` grant under a browser sign-in that opens a session costs one State read more (5 reads, 9 writes), and a refused one also revokes the session it filed; one that opens no session costs one read, as an `openid`-only grant already did, now also for a grant with no scope. A refresh is unchanged (4 writes, 4 reads, 1 resolution), and so is a grant with no browser sign-in.
- **The issuer's recovery sign-in is accepted only from the browser the form was served to.** `POST /login/recovery` checked the signed `state` field and nothing else, and a valid state is anybody's to fetch: load the sign-in page for a request of your own and read it off the form. So whoever held a valid recovery proof could post it from a page of theirs and sign a victim's browser in as the ServiceAccount (a login CSRF). The sign-in page that renders the recovery form now sets a recovery cookie (`__Host-access_roster_recovery`, `access_roster_recovery` without Secure cookies; HttpOnly, SameSite=Lax, 10 minutes) to the form's state, and the POST is refused with 400 ("this sign-in did not start in this browser") unless the browser presents that cookie with the same value, compared in constant time, as the provider callback does with the login cookie. A cross-site POST never carries a SameSite=Lax cookie. The recovery cookie is not the login cookie, because the issuer and a console mounted on its host both write the login cookie: opening any sign-in page, or following a provider button, would otherwise break a recovery form already open. The recovery form's state is also marked as a recovery state (`access.RecoveryPurpose` in its binding), and the recovery POST refuses a provider round trip's state while the provider callback refuses a recovery state, so neither door accepts the other's. The POST body is limited to 16 KiB before it is parsed (413 beyond it). The cookie is cleared once a proof is accepted; a refused proof keeps it so the form can be submitted again. A person who opens the sign-in page in two tabs can recover only from the last one loaded. A recovery form loaded before the upgrade is refused once; reload the page.

## v1.67.0

### Changed

- **Behaviour change: a client that presents a spent refresh token more than 30 seconds after it was spent now ends its session.** Refresh token reuse detection, per OAuth 2.0 Security BCP (RFC 9700 section 4.14.2): a refresh token used by both a thief and its rightful holder is presented twice, and the issuer cannot tell which presentation is the thief's, so the session the token was spent in is ended. The session is ended only once the library has authenticated the client and matched it to the session's: a spent token presented under another client is refused with nothing ended. The grant is refused with `invalid_grant`; the successor and every later refresh token of the session stop working, the session is gone from every listing, and userinfo refuses the access tokens that name it, as `RevokeID` ends a session; a client that declares a `backchannel_logout_uri` is sent a logout token for it. What is not ended: the browser sign-in (SSO) the session was opened under, so a false positive costs one client's session and not every one, and access tokens already issued as JWTs, and credentials already obtained by token exchange (RFC 8693), which stay valid until they expire. The revocation is audited as `roster.session.revoked` by the system with the scope `refresh_token_reuse`; the record names no browser sign-in, since a sign-in's id is its cookie's value. Ending the session is conditional on the session record being the revision read when the reuse was detected, so of several concurrent presentations of one spent token exactly one ends the session, writes the audit record and sends the logout tokens, and the others are refused with nothing written; the audit record follows that conditional delete, so it is never written for an end that did not happen. A reuse is acted on only when the token was spent more than 32 seconds ago (the grace window plus a 2-second clock tolerance); between 30 and 32 seconds it is refused and nothing is ended, so a replica whose clock runs a little ahead cannot turn a client's own burst of refreshes into a revocation. The replicas are expected to keep their clocks with NTP. As with any refresh token reuse detection (RFC 9700), a spent refresh token that leaks while its mark is kept (up to 24 h) can be presented once to end that session. Inside the 30-second grace window a replay is still answered with the same successor, exactly as before. To make this detectable, a spent token's pointer is kept until the absolute deadline of its refresh family, `auth_time` plus the absolute limit (24 h by default), so a reuse is detected for as long as the family it would end can live and never longer (a workload's session, which has no `auth_time`, or a deployment with no absolute limit, keeps it until the session's end as the rotation set it, at most the refresh lifetime, 12 h by default), instead of 30 seconds, and holds when it was spent, the session id and the successor sealed under the spent token (AES-256-GCM, key derived from the spent token, so the keyspace never holds a live refresh token in plain): `spent:<ms>:<sealed>:<session>`. A mark that does not open with the presented token ends nothing. That is the TTL of the write a rotation already makes, so a refresh still costs 4 writes and 4 reads; a reuse costs 2 reads and 4 writes (the record and its three index sets), a reuse that lost to a concurrent one 2 reads and 1 failed conditional delete, a repeated reuse 3 reads. Storage holds one small spent mark per refresh for that window rather than for 30 seconds: for a client refreshing every 5 minutes, up to about 288 marks per session. A mark dated more than 2 seconds ahead of the reading replica's clock is logged and counted (`access_issuer.spent_mark_ahead`), since replica clock skew moves the grace window. A token spent by v1.66.0 (the `issuer:session-rotated:` record, read for one release) cannot be detected after its 30 seconds, since that version kept nothing longer; during a rollout, a replay inside the grace window that lands on a v1.66.0 replica is refused, as that version does not read the new mark.
- **Audit catalogue 1.9.0**: the summary of `roster.session.revoked` names the scopes the issuer uses on its own: `refresh_token_reuse`, when it ends a session on a refresh token reuse; `pre_upgrade_cookie`, when a browser signs out with a sign-in cookie set before the cookie had a secret of its own (by an `anonymous` actor); and `sign_in_replaced`, when another person signs in in the same browser (by the person signing in). What a record carries is unchanged. An audit installation on Kubernetes registers the new catalogue automatically when the service starts; a Lambda audit writer needs the new catalogue release asset (`roster-1.9.0.yaml`) before it can keep records of this version.
- **A refresh_token grant makes 4 State writes and 4 reads (was 14 and 8), and asks the directory once (was 4); an authorization_code grant makes 9 writes and 4 reads (was 13 and 5).** One resolution per request, the snapshot decoded once per blob version, the last-known groups rewritten only when they change, when the stored time is an eighth of the hold window old (a hold can now end up to that much early, never late), or when the stored record is no longer the one this process wrote (checked with an eventually consistent read of its revision only, the new optional `port.RevisionPeeker`), the access-token record written once, the refresh token and its session read once and the spent token marked in its own pointer (`spent:`, written only over the revision read, so a concurrent refresh becomes a replay and a revocation during a refresh is not undone), and the index and sign-in-client sets added to only when a membership would lapse. Behaviour is otherwise unchanged; `issuer:session-rotated:` is still read for one release.
- **The issuer's sign-in cookie no longer equals the sign-in id; every browser signs in once more after the upgrade.** The browser session cookie (`__Host-access_issuer_sso`, `access_issuer_sso` without Secure cookies) used to carry the sign-in record's id, which the operators' listing shows for every signed-in person and every session carries, so anyone who saw an id could set the cookie and be signed in as that person until the sign-in ended. The cookie now carries a fresh 256-bit random secret (base64url). The store keeps only its labelled SHA-256 hash, as a pointer `issuer:sso-cookie:<hash>` (layout kind `issuer-sso-cookie`) to the sign-in id and in the sign-in record, with the record's lifetime; the pointer is removed when the sign-in ends (sign-out, revocation, the absolute session limit). The id stays the sign-in's name everywhere it was shown and authenticates nothing. A sign-in costs one State write more, a silent sign-in one read more, and ending a sign-in one delete more (and, for "sign out everywhere", one read per sign-in). A cookie set before the upgrade signs nobody in: those browsers sign in once more. For one release it still signs its own browser out: `/logout` and `/end_session` with a pre-upgrade cookie end that sign-in and the sessions it opened, and tell the clients, as before. This works only for a sign-in written before the upgrade, and never signs anybody in. A sign-out whose sign-in cannot be read from the State now answers 503 and keeps the cookie, so the person can retry, instead of clearing it and reporting success. An interactive sign-in (step-up, `prompt=login`, `max_age`, another account) now ends the sign-in the browser held before, once the new one is handed to the browser (a refused recovery leaves the earlier one in place). When the earlier sign-in was another person's (a shared browser), their sessions under it are revoked and the clients told, as at sign-out; a sign-in whose record cannot be written clears the browser's previous cookie. Revoking one browser in the console now also ends the sessions filed under a sign-in that has already ended. A sign-out by a pre-upgrade cookie is audited as `roster.session.revoked` by an `anonymous` actor with scope `pre_upgrade_cookie`, since an id proves nothing about who presented it; the shared-browser case is audited as `roster.session.revoked` by the person signing in with scope `sign_in_replaced`. During a rolling upgrade, or after a rollback, an older replica still accepts a sign-in id as the cookie, so the protection holds only once no older replica serves traffic.
- **Upgrade note: an IAM policy that limits `dynamodb:LeadingKeys` to the issuer's kinds must allow `issuer-sso-cookie` before the upgrade.** Without it the cookie pointer cannot be written or read, and single sign-on stops without an error page: every console asks for a login again. The policy the Pulumi library writes does not restrict leading keys and needs no change.

## v1.66.0

### Added

- **Pulumi library: opt-in API Gateway access logs (path and status only).** `LambdaArgs.AccessLogs` (off by default) declares a log group `/aws/apigateway/<FunctionName>` (`RetentionDays`, default 7) and the stage's access log settings, for an installation where MCP clients refresh every few minutes and the request pattern is worth seeing. The line holds the request time, id, method, path, status and the two latencies; the query string (OAuth codes and state), headers, source address and identity are never logged. An HTTP API needs no account-level CloudWatch role, so no IAM resource is added. New output `AccessLogGroupName`.
- **Confidential clients can let the issuer generate their secret.** A policy client's `secret` is now one of two shapes: a string, the name of an input (`clients/<id>/secret`, unchanged), or the object `{generate: true}`. With the object form the issuer makes a 32-byte random secret (base64url, no padding) the first time it runs and keeps it with its credentials, at `credentials/oidc-client/<id>/secret`, as one record that also has room for a previous secret and the time until which it is accepted. The write is create-only, so replicas and Lambda invocations that start together agree on one value, and an existing record is never overwritten. When the input `clients/<id>/secret` exists at that moment it is adopted, so a client that already uses it keeps working. The token endpoint reads the record of a generated client first and, only while the store says there is none, the input; a corrupt or unreadable record authenticates nobody (a record read earlier is served for at most 5 minutes when the store fails), and a client with a named input secret is served by the input alone, so a first deploy never refuses a valid client before the secret exists. Start-up is refused for a generated client when the State is not shared between replicas (the memory adapter excepted); the record is cached for 30 seconds. The check compares both the current and the previous secret on every request, in constant time. Generation is refused (at start-up) when the secrets adapter cannot create a secret only if absent, which is the `legacy` adapter's, and for a public or exchange client; `generate: false` is refused. A failure for one client is logged and counted (`sluis.client_secret.reconcile`, `sluis.client_secret.auth`) and does not stop the issuer; it is retried every five minutes on a server and on the directory refresh schedule on Lambda. An older binary refuses the object form, so roll every replica before writing it.
- **A generated client secret can be exported.** An `exports[]` entry with `source: oidc-client` and `client: <id>` copies a confidential client's id and its current generated secret (never the previous one) as `client-id` and `client-secret` to the export store, written with `replace`, so the relying party reads it through its own secret operator. The client must be confidential with `secret: {generate: true}`, or the policy is refused at start. A copy is made at start and every `interval` (default 1h, minimum 1m); there is no watch on the Secrets port, so a change by anything other than `sluisctl clients rotate` reaches the copy at the next interval; a rotation by that command copies the new secret out at once.
- **Rotate, look at and purge a generated client secret: `sluisctl clients rotate|show|purge <id>`.** `rotate [--overlap 24h]` makes a new secret and keeps the old one accepted for the overlap (default 24h, at most 7d, `0` cuts it at once), so a relying party is not cut off between the new value being made and being deployed. A rotation during an open overlap drops the older previous secret, and says so. It is refused for a client that is not generated or has no record yet. `show` prints metadata only (created, rotated, whether a previous exists, until when it is valid, whether the client is orphaned): never a secret. `purge` deletes the stored record of a client that is no longer a generated client of the policy (an orphan); the copy an export made is not touched, since the export is declared with the client and goes with it, and neither is the input secret `clients/<id>/secret`: the command tells the operator to delete both by hand. The commands call the issuer's `POST /.access/client-secrets/{rotate,show,purge}`, which admits a bearer token from this issuer that was issued to `accessctl` (sluisctl's default client) or `console` and whose `groups` hold the operators group, as the session service's operator calls do. A verified caller refused for it (not an operator, wrong audience, busy, not generated, still declared, no record, a bad overlap) is audited as `roster.client.secret.denied`; a request with no accepted token is only logged and counted (`sluis.client_secret.admin_refused`). Writers of one record are serialised by a per-client lease on the State (ssm's conditional write is a read and then a write). The resolver on the replica that served the request forgets the client at once; another replica's 30-second cache lapses on its own. Metrics: `sluis.client_secret.rotations`, `sluis.client_secret.purges`, `sluis.client_secret.orphans` (no client ids in labels).
- **Orphaned generated secrets are reported once.** At start, on the five-minute tick and on the Lambda refresh, stored `credentials/oidc-client/<id>/secret` records whose client is no longer a generated client in the policy are logged and audited once (an `orphaned` time is written into the record); they are never deleted by the issuer. A client that comes back clears the mark and keeps the stored secret unchanged.
- **Audit catalogue 1.8.0**: `roster.client.secret.created`, `.adopted`, `.rotated`, `.orphaned`, `.deleted` and `.denied` on a `client` target, with the client, the times and the overlap, never a value (actor `system` for reconcile and the orphan report, the person for a rotation and a purge). An audit installation on Kubernetes registers the new catalogue automatically when the service starts; a Lambda audit writer needs the new catalogue release asset (`roster-1.8.0.yaml`) before it can keep these records.

### Changed

- **Every cookie sluis sets carries the `__Host-` prefix when cookies are Secure.** The console session (`access_roster_session`), the three flow cookies (`access_roster_connect`, `access_roster_login`, `access_roster_link`) and the issuer's browser session (`access_issuer_sso`) are now written, read and cleared as `__Host-<name>`. A browser honours that prefix only for a cookie that is Secure, has `Path=/` and no `Domain`, which these already were, so a sibling host in the same zone can no longer plant ("toss") a cookie that the issuer or console would then read. One helper, `access.CookieNameFor`, decides the name for every write, read and clear. With `issuer.secureCookies` false (plain-HTTP local development) the old unprefixed names are kept, because a browser rejects a `__Host-` cookie that is not Secure. The old names are not read as a fallback: sessions and in-flight sign-ins started before the upgrade are dropped once, and every user signs in again a single time.

## v1.65.1

### Fixed

- **Chart: documents mode projects the input secrets by `secrets.source`, not by the credentials adapter.** With `adapters.secrets: openbao` (or `ssm`) the chart skipped every input file, so an installation that reads its inputs (client secrets, the Google OAuth client, the signing state secret) as files from Kubernetes Secrets, and keeps credentials and exports in OpenBao, had none of them mounted. Now `secrets.source: file` projects the Secrets declared in `secrets` at `<root>/<name>` (mode 0440, read-only, pod `fsGroup` set), whatever the adapter; `ssm` or `openbao` as the input source projects nothing. In documents mode a policy client's `secret` is the secret's name, so each `clients/<id>/secret` is declared in `secrets` (`{name, secretName, key}`) and the chart refuses a confidential client whose name has no entry. The refusal covers every input name the documents use (the Google OAuth client, `...Secret` fields such as `stateSecret` and `passwordSecret`), a name declared twice is refused, the projected `secretName`, `key` and `name` are quoted, and the pod runs as 65532:65532 with `fsGroup` 65532. The #323 guards are unchanged. Values mode keeps its value shapes; its projected volume is also mode 0440 now.

## v1.65.0

### Changed

- **`github.com/truvity/policy` v1.44.0 to v1.45.0** (root module and `deploy/pulumi`). v1.45.0 removes `config.Secret` and replaces the `...Env` spellings in its shared fragments with `...Secret` names; sluis used neither (its schemas do not `$ref` those fragments and nothing called `config.Secret`), so no document, schema, chart value or behaviour changes. The unused `config.Secret` wrapper in `internal/config` is removed. sluis keeps its own `internal/secrets` resolver (the `SLUIS_SECRET_<NAME>` env mapping, the legacy v1 locations, the bulk SSM read with a five-minute refresh); it does not yet sit on policy's `config.NewSecrets`.


## v1.64.0

Documents mode, `sluisctl render` and the installation document, the OpenBao Secrets adapter, `k8s-aws`, verify-only signing keys. Presets `server`, `k8s-minimal` and `k8s-openbao` are refused, and the chart's values mode is deprecated: see [upgrade to v1.64](docs/guides/sluis/upgrade/v1.64.md).

### Added

- **Chart: `documents.service` and `documents.policy`**, the rendered documents of one installation
  (`sluisctl render`). The chart puts them into their ConfigMaps unchanged, holds them to what it mounts (release name,
  `policy.file`, public URLs, audit token, verify-only keys, the controllers' console URL) without rewriting them, and
  keeps only the deployment-level values. A secret an `openbao` or `ssm` secrets adapter delivers is not projected from a
  Kubernetes Secret in this mode. Helm cannot run the loader, so the chart also refuses an `http://` OpenBao address and a
  credential-looking key in adapter settings; the chart README says documents must come from `sluisctl render` (and
  `--check` in CI). A Truvity-shaped case (k8s-aws, OpenBao, KMS-wrapped, 20 clients, both controllers) is
  rendered from the installation's documents and held byte for byte.
- **The installation document and `sluisctl render`: estates render their documents through sluis**
  ([0038](docs/decisions/0038-estates-render-through-sluis.md)). An installation
  (`apiVersion: sluis.truvity.github.io/installation/v1`, `schemas/config/installation.schema.json`) is what an
  estate knows about one installation: its shape (`lambda`, `kubernetes`, `server`), the AWS resources and the OpenBao it is built
  on, whom it trusts, its clients and its exports. `sluisctl render --installation <file> --out <dir>` writes the service
  document (`sluis.yaml`, v3) and the policy document (`policy.yaml`, v2) from it, deterministically, held to the loader
  the service runs at start; `--check` compares with the files already there and exits 1 on a difference. Documented in
  [sluisctl](docs/reference/sluis/sluisctl.md#render-an-installation-in-the-two-documents-out) and
  [configuration](docs/reference/sluis/installation-document.md).
- **A public configuration package, `github.com/truvity/sluis/config`**: the service (v3) and policy (v2) document
  types, `Load` and `Validate` against the authored schemas, `LoadInstallation`, `Render` and `InstallationSchema`.
  Estates and the Pulumi library use it instead of `internal/config`.
- **Pulumi library: `LambdaArgs.Installation`**, rendered by the public package. The library completes it with the
  instance, region, account and function name from its arguments when the installation leaves them out, and refuses
  one that says another.
- **`secrets/openbao`: the Secrets port in an OpenBao KV version 2 mount**
  (`adapters.secrets: {adapter: openbao}`), laid out like SSM layout v3: `<root>/private/config/<name>`,
  `<root>/private/credentials/<kind>/<id>/<ref>` and `<root>/export/<path>`. It shares the Export
  adapter's client (the `jwt` or `kubernetes` login, the token file read again at every login, a token per
  namespace, TLS always verified against `caFile` or the system CAs). Compare-and-swap is KV's
  `cas`, atomic on the server. The root is configurable: `sluis` inside an installation's own OpenBao namespace
  (recommended), or `sluis/<instance>`; `private` and `export` are reserved. An export in the default destination
  (`ports.export` unset) honours an entry's `namespace`: the adapter writes the same `export/<path>` in that
  namespace, so a preview runner App can land in `devel`. An export of properties is stored as the properties
  themselves, one KV field each, readable by a consumer's External Secrets as it reads a copy made by
  `ports.export: openbao`. The policy it needs is in
  [configuration](docs/reference/sluis/openbao-secrets-adapter.md). Settings: `address`, `caFile`,
  `mount`, `namespace`, `root`, `auth{method, mount, role, tokenFile}`. The OpenBao client accepts https only, never
  follows a redirect, puts a 403 down to the token only when it is older than 30s, and a `Put` under a
  `cas_required` mount is a refusal that names it, not a conflict.
- **Preset `k8s-aws`**: DynamoDB state, SSM secrets (OpenBao with `adapters.secrets`), S3 blobs, kms-wrapped
  signing, the DynamoDB trigger, the ticker and the `connect` audit sink. Every adapter it names is built, so it
  starts; naming `adapters.secrets: openbao` needs no `platform.openbao`.
- **`signingKey.verifyOnly`: public keys published and never signed with**, each with an optional `kid` (default:
  the RFC 7638 thumbprint, the file signer's derivation), `alg` and `until`, so tokens issued by the old file keys
  keep verifying across the cutover to `kmsWrapped`. A private key stops the start. The chart mounts them from a
  ConfigMap (`signingKey.verifyOnly[].pem`). `until` is required; the chart refuses private material at render
  (PEM blocks other than PUBLIC KEY and CERTIFICATE, anything containing "private", a JWK with a private member).
- **Release assets `sluis-config-schemas_<version>.tar.gz` and `sluis-audit-catalogue_<version>.tar.gz`**, in
  `checksums.txt`: the JSON Schemas of the configuration documents, and the audit catalogue `roster.yaml` with
  every schema it references (the audit writer refuses to start without one). A test holds each bundle to its source.
- **Chart: `serviceAccount.awsIdentity`** (`pod-identity`, the default and renders nothing, or `irsa`, which annotates
  the account with `eks.amazonaws.com/role-arn: <serviceAccount.awsRoleArn>`).

### Deprecated

- **Chart: the values-mode** (`config`, `policy`, `exchange.clusters`, `exchange.aws`, `githubApps.catalogue` and
  `slackApps` rendering the two documents) keeps working for one minor and is then removed; NOTES.txt says so while it is
  used. Render the documents with `sluisctl render` and pass them as `documents.service` and `documents.policy`.
- **`LambdaArgs.Config`, `Policy` and `PolicyPath`** (Pulumi library): write the estate's facts as `LambdaArgs.Installation`.
  They keep working for one minor, and `NewLambda` logs a warning while one is used.

### Changed

- **Presets `server`, `k8s-minimal` and `k8s-openbao` are marked unavailable**: each names adapters that are planned
  and not built, and loading one now fails with a message naming the preset and the missing adapters, unless
  `adapters` replaces every one of them. They are not removed; `docs/reference/sluis/adapters.md` lists them.
- **The `$id` of `sluis.schema.json` says v3**, the version of the document (it said v2). A schema's `$id`
  version now follows its document's `apiVersion`.
- **`docs/reference/sluis/adapters.md` shows the `invoke` trigger as implemented**, as is the `aws-serverless` and
  `aws-hybrid` presets' trigger: the generator now links every adapter any binary registers.
- **The Pulumi library imports no `internal/` package, and its `require` of the root module is pinned by the
  release.** `deploy/pulumi/vX.Y.Z` is now tagged at a child of the release commit whose `go.mod` requires `vX.Y.Z`
  (`hack/pin-pulumi-require.sh`), so the require is never bumped by hand before a tag and a library tagged against a stale
  one no longer exists. A test holds the library to no `internal/` import.
- **Durations are written without their zero units** (`1h`, not `1h0m0s`) by the service document's types and the
  renderer; both read back to the same span.
- **Chart: KMS signing renders cleanly.** With `config.signingKey.kmsWrapped` (or `kms`, or `adapters.signing`
  naming one) the chart renders no signing Certificate and mounts no signing Secret, and refuses
  `signingKey.additional` and `existingSecret`; the chart's default `config.signingKey.file` is dropped with
  `file: null`.
- **Chart: `adapters.secrets: openbao` composes with `config.secrets.source: file`.** The chart checks
  `adapters.secrets.settings.caFile` and `.auth.tokenFile` against the `exports.openbao.caBundle` and
  `exports.openbao.token.audience` it mounts, one bundle and one audience for the export and the secrets login.
- **Chart: `signingKeyRotationStalled` follows the rotation.** Unset, `maxAgeSeconds` is `rotateEvery` plus two hours
  with kms-wrapped signing (26h for 24h), and 350 days otherwise, as before. An alerts-only release needs the same
  `config.signingKey`, or sets the value.
- **Chart: the replica check understands presets**: `k8s-aws` and the other AWS presets, and `adapters.state`,
  keep state in DynamoDB.
- An explicit adapter that needs OpenBao is no longer refused for a preset's `platform.openbao: false`.

### Deprecated

- **Preset `aws-eks`** is the deprecated name of `k8s-aws` (it never started: it named the unbuilt trigger `watch`).
  It resolves to `k8s-aws` and start logs a warning.

### v1.64.0-rc.1

The release candidate of v1.64.0: its notes are v1.64.0's, above. Cut to exercise the release workflow's library-tag job before the final tag; its npm package was not published (npm refuses a pre-release without `--tag`).

## v1.63.0

One process everywhere (ADR 0037): on AWS Lambda one function and one role, on Kubernetes one Deployment and one Pod Identity role, configured by one service document `sluis.yaml` (`apiVersion` v3, with `controllers.github` and `controllers.slack`) plus the canonical `policy.yaml`. No data migration from 1.62; binary 1.63 and the Pulumi library 1.63 deploy together. **Upgrading:** [upgrade to v1.63](docs/guides/sluis/upgrade/v1.63.md).

### Changed

- **Breaking: one process everywhere.** `sluis serve` is the whole of sluis:
  the issuer, the console, the directory hub and, beside them, the GitHub and
  Slack controllers, each in a loop of its own in the same process. There is no
  separate controller process to deploy: on Kubernetes it is ONE Deployment
  (the chart no longer renders the two controller Deployments), and on AWS
  Lambda it is ONE function (below, in the Pulumi library's entry). The cost is
  accepted: a controller's code runs with the service's permissions and in its
  pod, and a controller that cannot start stops the process.
- **The one service document, `apiVersion: sluis.truvity.github.io/sluis/v3`**
  (`schemas/config/sluis.schema.json`, `sluis serve --config` / `SLUIS_CONFIG`).
  Every key of the v2 `serve` document stays where it was, at the top level,
  and `controllers` is what it adds: `controllers.github` and
  `controllers.slack`, each optional, an absent one being a controller that is
  off. A controller's section holds only what is its own: `consoleURL` (unset is
  `publicURL`), `tokenFile`, `console.auth.aws.audience`, `recordsDir`,
  `appsDir` (GitHub) or `credentialsDir` (Slack) and `interval`. The release,
  the policy, `ports`, `platform`, `preset`, `adapters`, `audit`, `log` and
  `probes` are the process's own, and a controller shares them. `policy.file`
  is required when a controller is named.
  ```yaml
  apiVersion: sluis.truvity.github.io/sluis/v3
  issuerURL: https://access.example
  publicURL: https://access.example/console
  policy: {file: /etc/sluis/policy.yaml}
  secrets: {source: ssm, root: /sluis/example}
  ports: {adapter: dynamodb, dynamodb: {table: sluis}}
  audit: {tokenFile: /var/run/audit/token}
  controllers:
    github: {consoleURL: "http://sluis.access.svc:8080/console", interval: 15m}
    slack: {consoleURL: "http://sluis.access.svc:8080/console"}
  ```
- **N-1.** The binary still loads the v2 `serve` document (and v1, with no
  apiVersion) as this document with no controllers, so `sluis serve` on an
  unchanged document behaves as before. For one release `sluis controller
  github|slack` still run a controller as a process of its own (deprecated, and
  said so in the log), reading either their own v2 documents or the one v3
  document, whose `controllers.<kind>` section they then take; `sluis tick
  github|slack` and `sluis migrate` read either. They are removed in the next
  release.
- **Telemetry.** The one process reports as `access-issuer`: the controllers'
  series no longer carry `github-roster` or `slack-roster` as their service
  name. A dashboard or an alert that selects on those names must stop.
- **Readiness is the whole process.** `/readyz` of the one process is ready
  only once each controller it runs has begun, and a controller that fails to
  start (a refused audit catalogue, an enabled organisation the policy does not
  bind) stops the process, as it stopped the controller before. A controller
  waits for the console, which is its own process, to answer before its first
  pass.

### AWS Lambda and the Pulumi library

- **Breaking: ONE function.** `sluis-http`, `sluis-github` and `sluis-slack`
  are one function from the release zip. It takes API Gateway events (the issuer
  and the console), `{"kind":"tick"|"run","target":"<id>"}` (one pass of one
  target, run by the controller the policy says the target belongs to: the
  GitHub controller's organisations and `github:links`, the Slack controller's
  workspaces; a run-now of an undeclared target ends cleanly, a schedule's tick
  of one fails), and `{"kind":"refresh"}` / `{"kind":"exports"}`. The controllers
  do not loop on Lambda: each pass is assembled for its invocation, as before.
  `SLUIS_ROLE` is retired (a function that still sets it is refused, saying why);
  `SLUIS_CONFIG` names `/opt/sluis/sluis.yaml`. The function's timeout is 300 s
  by default (API Gateway still cuts a request at 30 s) and its memory one
  setting (512 MB). The `invoke` trigger's `github` and `slack` settings name
  this one function, and the library writes them.
- **The library (`deploy/pulumi`, MinPackageVersion 1.63).** `LambdaArgs`:
  `Config` is the one v3 service document (`controllers` included);
  `GitHubConfig`, `SlackConfig`, `HTTP`, `GitHub`, `Slack` and
  `Exports.Function` are gone; `Function` (`MemoryMB`, `TimeoutSeconds`) and
  `FunctionName` (default `FunctionNamePrefix`, so `sluis`) are new. Outputs:
  `FunctionArn`, `FunctionName`, `RoleArn`, `RoleName` replace the
  `HTTP|GitHub|Slack` ones. One role, `<FunctionName>`, with the http role's
  policy and the controllers' needs: credentials and exports read/write, config
  read, the signing keys, `lambda:InvokeFunction` on the function itself,
  `sts:GetWebIdentityToken` (audience-restricted by `WebIdentityAudience`); no
  denials, so the keyring is writable by the one role. The controllers' code runs
  with these permissions: the per-role isolation is gone by decision (S1a). The
  scheduler role may invoke only the function. Kept: reserved instance names, no
  endpoints without `AllowEndpoints`, the `Telemetry.Env` allowlist, the
  release-zip SHA-256 verification, documents held to sluis's loader before
  anything is published, the layer mounted last, every IAM grant under
  `/sluis/<instance>/` (a test holds it, with no `*` but a trailing `/*`).
- **Migrating:** merge the three documents into one v3 document, admit the one role in the policy and the audit
  installation's workload map, and keep `FunctionName: "<prefix>-http"` to replace nothing: [upgrade to v1.63](docs/guides/sluis/upgrade/v1.63.md).

- **Breaking: `NewKubernetesIdentity` makes ONE role for the one pod.** The
  `Serve`, `GitHub` and `Slack` `ProcessArgs` and `ProcessArgs` itself are gone;
  `ServiceAccount` (required) and `Description` are on the args. The role is
  `<prefix>-sluis` (was `<prefix>-sluis-serve`; `-github` and `-slack` are
  gone), with one Pod Identity association for the one ServiceAccount, and the
  outputs are `RoleArn` and `RoleName` (were `ServeRoleArn`, `GitHubRoleArn`,
  `SlackRoleArn` and the names). Its policy is the old serve role's (storage,
  state, signing keys or the wrapped key, with no key-ring denial now that the
  one role signs) and, with the new `Instance` (and `Region`,
  `ParameterKeyArn`), the Lambda role's SSM grants under `/sluis/<instance>/`:
  credentials read/write, config read, exports, the parameter key through SSM
  only. Moving: Pulumi replaces the serve role under its new name and destroys
  the github and slack roles and associations ([upgrade to v1.63](docs/guides/sluis/upgrade/v1.63.md#4-eks-identity-one-role-for-the-one-pod)).

### Chart

- **Breaking: one Deployment.** `controllerGithub` and `controllerSlack` are
  gone, with the Deployments, ServiceAccounts, ConfigMaps
  (`<release>-github-roster-config`, `<release>-slack-roster-config`) and
  PodDisruptionBudgets they rendered. The controllers are
  `config.controllers.github` and `config.controllers.slack` of the one
  service document, and run in the Deployment `<release>`, as its
  ServiceAccount: that account gets the controllers' Role (update, by name, the
  status ConfigMaps and the GitHub links Secret), the token, Apps, credentials
  and records volumes of the controllers named, and an ingress rule that lets the
  pods reach the console through the release's own Service. Policy: `exchange`
  must admit that ServiceAccount (the controllers read the console as it),
  where it admitted `<release>-github-roster` and `<release>-slack-roster`, and
  the audit installation's `workloadIdentity` need map one account.
- **Refused at render:** a controller in `replicaCount` above 1 unless
  `config.ports.adapter` is `dynamodb` (the controllers' tick leases must be in
  a State every replica shares, or every replica acts on every target); a
  controller without `exchange.clusters`, `console.mount` or the console's own
  Service as `consoleURL`; `tokenFile`, `appsDir`, `credentialsDir` or
  `recordsDir` that is not where the chart mounts it.
- The service document the chart renders is `sluis/v3`; the checksum
  annotations are two (`checksum/config`, `checksum/policy`) and a change to a
  controller's section rolls the pod.

#### Removed (chart values)

| Value | Replacement |
|---|---|
| `controllerGithub.enabled`, `controllerGithub.config` | `config.controllers.github` (present is on): `consoleURL`, `interval`, `tokenFile`, `appsDir`, `recordsDir` |
| `controllerSlack.enabled`, `controllerSlack.config` | `config.controllers.slack` (present is on): `consoleURL`, `interval`, `tokenFile`, `credentialsDir`, `recordsDir` |
| `controllerGithub.config.{policy,release,log,ports,platform,preset,adapters,audit,probes}` and the same for Slack | the service document's own keys, which the controllers share |
| `controller{Github,Slack}.{replicas,strategy,minReadySeconds,podDisruptionBudget,resources}` | `replicaCount`, `resources` (the one Deployment's) |

## v1.62.0

Configuration is immutable per instance (ADR 0036): four versioned documents (`serve`, `controller-github`, `controller-slack`, and one canonical `policy`) with `apiVersion` v2, secrets by name from a declared source, SSM layout v3 under `/sluis/<instance>`, and on Lambda the release zip deployed unchanged with the configuration as a layer. Binary 1.62 and the Pulumi library 1.62 deploy together. **Upgrading:** [upgrade to v1.62](docs/guides/sluis/upgrade/v1.62.md).

### Changed

- **Breaking: configuration is four documents, each with an `apiVersion`; the
  policy is one rendered document.** The three service documents (`serve`,
  `controller-github`, `controller-slack`) say how a process runs; the new
  policy document (`schemas/config/policy.schema.json`) says what the
  installation decides, and every service document names it with
  `policy.file`. Each document carries `apiVersion:
  sluis.truvity.github.io/<document>/v2`; this build reads v2 and v1 (no
  apiVersion), converting a v1 document as it loads it through truvity/policy's
  versioned loader, so a deployment can roll the binary first and its
  configuration second. Configuration and policy are read once, at start: a
  change is a new instance. Moved out of the service documents into the policy
  document, as values rather than files:
  - `exchange.clustersFile` → `exchange.clusters`; `exchange.awsFile` →
    `exchange.aws`; `github.owners` → `exchange.github.owners`;
  - `github.runnerTiers` → `apps.github.runnerTiers`; `github.catalogueFile`
    (and the GitHub controller's `catalogueFile`) → `apps.github.catalogue`;
    `slack.catalogueFile` → `apps.slack.catalogue`;
  - the controllers' `enabledOrgs` / `enabledWorkspaces` →
    `controllers.github.enabledOrgs` / `controllers.slack.enabledWorkspaces`;
  - `exports` → `exports`;
  - `policyDir` → `policy.file`, naming the one rendered document.
  `overlayFile` becomes the serve document's `directory.workspaces`. `api`
  (the directory API listener's guard and `consumersFile`) is removed: `sluis
  serve` serves no such listener. A v2 document naming a retired key is
  refused with where it went. The checks the service made at start across
  these (a catalogue grant naming an undeclared group, a Slack App for an
  undeclared workspace, an enabled organisation or workspace the policy does
  not bind, an export of an undeclared App) are the policy document's, run
  wherever it is loaded. A v1 document keeps working until moved
  ([upgrade to v1.62](docs/guides/sluis/upgrade/v1.62.md)).

- **Breaking: a service document names its secrets; `secrets.source` delivers
  them.** A key ending in `Secret` holds a secret's NAME, from the layout of
  docs/decisions/0036: `valkey.passwordSecret` (`valkey/password`),
  `recovery.passwordSecret` (`recovery/password`),
  `signingKey.kms.stateSecret` and `signingKey.kmsWrapped.stateSecret`
  (`issuer/state-secret`), a declared workspace's `keySecret`
  (`directory/<id>/key`), and `oauthClient.provider`, whose two halves are
  `providers/google/<provider>/client-id` and `client-secret`; a confidential
  client's secret is `clients/<client-id>/secret`. `secrets: {source: env |
  file | ssm, root}` says how a name is delivered: `env` reads
  `SLUIS_SECRET_<NAME>`, `file` reads `<root>/<name>` on every use, `ssm` reads
  every parameter under `<root>/private/config/` at once (decrypted, paged)
  and again after `refresh` (5m). Retired, each refused in a v2 document with
  where it went: `valkey.passwordEnv`, `oauthClient.idFile`, `.secretFile`,
  `.secretEnv`, `adminPasswordEnv`, `recovery.passwordFile`,
  `clientSecretsDir`, `signingKey.kms.stateSecretFile`,
  `signingKey.kmsWrapped.stateSecretFile` (the `kms` and `kms-wrapped`
  adapters' setting is `stateSecret` too) and `directory.workspaces[].keyFile`.
  A v1 document keeps reading each secret where it named it.
- **Breaking: SSM layout v3; an installation has one root, `secrets.root`
  (`/sluis/<instance>`).** The `ssm` Secrets adapter takes it from the serve
  document's `secrets.root` (`source: ssm`); naming another root under
  `adapters.secrets.settings` is refused, and with neither the start is
  refused. Two installations share an account by their roots:
  `<root>/private/config/...` (what an operator seeds),
  `<root>/private/credentials/...`, `<root>/export/...`. A v1 document that
  names no root keeps `/sluis` (layout v2) until it moves. The secrets are copied with `sluis migrate
  ssm-layout` first ([upgrade to v1.62](docs/guides/sluis/upgrade/v1.62.md#3-copy-the-configuration-secrets-to-the-instance-root)).
- **Breaking: on Lambda, `SLUIS_CONFIG` names the document; `SLUIS_CONFIG_FILE`,
  `SLUIS_SECRET_FILES` and the `ssm:<path>` variables are retired** and refused
  at start, naming the v1.62 Pulumi library to deploy with: a function the
  v1.61 library deployed does not start on this binary, so the binary and the
  library move together. The secrets are read by the document's `secrets`
  source.

- **Breaking: Pulumi library (`deploy/pulumi`): the release zip unchanged, and
  the configuration as an immutable layer.**
  - `LambdaArgs.PackageSHA256` is required and checked; the functions' code is
    the release zip byte for byte (nothing is added to it). A package older
    than the library (`sluis-lambda_<version>_…zip`, or `PackageVersion`) is
    refused: v1.61 and older cannot read the layer.
  - The three service documents (`Config`, `GitHubConfig`, `SlackConfig`, v2)
    and the policy (`Policy`, a document, or `PolicyPath`, a file or directory
    rendered by sluis's own renderer) are held to sluis's own loader and
    published as one `aws.lambda.LayerVersion` (`<prefix>-config`) mounted
    LAST at `/opt/sluis`; a change publishes a new version and updates the
    functions, and old versions are kept (a rollback is re-pointing). The
    library writes the apiVersion, `policy.file`, `secrets` (`ssm`,
    `/sluis/<instance>`, the region), `recovery.passwordSecret`,
    `recovery.enabled` and the state secret's name; a document that disagrees
    is refused.
  - A function's environment is `SLUIS_ROLE`, `SLUIS_CONFIG=/opt/sluis/<role>.yaml`
    and the telemetry layer's `OTEL_*`; nothing else.
  - New required `Instance`: the SSM root `/sluis/<instance>`. The state secret
    and the recovery password are generated at
    `/sluis/<instance>/private/config/{issuer/state-secret,recovery/password}`
    (same values: the random resources are unchanged). IAM: every function
    reads and writes `<root>/private/credentials/*` and `<root>/export/*` and
    nothing above them; only the http function reads `<root>/private/config/*`
    (by path, for its `secrets` source), which the controllers are denied;
    `ExportReadPolicy` takes the instance and reads `<root>/export/*`. (Before,
    a controller's allow on `/sluis/private` let `GetParametersByPath` reach
    `config/*` past its Deny.)
  - Removed: `Catalogues`, `CataloguePaths`, `Env`, `FunctionArgs.Env`,
    `FunctionArgs.SecretFiles`, `SecretFile`, `ConfigFilePath`,
    `StateSecretPath`, `RecoveryPasswordPath` and
    `WrappedSigningArgs.KeepRemoteSigningKeys`: with `WrappedSigning` the two
    asymmetric keys are no longer declared, and a `Config` naming
    `signingKey.kms` beside it is refused.
  - Refused in the documents the library publishes: any `endpoint`
    (`secrets.endpoint`, `ports.dynamodb.endpoint`, ...), unless
    `AllowEndpoints` (a LocalStack test); an `Instance` named `private` or
    `export`. `Telemetry.Env` holds `OTEL_*`, the telemetry layer's own
    (`ACCESS_ROSTER_*`, `OPENTELEMETRY_*`) and `AWS_LAMBDA_EXEC_WRAPPER`, and
    nothing else. Only the function that runs the exports reads `export/*`;
    with `ParameterKeyArn`, each role may use the key only for the parameters
    under its own prefixes (`kms:EncryptionContext:PARAMETER_ARN`).
  - Moving from `kms` to `WrappedSigning` drops the old key ids from the JWKS at once: it is a step of its own
    ([upgrade to v1.62](docs/guides/sluis/upgrade/v1.62.md#6-retire-the-asymmetric-signing-keys-only-when-moving-from-kms-to-wrappedsigning)).
  - The directory-refresh and exports schedules are unchanged.

### Added

- **`sluisctl policy render <file or directory> [-o <file>]`.** The one place
  layering happens: merges a directory of v1 policy files, access documents
  and policy document fragments (`apiVersion: sluis.truvity.github.io/policy/v2`)
  into the canonical policy document, held to every check the service runs at
  start. A process loads exactly one policy document.
- **`SLUIS_CONFIG`** names the service document when no `--config` is given.

### Chart

- **Breaking: the chart renders the four documents.** `<release>-config`,
  `<release>-github-roster-config`, `<release>-slack-roster-config` and
  `<release>-policy`, at the paths they had (each service document by
  `subPath`, read once at start; the policy as the directory each process
  had for it); each pod carries one checksum per document it reads, so a change to one
  controller's document restarts that controller only, and a policy change
  restarts all three. The clusters, AWS, overlay and catalogue ConfigMaps are
  gone: `exchange.clusters`, `exchange.aws`, `githubApps.catalogue` and
  `slackApps` are rendered into the policy document. `policy` is the policy
  document without its apiVersion (the chart writes it, and the values schema
  holds it to the policy schema).
  The secrets the config names are projected as files under
  `/var/run/sluis/secrets` from the new `secrets` value (`{name, secretName,
  key}`) and each confidential client's Secret (`clients/<id>/secret`), and
  `config.secrets` must be `{source: file, root: /var/run/sluis/secrets}`
  (the default); the `client-secrets` volume and `config.clientSecretsDir`
  are gone. `secretEnv` stays, for `secrets.source: env`.
  A confidential client's Secret key is still `policy.clients.<id>.secretKey`
  (default `client-secret`), projected as `clients/<id>/secret` and left out
  of the rendered policy document.
  `config.policy.file` must be `/var/run/access-issuer/policy/policy.yaml`
  (the controllers': `/var/run/github-roster/policy/policy.yaml`,
  `/var/run/slack-roster/policy/policy.yaml`).
### Removed (chart values)

| Value | Replacement |
|---|---|
| `access`, `overlay` | render the access document first, `sluisctl policy render <dir>`, and pass the result as `policy` |
| `directory.workspaces` (`backend`, `admin`, `secretName`, `secretKey`, `id`, `serve`, `syncGroups`) | `config.directory.workspaces` (`backend`, `admin`, `id`, `serve`, `syncGroups`, `keySecret: directory/<id>/key`), the key projected with a `secrets` entry `{name: directory/<id>/key, secretName, key}` |
| `config.clientSecretsDir` | none: `config.secrets` (`{source: file, root: /var/run/sluis/secrets}`, the default) |
| `config.exchange.clustersFile`, `.awsFile` | `exchange.clusters`, `exchange.aws` (rendered into the policy document), or `policy.exchange` |
| `config.github.*`, `config.slack.catalogueFile`, `config.exports` | `policy.exchange.github.owners`, `policy.apps.github.runnerTiers`, `githubApps.catalogue` / `slackApps` (or `policy.apps`), `policy.exports` |
| `controllerGithub.config.enabledOrgs`, `.catalogueFile`; `controllerSlack.config.enabledWorkspaces` | `policy.controllers.github.enabledOrgs`; the catalogue is the policy's; `policy.controllers.slack.enabledWorkspaces` |
| `config.policyDir`, each controller's `config.policyDir` | `config.policy.file` (`/var/run/access-issuer/policy/policy.yaml`; the controllers' under `/var/run/github-roster/policy`, `/var/run/slack-roster/policy`) |

## v1.61.2

Released automatically as a patch: last-known groups of identities are now kept in the shared State, fixing identity refusals after a cold start on Lambda or during a rollout when the directory cannot be vouched for.

### Fixed

- **Last-known groups live in the shared State, not in process memory, so a new instance finds what the previous one learned.**
  On Lambda or after a rollout that replaces a replica, a fresh instance had no last-known groups and refused every identity while the directory could not be vouched for. They now live under `issuer:held:<identity>` in the State with a lifetime of the hold window (groups and time only); memory is used only when there is no State or it fails.

## v1.61.1

Released automatically as a patch: the Lambda directory snapshot was refreshed on demand and every 15 minutes, fixing sign-in failures after 30 minutes.

### Fixed

- **On Lambda the directory snapshot was never refreshed after the first one, so
  sign-in failed about 30 minutes later ("the directory cannot be vouched
  for…"); it is now refreshed on demand and every 15 minutes by a schedule.**
  A request that finds the snapshot older than the refresh interval refreshes it
  (older than the freshness window: before answering, bounded to 20 seconds, and
  under the refresh lease so instances read a directory once between them), and
  `<prefix>-directory-refresh` invokes the http function with
  `{"kind":"refresh"}` every 15 minutes (`DirectoryRefresh.Rate`, `.Disabled`).

## v1.61.0

kms-wrapped signing (one symmetric KMS key, wrapped data key pairs, free rotation) becomes the AWS presets' default; recovery on Lambda is a Pulumi-generated password in SSM with an off switch; controllers lose access to config/*; GET / redirects to the console.

### Changed

- **A bare `adapters.signing: {adapter: kms}` no longer hides `signingKey.kms`.**
  Naming the adapter with no `settings` used to build it from nothing and stop the
  start with "the kms adapter needs keys and stateSecretFile", though
  `signingKey.kms` was written beside it. An override with no settings of its own
  now takes the settings of `signingKey.<adapter>` (`kms`, `kmsWrapped`) when that
  block is for the same adapter; settings given in the override still win whole.

### Added

- **`kms-wrapped` signing adapter, the default for the AWS presets.** Token
  signing moves from one remote asymmetric KMS key per algorithm to ONE symmetric
  key per estate and data key pairs: the issuer calls
  `kms:GenerateDataKeyPairWithoutPlaintext` (ES384 on `ECC_NIST_P384`, RS256 on
  `RSA_3072`), records the public key and the private key encrypted under the
  symmetric key in its key ring, and signs locally with the key it decrypts
  (`kms:Decrypt`, same encryption context
  `{purpose: sluis-signing, alg, kid}`) into process memory. Rotation is
  automatic and free: a new pair per algorithm every `rotateEvery` (24h), under
  the State lease `lease.signing-keygen:<alg>`, published for `prepublish` (15m,
  longer than a verifier caches the JWKS) before it signs and kept for `retain`
  (`lifetimes.token` + 5m) after it is replaced. Configure it with
  `signingKey.kmsWrapped: {keyId, stateSecretFile, algorithms, rotateEvery,
  prepublish, retain}` or `adapters.signing`. `aws-serverless` and `aws-hybrid`
  now default to it; `kms` (remote signing, non-extractable keys) stays
  selectable and unchanged, and so does `aws-eks`. **Trade-off:** wrapped keys
  are decrypted into memory, so a leaked signing role can forge offline for as
  long as the keys are published, and write access to the State (the key ring)
  is part of the trust boundary; the key policy must reserve the signing context
  to the signing roles (the library does it for the key it creates; a shared
  `KeyArn` needs the denial merged in). EdDSA is not supported yet. See
  [Signing on AWS](docs/concepts/sluis/signing-on-aws.md). A deployment that
  names `signingKey.kms` or `signingKey.file` keeps what it names.
- **Pulumi library: `LambdaArgs.WrappedSigning`.** One symmetric key (created
  with rotation enabled, protected, and a key policy that denies every principal
  but the signing roles any use of the signing context and holds those roles to
  `kms:EncryptionContext:purpose = sluis-signing` and no context keys beside
  `purpose`, `alg`, `kid`; an existing, possibly shared, `KeyArn` must carry the same denial,
  `WrappedKeyPolicyStatements`), a grant of only
  `kms:GenerateDataKeyPairWithoutPlaintext` and `kms:Decrypt` on it with those
  conditions to the http function, and no asymmetric keys unless
  `KeepRemoteSigningKeys`. The github and slack roles may not write the key ring
  items (with any signing). `KubernetesIdentityArgs.WrappedSigningKeyArn` grants the serve role the
  same.

- **Recovery on Lambda: a generated password, kept in SSM, with an off switch.**
  `sluispulumi.NewLambda` now generates the recovery password (`random.RandomPassword`,
  40 characters, no look-alikes), stores it as the SecureString
  `/sluis/private/config/recovery/password`, writes it to `/tmp/sluis/recovery-password`
  for the http function at cold start (the library names it as the new
  `recovery.passwordFile`) and exports its NAME as `RecoveryPasswordParameter`, never the
  value. `LambdaArgs.Recovery{Enabled *bool}` writes `recovery.enabled`; the default is
  **on**, because a first installation has no other way in; turning it off keeps the
  parameter and the file, refuses the sign-in with a message, and turning it on again
  rotates nothing. Before this a Lambda generated a different password at every cold
  start and printed it to the function's log. Every recovery attempt on the console,
  refused ones too, is now the audit event `roster.recovery.signed_in` (outcome
  `denied` or `failure` with the reason, actor `anonymous`); the catalogue is unchanged.
  The setup checklist's step "Turn off the recovery password" names the setting and the
  parameter. See [Recovery on Lambda](docs/guides/sluis/operate/recover-on-lambda.md).

- **`GET /` on the issuer's host redirects to `/console/`** (302, HEAD too) when the
  console is mounted, instead of the issuer's bare 404. Only the exact path: every
  other route keeps its handler.

## v1.60.0

Storage layout v2 moves DynamoDB items to a per-kind table partition, SSM configs to a /config prefix, and exports to Secrets; re-migrate from legacy.

### Changed

- **Layout change for the non-legacy adapters (storage layout v2): re-migrate from legacy.**
  What the `dynamodb`, `ssm` and Secrets-port adapters write is now clear and
  consistent ([storage layout](docs/reference/sluis/storage-layout.md)). A record has a
  kind and an id: DynamoDB `pk` is the kind (`directory`, `github-org`, `slack-workspace`,
  `issuer-token`, `lease`, `keyring`, ...) and `sk` its id (`google/C01ipl6j0`,
  `stable/acme`), where there were three conventions in one table; a credential
  is `/sluis/private/credentials/<kind>/<id>/<ref>`, where it was
  `/sluis/private/private/<key>/<ref>`; and the operator's secrets are
  `/sluis/private/config/...` (`config/oauth/client-id`, `client-secret`,
  `config/clients/<id>`, and the Pulumi-generated `config/issuer/state-secret`, now
  `StateSecretParameterName` under `ConfigParameterPrefix`). The mapping is one table
  (`internal/port/keys.go`); the legacy adapter and its key names are unchanged, and
  `sluis migrate` writes layout v2. **Consequence:** data written by an earlier
  non-legacy build is not found at its old place. There is no in-place relayout:
  empty the table and the `/sluis/private/credentials` prefix and migrate again from
  legacy. A deployment moves its `<NAME>=ssm:/sluis/private/oauth/...` environment
  mappings and `SLUIS_SECRET_FILES` entries to the `config/` names. IAM is unchanged.
  A directory workspace's State key gains its provider, `ws.dir.<provider>.<id>`
  (the record's backend), so that another identity directory is a provider and not a
  new kind.

### Added

- **Exports are written through the Secrets port.** With a Secrets adapter configured
  and `ports.export` unset, an export is the secret `export/<path>` (SSM
  `/sluis/export/<path>`), one JSON object of the export's properties, so ESO's SSM
  provider reads a property with `remoteRef.property`; the `exports` event on Lambda
  writes there. `ports.export: openbao` keeps working. The property names of each source
  are in the storage layout reference.

## v1.59.1

Released automatically as a patch: the declared OAuth client is read off-cluster, so the issuer on Lambda can open the Google Workspace directory.

### Fixed

- The OAuth client declared by `oauthClient.id` / `idFile` and `secretFile` / `secretEnv` is now read.
  Off-cluster (Lambda included) the issuer had no Google OAuth client, so the Google directory
  could not be opened and every sign-in was refused. Declaring it both ways (with `secretName`)
  is refused at start, as is a half-declared client or an unreadable file.

## v1.59.0

On Lambda, the GitHub and Slack controllers authenticate to the console with their role's AWS web identity token (a console audience of its own), and exports run on a schedule.

## v1.58.0

sluis runs on AWS Lambda (three functions from one zip) with DynamoDB state, SSM secrets, KMS token signing (ES384 and RS256), S3 blobs and SQS audit; adapters are chosen by name from presets; the sealer and the NATS adapter are removed.

- **The Lambda controllers authenticate to the console, and the exports keep running.**
  A controller's console client can present the function role's AWS outbound web
  identity token (`sts:GetWebIdentityToken`, one audience, cached until two minutes
  before expiry) instead of a projected ServiceAccount token: set
  `console.auth.aws.audience` in the controller's file, which must equal the issuer's new
  `console.awsAudience` (default `<issuerURL>/console`): the console and token exchange
  are two doors with two audiences, so a token minted for one is no proof at the other.
  The token is re-minted every four minutes, because the issuer refuses one whose `iat`
  is older than its `maxAge`. The console's workload door now accepts an AWS
  role as it does a cluster's ServiceAccount, and the policy's `aws` matchers decide
  what it may do (an `aws` matcher with no role admits every role of the account, and
  the issuer now warns at start). The `http` function also answers `{"kind":"exports"}` from a
  schedule: one pass of every export, each under its lease, failing the invocation if
  a copy could not be made. Kubernetes behaviour is unchanged. See
  [aws-lambda](docs/reference/sluis/lambda.md).

- **The Pulumi library creates a second signing key, RS256.** `NewLambda` makes an
  `RSA_3072` `SIGN_VERIFY` key beside the ES384 one (alias `SigningKeyRS256Alias`,
  default `alias/sluis-signing-rs256`; `DisableSigningKeyRS256` leaves it out) and
  outputs `SigningKeyRS256Arn`, `SigningKeyRS256ID` and `SigningKeyRS256Alias`. Only
  the `sluis-http` role may `kms:Sign` and `kms:GetPublicKey` with it.
  **Breaking:** `KubernetesIdentityArgs.SigningKeyArn` is now `SigningKeyArns`, a list.
  A caller's next apply creates the key.
  Also: an exports schedule (`Exports`: `<prefix>-exports`, default every 15 minutes,
  invoking `sluis-http` with `{"kind":"exports"}`, the function configurable);
  `sts:GetWebIdentityToken` on the github and slack roles (`WebIdentityAudience`
  restricts the audience); and `SLUIS_SECRET_FILES` per function (`SecretFiles`; the
  http function always lists the state secret at `/tmp/sluis/state-secret`).

- **KMS-backed RS256.** `signingKey.kms.additional: [{alg: RS256, keys: [...]}]` signs RS256
  with `RSA_2048`, `RSA_3072` or `RSA_4096` KMS keys beside the ES384 ones, for relying
  parties that need it (Kargo, EKS's OIDC provider); a client or resource pinned to
  `signing_alg: RS256` is signed by that ring. `RSASSA_PKCS1_V1_5_SHA_256` over a SHA-256
  digest, every signature verified before it is returned, kid the RFC 7638 thumbprint, each
  algorithm rotating on its own track by the same rules. The role needs `kms:Sign` and
  `kms:GetPublicKey` on both keys.

- **The Audit page's query URL no longer needs `audit.writer`.** `audit.queryURL` is its
  own setting, so the console's Audit page works with the `sqs` and `log` audit sinks, which
  have no receiver (the Lambda target state). The console already forwards the page's calls
  server-side, so the query host needs no CORS; a base URL with a path prefix
  (`https://audit.example.org/sluis`) is kept and the procedure path appended.

- **`sluis migrate` moves a whole installation to AWS.** By default it copies the State
  records, the secrets (to the Secrets port), the controllers' reports (to S3) and the
  issuer's key ring schedule, and leaves the issuer's sessions, refresh tokens, codes in
  flight and Index sets behind (`--with-sessions` copies them); `issuer:kms:*` is never
  copied. `--dry-run` validates sizes against the State and Secrets limits and key
  validity, prints a summary per concern and exits non-zero if anything would be
  refused (so does a real run, before it writes). `--kubeconfig`, `--kube-context` and
  `--namespace` read the legacy namespace from a workstation. The runbook has a "Cutover:
  migrating an installation" section.

- **Deployment guides and a generated adapter matrix.** `docs/guides/choosing-a-deployment.md`
  opens with the decision tree and modifiers, then the presets and support levels
  (`aws-hybrid` is the implemented, maintained path); `docs/guides/diy-adapter.md` is the
  fixed checklist for adding an adapter in a fork. `docs/reference/sluis/adapters.md` is
  generated from the adapter registry and the preset table by `just adapters-doc`;
  `just docs-check` fails when it is stale.

- **Audit records can go to an SQS queue.** The `audit` concern gains the `sqs` adapter
  (needs AWS; Kubernetes and Lambda runtimes): `adapters.audit: {adapter: sqs, settings:
  {queueURL, region, endpoint, timeout}}`, which the `aws-*` presets also name. The sink
  is now chosen from the resolved table: `connect` is the legacy `audit.writer` mapping
  and does not change, `log` keeps the log line only. On `sqs` there is no receiver, so
  the catalogue registration is skipped (no error, no retry; logged once) because the
  catalogue is delivered in the audit writer's package. A `block` action returns once
  SQS has the message; async actions never block a sign-in. On Lambda the trail is
  synchronous, waiting at most 3 seconds for the send and not waiting at all after a
  failed one, and `Trail.Flush` is there for a handler to call before it returns. The
  process needs `sqs:SendMessage` on the queue. See `docs/design/ports.md`.

- **sluis runs as AWS Lambda functions.** One arm64 `bootstrap` in one zip, deployed
  as three functions chosen by `SLUIS_ROLE`: `http` (the issuer and the console behind
  an API Gateway HTTP API, payload format 2.0, into the same `net/http` mux the server
  serves), and `github` and `slack` (one pass of one target per invocation, under the
  target's lease in DynamoDB). Events: `{"kind":"tick","target":"<id>"}` from an
  EventBridge Scheduler schedule and `{"kind":"run","target":"<id>"}` from the `http`
  function; a second invocation for a held target returns `contended` and succeeds.
  "Run now" is the new `invoke` adapter of the `trigger` concern (an asynchronous
  Lambda invoke; `Subscribe` is unused), and `eventbridge` is described for the
  `schedule` concern. The configuration is a file in the zip (`SLUIS_CONFIG_FILE`,
  default `/var/task/config/sluis.yaml`); an environment variable whose value is
  `ssm:/sluis/private/...` (or `/sluis/export/...`) is read from SSM Parameter Store at
  cold start, so a `*Env` secret is never in the file; `SLUIS_SECRET_FILES` (a JSON array of `{"parameter","path"}`) writes parameters to files under `/tmp` (0600) at cold start, so every `*File` setting works unchanged on Lambda. The release attaches
  `sluis-lambda_<version>_linux_arm64.zip` (`bootstrap` at its root, about 50 MB, 14 MB
  zipped; the Kubernetes binary is about 80 MB). The binary is built with
  `-tags lambda,lambda.norpc`, which leaves out client-go, NATS and Valkey, and
  `cmd/sluis-lambda/imports_test.go` fails on any of them. The controllers' configuration files gain the serve file's `platform`, `preset` and
  `adapters` keys (the Lambda controllers select `sqs` audit through them). **No change
  to the Kubernetes build.** See [aws-lambda](docs/reference/sluis/lambda.md).

- **Removed: sluis's own OTLP Lambda extension.** `cmd/sluis-lambda` used to be the
  extension installed as `extensions/access-roster-otlp`, deprecated in v1.57.0 for
  `truvity/observability`'s `otlp-lambda` layer. Nothing in an estate's GitOps repository or
  deploy repository deploys it, so the extension and the `sluis-lambda-layer_*` assets are
  gone and `cmd/sluis-lambda` is the function's composition root. The layer is the only
  telemetry layer; sluis ships none.

- **The `ssm` secrets adapter.** `internal/port/ssm` keeps `port.Secrets` in AWS SSM
  Parameter Store as SecureString parameters (the AWS-managed key, or `kmsKeyId`).
  A port path `p` is `/sluis/private/<p>`, and a path under `export/` is
  `/sluis/export/<rest>` (the root is the `root` setting), so a consumer's ESO can be
  granted `/sluis/export/*` alone. Versions are SSM's parameter versions; the tier
  is Intelligent-Tiering (advanced only for a value over 4 KiB). Creating ("only if
  absent") is atomic; `PutIfVersion` with a version is a read and a write, **not
  atomic** (last writer wins), safe because the target lease serialises the
  writers. The adapter is registered (AWS, kubernetes and lambda) and the secrets
  concern is now wired from the plan: a chosen adapter is `Set.Secrets`. With
  nothing chosen (every deployment today) nothing changes. IAM and the layout:
  `docs/design/ports.md`.

- **Removed: the NATS adapter and the KMS sealer.** Configs that name `ports.adapter: nats`,
  `ports.nats` or `ports.sealer` are refused. Sealing is retired entirely: the `Sealer`
  port, `internal/port/kmsseal`, the envelope code (`port.Seal`, `port.Open`) and the
  `sluis:binding` encryption context are gone, and so is `internal/port/nats` with its
  registration, chart test cases and documentation. A dynamic secret (a workspace
  credential, an App key, a link's token pair, the console's session key) is now
  written to the Secrets port under `private/<key>/<ref>`, and the record in State only
  names it; State never holds one. **Behaviour change for a non-`legacy` adapter:** it
  needs a Secrets adapter (`memory` has one; the `ssm` adapter follows), and start is
  refused naming it without one. A credential is written under a fresh ref and the
  one it replaces is removed, so a writer that loses a compare-and-swap never
  replaces the winner's secret. The chart accepts `replicas` above 1 only with
  `ports.adapter: dynamodb` now. `legacy` (which never sealed), Valkey, `Index`,
  `dynamodb`, `s3`, `memory`, file signing keys and the Export port are unchanged.
  The `nats` ADR records and the sealing ADR carry a superseded note.

- **Adapters are chosen by name, per concern.** `internal/port` gains an adapter registry:
  each adapter registers a descriptor (name, concern, what it needs of AWS, Kubernetes
  and OpenBao, the runtimes it works on, implemented or on request, and a factory from
  its settings), and a static catalogue lists the planned adapters, so the
  compatibility matrix is generated from the registry. The serve configuration takes
  an optional `platform` block (`aws`, `kubernetes`, `openbao`, `runtime`, `replicas`),
  an optional `preset` (`server`, `k8s-minimal`, `k8s-openbao`, `aws-serverless`,
  `aws-hybrid`, `aws-eks`) and per-concern `adapters`; an explicit adapter beats the
  preset, which beats the preset the answers derive. **No behaviour change without the
  new keys:** `ports.adapter` (`legacy` by default) and `ports.blob` map onto the same
  table. Start now refuses an adapter that needs a platform answer that is false, cannot
  run on the runtime (`legacy` on Lambda), is `memory` with more than one
  replica, or is planned and not built, then logs the resolved table once and exposes
  `sluis_adapter_info{concern,adapter}`. Also a `Secrets` port (`Get`, `Put`,
  `PutIfVersion`, `Delete`, `List`; exports under `export/`) with a `memory` adapter and
  a `porttest.RunSecrets` conformance suite. See `docs/design/ports.md`.

- **The Pulumi library deploys sluis on AWS Lambda.** Both estates (one on Kubernetes and
  one on AWS Lambda installations) move sluis to Lambda, and `deploy/pulumi` now expresses it
  ([guide](docs/reference/sluis/pulumi-library.md#lambda)):

  - `NewLambda` creates three functions from one released zip (`sluis-http`,
    `sluis-github`, `sluis-slack`; arm64, `provided.al2023`, handler `bootstrap`,
    no VPC), told apart by `SLUIS_ROLE`. The library adds the estate's
    configuration at `config/sluis.yaml` (`SLUIS_CONFIG_FILE`) and the catalogue
    files at `config/<name>` to the zip, so a change to either changes the package
    and redeploys.
  - **One IAM role per function.** All three get DynamoDB, S3, SSM under
    `/sluis/private/*` (read, write, delete), writes under `/sluis/export/*`,
    `sqs:SendMessage` on the audit ingest queue and logging; only `sluis-http`
    gets `kms:Sign`, `kms:GetPublicKey` and `lambda:InvokeFunction` on the
    controllers. `ExportReadPolicyJSON` is the policy a consumer's External
    Secrets Operator role attaches: read on `/sluis/export/*` and nothing else.
  - An HTTP API (payload 2.0) behind a custom domain with mutual TLS and a
    truststore the library uploads to a bucket of its own, with the default
    `execute-api` endpoint disabled unless `API.KeepDefaultEndpoint` is set (for
    the cutover's acceptance run).
  - One EventBridge schedule per GitHub organisation and Slack workspace,
    invoking the controller with `{"kind":"tick","target":"<id>"}` through a
    scheduler role that may invoke only those two functions.
  - The three functions' configuration files go in the package as
    `config/sluis.yaml`, `config/github.yaml` and `config/slack.yaml`
    (`Config`, `GitHubConfig`, `SlackConfig`), each function's `SLUIS_CONFIG_FILE`
    naming its own, as the Lambda app reads them. The issuer's OAuth-state secret is
    generated (32 random bytes, an SSM SecureString at
    `/sluis/private/issuer/state-secret`, output `StateSecretParameter`). The roles
    also get `dynamodb:UpdateItem` (the leases).
  - A new token-signing KMS key (`ECC_NIST_P384`, `SIGN_VERIFY`, alias default
    `alias/sluis-signing`), and an optional observability `otlp-lambda` layer.
  - **Breaking: the Sealer's KMS key is removed.** `NewStorage` no longer creates
    the key and its alias, and `StorageArgs.KeyAlias`, `KeyDescription`,
    `DefaultKeyAlias`, `Storage.KeyArn`, `KeyID`, `KeyAlias`, `StorageGrant.KeyArn`
    and `BindingContextKey` are gone; the roles no longer grant `kms:Encrypt` and
    `kms:Decrypt` on it. A caller's next apply therefore schedules the key's
    deletion (30-day window). The key and its alias are protected, so run
    `pulumi state unprotect` on both URNs first or the apply refuses.
    `PortsArgs.KeyID` is optional and an empty one renders no `sealer:` block.
  - `NewKubernetesIdentity` takes an optional `SigningKeyArn`, which only the
    serve role may sign with. EKS Pod Identity is otherwise as it was.

- **Sign with AWS KMS.** `signingKey.kms` (`keys`, `region`, `stateSecretFile`) makes the
  issuer sign ES384 tokens with `ECC_NIST_P384` KMS keys: the private key never leaves
  KMS. Exclusive with `signingKey.file`, which stays the default. Keys are listed oldest
  first and the last signs; the `kid` is the RFC 7638 thumbprint, rotation is appending a
  key and rides the existing `pollInterval`, `activationDelay` and `overlap`. The role
  needs `kms:Sign` and `kms:GetPublicKey`; signatures are counted by key in
  `access_issuer.kms_signatures`. See
  [Signing with AWS KMS](docs/guides/sluis/operate/sign-with-aws-kms.md). The chart
  does not render this yet.

- **The GitHub and Slack controllers roll safely.** The chart fixed each controller at
  one replica with `strategy: Recreate`, so a release whose pods crashed at start
  (sluis 1.57.0, 2026-10-04) deleted the running controller first and left it down for
  about 15 minutes, while the `serve` Deployment kept its old pods. Now:

  - `controllerGithub` and `controllerSlack` take `replicas` (default 1), `strategy`
    (default `RollingUpdate`, `maxUnavailable: 0`, `maxSurge: 1`), `minReadySeconds`
    (default 10) and `podDisruptionBudget` (rendered when `replicas` is above 1).
    A new pod must be Ready before an old one is removed. **Behaviour change:** a
    deployment that relied on `Recreate` sets `strategy.type: Recreate`; with the
    `legacy` adapter the new pod's first pass can overlap the old pod's last for a few
    seconds.
  - The controllers serve `/healthz` and `/readyz` on `probes.address` (default
    `:7070`), and the chart probes them. Ready means the process finished starting:
    the policy loaded, the stores open, the audit catalogue accepted.
  - More than one replica is refused at render unless the controller's
    `ports.adapter` is `nats` or `dynamodb`. With `legacy` or `memory` the tick leases
    are in each pod's memory and every replica would act on every target.
  - See [the runbook](docs/guides/sluis/operate/check-health.md#2-a-rollout-that-does-not-complete)
    and [high availability](docs/concepts/sluis/high-availability.md#the-controllers-in-the-one-process).

## v1.57.1

Released automatically as a patch: the roster audit catalogue bumped to 1.7.0 after its document changed in 1.57.0.

- **Fixed: the audit catalogue is now version 1.7.0.** v1.57.0 renamed the
  product through every file, including `internal/audit/catalogue/roster.yaml`
  and its released fixtures, so the document changed (three descriptions say
  `sluis` where they said `access-roster`) while its version stayed `1.6.0`.
  An audit installation refuses a changed document under a registered version,
  and every sluis process stopped at start with `roster version 1.6.0 is
  already registered with a different document`. The source stays `roster`;
  renaming it is catalogue 2.0.0. The released fixtures 1.0.0 to 1.6.0 are
  restored to the bytes of v1.54.0, and `TestAReleasedFixtureIsNeverRewritten`
  pins each fixture's SHA-256 in `testdata/released/SHA256SUMS`, so a sweeping
  edit can no longer rewrite a released document and its fixture together.

## v1.57.0

- **Deprecated: the Lambda extension layer (`sluis-lambda-layer`).** The
  extension moved to `truvity/observability`
  (`github.com/truvity/observability/lambdaext`, v0.47.0), which releases it as
  `otlp-lambda-layer_<version>_linux_<arch>.zip`. This release still builds
  `sluis-lambda-layer_<version>_linux_<arch>.zip`, from that package, so a
  consumer can switch; it is dropped in the release after this.
  `internal/lambdaext` is removed from this module. The protocol is unchanged,
  and `SLUIS_*` settings work alongside the `ACCESS_ROSTER_*` ones.

- **Breaking: renamed to sluis.** The product is now **sluis** and the
  repository `truvity/sluis` ([ADR 0035](docs/decisions/0035-renamed-to-sluis.md)).
  This ships as a minor release (v1.57.0, no `/v2`) by
  [ADR 0007](docs/decisions/0007-breaking-changes-inside-1x.md). It lands only
  after the GitHub rename, because the new module path resolves only then.
  What a consumer changes:

  - **Go module path:** `github.com/truvity/access-roster` becomes
    `github.com/truvity/sluis` (packages `policy`, `identity`, `tokens`; the
    `deploy/pulumi` library already was `github.com/truvity/sluis/deploy/pulumi`).
    Change every import and `go get github.com/truvity/sluis@v1.57.0`.
  - **Images:** `ghcr.io/truvity/access-roster/access-roster` becomes
    `ghcr.io/truvity/sluis/sluis`, and `ghcr.io/truvity/access-roster/resource-proxy`
    becomes `ghcr.io/truvity/sluis/resource-proxy`. The server binary is `sluis`
    (it was `access-roster`), and the chart mounts its files at `/etc/sluis/`.
  - **Chart:** `oci://ghcr.io/truvity/charts/access-roster` becomes
    `oci://ghcr.io/truvity/charts/sluis`; the chart is named `sluis` and its
    helpers `sluis.*`. `nameOverride` and `fullnameOverride` are honoured as
    before: an installation that sets them (the estate sets both to
    `access-issuer`) keeps every object name and every Deployment selector.
    An installation that relied on the defaults now has to say what it relied
    on (`fullnameOverride`, `nameOverride`, and `config.release: access-roster`
    for the store prefix), because the default `release` is now `sluis`.
  - **CLI:** `accessctl` is now **`sluisctl`**; release assets are
    `sluisctl_<version>_<os>_<arch>` and the Nix flake `sluisctl`. `accessctl`
    is kept as an alias for one or two releases: `accessctl_*` archives and an
    `accessctl` flake carry the same program, which prints a deprecation notice
    on stderr. Its settings are `SLUISCTL_*` (the `ACCESSCTL_*` names still
    work). The OIDC client id `accessctl`, the config and cache directory, the
    kubeconfig user names and the managed known-hosts file are unchanged.
  - **Release assets:** `sluis_<version>_checksums.txt`,
    `sluis_<version>_<os>_<arch>` for the service, and the deprecated Lambda
    layer `sluis-lambda-layer_<version>_linux_<arch>.zip`.
  - **KMS sealing context:** the encryption-context key is `sluis:binding`
    (it was `access-roster:binding`). Nothing is sealed anywhere yet, so
    nothing needs re-wrapping; a KMS grant that names the key must say
    `sluis:binding`.
  - **OpenBao names:** `access-roster-backup/<bundle>` becomes `sluis-backup/<bundle>` and the role `access-roster-writer` becomes `sluis-writer` in examples and defaults; the estate sets its paths explicitly. Neutral paths (`slack-apps/*`, `arc/*`, ...) are unchanged.
  - **Environment:** the Lambda extension reads `SLUIS_*` first and falls back
    to `ACCESS_ROSTER_*` (both work, `SLUIS_*` wins); `sluisctl` does the same
    for `SLUISCTL_*` and `ACCESSCTL_*`
    ([aws-lambda](docs/reference/sluis/lambda.md),
    [sluisctl](docs/reference/sluis/sluisctl.md)).
  - **npm:** `@truvity/access-roster` becomes `@truvity/sluis`. The release also
    publishes the same build as `@truvity/access-roster` for one or two
    releases, described as deprecated.
  - **Schemas:** the `$id` of the configuration schemas is
    `https://truvity.github.io/sluis/schemas/v1/config/...`.

  What did **not** change, on purpose: the issuer URL and every OIDC client id;
  the group names `all:access-roster:*` and the `groups: [access-roster]` thing;
  the Kubernetes label and annotation keys `access-roster.truvity.github.io/*`;
  `token-source: access-roster`, the `ACCESS_ROSTER_ISSUER` variable and the
  grants preset `access-roster`; the audit source `roster`; metric, alert and
  dashboard names and OTEL `service.name` (they change with the dashboards, at
  B5). The full list is in the ADR.

## v1.56.1

Released automatically as a patch by a workflow_dispatch of Auto Release; it carries a feature (the Pulumi library) that would normally be a minor.

- **A Pulumi library for the AWS part of an installation:
  `github.com/truvity/sluis/deploy/pulumi`.** A Go module of its own (Pulumi is
  not in the root's dependency graph; the release tags it
  `deploy/pulumi/vX.Y.Z`) with three components: `Storage` (the blob bucket, the
  Sealer's KMS key and alias), `State` (the DynamoDB table of the DynamoDB
  adapter) and `KubernetesIdentity` (one EKS Pod Identity role per process:
  serve, the GitHub controller, the Slack controller, each with the storage and
  table grants and nothing else), and `RenderPorts` for the `ports:` block,
  validated in its tests against the binaries' schemas. The KMS grant admits the
  encryption-context key `sluis:binding` only, so it needs a service release
  whose Sealer sends that key. Tested with Pulumi's mocks (`just pulumi-test`).
  [docs/deployment/aws.md](docs/reference/sluis/pulumi-library.md).

## v1.56.0

- **A longer absolute session for a read-only resource: `absolute_cap` and
  `read_only` on a policy resource.** The 24-hour absolute limit of
  [ADR 0001](docs/decisions/0001-sessions-and-an-absolute-limit.md) made every
  connector sign in again daily. A resource that declares `read_only: true` may
  now carry `absolute_cap` up to `168h`
  ([ADR 0033](docs/decisions/0033-a-longer-absolute-limit-for-read-only-resources.md)).
  A refresh chain's limit is the shortest among the resources it was used for,
  the client's own audience and an uncapped resource counting as
  `lifetimes.absolute`; it is enforced at refresh, at a silent `/authorize` and
  in the access token's `exp`. Refused: a cap above 168h, zero or negative, and
  (at start) one above `lifetimes.absolute` without `read_only`. Sign-out,
  removal and refresh-token reuse end the chain as before, and a cap withdrawn
  from the policy shortens it at its next refresh. `lifetimes.refresh` (default
  `12h`) still bounds a chain's idle time, so the seven days need it raised to
  match. Nothing changes for a resource that sets neither field.

- **Exports: the service copies the secrets it keeps into OpenBao itself.** With
  `ports.adapter` other than `legacy` the service writes no Kubernetes Secret, so the
  External Secrets `PushSecret`s that copied them into OpenBao (a Slack App's bot
  token for Alertmanager, the runner Apps for ARC, seven recovery bundles) had
  nothing to read. A new port, `port.Export` (`Put` in `replace` or `patch` mode,
  and `Delete`), with a memory adapter and an OpenBao KV version 2 adapter
  (`internal/port/openbao`: Kubernetes or JWT login inside each namespace, a JSON
  merge patch for per-property copies, nothing written when the key already holds
  the data), and `internal/exports`, which runs the copies. `ports.export` names
  the OpenBao and how to log in; `exports:` lists what is copied (`slack-app`,
  `github-app`, `runner-app`, or one of the seven `bundle`s) and where, under the
  property names the PushSecrets wrote, and the seven bundles are the Secrets'
  entries byte for byte. Validated at start: an unknown source, an App or tier the
  deployment does not declare, and two exports that would write one key stop the
  service. Each export is made once at start, again on a change to its source and
  every hour, under a lease so only one replica writes, retried with backoff, and
  never on the path of a sign-in, a tick or a console action: an OpenBao that is
  down changes nothing live. Metrics `access_roster.export.attempts`, `.duration`,
  `.last_success_timestamp` and `.contended`; alerts `AccessRosterExportFailing` and
  `AccessRosterExportStale`; a dashboard row. The chart mounts the CA
  (`exports.openbao.caBundle`) and projects the token the login presents
  (`exports.openbao.token.audience`), refusing a `caFile` or `tokenFile` anywhere
  else. The `push` values are kept for the `legacy` storage and are deprecated. The
  OpenBao role needs `read`, `create`, `update` and `patch` on
  `kv/data/<prefix>/*`. Marked 🧪 in the capabilities. Installations without
  `exports` see no change. See
  [docs/decisions/0034](docs/decisions/0034-exports-go-to-openbao-directly.md) and
  [docs/reference/sluis/configuration.md](docs/reference/sluis/exports.md).

## v1.55.0

This release adds a DynamoDB adapter for State, the session index and the Trigger. Installations on `ports.adapter: legacy` see no change.

- **A DynamoDB adapter for State, the session index and the Trigger:
  `ports.adapter: dynamodb`.** `internal/port/dynamodb` keeps them in one table
  (`pk` the key's first segment, `sk` the whole key, TTL on `expires`) with the
  platform's credentials, so a Kubernetes deployment on AWS, or a Lambda one, shares
  State across replicas as the NATS adapter does. Writes are conditional on a
  random 64-bit revision (an identical rewrite changes it and a delete-and-recreate
  cannot be mistaken for no change), reads are consistent and filter expiry
  themselves, and a `Create` takes an expired record at once. `Watch` and the
  Trigger poll (one second); the lambda-invoke Trigger of ADR 0029 stays a separate
  adapter. `ports.dynamodb.{table,region,endpoint,create}`: `create` is off by
  default so production binds to the table the infrastructure code made. It passes
  the whole conformance suite, with the other ports' assertions skipped and named,
  over a fake in `go test ./...` and over LocalStack in the `s3` CI job, which fails
  on any other skip, and `access-roster migrate` copies memory into it and back.
  Marked 🧪 in the capabilities: not yet run against AWS. Installations on any other
  adapter see no change. See
  [docs/design/ports.md](docs/reference/sluis/port-adapters.md#the-dynamodb-adapter).

## v1.54.0

This release adds the NATS JetStream KV, S3 Blob and KMS Sealer port adapters; the domain stores on the ports, with secrets sealed per key; GitHub link refresh as one compare-and-swap; the Slack Connect hand-off and the `users.info` cache; the `access-roster migrate` tool, with sessions copied and lifetimes kept; and the chart's `telemetry.otlp` value. Installations on `ports.adapter: legacy` see no change.

- **The chart sets the OpenTelemetry environment: `telemetry.otlp`.** With
  `telemetry.otlp.endpoint` set, every pod of `renders: app` gets
  `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL` (`protocol`,
  `http/protobuf` by default), an `OTEL_SERVICE_NAME` of its own (`access-issuer`
  for `serve`, `github-roster`, `slack-roster`, the names the binary already
  uses) and each `extraEnv` entry. Without an endpoint nothing is rendered, so the
  installed objects are unchanged (policy ADR 0006). The chart refuses an endpoint
  that is not an http(s) URL, an `extraEnv` name not starting with `OTEL_`, and
  `OTEL_EXPORTER_OTLP_ENDPOINT` in `extraEnv`. Without it the alerts and the
  dashboard had no data. See
  [docs/reference/sluis/telemetry.md](docs/reference/sluis/telemetry.md#wiring-it-with-the-chart).

- **`access-roster migrate --from <config> --to <config>`** copies the State from
  one storage to another (ADR 0031): the first step of the move, ConfigMaps,
  Secrets and Valkey to NATS, and the rollback the other way round. Each end is a
  `serve` configuration file. Every domain store (workspaces and credentials,
  GitHub organisations, Apps and links, Slack workspaces, Apps and channel
  records, confirmations and requests for a pass, the console's session key) is
  copied through its business interface, so a secret is sealed under the
  destination's Sealer; the issuer's sessions, refresh tokens, SSO and keyring
  schedule are copied with the lifetime each has left, so nobody signs in again.
  A plan runs first and writes nothing: a destination value that differs fails
  the run naming the key unless `--overwrite`; `--dry-run` stops there. A run that
  writes needs `--i-have-stopped-writers`. It then reads both sides again and
  compares every item, and prints a JSON report of counts and keys (never a
  value), also to a Blob with `--report-blob`. Re-running completes a partial
  copy. See [docs/operations/migrate.md](docs/guides/sluis/migrate/migrate-state.md). Adds the
  optional `port.StateExporter` and `port.IndexExporter`, a `Restore` on the two
  GitHub link stores and `PutSessionKey`, used only by the migration. `--backup`
  to a file is a follow-up.

- **The domain stores on the ports.** With `ports.adapter` set to `nats` or
  `memory`, the directory workspaces and their credentials, the GitHub
  organisations, the link App, runner and catalogue Apps, people's GitHub links,
  the Slack workspaces, Slack Connect and channel records, the operators'
  confirmations and requests for a pass and the console's session key are kept in
  State (`ws.`, `gh.org.`, `gh.link.`, `app.`, `rec.`, `gate.`), a record and its
  secret in one item, every secret sealed with the item's own key as the binding.
  `ports.adapter: legacy`, the default, keeps the ConfigMap and Secret stores
  unchanged. A Sealer is required: the start is refused, naming `ports.sealer`,
  without one (so `nats` needs `ports.sealer`). The controllers read the same
  records from the State instead of the mounted files. See
  [docs/design/ports.md](docs/concepts/sluis/domain-stores.md).

- **A GitHub link is one item with one compare-and-swap refresh.**
  `gh.link.<account>` holds the link and its sealed token pair; the refresh
  marker is the claim on the single-use refresh token, so two replicas never
  spend it twice, and the replica that loses uses the winner's pair. A claim that
  spans accounts is steps with a marker that the next read finishes. Links are
  permanent keys (a link outlives its tokens).

- **The Slack Connect hand-off and a `users.info` cache on the State.** The
  host's tick writes `share.<host>.<channel>` (which asks the guest's runner to
  tick), the guest's tick marks its side accepted; 14 days while pending, 7 once
  accepted. Who a channel's member is, is cached 24 hours in
  `cache.slack.user.<workspace>.<id>` and counted by
  `slack_roster.user_cache{result=hit|miss}`. The shared inputs cache stays in
  memory. Additive: nothing changes with the default adapter.

- **The NATS JetStream adapter of the State port.** `ports.adapter: nats`
  (with `ports.nats`: `url`, `bucket`, `replicas`, `tokenFile` or `credsFile`,
  `caFile`, `create`) keeps State, the transitional session Index and the
  Trigger in one JetStream KV bucket, so a lease is exclusive across replicas
  and a notification crosses processes. Revisions are the stream sequence, so a
  rewrite of identical bytes changes it and a record that went A, B, A is
  detected. Expiry is judged on read; with nats-server 2.11 or later the bucket
  also reaps each record by its own TTL. Blob, Sealer and Identity are the legacy
  adapter's unless `ports.blob` and `ports.sealer` name the S3 and KMS adapters. The conformance suite passes against an
  embedded nats-server, a single node and a three-node cluster. Additive: the
  default adapter is unchanged. See
  [docs/design/ports.md](docs/concepts/sluis/ports.md#the-nats-adapter).

- **S3 Blob and KMS Sealer adapters.** `ports.blob: {adapter: s3, s3: {bucket,
  prefix, region, kmsKey, endpoint, pathStyle}}` keeps the status reports and
  directory snapshots in S3 (`WriteIfVersion` is an `If-Match` on the ETag), and
  `ports.sealer: {adapter: kms, kms: {keyId, region, endpoint}}` wraps the data
  keys of sealed secrets with AWS KMS (the binding is the EncryptionContext; no
  unwrapped key is cached). Each replaces one port of whatever `ports.adapter`
  brings, so the legacy State with an S3 Blob is valid. Credentials are the
  platform's; no key is configured. Additive: an installation that sets neither
  runs what it did. Both are experimental: they pass the conformance suite on
  LocalStack (`just test-s3`, and the `s3` CI job, which fails on a skipped
  test). See [docs/design/ports.md](docs/concepts/sluis/ports.md#the-s3-blob-and-the-kms-sealer).

- **The access document.** A policy layer may be written as the lists an
  installation derives from its access matrix (`access`) plus the rows that are
  its own (`overlay`); `policy.ParseAccess` reshapes it into the layer, and
  `LoadDeclared` reads such a file beside ordinary layers. The chart takes the
  same two values (`access`, `overlay`), renders them to `access.yaml` in the
  policy ConfigMap, checks `enabledOrgs` and `enabledWorkspaces` against them
  and projects the secrets of the clients they declare. Additive: `policy` is
  unchanged, and an installation that sets neither value renders what it did.
  See [docs/reference/sluis/policy.md](docs/reference/sluis/policy-bindings.md#the-access-document).

## v1.53.0

This release adds traces and metrics through an exporter allowlist, the chart's `alerts` and `dashboards` render modes, per-target ticks with the `tick` command (which builds on v1.52.4's single-binary, single-chart, and configuration-file consolidation), and preparation for the audit SDK module bump that will land in a later commit before the tag.

- **Traces, issuer and controller metrics, and the chart's `alerts` and
  `dashboards` modes.** Telemetry is still only `OTEL_*`, exported only when a
  collector is named; the contract and every signal are in
  [docs/reference/sluis/telemetry.md](docs/reference/sluis/telemetry.md).

  - **Traces.** A server span per request on the issuer's listener, named for a
    fixed route and never the path; Connect spans on the console's and the
    session service's handlers and on the controllers' clients of the console
    (the trace continues across); a span per tick (target kind and target) and
    per storage port call, the latter only inside a trace already recorded.
    Every span leaves through an allowlist exporter: attributes outside the list
    (the client's address, the raw path, the user agent), every event, link
    attribute and status text are dropped, and a test plants personal data in
    each place and asserts none leaves. **The sampler default, when
    `OTEL_TRACES_SAMPLER` is unset, is parent based `always_on`**; truvity/audit
    keeps a tenth. Which is right is not decided: it is one function, and the
    environment overrides it.
  - **Metrics.** `access_issuer.http.requests` and `.request.duration` by route
    and status class, `access_issuer.tokens.issued` by declared client and grant,
    `access_issuer.login.failures` by reason and `.login.successes` by method,
    `access_issuer.reuse_detected` by kind,
    `access_issuer.signing_key.active_since_timestamp`, and
    `access_issuer.signing_keys_published` now **by algorithm** (it was one
    unlabelled gauge written by every ring). For the controllers,
    `access_roster.ticks`, `.tick.duration` and `.tick.last_success_timestamp`
    by kind and target, `access_roster.leases.{acquired,contended,lost,held}`,
    and `access_roster.port.operation.duration` by port, operation and outcome
    (its `conflict` count is the compare-and-swap conflicts). The rate-limit
    metrics are kept. Nothing is labelled by person or group; a client id is
    bounded by the policy (an undeclared one is `other`) and a target by the
    policy's own declaration.
  - **Chart: `renders: app|alerts|dashboards`.** `app`, the default, renders
    byte for byte what it did. `alerts` renders only a VMRule (or, with
    `alerts.format: prometheusrule`, a PrometheusRule) of ten rules, each with
    its threshold's reason in a comment and a runbook entry, with
    `alerts.ruleLabels` on every rule; `dashboards` renders only the sidecar
    ConfigMaps of an "access-roster overview - $cluster" dashboard. Both are
    installed as a release of their own and validate nothing of the service.
  - **Held by CI.** `just telemetry` (a new job, and part of `check`) regenerates
    the dashboard and runs truvity/observability's `dashboardlint` over it, and
    unit-tests every rule with `vmalert-tool`, each with a case that fires it
    and one that must not. Goldens cover both modes.

- **A flaky Slack controller test.** `TestAChangedCredentialRunsAPassWithoutWaitingForTheInterval`
  read the second workspace's report before its own tick had published it; it
  now waits for it.

- **Audit SDK module upgrade.** Migrate from `github.com/truvity/audit v0.3.1`
  to `github.com/truvity/audit/sdk v0.6.1`, updating all imports to the new
  module path. The audit catalogue and API remain compatible with the new
  version.

## v1.52.4

- **Breaking (released automatically as a patch):** this release replaces the three
  binaries (`access-issuer`, `github-roster`, `slack-roster`) and the
  `access-issuer` chart with one `access-roster` binary, image and chart, and
  moves configuration from environment variables and chart values to one
  validated file per binary. It is a breaking change shipped as a patch release;
  the migration steps are in
  [docs/reference/sluis/configuration.md](docs/guides/sluis/migrate/migrate-from-environment-variables.md)
  and
  [the chart migration](docs/guides/sluis/migrate/migrate-from-the-access-issuer-chart.md).

- **Breaking: each binary is configured by one validated file, in place of
  environment variables, and the chart passes it through.**
  [0032](docs/decisions/0032-one-configuration-file-one-binary-one-chart.md)
  (its configuration-file half; the single binary and the single chart are the
  next entry). `access-issuer`, `github-roster` and `slack-roster` take
  `--config <file>` and nothing else but `--version` and `--help`. The file is
  validated against a committed JSON Schema before anything starts
  (`schemas/config/access-issuer.schema.json`, `github-roster.schema.json`,
  `slack-roster.schema.json`, generated by `just config-schemas` and embedded in
  the binaries), so an unknown key, a missing required key or a value of the
  wrong type is a start-up error that names the path to it, and a misspelt
  value in a chart is a failed `helm template` rather than a container that
  ignores it. The key for each old variable is in
  [docs/reference/sluis/configuration.md](docs/guides/sluis/migrate/migrate-from-environment-variables.md).

  - **Secrets are the one thing the environment adds, and only the ones the
    file names.** A key ending in `Env` (`valkey.passwordEnv`,
    `oauthClient.secretEnv`, `adminPasswordEnv`) holds the name of the
    variable; the process reads exactly those, and an unset one refuses to
    start. A secret in the file is refused: there is no key for it, and a URL
    or address with a password in it does not match the schema. A signing key,
    the OAuth client's files, the policy, the cluster and AWS federation files
    and the catalogues are keys holding paths.
  - **Telemetry is only `OTEL_*`.** `telemetry.otlpEndpoint` is removed from the
    chart; the endpoint is set on the pods by the platform.
  - **The old environment is refused, not ignored.** A variable the binaries
    used to read (`ISSUER_URL`, `VALKEY_PASSWORD`, `ENABLED_ORGS`, and the rest)
    that is still set stops the process at start and names the key that replaces
    it. `NAMESPACE` is now read from the pod's mounted service-account
    namespace, and the audit instance name is the pod's hostname.
  - **The chart renders each component's `config:` as it stands** into a
    ConfigMap (`<release>-config`, `<release>-github-roster-config`,
    `<release>-slack-roster-config`), mounts it, and `values.schema.json` embeds
    the schema its binary uses. Platform values stay values: images, replicas,
    resources, the route, the signing key's Certificate, `policy`, `exchange`,
    `directory.workspaces`, `githubApps`, `slackApps`, `audit.token` and the
    new `secretEnv` and `secretMounts`. The old env-shaped values (`issuerURL`,
    `listeners`, `logLevel`, `lifetimes`, `valkey`, `recovery`, `oauthClient`,
    `github`, `githubRunnerApps`, `telemetry`, `directory.store`,
    `directory.freshness`, `signingKey.rotation`, `githubRoster.actsIn`, ...)
    are removed, not aliased, and refused at render. A Go test holds every
    rendered ConfigMap to the values' `config` and to its binary's schema.
  - **The chart checks the config against what it renders.** Because the config
    is not computed, the chart refuses one that disagrees with the chart itself,
    and prints the value to write: `release` must be the release's full name; a
    path (`policyDir`, `signingKey.file`, `exchange.clustersFile`,
    `overlayFile`, a catalogue file, `clientSecretsDir`, `audit.tokenFile`, a
    controller's directories) must be where the chart mounts it, and must be
    unset where it mounts nothing; a controller's `consoleURL` must be this
    release's Service; with `route.host`, `publicURL` and `publicRootURL` must
    be the route's and `secureCookies` may not be `false`; `recovery.enabled`
    needs `inCluster`, a service account and an audience. An installation whose
    Helm release is not called `access-issuer` sets `config.release` to
    `<release>-access-issuer`; the chart says so.
  - **Every safety refusal is kept**, in the chart, the schema or the binary:
    the table is in the pull request. `tests/invalid/access-issuer/` holds a
    fixture for each chart refusal, and the removed values have one each that
    shows they are refused.

  Migrating, for an installation with a Valkey, a sign-in client and a
  controller:

  ```yaml
  # before
  issuerURL: https://access.example.com
  logLevel: debug
  lifetimes: { token: 30m }
  valkey:
    address: valkey.access-issuer.svc:6379
    passwordSecret: { name: valkey-password, key: secret }
  oauthClient:
    secret: { name: google-client }
  recovery: { enabled: true, serviceAccountName: access-recovery, audience: access-recovery }
  route: { host: access.example.com }
  githubRoster: { enabled: true, interval: 5m, actsIn: [acme] }
  telemetry: { otlpEndpoint: http://otel-collector.observability.svc:4318 }
  ```

  ```yaml
  # after
  config:
    issuerURL: https://access.example.com
    publicRootURL: https://access.example.com        # with route.host
    publicURL: https://access.example.com/console    # route.host plus console.mount
    log: { level: debug }
    lifetimes: { token: 30m }
    valkey:
      address: valkey.access-issuer.svc:6379
      passwordEnv: VALKEY_PASSWORD
    oauthClient:
      secretName: google-client
      idFile: /var/run/access-issuer/oauth-client/client-id
      secretFile: /var/run/access-issuer/oauth-client/client-secret
    recovery: { enabled: true, serviceAccount: access-recovery, audience: access-recovery }
  secretEnv:
    - { name: VALKEY_PASSWORD, secretName: valkey-password, key: secret }
  secretMounts:
    - { secretName: google-client, mountPath: /var/run/access-issuer/oauth-client }
  route: { host: access.example.com }
  githubRoster:
    enabled: true
    config:
      consoleURL: http://access-issuer.access.svc:8080/console   # this release's Service
      interval: 5m
      enabledOrgs: [acme]
  # telemetry: set OTEL_EXPORTER_OTLP_ENDPOINT on the pods, outside the chart
  ```

- **Breaking: one binary, `access-roster`, one image and one chart, in place of
  three of each.**
  [0032](docs/decisions/0032-one-configuration-file-one-binary-one-chart.md)
  (its second half; `tick` is a later change, with
  [0029](docs/decisions/0029-ticks-per-target-under-a-lease.md)'s leases).
  `access-issuer`, `github-roster` and `slack-roster` are `access-roster serve`,
  `access-roster controller github` and `access-roster controller slack`, each
  still `--config <file>` and nothing else but `--version` and `--help`;
  `access-roster migrate` is reserved by
  [0031](docs/decisions/0031-a-generic-migration-tool.md) and prints that it is
  not yet available. Each command's file has its own schema:
  `schemas/config/serve.schema.json`, `controller-github.schema.json` and
  `controller-slack.schema.json` replace the three above. **Removed, not kept as
  an alias:** the three `cmd/` mains, the images
  `ghcr.io/truvity/access-roster/access-issuer`, `/github-roster` and
  `/slack-roster`, and the chart `oci://ghcr.io/truvity/charts/access-issuer`;
  none is published again. **Published instead:**
  `ghcr.io/truvity/access-roster/access-roster` and
  `oci://ghcr.io/truvity/charts/access-roster`. Migrating an installation
  (the full walk-through, with every name that changes, is in
  [docs/reference/sluis/configuration.md](docs/guides/sluis/migrate/migrate-from-the-access-issuer-chart.md)):

  1. Be on the config-file form of the values (the entry above).
  2. Rename the values `githubRoster` to `controllerGithub` and `slackRoster` to
     `controllerSlack`, and delete `githubRoster.image` and `slackRoster.image`:
     a controller runs the chart's one `image`. If `image.repository` is set,
     point it at `ghcr.io/truvity/access-roster/access-roster`.
  3. Add `nameOverride: access-issuer` and `fullnameOverride: <the release's old
     full name>`. The chart's name is part of every object's name, so without
     them every object is renamed, the signing key's Secret is a new key and the
     service starts on an empty store, because `config.release` (which must be
     the full name) names the objects it writes. With them nothing is renamed and
     no Deployment selector changes. Write `config.release` and each
     controller's `config.release` out if they were unset: the default is now
     `access-roster`, not `access-issuer`.
  4. Point the chart reference (`helm`, Argo CD, Flux) at
     `oci://ghcr.io/truvity/charts/access-roster` at this version, run
     `helm template`, and roll out.
  5. Change anything outside the chart that ran a binary or an image by name.

  The container names, the `app.kubernetes.io/component` labels and where the
  config file is mounted change (`serve`, `controller-github`,
  `controller-slack`; `/etc/access-roster/...`). Unchanged: the controllers'
  object names (`<full name>-github-roster`, `-slack-roster`), every path the
  chart mounts under `/var/run/...`, and the telemetry service names.

- **The storage ports of `docs/design/ports.md` exist in the code, behind
  today's storage, and the apps depend on them.** No data moves, the same
  objects and keys are written, and nothing behaves differently. A new package,
  `internal/port`, defines `State`, `Blob`, `Trigger`, `Sealer` and `Identity`
  (the audit sink stays `audit.Recorder`); `internal/port/memory` implements
  all of them for tests and the demonstration; and `internal/port/legacy` is a
  temporary adapter that implements them by reaching the ConfigMaps, Secrets and
  Valkey keys the service writes today, byte for byte (`gh.org.<org>` is the
  `<release>-github-orgs` entry, `snapshots/<workspace>` and `lease.<kind>:<workspace>`
  are the Valkey keys the hub has always used, `reports/github/` and
  `reports/slack/` are the two status ConfigMaps). A key of the layout that has
  no object of its own today (`ses.`, `sid.`, `ws.`, `gh.link.`, ...) is refused
  as unsupported rather than written somewhere else. The gaps are listed in
  [design/ports.md](docs/reference/sluis/capabilities.md): a revision is
  a digest of the stored bytes, `Watch` polls, and the legacy `Sealer` refuses.
  The issuer's logins in progress, the hub's snapshots and refresh lease, the
  controllers' reports and the cluster `TokenReview` now go through the ports;
  the ConfigMap and Secret domain stores of a connected workspace, an
  organisation's credential and a person's link stay behind their own
  interfaces until the data moves. A new `ports.adapter` key (`legacy`, the
  default, or `memory`) in the `serve` and controller files chooses the adapter;
  `memory` keeps all state in the process and is refused with `store: kubernetes`
  or `valkey.address`. `internal/port/porttest` is the conformance suite (CAS
  races, TTL visibility, lease takeover, prefix paging, revisions, watch, limits,
  blobs, sealing, identity) that both adapters pass, with each assertion the
  legacy adapter cannot meet skipped by name and reason. A test fails the build
  if a business package imports `internal/kube`, `internal/valkey` or the legacy
  adapter. `valkey.Snapshots` is gone: its encoding moved to the hub, unchanged.

- **Each reconciler works in ticks of one target under a lease, and there is an
  `access-roster tick` command.**
  [0029](docs/decisions/0029-ticks-per-target-under-a-lease.md), on the ports
  above. A GitHub organisation, a Slack workspace and (for GitHub) the people's
  link check, `github:links`, are targets; `controller.Tick(ctx, target)` is
  one target's pass and publishes **its own report only**, so the report
  ConfigMap entry of a target nobody ticked is not read, written or rewritten.
  `access-roster controller github|slack` is still the Kubernetes runner: it
  sweeps every target on the interval (links first), each under a lease taken
  from the State port (a create with a lifetime, renewed by compare-and-swap,
  released only if still the holder's, and the tick's context ends if the lease
  is lost), and the sweep prunes the reports of targets the policy no longer
  has. **New:** `access-roster tick <github|slack> <target> --config <file>`
  runs one target's tick once under its lease and exits (an organisation's
  login, `github:links`, or a workspace's key), which is the shape of a
  function that lives for one invocation and is useful to an operator now.
  **It refuses to run while the leases are in-process only** (no shared State,
  which is every installation until B3): a running controller would not be kept
  off the same target. Scale the controller to 0 and pass
  `--unsafe-local-lease` to run it anyway.

  - **Nothing moves and nothing new is stored.** The leases are the
    `lease.<kind>:<target>` keys the legacy adapter already maps to the hub's
    Valkey lease slot (`{target}:lease:github-tick`, `github-links`,
    `slack-tick`); reports stay the two status ConfigMaps. Keys the legacy
    adapter cannot hold (`share.`, `cache.`, `gate.`, `gh.link.`) are not used:
    the shared inputs are cached in memory per policy digest (five minutes,
    and read again when anything mounted changes, such as an operator's
    request), and the Slack Connect hand-off keeps working without a
    pending-share record, as below. All of that is B3.
  - **A request ticks its target.** An operator's Refresh now ticks only its
    organisation or workspace (the controller's mounted-records watch notifies
    its in-process trigger with that target) instead of the whole pass, and the
    console calls `Trigger.Notify(target)` on a Refresh, a confirmation and a
    save of a channel or Slack Connect record. With the legacy adapter the
    console and the controllers are different processes, so the controllers
    still learn of a console write from the records they mount, polled every 30
    seconds, and a change of a credential or record runs a sweep; B3's
    key-value watch replaces the poll.
  - **Slack Connect.** The host's tick, having invited a guest (or seeing an
    invitation still waiting), notifies the guest's tick, which accepts; the
    sweep is the fallback when the notification cannot reach the guest's runner.
    `probeGuestSides` is now the host's: it reads the guests' last reports from
    the blob, asks only for the sides a guest's own report does not list, and
    publishes what it found in the host's report as the new additive
    `guest_sides` (the console merges them into the guest's side as before; an
    older console shows no probed side and nothing else changes).
  - **Replicas stay at one, strategy `Recreate`.** The leases are only
    exclusive across pods when the State is shared, and a controller has no
    Valkey configured and the chart gives it no way to name one, so with the
    legacy adapter its leases are in its own process (it logs that); a second
    replica or a rolling update would not be kept off, and the previous
    version, which takes no lease, would run beside the new one. Two replicas
    wait for B3's key-value State, which both pods share. Nothing in the chart
    changes.

## v1.52.3

- **The GitHub controller waits out a rate limit instead of failing the
  pass.** A 429, or a 403 with `Retry-After`, an empty `X-RateLimit-Remaining`
  or a secondary-limit message, is waited for (`Retry-After`, else the
  `X-RateLimit-Reset` time, at most 60 seconds) and retried up to three times;
  the wait ends with the context. Only such an explicit rejection is retried,
  never a call GitHub may have processed, so the single-use OAuth token
  refresh is not repeated after any other answer. The members listing reads
  its GraphQL point budget and waits for the reset before the next page when
  less than two pages' worth is left; a GraphQL rate limit answered inside a
  200 is waited out and retried the same way. Each wait is one log line and
  counts in the new `github_roster.rate_limited` metric;
  `github_roster.rate_limit_remaining` reports the budget GitHub last stated.

## v1.52.2

- **The documented IAM policy for `sts:GetWebIdentityToken` now works.** The
  examples in the AWS workloads and Lambda guides pinned the audience with
  `StringEquals`, but `sts:IdentityTokenAudience` is multi-valued, so STS
  answered `AccessDenied` for a correctly configured role. The audience
  condition is now `ForAllValues:StringEquals`; `sts:SigningAlgorithm` keeps
  `StringEquals`.

## v1.52.1

- **A group address is no longer read as a user.** The directory answers a
  user read of a group (or a group alias) with a 400 "Type not supported:
  userKey", which the hub logged as a `live account read failed` warning on
  every lookup. A group the snapshot knows is answered from it without a
  directory read, and that one answer from Google is an absence rather than
  an error. Authentication failures, rate limits and 5xx still warn.

## v1.52.0

- **The Lambda extension forwards Lambda platform logs as OTLP logs.** It
  subscribes to the Lambda Telemetry API and sends `platform.*` events
  (timeouts, out-of-memory kills, init and restore errors, and the `REPORT`
  metrics: duration, billed duration, max memory, init duration) to
  `<endpoint>/v1/logs` with the same bearer token as the proxy, so they reach
  the log store without CloudWatch. Failures (`status` other than `success`,
  any `errorType`) are ERROR records; X-Ray trace context is carried when the
  event has it; the resource is `service.name` (`OTEL_SERVICE_NAME`, else the
  function name), `faas.*` and `cloud.*`. On by default
  (`ACCESS_ROSTER_PLATFORM_LOGS=false` turns it off). `function` and
  `extension` logs are opt-in (`ACCESS_ROSTER_FUNCTION_LOGS`,
  `ACCESS_ROSTER_EXTENSION_LOGS`) because a function that exports its own logs
  through OpenTelemetry would send each line twice. The queue is bounded
  (`ACCESS_ROSTER_TELEMETRY_BUFFER_*`; oldest dropped and counted), exports are
  fail-open, and what is queued is exported before the environment can freeze
  and on `SHUTDOWN`. The binary grows by about 65 KB. See
  [integrations/aws-lambda.md](docs/reference/sluis/lambda.md#platform-logs).

## v1.51.0

- **AWS workloads exchange their IAM role's token.** A Lambda function, ECS
  task or EC2 instance can call `sts:GetWebIdentityToken` (AWS outbound
  identity federation) and exchange the JWT it gets for a token of this
  issuer's, with no stored secret. New `exchange.aws` chart value
  (`audience`, `maxAge`, `accounts[]` of `{account, name, issuer, jwksUri,
  orgId, algs}`), mounted as a file named by `AWS_FEDERATION_FILE`; **an empty
  list verifies no AWS token**, because any AWS account can mint one for a role
  of its own. A token is accepted only from a configured account's issuer, with
  its signature checked against that account's key set (ES384 or RS256, pinned
  per row), the configured audience, `iat` no older than `maxAge` (default
  5 minutes) and the account claim, the role's ARN and the row all agreeing.
  The identity is the IAM **role**: the minted subject is
  `aws:<account>:role/<path><name>`, never a session or a function. `sub` is
  accepted only as a role ARN (AWS documents no other form), so an
  `assumed-role` session ARN is refused. New policy matcher
  `aws: {account, role, path, function, org_id}` (account exact and required,
  the rest `path.Match` globs; roll the issuer before the policy that uses it,
  since an older issuer refuses the key). Audited as `roster.token.exchanged`
  with proof `workload`; the catalogue is unchanged. See
  [connect/aws-workloads.md](docs/guides/sluis/connect/aws-workloads.md).

- **A Lambda extension layer sends a function's OpenTelemetry data with the
  function role's identity.** The release now carries
  `access-roster-lambda-layer_<version>_linux_{amd64,arm64}.zip`, whose only
  file is `extensions/access-roster-otlp` (about 10 MB, 4 MB zipped). Set
  `OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318` in the function: the
  extension gets an identity token from regional STS
  (`sts:GetWebIdentityToken`), trades it at the issuer for a short-lived access
  token, refreshing on demand because a frozen Lambda runs no timers, and
  forwards each export with it as the bearer. It is fail-open: with no token the
  exporter gets a retryable 503 and the extension logs one line per failure
  window; the function is never blocked. `ACCESS_ROSTER_TOKEN_FILE` also writes
  the token for a function's own collector. `docs/integrations/aws-lambda.md`
  has the settings and the IAM policy. It needs an issuer that accepts AWS
  identity tokens. The release publishes the zip only; a layer version is yours
  to publish.

## v1.50.3

- **When a rollout replaces every Valkey pod at once, the client finds the new
  ones through the Service.** The topology reload asked the pod addresses it
  already held first, each costing the whole dial budget, and fell back to the
  configured Service name only after the last had failed, so both issuer
  replicas dialled the old pods for minutes while sign-in and token calls
  failed. The reload now reads `CLUSTER SLOTS` through the configured address on
  a fresh connection every time; the Service follows the pods, so one dial finds
  a live node. A test with six replaced pods goes from about 29s to about 2s.

## v1.50.2

- **A write that meets a lost Valkey node is retried once, after the topology
  reloads.** The failover fix below still left one failure: the command that
  discovered the dead primary was refused (`dial tcp <old primary>: i/o
  timeout`) although a replica was already serving its key. Every call the
  shared login state makes (`Get`, `Set`, `Delete`, `Add`, `Remove`, `Members`)
  that fails with no answer from the server (a dial error, a timeout or reset
  connection, `EOF`) or with `CLUSTERDOWN`/`TRYAGAIN` now waits (at most two
  dial timeouts) until the client sees a different primary for the key, then runs
  once more and logs one warning with the key's prefix. All of them are safe to
  repeat; `SetIfAbsent` is the exception, since a lost reply would turn "you
  took it" into "taken", so it is retried only when it certainly never ran (a
  dial error or `CLUSTERDOWN`). A server's own error, or the caller's context
  ending, is never retried. New `TestNoWriteFailsOnceTheReplicaHasTakenOver`
  (same opt-in docker cluster) streams writes through a primary kill and fails
  on any write still in flight after the takeover; it failed on every run
  without the retry.

## v1.50.1

- **In cluster mode the Valkey client follows a failover by itself.** When a
  shard's primary died, its replica was promoted within seconds, but the client
  kept sending that shard's commands to the dead address until its once-a-minute
  topology refresh: measured against a three-shard cluster, a third of all
  writes were still failing 30 seconds after the kill. A command that fails
  without an answer from the server (a dial timeout, a reset connection) or with
  `CLUSTERDOWN` now asks for a topology reload (asynchronous, coalesced), the
  periodic reload runs every 5 seconds instead of 60, and a dial gives up after
  1 second and 2 attempts instead of 5 seconds and 5 attempts, so a reload that
  happens to ask the dead node first does not wait half a minute on it. The same
  cluster now takes every write again 3–6 seconds after a primary is killed,
  with nothing written before the kill lost. The dial limits apply in
  non-cluster mode too. New `TestTheClientSurvivesTheLossOfAPrimary`
  (docker, opt-in via `VALKEY_TEST_CLUSTER_ADDR` and
  `VALKEY_TEST_CLUSTER_CONTAINERS`) kills a primary and asserts both.

## v1.50.0

- **A test keeps `contracts.md` in step with the protos.** `just docs-check` now
  fails, naming each one, when a service or RPC in `proto/` is not mentioned in
  `docs/reference/sluis/contracts.md`. It found `accessissuer.v1.SessionService`
  (`ListSessions`, `RevokeSessions`) undocumented, and the page now describes it.

- **GitHub organisations get Refresh and a prompt pass, as Slack workspaces
  have.** The GitHub controller now looks every 30 seconds at its mounted App
  credentials and at the console's records, and runs a full pass at once when an
  organisation's credential or record changed (a new installation, a reconnect)
  or an operator asked for one, instead of waiting out `githubRoster.interval`.
  The organisation's page has a **Refresh** button for the organisation's
  operators (the installation-wide operator, or the operator of the owning
  directory), backed by the new `RequestGitHubPass` RPC: it leaves a
  `_pass.<organisation>.json` marker in the `<release>-github-orgs` ConfigMap,
  is refused within a minute of the last request (`resource_exhausted`) and for
  an organisation whose App is not installed (`failed_precondition`), is
  forgotten when the organisation is disconnected, and is audited as the new
  `roster.github_org.pass_requested`. `GetGitHubStatus` carries the last request
  as `pass_requested_at`, and the page says *Pass requested* until a newer report
  exists. The chart mounts `<release>-github-orgs` read-only into the controller
  (new `RECORDS_DIR`, optional volume); no RBAC changes, because a mounted volume
  is read by the kubelet. The watch itself, the directory listing and the
  rate-limit gate are now shared with the Slack controller in `internal/rails`
  (`Watch`, `Digest`, `Entries`, `Gate`).

- **Audit catalogue 1.6.0 removes what was dead and states what is historical.**
  The `takeover` branch of the console-channel message (the feature was removed
  in v1.48.0) and the stale "taken over by id" summary of
  `roster.slack_channel.adopted` (adoption is by name) are gone; a Slack Connect
  channel's records now carry the `sources` count its console counterpart always
  had, and its created message says how many directory groups and individual
  addresses feed it. `reason` on console-channel records and `from` on
  Slack Connect records are no longer written; both stay declared in their
  schemas, described as historical, because records written under 1.3.0 to 1.5.0
  carry them and must still read. A console-channel record written by the
  removed take-over feature now reads without its "taken over from git" suffix.
  Adds `roster.github_org.pass_requested`. Existing installations take the new
  version at the next start.

## v1.49.3

- **Fix: a shared channel's record no longer tells an outsider that it exists.**
  Editing or deleting a Slack Connect record answers *no such channel* to a
  caller who may not see it (a viewer of neither its host nor a guest), asked
  before the role over its host; a caller who may see it but not operate it is
  still refused plainly. Creating a record whose name another host's record
  already holds no longer names that host to a caller who may not see it.

- **Fix: a channel defined in both git and the console reads *held* on the
  record's row too.** The console showed *invalid* for the record while the
  controller reported both as held; both now say *held*, with the same reason.

- **Fix: a directory-groups read that fails is said, not shown as an empty
  picker.** The channel forms show the failure in the group picker (new
  `source_directories_error` field on `ListSlackChannelsResponse` and
  `ListSlackSharedChannelsResponse`).

- **Fix: one definition of "this record is that channel" and of a channel id.**
  The probe of a Slack Connect channel's guest sides matches a record that has
  no channel id by name only for a proven host (the host reports it, or both host
  teams are known and equal), as the reconciler does. A record's channel id is
  checked with the policy's own rule (`C` or `G` and at least eight capitals or
  digits); a shorter id on a console or Slack Connect record is now refused. The
  chart's `slackApps[].workspace` takes the policy's workspace-key shape, so a
  key the service would refuse fails `helm template`. The controller and the
  console use one *no owning directory* hold text.

- **Docs and wording.** The `policy` package, the proto comments (individual
  members, the update fields, `can_change_owner`, the `GetSlackStatus` refusal),
  the state-push mirror comment and the console wording (*adopted*, not *taken
  over*, for an existing channel; the navigation as Overview and four clusters)
  say what the code does.

## v1.49.2

- **Fix: archiving from the console asks Slack first.** Deleting a console
  channel's record with *Also archive* ticked now refuses, with the record kept
  and nothing changed, unless the workspace's controller reports that it acts
  (a dry-run workspace, or none reported, is archived by hand), asks Slack
  (`conversations.info`) and refuses a Slack Connect channel whatever the
  controller's report says (a held console record over a channel that is shared
  in Slack used to be archived for every organisation in it), and refuses a
  channel the bot cannot see or a Slack that does not answer. The delete dialog
  shows the checkbox only for a workspace that acts (new `acting` field on
  `SlackChannelWorkspace`).

- **The chart refuses an `actsIn` entry the policy does not define.** With the
  policy given inline in values, `slackRoster.actsIn` must name keys of
  `policy.slack.workspaces` and `githubRoster.actsIn` must name organisations of
  `policy.github`; an unknown entry now fails `helm template` with the entry
  named, instead of crash-looping the controller (which would be down for every
  workspace) after the rollout. With no policy in the values the check is
  skipped; the controller's own refusal to start stays as the backstop.

- **Disconnecting a Slack workspace clears its old report, and the dialog says
  its records stay.** A workspace with no bot token (not connected, or created and
  not installed) is now reported as waiting with nothing carried over, so the
  Channels and People views no longer show the channels and members of a
  connection that is gone, or of another team. The channel and Slack Connect
  records are kept as before, and the Disconnect dialog now says they apply to
  whichever Slack team is connected under that key next.

- **Saving a channel or Slack Connect record wakes the Slack controller.** The
  controller's 30-second look at the mounted credentials and records now includes
  the console's `_channel.*` and `_shared.*` records (confirmations, pass
  requests and install states still do not count), so a save no longer waits up to
  an interval for its pass; saves made close together are answered by one pass.
  The console and the docs now say a change takes effect "within a couple of
  minutes" (the kubelet's projection of the mounted files dominates), not "at
  once" or "on the next pass".

- **Documentation brought up to date with the Slack reconciler, console channels,
  Slack Connect and the v1.41–v1.49 changes; nine new decision records
  (0017–0025).**

## v1.49.1

- **The guest-side probe asks only about managed Slack Connect channels.** A
  shared channel no console record manages is no longer probed with
  `conversations.info`, so the roster stops spending a call per other
  connected workspace per unmanaged channel every pass. For a managed channel
  the rules are unchanged (Slack-named guests when informative, workspaces
  that already list it skipped), except that when Slack names no guest the
  probe asks exactly the workspaces the record names as sides (host and
  `with`), not every connected workspace.

## v1.49.0

- **Individual addresses as Slack channel members.** A console channel record
  (`_channel.<workspace>.<name>.json`) and a Slack Connect record
  (`_shared.<name>.json`) gain `members: [<email>...]` beside `sources`
  (directory groups). Either may be set, at least one must be. The Manage form
  has an *Individual addresses* field next to *Directory groups*. An address
  must be an active user of a directory the channel draws from: an ordinary
  channel, the directory that owns its workspace; a Slack Connect channel, any
  connected directory. The console refuses a group typed as a person, a person
  typed as a group, a repeat, and an address outside those directories. The
  desired membership is the union of the groups' members and the individuals,
  mapped to people exactly as group members are; an individual who is
  suspended or gone is a leaver like a group member (never added, removed by a
  strict channel). The channel page, the Channels and Slack Connect rows show
  both ("2 groups, 3 people"), and a person's page marks the channels that list
  them *individually*. `ResolveDirectoryGroups` also answers for `users`.
  Audit catalogue **1.5.0**: the individuals are targets of the new
  `directory_user` type and the record's data counts them (`members`).

## v1.48.0

- **Archive a channel in Slack when forgetting its console record.** The
  delete dialog of a console channel has an opt-in, off by default: *Also
  archive #name in Slack*. Ticked, the bot calls `conversations.archive` after
  the record is forgotten (`channels:manage` and `groups:write`, already in the
  App's scopes), under the same operator role as the delete, and the action is
  audited as `roster.slack_channel.archived` (the audit catalogue is
  **1.4.0**). When the bot cannot (it is not in the channel, or Slack refuses)
  the record is still deleted and the note says to archive it by hand. A Slack
  Connect channel is never archived from the console, whoever hosts it: the
  dialog says so and the server refuses the request with nothing changed,
  because archiving closes the channel for every organisation in it. Channels
  the policy defines cannot be deleted here at all.

- **The Channels tab uses the shared filter bar.** It narrows by workspace
  (any side of a channel), kind (policy, console, Slack Connect), state (ok,
  pending, waiting, held, invalid, not reported; pending is a channel the
  controller is about to create, adopt or accept) and a name or Slack id
  search, with the
  same components as Discovered and Slack Connect, and its summary reads "N of
  M shown". Every selection is in the address query
  (`#/slack/channels?workspace=&kind=&state=&q=`).
- **Removed: Take over from git.** It was a migration aid. The channel page has
  no **Take over from git** action and no *taken over* state; the Manage form
  refuses a channel the policy defines in that workspace (*this channel is
  defined in git; remove it there to manage it here*), and the server refuses
  a create or update the same way. To move a channel from git to the console:
  remove it from the policy, then Manage it from Discovered. **No mixing:** a
  channel defined both in the policy and as a console record is held on both
  sides (*defined in both git and the console*) and nothing on it changes
  until one definition is removed. A stored record that still carries
  `supersedes_policy: true` keeps loading with the field ignored, is never
  written with it again, and is a plain console channel once git no longer
  defines the channel. The field is reserved in
  `SlackChannelDefinition`, and `superseded` and `ignore` are gone from the
  Slack status. The removal itself leaves the audit catalogue alone: records
  already written keep their `reason: takeover`, and nothing emits it any more.

## v1.47.2

- **Fix: the guest-side probe skipped every channel when Slack named no
  guests.** Slack returns a bot only its own team for a Slack Connect channel,
  so the team filter added for the probe skipped every workspace and a guest
  side only the probe could find disappeared from the report. The probe now
  asks only the workspaces Slack names as guests when it names any connected
  one besides the host and the workspaces that listed the channel; when it
  names none, it asks every other connected workspace again. Expected
  `channel_not_found` and `not_in_channel` stay at debug, real errors warn, and
  each pass still logs one `guest-side probe` summary.

## v1.47.1

- **Filters on the Slack Discovered and Slack Connect tabs.** Discovered
  narrows by workspace, kind (ordinary or Slack Connect), visibility (public,
  private, unknown) and a name search, sorts by workspace then name (or most
  members), and its summary reads "N of M shown". Slack Connect narrows by host,
  by a workspace on either side, by state (active, waiting, pending, held,
  invalid, not reported) and a name search. Every selection is in the address
  query (`#/slack/discovered?workspace=&kind=&visibility=&q=&sort=`,
  `#/slack/connect?host=&side=&state=&q=`), like the Channels tab's.
- **Fix: Manage on a discovered Slack Connect channel left a side out and
  defaulted an unseen side to public.** A workspace whose own report lists the
  channel (found, or probed from the guest side) is now a prefilled side with
  the privacy it reported, even when its report carries no team id; a side
  nobody could see has no default and must be chosen ("private there and the
  bot is not in it, or not shared"). A managed Slack Connect channel the
  controller holds for a visibility that differs from its record now says so,
  with an Edit hint, on the Slack Connect row and the channel page.

- **The guest-side probe no longer logs a warning per channel per pass.** The
  controller now asks a connected workspace about a Slack Connect channel
  only when Slack lists that workspace's team in it (the host, shared,
  connected, pending or internal team ids a report carries); every other
  workspace is skipped without a call. A `channel_not_found` or
  `not_in_channel` from a probe that was expected is an invisible side, logged
  at debug (the old check matched the error the wrong way round, so it always
  warned). Real errors still warn, and each pass logs one summary line:
  `guest-side probe` with `probed`, `visible` and `invisible` counts.

## v1.47.0

- **Take over a policy channel from git on the console, with no unmanaged
  gap.** A policy channel (`slack.workspaces[k].channels`) shows **Take over
  from git** on its channel page (operator over the workspace's owning
  directory, or installation-wide operator): the console-channel form opens
  prefilled with its workspace, name, channel id (from the latest report),
  visibility, mode and `ignore` list, and asks for directory-group sources.
  Saving writes the usual `_channel.<workspace>.<name>.json` record with the
  new field `supersedes_policy: true` (also `SlackChannelDefinition.supersedes_policy`)
  and audits it as `roster.slack_console_channel.created` with a new optional
  data field `reason: takeover`; the audit catalogue is **1.3.0**. A console
  channel that duplicates a policy channel is still refused as *defined in git*
  unless it sets `supersedes_policy` and covers exactly that channel (same
  workspace and name, or channel id; same visibility). The controller then
  reconciles the record and never the policy entry, reports the entry as
  `superseded` (`taken over on the console by X at T; remove it from git`,
  also on the Channels tab and the channel page), and removing the entry from
  git later changes nothing in Slack. A takeover removes nobody by itself;
  strict removals still need the directory to vouch and the breakers apply.
  Deleting the console record restores the policy entry's management on the next
  pass. The old way (remove it from git first) still works.

## v1.46.1

- **A Slack Connect side the guest bot does not list is now
  probed by id.** A bot lists a channel that is public on its side only
  sometimes, and one it has not joined often not at all, so discovery showed
  that side as "not listed" and the operator had to add it by hand. For every
  Slack Connect channel any connected workspace discovered, the controller now
  asks each other connected workspace that did not list it, with
  `conversations.info` by channel id (bot token, `include_num_members`), at
  most once per channel and workspace per pass. An answer is published in that
  workspace's `discovered_shared` (privacy, name and member count as that side
  sees them, bot not joined), so the Manage form prefills the side; a public
  side the bot has not joined is joined on Manage as before. A private side
  answers `channel_not_found` and stays unknown. A probe that fails is logged
  and never fails the pass. Nothing else changes; the status document only
  gains entries.

## v1.46.0

- **The console is organised as four clusters, and Slack is one place.** The
  rail reads Overview · IDENTITY (Directories, Directory groups, People, Rules)
  · ACCESS (Internal groups, Clients, Sessions) · SYSTEMS (GitHub, Slack) ·
  ADMIN (Audit, Settings). Slack is a single entry with tabs — Workspaces,
  Channels, Slack Connect, Discovered, Apps — and every managed channel has a
  page of its own: what feeds it (internal groups for a channel defined in
  git, directory groups for a console channel), its mode, each person's state
  and why, the Slack Connect sides, the removal breaker, and its audit
  history. GitHub gains a Runners tab. Old links (`#/slack-apps`,
  `#/slack-connect`) still work.
- **Reverse links.** A directory group's page lists the Slack channels it
  feeds and how its people stand there, and the GitHub teams it reaches; an
  internal group's page lists the channels defined in git that name it; a
  person's page has a Slack section with each channel's state and reason
  (e.g. "waiting for them: no Slack account yet").
- `SlackChannelStatus.sources` now also carries the internal groups a channel
  defined in git is fed by, so the channel page can link them. No other API
  change; nothing new calls Slack.

## v1.45.0

- **Console channels: ordinary Slack channels managed on the console, fed by
  directory groups.** Slack channels now come in two kinds that are never mixed
  on one channel. **Policy channels** (`slack.workspaces[k].channels`, in git)
  are fed by internal groups and are unchanged, for channels the
  infrastructure owns. **Console channels** are records on the console, audited
  and backed up with the other Slack records, fed by **directory (IdP) groups**
  by address and never by internal groups: an **ordinary** channel in one
  workspace takes the groups of the directory that owns the workspace, and a
  **Slack Connect** channel takes groups of any connected directory, each person
  joining on the side whose owning directory serves their address. Members are
  resolved through nested groups (new `AccessService.ResolveDirectoryGroups`,
  gated like the other reads; cycles end and the depth and size are bounded,
  and a read cut short refuses the channel for the pass). The controller
  reconciles a console channel with the same rules as a policy channel (create
  or take over by name or id, `extend` or `strict`, the directory vouches
  before a removal and now asks about the directory groups and the groups they
  nest, breakers, holds, never a visibility change), refuses a record whose
  source is not a group of an allowed directory, and fails only the workspaces
  that depend on a directory it cannot read. A console channel is refused as
  *this channel is defined in git* when the policy binds the same name or
  adopts the same channel id, and one channel is managed one way. New record
  `_channel.<workspace>.<name>.json` (workspace, name, channel_id, private,
  mode, ignore, sources, created/updated by and at) in
  `<release>-slack-workspaces`, included in the `slack-records` mirror, and
  `SlackChannelService` (list, create, update, delete: operator over the
  workspace's owning directory, or installation-wide). The Slack page lists the
  console channels with a form, and **Discovered channels**: every channel the
  bots see that no policy binding or record manages (reports gain
  `discovered`, additive, capped at 500 per workspace with a count of the
  rest), with **Manage** prefilled. **Breaking for a record, not for a
  release:** a Slack Connect record's `from` is now `sources`, directory
  groups. A record written with internal groups is listed `invalid` with a
  message, its host's operators can edit it, and it is acted on by nobody until
  then. The Slack Connect form's picker lists directory groups of every
  connected directory under the directory (id and domains), searchable; it shows
  which chosen groups land on each side and warns about a group whose directory
  owns no side. Audit catalogue **1.2.0** adds
  `roster.slack_console_channel.created`, `.updated` and `.deleted` and the
  `directory_group` target type: a group's address is carried as a target,
  never as data, so the Slack Connect records no longer write `from`. Moving a
  policy channel to the console: remove it from the policy, find it under
  Discovered, Manage it with the directory group as the source and the same
  mode ([docs](docs/guides/sluis/connect/slack-console-channels.md)).

- **Fix: a Slack Connect side no report mentions is shown as unknown, not
  dropped.** Slack names only the host among a channel's teams when the host's
  channel list is read, and a guest bot lists a private channel only once it is
  in it, so a guest side could leave no trace in any report and the Manage form
  omitted it. Discovery now offers every connected workspace the caller may view
  as a side: one nothing places the channel in is unknown (`listed: false`) and
  is not prefilled; Slack's pending-guest and internal team lists now place a
  channel in those workspaces too.

## v1.44.0

- **A recovery copy of the Slack state: `slackState.push`.** In the shape of
  `directory.push` and `githubApps.push` (`secretStore`, `remoteKey`,
  `refreshInterval`, `deletionPolicy` fixed at `None`) with one more required
  key, `recordsRemoteKey`. It renders two External Secrets `PushSecret`s: the
  whole of `Secret <release>-slack-credentials` at `remoteKey`, and the whole
  of the new `Secret <release>-slack-records` at `recordsRemoteKey`. The
  records live in a ConfigMap and a `PushSecret` reads Secrets only, so the
  service now keeps that Secret as a mirror of exactly the ConfigMap's
  `<workspace>.json` and `_shared.*` entries (never confirmations or pass
  markers), written in the same code path as the ConfigMap and reconciled at
  start. If the ConfigMap holds no record and the mirror does, start
  repopulates the ConfigMap from it. Off unless `slackState.push` is written,
  and refused at render without `directory.store: kubernetes`, without a
  store or either key, or for two pushes sharing one path. The mirror Secret
  is written regardless; it uses the permissions the service already has.
  Restore procedure: docs/guides/sluis/operate/back-up-and-restore.md, Slack state.

- **Slack Connect: find channels that already exist and take them under
  management.** The Slack controller now lists, per connected workspace, the
  Slack Connect channels its bot can see and publishes them in the report as
  `discovered_shared` (additive; status version unchanged). `#/slack-connect`
  has a Discovered section: one row per channel with its name, privacy and
  members per side, its host workspace and whether it is managed; Manage opens
  the create form prefilled, and the record keeps the channel's id
  (`channel_id`) so the reconciler takes over exactly that channel. A host side
  takes over by id and never invites a side that is already connected; a
  connected guest side joins a public channel instead of waiting for an
  invitation, and a private side without the bot is held until the bot is
  invited. Nobody is ever removed, and a team that is not a connected workspace
  is never touched. The audit catalogue is unchanged. See
  [docs/connect/slack-connect-channels.md](docs/guides/sluis/connect/slack-connect-channels.md).

## v1.43.1

- **Fix: a refused Slack install now says why.** Every refused or failed
  install callback, for a workspace connection and for the catalogue App, is
  logged (values through `logsafe`; never the code, a token or a secret) and
  audited with its reason, using the existing `roster.slack_workspace.connect_refused`
  and `roster.slack_app.install_refused` actions. There is no audit catalogue
  change. The callbacks still require the flow cookie and the signed state
  exactly as before.
- **Fix: a person with no Slack account yet is waiting, not blocking.** The
  hold reason on that person's row reads "waiting for them" instead of "needs
  you".

## v1.43.0

- **A pass runs right after a Slack workspace's credential changes, and the
  console has a Refresh button.** The Slack controller now checks the mounted
  credentials and records every 30 seconds and runs a full pass at once when a
  workspace's credential changes, such as a new bot token after an install; the
  15-minute interval is unchanged. Until a report newer than the connection
  exists, the console shows "Installed - waiting for the first pass" instead of
  the previous pass's banner. A new `RequestSlackPass` RPC and a per-workspace
  **Refresh** button (offered only to operators, only for an installed
  workspace) ask for a pass: the request is a marker in the
  `<release>-slack-workspaces` records ConfigMap, a second request within 60
  seconds is refused, and the card shows "Pass requested" until a newer report
  exists. The requester is logged; there is no audit action.

## v1.42.4

- **Fix: an owning directory is labelled by its id and every authoritative
  domain.** In every owner dropdown and "owned by" line (Slack, GitHub, Change
  owner) a directory reads `<workspace id> - <authoritative domains, sorted>`;
  served domains that are not authoritative are left out. `DirectoryRef` gains
  `domains`, and a row's `owner_domain` now carries the joined list.
- **Fix: a Slack workspace that is not connected or not installed yet is
  waiting, not failed.** Such a workspace reports a `waiting` pass with no
  error, the console shows a neutral note, and metrics count it as a waiting
  pass. Real failures stay red.

## v1.42.3

- **Fix: Slack handlers no longer log raw request values.** Every request- or
  Slack-derived value in the Slack console handlers, the Slack controller and
  its records is routed through `logsafe`, as the GitHub handlers already did,
  so a crafted value cannot forge a log record. This closes the open
  `go/log-injection` findings; no token is logged.
- **Guard: a changed audit catalogue under an unchanged version is refused by a
  test.** The document of each released catalogue version is frozen as a test
  fixture, and a catalogue carrying one of those versions must equal it. A
  change to the catalogue now needs a new version and its fixture.

## v1.42.2

- **Fix: a slow client-document origin no longer fails a sign-in.** The fetch
  of a client document (`client_documents`) now allows 10 seconds per attempt
  (was 5) and retries once, after a short pause, on a timeout, a reset
  connection or a 5xx, within the sign-in's own deadline. When refreshing an
  already-validated document still fails that way, the last good copy is served
  for at most one hour past its ten-minute expiry, with a warning logged each
  time. Never on a validation failure, a redirect or a 4xx: those stay refused.
  Allow-listed origins, no redirects, the size limit and document validation
  are unchanged.

## v1.42.1

- **Fix: the audit catalogue's version is now 1.1.0.** v1.41.0 and v1.42.0 added
  actions under 1.0.0, so an audit installation that had already registered
  1.0.0 refused the changed document and the service stopped at start.

## v1.42.0

- **BREAKING: a Slack workspace's team, owner and domains, and a GitHub
  organisation's owner, are no longer policy keys.** v1.41.0 briefly let the
  policy carry `slack.workspaces.<key>.team_id`, `.domains` and `.owner` and
  `github.<org>.owner`. access-roster already knows each at run time (each
  connected directory has its workspace id and the domains it serves, a Slack
  install tells us the team, and the person connecting acts within a
  directory), so holding them twice was drift waiting to happen. A policy that
  still carries any of them is **refused at load**, with a message saying where
  the value now comes from. **Migration:** delete the keys, then connect (or
  reconnect) from the console, where the owning directory is chosen. A Slack
  workspace stays held (*no owning directory: set the owner on the console*)
  until it has an owner; a GitHub organisation keeps working as an
  installation-wide one until it is connected with an owner, or the
  installation-wide operator sets one. The policy keeps what is policy: the
  workspace key and `channels` (with `mode` and `ignore`), `people`, and GitHub
  team bindings. Removed from `policy`: `SlackWorkspace.TeamID`, `.Domains`,
  `.Owner`, `GitHubOrg.Owner`, `Set.SlackWorkspaceTeam`, `Set.SlackOwner`,
  `Set.GitHubOwner` and `SlackWorkspace.NormalisedDomains`; added
  `Set.SlackWorkspaceDeclared`.
- **Upgrade order: roll the console before the slack-roster controller.** The
  controller now needs the new `ListServedDomains` RPC and fails every pass
  against an older console. Its identity must also hold the installation-wide
  viewer role (or the viewer role over each owning directory) to read the
  served domains.
- **New: the owner is recorded when a connection is made.** One rule for Slack
  workspaces and GitHub organisations. The installation-wide operator chooses
  the owning directory from the connected ones, or none; an operator of
  exactly one connected directory owns what they connect; an operator of
  several chooses among theirs; a directory the caller does not operate, or one
  that is not connected, is refused. The owner is the connection record's
  `owner` (optional in version 1, so a record written before it reads as "no
  owner" and stays installation-wide) and is carried in the signed connect state
  to the callback that creates the record. Every owner check (`requireOwner`, the
  Slack catalogue, the workspace page, the Slack Connect editor, viewer
  filtering, `github_owner`) now reads the **connection record**, not the policy.
  Only the installation-wide operator changes it afterwards: new RPCs
  `ChangeSlackWorkspaceOwner` and `ChangeGitHubOrganisationOwner`, audited as
  `roster.slack_workspace.owner_changed` and `roster.github_org.owner_changed`.
  `roster.slack_workspace.connected` and `roster.github_org.connected` now carry
  `owner`. The connect forms show the owner choice where there is one, the rows
  show the owner by its primary domain, and the installation-wide operator gets
  *Change owner*. New request fields `BeginSlackWorkspaceConnectRequest.owner`
  and `BeginGitHubConnectRequest`/`BeginGitHubAppConnectRequest.owner_directory`;
  new response fields `owner_choices` and `may_connect_without_owner`, and
  `owner_domain`, `can_change_owner` on the rows.
- **New: the Slack team is recorded at the first install.** The workspace
  connect callback records the team from `oauth.v2.access`; any later install
  or reconnect must match it (a mismatch is revoked and refused, as before),
  and so is a first install into a team already connected under another key.
  The Slack App catalogue now requires its entry's workspace to be connected
  first (*connect the workspace first*) and holds its install to the recorded
  team. A record is valid with no team until the first install
  (`connection.Record.TeamID` is optional).
- **New: a person is looked up by the owning directory's served domains, every
  pass.** The Slack controller reads the domains each connected directory serves
  from the console (new `AccessService.ListServedDomains`, a viewer's read,
  scoped like the others) and finds a person in a workspace by their address in
  its **owner's** domains. A workspace with no owner holds its people (*no owning
  directory: set the owner on the console*); a directory that cannot be read or
  is no longer connected fails the workspace's pass and changes nothing.
- **Changed: a bound Slack channel is an idempotent upsert, taken over by
  name.** Create if missing, otherwise adopt the existing channel by its
  declared name: a public one is joined and then managed, a private one the bot
  is in is managed, and each adoption is recorded once as
  `roster.slack_channel.adopted`. Before, a same-name channel the bot did not
  create was held (*adopt it by id*); `adopt: <id>` is now only an optional
  disambiguation (a renamed channel, two candidates), still validated as before.
  Kept safe, each held with its reason and tested: a channel whose visibility
  differs from the declared `private` is never converted; an archived channel of
  that name is never unarchived (the controller now lists archived channels,
  `slackapp.Client.AllChannels`, to tell an archived name from a free one); a
  private channel the bot cannot see makes `conversations.create` answer
  `name_taken`, which is a hold (*a private channel named X exists that the bot
  cannot see; invite the bot to it*), recorded once as
  `roster.slack_action.held`, never a duplicate under another name and no longer
  a failed `roster.slack_channel.created` every pass; and a `strict` adopted
  channel removes only after the directory vouches, with the first pass after
  adoption subject to the breaker like any other. A channel that was held for
  this reason before is adopted on the first pass after the upgrade, in a
  workspace listed in `slackRoster.actsIn`: review a dry run first.
- **State:** `access.Binding` carries the owner a flow will record; a state
  issued before it (four parts) still verifies, as one with no owner.

## v1.41.0

- **New: `OUTBOUND_CA_FILE` for resource-proxy.** A PEM bundle appended to the
  system root pool, used only by the outbound forwarder's connection to
  `OUTBOUND_TARGET`, so a target served by a private CA is reachable while
  everything else (the issuer, the token exchange) keeps trusting public roots
  only. Flag `--outbound-ca-file`. Read once at start; a file that is unreadable
  or holds no certificate refuses to start; it needs `OUTBOUND_LISTEN` like the
  other `OUTBOUND_*` values. Restart to rotate.
- **New: Slack Connect channels, created and edited on the console.** A
  shared channel between the installation's own Slack workspaces is a record,
  not policy: `name`, `host` (the workspace that creates and owns it,
  **immutable**), `with`, `from` (policy groups: members come only from
  groups) and `private` (one bool, or one per side). The new Slack Connect page
  lists the records with what the host's controller reported (not reported,
  pending, waiting for acceptance, active, held, invalid), creates, edits (`with`,
  `from`, `private`; a change of host or name is refused with "create a new
  channel") and deletes (the record only: the channel stays in Slack and the
  reconciler stops managing it). Records are validated against the policy and
  written as `_shared.<name>.json` in `<release>-slack-workspaces` under the
  ConfigMap's version, retried on a conflict. The operator of the host
  workspace's owner, or the installation-wide operator, may change a record;
  viewers of any workspace it touches see it. New RPCs `SlackSharedChannelService`
  (`ListSlackSharedChannels`, `CreateSlackSharedChannel`,
  `UpdateSlackSharedChannel`, `DeleteSlackSharedChannel`), new audit actions
  `roster.slack_shared_channel.created`, `.updated` and `.deleted`. See
  [docs/connect/slack-connect-channels.md](docs/guides/sluis/connect/slack-connect-channels.md).
- **New: the Slack page.** Connect, read and operate a Slack workspace from
  the console. **Connect** pastes a throwaway app configuration token
  (api.slack.com/apps, *Your App Configuration Tokens*; 12 hours, used once,
  never stored or logged): the service creates the roster's own Slack App from
  a manifest carrying `connection.BotScopes` (nine bot scopes, including `conversations.connect:manage` for listing Slack Connect invitations, each for a
  method the controller calls), keeps its client id and secret as "created, not
  installed", and sends an owner of the workspace to Slack. On the way back the
  bot token is written into `<release>-slack-credentials` and the record into
  `<release>-slack-workspaces` only if Slack says it belongs to the policy's
  `team_id`; any other workspace is **revoked** (`auth.revoke`) and refused,
  recorded as `roster.slack_workspace.connect_refused`. **Reconnect** grants
  new scopes (with a configuration token that updates the manifest),
  **Disconnect** revokes the token and forgets the connection, and the page
  shows per workspace the connection, acting or dry run, the last pass, each
  channel's people (in step, will invite, will remove, held with the reason),
  leavers and any breaker, with **Confirm** for an operator
  (`ConfirmSlackRemovals`: the fingerprint must be the latest report's for that
  gate; lapses in 24 hours; audited). Gated by the workspace's owner
  (`slack.workspaces.<key>.owner`), each row carrying `can_operate`. New
  service `SlackService` (`GetSlackStatus`, `BeginSlackWorkspaceConnect`,
  `DisconnectSlackWorkspace`, `ConfirmSlackRemovals`), new audit action
  `roster.slack_workspace.connect_refused`, new `slackapp.Client.Revoke`. The
  catalogue's install into the wrong workspace now revokes the token too. See
  [docs/connect/slack-workspace.md](docs/guides/sluis/connect/slack-workspace.md#connect-a-workspace-from-the-console).

- **New: a catalogue of Slack Apps, created and installed from the
  console.** `slackApps` declares each App (`id`, the policy's `workspace`
  key, `botScopes`, optional `name`, `description` and `push`). An operator
  creates it on the new Slack Apps page by pasting a throwaway app
  configuration token (api.slack.com/apps, *Your App Configuration Tokens*;
  it expires in 12 hours): the service builds the manifest, creates the App,
  and keeps its client id and secret as "created, not installed". Install
  sends an owner of the workspace to Slack and, on the way back, keeps the
  bot token as `<id>.slack_bot_token` in `<release>-slack-catalogue-apps`
  only if Slack says it belongs to the policy's `team_id` for that workspace;
  any other team is refused and recorded. An entry that later declares more
  scopes than Slack granted shows **scopes missing** and is reinstalled (with
  a configuration token, which updates the manifest). The configuration token
  is used for one call and never stored or logged. `push` copies only the bot
  token, through a PushSecret per entry. New RPCs `SlackAppService`
  (`ListSlackApps`, `CreateSlackApp`, `InstallSlackApp`), new audit actions
  `roster.slack_app.created`, `.installed` and `.install_refused`. See
  [docs/connect/slack-apps-catalogue.md](docs/guides/sluis/connect/slack-apps-catalogue.md).
- **New: per-organisation operators for Slack workspaces.**
  `slack.workspaces.<key>.owner` names the directory workspace that owns a
  Slack workspace, with the same meaning and checks as
  `github.<org>.owner`: its scoped operator creates, installs and reinstalls
  its Apps, the Slack Apps page lists only what the caller may view, and each
  row says whether the caller may operate it (`can_operate`). See
  [docs/reference/sluis/policy.md](docs/reference/sluis/policy-ownership.md#who-owns-a-slack-workspace).

- **New: per-organisation operators for GitHub.** `github.<org>.owner`
  names the directory workspace that owns an organisation; its scoped
  operator (`<id>:access-roster:operator`) may then connect, reconnect and
  disconnect it, confirm its removals and manage its runner and catalogue
  Apps, beside the installation-wide operator. An organisation with no
  `owner` is operated by the installation-wide roles alone, as before, so
  nothing changes until one is named. The check is one helper
  (`requireOwner`) that Slack workspaces will use for theirs. The GitHub
  pages list only the organisations the caller may view, each row says
  whether the caller may operate it (`can_operate`), and the connect
  callbacks ask the role question again. See
  [docs/reference/sluis/policy.md](docs/reference/sluis/policy-ownership.md#who-owns-a-github-organisation).
- **New: the Slack controller, `slack-roster`, and its chart values
  `slackRoster.*`.** A second process from the `access-issuer` chart (and its
  own image and archive) that makes each Slack workspace's channels match the
  policy's `slack` table: per pass it reads Slack whole, asks the directory who
  holds each bound group and to vouch (one question per address per pass) for
  each removal and leaver, decides, and acts only in the workspaces listed in
  `slackRoster.actsIn`; every other workspace is a dry run that publishes its
  report and changes and records nothing. A removal set over half of a channel
  or of a workspace is held until an operator confirms that exact fingerprint;
  **one confirmation now satisfies every breaker gate that fingerprint covers**
  (before, a single-channel trip needed the same set confirmed twice). Leavers
  and new holds are reported and recorded once. A workspace that is not
  connected, not installed or whose read failed is reported `failed` alone. It
  never creates accounts, touches user groups or removes anybody from a public
  channel. It needs egress to `slack.com:443`, which the chart leaves to the
  fleet's egress policy. Off by default; see
  [docs/connect/slack-workspace.md](docs/guides/sluis/connect/slack-workspace.md).
- **New: `people` and `slack` in the policy schema (schema only; no
  controller yet).** `people` links the addresses of one person across
  domains; `slack` declares workspaces (own key, Slack `team_id`, email
  `domains`) and the channels bound in them to internal groups, created or
  adopted by ID. A channel is `mode: extend` (the default: only add) or
  `mode: strict` (add and remove; private channels only, so `strict` on a
  public channel is refused at load because Slack lets only administrators
  remove people from one), and a strict channel may `ignore` addresses or
  Slack user ids it never removes. Both keys are validated at load, merged
  across files as `github` is, covered by the policy digest, and their groups
  count as consumed. Slack Connect shared channels are not in the policy:
  they are managed on the console. A controller that reads these keys is
  being built; until it ships, nothing does. (The controller ships in this same
  release, in the first bullet above.)
  See [docs/reference/sluis/policy.md](docs/reference/sluis/policy-bindings.md#slack-channels).
- **Internal: the Slack reconciler's core (`internal/slackroster`): the pure
  decision (who to invite, remove, hold and report in each workspace's
  channels, and in Slack Connect channels given as input), its status
  document, the per-workspace connection record and credential, and the step
  that applies a decision through the Slack client.** No controller runs it
  yet. (The controller ships in this same release, in the first bullet above.)
  `internal/slackapp` gains `UserInfo` (a member's address) and
  `SharedTeamIDs` on a channel. See
  [docs/concepts/sluis/slack-reconciler.md](docs/concepts/sluis/slack-reconciler.md).
- **Internal: `internal/rails` now holds what the GitHub controller and the
  reconcilers after it share: the pass loop with its policy-retry backoff
  (`Run`), the console's two questions gated by the policy digest
  (`Directory`) with the removal rule (`Removal`), the held-once ledger
  (`Ledger`) and the last-good-report journal (`Journal`).** The GitHub
  controller calls them and keeps everything GitHub-shaped to itself. No
  user-visible change: same decisions, same audit records, same metrics.
  See [docs/concepts/sluis/github-controller.md](docs/concepts/sluis/github-controller.md#reconciler-rails).

## v1.40.0

- **New: `resource-proxy`, a sidecar that gives a stock MCP server (or any
  HTTP service) an access-roster resource server's front door, and
  `identity/resource`, the library it is built on.** Inbound it verifies
  the caller's token (signature, issuer, `aud` = the resource's own URL),
  serves the RFC 9728 Protected Resource Metadata at its path-suffixed
  location, answers `401` with `WWW-Authenticate: Bearer
  resource_metadata="...", scope="..."`, writes one audit line per request
  (caller, client, JSON-RPC method and tool, status, duration; never a
  token or a body) and reverse-proxies with the caller's `Authorization`
  removed and SSE streaming intact. Optionally, on a loopback listener, it
  injects a bearer token the workload's own projected ServiceAccount token
  earned by an RFC 8693 exchange, so the stock server holds no credential.
  The image is `ghcr.io/truvity/access-roster/resource-proxy:<version>`,
  multi-arch. See [docs/connect/mcp.md](docs/guides/sluis/connect/mcp.md#fronting-a-stock-mcp-server-with-resource-proxy).
  `identity.Verified` gains `ClientID` (the token's `azp`, or
  `client_id`). No existing package changes behaviour.

- **Removed: the one-time label move.** The start-up relabel of objects an
  earlier release wrote under the old label keys, and the once-a-minute
  sweep that repeated it, are gone: every installation has run a release
  that contained them. An installation still holding objects under the
  old keys must run a release that has the move (see the entry that added
  it) first; the credential-store migration is unaffected.

- **Fixed: reopening a stored, console-connected workspace at start no
  longer refuses every backend kind but `"google"`.** `openStored`
  hardcoded that check, so a second backend (Entra, say) would be
  adopted from a fresh consent but rejected the moment the process
  restarted -- even though `backend.Backend` is documented as
  multi-implementation and the wire contract already carries
  `BACKEND_ENTRA`. It now resolves the kind through the same connector
  list the console offers for connecting a workspace the first time, via
  the new `server.CredentialReopener` an implementation opts into next to
  `Exchange` and `FromKey`. A kind with no such connector is still
  refused, by name.
- **Internal: the GitHub controller's confirm-before-remove gate, policy-digest
  guard, removal circuit breaker and dry-run switch moved to a new
  `internal/rails` package**, generic over what a reconciler is confirming or
  breaking on instead of GitHub-shaped. `internal/githubroster` now calls
  `internal/rails` for these four pieces and keeps everything GitHub-shaped —
  teams, logins, invitations, deriving and deciding — to itself. No
  user-visible change: same decisions, same audit records, same metrics. See
  [docs/concepts/sluis/github-controller.md](docs/concepts/sluis/github-controller.md#reconciler-rails).

## v1.39.2

- **Fixed: since v1.29.0, `resources` and `client_documents` declared in
  a multi-file policy directory — the chart's layout — were silently
  ignored.** Loading a directory merges its files one by one, and the
  merge had no case for either block, so both were read and then
  dropped. A single-file policy was unaffected. In a deployment this
  meant the discovery document never advertised
  `client_id_metadata_document_supported`, no document client was
  admitted, and no declared resource could be asked for. The failure
  granted less rather than more, but a declared block that does nothing
  is a defect all the same. Both now merge like the rest:
  - `resources` merge by id, and one id declared in two files is
    refused, exactly as a client is.
  - `client_documents` is installation-wide, like `vocabulary`: a second
    file declaring it is refused. An empty `client_documents: {}` counts
    as not declared, since it turns nothing on.

  After upgrading, a directory that declares one resource id in two
  files, or `client_documents` in two files, refuses to load. Before,
  it loaded and the block did nothing.

  A test now lists every field of the policy, and of a GitHub
  organisation binding, with the rule for merging it. A field added
  without one fails the build.
- README gains `Consumers` and `Neighbours` (openbao as relying party, audit, `accessctl` versus workstation's `awsctl`); a test fixture's audience is neutral; ci-workflows pins moved to v3.13.1.

## v1.39.1

- **Every value the GitHub App, consent and workspace flows log now
  passes through `internal/logsafe`.** The organisation, tier, owner,
  workspace, backend, App slug and the errors built from them were
  written as they arrived. The JSON handler escaped them already, so
  none of it was forgeable in practice. Now it is true by construction,
  as it already was for addresses and paths.
- `github.com/truvity/audit` v0.3.1, the same version the console's
  `@truvity/audit` already pinned.

## v1.39.0

- **Added: `accessctl r2`, authenticating for an R2 credential broker's
  audience and then running the real `r2broker` CLI unchanged.**

  Follows the same shape `accessctl bao` already ships
  ([ADR 0013](docs/decisions/0013-openbao-access-through-the-bao-cli.md)):
  it signs in (or takes a job's own identity), exchanges for
  `--audience` (default `r2-broker`, or `$ACCESSCTL_R2_AUDIENCE`), and
  execs `r2broker` with the token in `R2BROKER_TOKEN` — never on argv,
  never in a temp file, since `runChild` replaces this process's image on
  every platform but Windows and a temp file written before an exec that
  never returns could not be cleaned up. The subcommand defaults to
  `credentials` when none is named, and `--service-url` (or
  `$ACCESSCTL_R2_SERVICE_URL`) is injected as `r2broker`'s own flag when
  configured, so a `credential_process` line can be as short as
  `accessctl r2 -- credentials --bucket <bucket> --prefix <prefix>/`. The
  token is cached one file per issuer, client and audience, the same
  shape and margin `kube-token`'s own cache uses.

  access-roster still holds no R2 logic: no bucket, no prefix, no
  permission is ever named here — everything after the sign-in is
  `r2broker`'s own syntax, per
  [ADR 0014](docs/decisions/0014-minting-third-party-credentials-only-where-membership-is-governed.md).
  See
  [docs/reference/sluis/sluisctl-wrappers.md#r2-authenticate-then-run-the-real-r2broker-cli-unchanged](docs/reference/sluis/sluisctl-wrappers.md#r2-authenticate-then-run-the-real-r2broker-cli-unchanged)
  and [docs/connect/r2-storage.md](docs/guides/sluis/connect/r2-storage.md).

## v1.38.0

- **Added: `accessctl ssh known-hosts`, which writes one managed file
  trusting an installation's own configured SSH host certificate
  authorities, so a laptop stops being prompted on the first connection
  to a fleet host.**

  `~/.ssh/known_hosts.d/accessctl` (or `--file`) is fully rewritten each
  run with one `@cert-authority <patterns> <key>` line per configured
  entry — never `~/.ssh/known_hosts` or `~/.ssh/config` themselves. The
  list of CAs to trust is entirely config, never code: `config.yaml`'s
  own `sshKnownHosts:` section (or `$ACCESSCTL_SSH_KNOWN_HOSTS`, the
  same YAML, when the file names none), each entry pairing one or more
  SSH host patterns with a CA source — a full `url:`, or
  `openbao: {namespace, mount}` joined with the address `accessctl bao`
  already resolves (`--address`, then `$BAO_ADDR`/`$VAULT_ADDR`). Only
  `ssh-ed25519` CA keys are ever written, and a fetch failure keeps the
  previous run's line for that entry (with a warning) rather than
  dropping trust silently or failing the whole run over one
  environment's CA being briefly down.

  It never edits `~/.ssh/config`; it only checks whether a
  `UserKnownHostsFile` line already names the managed file and prints
  the one line to add when it does not. `accessctl login` refreshes the
  file automatically once something is configured — a fresh sign-in
  never fails, or prints anything, over a feature it was never opted
  into. See
  [docs/reference/sluis/sluisctl-wrappers.md#ssh-known-hosts-trust-configured-ssh-host-cas-before-the-first-connect](docs/reference/sluis/sluisctl-wrappers.md#ssh-known-hosts-trust-configured-ssh-host-cas-before-the-first-connect),
  [docs/connect/ssh.md](docs/guides/sluis/connect/ssh.md) and
  [docs/decisions/0016](docs/decisions/0016-a-managed-known-hosts-file-for-ssh-host-cas.md).

## v1.37.0

- **Added: `groups_delimiter`, a per-audience policy option that rewrites
  a token's `groups` claim to work around opkssh's own colon-splitting
  bug.**

  A client row or a resource row may pin `groups_delimiter: "."` (or
  another delimiter this schema accepts), modelled on `signing_alg`
  ([docs/decisions/0009](docs/decisions/0009-a-default-signing-algorithm-and-per-audience-exceptions.md)):
  after
  [per-audience groups scoping](docs/reference/sluis/policy.md#groups-in-a-token-scoping)
  has decided which groups a token for that audience carries, every `:`
  in each one is rewritten to the configured string — `devel:ssh:user`
  becomes `devel.ssh.user`. This is for opkssh specifically: its
  server-side policy, `oidc:groups:<value>`, splits its argument on
  EVERY `:` and reads only the last segment, so it can never match a name
  shaped `<scope>:<thing>:<role>`, this schema's own separator, however
  it is quoted. Rows that name no `groups_delimiter` — every default
  installation, and every other audience of one that sets it — are
  unaffected.

  A delimiter is refused at load if it is empty, the separator itself, a
  quote, a comma, whitespace, or built from the alphabet a scope, thing
  or role is itself conventionally written in
  ([taxonomy.md](docs/reference/sluis/taxonomy.md)) — and, because no single character
  can be proven absent from every group name this schema could ever
  declare, also if it would collide two of the policy's own declared
  groups once rewritten. See
  [docs/decisions/0015](docs/decisions/0015-a-per-audience-groups-delimiter-for-opkssh.md)
  and
  [docs/reference/sluis/policy.md#groups-delimiter-per-audience-opkssh-interop](docs/reference/sluis/policy.md#groups-delimiter-per-audience-opkssh-interop)
  for the full mechanism. It is a temporary interop shim, meant to be
  removed once opkssh's own parser stops splitting on every `:`.

- **Added: a test pins that `/keys` and the discovery document carry no
  caching header a fronting proxy or CDN could turn into a stale-JWKS
  window.**

  A go-oidc-based verifier — a Kubernetes API server's OIDC authenticator
  (e.g. a managed EKS cluster), or Kargo — keeps its own JWKS cache and
  only refetches on an unknown `kid` once that cache has expired, deriving
  the expiry from `/keys`'s own `Cache-Control`/`Expires` headers. This
  issuer sets neither, so a rotated (or newly re-algorithm'd) `kid`
  verifies on the very next request — confirmed live.
  `TestJWKSAndDiscoveryAreNotCacheableByAProxy`
  (`internal/issuer/jwks_cache_test.go`) now fails the build the day that
  stops being true. See
  [docs/operations/high-availability.md#signing-keys-across-replicas](docs/concepts/sluis/high-availability.md#signing-keys-across-replicas)
  for the same rule restated as a deployment concern: nothing in front of
  this issuer may cache `/keys` either.

## v1.36.0

- **Added: `accessctl version` (and `--version`).**

  Prints this build's own version — `accessctl <version>`, `accessctl
  dev` for one built without the release workflow's ldflags — plus the
  commit and build date when the release stamps those too, from the same
  `internal/version` the services already report. `--version` and
  `-version`, as the first argument, do the same; `--json` prints
  `{"version", "commit", "date"}`, including only whichever of those
  this build carries. No network call, no config, no session, no `HOME`
  needed.

## v1.35.0

- **Added: `accessctl bao`, `pg` and `psql` gain `--login-ns` (and
  `$ACCESSCTL_BAO_LOGIN_NAMESPACE`), so an installation that keeps its
  logins at one parent namespace while data lives in per-project
  children can log in at the parent while still operating on the child.**

  A token minted by logging in to an OpenBAO namespace is valid there
  and in its children, never in a sibling — so `-ns=<env>/<project>`
  today has no way to log in anywhere but `<env>/<project>` itself, which
  fails wherever the login mount only exists at `<env>`. `--login-ns`
  (default: the target namespace, unchanged when neither it nor the
  environment variable is set) names where the login happens instead;
  the target must be `--login-ns` itself or a descendant of it (a
  path-segment prefix, not a string prefix: `dev` is not a parent of
  `devel`), refused as a usage error before any exchange otherwise. `bao`
  itself, and the PKI `sign` call `pg`/`psql` make, still run against
  their own target namespace unchanged. The login token cache is keyed
  by the login namespace rather than the target, so two targets sharing
  a parent login (`bao -ns=<env>/a`, `bao -ns=<env>/b`) reuse the same
  login; `--forget` clears the entry at that login namespace. See
  [docs/connect/openbao.md#logins-at-a-parent-namespace](docs/guides/sluis/connect/openbao.md#logins-at-a-parent-namespace).

## v1.34.0

- **Fixed: the "internal groups are declared but nothing consumes them"
  warning no longer names a group a GitHub App catalogue's grant
  consumes, or one only a `groups` override reaches.**

  `policy.Policy.Unconsumed` read `requires` on every client, resource
  and `client_documents`, GitHub org/team bindings, and the hub's own
  roles — but not a GitHub App catalogue's grants, which this package
  cannot read for itself: the catalogue is a deployment's own file,
  loaded by whichever process keeps one (`internal/app`, wired through
  to `internal/issuerapp`; the standalone `internal/githubroster/app`
  controller, which now reads it too, read-only, for this reason alone).
  `Unconsumed` gains a variadic `catalogueGroups` parameter — existing
  callers that pass nothing keep today's behaviour exactly — and
  `internal/githubapp/catalogue.Catalogue` gains `GrantGroups`, its
  `UndeclaredGroups` mirror, for a caller to read its own catalogue's
  grants with. On a real installation this closed about twenty false
  positives: every GitHub-derived group (`<org>:<repo-or-team>…`) that
  existed only to appear in a catalogue grant.

  While in there: a client's, resource's or `client_documents`' `groups`
  override (`docs/decisions/0006-groups-claim-scoped-per-audience.md`)
  is now counted too, by the same rule `Policy.ScopeGroups` applies to a
  live token — `groups: all` consumes every declared group, and
  `groups: [thing, ...]` consumes every declared group of that thing, in
  any scope. This closed a KNOWN LIMITATION `Unconsumed`'s own doc
  comment had carried since that override shipped: a client widening
  what it reads this way, rather than through `requires`, was invisible
  to this warning until now.

- **Added: `accessctl bao <args…>` authenticates to OpenBAO and runs the
  real `bao` binary, unchanged.** `docs/decisions/0013-openbao-access-through-the-bao-cli.md`:
  accessctl stops reimplementing OpenBAO's own features one
  `accessctl credential` kind at a time — the sign-in (or a job's own
  identity) is exchanged for `--audience openbao` and logged in on the
  JWT mount, in the SAME namespace the caller's own `bao` command is
  about to operate in (read from its `-namespace`/`--namespace` flag,
  then `BAO_NAMESPACE`, then `VAULT_NAMESPACE`), and the resulting token
  is handed to `bao` as `BAO_TOKEN` in the child process's environment
  alone — never `~/.vault-token`, never bao's own token helper file. The
  login is cached, one file per OpenBAO address, namespace and subject,
  under accessctl's own config directory; `accessctl bao --forget`
  revokes it and removes the cache entry. accessctl's own flags
  (`--address`, `--ca-cert`, `--issuer`, `--client`, `--audience`,
  `--mount`, `--login-role`, `--forget`) go BEFORE the bao subcommand;
  bao's own flags, including `-namespace`, go after it, exactly where
  bao has always accepted them. See
  [docs/reference/sluis/sluisctl-wrappers.md#bao-authenticate-then-run-bao-unchanged](docs/reference/sluis/sluisctl-wrappers.md#bao-authenticate-then-run-bao-unchanged)
  and [docs/connect/openbao.md](docs/guides/sluis/connect/openbao.md).

- **Added: `accessctl bao kv get ... -format=env` renders a KV secret as
  dotenv lines**, a stop-gap for the one thing `bao kv get` cannot do yet
  upstream (proposed there under the same rule). A string with none of
  `'`, CR or LF is written `KEY='value'`; any other string is
  `KEY="value"`, with backslash, `"`, `$`, CR and LF escaped; a number or
  boolean is written as its own JSON text; `null` is `KEY=''`; a nested
  object or array, or a key outside `[A-Za-z_][A-Za-z0-9_]*`, is refused
  by name rather than silently mangled or renamed. `-field` combined with
  `-format=env` is a usage error. Detected once, cheaply, against the
  installed `bao`'s own `-format` help: the day it lists `env` on its
  own, accessctl gets out of the way and the call is bao's own answer,
  unchanged.

- **Changed: the `accessctl secrets` refusal now points at `accessctl bao
  kv get`** instead of a bare `bao login` / `bao kv get` recipe, since
  accessctl now authenticates that path itself.
  `docs/decisions/0002-mission-boundary-tokens-and-memberships.md`.

- **Added: `accessctl psql` and `accessctl pg --` mint a Postgres client
  certificate and run a command with libpq's own environment variables
  pointed at it**, replacing `accessctl credential db`.
  `accessctl pg [flags] -- <command> [args…]` authenticates — sharing
  `accessctl bao`'s own login and its cache — mints (or reuses, five
  minutes' margin) a client certificate via `pki/sign/<role>` (`-role`,
  `db-client` by default; `-ns`, `-mount` mirroring `bao`'s own flag
  spelling), and runs `<command>` with `PGSSLCERT`, `PGSSLKEY`,
  `PGSSLROOTCERT` and `PGSSLMODE=verify-full` set, plus `PGUSER` (the
  certificate's own common name) **only when the caller has not already
  chosen one** — an explicit `-U`/`user=`, or a libpq service file's own
  `user=`, still wins. `accessctl psql [flags] [psql args…]` is the
  shorthand for `accessctl pg -- psql [psql args…]`; psql's own
  arguments, including a service file's `service=<name>`, pass through
  unchanged. accessctl no longer writes a `pg_service` entry: a
  repository keeps its own, committed and secret-free, and points
  `PGSERVICEFILE` at it. See
  [docs/reference/sluis/sluisctl-wrappers.md#pg--psql-a-postgres-client-certificate-then-a-command](docs/reference/sluis/sluisctl-wrappers.md#pg--psql-a-postgres-client-certificate-then-a-command)
  and [docs/connect/postgresql.md](docs/guides/sluis/connect/postgresql.md).

- **Breaking: `accessctl credential ssh|db|client` is removed.**
  `docs/decisions/0013-openbao-access-through-the-bao-cli.md`. Each now
  refuses, naming its replacement: `ssh` → `accessctl bao ssh -mode=ca`
  for an interactive session, or `accessctl bao write -field=signed_key
  <mount>/sign/<role> public_key=@key.pub > key-cert.pub` for scp, git,
  CI and Ansible; `db` → `accessctl psql` / `accessctl pg --`; `client`
  → `accessctl bao write <pki mount>/sign/<role> csr=@your.csr` (an
  `openssl req -new` recipe for the CSR is in
  [docs/connect/openbao.md](docs/guides/sluis/connect/openbao.md)). See
  [docs/connect/ssh.md](docs/guides/sluis/connect/ssh.md) and
  [docs/connect/postgresql.md](docs/guides/sluis/connect/postgresql.md) for the
  full replacements.

## v1.33.0

- **Added: a declared role may restrict itself to some of its thing's
  scopes.** `docs/decisions/0012-per-role-scopes-in-the-vocabulary.md`,
  extending 0010's vocabulary: a role's value in `things.<t>.roles` may
  now be an object (`user: { implies: [...], scopes: [...] }`) alongside
  the plain implies-list form it has always accepted, restricting that
  role to a non-empty subset of its thing's own declared scopes — `ssh`'s
  `user` role valid on `devel` alone even though `ssh` itself also
  declares `core`, `stage` and `prod`. `core:ssh:user` is refused,
  distinctly from a scope the thing itself does not have; a mapping
  wildcard skips a combination the role disallows the same way it already
  skips a thing without the role at all (`*:ssh:user` reaches
  `devel:ssh:user` alone); and an `implies` edge whose target role does
  not cover every scope its source does is refused at load rather than
  silently narrowed. No policy that declares no per-role `scopes` changes
  shape or behaviour. See
  [docs/reference/sluis/policy-vocabulary.md#per-role-scopes](docs/reference/sluis/policy-vocabulary.md#per-role-scopes)
  and [docs/taxonomy.md#per-role-scopes](docs/reference/sluis/taxonomy.md#per-role-scopes).

- **Added: `groupsScoping: enforce` actually narrows a token's `groups`
  claim, and `/userinfo`'s answer, to what report mode has been
  computing since 1.32.0.** Every path that writes `groups` is covered:
  the ID token, the access token (an authorization code, a refresh, a
  token exchange alike), `Storage.MintFor` (the console's own internal
  mint), and — closing the one gap report mode could not, on its own —
  `/userinfo`, scoped by the presented access token's own audience or
  resource, or a caller could recover the unscoped list with one extra
  call. `requires` still gates entry, and a `rung:` group's lifetime is
  still computed, off the FULL held set either way: scoping narrows what
  a token SAYS, never what the issuer computes from what a caller holds.
  Report's INFO line becomes a DEBUG line under enforce, at the same rate
  limit, for turning on when a role goes missing.

  Opt-in: the chart's default stays `report`. `docs/reference/sluis/policy.md#groups-in-a-token-scoping`
  and `docs/guides/sluis/turn-enforce-on.md` for how to move
  from report's findings to `enforce`, and how to find a role that went
  missing once it is on.

- **Added: a `groups` override entry may name a two-segment FAMILY
  (`rung`, `emp`), not only a thing.** `rung:<name>` and `emp:<slug>` have
  no thing a pair could match or an outright thing entry could widen, so
  the only way to keep one under scoping used to be naming it outright,
  one exact name at a time (`groups: [rung:sre]`) — unworkable for a
  Kubernetes audience binding every person's own `emp:<slug>` to their
  namespace, where no single entry could name every person's slug up
  front. `groups: [emp]` now keeps every held `emp:` name at once, the
  same way a thing entry keeps every role of it; `groups: [rung]` does
  the same for `rung:`. A declared vocabulary constrains a bare-word entry
  to a declared thing or one of the two known families; an exact
  two-segment name validates either way, unchanged. See
  `docs/reference/sluis/policy.md#groups-in-a-token-scoping`.

## v1.32.1

- **Fixed: per-audience `groups` scoping now reads a self-described
  client's own gate, `client_documents.requires`.**

  `policy.Policy.ScopeGroups` fell through to "no gate" for any audience
  that was not a declared client or resource row, which included every
  self-described client (an MCP client or similar, admitted by URL
  through `client_documents`) — even though such a client IS gated, by
  `client_documents.requires`, which every one of them shares. Report
  mode was logging every held group as dropped for these audiences, and a
  future enforce mode would have handed them no groups at all.

  `client_documents` also gains its own optional `groups` override,
  validated the same way a client's or a resource's is, so an
  installation can widen it for every document client at once. An
  audience that matches no gate at all — not a client, not a resource,
  and not a URL `client_documents.origins` permits — still keeps nothing,
  which remains the useful report-mode signal that it needs one of the
  three before enforce mode could narrow anything for it correctly.

  Also notes, for whichever release ships `enforce`, that `userinfo` has
  to be scoped by the token's own audience too: narrowing only the token
  and leaving `userinfo` unscoped would let a relying party read the
  fuller list by calling `userinfo` instead.

## v1.32.0

- **Added: per-audience `groups` scoping, in REPORT-ONLY mode — no token
  changes shape yet.**

  `docs/decisions/0006-groups-claim-scoped-per-audience.md`, refined by
  0010's vocabulary: a token would keep only the held groups whose
  `<scope>:<thing>` pair appears among its audience's `requires` pairs, in
  any role, plus a declared `groups: all` or `groups: [thing, ...]`
  override on that client or resource row. `policy.Policy.ScopeGroups`
  computes this at every place a token's `groups` claim is built — the ID
  token, the access token (authorization code, refresh and a token
  exchange's own claims all converge on one hook), and the console's
  internal mint — and logs ONE line at INFO (audience, client, subject,
  dropped groups) when it would have dropped something, rate-limited per
  (audience, subject, dropped-set) to once every ten minutes. **It is
  never applied**: every token this release mints carries exactly the
  `groups` it always has, byte for byte, proven by tests for the ID token,
  the access token and an exchange alike.

  The chart's new `groupsScoping` value (`GROUPS_SCOPING` in the
  environment) is `off`, `report` (the default) or `enforce`; `enforce`,
  which would actually narrow a token, is **refused at issuer start** in
  this release, by name, so the switch is visible and wired before an
  installation can reach for it. See
  [docs/reference/sluis/policy.md#groups-in-a-token-scoping](docs/reference/sluis/policy.md#groups-in-a-token-scoping),
  [docs/reference/sluis/configuration.md](docs/reference/sluis/configuration.md) and
  [docs/guides/sluis/read-the-groups-scoping-report.md](docs/guides/sluis/read-the-groups-scoping-report.md)
  for reading what report mode finds.

- **Added: an optional `vocabulary` table declares which scopes and things
  exist, each thing's role ladder, and which role implies which other
  one — things, scopes, roles, inheritance and mapping wildcards.**

  Opt-in and strict: a policy with no `vocabulary` table changes nothing,
  proven by a test. Declare one, and the policy refuses to load when a
  concrete grant anywhere in the file — a `groups` key, a `claims` key, a
  `lifetimes` key, any `requires`, any GitHub binding — names an
  undeclared scope or thing, a scope the thing does not have, or a role
  the thing does not declare. `rung:`/`emp:` names stay exempt, as they
  always were.

  Roles imply explicitly (`admin: [operator]`, branching where a ladder
  branches) and the graph may not cycle; holding a role also holds every
  role it implies, transitively, on the SAME scope and thing — never
  across scopes, so `all:x:admin` never implies `devel:x:admin`. This is
  applied once, in evaluation, so a client's `requires`, a token's
  `groups` claim and GitHub team reconciliation all see the expanded set
  without knowing inheritance exists: a GitHub team bound to `S:T:viewer`
  is now fed by anyone in `S:T:admin` too.

  A `groups` key may use `*` in the scope and/or thing position —
  `*:k8s:admin`, `devel:*:viewer` — expanding, against the vocabulary,
  into every concrete grant a declared thing has for that scope and role,
  excluding every scope marked `sensitive`. A role wildcard and `*:*:*`
  are always refused, wildcards need a declared vocabulary, and a
  wildcard may only appear as a `groups` key — never in `requires`, a
  GitHub binding, `claims` or `lifetimes`. Nothing past evaluation ever
  sees anything but a concrete name.

  `policy.Result`'s `Held` now carries, per held group, which `groups`
  key matched directly and which concrete group's role implied it, so a
  later console change can explain the chain; the `Unconsumed` lint
  counts a wildcard key as consumed the moment any group its expansion
  names is.

  See [docs/reference/sluis/policy.md#vocabulary](docs/reference/sluis/policy.md#vocabulary),
  [docs/taxonomy.md](docs/reference/sluis/taxonomy.md) and
  [docs/decisions/0010-a-declared-vocabulary.md](docs/decisions/0010-a-declared-vocabulary.md).

- **Added: a person's page states the whole "why do I hold this group"
  chain, not just the group's own name.**

  `Explain`'s `HeldGroup` now carries `granted_by_key` (the `groups`
  table key that matched — a mapping wildcard's own spelling when that is
  what matched, the group's own name otherwise), `wildcard` (whether that
  key is a wildcard), and `implied_by` (the direct parent group, when the
  entry came from inheritance rather than a direct hold). Every existing
  field is unchanged; these are additive, on new field numbers.

  The console renders one line per held group by walking `implied_by`
  hop by hop, client-side, from the already-fetched `Explain` answer:
  `stage:k8s:viewer ← implied by stage:k8s:operator ← implied by
  stage:k8s:admin ← wildcard *:k8s:admin ← directory group
  sre@example.com`.

- **Breaking: the `access-proxy` chart is no longer published.** Gateway-native
  OIDC (a `SecurityPolicy` with `oidc:` on Envoy Gateway) is the replacement
  for a console with no OpenID flow of its own. For a gateway that is not Envoy
  Gateway, run upstream `oauth2-proxy` yourself following the recipe in
  [docs/design/access-proxy.md](docs/guides/sluis/connect/oauth2-proxy.md).

  Versions of the chart already published remain available in the OCI registry,
  so existing pins keep working. See
  [ADR 0003](docs/decisions/0003-deprecate-access-proxy.md) for the rationale.

## v1.31.0

- **Added: the issuer and github-roster warn at load if an internal group is
  declared but nothing consumes it.**

  A group referenced by a client, resource, or GitHub binding is working. A
  group referenced only by `claims` or `lifetimes` is still unused, because
  claims and lifetimes decorate a group and do not consume it. The hub's own
  roles (`operator` and `viewer` on `access-roster`) are not reported, because
  the hub reads them directly from the token. A group with the `rung:` or
  `emp:` prefix is never reported, because these are identities and sessions,
  not grants.

  **Known limitation:** a relying party may read groups beyond what its
  `requires` names, for its own role mapping (a console's viewer vs editor
  role, for example). Such groups are consumed outside the policy's view, so
  this warning may name them. The gap closes when a client can declare what
  it maps — per `docs/decisions/0006-groups-claim-scoped-per-audience.md`.

  The warning reaches an operator at the moment they see their logs, where
  they can check whether the group is a leftover, a typo, or intentionally
  ahead of the client that will use it. It is a warning rather than an error,
  because an installation may legitimately prepare a group before its consumer
  arrives.

- **Added:** the issuer signs with several algorithms at once — RS256,
  ES256 and ES384 — chosen per token by the audience it is minted for,
  rather than one algorithm for the whole installation.

  A client row or a resource row may pin `signing_alg: RS256 | ES256 |
  ES384` in the policy; a row naming none keeps signing the installation
  default (ES384 in the chart, unchanged). This is for the relying
  parties that lag: EKS's associated OIDC identity provider and Kargo's
  verifier both accept RS256 only, and OIDC Core §15.1 expects a provider
  to be *able* to sign with it — previously the only fix was moving the
  *whole* installation's default key to RSA, off every other audience's
  ES384 too.

  `signingKey.additional[]` in the `access-issuer` chart adds a key per
  extra algorithm, each its own cert-manager `Certificate` and `Secret`,
  each on its own rotation track: renewing one never disturbs another's
  schedule, including the default key's. A policy row naming an algorithm
  with no configured key is refused loudly at issuer start, never a
  silent fall-back to the default. The existing single-key
  `signingKey.certificate` shape is unchanged and renders byte-identical
  output.

  See [reference/policy.md#signing-algorithm-per-audience](docs/reference/sluis/policy.md#signing-algorithm-per-audience)
  and [ADR 0009](docs/decisions/0009-a-default-signing-algorithm-and-per-audience-exceptions.md).

## v1.30.0

- **An absolute session limit: every session now ends 24 hours after
  sign-in, no matter how often it is refreshed. This is a behaviour
  change.**

  A per-client session slid forward on every refresh — `ExpiresAt =
  now + lifetimes.refresh` — with nothing measuring how long ago the
  person actually signed in. A client that refreshed often enough (a
  proxy, a CLI left running) stayed signed in indefinitely, and
  `auth_time` was carried into every token without ever being checked.

  `lifetimes.absolute` (default `24h`) is the new cap, and a session's
  end is now `min(now + lifetimes.refresh, auth_time + lifetimes.absolute)`
  — decided when it opens and recomputed on every rotation, so a sliding
  refresher plateaus at the limit instead of climbing past it:

  ```yaml
  lifetimes:
    refresh: 12h
    absolute: 24h # may be shorter OR longer than refresh; the earlier wins
  ```

  **Three things enforce it.** A refresh presented at or after the limit
  is refused (`invalid_grant`) and the session is revoked, with its own
  audit reason distinct from an ordinary inactivity timeout. An access or
  ID token's `exp` is capped the same way, even when the ordinary token
  lifetime would reach further — a session that has just hit the limit
  must not go on answering `userinfo` for whatever was left of its last
  token. And a **single sign-on** session whose `auth_time` is past the
  limit is ended outright — the same cascade `/logout` runs, Back-Channel
  Logout included — rather than answering a silent `/authorize`, which is
  what would otherwise let a browser left open renew its sign-in one
  client at a time forever.

  **Unaffected:** a workload or a machine trading a proof through token
  exchange authenticates nobody, carries no `auth_time`, and has nothing
  to measure the limit against — it keeps its ordinary refresh window,
  exactly as before. The console's own session is capped the same way,
  bounded by whichever of its own `directory.sessionLifetime` and the
  absolute limit is shorter.

  **Refused at render and at start**, not defaulted, if `lifetimes.absolute`
  is zero, negative, or shorter than `lifetimes.token`: a session cannot be
  limited to less time than its own first access token needs to live.

- **Fixed: the signing key rotates without a restart or a verification
  gap, and changing its algorithm is now just a rotation.**

  cert-manager's `rotationPolicy: Always` makes every renewal a new key,
  but the issuer only ever read `SIGNING_KEY_FILE` once at start. A
  renewal took effect only at the next restart; a rolling restart between
  it and then left replicas signing with different keys, so roughly half
  of every verification failed depending on which replica's JWKS was
  fetched; and once every replica had restarted, every token the previous
  key had signed failed at once, because the JWKS never kept it published
  after.

  The issuer now polls the mounted file and keeps a key ring: a newly
  seen key is published in the JWKS immediately, but this replica signs
  with it only once every other replica has had time to notice and
  publish it too — by default 15 minutes, long enough that verifiers'
  JWKS caches (Envoy's default is 10 minutes) and Secret projection delay
  have all passed — and the key it replaces stays published for at least
  as long as a token it signed can still be presented plus 5 minutes for
  clock skew before it retires. The schedule is decided once and shared
  through Valkey when one is configured, so a replica that restarts
  mid-rotation does not forget a key still inside its overlap; with none,
  it is kept in memory, which is right for one replica and a local run.
  **Changing `signingKey.certificate.algorithm` — RSA to ECDSA, or back —
  is now safe as just a rotation**: the JWKS and discovery's advertised
  algorithms carry both kinds for the overlap, then only the new one.

- **Breaking: `accessctl secrets` is removed.**

  Reading a team's shared values back out of a secret store's KV engine is
  the store's own job, once it can authenticate a person by the issuer's
  token. A courier command here duplicated a client the store itself should
  ship.

  **The replacement:** The store's own client. With OpenBAO: `bao login
  -method=oidc` then `bao kv get <path>`. With External Secrets in a
  cluster: write a SecretStore with the issuer as an auth provider. See
  [docs/decisions/0002-mission-boundary-tokens-and-memberships.md](docs/decisions/0002-mission-boundary-tokens-and-memberships.md)
  for the reasoning.

  Running `accessctl secrets` now fails immediately with a message naming
  the version and the replacement.

- **Breaking: the console's secret-store view and the `SecretManagerService` API
  are removed.**

  The console's Secret stores page displayed OpenBAO's policies, groups and
  aliases with a reader grant the issuer held. This is out of scope for
  access-roster, which delivers tokens and memberships, not authorization for
  other systems. See [docs/decisions/0002-mission-boundary-tokens-and-memberships.md](docs/decisions/0002-mission-boundary-tokens-and-memberships.md).

  **Migration:**

  1. Delete the `secretManagers` block from your deployment values.
  2. Revoke the reader grant you gave the issuer in OpenBAO: the policy
     `sys/policies/acl/*`, `identity/group/name*` and `sys/auth` — see
     [docs/connect/openbao.md](docs/guides/sluis/connect/openbao.md) for the full path list.
  3. Delete the secret stores page from your console bookmarks.

  **Sign in to OpenBAO stays unaffected:** the issuer still hands OpenBAO a
  bearer from its own token, and people still sign in with OpenBAO's own OIDC
  login or the issuer as a broker.

  **Values validation:** if `secretManagers` is still set, the chart render fails
  with a message that repeats this guidance. `SECRET_MANAGERS_FILE` at the issuer
  raises an error on start-up, with the same message. A deployment trying to activate
  the feature is clearly intentional, not silent drift.

## v1.29.0

- **A token can be minted for a resource, not only for the client asking
  — and a `resource` a client sends is now refused rather than ignored.**

  A client's id was always the audience, which held while the client and
  the thing a person reached were one object: sign in to Argo CD, get a
  token for Argo CD. It stops holding as soon as they are not. A Model
  Context Protocol client is somebody's editor; what it wants a token for
  is a service elsewhere, and `aud` naming the editor is both untrue and
  useless — a service pinning `aud` would have to pin the name of every
  editor that might call.

  The new `resources` table declares what a token may be for. A client
  names one with the `resource` parameter (RFC 8707) and `aud` becomes the
  resource:

  ```yaml
  resources:
    https://mcp.example/:
      requires: [prod:k8s:admin]
      ttl_cap: 5m
  ```

  **The two gates compose**: a client's `requires` says who may use that
  client, a resource's says who may reach that service, and a caller must
  satisfy both. Both `ttl_cap`s apply and the shorter wins.

  **`resource` was previously ignored, which was the worse half of this.**
  The library models no such field on an authorization request and its
  decoder drops unknown parameters, so a client asking for a token scoped
  to one service was handed one scoped to itself and told nothing — and
  the failure surfaced later, somewhere else, for a reason nobody connects
  to the request. It is now validated before the library sees it and
  refused with `invalid_target` as RFC 8707 says: for a resource this
  installation does not declare, for a relative URI or one carrying a
  fragment, and for more than one resource at a time.

  **Nothing changes for a client that names no resource** — its own id is
  still the audience, so no relying party needs to re-pin anything.

  **The session remembers which resource it was opened for.** A refresh
  carries a token and nothing else, so without that the renewed token
  would be minted for the *client* while the original named a resource —
  silently changing what the token is for halfway through a session, with
  the resource's gate unchecked for the rest of its life. It is re-checked
  on every refresh, which is where a withdrawn grant actually bites.

- **A client may register itself by serving a document, instead of needing
  a row in the policy.** Software this installation does not deploy and
  cannot enumerate — an editor, a hosted assistant, the clients of the
  Model Context Protocol — presents an HTTPS URL as its `client_id`, and
  that URL serves a JSON document describing it (an OAuth Client ID
  Metadata Document). The issuer fetches it, validates it, and treats the
  client as `public`. Nothing is registered and nothing accumulates.

  **Off unless an origin is named**, and the new `client_documents` block
  is where that happens:

  ```yaml
  client_documents:
    origins: [clients.example]
    requires: [rung:engineering]
    ttl_cap: 5m
  ```

  `requires` is **mandatory** alongside `origins`: turning the mechanism
  on without saying who may use it would admit every person who can sign
  in at all, which is not a decision anybody makes on purpose.

  Why an allow-list of origins rather than a refusal of unknown clients:
  registration is not the authorization decision here. Reach is decided by
  the groups a caller holds, so a client this issuer has never seen cannot
  widen anything — it can only ask a person to consent to the reach that
  person already has. A document may ask for a different `kind`, a longer
  cap or a wider `requires`; none of those fields is read. The threat is
  therefore phishing rather than escalation, and the allow-list is what
  bounds it.

  **A declared client always wins.** The policy is consulted first, so
  nothing is fetched for a client already in the file and a document
  cannot displace one. Existing clients are unaffected.

  The refusals, each with the failure it prevents, are in
  [reference/policy.md](docs/reference/sluis/policy-clients.md#clients-that-describe-themselves).
  Two worth naming here: a document whose `client_id` is not the URL it
  was served from is refused, because otherwise a document at any
  allow-listed host could claim to be any client; and a document that
  cannot be fetched fails the flow rather than falling back to a cached
  copy, because a cached copy is redirect URIs the client may have
  retired.

  `client_id_metadata_document_supported` is advertised in discovery only
  while an origin is named — a client reads it to decide whether to
  present a URL at all, so advertising it on an installation that admits
  none would send every such client into a refusal.

  Dynamic Client Registration is **not** implemented and is not planned:
  the Model Context Protocol deprecated it in its 2026-07-28 revision in
  favour of these documents, and its own failure mode is registrations
  that accumulate with nothing to review them against.

## v1.28.0

- **`accessctl` holds a session per issuer, so one laptop can be signed in
  at two estates at once.** There was a single `session.json`, so signing
  in at the second installation replaced the first one's refresh token.
  `--issuer` then selected the right endpoint and handed it the **wrong**
  token, which the issuer refuses as `subject_token is invalid` — a
  message that reads as expiry, and which sent people to re-run a login
  that had already worked. The sign-in now lives in
  `<config>/sessions/<issuer>-<hash>.json`, one file per installation.
  Nothing else moves: `config.yaml` still names the default issuer, a bare
  `accessctl whoami` behaves as before, and every context `kubeconfig`
  writes has always carried its own `--issuer` — the plumbing was already
  multi-issuer and only the login cache was not.

  Separate files rather than one file holding them all, for a second
  reason: more than one process writes here — every `kubectl`, every
  provider of a Pulumi stack — and with the sessions together, two exec
  plugins for **different** estates would rewrite the same file and one
  would lose its token. The refresh lock moves with the file, so a busy
  estate no longer makes the other one wait.

  The name is derived from the issuer so the directory is readable, and
  the issuer is stored **inside** the file: that is what a read checks, so
  a name that collides fails closed as *not signed in* rather than opening
  a session at the wrong estate. **No one signs in again** — an existing
  `session.json` is adopted by the first issuer that asks and replaced by
  the next `login`.

## v1.27.1

- **1.27.0's grace window was never reached, and this is the release that
  delivers it.** The refresh endpoint reads the token twice — the library
  resolves it to a request before it asks for new tokens — and the window
  was only in the second of those readings, so a replay was refused by the
  first and the window never ran. The one thing 1.27.0 changed in a running
  installation was the wording of the refusal. A deployment that took
  1.27.0 for the concurrent-refresh fix does not have it: a gateway that
  refreshes per request, or a page that opens several calls at once, still
  loses the session to its own concurrency. Both readings now resolve
  through the window, so a refresh token replayed within thirty seconds of
  being spent is answered with the successor the winning refresh produced,
  as 1.27.0 said it would be. `ByToken` is unchanged and still exact —
  revocation and listing are asking whether a token is the live one, which
  is a different question — and revocation resolves through the window too,
  so a caller revoking with a token a refresh rotated a moment earlier
  still ends the session rather than being refused and leaving it open.
  Nothing a caller passes or reads changed: upgrading from 1.27.0 is a fix
  and nothing else.

## v1.27.0

- **Breaking: `@truvity/access-roster/server` verifies with the algorithms
  the issuer advertises.** It pinned RS256, and the chart has signed with
  ECDSA P-384 by default since 1.19.0, so a Node service built per the
  documentation against a default installation rejected every token. The
  verifier now reads `id_token_signing_alg_values_supported` from
  discovery, falls back to the four the issuer can sign with (RS256,
  ES256, ES384, ES512) when nothing is advertised, never accepts `none`
  or an HMAC, and takes an `algorithms` option to narrow. A caller that
  relied on the RS256 pin against an issuer advertising more now accepts
  more; narrow it if that matters.
- **Every relying-party guide says which algorithm it needs.** kube-apiserver's
  `--oidc-signing-algs` defaults to RS256 and must name ES384 for a default
  installation; ArgoCD follows discovery; **Kargo is RS256-only** at the
  source, so an installation Kargo signs into must set
  `signingKey.certificate: {algorithm: RSA, size: 2048, encoding: PKCS1}`;
  IAM accepts ES384. The README's worked example says it ships ES384.
- **A concurrent refresh gets the winner's token, not a refusal.** Rotation
  spent the refresh token the moment it was presented, so of several
  refreshes carrying the same token exactly one could succeed and the rest
  were told the token is not live — the answer meant for a thief — which a
  relying party reads as a dead session. A gateway that verifies per request
  presents one spent token several times inside a second. Inside a short
  grace window a replay is now answered with the successor the winning
  refresh produced: the loser holds exactly what the winner holds, and the
  token it offered is never minted, so there is still one live credential.
- **The reference pages catch up with 1.17 to 1.25.** The configuration
  reference gains every chart key added since 1.17 — the signing-key
  certificate, the route's private key, both push blocks, the whole
  `secretManagers` section, `serviceAccount.annotations`,
  `networkPolicy.gatewayNamespace` — with the objects and environment it
  renders; the contracts page gains `SecretManagerService`; the accessctl
  reference documents the token caches and lock 1.25.1 added; the OpenBAO
  guide follows 1.24 and 1.25; the proxy reference gains
  `exposure.parentRefs`; the runbook's rotation section now states the
  per-Secret restart rule the chart's values state, replacing two
  instructions that did not work.

## v1.26.0

- **The audit trail is an installation of this service's own.** Every
  record goes to an installation of
  [truvity/audit](https://github.com/truvity/audit) rendered beside this
  service, in its namespace, at the address `audit.writer` names — which
  also takes the catalogue this service registers at start — and the
  console's Audit page reads that installation's query service
  (`audit.query`) with a token this issuer mints for the person signed in.
  This service holds no bucket, no keys and no cloud identity for the
  trail. What it keeps is the vocabulary: `internal/audit/catalogue/roster.yaml`
  declares thirty-seven actions, one constructor each, and
  `just audit-catalogue` holds the code to the document.
- **Breaking: the chart refuses `audit.s3.*` and `audit.maxEvents`**, and
  the `AuditService` and `AuditSinkService` RPCs are gone with the trail
  they served. The GitHub controller records as itself, with its own
  projected token, so the `all:access-roster:reporter` group it used to
  report through is not read; a policy may drop it. Objects the old trail
  wrote under `events/` are not migrated and age out under their lock.
- **Delivery is a bounded queue in memory, not an outbox on disk.** A
  record goes on the queue before the request completes and is retried
  with backoff until the writer takes it; past the queue's bound the oldest
  are dropped, counted (`audit.emit.records.dropped`) and each one logged
  by id at Error. A restart loses what the queue holds. The one exception
  stays: a recovery sign-in is `block`, kept before it succeeds and refused
  when it cannot be.
- **A refused catalogue ends the process**, whether at start or, after an
  unreachable start, on the retry that first gets an answer — a service
  whose records nobody accepts does not run for the life of the pod keeping
  nothing. A token the installation does not trust is said at Error naming
  the token file, rather than as "could not be reached" until the queue
  gives up.
- **`audit.forwardedForTrustedHops` counts the way the audit emitter
  counts**: X-Forwarded-For read left to right with the connection's peer as
  the last entry, so the peer is one hop. A gateway alone is 1; an edge
  that appends the client and a gateway that appends the edge's connector
  is 2 — where it used to be 1. A deployment with one proxy that appends
  the client, which the old count could not express, now records the
  client.
- `RecordDurable` refuses an action the catalogue does not declare `block`,
  because for any other it would return at enqueue and the caller would
  have been told a durability it did not have.
- Pinned at the component's v0.2.5, in the Go module and the console's
  package; the documentation describes the trail as it now is.

## v1.25.2

- `accessctl`'s token-cache lock builds on Windows too.

## v1.25.1

- **`accessctl` no longer signs the operator out of every audience when two
  of its processes run at once.** A refresh spends the refresh token — the
  issuer rotates it so a stolen one is good for a single use — and a
  credential process is not called once: every AWS provider a tool starts,
  and every kubectl, ran its own refresh, the first to finish rotated the
  token, and every other was left holding one the issuer refused, reported
  as "not signed in". `kube-token` and `aws` now keep a per-cluster and
  per-profile token cache under the config directory, take a lock around a
  refresh, and every command presents the issuer's own access token,
  kept in `session.json` beside the refresh token, while it lives.
- The chart's values say which of the Secrets it writes need a restart to
  rotate: none of them is watched, and each is read at a different moment.

## v1.25.0

- **A group's door twin is one row, not drift.** A store holds one alias
  per identity group, so admitting a group at two doors takes two
  identity groups — the bare name, and `<name>@<door>` carrying the same
  policy. The page drew them separately, which reported every group in
  the installation twice, the second time as drift nobody declared. They
  are now one row carrying both doors, which is what the column was for.
- **Only the groups the store holds a policy for are expected.** A
  cluster's tier, a CI job's group, the console's own: all of them are
  groups of the environment, and no secret store holds a policy for any
  of them. Reported as "not applied yet" they sent a reader looking for
  an apply that was never going to make them. The list is now the
  store's own exchange audience — a group is admitted to it exactly when
  the store holds a policy for it — so the page reads the same list the
  issuer enforces.
- **A group that spans environments is legitimate wherever it appears.**
  An `all:`-scoped group belongs to no single namespace: drawn as
  expected it was missing from every one of them, and left out entirely
  the installation's own reader appeared as drift. It is now shown where
  the store has it and never reported absent.

## v1.24.0

- **`secretManagers[].caCertConfigMap`** names a store's private root in
  a ConfigMap instead of a Secret. A root is not a secret, and
  cert-manager's trust-manager distributes one as a ConfigMap into every
  namespace — an installation that has it there had to copy it into a
  Secret to use it here. Name one of the two, never both: two bundles at
  one path is one of them silently unused, and the render refuses it.

## v1.23.0

- **The console shows a secret store.** A deployment declares one in
  `secretManagers:` — its address, the door to log in on, and which
  namespaces mirror which environments — and the console draws, per
  namespace, every group the deployment declares beside what the store
  holds, what each group's policy opens, and which doors admit it. A
  person's page gains what their own groups reach. `ListSecretManagers`,
  `GetSecretManagerNamespace` and `ListSecretManagerReach`, all viewer.
- **Read-only, and not by omission.** A store's desired state is written
  where you write it and applied by whatever applies it; a console that
  also wrote would make two custodians of one thing. No call here takes a
  write path, and the reader is granted the declared state — policies,
  identity groups, their aliases, the auth mounts — and **no KV path at
  all**, so a page built on this cannot show a secret's value however it
  is later changed. A drift row links to where the fix is made.
- **Four states, because a refused read is not an empty namespace.**
  `bound`, `not applied yet` (declared and not in the store — not drift:
  this side is already right), `not declared` (in the store and declared
  by nothing, the row worth opening the page for) and `cannot read`. The
  last is never inferred from an empty answer: the two are identical
  except in the status of the call, and reporting one as the other sends
  somebody to look at an apply that is fine.
- **The reader is this service's own ServiceAccount**, projected for the
  exchange audience and traded at the issuer for the store's audience
  exactly as a CI job's token is. No second credential, nothing stored,
  and the file is read per call because the kubelet rotates it under the
  pod. Give that identity `list` on `sys/policies/acl`,
  `identity/group/name` and `identity/group-alias/id`, `read` on each of
  their children and on `sys/auth`, and nothing else
  ([docs/connect/openbao.md](docs/guides/sluis/connect/openbao.md)). An
  exchange it is not granted is drawn on the page, naming the audience,
  rather than raised as an error.
- **`secretManagers[].caCertSecret`** mounts a PEM bundle trusted in
  addition to the system's roots, for that store alone.

## v1.22.0

- **`accessctl secrets env` fetches the values a team shares while it
  develops.** `accessctl secrets env --namespace staging --prefix
  orders/local-dev/checkout --out .env` exchanges the sign-in for
  `openbao`, logs in on the same JWT mount `credential` uses, walks a KV
  version 2 prefix to its leaves and writes one `KEY=value` line per leaf,
  `0600`, by rename. Nothing new is granted: reading a project's prefix is
  its `{env}:{project}:viewer` group, writing it is `deployer` and
  `approver`, and a `403` says so by name instead of repeating "permission
  denied". A run that reads **zero** keys fails rather than writing an
  empty `.env`, which is the failure nobody notices. Only the key names
  are printed, never a value.
  [docs/connect/openbao.md](docs/guides/sluis/connect/openbao.md),
  [docs/reference/sluis/sluisctl.md](docs/reference/sluis/sluisctl.md).

## v1.21.0

- **`access-issuer` keeps a recovery copy of the two Secrets nothing can
  re-deliver**, and `accessctl kubeconfig` writes `interactiveMode` on the
  entries it generates, without which kubectl refuses them.

## v1.20.2

- A pushed credential now declares the fields the `PushSecret` CRD
  defaults, so a deployment comparing desired against live stops reporting
  drift on a resource that is working.

## v1.20.1

- Shared CI v3.0.1.

## v1.20.0

- **`serviceAccount.annotations`** on the `access-issuer` chart, which is
  how a cloud identity reaches this service: an admission webhook — EKS Pod
  Identity, GKE Workload Identity, or the self-hosted
  `amazon-eks-pod-identity-webhook` — reads the annotation and injects the
  credentials into every pod using the account. The chart mounts no
  credential of its own and takes none as a value.

## v1.19.0

- **Breaking: the signing key is an EC P-384 key, and the issuer signs
  ES384.** The algorithm follows from the key rather than being declared
  beside it — an RSA key signs RS256, and P-256, P-384 and P-521 sign
  ES256, ES384 and ES512 — and it is what
  `id_token_signing_alg_values_supported` advertises, so **every relying
  party has to accept it before you upgrade**. Check each one; a verifier
  built on a library's defaults is the one to look at, because several
  default to RS256, ES256 and PS256 and would reject ES384 with a message
  that names the algorithm rather than the token. To stay as you were, set
  `signingKey.certificate: {algorithm: RSA, size: 2048, encoding: PKCS1}`
  before upgrading and nothing changes. Upgrading rotates the key either
  way: tokens signed with the previous one stop verifying once the old
  public key leaves the JWKS, so do it when a token lifetime of downtime
  for in-flight tokens is acceptable.
- **`signingKey.certificate.algorithm`, `.size` and `.encoding` are
  values.** `RSA` or `ECDSA`, sizes per algorithm (ECDSA 256, 384 or 521;
  RSA 2048, 3072 or 4096), `PKCS1` or `PKCS8`. A combination that
  cert-manager would decline is refused at render with the reason, rather
  than issuing a Certificate that never becomes a Secret and a listener
  that stays dark. An installation reading a key from
  `signingKey.existingSecret` is unaffected and may hand over either kind.
- **`route.certificate.privateKey` is passed through to the route's
  Certificate.** Empty by default, so nothing changes; set it when the
  issuer signs only one kind of key. A PKI role pinned to an algorithm
  refuses the request at issuance, long after the render succeeded, with
  the reason on the CertificateRequest where nobody is watching.
- **Verifiers accept what the issuer advertises.** The `identity` package
  and the GitHub verifier take their algorithms from the issuer's
  discovery document instead of the library's default, so an issuer
  signing with P-384 or P-521 is verifiable by a consumer that did not
  have to be told.

## v1.18.0

- **A default set of GitHub Apps, shipped as values to copy.** Every
  estate needs the same few automations, and every estate has been
  building them by hand. `charts/access-issuer/examples/github-apps.yaml`
  declares four — `renovate-public` and `renovate-private` (split so the
  App whose pull requests are world-readable cannot reach a private
  repository; the installation is what enforces it), `ci-automation`
  (approves bot pull requests so a required-approvals rule is satisfied
  without a person rubber-stamping a version bump, and cuts release
  tags), and `iac` (a Pulumi or Terraform program that manages the
  organisation) — each with the permissions it needs and why. It is
  values to read and copy, not a default the chart applies: creating an
  App stays an owner of the organisation confirming a manifest. The
  guide's new [*A default set*](docs/guides/sluis/connect/github-apps-catalogue.md#a-default-set)
  says why they are four identities and not one.
- **A catalogue App's credential can be projected to a secret store.**
  An entry may carry `push: {secretStore: {name, kind}, remoteKey,
  refreshInterval, deletionPolicy}`, and the chart renders an External
  Secrets `PushSecret <release>-github-app-<id>` that copies exactly that
  App's three property keys — `app_id`, `installation_id`, `private_key`
  — to the path the operator names. Off unless an entry carries it; the
  chart invents neither store nor path; the record and every other App's
  keys stay where they are. It is refused at render when two entries
  share one path in one store, or without `directory.store: kubernetes`.
  This is for a consumer that cannot ask the issuer at the moment it runs
  — an infrastructure-as-code apply that must work while this service is
  upgraded or restored. Everything that *can* ask should still exchange a
  token per run and hold nothing. **What lands in the store is a real
  credential**: the App's private key, a second durable copy, to be
  rotated as one, and the store that holds it is in the App's blast
  radius.
- **New guide:
  [connect/infrastructure-as-code.md](docs/guides/sluis/connect/infrastructure-as-code.md)**
  — the line between the two sides (this service owns identities and
  credentials; the program owns structure and names identities), a worked
  Pulumi program in Go that reads the credential from the store and
  builds a GitHub provider with it, the Terraform equivalent, the
  run-time exchange a CI job should prefer instead and when to choose
  which, and the rotation procedure for the copy.

## v1.17.0

- **Breaking:** anything that selects the service's objects by their old
  kind label — a backup, a script, a dashboard — must switch to the new
  one with this upgrade. **The service's own label keys are under the
  project's prefix.** Every ConfigMap and Secret the service writes is
  labelled `access-roster.truvity.github.io/kind`, and a workspace record
  is annotated `access-roster.truvity.github.io/workspace-id`, in place
  of the `directory-roster.truvity.com/` keys earlier releases wrote.
  `app.kubernetes.io/managed-by` and `app.kubernetes.io/part-of` are
  unchanged.
  - **Upgrading needs no step.** At start, before it reads anything, the
    service moves every object of its release (`managed-by` and
    `part-of` its own) from the old keys to the new ones, by a merge patch
    that two replicas can apply at once; a start with nothing to move
    writes nothing. While a rolling upgrade still runs replicas of the
    older release, which keep writing the old keys, the move repeats
    every minute. A start that cannot move them stops, rather than serve a
    directory missing the workspaces it could not see.
  - **Upgrade note — rolling back past this release needs a manual
    reverse relabel.** An older release reads only the old keys, so after
    the rollback it sees no connected workspace. Once no replica of this
    release is left running (it would move them straight back), run, with
    your namespace and release name:

    ```sh
    kubectl -n <namespace> get configmap,secret -o json \
      -l 'app.kubernetes.io/part-of=<release>,access-roster.truvity.github.io/kind' \
      | jq '.items[].metadata |= (.labels["directory-roster.truvity.com/kind"] = .labels["access-roster.truvity.github.io/kind"] | del(.labels["access-roster.truvity.github.io/kind"]) | if .annotations["access-roster.truvity.github.io/workspace-id"] then .annotations["directory-roster.truvity.com/workspace-id"] = .annotations["access-roster.truvity.github.io/workspace-id"] | del(.annotations["access-roster.truvity.github.io/workspace-id"]) else . end)' \
      | kubectl replace -f -
    ```

    then restart the service (`kubectl rollout restart`), which reopens
    stored workspaces only at start.

- **The repository runs a leak canary.** Every pull request is scanned
  for particulars (account ids, ARNs, internal hostnames, credential
  prefixes) in tracked files; the few mechanism shapes it allows (AWS's
  documented example account ids, ARNs composed from inputs, the pod
  secrets mount root) are listed with their reasons in
  `hack/leak-canary.sh`.

## v1.16.3

- **`access-proxy`: an `exposure.routes` entry with no `backend` at all
  gets the chart's own message.** It failed the render with `nil pointer
  evaluating interface {}.name`; it now fails with the same `route "…"
  needs backend.name, or attachRouteName …` as an entry whose `backend`
  has no `name`. Only the error changed: every values file that rendered
  still renders the same.

## v1.16.2

- **`accessctl credential` trusts a private root for OpenBAO when told
  to.** The connection to OpenBAO verified against the system's roots
  only, so an installation serving its API under a private root could
  not be reached from a machine whose system did not trust that root —
  short of pointing `SSL_CERT_FILE` at the bundle, which replaces the
  roots of every connection the command makes. `ssh`, `db` and `client`
  now take `--ca-cert <file>`, a PEM bundle, or read `BAO_CACERT` (then
  `VAULT_CACERT`), the flag first. The bundle is **added** to the
  system's roots and used for the OpenBAO connection alone: the exchange
  at the issuer keeps the system's trust.
  - **A bundle that trusts nothing is refused**: one that cannot be read,
    or holds no PEM certificate, exits 2 before anything is exchanged,
    rather than being ignored.
  - **An untrusted OpenBAO certificate says how to trust it**: the error
    names `--ca-cert` and `BAO_CACERT`.

## v1.16.1

- **`accessctl credential db` and `client` make the key on this machine
  and never send it.** v1.16.0 called `pki/issue/<role>`, which has the
  manager generate the private key and return it in the response — and a
  role that offers only `sign`, as a role that keeps keys off the wire
  does, refused it. Both kinds now generate an ECDSA P-384 key locally,
  send a CSR to `pki/sign/<role>` (the common name, and any URI SANs, in
  the CSR and in the request, so `use_csr_common_name` and `use_csr_sans`
  work either way), check the certificate that comes back is for that
  key, and write the key `0600` where the issued one used to go: the
  files and their names are unchanged. A role must accept `key_type: ec`
  with `key_bits: 384`, or `any`.
- **`accessctl credential` works in the environment's own namespace by
  default.** v1.16.0 defaulted `ssh` and `client` to `platform/<env>` and
  `db` to `<project>/<env>` — a layout the command assumed rather than one
  an installation had, so the shortest command logged in on a namespace
  that did not exist and every caller had to add `--namespace <env>`. The
  default is now `<env>` for all three kinds: `--env staging` works in
  `staging`. `--namespace`, `BAO_NAMESPACE` and `VAULT_NAMESPACE` still
  override it, in that order.
  - **`db --project` is optional.** Without it the database role is looked
    for in the environment's namespace; with it, in `<project>/<env>` as
    before, so a command line written for v1.16.0 means what it meant.
  - **`credential ssh --help` says what the two roles are for**: `user`,
    the default, for everyday logins as a host's ordinary account; `admin`
    for the account that administers it, granted separately and signed
    only when asked for by name.
  - **A missing OpenBAO address says how to give one** — the `--address`
    flag or `BAO_ADDR` (`VAULT_ADDR` is read too), each with the shape of
    a value — and the flag's help names both variables.

## v1.16.0

- **`policy.SplitGroup` reads any grant back into scope, thing and role.**
  The shape `<scope>:<thing>:<role>` was documented in trust.md and taken
  apart in one place, `SplitScopedGroup`, which only answered for this
  hub's own two roles. A relying party keying its authorization on the
  scope or the role — the audit log granting `<tenant>:audit:viewer` — had
  no reader to import and would have written a second one. Now there is
  one; `SplitScopedGroup` is a thin reading of it. The scope comes back as
  written, `all` included, because what `all` means is the reader's:
  this hub reads it as the absence of a scope, an audit log as every tenant.
- **`accessctl credential`: short-lived SSH, database and machine
  certificates, minted by OpenBAO and keyed by the roster subject.** One
  command family, three kinds — `accessctl credential ssh|db|client --env
  <env> [--role <role>]` — and one sentence behind all three: the sign-in
  (or the job's own token) is exchanged for `aud=openbao`, that token logs
  in on the JWT mount in the environment's namespace, and **one** call is
  made, `ssh/sign/<role>`, `pki/issue/db-client` or `pki/issue/client`.
  Three records then name the same subject: the issuer's audit trail for
  the exchange, OpenBAO's for the signing, and the server's own log for
  the certificate's `key_id` or common name — which the command prints,
  because a credential nobody can find afterwards is a credential nobody
  can investigate.
  - **The CLI decides nothing about the credential.** No request carries a
    TTL: the role's `ttl` and `max_ttl` are the whole answer, so
    shortening a role shortens every credential in flight and no flag here
    can ask for longer. What is sent is a public key, and the principals
    or common name that were asked for; a role that will not sign them
    refuses, which is where that decision belongs.
  - **The OpenBAO token is never written anywhere.** It lives in memory
    for one command and is revoked on the way out — and a mount handing
    out batch tokens refuses that revoke, which is not an error: such a
    token cannot be revoked, it was never on disk, and it expires on its
    own.
  - **Delivered where each kind is actually used.** SSH: a key pair
    generated for this one certificate, added to the **ssh-agent** with a
    lifetime the certificate decides, so the agent forgets it exactly when
    it stops working; or, with `--identity`, written into `~/.ssh` with
    the certificate beside the key where `ssh -i` finds both — and never
    over a key this tool did not write. Database: the files, plus a
    **psql service entry** whose `user` is the certificate's common name,
    for `psql "service=<name>"`, one block per service so a second
    database does not delete the first. Machine: the certificate, its key
    and the chain at the path the caller named.
  - **It works unchanged in a job**, like `kube-token`, `aws` and `token`
    before it: with the Actions variables set it exchanges the job's own
    identity token instead of a sign-in.
  - The OpenBAO roles this calls are the other half of the arrangement and
    are deployed separately; the command is proven here against a fake
    installation that signs and issues for real.

## v1.15.0

- **An App's recent tokens load.** The *Recent tokens* section of a GitHub
  App's page asked the audit trail for its own events — kind
  `github.token.minted`, target `github-app:<id>` — and narrowing the trail
  that way reads the objects of hour after hour, one by one, to find the
  handful that match. Measured against a real installation the call was
  still running fifteen seconds later when the gateway gave up on it, while
  the same listing unfiltered came back at once; the page had been shipped
  with an apology in place of the table. The service now keeps the last ten
  requests of each App beside the half that mints them, and the page reads
  those: when, who asked and how they proved it, the grant, the
  repositories and permissions, and whether it was minted, refused or
  failed, with the refusal's reason in the tooltip. A page load, not a
  scan.
  - **It is memory, not a record, and says so.** The ring is this replica's
    own, bounded per App, and a restart forgets it — which the page prints
    under the table and in place of the table when there is nothing yet
    ("No token has been asked for since this service started, 3h ago"),
    because "nothing has been asked for" on its own would be a claim about
    all time that it cannot make. The audit trail remains the record and
    holds every request for as long as the bucket does; **the token itself
    is still in neither**.
  - **A refusal is a row.** The refusals are usually why the page is open,
    so they are shown as refused with the reason the caller was given,
    rather than being the events that are hardest to find.
  - **A section that cannot be read says so in words.** Where the Apps
    cannot be read, or the deployment mints nothing here, the section
    prints the sentence rather than an HTTP code — and never an empty
    table, which reads as a quiet week.
- **The Audit page can be narrowed by its address.** `#/audit` now takes
  `source`, `kind`, `subject` and `target` as query parameters, and
  narrowing the page by hand changes the address. So *Recent tokens* links
  to the whole trail for that App — and any narrowing an operator is
  looking at is a link they can send.
- **A group's page says when each grant it holds was last used.** From the
  same memory, so the page still costs no call to GitHub and reads no
  store. A grant with nothing beside it is one nothing is remembered for,
  never one known to be unused.
- **A demonstration run has tokens to show.** `DEMO=1` seeds one App's
  recent requests — mints by a workflow, a person and a workload, a
  refusal outside the grant and a failure at GitHub — and leaves another
  App with none, which is the other thing the page has to say well.

## v1.14.0

- **One API for every GitHub App.** The console's Apps list and Apps pages
  were one list assembled in the browser out of four unrelated answers —
  a link App, an organisation's connection, a table of runner Apps and a
  table of catalogue Apps. The service now answers the question the page
  asks: `ListGitHubApps` returns every App this deployment keeps a key for
  or is declared to, in one shape, and `GetGitHubApp` returns one of them
  by the id its page is addressed by. Nothing about the pages changes;
  what changes is that the ids, the states and the words for them are the
  service's, so anything else that asks — a script, a second console — is
  told the same thing.
- **The service's own Apps are checked against their declaration, like the
  catalogue's.** The link App, each organisation's controller App and each
  tier's runner App are created from a manifest this service writes, and
  until now nothing ever compared that manifest with what GitHub holds. An
  owner could edit the permissions of an organisation's App on GitHub and
  the console would go on reporting it installed. Each of them now shows
  its permissions — before it is created, as what it will ask for — and
  after it is installed, what GitHub says it holds beside what was
  declared, with *Re-check* on the page to ask again.
  - **The runner App that cannot register a runner** is the case this was
    built for: an owner narrows `organization_self_hosted_runners` to
    read, every scale set stops registering, and nothing but the runners'
    own logs said why. It is now an App that *needs you*, with the single
    sentence that fixes it.
  - **A preset whose key cannot be read says so, and claims nothing.** The
    link App is authorized by a person rather than acted as, so this
    service holds no App key for it and cannot ask GitHub what it holds:
    its page says that, and no App ever reports "matches its declaration"
    on a check that did not happen.
- **Create, Install, Re-check and Disconnect are one call each.** They
  take the App's id and work for all four kinds. The calls they replace
  still answer, so a console and a service mid-rollout are never a broken
  page, and a browser part-way through GitHub's two clicks when the
  service restarts finishes exactly where it was going to: the generic
  call starts the same flow, under the same signed state, ending at the
  same callback.
- **A group's page says which GitHub tokens it may mint, from the
  service.** It used to fetch the whole GitHub report — which asks every
  connected organisation for its status — and work the reverse edge out in
  the browser, to render one section. The internal group now carries its
  `github_grants` from the catalogue: the Apps it may mint installation
  tokens of, the repositories each covers and the most a token may carry.
  The section no longer shows each App's state on GitHub, because reading
  the policy should not cost a call to GitHub; the App's own page is one
  click away and says it.
- **The Apps list says where each App's key is kept.** The Kubernetes
  Secret and the keys within it were a shape the console guessed from the
  release name; they are now the names the service actually writes, and a
  deployment that keeps no state in Kubernetes names no Secret instead of
  naming one that does not exist.

## v1.13.0

- **The People list shows the GitHub account each person linked.** The
  *GitHub: linked / not linked* facet told you a person had linked
  something without ever saying what; there is now a **GitHub** column
  beside the address, holding the login, linking to that account's page on
  GitHub. It is the same account the person's own page calls theirs — one
  rule, read in one place — so the two can no longer disagree. Somebody
  who has linked nothing gets an em dash, not a chip: a chip is a state,
  and a state on every second row of a directory-length table is a wall of
  grey that says nothing.
- **The GitHub facet is now the service's answer, not the browser's.**
  It used to be applied to the page in hand: with a snapshot of hundreds
  and a page of two hundred, "GitHub: linked" could report a handful while
  the rest of the company sat past the cut. `SearchPeople` now takes the
  filter and returns the login on each row, narrowing before the limit
  like the provider, domain and account filters always have — so the
  caption reads "the first 200 of 1,204 that match" and means it. The page
  also makes one call again instead of two: it no longer fetches the whole
  GitHub report, which asks every connected organisation for its status,
  to colour one column.
- **An unreadable link store says so instead of reporting a clean
  company.** Where links cannot be read — a deployment where nobody can
  link an account, or a failed read — the column is blank for everyone and
  the page says why underneath. Narrowing by *linked* or *not linked* then
  fails outright rather than answering "nobody".

## v1.12.0

- **One list and one page for every GitHub App.** The console's *Apps* tab
  was five unrelated blocks — a card for the link App, a table of
  organisations that linked the organisation rather than its App, a table
  of runner Apps, a box counting a catalogue behind a third level, and a
  directory-length table of linked accounts. It is now one list: every App
  this service keeps a key for or is declared to, grouped by organisation,
  those needing an operator first, with columns for what each App is for
  in plain words, where it stands, the repositories it reaches and the
  internal groups that may mint its tokens.
  - **Every App has a page**, at `#/github/apps/<id>`, not only the
    catalogue's. It opens with a sentence built from its facts — "Mints
    tokens for 2 internal groups on every repository in example-org;
    installed, matches its declaration" — then its facts, then its edges:
    who may mint its tokens, the organisation it acts on, the accounts
    linked through it, the last tokens asked for. Permissions, events, the
    Kubernetes Secret its key is in and its ids on GitHub are reference
    material behind a disclosure, and the permissions table is one column
    unless GitHub holds something other than the declaration.
  - **One vocabulary of state.** An App is *done*, *needs you*, *waiting on
    person* or *waiting on controller*, with the exact state in the
    tooltip — the same four words the membership rows use. An App that
    needs an operator says the single thing to do, and those Apps are now
    counted on the GitHub overview's *Next* line and on each
    organisation's card, which they never were.
  - **Create, Install, Re-check and Disconnect** sit on the App they
    change, and *Disconnect* asks first, stating what it does: what stops
    working, that the key is forgotten here, and that the App itself stays
    on GitHub with a link to its settings.
  - **Old addresses still work.** `#/github/apps/catalogue` opens the Apps
    list and `#/github/apps/catalogue/<id>` opens that App's page.
- **Organisation, team and person pages say each thing once.** An
  organisation lists the Apps installed or declared for it; what the
  controller leaves alone — owners, ignored addresses, outside
  collaborators and members nobody linked — moved into a *Left alone*
  disclosure, so "Nothing to change." is only said when there is nothing
  to change; people waiting to link or accept are counted rather than
  repeated once per team; a *Fed by* column that only repeats each team's
  own group is dropped; and the rule that owners are managed outside the
  policy is stated once above a table instead of on every owner's row.
- **An internal group says what it may mint.** A group granted tokens of a
  GitHub App now shows those Apps, their repositories and the most a token
  may carry, instead of reading "it only adds claims to a token".
- **People can be narrowed to who linked a GitHub account**, with a
  *GitHub: linked / not linked* facet, which the link App's page links to.
  The narrowing is applied to the page in hand for now.
- **The last tokens of an App degrade gracefully.** Where the audit query
  behind *Recent tokens* is slow or fails, the page says so in words and
  points at the Audit page, rather than showing a bare HTTP code after
  fifteen seconds.
- **A demonstration run shows the whole Apps page.** `DEMO=1` now declares
  runner tiers and a catalogue, with one App of each state: installed as
  declared, edited on GitHub since, and not created yet.

## v1.11.1

- **The audit log line is safe on every branch, not only the typed ones.**
  A field of a type the line does not expect is now rendered and escaped
  like any other caller-supplied value instead of being logged as is. No
  field takes that path today; the line no longer depends on that staying
  true.

## v1.11.0

- **A catalogue of GitHub Apps, created and installed from the console.**
  A deployment needs more GitHub Apps than the three this service creates
  for itself; each is now a declaration and two clicks.
  - **Declaring.** `githubApps.catalogue` lists Apps as data: `id`, `org`,
    optional `name`, `description`, `public`, `permissions`, `events`,
    `installation` (`all` or `selected`) and `grants`. It is rendered to
    `ConfigMap <release>-github-apps-catalogue` and read once at start
    from `GITHUB_APPS_CATALOGUE_FILE`. The service refuses to start on a
    malformed entry: an unknown key, a duplicate id, a level that is not
    `read`, `write` or `admin`, a name over GitHub's 34 characters, a
    grant above the App's permissions or naming a group the policy does
    not declare.
  - **Creating one.** On the GitHub page, *Apps*, then *Catalogue*: an
    operator presses *Create* on an App's page, an owner of its
    organisation confirms on GitHub, then installs. The App is created
    under the organisation the entry names and no other.
  - **Where it is kept.** `Secret <release>-github-catalogue-apps`, created
    empty at start: `<id>.github_app_id`, `<id>.github_app_installation_id`
    and `<id>.github_app_private_key` beside `<id>.record.json` once
    installed, `<id>.pending_private_key` until then. A deployment backs it
    up like the other Secrets, for example with a `PushSecret`.
  - **Drift.** Each App shows whether GitHub still holds what was
    declared: the App's permissions and events, and the permissions its
    installation accepted — a pending permission request reads as drift.
    GitHub has no API to change an App's permissions, so the page links
    to the App's settings; *Re-check* asks again. Answers are cached for a
    minute, and a failure to ask is the App's reason, never the page's
    error.
  - **Disconnect** uninstalls the App and forgets its keys. It does not
    delete the App on GitHub; its owner does, from the linked settings.
  - **Grants** — which groups may ask for an App's installation tokens,
    for which repositories, with at most which permissions — are declared,
    validated and shown on the App's page.
- **Installation tokens for catalogue Apps, minted under the grants.** A
  job, a workload or a person exchanges the proof it already holds at
  `/token` for a GitHub App installation token: RFC 8693 with
  `requested_token_type=urn:access-roster:params:oauth:token-type:github-installation-token`,
  `audience=github-app:<id>`, and optional `repositories` (names) and
  `scope` (`name:level` permissions). The response carries GitHub's token
  with `token_type: N_A`, its `expires_in`, and the repositories and
  permissions GitHub granted, under `Cache-Control: no-store`.
  - **One grant covers the whole request.** Of the App's grants for the
    proof's groups, in catalogue order, the first covering every named
    repository and permission is used; no repositories needs a `["*"]`
    grant; no permissions asks for exactly the grant's. GitHub is always
    sent that narrowing, so nothing the installation holds beyond the
    grant reaches a token.
  - **Errors** are RFC 6749's: `invalid_target` for an App that cannot
    mint or a proof no grant names, `invalid_scope` for a request wider
    than any one grant (or refused by GitHub), `invalid_grant` for a
    subject that is not a proof, `invalid_request` for a malformed request
    or an `actor_token`.
  - **Proofs are the same.** The verifier chain, the sign-in exchange's
    client rule and the group evaluation are the ones every exchange uses;
    ordinary exchanges are unchanged.
  - **Audited, never stored.** Every request is one `github.token.minted`
    event — proof kind, App, organisation, grant, repositories,
    permissions, installation, expiry — minted or refused. The token is
    never recorded and never kept.
  - **`accessctl github-token --app <id> [--repository name]...
    [--permission name=level]... [--json]`**, from the job's identity in
    CI and the sign-in on a laptop, and `Exchanger.GitHubInstallationToken`
    in the `tokens` package.
  - **The action** takes `github-app`, `repositories` and `permissions`,
    and sets the masked `github-token` output. `audiences` is now optional
    when `github-app` is given.
- **A GitHub matcher can pin the workflow file.** `workflow_ref`,
  `job_workflow_ref`, `sha`, `event_name` and `ref_type` are read from the
  job's identity token and matched as globs, so a group — and the grant
  that names it — can admit one reviewed workflow on one branch rather
  than every job in a repository. Matchers without them are unchanged;
  deploy the issuer before writing them in a policy, as an older one
  refuses the keys.
- The roster's own three Apps are built from the same catalogue shape by
  one manifest builder; the manifests GitHub is posted are unchanged.
- **The audit log line cannot be forged by what a caller sent.** Every
  string on the `audit` log line — a user agent, a subject, a request
  attribute — now drops record separators and control characters and is
  cut to 256 bytes, as the service's other log lines already were. The
  record kept in the trail is unchanged and keeps each value exactly.
- **accessctl rides out a dropped connection in a job.** Every tool call
  that runs `accessctl kube-token` (or `aws`, `token`, `github-token`)
  asks the job's token service and then the issuer again, so a long job
  makes many round trips, and one network blip among them used to fail
  the step. Both requests are now tried up to four times, waiting about
  a quarter of a second, then twice as long each time up to two seconds,
  jittered, when the failure may pass: no answer at all (a connection
  reset or refused, a timeout, a temporary DNS failure), `429` or a
  `5xx`. A refusal, any other `4xx`, a certificate that is not trusted, a
  name that does not exist, or an answer with no token is final at once,
  as before. The exchange is retried the same way on a laptop. A failure
  that outlasts the attempts exits as it did; the job's token, and an
  exchange that never got an answer, say so — `(after 4 attempts)`.

## v1.10.0

- **access-issuer's routes can attach to a ListenerSet.** `route.parentRefs`,
  when set, is used as written for both of the issuer's routes, and the
  chart then renders no Gateway or TLS Certificate of its own: the parent
  owns the listener for `route.host` and its certificate. Without it the
  chart renders exactly what it did.

## v1.9.0

- **access-proxy routes can attach to a ListenerSet.** `exposure.parentRefs`
  replaces `exposure.gateway` when set and is used as written for every
  route the chart renders, so a console's hostname can move to a
  ListenerSet, or sit on a Gateway and a ListenerSet together while it
  moves. Without it the chart renders exactly what it did.

## v1.8.1

- **A rollout no longer leaves the GitHub controller failed for an
  interval.** A policy change restarts the console's replicas and the
  controller at different moments, and for a few seconds the Service can
  still route the controller's questions to a replica on the previous
  policy. The controller rightly changed nothing on those answers — and
  then waited its whole interval (15 minutes by default) before asking
  again, so the GitHub page showed the pass failed and newly bound teams
  stayed empty until then. A pass that meets another policy, in a holders
  list or in a removal's confirmation, is now tried again after 5
  seconds, then twice as long each time up to a minute, six times at
  most; after that the interval resumes. Nothing is changed on an answer
  under another policy, as before.

## v1.8.0

- **Workspace credentials written by the release-rename script migrate
  too.** 1.7.0 found an old per-workspace credential Secret by its
  workspace annotation. The objects the release-rename script wrote carry
  none, so 1.7.0 refused them and kept reading them where they were.
  Start-up now starts from the workspace records and finds each old
  object by name, the way a read already did. An old object with no
  record is left alone.
- **Runner Apps are created from the console.** A runner App is the
  GitHub App a self-hosted runner scale set registers with, one per
  organisation per tier.
  - **Declaring tiers.** Set `githubRunnerApps.tiers`, for example
    `[preview, stable]`.
  - **Creating one.** An operator creates each App on the GitHub page
    (Apps), with the same two clicks as an organisation's App: create,
    then install.
  - **Scope.** The App asks for `organization_self_hosted_runners: write`
    and nothing else. It is private and has no webhook.
  - **Where it is kept.** Every App is in
    `Secret <release>-github-runner-apps`, under the keys gha-runner-scale-set's
    `githubConfigSecret` reads: `<tier>.<org>.github_app_id`,
    `.github_app_installation_id` and `.github_app_private_key`. A
    deployment copies them to its runners, for example with a
    `PushSecret`.
  - **Keys appear only once installed.** Until the App is installed, its
    key is kept under another name, so a copy never replaces working
    runners with an App they cannot register with.
  - **Disconnect.** It uninstalls the App and forgets its keys.

## v1.7.0

- **Three Secrets restore everything a console added.** Workspace
  credentials are one Secret, `<release>-workspace-credentials`, with a
  key per workspace. Before, each workspace had its own Secret, named with
  a hash of its tenant id, which nothing outside the service could
  select. Each credential now carries a copy of its record, as does every
  GitHub connection's and the link App's in `<release>-github-apps`.
  - **Start-up restores what is missing.** It rebuilds a workspace
    ConfigMap or a GitHub record that is gone, from the copy in its
    credential. So copying `<release>-workspace-credentials`,
    `<release>-github-apps` and `<release>-github-links` is a whole
    backup, for example with one External Secrets `PushSecret` each
    ([configuration](docs/guides/sluis/operate/back-up-and-restore.md)).
  - **Existing credentials migrate at start.** The first start copies each
    per-workspace Secret in, and gives older GitHub credentials their
    records.
  - **Rollback stays safe.** The per-workspace Secrets are left for a
    rollback. Reconnecting or disconnecting a workspace removes its old
    one.
  - **Probes don't touch the copy.** It leaves out the last probe, so a
    probe does not rewrite the Secret.

## v1.6.6

- **A failed GitHub pass keeps what was last known.** It reported the
  failure over an empty organisation, so the GitHub page blanked for as
  long as passes failed, and a controller started right after a failure
  found no held or reported rows to remember and recorded them all again —
  which is what an upgrade does, when a pass meets a console still on the
  old release. The failure is now reported over the last report with rows.
- **accessctl installs through devbox.** A release now also carries
  `accessctl_<version>_nix-flake.tar.gz`, a Nix flake over that release's
  own archives. A repository adds its URL with `#accessctl` to
  `devbox.json`
  ([docs/design/sluisctl.md](docs/concepts/sluis/sluisctl.md#installing-it)).

## v1.6.5

- **Audit events keep their request on a deployment, not only in tests.**
  The request's address, user agent and id were put into the context by a
  wrapper around a handler the service's listener never served, so every
  event recorded in production had none of them. The issuer's listener
  now serves the wrapped handler itself (`issuerapp.Deps.Around`), and the
  service's `Handler` is that same handler.

## v1.6.4

- **The client address is read from the right of `X-Forwarded-For`.**
  `audit.trustForwardedFor` took the first entry, which a caller can
  write, since an edge and a gateway append rather than replace. It is
  replaced by `audit.forwardedForTrustedHops`: the number of the
  deployment's own proxies that append, the client being the entry just
  left of them. `0`, the default, still records the connection's peer.

## v1.6.3

- **A restarted GitHub controller does not record every held and reported
  row again.** Which rows it had recorded lived in the process, so each
  restart wrote a fresh `github.owner.reported` for every owner in every
  team into a trail that is now durable. The first pass after a start
  takes them from the report the previous process wrote, so a restart is
  not news.
- **The Audit page says where the trail is kept:** in S3, not a capped
  stream whose durable copy was the log.
- **Audit records speak the Elastic Common Schema.** Each event kept in
  S3 is one ECS document (`event.action`, `event.category`, `event.type`,
  `event.outcome`, `user.name`, `user.target.name`, `observer.name`,
  `service.target.name`, …), and each log line carries the same fields
  under the same dotted names, with an `event.id` shared by the line and
  the record. What ECS cannot say stays under `access_roster.*`: the
  native outcome, the target and the attributes. The log line keeps
  `audit=true`; `kind`, `source`, `actor` and the `attr.<name>` keys are
  gone, so a log query naming them needs the new names. **Upgrade note:**
  objects written by 1.6.2 are read as before, beside the new records.
- **An audit event says where it came from.** `client_address`,
  `user_agent` and `request_id` (the gateway's `X-Request-Id`) are kept
  for every event a request caused, from sign-ins and console calls to
  token exchanges, shown on the Audit page, and accepted from a reporter
  within bounds. The address is the connection's peer unless
  `audit.trustForwardedFor` is set, which only a deployment behind a
  gateway that replaces `X-Forwarded-For` should do.
- **Audit writing is a ConnectRPC contract.** `AuditSinkService`
  (`WriteAuditEvents`, `ListStoredAuditEvents`) is what the service
  records through and what a writer implements: the S3 writer and the
  in-memory one, joined in process with no network. A writer in another
  process can implement it later without anything that records changing;
  none is configured in this release.
- **A recovery sign-in is refused when its audit record cannot be
  written.** It is the one event that fails closed: at the issuer and at
  the console's door alike, the record is put in S3 before the sign-in
  succeeds, and a failed put refuses it with a message naming the audit
  trail, and records the refusal. Every other event still never waits on
  S3. The runbook's *When the audit trail cannot be written* says what to
  check.
- **The audit writer publishes metrics:** `access_roster.audit.writes`
  by outcome and durability, `access_roster.audit.dropped`, and
  `access_roster.audit.queue`, over OTLP when `telemetry.otlpEndpoint` is
  set. The runbook carries the alert rules for when a collector exists.

## v1.6.2

- **The audit trail is kept in S3, never in Valkey.** `audit.s3.bucket`
  names the bucket; the service appends events as JSON-lines objects by
  the hour (`<prefix>YYYY/MM/DD/HH/…jsonl`), at most
  `audit.s3.flushInterval` (10s) after each event, and the console's
  Audit page and `ListAuditEvents` read them back, newest first. Recording
  still never waits on the store: events queue in the replica, are listed
  from there until written, and are written when S3 answers again. The
  Valkey stream is gone, and with it `audit.maxAge`; a deployment that
  sets no bucket keeps the trail in one replica's memory and says so at
  start. **Upgrade note:** the stream held in Valkey is not carried over;
  the pod's AWS identity needs `s3:PutObject`, `s3:GetObject` under the
  prefix, `s3:ListBucket` on the bucket, and the bucket key's
  `kms:GenerateDataKey`/`kms:Decrypt`. Put Object Lock on the bucket.

## v1.6.1

- **A CI matcher can require a repository's visibility.** `github:
  { owner: example-org, visibility: private }` admits every private repository
  of an organisation and nothing else: not its public ones, and not a
  fork, which is another repository. The issuer reads GitHub's
  `repository_visibility` claim into the proof, `Explain` takes it in
  `github.visibility`, and a value other than `public`, `private` or
  `internal` is refused when the policy loads. Deploy the issuer before
  writing the key in a policy: an older one refuses it.
- **Security: a policy rollout no longer removes people from GitHub teams.**
  The GitHub controller and the console load the policy when they start,
  and a rollout restarts them at different moments. For that window the
  controller could decide with the new policy and ask a console still on
  the old one, which knows nothing of a team the new policy binds: nobody
  holds its group there, and `Explain` lists no such group, so the
  controller took every member of the newly bound team as confirmed to
  leave it: binding a new team removed its members until the next pass,
  under one policy, added them back. `Explain` and `ListHolders`
  now carry `policy_digest`, the digest of the policy each answer was
  computed under, and the controller changes nothing on a holders list
  under another policy (the pass fails and is retried) and confirms no
  removal on an `Explain` under another one (the row waits). A console too
  old to send a digest counts as another policy, so deploy the controller
  and the console together, as the chart does. Organisation removals were
  never exposed: they rest on the directory's found and suspended, which
  no policy changes.

## v1.6.0

- **The sign-in page names the application.** It said "the application
  that sent you here", which is true of every sign-in page, a phishing
  page's included. Now it says *Sign in to continue to **Argo CD***, with
  a one-line description under it and the host the sign-in returns to,
  as text. A client declares the two new optional keys `display_name` and
  `description`; one with no name is shown by its id, and a `k8s:<cluster>`
  client as *Kubernetes — `<cluster>`*. When the redirect is on the
  person's own computer (kubelogin, accessctl) the page says a program on
  this computer is asking, and shows no port. The refusal for a client a
  person holds no group of names it too. Both keys are shown to anyone
  who starts a sign-in, so keep them free of anything a stranger should
  not read. Deploy the issuer before adding them to a policy: an older
  issuer refuses the unknown keys.
- **`accessctl token --audience <client>`** prints a token for one audience
  and nothing else, for a caller that is neither kubectl nor an AWS SDK —
  OpenBAO's JWT login reads it from stdin. Like `kube-token` and `aws` it
  answers from the sign-in on a laptop and from the job's own token in CI.

## v1.5.6

- **An owner the controller reports reaches the audit log.** The
  `github.owner.reported` event carried the outcome `reported`, which the
  audit stream does not have, so it refused the whole batch and the
  owners' events never landed. It is recorded with the outcome `ok` now;
  the kind says what happened. This only shows in an organisation the
  controller acts in.

## v1.5.5

- **Security: token exchange no longer accepts an ID token as a proof.**
  Before 1.5.5 the exchange accepted any token this issuer had signed whose
  claims named a person. An ID token names one, and is handed to every
  relying party a person signs in to, so a holder of it could exchange it
  -- presenting any public client -- for a token for any audience that
  person's groups admit, a cloud role or a cluster included. Signature,
  issuer and expiry were always checked; what was missing was any rule
  about which of this issuer's own tokens may stand for a person. Now a
  proof comes only from a verifier (a GitHub job, a cluster workload) or
  from a CLI sign-in as described below, and every other token this
  issuer signs is refused. Upgrade every access-issuer to 1.5.5; there is
  no configuration-only mitigation.
- **`accessctl` works on a laptop.** `accessctl login` followed by
  `accessctl kube-token` or `accessctl aws` exchanges that sign-in for the
  requested audience, so one kubeconfig and one aws.ini serve a person and
  a CI job alike. Of the tokens this issuer signs, the exchange takes only
  this one as a proof: the access token of a live session at a client
  declaring the new `sign_in_exchange: true` (a `public` client: the CLI),
  presented by that client. Deploy the issuer before adding the key to a
  policy: an older issuer refuses the unknown key.
- **Revoking a session reaches a renewed access token.** A token minted
  by a refresh now names its session, as the first one does, so
  `userinfo` stops answering for it once the session is revoked.

## v1.5.4

- **An organisation can ignore addresses and GitHub logins.** The policy's
  `github.<org>.ignore` lists what the controller leaves alone whatever the
  bindings say: an address in a bound directory group that nobody here can
  take out of it, a temporary owner. An ignored address is never invited
  and never reported as waiting; an ignored login is never added, removed
  or changed. The organisation's page lists them.

## v1.5.3

- **An owner is added to teams, and never removed from one or demoted.**
  Owners — an organisation's break-glass seat among them — are managed
  outside. The controller still adds an owner to the teams the policy wants
  them in and promotes them where it wants a maintainer; it no longer takes
  an owner out of a team or turns a maintainer into a member. Both are
  reported instead. On the first real dry run every role change it proposed
  was an owner being demoted.

## v1.5.2

- **Disconnecting the link App leaves profile matches and imports alone.**
  It made every linked account unverifiable, including the ones matched
  from a public profile or imported, which hold no token of the App's. So
  moving the link App to another organisation would have unlinked every
  imported account; now it unlinks only the people who authorized it.

## v1.5.1

- **The GitHub page is tabs.** *Overview* says what needs attention next,
  with a card per organisation and the people who have not linked, and a
  button to copy their addresses. *Organisations* opens each
  organisation — what enabling it would do in one sentence, removals
  first, its teams each with a page — and *Apps* holds the link App and
  every organisation's App. Rows read **OK**, **waiting for them** or
  **needs you**, with the controller's exact state in the tooltip.
- **A person's page shows them on GitHub**: the linked account, their
  teams and what comes next, and on your own page a button to link your
  account. A group's page lists the GitHub teams it feeds.

- **The TypeScript package is published to GitHub Packages** at each
  release tag's version, built and tested by the release workflow.
  Install `@truvity/access-roster` with the `@truvity` scope pointed at
  `https://npm.pkg.github.com` and a token that can read packages
  ([docs/sdk/typescript/sluis.md](docs/sdk/typescript/sluis.md)). A git
  install stopped working when `ts/dist` left git: yarn 4 packs a git
  dependency without running `prepare`, so it shipped no `ts/dist`.

## v1.5.0

The GitHub controller runs joiners, movers and leavers with no human in the
loop, and stops itself where a person is needed. Every organisation stays
a dry run until it is listed in `githubRoster.actsIn`, as before.

- **Three ways a GitHub account becomes somebody's.** Linked by the person,
  as before; **matched from a public profile** that shows a work address
  the directory has, live — GitHub lets an account publish only a verified
  address; and **imported** from approved pairings elsewhere through the
  new operator RPC `ImportGitHubLinks`, after three checks. The latter two
  are never re-checked on GitHub and never displace a link the person made.
- **Seats.** Nobody is invited past the last free seat, and nobody at all
  while the seats cannot be read; the GitHub page says how many seats to
  buy. **An organisation's App now asks for organisation administration
  (read).** Apps already created need an owner to add it on GitHub.
- **Mass removals wait for a person.** A pass whose removals concern more
  than half an organisation removes nobody until an operator presses
  Confirm, for exactly that set (`ConfirmGitHubRemovals`).
- **Two expired invitations stop the third**, until the person links again.
- **Owners are reported, never held**: owners and billing are managed
  outside. Transient trouble — the directory unable to vouch right now, a
  change GitHub refused — is **retried** every pass instead of held.
  Outside collaborators are listed.
- **OpenTelemetry metrics**, pushed over OTLP when
  `telemetry.otlpEndpoint` (or `OTEL_EXPORTER_OTLP_ENDPOINT`) is set:
  passes, changes, rows by state, seats, breaker trips, links by state and
  source. Nothing is exported, and no listener opened, without it.

## v1.4.0

- **`accessctl` works inside a GitHub Actions job.** With
  `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` set,
  `accessctl kube-token` and `accessctl aws` exchange the job's own
  identity token, minted for the issuer, and present the audience as the
  client, the way the root action does. Elsewhere nothing changes. One
  committed kubeconfig and one `aws.ini` now serve a laptop and a job
  alike, where a repository used to keep a second copy of each for CI.

## v1.3.2

- **The GitHub page reads in the order the work happens.** *Set up* first,
  as three ticked steps: every GitHub App in one table — the link App for
  all organisations and each organisation's team App, with Create and
  Disconnect beside each — then the link page to send people, with a copy
  button, then letting the controller act. *People* next, once per person
  across every organisation and team, filtered to what needs a change or
  is waiting on them. Each organisation's section keeps its teams and the
  changes it would make; nobody waiting to link is repeated there once per
  team.
- The demonstration shows linking: a link App, linked accounts, a lost
  link and people not linked.

## v1.3.1

- **An organisation waiting on people to link says so.** With nobody
  linked there is nothing to change and nothing held, and the controller
  reported `in-sync` — which is exactly what an operator reads as "safe
  to enable". It now reports `waiting`, with a count of the rows waiting
  on somebody to link (`tick.waiting`), and the GitHub page shows it.

## v1.3.0

People link their own GitHub account. GitHub discloses members' work
addresses only to organisations on its Enterprise Cloud plan, so on every
other plan the controller could match nobody: every member read as
unlinked and every invitation was held. Nothing was changed on GitHub by
that, and nothing is now until a person links.

- **Self-service linking.** An operator creates the **link App** once,
  from the GitHub page: a public App that asks only to read a person's own
  email addresses and is installed nowhere. A person opens
  `/connect/github/link`, authorizes it, and their account is linked to
  each verified work address the directory has, live. No console role is
  needed, and nobody types a username. Linking a second account with the
  same address moves the address to it.
- **A link is checked every pass.** The controller keeps the person's
  token pair and reads the account's verified addresses again each pass.
  An account whose linked addresses are all gone or unverified, or whose
  authorization was revoked, **leaves the organisation at once** — the one
  removal that does not ask the directory. An outage changes nothing. A
  token pair lost in an interrupted renewal makes the link
  *unverifiable*, never lost: renewals are written as in progress first.
- **Invitations go to the linked account**, by its id, straight into its
  teams. Somebody wanted who has not linked is `not-linked` — waiting on
  them, not held. Invitations by address are no longer sent.
- **Chart:** the controller's Role may update one Secret by name,
  `<release>-github-links`, which the service creates. The link App's
  credential sits beside the organisations' in `<release>-github-apps`.
- **Console:** the GitHub page gains *Linking accounts* — the link App,
  the page to send people to, and every link with its state.

Also in this release:

- **An access token names the person.** `name`, `given_name` and
  `family_name` now travel in the access token as they already did in the
  ID token, from the same one directory call. The access token is what a
  gateway or a proxy forwards to an application, so one showing who is
  signed in no longer has to call userinfo on every page. A workload's
  token carries no names rather than empty ones.

- **The Go `identity` package reads them**: `Verified` gains `Name`,
  `GivenName` and `FamilyName`, and `WhoAmI` answers `name`, `givenName`
  and `familyName` — the keys the TypeScript `Identity` already declared,
  and which nothing had been filling.

- **A server half for Node: `@truvity/access-roster/server`.** The Go
  package's issuer anchor in TypeScript — `Issuer`, `middleware`,
  `requireGroups`, `whoami` — with the same checks, the same caller and the
  same `whoami` body, connect-style for Express and Nest. It exists for the
  business applications leaving gateway-auth, whose backends are Node and
  which had nothing to verify a token with but a header or a generic JWT
  library. `jose` becomes the package's one runtime dependency; a browser
  bundle importing only the root or `/react` never loads it.

  access-roster itself does not run this half, being a Go service, which
  is the one place the rule that it consumes what it publishes cannot hold.
  Its tests verify tokens over a real listener against a real key set, and
  the Go test beside them proves the issuer's own tokens carry what both
  halves read.

## v1.2.0

GitHub organisations, managed from the policy, and an audit stream for the
whole service. **Nothing changes for a deployment that sets nothing new:**
the GitHub controller is off unless `githubRoster.enabled`, and changes no
organisation until it is listed in `githubRoster.actsIn`.

The one incompatible change is to the policy's `github` table, which
nothing rendered and nothing but the console ever read: it now names
internal groups. A policy carrying the old shape is refused at start
rather than reinterpreted.


- **A GitHub team binding now names internal groups, not provider
  addresses**, and declares both of GitHub's team roles:

  ```yaml
  github:
    globex:
      members: [all:globex:employee]      # in the org, with or without a team
      teams:
        team-platform:
          members: [all:platform:engineer]
          maintainers: [all:platform:lead]
  ```

  A team is a consumer of a group exactly as a client's `requires` is,
  so everything the policy already does applies to a team for free:
  holders from several workspaces, a matcher for the day before a
  provider group exists, the naming convention, the console's holders
  view. Which accounts hold a group stays a question the directory
  answers once, in `groups`, rather than one this table asks again.

  An organisation's own `members` is new and is for the people who
  belong in it without a team — without it they are people no binding
  accounts for, which is exactly who a controller would remove.

  Refused, each because it is otherwise silent: a group nothing
  declares, a team fed by neither role, an organisation binding nothing
  at all, and either half declared twice across two merged files.

  **This is a breaking change to the table**, which was read by nothing
  but the console: no controller exists yet, and none of it has ever
  reached a token. A deployment carrying the old shape fails the render
  rather than being reinterpreted.

- The Rules page reads the new shape: a binding's rule is the internal
  group and links to its page, *depends on* is whatever that group
  depends on, and an organisation's own members are their own kind.
  `GetPolicy` carries `maintainers` on each team and a new `orgs` list.

- **A workload in a federated cluster can call the console's API with
  its own ServiceAccount token.** It presents the projected token as the
  bearer, with the audience token exchange uses, and it is verified
  against the same cluster key sets — no exchange in front of a
  same-cluster call, and no TokenReview, so the service still holds no
  access to its own cluster. The identity has the new source `workload`
  and is whatever the policy's `service_account` matchers make it:
  never recovery's operator, the only other identity that arrives as a
  ServiceAccount. It is how the GitHub controller will read
  `ListHolders`.

- **`ListHolders` no longer answers as though complete when it was not.**
  `truncated` reported only the response limit, so past the examined cap
  of 10,000 accounts an answer silently left holders out and looked
  whole. It now reports either bound. Its documentation also says what
  was always true and is the thing a consumer removing access needs to
  know: absence from `holders` is never evidence on its own, because a
  workspace whose snapshot cannot be read contributes no accounts — a
  removal is confirmed per account with `Explain`.

- **A GitHub page in the console**, on the internal side beside
  clients. Per organisation it shows the policy's bindings beside what
  the GitHub controller last reported — each team's groups in both roles,
  every person's state and what happens next, held actions with their
  reason, and members no binding explains. Read-only. The report is a
  ConfigMap, `<release>-github-status`, which the service now creates at
  start so that the controller's Role can name the one object it
  updates; `GitHubService.GetGitHubStatus` serves the join. The
  demonstration run carries bindings and a sample report, so the page
  can be walked through without a controller.

- **Connect a GitHub organisation**, from the console's GitHub page. An
  operator presses Connect; the organisation's owner creates the App
  GitHub offers — private, `members: write` and nothing else, no webhook
  — and installs it. Nothing is typed or pasted, and the key exists only
  in this service's namespace. Coming back from Install the service asks
  GitHub where the App is installed rather than trusting the redirect.
  Only a bound organisation can be connected; an App created and never
  installed is finished rather than created again; an installed one is
  refused rather than duplicated. **Disconnect** uninstalls and forgets.
  Records live in `<release>-github-orgs`, keys in `<release>-github-apps`,
  both created empty at start. The service now calls `api.github.com`,
  which a default-deny egress policy has to allow.

- **An audit stream for the whole service**, and an operator-only
  **Audit** page. The issuer records sign-ins and their refusals, recovery
  sign-ins as their own kind, refused refreshes, token exchanges, revokes
  and sign-outs; the console records its own sign-ins, provider connects,
  disconnects and domain and group changes, and GitHub Apps created,
  organisations connected and disconnected. One Valkey stream shared by
  every replica and both halves, capped by `audit.maxEvents` and
  `audit.maxAge`; in memory without Valkey. **Every event is also a log
  line** with `"audit":true`, which is the durable copy.

  A component in another process reports through
  `AuditService.RecordAuditEvents` with its own ServiceAccount token, and
  only a workload in the new group `all:access-roster:reporter` may. The
  service stamps who reported and when, and refuses a report naming one of
  its own sources — so a reporter cannot forge a sign-in. A component never
  writes to Valkey itself: that store holds every session and refresh
  token. Recording never fails what it records.

- **The GitHub controller**: `github-roster`, a second binary
  and image from this repository and a second process from this chart,
  behind `githubRoster.enabled`. It makes each organisation's teams match
  the policy's `github` table and reports on the GitHub page.

  Every pass, for every bound organisation: it asks the console who holds
  each bound group, with its own ServiceAccount token; reads GitHub
  through the organisation's App — members with their verified-domain
  addresses, invitations, teams and roles, all of it or the pass fails;
  links a login to a person by verified address alone; invites joiners
  straight into their teams, adds and re-roles members, removes a member
  no bound group wants from a team, and removes from the organisation only
  somebody the directory no longer has. **Each removal is confirmed** by
  asking about that one address, and done only on an answer the directory
  vouches for. Owners, members with no verified address and unbound teams
  are never touched.

  **Born disabled:** organisations not in `githubRoster.actsIn` are derived
  and reported, and nothing is changed. Changes and newly held actions are
  recorded in the audit stream. The chart gives its account one
  permission — updating its report — and mounts the App keys as a volume;
  it refuses to render without the cluster row the service verifies the
  controller's token against.

## v1.1.0

- **SECURITY: a client's `requires` is now enforced when somebody signs
  in through a browser, and again when a session is refreshed.** It was
  enforced on token exchange and nowhere else, so for a browser client
  the list was documentation: anybody the issuer would authenticate was
  issued a token for any declared client, and what stopped them was
  whatever the application checked for itself.

  Most relying parties were saved by that second check — ArgoCD admits
  nobody by default, Kargo authorizes itself, the consoles check their
  own roles. One was not. A console with no authorization of its own,
  behind a proxy with posture `authenticated`, had `requires` as its
  only gate, which means it had none.

  Not a way in for a stranger: the identity still had to be one this
  issuer authenticates. What it collapsed was *which* console a
  signed-in person could open.

  The refusal is a **page**, not a redirect carrying an error. The
  relying party is not the one that needs telling, and sending the
  browser back to it produces a console rendering its own version of a
  refusal it does not understand. The page says the sign-in was fine and
  that signing in again will not help, and it does not name the group
  that would have admitted them — that is telling somebody what to ask
  for by name. The detail goes to the log.

  **Checked again at refresh**, because checking only at sign-in would
  make the gate good for as long as a refresh token lives: somebody
  taken out of a group would go on renewing for up to twelve hours
  against a client no longer theirs. Now it ends at the next refresh,
  which for a proxied console is its `ttl_cap`. The answer is
  `invalid_grant`, which is what a relying party acts on — it stops
  renewing and starts a new authorization, which meets the same gate.

  Found by migrating a console and watching an identity that held none
  of its groups be admitted by the issuer and refused by the console.

## v1.0.0

The first release the design document, the architecture as shipped and
the OpenID Foundation's suite all describe the same thing. No code
changed since 0.17.1; what changed is what can be said about it.

- **Four conformance plans, zero failed, from a suite the issuer can
  reach.** Config OP, Basic OP, RP-Initiated Logout OP and Back-Channel
  Logout OP, run against the deployed issuer from the suite running in
  the cluster. The Foundation's rule is that only FAILED and INTERRUPTED
  disqualify; every REVIEW screenshot was looked at and shows the page
  its step demanded. The logout pair — RP-Initiated plus one of the
  other three — is what the Foundation requires for a logout
  submission, and both halves are green for the first time.
  [docs/conformance.md](docs/concepts/sluis/conformance-findings.md) carries the run and what
  each column means.

- **Documentation at 1.0**: one design document for the one
  service, the architecture drawn as shipped, a connect guide per row of
  the fan-out table, references that match the schema, and nothing in
  the tree describing what is not built except under a heading that
  says so.

## v0.17.1

- **Back-Channel Logout reaches every client that signed somebody in,
  and names the session that client actually saw.** Two defects, both
  found by the Foundation's Back-Channel plan the moment it could
  receive a token, which it could not from a laptop.

  A client that asked for `openid` alone holds no refresh token, and a
  session here IS a refresh token — so the issuer recorded nothing for
  it and, at sign-out, announced nothing. The sign-in now remembers
  which clients were issued an ID token under it, and each is told when
  it ends, whether or not it holds a refresh token.

  And the logout token carried the browser sign-in's id as `sid`, while
  the ID token had carried the per-client session's. A relying
  party matches the two by that value; a token that verified and matched
  nothing was a sign-out that silently did not happen. The logout token
  now names the `sid` the ID token did, and a client whose ID token had
  none is told by `sub` alone, which the specification allows.

- **The conformance suite runs in the cluster**, rendered exactly while
  its client rows are declared, at a hostname of its own. Only the
  relying-party paths are public; the control plane is reached over the
  tailnet. It is the only way the Back-Channel module can be witnessed
  at all: the issuer has to POST to the suite, and a laptop suite is the
  pod's own loopback.

## v0.17.0

- **The Sessions page filters MATCH rather than equal.** Typing `lovelace`
  in the person box finds `ada.lovelace@globex.example`, and `karg` finds
  `kargo` — prefix, suffix and middle, one rule. A box you have to fill
  in exactly is a box you can only use once you already know the answer,
  which is not the state anybody is in when they open that page.

  Valkey cannot do this for us, and it does not need to. Its glob is
  over KEY NAMES and the identity lives inside the record, not in the
  key; there is no substring index in the core and the search module is
  not deployed. What is there is a set per exact identity and a set of
  every live session — and the unfiltered listing already reads the
  second one. So a substring is the read the page was doing anyway, with
  the comparison changed. What it gives up is the narrow index, which is
  why the exact path stays exact: an identity's own page, and any
  non-operator, still read one small set.

  **Operator-only, and refused rather than narrowed for anyone else.**
  Every other rule here decides what a caller may see from the identity
  they NAMED, and an exact identity is the caller's own or nobody's. A
  substring names an unknown set: `globex.example` is everybody, and the
  checks underneath would pass it precisely because it is not anybody's
  identity to refuse.

  **`RevokeSessions` takes no such field.** It shares the query type, so
  this is enforced rather than merely absent: a revoke scoped to
  *anything containing this* takes `kargo` and `karma` together, and
  there is no undo.

## v0.16.0

- **Back-Channel Logout (OIDC Back-Channel Logout 1.0), opt-in per
  client.** A relying party that declares `backchannel_logout_uri` is
  posted a signed logout token, server to server, the moment a sign-out
  ends a session it holds. One that declares none is never contacted, so
  serving this changes nothing for a client that has not asked.

  It closes the window this design otherwise only bounds. Revoking is
  immediate at the issuer and invisible at the relying party, which keeps
  serving on a valid access token until it next refreshes.

  Of the three optional logout mechanisms it is the only one worth
  serving. Session Management and Front-Channel both load something from
  this origin inside the application's page — a polled iframe, or one
  hidden iframe per client — which browsers block by default, so both
  fail quietly in exactly the case they exist for. And neither can reach
  a PROXY, which is what holds the session for a console running no
  OpenID flow of its own.

  Two details the specification is strict about, both pinned by tests:
  `typ` is `logout+jwt`, and there is no `nonce`. Both exist so a logout
  token cannot be mistaken for an ID token by a relying party that checks
  too little — which would turn *you are signed out* into *you are signed
  in as somebody*.

- **The access-proxy chart refreshes every minute rather than every
  five.** That number IS how long a sign-out or a revoke takes to become
  true at a proxied console: the proxy keeps serving on the token it
  holds until it next asks for a new one. The cost is five times the
  refresh traffic, which for a handful of consoles is nothing.

  oauth2-proxy cannot receive a logout token — it encrypts each session
  with a secret that lives only in the user's cookie, so nothing
  server-side can find the session one names. Until that changes
  upstream, the refresh interval is the whole of the dial.

## v0.15.3

- **The Sessions page shows one row per identity**, with how it proved
  itself, how many browsers, and one *Sign out all*. It showed one row
  per browser, which is the truth and not the answer that page is for: a
  recovery account with 104 sign-ins rendered 104 rows, 103 of them with
  an empty name column, and pushed the sessions the table introduces a
  screen and a half down. Nobody reads 104 rows; they read *104* and act
  on it. The detail belongs on that identity's own page, where there is
  one identity and the rows carry information.

- **The column is *Identity*, not *Person*.** The row that made the case
  reads `prod:k8s:access-issuer:access-issuer-recovery`, which is a
  ServiceAccount. People still means people — the directory-backed page
  is unchanged — but a session listing holds workloads and CI jobs too.

- **The conformance driver signs out between modules.** Clearing cookies
  drops the browser's copy and leaves the sign-in record alive at the
  issuer, so a thirty-five module plan abandoned thirty-five of them.
  That is where the 104 came from.

## v0.15.2

- **A declared `exchange` client could never authenticate**, so every
  token-exchange audience was unusable. The library authenticates the
  caller of an exchange by HTTP Basic; public clients were handled —
  presenting nothing is right, because in an exchange the subject token
  IS the credential — and `exchange` fell through to a secret lookup.
  The policy refuses to let that kind carry a secret at all, so the
  request failed with *the client secret does not match* while the policy
  read correctly.

  This is the deeper reason token exchange had never verified a proof.
  Not only was no cluster federated: even with one, the audience could
  not authenticate. It would have affected every exchange target the
  design describes, including the AWS roles.

  Found by performing the first real exchange this issuer has ever been
  asked for, with a workload token minted in another cluster.

- **A revoked session's access token stops answering at `userinfo`.** An
  access token is a JWT verified offline everywhere else, so nothing can
  be told to stop honouring one before it expires — but `userinfo` holds
  the record, so it is the single place a revocation can reach a token
  already in circulation. Access tokens now name their session and are
  refused when it has ended.

  Conformance found it through the narrowest door: a reused authorization
  code must revoke what it issued (RFC 6749 4.1.2). We revoked the
  session and `userinfo` went on answering with the access token from the
  first redemption. Fixing only that case would have left every other
  revocation with the same hole.

- **The conformance driver can hand the browser step to a person**
  (`--manual`). Four Basic OP modules ask what a real sign-in returns,
  and recovery has no name or email to return.

## v0.15.1

- **The sign-ins table writes the person's name once.** Grouping the
  sessions list by identity in v0.15.0 fixed the half that sits below the
  fold; the table that actually fills the Sessions page is *Sign-ins*,
  and it repeated one identity fifteen times down the screen after a day
  of testing. One row per browser is still right — a sign-in is a browser
  and ending one is the unit of sign-out — but the name is written once,
  with a count of how many browsers.

  Found by taking a screenshot of the live page rather than trusting the
  change.

## v0.15.0

- **Sessions group by identity, then by browser.** Browser alone was the
  whole grouping, and on the installation-wide listing that reads as
  noise: one identity that signed in eight times is eight groups of one,
  stacked, repeating the same name eight times. By person first, with
  *same browser* kept underneath, because that is the unit a sign-out
  ends. Each heading carries its count.

- **The split deployment is gone from the code, not just from the
  cluster.** `HUB_ADDRESS` and `HUB_TOKEN_FILE`, the branch that dialled
  a directory over the network, and the whole `hubclient` package. The merge
  folded the hub into this process and nothing has dialled it since, so
  what was left was a branch that could not run and two settings nothing
  set — configuration that reads as a supported deployment and is not one.
  The directory is a required in-process dependency now.

  Removing it found the last caller: three tests were driving a stub HTTP
  hub, which is the shape from when the hub was a service of its own.
  They use an in-process directory now, which is what they were testing
  all along.

## v0.14.9

- **Charts are published by the release workflow, not by goreleaser**, so
  the set of shipped artifacts is written down in two places — and the
  second one kept `directory-roster` after the chart was deleted. v0.14.8
  built fine and then failed on `copy chart: lstat
  charts/directory-roster: no such file or directory`.

  Swept the repository for the rest rather than finding them one release
  at a time. Two were stale instructions that would have wasted
  somebody's afternoon: the issuer chart's README told you to install
  with `--set hub.address=...`, naming a service that no longer exists,
  and the acceptance command's doc comment described the wrong binary.


- **The release builds the bundles through `just console`** rather than
  restating the npm commands. v0.14.7 failed on its first release after
  the bundles left git: the hook built the console against `ts/dist`,
  which is what the console imports as `file:../ts` and which nothing had
  built yet. The ordering was already declared in the Justfile, and
  writing it out a second time is how the two got to disagree.


**The git history was rewritten at this version, and every tag before it
was deleted.** Nothing in the code changed by the rewrite — the tree at
this commit is byte-identical to what v0.14.6 shipped — but every commit
before it has a new hash, and the old tags are gone. A clone from before
this point cannot be fast-forwarded; re-clone instead.

- **Generated bundles are no longer in git.** `frontend/dist` cost 29.2 MB
  of history, about seventy per cent of the repository, because a
  minified bundle is a new blob on every dependency bump. It also bought
  a silent failure: a committed artifact goes stale while everything
  still compiles, which is how v0.14.0 shipped a console reading a
  protobuf field the server no longer sent. Absent, the embed is a
  compile error. Loud beats stale.

  `ts/dist` goes for the same reason, with a `prepare` script so a git
  install still needs no toolchain of its own. `gen/` STAYS: it is Go
  source, small and diffable, and it is what makes the module
  `go get`-able without buf.

- **`directory-roster` leaves the release.** One service, one image, one
  chart. The hub was a second binary until the merge folded it into the
  issuer, which runs it in process — `internal/app` is still here and
  still does the directory work. What goes is the separate deployment,
  which had gone on being built and pushed for a service deployed
  nowhere.

- **react 19.3.0**, which is what Renovate's two open pull requests were
  for. Neither could land: a bot can edit a lockfile and cannot rebuild
  what it changes. There is nothing to rebuild now.

- **The chart/binary environment check now points at the issuer's chart**
  and reads both environment consumers. It immediately named eight
  settings the merged service supplies to nobody, `SIGN_OUT_URL` among
  them — which is the defect behind *"sign out does not work"*, reported
  twice. Nothing failed at the time, because an empty string is valid
  everywhere it lands. The list is in the test now, with what replaced
  each one.

## v0.14.6

Both of these were found by LOOKING at the screenshots the conformance
suite had already collected. The suite cannot see what is in them — it
asks a person — so a module sitting in REVIEW with a picture of the
wrong thing passes silently. Two did.

- **The signed-out page was telling people the opposite of what had
  happened.** It said applications they already had open *"keep their OWN
  sessions until those expire"* and that ending a sign-in here *"cannot
  reach into them"*. True when it was written, and false since v0.14.2:
  signing out revokes every session the browser opened. So the page
  claimed a person's other consoles were still open at the moment it
  closed them.

  It now says what happens, and keeps the one piece of honesty that is
  still due: a proxy already holding a valid access token finds out at
  its next refresh, so a console can serve for a few minutes more. That
  delay is bounded by the client's `ttl_cap`.

- **`/authorize` refused with the library's bare text.** Unstyled black
  on white, with nothing on it saying which service had been reached.
  It is reached exactly when there is nowhere safe to redirect somebody
  — an unregistered `redirect_uri`, an unknown client — so the person is
  left looking at it with no way onward. It renders as a page now, in
  the same voice as the rest, keeping the library's sentence because it
  already says what is wrong.

## v0.14.5

- **A client's `ttl_cap` now reaches the tokens a browser gets.** It was
  applied on token exchange and nowhere else, so declaring it on a
  console did nothing at all — the code flow used the deployment-wide
  lifetime whatever the client said.

  That number is the lever over how long a REVOKED session keeps working.
  A client only learns a session ended when it next has to refresh, so
  the access token's remaining life is exactly the window in which a
  sign-out has not taken effect yet. Reported twice from live use, as a
  console that went on serving after signing out; the sessions are now
  revoked at sign-out (v0.14.2, v0.14.4) and this is what makes the
  revocation prompt rather than eventual.

  Back-channel logout would close the window entirely by telling each
  client at the moment of sign-out. It is still not served, because
  oauth2-proxy does not consume it, so a short cap is the lever we have.

## v0.14.4

**Security.** An unauthenticated `GET /end_session` ended every session
in the installation — every person and every workload, from anyone on the
internet, at an address the discovery document publishes.

The library hands the storage whatever the end-session request named, and
a bare request names nothing: no `id_token_hint` and no `client_id` left
both arguments empty. `TerminateSession` passed that straight into
`Revoke(Query{})`, and an empty query selects everything.

The same path had a second, quieter weakness. An `id_token_hint` is a
*hint* in the specification rather than a credential, and the library
accepts an **expired** one by design. Honouring it as authority to revoke
meant anybody who found an old ID token — in a log, in browser history,
in a referrer header — could sign that person out of a console.

`TerminateSession` now ends nothing. What a logout request can actually
prove is the cookie it carries, so the browser's own sign-in is the only
authority for what gets revoked. The hint keeps its real job, which is
choosing the client's signed-out page. Ending one identity's sessions at
one client is still available through `RevokeSessions`, which authorizes
the caller first.

- **Both sign-out doors now do the same thing**, and the one that had the
  weaker half was the one a PROXY uses. `/logout` revoked every session
  the browser had opened; `/end_session` — what oauth2-proxy chains to —
  only ended the sign-in. So a console behind a proxy went on refreshing
  and serving pages after a sign-out that reported success, which is how
  it was reported from a proxied console. Both call one `SignOut` now.

## v0.14.3

- **Signing out lands on the page that says so.** `/end_session` had no
  default landing page, so a request naming nowhere to go redirected to
  the issuer root, which redirects to the console, which starts a new
  authorization — and the last thing a person saw after signing out was a
  login prompt. That reads as the sign-out having failed. It now lands on
  the signed-out page, which says what did and did not end.

- **A refused sign-out no longer signs anyone out.** The browser session
  was ended on the way IN to `/end_session`, before the library had
  looked at the request. A request it then rejected — a bad
  `id_token_hint`, an unregistered `post_logout_redirect_uri` — produced
  an error page for a sign-out that had already happened. The response is
  now held until its status is known, and the sign-in ends only if the
  request was good.

- **`/end_session` answers a browser with a page.** Every failure there
  was an OAuth JSON body, which is right for `/token` and wrong for an
  endpoint a person's browser is redirected to. Anything that does not
  ask for HTML still gets the JSON, with its `error` code intact.

- **A `post_logout_redirect_uri` with no `id_token_hint` and no
  `client_id` is refused** rather than quietly dropped. There is no
  client named, so there is nothing to have registered it, and "not
  registered" is the only answer available. Nothing was being sent
  anywhere unregistered before this — the URI was ignored and the person
  signed out regardless — but silence in answer to a request is its own
  defect.

- **The conformance driver answers the suite's manual steps.** Eight of
  the eleven RP-Initiated Logout modules end at a page the suite cannot
  see and ask a human for a screenshot of it. Unanswered, each sat in
  WAITING until the next module interrupted it — a row of greyed-out
  results that looked like a server fault and was a step nobody had
  performed. The driver uploads the screenshot from the browser it is
  already driving.

## v0.14.2

- **Signing out ends what the browser opened**, not only the sign-in
  itself. The design leaned on those sessions dying *"at their next
  refresh"* — they do, because a revoked session's refresh is refused —
  but nothing was revoking them. So every console the person had opened
  kept its own session until it happened to refresh, and a sign-out that
  reported success left access in place.

  The sessions go first and the sign-in second: if the first half fails
  the sign-in is still there and the person can try again, where the
  other order would leave sessions running with nothing listing them.

## v0.14.1

- **The console bundle shipped in v0.14.0 was stale**, so the Sessions
  page's new sign-ins table would have shown nothing: a protobuf field
  was renamed `signins` → `sign_ins`, the TypeScript was regenerated, and
  `frontend/dist` was never rebuilt — so the bundle read a field the
  server no longer sends.

  `just check` did not catch it because `ts` and `console` were not in
  it: CI runs each recipe as its own parallel job, so the local check and
  the pre-push hook skipped the two that build. They are in it now. The
  check is slower and it is the check that runs before a push.

## v0.14.0

- **Reusing an authorization code ends the session it opened.** RFC 6749
  4.1.2 says a code used twice must be denied and SHOULD revoke the
  tokens already issued from it. We denied the reuse — the first
  redemption deletes the request — but left the first redemption's tokens
  working, which conformance saw as a resource endpoint answering 200
  where it wanted a 4xx.

  Denying alone is the worse half: a code presented twice is a code
  somebody else has, and the tokens from its first use are the ones now
  in doubt. PKCE with S256 is required here and already defeats most code
  interception, so this is defence in depth rather than an open door —
  and it is the cheap half, because the code arriving twice is the whole
  signal.

  A reuse is logged at WARN, since it is either a broken client or a
  stolen code and both are worth seeing.


- **A token says how the person was proved.** `acr` was empty, so a
  client asking with `acr_values` got none back — which conformance
  flags, and which matters more than the flag: a recovery sign-in
  bypasses the directory **by design**, and a relying party that wants to
  refuse one had no way to see it in a token. Two classes, and discovery
  now advertises both, because a client cannot ask for a value it has no
  way to learn about.

  `amr` said `pwd` for everything, which is untrue of every sign-in this
  issuer serves: recovery presents a ServiceAccount token, and a
  directory sign-in presents whatever the provider asked for — which we
  are not told, so claiming a password was an invention. It is empty
  where we were not told.


- **A response carrying a credential is never cached.** RFC 6749 5.1
  requires `Cache-Control` on the token endpoint and the library does not
  set it, so conformance failed `oidcc-refresh-token` with *"token
  endpoint response does not contain 'cache-control' header"*. The rule
  exists for a reason worth stating: a token response sitting in a
  proxy's cache, or a browser's, is a credential anybody who can reach
  that cache now holds.

  `no-store` and `Pragma: no-cache` go on `/token`, `/revoke`,
  `/userinfo` and `/introspect` — and deliberately **not** on discovery
  or the key set, which are public documents that should be cached.
  Telling the world not to cache a key set would put a fetch of it in
  front of every verification anybody does.


- **`prompt=none` with nobody signed in now answers the CLIENT.** OpenID
  Connect Core 3.1.2.6 requires `login_required` at the redirect URI; the
  issuer rendered an HTML page saying so instead, and the code comment
  had predicted the failure without fixing it.

  Worse than it sounds: the caller of `prompt=none` is usually a hidden
  iframe doing a silent renewal. It cannot read an HTML page, has nobody
  to show it to, and waits until it times out — so a relying party doing
  silent refresh would hang rather than re-authenticate. Conformance
  called it *"expected an error but did not get one"*, which is the same
  fact from the other side.

  Found by the Basic OP profile, which is the first thing that run has
  paid for.


- **The conformance driver runs in headless Chrome, because it has to.**
  The first one used `curl` on the reasoning that the flow is redirects
  and one form POST. It is not: the suite's callback is an HTML page that
  posts the result back **with JavaScript**, so `curl` reached it, never
  ran it, and every module sat in WAITING while the authorization it was
  waiting for had already succeeded. From outside that is indistinguishable
  from a hang.

  `hack/conformance_drive.py` drives Chrome over the DevTools protocol and
  submits the recovery form in the page, so the browser follows the
  redirects itself and runs the callback's script.

- **What a recovery sign-in cannot prove**, now written down. A recovery
  subject is a ServiceAccount: no address, no name, so `userinfo` returns
  no `email`, `name` or `preferred_username`. Every module checking the
  claims a scope implies warns for a reason that does not exist when a
  person signs in. The unattended run is evidence for the protocol
  modules and not for the claim-bearing ones.

- **Run one plan at a time.** The suite serves every plan's callback under
  its alias and the clients register one callback, so a second plan with
  a different alias is refused a redirect it never registered, and one
  with the same alias interrupts the running test — which it reports only
  in its own log, so from outside it looks like a hang. This is what
  stopped the first attempt.


- **The Sessions page lists the SIGN-INS**, above the sessions they
  opened. This is what made revoking look like a no-op: the page showed
  every per-client session and no sign-in, so emptying the list changed
  nothing about who could walk back in. Worse, the console's own sign-in
  appeared nowhere at all — it never redeems the code it gets back, so it
  opens no session — while being the very thing keeping the reader signed
  in.

  Each row ends that browser's sign-in and everything under it.
  `ListSessionsResponse` gains `sign_ins`, the sign-in store gains a
  global index beside its per-identity one, and both are returned under
  the same permission rule as the sessions.


- **Signing out leads back to signing in.** The signed-out page said what
  had happened and left you there; sign-out now lands on the console,
  which is where a sign-in can actually start. Not `/login` itself: its
  buttons carry the id of a pending authorization request, so visiting it
  without one is a page that looks like a sign-in and cannot finish. The
  console's front page sends an unauthenticated browser through
  `/authorize`, which makes that request. A deployment with no console
  still gets the signed-out page, which is the honest ending for one.

- **"Sign out everywhere" on your own page follows through.**
  *Everywhere* includes here: naming no client ends the sign-in as well
  as the sessions, so the page was left acting signed in until its next
  call failed with a sentence about tokens — reported as an error on
  revoke, and it was the trace of the sign-out that had already worked.

- **A refused call says the session ended**, rather than repeating the
  issuer's sentence about tokens, which is true and is not what happened
  to the person reading it.

## v0.13.3

- **Sign-out still did not work, and for a second reason.** The route
  existed but answered **GET only**, and the console sends **POST** — its
  own sign-out was a POST on the reasoning that a link which logs you out
  is a link anyone can put in a page. So the button got a 404 from a
  route that was there.

  It was verified the first time with `curl`, which sent GET, so the
  proof missed exactly the path the button takes. The network tab showed
  it in one line: `logout POST 404`.

  `/logout` now answers both. And the console is told the issuer's
  sign-out **absolutely**, because it treats a bare `/logout` as its own
  and fetches it — right where it serves that route, wrong here, where
  the route answers with a redirect a fetch would swallow and leave
  somebody reading "signed out" with the session still open.


- **The account block went back to the foot of the rail.** Moved up and
  moved back on looking at it: near the brand it competed with the
  navigation for the first thing the eye lands on, and a console is
  opened to go somewhere rather than to check whose account it is. What
  it needed was not height. It was a sign-out that says *Sign out*
  instead of an icon to guess at, and that stays — as does Settings in
  the list of places to go rather than alone in the foot.

## v0.13.2

- **The Config profile runs in CI**, daily and on demand
  (`.github/workflows/conformance.yaml`), and the three profiles are
  named in the README with which of them can run unattended and why.

  Config is the one that can: it reads the discovery document and the key
  set, so it needs no client, no secret and nobody at a browser. It also
  guards the surface most likely to break by accident — change a provider
  option and discovery changes with it, silently, for every relying party
  that reads it.

  **On a schedule rather than on a tag**, deliberately. A tag is a build,
  not a deployment: at the moment `v1.2.3` is pushed the cluster still
  runs what it ran before, so a run then would certify the OLD issuer and
  file the result under the NEW version. Certifying the tag itself means
  standing its image up inside the job with a policy, a signing key and a
  certificate the suite accepts — worth doing, and a different job.

  The other two sign somebody in, and the signing-in needs a credential
  from the cluster. CI has no business holding that, so they stay a
  person's job — `hack/conformance-drive.sh` makes thirty sign-ins one
  command.


- **The rail puts who you are at the top, and says "Sign out".** The
  account block sat at the foot of a scrolling column, which is the last
  place somebody looks for the first question a console like this raises:
  *which account am I looking at this with*. Settings sat down there too,
  alone behind two dividers, rather than in the list of places to go.

  Sign-out is a labelled button now instead of a bare icon. An icon alone
  is a guess, and this is the one control nobody should have to guess at
  — it was reported as not working when it was both hard to find and, as
  above, a 404.


- **Two directories read `provisional · stale` on a service that was
  working.** The refresh lease was held for the whole refresh interval,
  so the lease and the ticker were the same length and beat against each
  other: a tick arriving a second before its predecessor's lease expired
  was refused, and the next chance came a whole interval later. The
  effective period doubled to thirty minutes — **exactly the freshness
  window** — so the snapshot aged out and every domain in it lost
  authority.

  The evidence was in the ages: two directories at 32 minutes, and a
  third that happened to miss the collision at 17. The lease now runs
  three quarters of the interval, which still refuses a replica whose
  turn comes a few minutes later and never refuses one ticking on
  schedule.

  **The start-up catch-up now refreshes what is DUE rather than what is
  already stale.** A fourteen-minute-old snapshot on a pod that has just
  replaced another used to wait a whole interval more, reaching
  twenty-nine minutes — one rollout short of provisional. A restart
  should not extend the schedule, and an afternoon of releases should
  not look like a directory going bad.

## v0.13.1

- **Sign-out did nothing, because nothing served `/logout`.** The
  console's button pointed there, the issuer answered 404, and the
  sign-in survived — reported as *"even sign-out button does not work"*,
  which it did not. The issuer serves `/logout` now: it ends the browser's
  sign-in, clears the cookie and lands on the signed-out page.

  `/logout` rather than pointing the console at `/end_session`, and
  that is the right call: this is the address a person expects and
  types, `end_session` is a name from a specification, and the console
  could not supply the `id_token_hint` that endpoint wants anyway — it
  never redeems the code it gets back, so it holds no ID token. Both end
  the same thing.

- **The signed-out page stopped linking to a page that was deleted.** It
  sent people to `/account`, whose page went into the console. It now says what
  ending a sign-in does and does not reach, and points at the console's
  Sessions page for the rest.

- **`hack/conformance-drive.sh`** completes the browser half of a run
  without a browser. Nothing in that flow is JavaScript — a chain of
  redirects and one form POST — so it follows them with `curl` and signs
  in through recovery, which is a ServiceAccount token rather than a
  person at a Google prompt. It signs in fresh each time, because that is
  what the logout modules exist to check.

  It also treats `INTERRUPTED` as terminal. `conformance-run.sh` did not,
  which is why an alias conflict looked like a hang: **run one plan at a
  time**, because the suite serves every plan's callback under its alias
  and starting a test in a plan that shares one interrupts the running
  test.

## v0.13.0

- **Revoking every session left the sign-in standing.** Reported from the
  live console: *"I revoked all sessions, but still has access
  everywhere."* Every Revoke button sent a session id, and that path ends
  one session and nothing else — so a browser whose rows were all revoked
  kept its SSO session, the list emptied, and the next `/authorize`
  completed silently with no password. The half sign-out this design
  names twice, shipped in the console that was supposed to prevent it.

  The Sessions page now offers **signing the browser out** beside the
  rows, which ends the sign-in and every session under it. The rows keep
  their narrow meaning, because ending one session that is not the one
  you are using is a real thing to want.

  `RevokeSessionsRequest` gains `sso`, and it is checked against the
  identity before anything is ended — the permission check is against the
  identity the caller names, so without that an id alone would end
  somebody else's sign-in. Both properties have tests, and the first was
  verified to fail without the fix.

  **What this does not reach** is a relying party's own session. A console
  that ran its own flow holds its own cookie; `end_session` is
  front-channel and back-channel logout is not built, so Kargo answers
  until its own session expires however thoroughly you revoke here. Said
  plainly in `docs/design/sluis.md` rather than left to be
  discovered twice.

- **`hack/conformance-run.sh` runs a whole plan.** The suite's page has no
  *run all* and Basic OP has thirty modules. It starts them in order,
  waits for each, prints the result, and names the URL to open for the
  ones that genuinely need a person at a sign-in. `--from` resumes after
  a failure rather than re-running what passed.

## v0.12.8

- **Filter rows stopped stepping sideways when they wrap.** MUI's
  `spacing` sets margins on children and `gap` does not, so a row that
  declared both wrapped with a stray indent on every line after the
  first — visible on the Sessions filters on a phone, and latent in three
  more rows. The rows that wrap now use `gap` alone.

## v0.12.7

- **Every filter on every page wraps now.** Provider groups was still
  scrolling 73px sideways on a phone after the first pass, because it had
  its own copy of the control. Rules and its proof simulator are on the
  shared one too, so there is one filter in the console rather than five
  spellings of one.

## v0.12.6

Found by signing in to a running console with a headless browser and
looking at every page at 1440px and at 390px.

- **The Overview stopped shouting.** "Needs attention" rendered one row
  per internal group that opens no client — **73 of them**, because the
  clusters and cloud accounts that will require those groups are not
  connected yet.
  A healthy installation read as a broken one, the page was 4832px tall,
  and the working state was pushed off the screen. Runs of the same
  finding now collapse into one row with a count once there are more than
  three: below that the names are the information, above it the count is.

- **The filters fitted on a phone.** A `ToggleButtonGroup` is a flex row
  that does not wrap, so twelve domains ran off the side of the screen
  and took the page's width with them — the People page scrolled 182px
  sideways and Provider groups 73px, with the filter itself unreachable.
  One shared `Facet` now wraps, and three pages that had hand-rolled the
  same control with slightly different spacing use it.

- **The account block stopped linking to a page that cannot exist.** A
  recovery sign-in has no address — it is a ServiceAccount the cluster
  vouched for — so the link went to an empty person page. It still says
  who is signed in, and shows the full subject on hover rather than its
  first twenty characters.

## v0.12.5

- **The conformance runbook was followed, and it was wrong twice.**
  It told you to leave `requires` off the two temporary
  clients — the policy refuses a client that requires no group, so the
  render would have failed before a single test ran — and it gave their
  hostname without the port, which the render also refuses, because a row
  names one host and the redirects are on `:8443`. Both are fixed, and
  the page now records what the last run actually reported.

  **Config profile: PASSED against the merged service**, 34 checks, no
  failures and no warnings. The two attended profiles need a person at a
  browser and are the remaining gate.


- **The documentation describes what ships**. The sweep found
  seven Go symbols the guides promised and the module does not export —
  `identity.NewIssuerVerifier`, `identity.ClusterConfig`,
  `identity.ServiceAccountRef`, a `directory` package, an `authz`
  package — every one written down as though it shipped. A stranger
  following `docs/connect/console-app.md` or `service-to-service.md`
  could not have compiled what they were told to write.

  `just check` now asks the compiler: `hack/check-docs-symbols.py` runs
  `go doc` for every `identity.`/`tokens.`/`policy.` name the docs use,
  and fails on one that does not exist. Nothing compiles a code block in
  a Markdown file, which is why this drifted in silence.

- **`docs/integrations.md` stopped carrying a banner saying it was
  wrong.** Cases ④, ④b and ⑤ described the two-service shape; ④ is now a
  workload proven against its own cluster's published key set, ⑤ is a
  function call, and ④b is gone with the listener it described. The
  two-anchor summary was rewritten too: recovery alone stands on the
  cluster now.

- **`docs/connect/console-app.md` covers both console shapes** — a proxy
  in front, or its own flow — and says which is which, with the real
  `identity.Middleware`/`identity.Require` rather than a package that was
  never built. It also warns against registering a sign-out landing page
  as a redirect, which is the trap the cutover hit.

- The install line for the TypeScript package named a tag from eight
  releases ago.

## v0.12.4

- **The console says `access-roster`.** It said `directory-roster`, which
  was the name of a service that no longer exists, and the wording around
  it still called this "the hub" — a word that meant something only while
  there were two services. The provider pages, the setup steps and the
  settings hints say `access-roster` now.

- **The Sessions page is a table.** Four facts per session were stacked
  into one caption line, so a page that can hold a hundred rows used a
  third of its width and lined up none of its columns: a reader scanning
  for *whose session expires soonest* had to read every line. It is now
  Person, Client, Way in, Browser, Opened, Last used, Expires, with a
  facet for the way in that offers only the ways actually present.

  **The browser grouping became a column** rather than a run of
  subheadings. Two rows carrying the same mark came from one browser, and
  a blank is a session with no browser behind it at all — which is what a
  token exchange is. A column can be compared down the page, which is the
  one thing a subheading cannot.

  The grouped list stays for a person's page and a client's page, where
  it sits in a narrow column, holds three rows, and the grouping is the
  point.

## v0.12.3

- **The Sessions page came back.** It vanished at the cutover, silently:
  the console learned where its issuer was from the FORWARDED bearer's
  issuer, which the proxy in front configured, and on one origin there is
  no proxy. An empty issuer reads as *there is no issuer to talk to*, so
  the console hid the Sessions page and the sessions section of a
  person's page — on exactly the deployment where they work best, since
  the call is now same-origin and carries the browser's own SSO cookie.

  The merged process now tells the console its own issuer URL, the same
  way it already hands over the session reader and the sign-in entry.
  Nothing failed and nothing was logged, so the test asserts `whoami`
  reports an issuer and fails without the wiring.

- **The Providers page filters by provider and by state.** The state
  facet offers only the states actually present, so it never shows a
  button that returns nothing — and one function decides a domain's state
  for both the chip and the filter, because two would drift.

- **The People page's domain filter lists only served domains.** A
  provider discovers every domain its tenant owns, most of them parked;
  offering eleven when three can hold an account made the filter mostly
  buttons that return nothing, and hid the ones that work among them.


- **`hack/cutover-cleanup.sh`**, for the two messes the one-service cutover
  leaves that will not resolve on their own.

  A **stuck ValkeyCluster**: the retired store was pruned with foreground
  propagation, so it waits for its dependents while the Valkey operator
  keeps recreating them. The tell is that its pod, StatefulSet and
  Service are a few seconds old however long you watch.

  And **orphans**: the two retired Applications were pruned without a
  cascade, so everything they owned still runs with a tracking-id naming
  an Application that no longer exists. Nothing owns them, so nothing
  will ever prune them — and an orphaned HTTPRoute still competes for its
  hostname.

  It refuses to run unless the proxies' session store and the workspace
  records are both present, because those are what must survive, and it
  names every object rather than selecting by label: a selector here
  would also match what the service itself wrote.

  **In the event neither was needed.** ArgoCD finished the cascade on its
  own a few minutes later and the operator let the store go. The script
  stays because the state it describes is real, was live for about twenty
  minutes, and is not something to diagnose a second time from scratch —
  and because next time it may not resolve itself.

## v0.12.2

- **`console.mount` accepts `/console/` as well as `/console`.** The
  chart matched the trailing-slash spelling exactly and then redirected
  it to `/console//`, a path the console does not serve — from a value
  nothing rejects, because both are legal strings. Our own configuration
  writes it both ways: a declared client carries `prefix: /console` and
  `mount: /console/`. The Go side already trimmed it; now the chart does
  too, and `just check` renders both spellings and diffs them.

  Found while pointing a live installation's values at the merged chart, which
  is exactly where it would have bitten.

# Changelog

One line per release; full detail lives in the release notes and the
git history.

## v0.12.1

- **The v0.12.0 release published nothing**, and the reason is the one
  this repository's own release config warns about: release machinery is
  exercised only by a tag. `accessctl` is the single binary built for
  Windows, so in one shared archive the Windows download held one binary
  where every other held four, and goreleaser refuses that — four minutes
  into the tagged run, after every cross-compile had already succeeded.

  `accessctl` now has its own archive, zipped on Windows as that platform
  expects, which is also the better shape: it is the one thing here that
  runs on somebody's own laptop.

  And `just check` now proves every archive is uniform across its
  platforms by reading the same file goreleaser reads. Neither
  `goreleaser check` nor `build --single-target` reaches the archives
  stage, which is why nothing caught this.


- **A session cookie is marked `Secure` by default**, decided by the
  scheme of the service's own public URL rather than by a flag that
  defaults to off. It used to default to off, so an installation that
  simply did not set `SECURE_COOKIES` served its session cookie without
  the flag and a proxy could carry it over a plain-http hop. The chart
  always set it, which is why nothing was wrong in our own deployments
  and why the alert CodeQL raised was about the default rather than
  about any line it pointed at.

  `SECURE_COOKIES` still overrides in both directions, for a TLS
  terminator the URL does not mention.


- **The Action's own comment was an expression.** GitHub evaluates
  `${{ ... }}` anywhere inside a `run:` block, including in a shell
  comment, because the block is a string value before it is a script.
  A comment added in v0.12.0 to explain which inputs are untrusted named
  an event expression literally, so every run of the action would have
  expanded it. Found by CodeQL, which was right to call it code
  injection. **v0.12.0's action is broken; use this.**

- **What reaches `GITHUB_ENV` is now the profile name this run wrote**,
  not the input that selected it. The check against the written list was
  already there, but passing the input through meant the value's shape
  still came from the workflow. A name built here is `role@account` from
  an audience whose whitespace was stripped, so it cannot carry the
  newline that would declare extra environment variables.

## v0.12.0

- **The GitHub Action's `default-profile` is checked against the profiles
  the run actually wrote.** It reached `GITHUB_ENV`, so a newline in it
  declared arbitrary environment variables for every later step of the
  job — the input is trusted only as far as whoever wrote the workflow,
  and an expression like `${{ github.event.* }}` is not trusted at all.
  Found by CodeQL. Checking it against what was written closes that and
  also catches a name that is simply a typo, which would otherwise
  surface as an AWS error three steps later about a profile that does
  not exist.

- **The GitHub Action** (the other half). One action at the
  repository root, `curl` and `jq` and two files: nothing of ours is
  downloaded into a job, and there is no version of ours to bump when
  Amazon's tooling moves. One exchange per audience, a profile per
  `aws:<account>:<role>` with `web_identity_token_file`, a kubeconfig
  context per `k8s:<cluster>`, and every token masked before it is
  written anywhere.

  Exercised end to end against a stand-in for GitHub's id-token service
  and the issuer, which found the bug that would have hurt: `printf '%s'`
  leaves the last line unterminated and `read` drops it, so **the final
  audience of every job was silently discarded** — surfacing as a missing
  profile rather than an error.

- **`accessctl`** (the CLI half). `login` runs the browser flow
  once — authorization code with PKCE on a loopback port, the only
  browser flow left since the device flow was withdrawn — and caches the
  refresh token in a 0600 file. Everything else shares that cache:
  `whoami`, `kubeconfig`, `aws-config`, `setup`, `exchange`, and the two
  credential helpers `kube-token` and `aws` that kubectl and the AWS SDKs
  run themselves.

  It writes into two files that belong to somebody else, so it is careful
  about both. The kubeconfig goes through `kubectl config` rather than
  being rewritten, because a person's other contexts are none of this
  tool's business. The AWS config is rewritten only between two markers,
  so a profile for a role somebody no longer holds does not survive as an
  entry that fails when used, and nothing outside the block is touched.

  Exit codes are a contract: 2 usage, 3 not signed in, 4 audience not
  granted, 5 issuer unreachable — so a wrapper can tell *sign in again*
  from *the issuer is down*, and knows not to retry a refusal.

- **A public `tokens` package**: the RFC 8693 exchange, and the two
  envelopes a credential helper has to speak. It is what `accessctl`
  will run on and what a workload can use directly.

  The exchange presents its client in HTTP Basic, because the library on
  the other side reads it from Basic alone and a posted `client_id` is
  refused with an error naming the client rather than the mistake. A
  refusal carries the issuer's own sentence — which audience, and which
  groups the proof holds — since that is the whole value of the error in
  a build log.

  `WriteExecCredential` answers whichever apiVersion kubectl asked for,
  and carries the expiry so kubectl caches instead of running the plugin
  on every API call. `WriteCredentialProcess` writes real STS
  credentials with `Version` as the **number** 1, and
  `AssumeRoleWithWebIdentity` obtains them — unsigned, which is why the
  AWS path needs no stored key: the token is the proof and the account's
  trust policy decides what it opens.

- **A public `identity` package, and access-roster uses it** (the
  Go half). Two verifiers, one per anchor: `Issuer` for a token this
  installation signed, `Cluster` for a ServiceAccount token from the pod
  next door. Both yield one `Verified`, so a handler never learns which
  anchor proved the caller and cannot come to depend on it — the right
  anchor is decided by how far away the caller is, and that can change
  without the handler. No group re-mapping anywhere: the name in the
  policy is the name in the token is the name in the role check.

  With a `net/http` adapter: `Middleware` establishes the caller and
  passes the request on, because a listener serves pages that run before
  anybody is established; `Require` is what refuses, and never names the
  group that would have worked. `WhoAmI` answers rather than refuses when
  nobody is signed in, because that is something a console has to render.

  `Cluster` takes a review function rather than building one, so a
  consumer that only needs the issuer does not inherit Kubernetes client
  libraries.

  **The service consumes it.** `internal/server/forwarded.go` is now a
  thin adapter over `identity.Issuer` instead of a copy of the same
  verification. Doing that caught a narrowing: the lifted reader matched
  `Bearer ` exactly, and RFC 6750 makes the scheme case-insensitive —
  real clients send both spellings, and a caller that had done nothing
  wrong would have been refused.

- **GitHub team bindings are a table in the policy** (the
  access-roster half). `github: <org>: <team>: [provider groups]`, read
  exactly like a group's `members`: the people the directory puts in
  those groups are the people that team should contain. It grants
  nothing here and appears in no token — a controller reads it and makes
  the organisation match — and it lives in this file for one reason, that
  a reader of the access model sees every team's source without opening
  another file.

  The console's Rules page lists them beside the rest with the same
  *depends on* column. They feed a team rather than an internal group, so
  they open no client and the page says so. A team fed by an empty list
  is refused, because "remove everyone from platform" is not something to
  express by leaving a list out; the same team declared in two merged
  files is refused too, because the second would silently replace the
  first.

  The controller, the read-only GitHub page and the directory endpoint it
  authenticates against are the other three parts of this work and wait
  for github-roster.

- **The console signs people in as a client of the issuer**,
  which is what makes one binary mean one door. Somebody with no session
  is sent to `/authorize` with the console's declared client, signs in at
  the issuer's page, and comes back with the issuer's session set. No
  proxy in front of the console running an OpenID flow against a service
  in the same process, and no login of the console's own.

  The code that comes back is never redeemed: what the console needed was
  the session, not a token, and it reads the directory and the policy in
  this same process. It is stripped from the URL so it reaches no
  bookmark and no referrer. Set `console.client` to a declared client
  whose redirects name this origin plus the mount; empty keeps the
  console's own page.

- **The console gets its own HTTPRoute**, and that is not tidiness. A
  gateway policy attaches to a *route*, so anything put in front of the
  console on a shared route would also sit in front of `/token`, `/keys`
  and discovery — every relying party in the estate asked to sign in to
  fetch a key set. It renders whether or not anything attaches to it,
  because discovering at cutover that there is nothing to attach to
  leaves only that bad option. The prefix is deliberately not rewritten
  away: the service strips it itself, so a gateway that stripped it too
  would hand the console a path it never serves.

- **The console admits whoever the issuer signed in.** One origin and one
  process, so the browser's issuer session is read directly rather than
  being relayed. Before this, a console on the issuer's own host was
  authenticated either by a proxy — which ran an OpenID flow against a
  service in the same process, a network round trip and a second session
  store to learn something already known — or by a login of its own,
  which is the second door an installation with a gateway deliberately
  turns off.

  It does **not** remove the need for a way to *start* a sign-in. A
  person arriving with no session anywhere still needs one, and the
  console's own login or a proxy in front of it is still what provides
  that. What this removes is the second session for a person who already
  signed in somewhere behind this issuer.

- **An installation that signs nobody in yet still serves its sessions.**
  The handler returned early on "no sign-in providers" and took the
  session service and the signed-out page with it. The posture where that
  bites is day one: recovery is available with no OAuth client configured
  — that is the whole point of it, the way in before any directory is
  connected — and a recovery sign-in opens a session like any other. An
  operator who had just recovered could not then list or revoke anything.
  The same mistake, in a new shape, as gating the session service on
  `console.origin` once did.

- **The endpoint reference no longer promises two endpoints that do not
  exist.** `/.access/grants` and `/.access/simulate` were listed as
  served. Neither is implemented; both belong to `accessctl`,
  and the table now says so and names what answers the same question
  today.

- **A workload's cluster survives the exchange.** The verified proof
  travels through the OpenID library as a map of claims and is rebuilt on
  the other side, and the cluster was not among them — so it was dropped
  in silence. Two halves of that loss: the subject stopped naming the
  cluster, and the same namespace and name exist on every cluster, so two
  different machines became one `sub` — exactly the collision the
  qualifier exists to prevent. And a `service_account` matcher narrowed
  to one cluster was compared against an empty string, so it matched
  nothing at all and an operator would see a rule granting nothing with
  no reason visible.

  It predates the federation work — the qualifier never reached a token
  through exchange — but federation is what makes it reachable, because
  until now there was one cluster.

- **Both halves of the merged service act on one policy**, loaded once
  and handed to the issuer rather than loaded twice. They read the same
  file in a real deployment, so the disagreement stayed hidden — but
  their fallbacks differ, and two halves that *can* disagree about the
  policy is exactly the class of failure the merge existed to end. Found
  by booting the merged binary: with `DEMO=1` the directory half built a
  demonstration policy and the issuer half refused to start on an empty
  `POLICY_DIR`.

- **One design document.** `docs/design/hub.md` and
  `docs/design/access-issuer.md` fold into
  `docs/design/sluis.md` — the directory model, freshness, the
  policy, the three proofs, the six grants, sessions and one origin, the
  console, the store, recovery, failure semantics — and end with an
  appendix naming everything that was removed and why, so nobody adds one
  back without a reason. `architecture.md` loses its two-services banner
  and draws one container. The README no longer promises a merge that has
  happened.

  `integrations.md` carries a note on the three cases that describe the
  old shape; it is rewritten with the rest of the documentation at 1.0.

- **The console reads.** It no longer writes who is in which internal
  group. A console that could add a membership was a second
  source of truth beside git and a merge layer to reconcile them; who is
  in a group is now the policy, rendered from the installation's own
  access model, and `git log` is the complete history of access. Gone:
  the `memberships` table (refused now, not ignored), the console layer
  of the policy, the `layer` field on every member, and `SetOAuthClient`
  — the OAuth client is a Secret, delivered the way every other
  credential in the estate is.

  Kept, and each for a stated reason: **connect a provider** by admin
  consent, because Google's consent genuinely needs a browser and there
  is no infrastructure-as-code way to obtain that credential; and
  **revoke a session**, which is a removal and the lever between
  sign-out and expiry.

  Nothing was lost in the change: no installation had ever attached a
  membership through the console. Still to come under the same ticket:
  a provider's `serve` and `synced` are chosen in the console today, and
  become values once the values can name a consent-connected provider.

- **The issuer's UI is the login page.** `/account` — a person's own
  sessions and *sign out everywhere* — was server-rendered by the issuer
  because it had to be same-origin with the session service.
  The console is same-origin and, since the merge, the same process, and
  its page for a person already shows both. Two pages showing one thing
  is two things to keep true of each other, so the issuer's is deleted
  and the address redirects into the console. The two POSTs behind it go
  with it: an endpoint that answers after the page using it is deleted is
  surface nobody is keeping honest.

  What the issuer still renders is `/login` and `/signed-out`, and both
  stay for the same reason: each runs before there is anyone to
  authorize, so neither can be a console page.

- **One issuer, many clusters, access to none of them.** A workload's
  ServiceAccount token is verified against the key set its own cluster
  publishes, never by asking the cluster. Asking meant a
  TokenReview, and a TokenReview against a cluster elsewhere meant holding
  a kubeconfig for it — inside the service whose whole design is to hold
  almost no credential. A key set is public: EKS publishes one per cluster
  (it is what IRSA rests on) and Talos serves the same keys at the API
  server's `/openid/v1/jwks`. So a remote cluster's workload proves itself
  exactly the way a GitHub job does, and connecting one is a row of
  `exchange.clusters` naming a URL.

  This service's own cluster is a row like any other. There is no special
  case for it, because a special case is a second code path that only one
  installation exercises. The TokenReview verifier is deleted, and the
  cluster-scoped permission the chart creates now belongs to recovery
  alone — on the day everything else is broken it should depend on
  nothing but the API server.

  What this gives up, plainly: a TokenReview notices a deleted
  ServiceAccount and a key set does not, so a token stays usable until it
  expires. Bound tokens are short-lived, so the window is minutes.

- **Six grants, and the four that were served are gone.** The issuer
  serves the code flow with PKCE, refresh, userinfo, `end_session`,
  revocation and token exchange, and nothing else. The device
  flow is for a machine with no browser, and both headless cases here — a
  CI job and a workload — are token exchange. Client credentials is a
  machine with a stored secret, which is the thing this design exists not
  to have. JWT bearer is token exchange with a different spelling.
  Introspection never applied: these are JWTs, verified offline against
  the key set.

  Withdrawn from discovery *and* from the storage, which is the part that
  matters. The device flow stops working because nothing implements the
  library's device interface any more, so there is no device state kept
  and no way for a code to be stored by something that changed its mind.
  A test asserts each withdrawn grant is refused at `/token`, because an
  endpoint that answers after its metadata stops mentioning it is the
  failure that hides.

  `grant_types_supported` prints three, not six: three of the six are
  grants and three are endpoints, which discovery advertises in fields of
  their own. Listing an endpoint as a grant type would be the metadata
  lying in a new way.

- **One service.** The directory hub and the issuer are one process.
  The issuer asks the directory by calling a function instead
  of dialling a service, so a login now makes no network call except to
  the corporate directory: gone from every single sign-in are a
  ConnectRPC round trip, a TokenReview, a NetworkPolicy hop, and the
  class of failure where the two halves disagree about the same person.
  The console is served on the issuer's own origin under `/console/`,
  which is what lets its session pages use the browser's cookie with no
  bearer in JavaScript, and one `/readyz` answers for both stores. The
  split was built so that several things could ask the directory; the
  issuer became its only consumer, and the endpoint comes back on the
  merged service when the GitHub controller needs it.

  The console is now told where it sits, because a prefix that used to be
  stripped by the gateway also has to appear in every link the console
  hands a browser: `/login` resolves against the origin, where the
  issuer's page is.

  The `access-issuer` chart renders the whole of it: `directory.*` for the
  workspaces and their freshness, `console.mount` for where the console
  sits, a namespaced Role for the store, and no projected token for a hub
  nobody dials. `hub.address` is gone. The `directory-roster` chart and
  binary still ship unchanged, so an installation moves when it chooses
  and can move back; they go once nothing points at them.

  **Moving an installation is not only a chart switch.** What an operator
  connected — the workspace records and their credentials — lives as
  ConfigMaps and Secrets in the namespace the hub ran in. Copy them into
  the issuer's namespace before the cutover, or the new pod starts with no
  directories connected.

- **The console says *provider*, and the tables split domain out.** What
  the code calls a workspace the console now calls a **provider**, and
  the groups it holds **provider groups**; both sides of the rail then
  say simply *Groups*, and the heading above each — *Where people come
  from*, *Internal* — tells them apart, so the reader no longer carries
  a qualifier down every page. Providers list one row per *(provider,
  domain)* pair rather than stacking domains inside a cell, because the
  row is the unit a reader compares. Groups gain filters by provider and
  by domain; People gains a **Domain** column and a domain filter, and
  that one is applied by the hub (`SearchPeopleRequest.domain`) rather
  than over the page the console received — this list is capped at 200,
  and narrowing it in the browser would answer *nobody* while the
  snapshot holds hundreds. URLs and the API keep the old words, so
  nothing bookmarked or scripted moves.

- **A moved Valkey no longer needs a human.** On 2026-09-10 a Valkey pod
  was rescheduled onto a new address; the issuer and a console's proxy went
  on dialling the old one for half an hour, reported **Ready**
  throughout, and had to be restarted by hand. Three things were wrong
  and all three are fixed. **Cluster mode is off by default**: with one
  shard it makes the client learn node addresses from `CLUSTER SLOTS`
  and talk to those, bypassing the Kubernetes Service — the one
  mechanism whose whole job is to survive a pod moving. **Readiness now
  follows the shared store** and liveness deliberately does not, so a
  replica that cannot reach it leaves the gateway's rotation and answers
  fast instead of hanging, while one blip cannot restart the fleet; the
  refusal names the dependency and the reason. And **a test proves the
  recovery** rather than assuming it: stop the server, start it again,
  and the client must work without being reconstructed. It recovers in
  about two seconds.

## v0.11.0

- **The documentation is rewritten around what the product is.** The
  README opens with the idea in three sentences and the niche in one
  table: dex is the right shape and stops one step short of knowing
  anyone's groups; the heavy providers can do all of it at the cost of
  running an identity product to use a fifth of one. `architecture.md`
  is a third of its length, draws the live two-service shape honestly
  and names the merge that follows; `why.md` carries the seven problems
  and seven principles and nothing the README already says. Seven
  decisions taken 2026-09-10 are recorded where they land — one
  service, machines by a federated key set with token exchange
  as the one machine grant, six grants, a read-only
  console, the login page as the issuer's only UI —
  and the two design documents carry a banner saying which of their
  sections are current and which are history. No code changes.

## v0.10.0

- **A runbook for the conformance run.** `docs/operations/conformance.md`:
  the suite from published images so there is no Java build, the Config
  profile as a script that needs no client and no browser, and the two
  attended profiles as a checklist — including the two temporary clients
  they need and the step to remove them afterwards, which is the one
  that gets forgotten.

- **A refused bearer at `/userinfo` now carries a challenge.** RFC 6750
  requires a `WWW-Authenticate` header on a 401 from a bearer-protected
  endpoint; the library answers an unusable access token with a bare
  error and no challenge, which is the one shape a conforming client
  cannot act on — it is told it is unauthenticated and not told what
  would fix it, so a client library reports a transport failure or
  retries the same token for ever. Found by the conformance work,
  fixed in a wrapper because the header has to be set before
  the status is.

- **The API listener's consumers hold a grant.** Admission and
  authorization were one decision: a consumer admitted at all could
  enumerate every group of every company the hub reads. One consumer —
  the issuer — needs exactly that; a team-sync or a cross-cluster hook
  needs one directory and one question. A consumer is now declared with
  a grant along three axes — which directory (`workspaces` or `domains`),
  which `groups`, which `reads` (`resolve`, `groups`, `describe`,
  `probe`). No grant is full read, so nothing declared before this
  changes meaning. Outside the grant answers exactly as an unserved
  domain does, because a refusal would confirm what the grant withholds;
  `Describe` lists only granted domains, so discovery is scoped too; and
  the listener stays read-only whatever a grant says. **Breaking for a
  hub configured by environment alone:** `API_CONSUMERS` is gone and
  consumers are declared in a mounted file, because a grant does not fit
  in a comma-separated list in any spelling an operator could read. The
  chart renders and mounts it from the same `consumers[]` values.

- **The console's Matchers page becomes Rules.** It listed only
  rules that admit a proof by its *shape* and silently omitted those that
  admit by directory membership — 30 of 73 groups on the first real
  installation — so filtering it by a cluster role returned nothing and
  read as missing data rather than as the wrong page. How a rule is
  evaluated is a property to show in a column, not a reason to split the
  answer: a membership rule needs the directory to vouch and degrades to
  the hold window when it cannot; a matcher needs only the proof, which
  is why recovery is one. The page now shows every rule that puts an
  identity into an internal group, adds a **directory group** tab and a
  **depends on** column, and its group filter answers for all 73 groups
  rather than 30. `#/matchers` still resolves, so a bookmark does not
  land on the overview. The policy's `matchers:` field is unchanged, and
  People, Directory groups and Internal groups are untouched: they answer
  the same graph identity-first, source-first and target-first, and Rules
  is the fourth direction rather than a replacement for any of them.

## v0.9.15

- **The session service is mounted whether or not a cross-origin console
  was configured.** It was gated on `console.origin` — a value that
  answers a different question, *may some other origin call this* — so on
  one origin, where there is no CORS to configure and nobody sets it, the
  service was never mounted. Every sessions section in the console
  answered 404 while `/account`, server-rendered beside them off the same
  store, worked perfectly: the half a person is most likely to try
  working, and the half a console shows not. The value now decides only
  whether the CORS wrapper goes on.

## v0.9.14

- **The console asked the wrong host who it was.** `/.access/whoami` was
  fetched as an absolute path, so mounted under `/console/` it resolved
  against the **origin** — the issuer — which serves no such endpoint.
  The console concluded nobody was signed in: it offered *Sign in* to
  somebody already authenticated and disabled every operator control,
  while the Connect calls beside it worked, because those had been
  fixed for the mount point and this had not. Every path the console asks
  for now goes through one `mounted()` helper, so there is one place to
  get it right rather than one per call site.
- **A snapshot already past its freshness window is refreshed at start.**
  A ticker's first tick is a whole interval away, so a restart served the
  previous process's snapshot for fifteen minutes — and a deployment
  rolling more often than that never reached a tick at all. The snapshot
  aged past the window and every domain read *provisional*, which is a
  release cadence showing up to an operator as a loss of authority. Only
  what is already stale is re-read, and the existing lease still means
  replicas starting together read once between them.

## v0.9.13

- **The console's assets are referenced relatively, so one bundle serves
  at any mount point.** Mounted under a path they were requested from the
  origin root — where the issuer answers — so every asset 404'd and the
  console did not load. A build-time base path could not fix it either:
  the bundle is committed and embedded, so baking one deployment's prefix
  into it would ship that prefix to all of them. `./assets/…` resolves
  against the page instead. It requires the trailing slash, so the bare
  prefix now redirects to itself with one, and the Connect transport
  resolves its base from the page rather than a literal.
- **A bare GET of the issuer's host can land somewhere useful.**
  `route.rootRedirect` on the issuer — the issuer serves nothing at `/`,
  every endpoint it answers being a named one, so a person who types the
  domain got a 404. Empty keeps that 404, which is honest for an issuer
  deployed alone.
- **`/register` is dropped, and every client is declared.** Only our own
  proxy could ever have called it; an endpoint that mints clients is the
  one surface an issuer least wants; and declaring them keeps *who can
  obtain tokens for which audience* answerable by reading a repository
  rather than by querying the running service. `registration.enabled`
  leaves the access-proxy chart, `/register` leaves the issuer's surface,
  and the console's Clients page is read-only by construction rather than
  by policy. The drift it would have prevented is closed by generating a
  console's client from one row instead.

## v0.9.12

- **The sign-out chain moves with the console.** Mounted under a path,
  the console's sign-out link still pointed at `/oauth2/sign_out` at the
  root — which belongs to the issuer, not the proxy — and its
  `post_logout_redirect_uri` was the host root rather than the console's
  own page, so it matched no `signed_out` entry and the issuer landed the
  person on its own page. Both halves fail quietly: one is a button that
  404s, the other is a sign-out that worked and reads as though it did
  not. The proxy prefix now derives from `route.pathPrefix` when unset,
  so the two cannot drift, and three guards hold the chain. No prefix
  renders exactly what it always did.

## v0.9.11

- **One Gateway can be shared between the hub and its issuer.** Both
  charts rendered their own for `route.host`, so pointing them at one
  hostname produced two Gateways each declaring a listener for it — and
  Envoy Gateway merges every Gateway of a class into one deployment, so
  they collide on that listener rather than coexisting. Exactly one may
  own it now: the hub's `route.gateway.{name,namespace,sectionName}`
  attaches to an existing one instead of rendering a Gateway and a
  Certificate, and the issuer's `route.sharedWith[]` admits routes from
  the namespaces named (its own always included — a selector, unlike
  `from: Same`, does not imply it). Both default to today's shape.
  Whether a Gateway accepts a route from another namespace is decided
  there and not by a ReferenceGrant, which governs `backendRefs` and has
  nothing to say about `parentRefs`.

## v0.9.10

- **The console's sessions sections need the issuer to share the origin,
  not merely to exist.** They were gated on an issuer being configured at
  all. But the session service is called **same-origin**, with the
  browser's issuer cookie and no bearer — that is the whole point of
  putting the console under its issuer's host — so wherever the two are
  still separate hosts the sections rendered and then called the
  console's own origin, which serves no such service. A 404 per section,
  on every deployment that has not done the cutover. Supersedes v0.9.9,
  which carried the bug.

## v0.9.9

- **Docs: one domain, and where session management lives.** Decided
  2026-09-10: the issuer, the directory's console and the shared UI
  live on one hostname. The issuer sits at the **root** — its URL is the
  `iss` claim and discovery lives at the origin root, so it cannot take a
  path — and the console is mounted under **`/console/`**, the gateway
  rewriting the prefix away. On one origin the console's session pages
  call the issuer with the browser's own session cookie, so the
  cross-origin bearer question stops existing. The global sessions
  listing **exists**: operator-only, capped, audited. The issuer's plain
  `/account` page stays as the fallback for an installation with no
  console. `docs/design/access-issuer.md` *One origin*, `docs/design/hub.md`,
  `docs/architecture.md`, the references.
- **The console can be mounted under a path of its host, so it can share
  its issuer's origin.** `route.pathPrefix` on the hub's chart: the
  console's own route matches the prefix and the gateway rewrites it
  away, so the hub's own routes never learn it exists. The **bootstrap
  surface stays at the host root** — `/login` and `/connect` are
  registered OAuth redirect URIs, and a provider returns to the literal
  address on file, so a prefixed one would be a callback nothing points
  at. Two chart guards hold both halves. Empty is exactly today's shape.
- **The global session listing exists, for an operator.** A request
  naming neither an identity nor a client used to be refused outright;
  it now answers for an operator and is refused for everyone else. It is
  the incident case: the one where you do not know *whose* session to
  look for. Paged by a cursor that is the last session seen rather than
  an offset, because an offset is invalidated by every session that opens
  or closes between two calls and this index is precisely the thing that
  changes constantly. Capped, and a session now reports the browser
  session that parented it.
- **Sessions in the console.** *Active sessions* with Revoke on a
  person's page and *Sign out everywhere* on your own; *Open sessions* on
  a client's page; and a new operator-only **Sessions** page listing the
  installation, filterable by person and client. Rows opened from one
  browser group together. They call the issuer's session service
  same-origin with the browser's own session cookie — no bearer, no CORS
  — and render only when the console knows of an issuer. Removal only,
  never a grant.

## v0.9.8

- **A ServiceAccount's subject names its cluster.** `sub` was
  `k8s:<namespace>:<name>`, and the same namespace and name exist on every
  cluster in an estate — so two different machines were one subject, which
  is the collision `sub` exists to prevent. It is now
  `<cluster>:k8s:<namespace>:<name>`, from the issuer's new `cluster`
  value; scope first, like every group name. An installation that names no
  cluster keeps the unqualified form, so nothing changes until it is set.
  A `service_account` matcher may name a `cluster` to narrow to one, and
  naming none matches any — every rule written so far still means what it
  meant.
- **One spelling for a ServiceAccount, and one reader for all three.**
  A recovery sign-in completed as the API server's
  `system:serviceaccount:<ns>:<name>` while a token exchange minted
  `k8s:<ns>:<name>`, so the same machine had two subjects and a
  `service_account` matcher could admit one and not the other. Recovery
  now completes as the issuer's own spelling. Every spelling the estate
  has minted is still **read** — by one function, in `policy` — because a
  reader that knew only its own would refuse a token from a release either
  side of it, and for recovery that is exactly the day it is the only way
  in.

## v0.9.7

- **The issuer holds a session with the browser, so a second console
  costs no login.** It held only a login-round-trip cookie: every console
  bounced the person back through the corporate directory, and *global
  sign-out* had almost nothing to end. Now an authorization request
  completes against that session — silently — and `auth_time` comes from
  where the person actually authenticated rather than from the moment a
  token was minted. `prompt=login` and `max_age` are honoured, including
  `max_age=0`, which is a request for a fresh authentication and not, as
  a zero duration would otherwise read, no requirement at all. The
  directory still decides: a silent sign-in re-asks the hub, so a
  suspended account stops being admitted instead of coasting on a browser
  session. `end_session` ends the sign-in, not only one application's
  tokens — the half-sign-out that looks exactly like a whole one.
- **An account page, served by the issuer at its own host.** `/account`
  lists what you have open and ends all of it. Being same-origin with the
  session service is the point: the browser already holds this issuer's
  session there, so the page needs no bearer, no CORS and no console, and
  its buttons are form posts rather than JavaScript. *Sign out
  everywhere* ends both halves — the sessions already running and the
  sign-in that would silently open more. Per-client sessions now record
  the browser session that parented them and the time it authenticated.
- **Docs: the SSO session and where session management lives.** The
  design now says plainly that the issuer holds a first-class **SSO
  session** (to build) and that session management is served at
  the **issuer's own host** — an account page, same-origin with the
  session service — rather than through a cross-origin bearer from each
  console. The v0.9.4 `console.origin` CORS path becomes the optional way
  to weave the operator view into the directory console. `docs/design/access-issuer.md`.
- **Docs: `sub` is decided.** A person is their email; a ServiceAccount is
  `<cluster>:k8s:<namespace>:<name>` (the cluster qualifier is the one part
  still to land in code). `docs/reference/sluis/policy.md`,
  `docs/design/trust.md`.

## v0.9.6

- **One question to the directory per token, not four.** Every claim a
  token carries comes from one answer, and the code was asking for it up
  to four times over one exchange — the hub call behind it being the
  issuer's hottest. Asking twice is not only two round trips where the
  design counted on one; it is two answers that can disagree, with the
  grants from before a change and the name from after.

## v0.9.5

- **An ID token names who signed in.** It carried no `sub` at all, which
  makes it invalid, and no `email`, `name` or `groups` either. Every
  client asserts userinfo claims in its ID token, so the library
  assembles one from this storage and assigns the result **wholesale** —
  and the hook it assembles from was empty here, deprecated in favour of
  the one the userinfo *endpoint* uses. Supplying nothing did not leave
  the ID token's own claims alone; it overwrote them. A relying party
  that reads the ID token rather than calling userinfo — ArgoCD and Kargo
  both do — saw nobody.
- **A token says which session it belongs to, and when the person signed
  in.** `sid` is the session id the console lists and revokes, so a
  relying party can say WHICH of a person's sessions it holds rather than
  only that it holds one; a token no session backs, such as a workload's,
  carries none rather than an empty one. `auth_time` is the sign-in, not
  the minting: a refresh an hour later carries the same `auth_time` and a
  fresh `iat`, and that difference is the whole of what a
  "re-authenticate for this action" rule reads. Both are identity;
  `groups` still decides.
- **A session remembers the scopes it was granted.** It did not, and a
  refresh arrives carrying a token and nothing else — so the answer to
  "what may this session ask for" was *nothing*. Two consequences, both
  live: a refresh naming any scope at all was refused as though it had
  asked for more than it held, and one naming none minted an ID token
  the library assembled from an empty scope set. A session recorded
  before this release has no scopes and behaves exactly as they all did.

## v0.9.4

- **The issuer answers what sessions it is holding, and ends them.**
  `SessionService` (`ListSessions`, `RevokeSessions`) over the shared
  index, served only when `console.origin` names the one browser origin
  allowed to call it. It can only ever **remove**: no call here grants
  anything, which is what makes it safe to point a console at. Your own
  sessions are yours to list and end; somebody else's need an operator;
  listing a client names everybody on it, so that is an operator's too.
  A request that narrows to neither an identity nor a client is refused —
  "everything" names every person signed in. A session id alone is never
  enough to end somebody else's, and a mismatch answers exactly as an
  absent session does, so an id cannot be probed.
- **A token names the person, not only the address.** `ResolveUser`
  carries the account's given and family names (additive fields 7 and 8),
  the issuer puts them in `userinfo` and the ID token as `name`,
  `given_name`, `family_name` and `preferred_username`, and a relying
  party's UI shows somebody rather than an address — which is what ArgoCD
  and Kargo render after a cutover. Identity, never authorization:
  `groups` decides, as before, and every one of these is absent for a
  workload or a recovery sign-in, which have no names to give. A **held**
  answer carries the last known grants and no names: the hold window
  exists for authorization, and a name recovered from memory would be a
  claim the issuer cannot currently vouch for.

## v0.9.3

- **Every grant is named `<scope>:<thing>:<role>`.** The hub's own two
  roles are `all:access-roster:operator` and `…:viewer`; a role over one
  directory is `<workspace id>:access-roster:<role>`, the scope in the
  first position like every other name, where it used to be an `@`
  suffix. `policy.ScopedGroup` and `SplitScopedGroup` follow, and the
  loader **warns** at start on a name that is neither a grant nor one of
  the two families that deliberately are not grants (`rung:<name>`,
  `emp:<slug>`) — a convention is worth saying out loud where an operator
  sees it, and worth not refusing, since an installation mid-rename holds
  both shapes at once. The demonstration policy is written in the shape
  it documents. **This must be pinned in the same window as the
  installation's own policy rename**, or the console stops recognising
  its operators.
- **Docs: the naming rule.** Every grant is `<scope>:<thing>:<role>` —
  `prod:k8s:admin`, `prod:shop:deployer`, `all:access-roster:operator`
  — with `rung:` and `emp:` the only two-segment families and neither a
  grant. The reasoning is in `docs/design/trust.md`.

## v0.9.2

- **A GitHub Actions workflow can prove what it is.** `verify.GitHub`
  turns a workflow identity token into a proof carrying repository, owner,
  ref, workflow and environment — the five things a `github:` matcher pins
  a job to — so CI can trade its token for one of this issuer's. Two
  settings are the trust boundary, not tuning: `github.owners` (anybody
  may run a workflow in their own repository and get a valid token, so the
  owner allow-list is the whole of what makes one of them ours — empty
  verifies nothing) and the audience, which is this issuer's URL and is
  not configurable, so a token minted for a cloud provider cannot be
  replayed here. A token from another issuer comes back *unrecognised* so
  the next verifier may try it; one this verifier owns and refuses is
  final.
- **The session index is shared, not per-process.** It answered from
  whatever one replica happened to record: a listing was arbitrary rather
  than wrong, and a revocation reported success while the session went on
  working at the pod next door — the worst failure available to a control
  whose whole job is to end access. It now lives in the same store as the
  logins in progress. Sets make it findable, the record's TTL is the whole
  of expiry, and a listing repairs the sets it walks. A refresh token is
  hashed into its key rather than written into the keyspace: an index that
  can be read must not be an index that can be replayed.
- **The rule under everything is written down.** `docs/design/trust.md`:
  a service trusts exactly two anchors — the cluster for a workload next
  door, the issuer for everything further away — chosen by scope, never
  a third; `groups` is the one vocabulary; recovery is the cluster anchor
  used as the floor; a service with a console and an API has two
  listeners. `docs/connect/service-to-service.md` is the how-to. Every
  connect guide names its anchor; the policy examples use the built
  syntax (`clients:` with `signed_out`, `github.owners`) instead of the
  design-era one.

## v0.9.0

- **Sign out ends the sign-in, not just the cookie.** Clearing the
  proxy's session cookie ends the session with one application; the
  issuer still holds the person's sign-in, so the next click — that
  console or any other behind the same issuer — admits them again with no
  password. The screen said signed out and they were not, which is the
  one failure a person cannot see. `access.signOutThroughIssuer` now
  renders both halves (proxy sign-out → the issuer's RP-initiated logout
  → back to the console's front page), and refuses to render half a chain.
  A client's landing pages are a new `signed_out` list in the policy,
  separate from `redirects`: a redirect URI *starts* a sign-in, so landing
  there after signing out begins the login just ended — and listing one
  address as both now fails the load.

## v0.8.6

- **A policy change is a rollout, not a reload.** The declared layer is
  read once at start, and the hub's Deployment carried no checksum of it:
  the ConfigMap changed, kubelet wrote the file a minute later, and every
  replica went on answering from the policy it booted with — a grant
  visible in git, in the ConfigMap and in ArgoCD's *Synced*, and nowhere
  in the running service. Seen live rolling out the derived policy.
  The issuer has carried `checksum/policy` since its first
  release; the hub reads the same file the same way and now does too, and
  `just chart-lint` fails either chart that loses it.
- The console's account block is three lines — name, address, roles —
  with the roles held over a single directory named beside the
  installation-wide one.

## v0.8.5

- **A person's page reads down the column.** The 300px rail was carrying
  the two longest things on the page — every directory group the person
  is in, and the JSON a token would carry — so on a real directory they
  had to be read sideways while the main column ended halfway down. Both
  now sit in the main column, in the order the page already reads; the
  rail keeps the seven short facts, which is what a rail is for.

## v0.8.4

- **A probe retries what it could not ask, and not what was refused.**
  One transient `503` from Google's `domains.list` — seen live, during a
  rollout — flipped a directory whose credential is fine to *failing*,
  and with 0.8.0's reasons attached it told the operator its domains were
  *provisional — probe failed*. A directory that answers 503 has said
  nothing about the credential; one that answers 403 has. Backends now
  mark the first kind `ErrUnavailable`, the hub retries only that, and a
  revoked credential still surfaces on the first attempt.

## v0.8.3

- **React 19**, and the console bundle rebuilt on it. The major itself was
  a deliberate, human-merged update; what a bot cannot do is rebuild what
  `package.json` produces, so the repository declared 19 and carried a
  bundle built against 18. `frontend/dist` is embedded in the binary and
  `ts/dist` is what a git-tag install gets, so a stale one ships a console
  nobody's manifest describes. CI now runs `console` and both bundle
  recipes fail when a fresh build differs from what is committed.
- An empty **Directories** page offers the action it names, instead of
  saying "Add one to start serving its domains" with the only control in
  the page header.
- The connect runbook says what an unpublished consent screen actually
  does: in Testing it admits only listed test users, so the first tenant
  connects and the next company's administrator is refused before the
  request reaches the hub — with the seven-day refresh-token expiry as
  the half that bites later.

## v0.8.2

- **Sign-out ends the session that actually signed you in.** Behind a
  proxy the console's sign-out cleared this hub's own cookie — which
  nothing was using, because the proxy holds the session and forwards a
  bearer. So sign-out did nothing, and it landed on a sign-in page with
  no way in, this hub's own sign-in being off by design. `access.signOutURL`
  names the proxy's own sign-out, the console navigates to it rather than
  POSTing (a redirect a fetch would swallow), and the login page now says
  where the door is instead of showing an empty card.
- **A page waiting for a first snapshot fills in when it lands.** The
  first snapshot runs detached, so a directory's page opens on a
  workspace with nothing in it and used to stay that way — a photograph
  of the first two hundred milliseconds, while the read it was waiting
  for finished five seconds later behind it. The directory and Overview
  pages now say the first snapshot is running and refresh themselves
  until it is not.

## v0.8.1

- **A probe cancelled by the hub's own shutdown is no longer written down
  as a probe that failed.** Seen on the 0.8.0 rollout: the pod stopped
  mid-probe, the token request returned `context canceled`, and that
  became the workspace's health — so a directory whose credential is
  fine showed as failing, and its domains as *provisional — probe
  failed*, until the next pass. A probe that did not happen is not a
  probe that failed.

## v0.8.0

Everything the first live connect exposed, and the two choices it showed
the console was making for the operator.

- **A request never waits on the directory.** The first snapshot ran
  inside the consent callback and met the gateway's fifteen-second route
  timeout: a 502 for a workspace that had already been stored. A console
  listing with no snapshot read the directory under the request's own
  context. Narrowing refreshed before returning. All three now run
  detached; a read that did not ask for freshness never fetches; and
  narrowing excludes from what is already in memory, so it does not
  depend on a read succeeding.
- **The store is the truth and the reader map is a cache of it.** With
  two replicas, a workspace connected on one was "not found" on the other
  until it restarted. A miss now opens the workspace from the credential
  stored beside the record.
- **Group members are read with bounded concurrency** — eight in flight,
  atomic, in the directory's order — and every pass logs how long it took.
- **`hold` is now `provisional`, and says why**: first snapshot, stale,
  probe failed, contested. The Overview also counted *unserved* domains
  as held, which is how one record read "0/7 served, 7 on hold" on one
  page and "six not served, one hold" on another.
- **A connect asks which domains to serve**, with the consenting
  administrator's own domain pre-selected, instead of quietly serving all
  seven a tenant happened to own. "All of them, including ones added
  later" is still the empty list — now chosen rather than defaulted into.
  And a **reconnect keeps the answer**: it brings a new credential, not a
  new configuration.
- **An operator chooses which groups to sync.** `Workspace.SyncGroups`
  existed and was wired to nothing — not the refresh, not either store,
  not the contract, not the console, and `clone` did not even copy it.
- **The setup panel names the redirect URIs where each flow lands.** With
  one shared OAuth client the sign-in returns to the *issuer*, not here,
  so an operator was registering a URI nothing returns to. And the client
  is checked before an administrator is sent to spend a real consent on
  one the provider will refuse.
- **A role may be held over one workspace** (`hub-operators@C0example`),
  so connecting a second company's directory does not hand its
  administrator the first one. Recovery stays installation-wide by
  construction.

## v0.7.2

- **A consent that fails says so on a page.** The callback answered 502
  and the CDN in front of the console replaced it with its own "Bad
  gateway" — six kilobytes of Cloudflare HTML in place of the line naming
  the exact Google project and the exact API to enable. The diagnosis
  survived only in the log, which is the one place the person who could
  act on it was not looking. Every browser-facing outcome of the consent
  callback now renders a page in the console's own style, carrying what
  the directory said verbatim and the usual causes in order of
  likelihood, and none of them answers 5xx. A test asserts that.

## v0.7.1

- **The customer id is read from the admin's own user record.** `Tenant`
  called `Customers.Get`, which needs a *fifth* scope,
  `admin.directory.customer.readonly`, that is not among the four the hub
  asks for. Google granted the consent and the first read then failed with
  `Request had insufficient authentication scopes` — naming no scope, and
  arriving as a 502 on the callback. A `User` carries `customerId` and is
  covered by the user scope already granted, so the id is free and no
  administrator has to consent again.

## v0.7.0

- **The consent callback takes its operator from the signed state.** It is
  a redirect from Google and it lands on the bootstrap route — the one
  that exists precisely so a callback is not swallowed by a login prompt,
  which means the gateway adds no identity to it. Insisting on an identity
  in that request refused the one flow the route exists to finish: a live
  403, `this needs the operator role`, on the first workspace anyone tried
  to connect. The authorisation still happens where it always did, when an
  operator asks for the consent; the state now carries the answer, signed
  by the hub and pinned to the browser by the cookie the callback already
  checked. `docs/reference/sluis/configuration.md` had described this shape all
  along.
- `Identity.Who()` — the address where there is one, the subject where
  there is not. A recovery sign-in completes as a ServiceAccount and has
  no address, so `ConnectedBy` recorded a blank for exactly the sign-in
  whose actions most need a name against them.
- Dependencies: typescript 7, vite 8 with @vitejs/plugin-react 6, MUI 9.4,
  vitest 5. React stays on 18.

## v0.6.4

- **access-proxy writes `weight` out on every `backendRefs` entry.** The
  API server defaults it, ArgoCD normalises core-API defaults but not
  CRDs, and the child Application was therefore permanently OutOfSync —
  the third field in this family after the route's `matches` and
  `certificateRefs.group`, and the only chart of the three that had not
  learnt it. The lint now counts one `weight` per backend.

## v0.6.3

- **The gateway now sends the proxy the session cookie.** An HTTP
  ext_authz service is sent only `Host`, `Method`, `Path`,
  `Content-Length` and `Authorization` unless the `SecurityPolicy` says
  otherwise, so the proxy answered every check without ever seeing the
  cookie it had just written: sign-in completed, the callback returned
  its 302, and the next request began a fresh login — forever. The chart
  names `cookie` itself and will not let a value take it away; the lint
  asserts every rendered policy carries it.

## v0.6.2

- A recovered sign-in has no email address. It completes as a
  ServiceAccount **subject** and is carried as one end to end, instead of
  failing where an address was assumed.

## v0.6.1

- The issuer reads a confidential client's secret. It was constructed
  with no resolver at all, so every confidential client got
  `invalid_client`.

## v0.6.0

- **Recovery sign-in**, so a first installation can be bootstrapped:
  a ServiceAccount token checked by the API server against a mandatory
  audience. It stores no credential and grants nothing by itself — the
  policy's `service_account` matchers decide what it is in.

## v0.5.0

- A bootstrap surface on the hub the gateway does not cover, so the
  console that connects the first directory is reachable before any
  directory exists.

## v0.4.3

- `certificateRefs.group` written out — the last Gateway API field the
  API server defaulted and ArgoCD would not normalise, which left the
  child Application permanently OutOfSync and gated every later wave.

## v0.4.2

- The HTTPRoute path match written out, for the same reason.

## v0.4.1

- Several protected routes on one host, each with its own posture — the
  shape a surface needs where a demo path is open to any employee and the
  application behind it is not.

## v0.4.0

- **The access-proxy chart is published.** oauth2-proxy, a Valkey session
  store and the Gateway API resources that put them in front of one
  console, for applications that cannot run the code flow themselves.

## v0.3.0

- The hub verifies the gateway's forwarded token against the issuer's
  keys instead of trusting a header.

## v0.2.0

- **The TypeScript package exists.** `@truvity/access-roster`, installed
  from git at a tag with `ts/dist` committed so it needs no toolchain and
  no registry: `fetchIdentity`, `useIdentity()` and `<UserBadge>`, with
  react and MUI as optional peers. It parses no token — the browser asks
  the application it is already talking to. Its reference page described
  three states and the endpoint's real shape had different fields; both
  now match what is served, and there is a **fourth state**, `unknown`,
  for when the question could not be asked. A console that showed a
  sign-in button because one request failed would send a signed-in person
  to authenticate again for nothing.
- **Revocation always reaches the shared state.** It took a hit in the
  per-process session index as proof that revocation was done and
  returned — so a token revoked on the replica that happened to hold the
  session stayed valid at every replica, including that one. Both now
  happen, always, in that order.

## v0.1.0

The first release: enough to stand the hub up on a cluster, connect the
companies it serves, and let people in. The issuer is here and runnable
but has not carried a relying party yet.

**Not in it**, though the reference documents describe them: the
TypeScript package (`docs/reference/typescript.md`) and most of the Go
module for consoles (`docs/reference/go-module.md` — `identity`,
`authz`, `directory`, `tokens`). What a `go get` at this tag gets is the
policy engine and the backend interface. Both libraries belong to the
work that replaces gateway-auth, and nothing in the hub's rollout needs
them.

This section describes what is in the release, not the order it arrived
in.

- **directory-roster**, the directory hub: workspaces whose domains are
  discovered, snapshots with the freshness policy (`max_age`, the
  cheapest path, an in-domain miss that always checks live once), routing
  by email domain with conflict detection, and the authority rule that
  makes everything degrade to a hold rather than to "gone".
- **Served domains**: a workspace may be narrowed to a subset of the
  domains its tenant owns — `workspaces[].serve` in the values, or
  *Choose which to serve* on a connected directory's page. What is left
  out is discovered and shown but routes nothing and is not cached, only
  two workspaces that both serve a domain contest it, and the list is
  intersected with discovery so a domain moving between tenants hands
  over without an edit.
- **DirectoryService** over ConnectRPC for consumers, authenticated by
  Kubernetes ServiceAccount tokens; the operator services, the login
  routes, the consent callback and `/.access/whoami` on a second
  listener.
- **Connecting a real Google Workspace**, both ways in: admin consent
  (offline access, a forced consent screen so a reconnect really returns a
  refresh token, and the consenting account read from the id token) and an
  uploaded service-account key. Disconnecting hands the refresh token back
  to Google.
- **Nothing is lost on restart.** What a console changed — connected
  workspaces, their credentials, the memberships, the OAuth client, the
  session key and the break-glass password — is kept as plain ConfigMaps
  and Secrets in the hub's own namespace, written and read by the hub
  itself. `STORE=memory` keeps nothing and says so at WARN; the chart
  always sets `kubernetes`. At start, a declaration removed from the
  values takes its record with it, and a credential that cannot be read
  leaves one workspace unhealthy rather than stopping the hub.
- **Snapshots shared across replicas**, in Valkey: one copy of each
  directory, gzipped, with the reverse index rebuilt on read rather than
  stored. The refresh lease is held for the whole interval rather than for
  the work, so replicas that tick at different moments still read a
  directory once per interval — a quota is per tenant, not per reader —
  while a failed pass hands its lease straight back. No address configured
  keeps snapshots in memory, which the hub says at start.
- **Nothing untrusted reaches a log line unsanitised.** Addresses,
  request paths and the errors built from them now pass through
  `internal/logsafe`, which removes what a reader or a parser would take
  for the end of a record. Structured handlers escaped these already —
  none of it was forgeable in practice — but it is now true by
  construction rather than by the handler's choice, and named where it can
  be seen. The address stays in the line: an audit record that does not
  say who was refused is not one.
- **A login in progress is shared across replicas.** The authorization
  request, the code, the tokens and the device flow were four maps in one
  process — so a browser that started at `/authorize` on one replica and
  came back from the provider at another found nothing, and a terminal
  polling the device endpoint reached whichever pod answered. All four now
  live in Valkey when one is configured, each carrying its own expiry so
  nothing sweeps, with the user code claimed by a single atomic write
  because two replicas minting the same short code must not both believe
  they own it. Memory remains the default and says so at start.
- **The release publishes both services.** `.goreleaser.yaml` was missing
  entirely — the workflow would have failed at its GoReleaser step on the
  first tag ever cut. It now builds the hub, the issuer and the acceptance
  binary for linux and darwin on both architectures, publishes two images
  under `ghcr.io/truvity/access-roster/`, and stamps the git tag into each
  binary's version. `just release-check` validates it without cutting one.
- **access-issuer has a chart**, so the release has both to publish: the
  Deployment, the TokenReview permission the exchange needs, the policy
  ConfigMap, the route, and the cert-manager `Certificate` that produces
  the signing key with `rotationPolicy: Always` — a renewal has to be a
  new key, because a renewed certificate over the same key rotates
  nothing. `issuerURL` and `hub.address` fail the *render* when unset,
  rather than the pod.
- **People can sign in to the issuer.** `/login` is the chooser the
  library sends a browser to, `/login/<provider>/start` and `/callback`
  are the round trip, and `/signed-out` is where a logout lands. One
  button per provider kind, never one per company; with one provider it
  redirects rather than asking a question with one answer. The address is
  all that is taken from the provider — the hub decides whether it is
  anybody here, and refuses on that page, naming the address, because
  everywhere downstream the person would just be admitted nowhere. The
  half-finished request travels in signed state, so a callback cannot
  finish somebody else's login, and that state's key is derived from the
  signing key rather than being a second Secret to provision.
- **The issuer's signing key is provisioned, not minted.** It reads a PEM
  a Secret carries — cert-manager issuing one, external-secrets delivering
  one — mounted as a file, and holds no permission to read Secrets at all.
  A service that creates its own credential is an exception to how every
  other credential here is provisioned. The key id is now the key's own
  RFC 7638 thumbprint rather than a name travelling beside it, which is
  what lets the key arrive from anywhere and makes rotation a matter of a
  new key having a new id.
- **access-issuer is a service.** `cmd/access-issuer` and
  `internal/issuerapp` assemble it from the environment — policy, the door
  to the hub, the signing key, the verifiers — and serve discovery, the
  JWKS, the code flow, exchange, revocation and the device flow, with
  health beside them. It refuses to start without an issuer URL, because
  that string is baked into every token and every relying party's trust
  and a default would be a value nobody chose spread across an estate.
- **Discovery stopped advertising the implicit grant.** `response_types`
  was already corrected; `grant_types_supported` was not, and a relying
  party reads that one and picks — offered implicit, a library uses it,
  and the refusal arrives in a browser redirect where nobody sees why.
- **The chart has been installed and run**, in kind, with the real
  Kubernetes store and token recovery: two replicas, recovery by a minted
  token straight into the console, the API listener admitting the declared
  consumer and refusing every other identity, and no standing credential
  anywhere in the namespace. The first attempt would not start at all —
  the rendered policy carried no `version`, so the loader refused it. The
  version belongs to the chart now, not to the values.
- **An acceptance suite against a real API server** (`just acceptance`, a
  throwaway kind cluster). It covers the three things a fake clientset is
  silent about and the hub leans on: name validation, a create that raced
  another — now handled rather than failed — and TokenReview, which is
  what recovery and the API listener's guard are made of. Running it
  showed that the audience is enforced by *asking* for it: a token minted
  for another audience comes back not authenticated at all.
- **The wiring is testable.** Everything `main()` decided moved to
  `internal/app`, with an acceptance suite that boots a whole hub from the
  environment and walks the use cases over the real handlers, and a test
  that compares every variable the binary reads against every one the
  chart sets — reading both from the source, because the five settings
  that were read and never set were exactly the kind of thing a restated
  list gets wrong.
- **The hub's own sign-in is a switch** (`access.login.directory`), and
  turning it off closes the routes rather than hiding the buttons —
  connecting a directory is unaffected, because an operator granting this
  hub access is not a way in. The external-OIDC login the values gestured
  at is **removed** rather than built: an installation that has an issuer
  has access-proxy in front of it, and the proxy's forwarded identity is
  that path.
- **Four chart values that did nothing now do something.** `PUBLIC_URL`
  was never set, so a deployed hub built both OAuth redirect URIs — and
  the values its setup steps tell an operator to paste — from
  `http://localhost:8081`; it now comes from `route.host`, and the session
  cookie is marked Secure with it. The forwarded-identity path a console
  behind the fleet's gateway has been documented as using was never
  rendered either; it now is, with the header name as a value. Session
  lifetime and log level joined them.
- **The API listener authenticates its callers.** It was open: anything
  that could reach the port got every account and group of every company
  the hub serves. Callers now present a projected ServiceAccount token
  with the hub's audience, verified by TokenReview against the declared
  `consumers`. A deployment declaring none admits nobody; outside a
  cluster there is nothing to verify against, so it stays open and the
  process says so at start.
- **Signing in with a directory works.** `GET /login/<backend>/start` →
  `/callback` asks the provider for `openid email profile` and nothing
  else: the address is all that is taken from it, and whether the account
  is live, which company it belongs to and what it may do are answered by
  the directory this hub already reads. An address in no served domain is
  refused at the door rather than given a session with no role, while a
  person of a served company who is in no group signs in fine — their own
  page explains what they have. One button per directory *kind* on the
  sign-in page, never one per company, which would publish the tenant list
  to anyone who loads it. The OAuth client now needs **two** redirect
  URIs, and the setup step shows both.
- **Recovery replaces the break-glass account.** In a cluster the hub
  stores no credential at all: recovery is a ServiceAccount token minted
  for one audience and a few minutes, checked with a TokenReview, so the
  authority is the cluster's own RBAC — revocable by removing a binding,
  recorded in the cluster's audit log, and naming who recovered rather
  than "admin". Whoever could read a stored break-glass Secret already had
  cluster access, so the secret was only ever converting that access into
  a session; this does it directly. Outside a cluster a password is
  generated and printed once, kept as an Argon2id digest with a random
  salt, serialised, and silent for a minute after ten failures — the
  correct one included, so the limit says nothing about which guess was
  close. Only that shape is a standing credential, so only it gets a
  warning and a "turn it off" setup step. `POST /admin/login` becomes
  `POST /login/recovery`.
- The forwarded identity header is now required to be an address before it
  is taken as a principal; the consent cookie is cleared with the same
  attributes it was set with.
- **The policy** (`docs/reference/sluis/policy.md`): five tables — groups,
  claims, lifetimes, clients, memberships — one schema for both services,
  deep merge with a load-time scalar-conflict check, shortest lifetime,
  layered loading, memberships the only console-writable table, clients
  declared or self-registered and never created in a console. The hub is
  a relying party of it: `hub-operators` and `hub-viewers`.
- **The issuer design, completed on sessions and standards**: sessions
  are first-class issuer state, listable per identity and client and
  revocable, which gives the console its second write — Revoke, and
  "sign out everywhere" for oneself — and the operator a lever between
  the proxy's sign-out and the next refused refresh. The standards table
  names what is in (Core code+PKCE, Discovery, RP-Initiated Logout as the
  conformance target; device, token exchange, JWT profile, client
  credentials, revocation, dynamic registration, JWT access tokens) and
  what is deliberately out (introspection, implicit and hybrid, back-
  channel logout for 1.0, the session iframe, PAR, DPoP, mTLS, CIBA), on
  `zitadel/oidc/v3`, with the OpenID conformance suite as the spike's
  seventh item.
- **The console** on the fleet stack, organised as the graph the content
  actually is rather than as a set of tables: search on every page, an
  overview that answers whether anything is broken, and a page per
  tenant, group, client and person, each carrying its edges in both
  directions. Every name is a link, every page opens with a
  plain-language summary, and actions live on the object they change.
  The navigation is two clusters, identity and access, with one adjective
  each — directory groups and internal groups — and a page at every level
  of both: a directory group's page mirrors an internal group's, and the
  membership that joins them is editable from either end. A person's page
  is the chain, one row per internal group held. Matchers lists every
  declared rule — the identity side's second way in, by shape rather than
  by membership — and keeps the proof simulator for a CI job or a
  workload, because a run exists only while it runs. A client's page
  lists the machines that reach it beside the people. People filters by
  directory and by whether an account is live. **Add a directory** offers both ways in and only
  the ways the deployment can take. The visual layer follows Material's
  guidance for a console: a navigation rail with the two sides as groups
  and a header kept for search and identity, a denser lowercase theme,
  and one meaning per form — names are links, chips are states, facts are
  a label over a value, and two-column data is a list. The account sits at
  the foot of the rail with your name linking to your own page, which
  also says how you signed in; detail pages split into a main column and
  an aside on wide windows, so a person's chain fits a screen. The
  contract was tightened for it: `Explain` names the directory that
  served the address, `SearchPeople` reports the total before the limit,
  and `GetPolicy` carries matchers only in structured form.
- **The Google backend**, which is the first real directory the hub can
  read: the Admin SDK over a service-account key with domain-wide
  delegation, discovering the customer id and every verified domain,
  listing accounts and groups with their flat membership, and answering
  one address at a time. Archived counts as not live beside suspended.
  Unverified domains are not served, because a domain anyone may claim in
  a console is not evidence of anything. The credential type is pinned to
  a service-account key, since a credentials file may also name an
  external account that fetches its token from a URL the file itself
  carries. The console's setup guidance now reads its scope list from the
  backend rather than repeating it.
- **Declared workspaces are read at start**, which the chart had shipped
  the configuration for and no code had read. The tenant id became
  optional — the credential opens one tenant and it knows its own id — and
  supplying it turns adoption into a check that refuses a credential
  opening a different tenant. A declared workspace that cannot be adopted
  stops the process rather than leaving a hub that silently serves less
  than it was configured to. The chart renders the Gateway, HTTPRoute and
  Certificate for the console host it had always claimed to.
- **Day one leads itself.** Overview carries what a fresh installation
  still has to do, with that installation's own redirect URI and scopes to
  copy rather than a document's placeholders, and each step disappears as
  it completes. The break-glass account's default is computed rather than
  fixed: it stays off when the values already declare a workspace and a
  non-empty `hub-operators`, because such a deployment signs in through
  the directory from its first boot and a password nobody needs is a
  standing credential. `GetSettings` reports the setup values.
- **A demonstration mode** (`DEMO=1`): two tenants in memory and a
  consent connector, so every use-case is walkable before a credential
  exists.
- **The documentation set**: why it exists, the concepts, the fifteen
  integration points, the architecture, a design per battery, the
  reference pages, one connect guide per kind of relying party, the
  operations runbooks and the extension points.

Designed but not built: access-issuer, access-proxy, the libraries as a
public module, accessctl and the GitHub Action.
