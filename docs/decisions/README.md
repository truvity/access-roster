# Architecture decisions

One record per decision that shapes this repository from the outside —
what a relying party must do, what an installation must accept, what a
release removes. The pages under [`concepts/sluis/`](../concepts/sluis/architecture.md) say
how the shipped thing works; a record here says why it is shaped that
way, what was weighed against it, and what follows from choosing it. When
the two disagree, the explanation pages describe what actually shipped and a
record here is read as the reasoning that got there.

A record is never edited to reverse a decision. A changed mind gets a new
record that supersedes the old one, so the index below stays a true
timeline and nothing is silently rewritten under an old date. The old record's
**Status** line (and the Status column below) is changed to say what overtook
it, so a reader of one record does not need to know another exists; its body
is not edited.

## Index

<!-- generated: adr-index -->

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-sessions-and-an-absolute-limit.md) | Sessions and an absolute limit | Accepted; amended by [0033](0033-a-longer-absolute-limit-for-read-only-resources.md) and [0040](0040-agent-class-sessions.md) |
| [0002](0002-mission-boundary-tokens-and-memberships.md) | Mission boundary: tokens and memberships | Accepted; partly superseded by [0008](0008-credentials-only-where-we-govern-membership.md) and, for `sluisctl credential db`/`client` specifically, by [0013](0013-openbao-access-through-the-bao-cli.md); its "next candidate, a chat workspace's channel membership" was built as the Slack reconciler, see [0017](0017-the-slack-reconciler-membership-only.md) |
| [0003](0003-deprecate-access-proxy.md) | Deprecate and remove the access-proxy chart | Accepted; carried out in v1.32.0 (the chart is removed; the recipe for running upstream oauth2-proxy on another gateway lives in [how-to/connect/oauth2-proxy.md](../guides/sluis/connect/oauth2-proxy.md)) |
| [0004](0004-ssh-opkssh-and-the-secret-stores-ca.md) | SSH: opkssh for people, the secret store's SSH CA for hosts | Accepted; partly superseded by [0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md) (machines and hosts move to the secret store); refined by [0015](0015-a-per-audience-groups-delimiter-for-opkssh.md) |
| [0005](0005-es384-signing-algorithm.md) | ES384 is the signing algorithm | Accepted; partly superseded by [0009](0009-a-default-signing-algorithm-and-per-audience-exceptions.md) (ES384 stays the default; it is no longer the only algorithm an audience may have) |
| [0006](0006-groups-claim-scoped-per-audience.md) | The groups claim is scoped per audience, by default | Accepted; the scoping rule is refined by [0010](0010-a-declared-vocabulary.md) |
| [0007](0007-breaking-changes-inside-1x.md) | Breaking changes inside 1.x | Accepted; extended by [0036](0036-configuration-is-immutable-per-instance.md) |
| [0008](0008-credentials-only-where-we-govern-membership.md) | Credentials only where we govern membership | Accepted; supersedes [0002](0002-mission-boundary-tokens-and-memberships.md) in part; refined by [0014](0014-minting-third-party-credentials-only-where-membership-is-governed.md); applied to Slack by [0025](0025-slack-apps-catalogue-keeps-credentials-mints-none.md) |
| [0009](0009-a-default-signing-algorithm-and-per-audience-exceptions.md) | A default signing algorithm, and per-audience exceptions | Accepted; partly supersedes [0005](0005-es384-signing-algorithm.md) |
| [0010](0010-a-declared-vocabulary.md) | A declared vocabulary: things, scopes, roles, inheritance and mapping wildcards | Accepted; extended by [0012](0012-per-role-scopes-in-the-vocabulary.md) |
| [0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md) | SSH: people on opkssh, machines and hosts on the secret store's OpenBAO | Accepted; amended by [0013](0013-openbao-access-through-the-bao-cli.md) (the machine path is now `sluisctl bao ssh -mode=ca` / `sluisctl bao write ... sign/<role>`, not a dedicated `sluisctl credential ssh`); refined by [0015](0015-a-per-audience-groups-delimiter-for-opkssh.md), [0016](0016-a-managed-known-hosts-file-for-ssh-host-cas.md) |
| [0012](0012-per-role-scopes-in-the-vocabulary.md) | Per-role scopes in the vocabulary | Accepted; extends [0010](0010-a-declared-vocabulary.md) |
| [0013](0013-openbao-access-through-the-bao-cli.md) | OpenBAO access through the `bao` CLI | Accepted; refines [0002](0002-mission-boundary-tokens-and-memberships.md), amends [0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md) |
| [0014](0014-minting-third-party-credentials-only-where-membership-is-governed.md) | Minting third-party credentials: only where membership is governed, brokers elsewhere | Accepted; refines [0008](0008-credentials-only-where-we-govern-membership.md) |
| [0015](0015-a-per-audience-groups-delimiter-for-opkssh.md) | A per-audience groups delimiter, for opkssh's colon-splitting bug | Accepted; refines [0004](0004-ssh-opkssh-and-the-secret-stores-ca.md) and [0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md) |
| [0016](0016-a-managed-known-hosts-file-for-ssh-host-cas.md) | A managed known_hosts file for SSH host CAs, distinct from `sluisctl bao` | Accepted; refines [0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md), distinguishes from [0013](0013-openbao-access-through-the-bao-cli.md) |
| [0017](0017-the-slack-reconciler-membership-only.md) | The Slack reconciler keeps channel membership and nothing else | Accepted; applies [0002](0002-mission-boundary-tokens-and-memberships.md) |
| [0018](0018-do-not-configure-what-the-product-knows.md) | Do not configure what the product already knows | Accepted; applies [0007](0007-breaking-changes-inside-1x.md) |
| [0019](0019-two-kinds-of-slack-channel-never-mixed.md) | Two kinds of Slack channel, never mixed | Accepted; refines [0017](0017-the-slack-reconciler-membership-only.md) |
| [0020](0020-hold-on-double-definition-instead-of-taking-over.md) | A channel defined twice is held, not taken over | Accepted; refines [0019](0019-two-kinds-of-slack-channel-never-mixed.md) |
| [0021](0021-slack-connect-channels-are-console-records.md) | Slack Connect channels are console-managed, audited records | Accepted; refines [0019](0019-two-kinds-of-slack-channel-never-mixed.md) |
| [0022](0022-the-console-archives-only-ordinary-channels-only-when-asked.md) | The console archives only ordinary channels, only when asked | Accepted; refines [0017](0017-the-slack-reconciler-membership-only.md) |
| [0023](0023-guest-side-probe-only-for-managed-slack-connect-channels.md) | The guest-side probe asks only about managed Slack Connect channels | Accepted; refines [0021](0021-slack-connect-channels-are-console-records.md) |
| [0024](0024-reconciler-rails-are-shared-pieces-not-a-framework.md) | Reconciler rails are shared pieces, not a framework | Accepted |
| [0025](0025-slack-apps-catalogue-keeps-credentials-mints-none.md) | The Slack Apps catalogue keeps credentials but mints none | Accepted; applies [0008](0008-credentials-only-where-we-govern-membership.md) and [0014](0014-minting-third-party-credentials-only-where-membership-is-governed.md) |
| [0026](0026-two-platforms-permanently-kubernetes-and-aws-lambda.md) | Two platforms, permanently: Kubernetes and AWS Lambda | Accepted |
| [0027](0027-the-state-port-nats-jetstream-and-dynamodb.md) | The State port: NATS JetStream on Kubernetes, DynamoDB on AWS | Accepted; partly superseded (2026-10-04): the NATS JetStream half was removed, the DynamoDB half stands. It supersedes the store statement in [the store](../concepts/sluis/store.md) ("plain Kubernetes objects … no cloud parameter store, no cache") once the migration in [0031](0031-a-generic-migration-tool.md) has run |
| [0028](0028-nothing-writes-configmaps-or-secrets.md) | Nothing writes ConfigMaps or Secrets; written secrets are sealed | Accepted; partly superseded (2026-10-04): sealing is retired, the rule that nothing writes ConfigMaps or Secrets stands; extended by [0034](0034-exports-go-to-openbao-directly.md); amended by [0036](0036-configuration-is-immutable-per-instance.md) |
| [0029](0029-ticks-per-target-under-a-lease.md) | Ticks per target, under a lease | Accepted; applies [0024](0024-reconciler-rails-are-shared-pieces-not-a-framework.md) |
| [0030](0030-workload-identity-on-both-platforms.md) | Workload identity: both mechanisms on both platforms | Accepted; applies [0002](0002-mission-boundary-tokens-and-memberships.md) |
| [0031](0031-a-generic-migration-tool.md) | A generic migration tool, and the order of the move | Accepted; amended by [0036](0036-configuration-is-immutable-per-instance.md) |
| [0032](0032-one-configuration-file-one-binary-one-chart.md) | One configuration file, one binary, one chart | Accepted; applies [0007](0007-breaking-changes-inside-1x.md), [0018](0018-do-not-configure-what-the-product-knows.md); refined by [0036](0036-configuration-is-immutable-per-instance.md) |
| [0033](0033-a-longer-absolute-limit-for-read-only-resources.md) | A longer absolute limit for read-only resources | Accepted; amends [0001](0001-sessions-and-an-absolute-limit.md); amended by [0040](0040-agent-class-sessions.md) (the lengthening for read-only resources is deprecated) |
| [0034](0034-exports-go-to-openbao-directly.md) | Exports: the service copies its secrets into OpenBao itself | Accepted; amended by [0041](0041-the-secret-contract.md) (proposed): the export copies, their schedule and the recovery bundles are retired; extends [0028](0028-nothing-writes-configmaps-or-secrets.md) and supersedes the part of an estate's GitOps ADR-034 §9 that says the issuer never calls OpenBao and a PushSecret copies |
| [0035](0035-renamed-to-sluis.md) | Renamed to sluis | Accepted; its NATS-bucket and `sluis:binding` rows are moot since [0027](0027-the-state-port-nats-jetstream-and-dynamodb.md) and [0028](0028-nothing-writes-configmaps-or-secrets.md) removed NATS and sealing (2026-10-04); the kept contract names still stand |
| [0036](0036-configuration-is-immutable-per-instance.md) | Configuration and policy are immutable per instance; credentials and State are read live | Accepted; amended by [0037](0037-one-process-everywhere.md); amended by [0071](0071-least-privilege-modules-one-credential-holder-per-function.md) (immutable per execution environment; AppConfig on AWS); amended by [0041](0041-the-secret-contract.md) (proposed): layout v3 becomes v4; refined by [0038](0038-estates-render-through-sluis.md); refined by [0075](0075-recovery-is-turned-off-from-the-console-and-on-by-configuration.md) (a runtime decision kept in State that configuration overrides by naming a generation); follows up [0007](0007-breaking-changes-inside-1x.md) (the deferred deprecation window), refines [0032](0032-one-configuration-file-one-binary-one-chart.md), amends [0028](0028-nothing-writes-configmaps-or-secrets.md) and [0031](0031-a-generic-migration-tool.md) only where they name SSM paths or configuration documents |
| [0037](0037-one-process-everywhere.md) | One process everywhere: one Lambda function, one Deployment, one service document | Superseded by [0071](0071-least-privilege-modules-one-credential-holder-per-function.md) (2026-10-09); was: Accepted; refined by [0038](0038-estates-render-through-sluis.md); amends [0036](0036-configuration-is-immutable-per-instance.md) (three documents and three Deployments → one unified process) |
| [0038](0038-estates-render-through-sluis.md) | Estates render their documents through sluis | Accepted; refines [0036](0036-configuration-is-immutable-per-instance.md) (who writes the documents an instance is started with) and [0037](0037-one-process-everywhere.md) (one service document, one policy document) |
| [0039](0039-the-issuer-generates-confidential-client-secrets.md) | The issuer generates confidential client secrets | Accepted; amended by [0041](0041-the-secret-contract.md) (proposed): the secret and its previous value live at `external/oidc/<client>`; extends [0038](0038-estates-render-through-sluis.md) (what an estate declares for a client) and refines the client table of the policy document |
| [0040](0040-agent-class-sessions.md) | Agent-class sessions: a longer chain by client class, not by resource | Accepted; amends [0001](0001-sessions-and-an-absolute-limit.md) (agent-class chains are not held to the installation's absolute limit) and [0033](0033-a-longer-absolute-limit-for-read-only-resources.md) (its lengthening half is deprecated) |
| [0041](0041-the-secret-contract.md) | The secret contract: internal and external, one storage module, keys by purpose | Accepted (2026-10-08). Once carried out it amends [0034](0034-exports-go-to-openbao-directly.md) (the export copies, their schedule and the recovery bundles are retired), [0036](0036-configuration-is-immutable-per-instance.md) (layout v3 becomes v4) and [0039](0039-the-issuer-generates-confidential-client-secrets.md) (where a generated secret and its previous value live). Its companion [0042](0042-one-repository-one-release-train.md) moves audit into this repository and decides how audit is installed. |
| [0042](0042-one-repository-one-release-train.md) | One repository, one release train: audit moves into sluis and is installed by preset to destinations | Accepted (2026-10-08). Companion of [0041](0041-the-secret-contract.md), which decides secrets, storage, keys and deployment shapes for both products. |
| [0043](0043-record-schema-proto-with-json-schema-slots.md) | Record schema in Protocol Buffers with JSON Schema extension slots | accepted |
| [0044](0044-profiles-composed-from-framework-profiles.md) | Profiles composed from framework profiles, one copy per profile | accepted; the compliance bundle this record first called a preset is a *framework profile*, and the `profiles/` directory, the `frameworks:` key and the `profile` package carry that name (a *preset* is a named bundle of adapter or deployment choices, per truvity/policy decision 0012) |
| [0045](0045-s3-object-lock-as-the-record.md) | S3 Object Lock in compliance mode is the record; everything else is a projection | accepted; the object layout is superseded by [0060](0060-v1-bucket-layout.md), and retention is extended by [0065](0065-archive-retention-and-lifecycle.md) |
| [0046](0046-sink-interface-and-transports.md) | One sink interface at every hop; the queue is invisible | accepted; the delivery modes are superseded by [0054](0054-two-deliveries-and-a-durable-ack.md), itself superseded by [0059](0059-sink-durability-and-transports.md), which extends this |
| [0047](0047-identity-tiers-and-pseudonymisation.md) | Identity tiers and per-purpose pseudonymisation in the split writer | accepted |
| [0048](0048-search-contract.md) | Search contract: DNF typed predicates, cursor page object, tail cursor | accepted |
| [0049](0049-authentication-and-authorization-plug-points.md) | Pluggable authentication and authorization with declarative defaults | accepted |
| [0050](0050-digest-chain-and-verification.md) | Hourly signed digest chain and an auditor-run verify command | superseded by [0061](0061-seals.md) |
| [0051](0051-versioning-policy.md) | Versioning: package per major, major.minor on the record, decoders forever | accepted; refined by [0067](0067-configuration-is-immutable-per-instance.md) for configuration |
| [0052](0052-key-providers.md) | Key providers: local, OpenBAO transit and AWS KMS envelope, behind one interface | accepted; the default is `none` per [0055](0055-no-pseudonymisation-keys-by-default.md) |
| [0053](0053-one-installation-per-service-or-product.md) | One installation per service or product, in that application's namespace | accepted; refined by [0058](0058-three-parts-installed-independently.md) |
| [0054](0054-two-deliveries-and-a-durable-ack.md) | Two deliveries, and the receiver's acknowledgement means durable | superseded by [0059](0059-sink-durability-and-transports.md) |
| [0055](0055-no-pseudonymisation-keys-by-default.md) | No pseudonymisation keys by default | accepted; supersedes the default of [0052](0052-key-providers.md) |
| [0056](0056-lock-modes-and-store-tiers.md) | Lock modes and store tiers: the lock is demanded where a framework demands it | accepted; refined by [0068](0068-storage-is-configured-per-preset.md) (the lock is a property of the install preset's bucket, not a setting of the process) |
| [0057](0057-schema-ids-on-github-pages.md) | Schema identifiers on GitHub Pages, the old ones kept as aliases | accepted; the base moved to the sluis site by [0069](0069-schema-ids-move-to-the-sluis-site.md) |
| [0058](0058-three-parts-installed-independently.md) | Three parts, installed independently; the bucket layout is the contract | accepted; refines [0053](0053-one-installation-per-service-or-product.md) |
| [0059](0059-sink-durability-and-transports.md) | Sink durability: the acknowledgement says how durable, and the start-up refuses less | accepted; supersedes [0054](0054-two-deliveries-and-a-durable-ack.md) and extends [0046](0046-sink-interface-and-transports.md) |
| [0060](0060-v1-bucket-layout.md) | The v1 bucket layout, and v0 is dropped | accepted; supersedes the object layout of [0045](0045-s3-object-lock-as-the-record.md) |
| [0061](0061-seals.md) | Seals: JOSE ES384, chained, per profile, tenant and hour | accepted; supersedes [0050](0050-digest-chain-and-verification.md) |
| [0062](0062-observe-follows-the-bucket.md) | Observe follows the bucket by cursor; notifications only wake it | accepted |
| [0063](0063-one-validated-configuration-file.md) | One configuration file, validated against a schema | accepted; refined by [0067](0067-configuration-is-immutable-per-instance.md); the secret fields it names (`<field>Env`) are `<field>Secret` through `secrets.source` in configuration version 2 (truvity/policy decision 0012; [upgrade](../guides/audit/upgrade/v0.13.md)) |
| [0064](0064-contracts-proto-and-connect.md) | Contracts are proto and Connect; Lambda RPCs are unary | accepted |
| [0065](0065-archive-retention-and-lifecycle.md) | Archive retention: Object Lock compliance as the target, governance first | accepted; extends [0045](0045-s3-object-lock-as-the-record.md) and [0056](0056-lock-modes-and-store-tiers.md) |
| [0066](0066-indexer-and-query-are-separate-processes.md) | The indexer and the query service are separate processes, under separate database roles | accepted |
| [0067](0067-configuration-is-immutable-per-instance.md) | Configuration is immutable per instance; credentials and State are read live | accepted; refines [0063](0063-one-validated-configuration-file.md) and [0051](0051-versioning-policy.md) for configuration |
| [0068](0068-storage-is-configured-per-preset.md) | Storage is configured per install preset | accepted; refines [0056](0056-lock-modes-and-store-tiers.md) and [0065](0065-archive-retention-and-lifecycle.md) |
| [0069](0069-schema-ids-move-to-the-sluis-site.md) | Schema identifiers move to the sluis site, the audit Pages base kept as an alias | Accepted (2026-10-08). A consequence of [0042](0042-one-repository-one-release-train.md): audit's repository and its Pages site are retired. Amends [0057](0057-schema-ids-on-github-pages.md). |
| [0070](0070-cloudflare-tokens-and-r2-credentials-by-prototype-clone.md) | Cloudflare tokens and R2 credentials: sluis clones a disabled prototype token | Accepted (2026-10-08). Follows [0014](0014-minting-third-party-credentials-only-where-membership-is-governed.md) (a credential is minted only where membership is governed), stores its output under the contract of [0041](0041-the-secret-contract.md) and grants it to people and agents as [0040](0040-agent-class-sessions.md) sets out. |
| [0071](0071-least-privilege-modules-one-credential-holder-per-function.md) | Least-privilege modules: one function per credential holder, the signer inside the issuer and a binary per module | Accepted (2026-10-09); amended 2026-10-09 by [0072](0072-storage-layout-v5-module-first.md) (points 1, 3, 5, 8, 9 and 11: the signer and the console stay inside `sluis-issuer`; six binaries and seven functions; restore is a second deployment of the backup binary). Amended 2026-10-12 by [0073](0073-backup-format-2-age-encrypted-tar.md) (point 9: a backup is encrypted with age to public recipients, not under a KMS or OpenBao key). Supersedes [0037](0037-one-process-everywhere.md) (one process everywhere); amends [0036](0036-configuration-is-immutable-per-instance.md) (immutability moves from the instance to the execution environment, and AWS configuration is delivered through AppConfig); builds on [0026](0026-two-platforms-permanently-kubernetes-and-aws-lambda.md), [0030](0030-workload-identity-on-both-platforms.md), [0041](0041-the-secret-contract.md) and [0042](0042-one-repository-one-release-train.md). The Cloudflare module is the one ADR 0070 (in review) decides. |
| [0072](0072-storage-layout-v5-module-first.md) | Storage layout v5: module first, a table per module, and a one-time migration | Accepted (2026-10-09). Refines point 8 of [0071](0071-least-privilege-modules-one-credential-holder-per-function.md) (state, secrets, keys and blobs are per module) and amends its points 1, 5, 9 and 11; builds on [0041](0041-the-secret-contract.md) (the secret contract) and [0031](0031-a-generic-migration-tool.md) (a generic migration tool); extended by [0076](0076-password-sign-in-is-srp-for-recovery-and-conformance-only.md) (two verifier parameters, and a deny on the passwords, in the issuer's namespace). |
| [0073](0073-backup-format-2-age-encrypted-tar.md) | Backup format 2: one age-encrypted tar.gz per backup | Accepted (2026-10-12). Amends point 9 of [0071](0071-least-privilege-modules-one-credential-holder-per-function.md) (a backup is encrypted to age recipients, not under a KMS or OpenBao key) and replaces backup format 1 of [0072](0072-storage-layout-v5-module-first.md). |
| [0074](0074-goalert-identity-and-a-telegram-module.md) | GoAlert identity reconciler and a Telegram module | Accepted (2026-10-15). Builds on [0071](0071-least-privilege-modules-one-credential-holder-per-function.md) (one function per credential holder), [0017](0017-the-slack-reconciler-membership-only.md) (membership only) and [0008](0008-credentials-only-where-we-govern-membership.md). |
| [0075](0075-recovery-is-turned-off-from-the-console-and-on-by-configuration.md) | Recovery is turned off from the console and turned on by configuration | Accepted (2026-10-18). Refines [0036](0036-configuration-is-immutable-per-instance.md) (configuration is immutable and State is read live: this is a decision kept in State that the configuration overrides only by naming a new generation). Applies [0027](0027-the-state-port-nats-jetstream-and-dynamodb.md) (the State port keeps the record); extended by [0076](0076-password-sign-in-is-srp-for-recovery-and-conformance-only.md) (the switch shuts the conformance account's password door as well). |
| [0076](0076-password-sign-in-is-srp-for-recovery-and-conformance-only.md) | A password signs in by SRP, for recovery and for the conformance harness only | Accepted (2026-10-19). Extends [0075](0075-recovery-is-turned-off-from-the-console-and-on-by-configuration.md) (the recovery switch closes the new door too) and [0072](0072-storage-layout-v5-module-first.md) (two new parameters in the issuer's namespace, and a deny on the password). Owner decisions D688 (SRP for this password), D709 (keep the hand-written implementation, with the review's fixes), D710 (the recovery switch shuts the conformance account too), D711 (one client key, `harness`), D712 (a password recovery says `amr` `pwd`). |
| [0077](0077-the-outline-controller-is-a-module-of-its-own.md) | The Outline controller keeps an Outline wiki's groups, roles and collections, as a module of its own | Accepted (2026-10-24). Applies [0017](0017-the-slack-reconciler-membership-only.md) (a reconciler where a claim cannot be read), [0018](0018-do-not-configure-what-the-product-knows.md) (the product's facts are not policy), [0024](0024-reconciler-rails-are-shared-pieces-not-a-framework.md) (the shared rails) and [0071](0071-least-privilege-modules-one-credential-holder-per-function.md) (one credential holder per function). |
| [0078](0078-a-company-access-fragment-is-owned-rows-checked-against-a-ceiling-and-by-effect.md) | A company access fragment is owned rows, checked against a ceiling and by effect | Proposed (2026-11-06). Applies [0010](0010-a-declared-vocabulary.md) (one vocabulary for groups) and [0018](0018-do-not-configure-what-the-product-knows.md) (the product's facts are not policy). |
<!-- /generated -->

## Audit's records

The records numbered 0043 to 0067 are audit's, which had its own series
(0001 to 0025) before audit moved into this repository
([0042](0042-one-repository-one-release-train.md)). They were renumbered after
sluis's, in order, and are otherwise unchanged apart from the Status and Date
lines, which now use the shape the rest of this directory has. A reference to
"audit ADR NNNN" in an older changelog entry, issue or comment means the
record in this table.

| formerly audit ADR | now | decision |
|---|---|---|
| 0001 | [0043](0043-record-schema-proto-with-json-schema-slots.md) | Record schema in Protocol Buffers with JSON Schema extension slots |
| 0002 | [0044](0044-profiles-composed-from-framework-profiles.md) | Profiles composed from framework profiles, one copy per profile |
| 0003 | [0045](0045-s3-object-lock-as-the-record.md) | S3 Object Lock in compliance mode is the record; everything else is a projection |
| 0004 | [0046](0046-sink-interface-and-transports.md) | One sink interface at every hop; the queue is invisible |
| 0005 | [0047](0047-identity-tiers-and-pseudonymisation.md) | Identity tiers and per-purpose pseudonymisation in the split writer |
| 0006 | [0048](0048-search-contract.md) | Search contract: DNF typed predicates, cursor page object, tail cursor |
| 0007 | [0049](0049-authentication-and-authorization-plug-points.md) | Pluggable authentication and authorization with declarative defaults |
| 0008 | [0050](0050-digest-chain-and-verification.md) | Hourly signed digest chain and an auditor-run verify command |
| 0009 | [0051](0051-versioning-policy.md) | Versioning: package per major, major.minor on the record, decoders forever |
| 0010 | [0052](0052-key-providers.md) | Key providers: local, OpenBAO transit and AWS KMS envelope, behind one interface |
| 0011 | [0053](0053-one-installation-per-service-or-product.md) | One installation per service or product, in that application's namespace |
| 0012 | [0054](0054-two-deliveries-and-a-durable-ack.md) | Two deliveries, and the receiver's acknowledgement means durable |
| 0013 | [0055](0055-no-pseudonymisation-keys-by-default.md) | No pseudonymisation keys by default |
| 0014 | [0056](0056-lock-modes-and-store-tiers.md) | Lock modes and store tiers: the lock is demanded where a framework demands it |
| 0015 | [0057](0057-schema-ids-on-github-pages.md) | Schema identifiers on GitHub Pages, the old ones kept as aliases |
| 0016 | [0058](0058-three-parts-installed-independently.md) | Three parts, installed independently; the bucket layout is the contract |
| 0017 | [0059](0059-sink-durability-and-transports.md) | Sink durability: the acknowledgement says how durable, and the start-up refuses less |
| 0018 | [0060](0060-v1-bucket-layout.md) | The v1 bucket layout, and v0 is dropped |
| 0019 | [0061](0061-seals.md) | Seals: JOSE ES384, chained, per profile, tenant and hour |
| 0020 | [0062](0062-observe-follows-the-bucket.md) | Observe follows the bucket by cursor; notifications only wake it |
| 0021 | [0063](0063-one-validated-configuration-file.md) | One configuration file, validated against a schema |
| 0022 | [0064](0064-contracts-proto-and-connect.md) | Contracts are proto and Connect; Lambda RPCs are unary |
| 0023 | [0065](0065-archive-retention-and-lifecycle.md) | Archive retention: Object Lock compliance as the target, governance first |
| 0024 | [0066](0066-indexer-and-query-are-separate-processes.md) | The indexer and the query service are separate processes, under separate database roles |
| 0025 | [0067](0067-configuration-is-immutable-per-instance.md) | Configuration is immutable per instance; credentials and State are read live |

## Template

Start a new record from this shape. Keep it tight — long enough to make
the reasoning checkable, short enough that the next reader finishes it.

```markdown
# NNNN — <a decision, stated as a decision>

**Status:** Proposed | Accepted | Accepted; amended by [NNNN](NNNN-slug.md) | Accepted; partly superseded by [NNNN](NNNN-slug.md) | Superseded by [NNNN](NNNN-slug.md)
**Date:** YYYY-MM-DD

## Context

The situation that made a decision necessary, and the constraint that
ruled some answers out before the rest were compared.

## Decision

What was decided, stated so a reader could act on it without reading
anything else. Include the shape of the mechanism, not just its name.

## Consequences

What this costs, what it forecloses, and what a relying party or an
operator must now do differently. Say the honest boundary out loud —
the case this decision does not cover — rather than leaving it to be
discovered.

## Alternatives considered

Each one named, with the specific reason it was not chosen. "We didn't
think of it" is a fine thing to be able to write here later; do not
retrofit reasons no one had at the time.
```

Use `refines`, `extends` or `amends` on the newer record, and add the matching
`amended by`, `refined by` or `extended by` to the older one's Status line only.
The older record's text is never edited.
