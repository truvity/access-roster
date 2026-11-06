# The policy

Tables of the policy file (`version: 1`) and of the policy document (`apiVersion: sluis.truvity.github.io/policy/v2`). Why: [policy concepts](../../concepts/sluis/policy.md).

| Page | Holds |
|---|---|
| [policy-document.md](policy-document.md) | `exchange`, `apps`, `controllers`, rendering |
| [policy-groups.md](policy-groups.md) | proofs, matchers, claims, merge rules |
| [policy-clients.md](policy-clients.md) | clients, exchange limits, resources, delimiter, signing algorithm, self-described clients |
| [policy-vocabulary.md](policy-vocabulary.md) | vocabulary, per-role scopes, wildcards |
| [policy-bindings.md](policy-bindings.md) | `github`, `people`, `slack`, the access document |
| [policy-ownership.md](policy-ownership.md) | the service's own groups, organisation and workspace owners |
| [policy-validation.md](policy-validation.md) | load refusals, the unconsumed-group warning |
| [policy-fragment.md](policy-fragment.md) | a company's own rows, the ceiling, the violation codes |
| [taxonomy.md](taxonomy.md) | grammar of grant names |

## The tables


```yaml
version: 1

groups:                        # internal groups, the vocabulary, named <scope>:<thing>:<role>
  prod:k8s:admin:
    members: [role-sre@a.example, role-sre@b.example]   # directory groups, any workspace
  prod:k8s:auditor:
    members: [role-security@a.example]
  prod:shop:deployer:
    members: [team-shop@a.example]
  rung:sre:                                             # two segments: a lifetime carrier, not a grant
    members: [role-sre@a.example, role-sre@b.example]
  ci:platform:deployer:
    matchers:                                           # matched, not listed
      - github: { repository: acme/platform, ref: refs/heads/master }
  all:sluis:viewer:
    matchers: [{ email_domain: a.example }]              # the escape hatch
  all:sluis:operator:
    members: [directory-admins@a.example]

claims:                        # what a group adds beyond its own name: sparse, usually empty
  prod:k8s:auditor: { tailnet: { tiers: [vpc] } }

lifetimes:                     # how long: default plus the rungs
  default: 4h
  rung:sre: 8h
  ci:platform:deployer: 1h

clients:                       # who may be issued a token for what; the id is the audience,
                               # unless the request names a resource below
  k8s:prod:          { kind: public,       requires: [prod:k8s:admin, prod:k8s:auditor] }
  aws:1111:power:    { kind: exchange,     requires: [prod:k8s:admin] }
  argocd:            { kind: confidential, secret: argocd-oidc-client, redirects: [https://argocd.example/auth/callback], requires: [prod:k8s:admin], ttl_cap: 12h, display_name: Argo CD }
  local-dev:         { kind: public,       redirects: [http://localhost:8000/callback], requires: [prod:shop:deployer] }

resources:                     # what a token may be minted FOR, when that is not the client asking
  https://mcp.example/:        { requires: [prod:k8s:admin], ttl_cap: 5m, display_name: Telemetry }

client_documents:              # clients that describe themselves; empty means the mechanism is off
  origins:  [clients.example]
  requires: [prod:shop:deployer]
  ttl_cap:  5m

exchange_limits:               # per identity, the only clients its proof may be exchanged for
  - match: { github: { repository: acme/platform } }
    clients: [aws:1111:power]
```

`memberships` is refused as unknown. Name a directory group in a group's `members`.

## Layers

The policy is one file or a directory of `*.yaml` files, each `version: 1`. `sluisctl policy render` merges them ([rendering](policy-document.md#rendering)). Validation runs once on the result ([policy-validation.md](policy-validation.md)).

| Table | Merge across files |
|---|---|
| `groups`, `claims`, `lifetimes`, `clients`, `resources`, `github.<org>.teams`, `people` | by key; a key declared twice is refused |
| `vocabulary`, `client_documents` | one file declares each; a second is refused |
| `slack` workspaces | field by field; a channel comes from one file |
| `github.<org>.members` | one file; `ignore` entries add up |
| `exchange_limits` | every file's limits add up; an identical limit is kept once |

A file with an `access` key is an access document ([policy-bindings.md](policy-bindings.md#the-access-document)).

## Naming

| Form | Meaning |
|---|---|
| `<scope>:<thing>:<role>` | a grant; grammar in [taxonomy.md](taxonomy.md) |
| `rung:<name>` | a session lifetime |
| `emp:<slug>` | a person |

Others warn.

## Claims

Merge rules: [policy-groups.md](policy-groups.md#groups-to-token-by-deep-merge).

## Vocabulary

Optional scopes, things and role ladders: [policy-vocabulary.md](policy-vocabulary.md). Write one: [declare a vocabulary](../../guides/sluis/declare-a-vocabulary.md).

<a id="resources--what-a-token-is-for"></a>

## Resources: what a token is for

A client names a resource with `resource` (RFC 8707). The caller meets both `requires`; the shorter `ttl_cap` wins.

| Topic | Page |
|---|---|
| keys | [policy-clients.md](policy-clients.md#resources) |
| decided in | [policy concepts](../../concepts/sluis/policy.md#why-a-resource-is-not-a-client) |

## Agent-class clients

`session: agent` marks software that holds its own refresh token. Lifetimes: `lifetimes.agent` in [configuration.md](configuration.md).

| Topic | Page |
|---|---|
| keys, refusals, ceilings | [policy-clients.md](policy-clients.md#agent-class-sessions) |
| decided in | [sessions](../../concepts/sluis/sessions.md#agent-class-sessions) |

## Groups in a token (scoping)

`groupsScoping` is `off`, `report` or `enforce`; the default is `report`.

| Mode | Token groups |
|---|---|
| `off` | all held groups |
| `report` | all held groups; logs what `enforce` would drop |
| `enforce` | held groups whose `<scope>:<thing>` pair is in the audience's `requires`, plus the `groups:` override (`all`, a list of things, `rung`, `emp`) |

`requires` and lifetimes read the full set. See [override](policy-clients.md#groups-override), [rule](../../concepts/sluis/groups-in-a-token.md), [read the report](../../guides/sluis/read-the-groups-scoping-report.md), [turn enforce on](../../guides/sluis/turn-enforce-on.md).

## Groups delimiter (per audience, opkssh interop)

`groups_delimiter` replaces every `:` in the audience's `groups` claim.

| Topic | Page |
|---|---|
| keys, refusals | [policy-clients.md](policy-clients.md#groups_delimiter) |
| use | [connect SSH](../../guides/sluis/connect/ssh.md) |
| decided in | [policy concepts](../../concepts/sluis/policy.md#why-a-groups-delimiter-exists) |

## Signing algorithm per audience

`signing_alg` pins RS256, ES256 or ES384. The default is ES384 in the chart. A pin with no key is refused at start.

| Topic | Page |
|---|---|
| keys | [policy-clients.md](policy-clients.md#signing_alg) |
| decided in | [policy concepts](../../concepts/sluis/policy.md#why-an-audience-can-pin-a-signing-algorithm) |

## Clients that describe themselves

`client_documents` admits an HTTPS `client_id` from an allow-listed origin. Off unless `origins` is set.

| Topic | Page |
|---|---|
| keys | [policy-clients.md](policy-clients.md#clients-that-describe-themselves) |
| decided in | [policy concepts](../../concepts/sluis/policy.md#why-a-self-described-client-is-proportionate) |

See [test the policy](../../guides/sluis/test-the-policy.md), [Slack channels](../../guides/sluis/bind-slack-channels-in-git.md), [GitHub teams](../../guides/sluis/bind-github-teams.md).

## Keys

<!-- generated: policy-keys -->

Source: `schemas/config/policy.schema.json`. Generated by `just docs-generate`; keys are listed with their parents first.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `apiVersion` | any | **required** | Which version of which document this is. sluis.truvity.github.io/policy/v2 is what this build writes; a document with no apiVersion is v1, which the binary converts as it loads it, and a binary reads v2 and v1 (docs/reference/sluis/configuration.md). |
| `apps` | object | — | What an operator may make on the console. |
| `apps.github` | object | — | GitHub Apps. |
| `apps.github.apps` | array | — | Every GitHub App the installation declares, of every purpose: the link App, the catalogue Apps and the runner tiers (docs/guides/sluis/connect/github-apps-catalogue.md). A grant naming an undeclared group stops the service. |
| `apps.github.apps[].description` | string | — | What it is for. |
| `apps.github.apps[].events` | array | — | Webhook events the App subscribes to. They are delivered only to an App that declares a `webhook`. |
| `apps.github.apps[].export` | boolean | — | Place the installed App's key at `external/github/<id>` for a consumer to read. Unset keeps it internal. A runner App is always exported. |
| `apps.github.apps[].grants` | array | — | Who may ask for tokens of it, and for how much. |
| `apps.github.apps[].grants[].group` | string | **required** | The internal group. |
| `apps.github.apps[].grants[].permissions` | object | **required** | Permission name to level: read, write or admin. |
| `apps.github.apps[].grants[].permissions.<name>` | one of read, write, admin | — |  |
| `apps.github.apps[].grants[].repositories` | array | **required** | Repository globs. |
| `apps.github.apps[].id` | string | — | The App's key in storage, unique, never changes. `link` for the link App; for a catalogue App [a-z0-9-], at most 32, not beginning `runner-`; a runner entry may leave it out (`runner-<tier>`, and `runner-<tier>-<org>` with an `org`). |
| `apps.github.apps[].installation` | one of all, selected | — | all or selected (default). |
| `apps.github.apps[].labels` | object | — | At most 16 short lower-case labels, key to value, kept on the App's record for a reader that selects Apps by them. |
| `apps.github.apps[].labels.<name>` | string | — |  |
| `apps.github.apps[].name` | string | — | The App's name on GitHub, at most 34. A catalogue App's default is <org>-<id>; the `link` App's and an organisation's have a built-in default, cut to the limit. A runner entry takes none. |
| `apps.github.apps[].org` | string | — | The organisation a catalogue App is created under (required for it), or the only organisation of a runner entry (no `org` offers the tier in every organisation). The link App's owner. |
| `apps.github.apps[].permissions` | object | — | Permission name to level: read, write or admin. |
| `apps.github.apps[].permissions.<name>` | one of read, write, admin | — |  |
| `apps.github.apps[].public` | boolean | — | Installable by other organisations. |
| `apps.github.apps[].purpose` | one of link, catalogue, runner | **required** | What the App is for: `link` is the App that links a person's GitHub account, `catalogue` an App an operator creates and installs from the console, `runner` the tier an operator may create a runner App for. |
| `apps.github.apps[].tier` | string | — | A runner entry's tier: lower-case letters, digits and dashes, at most 16. |
| `apps.github.apps[].webhook` | object | — | Where GitHub delivers the App's events: exactly one of `url` and `kargo`. Needs non-empty `events`; set `export: true` so a consumer can read the secret. The secret is generated by this service, set on GitHub right after the App is created, and kept at `external/github/<id>` as `webhook_secret`; it is rotated from the console, without overlap (docs/decisions/0041). An App created before this is declared cannot be switched to a webhook: GitHub has no API for that, so disconnect it and create it again. |
| `apps.github.apps[].webhook.kargo` | object | — | A Kargo GitHub receiver. Kargo derives the receiver's path from its secret (`/github/<hex sha256(project + receiver + secret)>`), so the URL moves whenever the secret does. |
| `apps.github.apps[].webhook.kargo.base` | string | **required** | Where Kargo's receivers are served. |
| `apps.github.apps[].webhook.kargo.project` | string | — | The Kargo project; empty for a cluster-scoped receiver. |
| `apps.github.apps[].webhook.kargo.receiver` | string | **required** | The receiver's name in the Kargo project. |
| `apps.github.apps[].webhook.url` | string | — | The endpoint every delivery is POSTed to, e.g. Argo CD's `https://argocd.example/api/webhook`. |
| `apps.github.catalogue` | array | — | DEPRECATED: declare each as a `purpose: catalogue` entry in `apps`. Still read as those entries, with a warning. |
| `apps.github.catalogue[].description` | string | — | What it is for. |
| `apps.github.catalogue[].events` | array | — | Webhook events the App subscribes to. They are delivered only to an App that declares a `webhook`. |
| `apps.github.catalogue[].export` | boolean | — | Place the installed App's key at `external/github/<id>` for a consumer to read. Unset keeps it internal. An id may not begin `runner-`. |
| `apps.github.catalogue[].grants` | array | — | Who may ask for tokens of it, and for how much. |
| `apps.github.catalogue[].grants[].group` | string | **required** | The internal group. |
| `apps.github.catalogue[].grants[].permissions` | object | **required** | Permission name to level: read, write or admin. |
| `apps.github.catalogue[].grants[].permissions.<name>` | one of read, write, admin | — |  |
| `apps.github.catalogue[].grants[].repositories` | array | **required** | Repository globs. |
| `apps.github.catalogue[].id` | string | **required** | [a-z0-9-], at most 32, unique; never changes. |
| `apps.github.catalogue[].installation` | one of all, selected | — | all or selected (default). |
| `apps.github.catalogue[].name` | string | — | Default <org>-<id>. |
| `apps.github.catalogue[].org` | string | **required** | The organisation it is created under. |
| `apps.github.catalogue[].permissions` | object | **required** | Permission name to level: read, write or admin. |
| `apps.github.catalogue[].permissions.<name>` | one of read, write, admin | — |  |
| `apps.github.catalogue[].public` | boolean | — | Installable by other organisations. |
| `apps.github.catalogue[].webhook` | object | — | Where GitHub delivers the App's events: exactly one of `url` and `kargo`. Needs non-empty `events`; set `export: true` so a consumer can read the secret. The secret is generated by this service, set on GitHub right after the App is created, and kept at `external/github/<id>` as `webhook_secret`; it is rotated from the console, without overlap (docs/decisions/0041). An App created before this is declared cannot be switched to a webhook: GitHub has no API for that, so disconnect it and create it again. |
| `apps.github.catalogue[].webhook.kargo` | object | — | A Kargo GitHub receiver. Kargo derives the receiver's path from its secret (`/github/<hex sha256(project + receiver + secret)>`), so the URL moves whenever the secret does. |
| `apps.github.catalogue[].webhook.kargo.base` | string | **required** | Where Kargo's receivers are served. |
| `apps.github.catalogue[].webhook.kargo.project` | string | — | The Kargo project; empty for a cluster-scoped receiver. |
| `apps.github.catalogue[].webhook.kargo.receiver` | string | **required** | The receiver's name in the Kargo project. |
| `apps.github.catalogue[].webhook.url` | string | — | The endpoint every delivery is POSTed to, e.g. Argo CD's `https://argocd.example/api/webhook`. |
| `apps.github.runnerTiers` | array | — | DEPRECATED: declare a `purpose: runner` entry in `apps` for each tier. Still read as those entries, with a warning. |
| `apps.slack` | object | — | Slack Apps. |
| `apps.slack.catalogue` | array | — | Every Slack App the installation declares (docs/guides/sluis/connect/slack-apps-catalogue.md). One for a workspace the policy does not declare stops the service. |
| `apps.slack.catalogue[].botScopes` | array | **required** | The bot scopes. |
| `apps.slack.catalogue[].description` | string | — | At most 140. |
| `apps.slack.catalogue[].id` | string | **required** | [a-z0-9-], at most 32, unique; never changes. |
| `apps.slack.catalogue[].name` | string | — | Default <workspace>-<id>. |
| `apps.slack.catalogue[].workspace` | string | **required** | A key of the policy's slack.workspaces. |
| `backup` | object | — | Who may start a backup through the issuer, from the console or `sluisctl backup run`. Reading the status, the list and a restore needs the viewer role and is not named here. A restore is never started through the issuer. |
| `backup.runGroups` | array | — | Groups of this policy: every holder may start a backup. Empty or unset lets nobody; the operators group is not implied. |
| `claims` | object | — | What a group adds to a token, by group. |
| `claims.<name>` | object | — | A claims fragment: merged into the token (docs/reference/sluis/policy.md#claims). |
| `client_documents` | object | — | Admits clients that are not declared, by a document they serve about themselves. Off unless it names an origin. |
| `client_documents.groups` | any | — | Which held groups beyond the requires pairs a token for it carries: `all`, or a list of things, families or names (docs/reference/sluis/policy.md#groups-in-a-token-scoping). |
| `client_documents.origins` | array | — | The origins. |
| `client_documents.requires` | array | — | The groups a caller must hold. |
| `client_documents.session` | one of interactive, agent | `"interactive"` | Every document client's refresh chains: `interactive` (a person at a browser, the installation's `lifetimes`) or `agent` (software that holds its refresh token and works in the background, the service's `lifetimes.agent`). Recorded on each chain when its authorization completes (docs/decisions/0040). Never read from a document: admit with `agent` only an origin whose documents its vendor controls. |
| `client_documents.ttl_cap` | string | — | The longest a token lives. |
| `clients` | object | — | Who may be issued a token, by client id. |
| `clients.<name>` | object | — | A client: who may be issued a token, and for what. Its id is the audience. |
| `clients.<name>.backchannel_logout_uri` | string | — | Where a back-channel logout is posted. |
| `clients.<name>.description` | string | — | One line about it on the sign-in page. Public. |
| `clients.<name>.display_name` | string | — | What the sign-in page calls it. Public. |
| `clients.<name>.groups` | any | — | Which held groups beyond the requires pairs a token for it carries: `all`, or a list of things, families or names (docs/reference/sluis/policy.md#groups-in-a-token-scoping). |
| `clients.<name>.groups_delimiter` | string | — | Rewrites `:` in its `groups` claim (docs/decisions/0015). |
| `clients.<name>.harness` | boolean | — | A conformance or test harness signs in through it: the only kind of client the conformance account (`conformance.enabled`) may sign in to. Refused on an exchange client. |
| `clients.<name>.kind` | one of public, confidential, exchange | **required** | public, confidential or exchange. |
| `clients.<name>.pkce` | one of required, optional | — | Whether it must use PKCE (RFC 7636, RFC 9700 2.1.1): `required` refuses an authorization request with no S256 `code_challenge` and a code redeemed with no `code_verifier`. A public client is always `required` and refuses `optional`; absent is `optional` for a confidential client. Refused on an exchange client. |
| `clients.<name>.redirects` | array | — | The redirect URIs. Plain `http://` only to `127.0.0.1`, `[::1]` or `localhost`. |
| `clients.<name>.requires` | array | — | The groups a caller must hold, any of them. |
| `clients.<name>.secret` | any | — | For a confidential client: the name its secret is delivered under, or `{generate: true}` to have the issuer generate it and keep it with its credentials. |
| `clients.<name>.secret.generate` | any | — | Must be true; `generate: false` is refused. |
| `clients.<name>.session` | one of interactive, agent | `"interactive"` | Its refresh chains: `interactive` (a person at a browser, the installation's `lifetimes`) or `agent` (software that holds its refresh token and works in the background, the service's `lifetimes.agent`). Recorded on each chain when its authorization completes (docs/decisions/0040). Refused on an exchange client and, as `agent`, with `sign_in_exchange`. |
| `clients.<name>.sign_in_exchange` | boolean | — | It may exchange a sign-in for a token of its own. |
| `clients.<name>.signed_out` | array | — | Where sign-out may return the browser. Plain `http://` as for `redirects`. |
| `clients.<name>.signing_alg` | string | — | The algorithm its tokens are signed with, when it cannot verify the default: RS256, ES256 or ES384. |
| `clients.<name>.ttl_cap` | string | — | The longest a token for it lives. |
| `cloudflare` | object | — | Who may ask for a Cloudflare preset (the presets are the service document's `cloudflare.presets`). A preset named here and not there stops the service. |
| `cloudflare.grants` | array | — | One row per group. |
| `cloudflare.grants[].group` | string | **required** | A group of this policy: every holder may ask, a person from the console or `sluisctl`, a CI job through the exchange. A CI job is a group declared with `github` matchers. |
| `cloudflare.grants[].presets` | array | **required** | The presets the row opens. |
| `controllers` | object | — | What each controller may CHANGE. Everything else the policy binds is derived every pass and shown with what would happen, and left alone: an organisation or workspace is born disabled. |
| `controllers.github` | object | — | The GitHub controller. |
| `controllers.github.appNames` | object | — | For an organisation the github table binds, the name its App is created with on GitHub (at most 34 characters). Optional: an organisation with no entry gets the built-in default, cut to the limit. An App already created keeps the name it has. |
| `controllers.github.appNames.<name>` | string | — |  |
| `controllers.github.appRefs` | object | — | For an organisation the github table binds, the id of the catalogue App (in `apps.github.apps`, created under that organisation) whose key its record refers to, `app_ref`. Optional: an organisation whose record already names an App keeps it, so an entry only overrides it or declares an organisation anew. |
| `controllers.github.appRefs.<name>` | string | — |  |
| `controllers.github.enabledOrgs` | array | — | The organisations it changes. Each must be bound by the github table. |
| `controllers.outline` | object | — | The Outline controller. |
| `controllers.outline.enabledWorkspaces` | array | — | The workspaces it changes, by key. Each must be declared by the outline table. The rest are dry runs. |
| `controllers.slack` | object | — | The Slack controller. |
| `controllers.slack.enabledWorkspaces` | array | — | The workspaces it changes, by key. Each must be declared by the slack table. |
| `exchange` | object | — | Whom the token exchange trusts. Nothing here is a secret: every row is a name and a URL. |
| `exchange.aws` | object | — | The AWS accounts whose roles' outbound identity tokens (sts:GetWebIdentityToken) are verified. An empty list verifies none. |
| `exchange.aws.accounts` | array | — | The accounts. |
| `exchange.aws.accounts[].account` | string | **required** | The 12-digit account id. |
| `exchange.aws.accounts[].algs` | array | — | Default both; narrow, never widen. |
| `exchange.aws.accounts[].issuer` | string | **required** | From `aws iam get-outbound-web-identity-federation-info`. https. |
| `exchange.aws.accounts[].jwksUri` | string | — | Default <issuer>/.well-known/jwks.json. |
| `exchange.aws.accounts[].name` | string | **required** | The estate's word for it, for logs. |
| `exchange.aws.accounts[].orgId` | string | — | Require this AWS Organizations id. |
| `exchange.aws.audience` | string | — | The audience the role must request. Required with an account: it is the trust boundary. |
| `exchange.aws.maxAge` | string | `"5m"` | Refuse a token whose `iat` is older than this. At most 1h. |
| `exchange.clusters` | array | — | The clusters whose ServiceAccount tokens are verified, each against the key set it publishes for itself. This service's own cluster is a row like any other. |
| `exchange.clusters[].issuer` | string | **required** | The `iss` its ServiceAccount tokens carry. |
| `exchange.clusters[].jwksUri` | string | — | Where its keys are. Unset discovers them from the issuer. |
| `exchange.clusters[].name` | string | **required** | The estate's word for it: the cluster in a `service_account` matcher. Renaming a row changes every rule about it. |
| `exchange.github` | object | — | Whose GitHub Actions tokens are verified, for this issuer's URL as the audience. |
| `exchange.github.ownerIds` | array | — | The numeric ids of those organisations (the token's `repository_owner_id`). When set, a token must carry one of them as well as an owner above: a login can be renamed or taken by someone else after a deletion, an id cannot. Unset asks nothing of the id. |
| `exchange.github.owners` | array | — | The organisations. None verifies none: an empty list would admit every repository there is. |
| `exchange.github.repositoryIds` | array | — | The numeric ids of the repositories whose tokens are verified (the token's `repository_id`). When set, a token must carry one of them. Unset asks nothing of the id. |
| `exchange_limits` | array | — | Per identity, which clients a proof may be exchanged for (docs/reference/sluis/policy-clients.md#exchange-limits). A proof that a limit's `match` matches may be exchanged only for that limit's clients, the union when several match; a proof no limit matches is not limited. A limit grants nothing: the client's `requires` must still admit the proof. |
| `exchange_limits[].clients` | array | **required** | The client ids such a proof may be exchanged for. Each must be a declared client. |
| `exchange_limits[].match` | object | **required** | The identity the limit is about: one matcher, as a group's, matched against the proof alone. Exactly one kind is set. |
| `exchange_limits[].match.aws` | object | — | An IAM role in an account `exchange.aws` federates. |
| `exchange_limits[].match.aws.account` | string | **required** | The 12-digit account id. |
| `exchange_limits[].match.aws.function` | string | — | A Lambda function's name. |
| `exchange_limits[].match.aws.org_id` | string | — | The AWS Organizations id. |
| `exchange_limits[].match.aws.path` | string | — | The role's path. |
| `exchange_limits[].match.aws.role` | string | — | The role's name, a glob. |
| `exchange_limits[].match.email` | string | — | One signed-in address. |
| `exchange_limits[].match.email_domain` | string | — | Every signed-in address in a domain. |
| `exchange_limits[].match.github` | object | — | A GitHub Actions job, by what its verified token says. |
| `exchange_limits[].match.github.environment` | string | — | The deployment environment. |
| `exchange_limits[].match.github.event_name` | string | — | The triggering event. |
| `exchange_limits[].match.github.job_workflow_ref` | string | — | The reusable workflow at a ref, a glob. |
| `exchange_limits[].match.github.owner` | string | — | The repository's owner. |
| `exchange_limits[].match.github.ref` | string | — | The ref, a glob. |
| `exchange_limits[].match.github.ref_type` | string | — | branch or tag. |
| `exchange_limits[].match.github.repository` | string | — | owner/name, a glob. |
| `exchange_limits[].match.github.sha` | string | — | The commit. |
| `exchange_limits[].match.github.visibility` | string | — | public, private or internal. |
| `exchange_limits[].match.github.workflow` | string | — | The workflow's name. |
| `exchange_limits[].match.github.workflow_ref` | string | — | The workflow file at a ref, a glob. |
| `exchange_limits[].match.service_account` | object | — | A ServiceAccount on a federated cluster. |
| `exchange_limits[].match.service_account.cluster` | string | — | The cluster's name in `exchange.clusters`. Unset is the unqualified subject. |
| `exchange_limits[].match.service_account.name` | string | **required** | The ServiceAccount. |
| `exchange_limits[].match.service_account.namespace` | string | **required** | The namespace. |
| `github` | object | — | GitHub organisations bound to internal groups, by login. |
| `github.<name>` | object | — | An organisation's bindings. |
| `github.<name>.ignore` | array | — | Addresses and logins the controller leaves alone. |
| `github.<name>.members` | array | — | The groups whose holders belong in the organisation. |
| `github.<name>.teams` | object | — | Each team, by slug. |
| `github.<name>.teams.<name>` | object | — | A team's binding. |
| `github.<name>.teams.<name>.maintainers` | array | — | The groups whose holders are maintainers. |
| `github.<name>.teams.<name>.members` | array | — | The groups whose holders are members. |
| `groups` | object | — | Every internal group, by name, and how a caller comes to be in it. |
| `groups.<name>` | object | — | A group. |
| `groups.<name>.matchers` | array | — | The matchers. |
| `groups.<name>.matchers[].aws` | object | — | An IAM role in an account `exchange.aws` federates. |
| `groups.<name>.matchers[].aws.account` | string | **required** | The 12-digit account id. |
| `groups.<name>.matchers[].aws.function` | string | — | A Lambda function's name. |
| `groups.<name>.matchers[].aws.org_id` | string | — | The AWS Organizations id. |
| `groups.<name>.matchers[].aws.path` | string | — | The role's path. |
| `groups.<name>.matchers[].aws.role` | string | — | The role's name, a glob. |
| `groups.<name>.matchers[].email` | string | — | One signed-in address. |
| `groups.<name>.matchers[].email_domain` | string | — | Every signed-in address in a domain. |
| `groups.<name>.matchers[].github` | object | — | A GitHub Actions job, by what its verified token says. |
| `groups.<name>.matchers[].github.environment` | string | — | The deployment environment. |
| `groups.<name>.matchers[].github.event_name` | string | — | The triggering event. |
| `groups.<name>.matchers[].github.job_workflow_ref` | string | — | The reusable workflow at a ref, a glob. |
| `groups.<name>.matchers[].github.owner` | string | — | The repository's owner. |
| `groups.<name>.matchers[].github.ref` | string | — | The ref, a glob. |
| `groups.<name>.matchers[].github.ref_type` | string | — | branch or tag. |
| `groups.<name>.matchers[].github.repository` | string | — | owner/name, a glob. |
| `groups.<name>.matchers[].github.sha` | string | — | The commit. |
| `groups.<name>.matchers[].github.visibility` | string | — | public, private or internal. |
| `groups.<name>.matchers[].github.workflow` | string | — | The workflow's name. |
| `groups.<name>.matchers[].github.workflow_ref` | string | — | The workflow file at a ref, a glob. |
| `groups.<name>.matchers[].service_account` | object | — | A ServiceAccount on a federated cluster. |
| `groups.<name>.matchers[].service_account.cluster` | string | — | The cluster's name in `exchange.clusters`. Unset is the unqualified subject. |
| `groups.<name>.matchers[].service_account.name` | string | **required** | The ServiceAccount. |
| `groups.<name>.matchers[].service_account.namespace` | string | **required** | The namespace. |
| `groups.<name>.members` | array | — | Directory groups whose members are in it. |
| `lifetimes` | object | — | How long a token lives, by group, and `default`. The shortest across a caller's groups wins. |
| `lifetimes.<name>` | string | — | A lifetime. |
| `outline` | object | — | Outline workspaces: the admin role and the collections, bound to internal groups (docs/reference/sluis/outline.md). The URL and the API key are the console's connection record, never policy. |
| `outline.workspaces` | object | — | Each workspace, by the installation's key (the rules of a Slack workspace key). |
| `outline.workspaces.<name>` | object | — | A workspace. |
| `outline.workspaces.<name>.client` | string | — | The sluis client the workspace signs in through. An account that reaches none of its required groups is suspended. Unset, an account must hold a group the workspace binds. |
| `outline.workspaces.<name>.collections` | object | — | Each collection, by name as Outline spells it. |
| `outline.workspaces.<name>.collections.<name>` | object | — | A collection's binding. |
| `outline.workspaces.<name>.collections.<name>.admin` | array | — | The internal groups granted `admin` on the collection. A group at two levels takes the higher. |
| `outline.workspaces.<name>.collections.<name>.adopt` | string | — | The id of an existing collection to adopt: for a renamed one, or when two carry the name. |
| `outline.workspaces.<name>.collections.<name>.directory` | string | — | The connected directory, by its primary domain (`example.com`), that every bound group's members must come from. A collection whose groups reach outside it is held. |
| `outline.workspaces.<name>.collections.<name>.mode` | one of extend, strict | — | `extend` (the default) only adds grants; `strict` also removes the group grants and direct members the policy does not name. |
| `outline.workspaces.<name>.collections.<name>.read` | array | — | The internal groups granted `read` on the collection. A group at two levels takes the higher. |
| `outline.workspaces.<name>.collections.<name>.read_write` | array | — | The internal groups granted `read_write` on the collection. A group at two levels takes the higher. |
| `outline.workspaces.<name>.ignore` | array | — | Addresses never demoted, removed or suspended: the API key's owner among them. Joined across files. |
| `outline.workspaces.<name>.roles` | object | — | The workspace roles. |
| `outline.workspaces.<name>.roles.admin` | array | — | The internal groups whose holders are workspace admins. Every other managed account is a member. |
| `people` | object | — | Which addresses are one person, by a name the installation chooses. |
| `people.<name>` | array | — | The addresses. |
| `resources` | object | — | What a token may be minted FOR, by resource indicator. |
| `resources.<name>` | object | — | A resource a token may be minted for, when it is not the client asking. |
| `resources.<name>.absolute_cap` | string | — | The longest a session that touched it lives. |
| `resources.<name>.description` | string | — | One line about it. |
| `resources.<name>.display_name` | string | — | What the consent page calls it. |
| `resources.<name>.groups` | any | — | Which held groups beyond the requires pairs a token for it carries: `all`, or a list of things, families or names (docs/reference/sluis/policy.md#groups-in-a-token-scoping). |
| `resources.<name>.groups_delimiter` | string | — | Rewrites `:` in its `groups` claim. |
| `resources.<name>.read_only` | boolean | — | It only reads: an absolute cap past the installation's may be honoured. Deprecated as a lengthening (docs/decisions/0040): mark the clients `session: agent` instead; a lengthening row is warned about at start. |
| `resources.<name>.requires` | array | — | The groups a caller must hold, any of them. |
| `resources.<name>.signing_alg` | string | — | The algorithm its tokens are signed with: RS256, ES256 or ES384. |
| `resources.<name>.ttl_cap` | string | — | The longest a token for it lives. |
| `slack` | object | — | Slack channels bound to internal groups, across workspaces. |
| `slack.workspaces` | object | — | Each workspace, by the installation's key. |
| `slack.workspaces.<name>` | object | — | A workspace. |
| `slack.workspaces.<name>.channels` | object | — | Each channel, by name. |
| `slack.workspaces.<name>.channels.<name>` | object | — | A channel's binding. |
| `slack.workspaces.<name>.channels.<name>.adopt` | string | — | Adopt an existing channel. |
| `slack.workspaces.<name>.channels.<name>.from` | array | — | The groups whose holders belong in it. |
| `slack.workspaces.<name>.channels.<name>.ignore` | array | — | Members left alone. |
| `slack.workspaces.<name>.channels.<name>.mode` | string | — | How membership is kept. |
| `slack.workspaces.<name>.channels.<name>.private` | boolean | — | A private channel. |
| `vocabulary` | object | — | Which scopes, things and roles a grant name may use, and each thing's role ladder. Optional: absent, any `<scope>:<thing>:<role>` is accepted unchecked. |
| `vocabulary.scopes` | object | — | The scopes. |
| `vocabulary.scopes.<name>` | object | — | A scope. |
| `vocabulary.scopes.<name>.sensitive` | boolean | — | Grants on it are sensitive. |
| `vocabulary.things` | object | — | The things. |
| `vocabulary.things.<name>` | object | — | A thing. |
| `vocabulary.things.<name>.roles` | object | — | Its roles. |
| `vocabulary.things.<name>.roles.<name>` | any | — | A role: the roles it implies, or `{implies, scopes}` to restrict it to some of its thing's scopes. |
| `vocabulary.things.<name>.roles.<name>.implies` | array | — | The roles it implies. |
| `vocabulary.things.<name>.roles.<name>.scopes` | array | — | The scopes it may be exercised on. |
| `vocabulary.things.<name>.scopes` | array | — | The scopes it exists in. |
<!-- /generated -->
