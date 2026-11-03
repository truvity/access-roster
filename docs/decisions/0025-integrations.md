# 0025 — Integrations are adapters, work actors that return facts or carry out authorised effects, hold nothing at rest, and mint only for declared targets

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #997](https://github.com/truvity/sluis/issues/997).

## Context

[0002](/decisions/0002-families-of-actors/#work-actors) says that the work actor of an integration is an adapter, named `adapter-<vendor>@<boundary>`, that it holds no credential at rest, and that it returns facts or carries out effects that core has authorised. It does not say what an adapter may return, how core authorises an effect before it runs, what each kind of integration is called over its socket, how a tenant's connection reaches an adapter, or for which targets a credential may be minted at all. Every integration built after this one, and the sign-in of the first working version, is written against this contract.

The forces are the ones that made `policy` a separate actor ([0007](/decisions/0007-policy-and-sealed-grants/)). A vendor adapter is the part of sluis that speaks a third party's protocol and uses a third party's credential; if it also decides who gets what, the decision hides in vendor code that no policy file shows. Vendor error text, vendor identifiers and vendor structs in core would tie core to each vendor. An adapter that served several companies from credentials of its own would let one company's compromise reach another's; under the families it keeps nothing at rest, so what a flaw yields is the credential it is using at that moment ([principle 16](/principles/#16-few-credential-holders)).

A minter is a place where sluis holds standing power at a vendor, so each one needs a reason (principle 8). The only entitlement sluis can state with confidence is one it derives from its own groups and proofs (principle 4). A vendor that can trust sluis as an identity provider needs no minter at all. v1 minted for each vendor it integrated (parity rows [#811](https://github.com/truvity/sluis/issues/811), [#816](https://github.com/truvity/sluis/issues/816), [#817](https://github.com/truvity/sluis/issues/817) and [#819](https://github.com/truvity/sluis/issues/819)), and the credential that creates tokens at a vendor is the sharpest one in its integration.

## Decision

### The rule

- **An integration returns facts, or carries out an effect that core has authorised, and never decides.** Whether a fact entitles anyone to anything is the question of `policy`. A refusal by an adapter means "the vendor said no" or "this is outside what core authorised", never "this person may not".
- **An integration is implemented by an adapter.** An adapter serves one vendor, implements one or more of the contracts below for it, and opens each tenant's connection credential at key@ for each call ([Adapters and connections](/decisions/0025-integrations/#adapters-and-connections)).
- **Core calls adapters, and an adapter calls no work actor other than `policy`.** `session` calls its upstream adapter, `exchange` its minters and notifiers, and `console` the adapters whose flows it starts or whose kinds it routes writes to. `entry` only routes a push notification to an adapter. What a provisioner needs, a desired state, is data that it reads through its data port. The one call an adapter makes is to `policy`, for the grant of work that no caller started ([Adapters and connections](/decisions/0025-integrations/#adapters-and-connections)) and, for a directory adapter, for the members of the targets that its directory feeds. Writing what `policy` answered is executing, not deciding ([0026](/decisions/0026-reconcilers/#the-desired-state)).
- **Three invariants are tested:** core packages never import vendor packages; the actor registry has no call from an adapter to a work actor other than `policy`; policy matchers have no vendor-specific fields.

### The contracts

Every contract is a ConnectRPC service in the package `sluis.integration.v2alpha1` ([Contracts and errors](/reference/contracts/#packages-and-files)).

| Contract | Kind | Methods | Returns |
|---|---|---|---|
| `Integration` | base, served by every adapter | `Describe`, `Probe` | Its kinds and version, the attributes it can return with their types, and its health |
| `Upstream` | sign-in | `Begin`, `Complete` | An authorization URL; then an assertion of identity |
| `FactsSource` | facts | `Lookup`, `Changes` | Facts about named subjects; the subjects whose facts changed since a cursor |
| `CredentialMinter` | effect | `Mint` | A short-lived credential for a sealed grant |
| `Provisioner` | effect | `Reconcile` | The outcome of making an external system equal a desired state |
| `Notifier` | effect | `Send` | The outcome of sending one message |

The workload verifier is not an adapter but a verifier driver of `exchange`, which holds public material only ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)).

### Adapters and connections

- **An adapter serves one vendor.** The adapters of the actor registry are `adapter-upstream-oidc` (the `Upstream` contract, and the directories of Google Workspace and Entra), `adapter-github` (a GitHub organisation's directory, minting and teams) and `adapter-slack` (chat channels and notifications). A provider for which sluis mints is served by the adapter of that provider. An adapter is added with the first consumer of its contract (principle 8).
- **One adapter runs for a vendor in a boundary, and connections tell the tenants apart.** `adapter-github@prod` serves every tenant of `prod` that has connected a GitHub organisation; two tenants' connections to the same vendor are two items of one kind under two tenants, not two instances. The actor registry places an adapter per boundary.
- **A connection is a tenant's own, durable and sealed.** A tenant's directory, chat workspace, code host or account at a provider that sluis mints for is a durable kind of that tenant with its credential sealed, made through the UI or the API. The rule that classes them, and the writer of each, is in [0004](/decisions/0004-the-data-model/#the-upstream-criterion). The adapter that completes the connect flow writes the connection, under ids that start with its own name ([0004](/decisions/0004-the-data-model/#one-writer-per-kind)).
- **Which kinds an adapter uses:**

  | Adapter | App definition, installation-wide (config, secret) | Connection of a tenant (durable, sealed credential) | Flow in progress (temp) |
  |---|---|---|---|
  | `adapter-upstream-oidc` | `Upstream`, `UpstreamSecret` | `EntraConnection`, `DirectoryConnection`; the customer's own `TenantConnection`, written by `session` ([0033](/decisions/0033-customer-connections/)) | `EntraConsentState` |
  | `adapter-github` | none | `GitHubApp`, `GitHubInstallation`, `DirectoryConnection` | `GitHubManifestState` |
  | `adapter-slack` | `SlackApp`, `SlackAppSecret` | `SlackConnection` | `SlackInstallState` |
  | A provider's adapter, for minting | `MinterBounds` | `MinterConnection`, `MinterTarget` | none |

- **`Integration` and `IntegrationSecret` define an integration made by hand or IaC:** its vendor, its capability and the hosts its adapter may reach. They serve the whole installation, hold no connection of a tenant, and are read by the adapter named in their id.
- **An adapter opens a connection's credential per call.** It reads the connection through its data port, asks key@ to `Open` the sealed credential with a grant sealed for the connection's tenant ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)), makes the call to the vendor, and keeps nothing. A pass that no caller started, such as a scheduled re-sync or a reconcile pass, has no grant to bring, so the adapter asks `policy` for one for that pass, for one tenant at a time, as `exporter` does for its own work. The grant is short-lived like any other. Deleting a connection ends the credential, and a tenant that leaves takes its connections with it ([0008](/decisions/0008-boundaries-and-tenants/#tenant-lifecycle)).
- **A credential that serves the whole installation stays in a secret source.** The client secret of an `Upstream` that the operator made, a `SlackAppSecret` and an `IntegrationSecret` are read by the adapter named in the registry from the secret source ([0005](/decisions/0005-the-store/#secret-sources)). The credential of a minter that has no tenant is in [Credential minters](/decisions/0025-integrations/#credential-minters).
- **An IaC tool may create a connection through the API.** What it writes lands in a durable kind of the tenant, not in config ([principle 17](/principles/#17-where-a-thing-is-written-decides-its-class)). The company that runs the installation is a tenant, so its own connections are durable too.

### What an integration may return

- **A fact is a subject reference, named attributes, the time observed (`as_of`), how long it may be used (`max_age`) and whether the source is authoritative.** A fact that has passed its `max_age` is stale, and `policy` is told so; staleness is never repaired by guessing.
- **References are opaque.** A subject or a group is a `{namespace, id}` pair, and core never parses the id. Attributes carry namespaced names (`github.repository`, `k8s.namespace`), declared with their types in `Describe`, so a policy file is validated at load without core knowing the vendor.
- **A directory's facts are temp kinds of the tenant** (`DirectoryUser`, `DirectoryGroup` and `DirectoryMembership`), written by the adapter and sealed because they hold names and addresses. Their time to live is the fact's maximum age, 24 hours by default and 7 days at most, and a re-sync rebuilds them. On boards every write is a commit of the cluster, so the cost of a full re-sync was measured on 2026-11-03: 100,000 users take 260 s and 4,100 commits and raise the p99 of a sign-in write from 37 to 209 ms, and clearing a directory first stalls writes for seconds, so a re-sync replaces items and does not clear first ([0037](/decisions/0037-capacity-is-measured-before-it-is-promised/#board-capacity)).
- **The sign-in assertion is a fact about one authentication.** `Upstream.Complete` returns the issuer, the value of the upstream's subject claim ([0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)), and the claims of a configured allow-list: the e-mail address and whether the upstream verified it, a display name, and `acr`, `amr` and `auth_time` exactly as the upstream sent them. An absent value is unknown, never a default. Groups and roles that the upstream sends are not read.
- **A refusal carries a reason from a closed list:** `UNAVAILABLE`, `UPSTREAM_REJECTED`, `INVALID`, `NOT_FOUND`, `RATE_LIMITED`, `UNSUPPORTED`, `STALE`, each with one Connect code ([Contracts and errors](/reference/contracts/#connect-codes)). No vendor error text crosses the contract.
- **"I could not ask" is `UNAVAILABLE`, never an empty answer.** A directory that cannot be read must not look like a directory with no members.

### The upstream contract

- **`Begin`** takes the `state`, the `nonce` and the S256 `code_challenge` that `session` made, sluis's callback URL, and optionally `acr_values`, `max_age`, a login hint, `prompt` and `ui_locales`, and returns the authorization URL. `prompt` and `ui_locales` are the request's own, passed on as given ([0035](/decisions/0035-customer-pages/#templates-and-locales)). `session` keeps the sign-in's state in a `PendingSignIn`; the adapter keeps none.
- **`Complete`** takes the callback's `code` and `iss` parameter, the `code_verifier`, the `nonce` and the callback URL. `adapter-upstream-oidc` exchanges the code at the upstream's token endpoint with the client credential, checks the ID token strictly (signature against the upstream's key set, an allow-list of algorithms, `iss`, `aud`, `azp`, `nonce` and the time claims), and returns the verified assertion to `session`. The client credential never leaves the adapter, so `session` holds no upstream credential and has no rule for `UpstreamSecret`.
- **The credential is the operator's or the customer's.** For an upstream the operator made, it is the `UpstreamSecret` of a secret source. For a customer organisation's own provider, it is the client secret sealed in its `TenantConnection`, opened at key@ for the call; those adapters run in a pool per customer boundary ([0033](/decisions/0033-customer-connections/#a-pool-per-customer-boundary)).
- **A missing subject claim, a bad token or a missing `iss` in the response is refused with `INVALID`.** There is no lenient fallback, and no fallback to another claim or to the e-mail address.

### How core authorises an effect

- **A mint is authorised by a grant that `policy` sealed.** The grant carries the decision, the digest of the policy and the hash of the scope ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). The minter opens it at key@, which fails for a grant of another boundary or of another tenant, refuses a scope the grant does not cover and cannot lengthen the lifetime. `exchange` has `quota` admit the operation before it calls the minter.
- **A reconciliation is authorised by a desired state that `policy` answered for and a directory adapter wrote.** The provisioner reads it by its digest through its data port; it never asks core a question and cannot choose what the state should be ([0026](/decisions/0026-reconcilers/#the-desired-state)).
- **A notification is authorised by core composing it.** The caller names a template and its parameters and a destination that configuration allows; the notifier sends that and nothing else.
- **Business limits live in core.** Caller caps, mint rates and which group may hold which role are policy and quota, checked before an adapter is called. An adapter enforces only technical limits: the vendor's API rate and maximum lifetime.
- **Every effect is reported as an outcome:** done with its expiry, refused with a reason from the closed list, or failed. A credential or a secret is never in an audit record, a log line or a span.

### Credential minters

- **A minter serves a declared target.** A target is a `MinterTarget`: a cloud role, a prototype token or a DNS zone of a tenant's account at a provider, with the lifetime asked for. It is durable and Tenant-adjustable, written by the adapter that mints it, and checked on write against `MinterBounds`, the config kind that says what the installation allows a minter to mint (the target types and the longest lifetime of each). The account itself is the tenant's connection to the provider, a `MinterConnection` for an account such as a Cloudflare account, with the credential that creates tokens sealed. A request for a target that is not declared, or that lies outside the bounds, is refused with `NOT_FOUND`.
- **sluis governs the membership that entitles a caller to mint.** Who may obtain a credential for a target is decided only by `policy`, from the internal groups it derives from directory facts and verified proofs ([0019](/decisions/0019-person-and-upstream-link/), [0020](/decisions/0020-grant-vocabulary-and-token-claims/)). The grant `policy` seals names the group, the target and the scope, and the minter opens only that. A target whose entitlement is held outside sluis, such as a personal token that a person supplies or a credential sluis would have to read from a caller, is not a target: the request is refused with `UNSUPPORTED`.
- **A minter never passes on, widens or records another party's credential.** What it returns is never wider than the one grant and never longer than the least of the grant, the policy cap and the vendor's maximum. It is handed to the caller and kept nowhere: no kind holds a minted credential, and no audit record, log line or span carries one ([0004](/decisions/0004-the-data-model/#what-is-not-data)). A mint is a one-shot action, so the minter leaves a `SpentGrant` ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)).
- **The minting credential has a floor in code.** Each minter refuses a target that grants administration of tokens, billing, account settings, memberships or identity providers at its vendor. Configuration can add names to the refusal list and cannot remove any. The per-vendor lists are on the integration pages and are not repeated here.
- **No minter where the vendor can federate.** AWS roles and Kubernetes API servers trust sluis as an OpenID Connect issuer and take its tokens ([0017](/decisions/0017-identity-and-sign-in/)); sluis does not mint an AWS key or a service-account token for them. A minter exists only for a vendor that cannot accept an external issuer for the purpose.
- **The credential of an installation-level minter stays in a secret source.** A minter whose "tenant" is not a sluis tenant, such as the NATS operator, is bounded by `MinterBounds` and keeps its credential as the secret kind `MinterSecret`. It is the sharpest edge of its adapter.
- **Per-vendor behaviour stays on the integration pages.** What a vendor needs, what its limits are and how a mint is requested are described there and tested against a fake vendor; this record fixes only when a minter may exist and what it may return.

### Splitting by credential

- **The split follows the credential, not the process.** Sign-in and the directory of one workspace are two credentials, so two connections (a sign-in client and a `DirectoryConnection`); two tenants' connections to the same vendor are two connections. Each fails, rotates and leaves on its own, and an adapter cannot reach a connection that its grant does not name. One adapter process serves them all, because it holds none of them at rest.
- **An adapter declares the hosts it may reach and the key purposes it needs,** and the actor registry grants no more. Outbound access is limited to the declared hosts: a per-uid egress rule on boards, a network policy on Kubernetes ([0003](/decisions/0003-units-transports-and-fusion/#units)).
- **Each adapter audits what it does** through its audit emit port: a facts pass with its digest and counts, a sign-in with its outcome, an effect with its outcome ([0002](/decisions/0002-families-of-actors/#ports-of-a-work-actor)).

### Push, then pull

- **A push is a notification, then a pull.** A small notification reaches `entry`, which routes it to the adapter; the adapter reads the full state from the vendor's API, and a periodic full pass runs as well. A pass that changes an external system takes a lease ([0026](/decisions/0026-reconcilers/#scope)).

### The first working version

- **The first working version has `Integration` and `Upstream`,** served by `adapter-upstream-oidc` for each `Upstream` the operator declares ([0019](/decisions/0019-person-and-upstream-link/)). `FactsSource` and the three effector contracts are written with their first consumer at the parity milestone, as additions to the package; adding a service or a method is compatible ([Contracts and errors](/reference/contracts/#versions)).

## Consequences

- A flaw in an adapter reaches the credential it is using at that moment and the facts it can return. It cannot grant, because it holds no policy, it cannot mint beyond a grant, because it opens only grants that `policy` sealed, and it holds no connection at rest.
- Policy and core stay free of vendors: a new vendor is a new adapter with a `Describe` document, and no core package changes.
- A minter is added with a reason that can be read off the registry: a bound in config, a connection of a tenant, a target within the bound, a group that policy binds. Reviewers see in one place what the credential can do.
- A user who wants a token for something sluis does not govern gets a refusal, not a surprise. The cost is that a vendor with no federation and no bounds that can be declared cannot be served until it has both.
- The AWS and Kubernetes rows of the parity list are relying-party recipes, not minters, and are tested as such.
- Every call to a vendor on behalf of a tenant costs an open at key@, and a pass over many tenants costs many. The cost is batched and measured with the other hops ([0037](/decisions/0037-capacity-is-measured-before-it-is-promised/)).
- The cost is a typed contract per kind to keep compatible. Small machines rely on the fusion rule of [0003](/decisions/0003-units-transports-and-fusion/#fusion).
- Treating an unreachable directory as `UNAVAILABLE` means a directory outage is felt as refusals after the freshness window, not as everyone silently losing access ([0017](/decisions/0017-identity-and-sign-in/#directory-outages)).
- The requirement records for the integrations stay with their areas: the upstream's checks are REQ-FED-001 to REQ-FED-016, and the minters' are [REQ-EXCH-013](/requirements/exch/#REQ-EXCH-013) to [REQ-EXCH-015](/requirements/exch/#REQ-EXCH-015).

## Roads not taken

- **One generic `Do(request)` call for every integration.** One interface, but no typed contract to test, no schema to validate a policy against, and every caller parses vendor-shaped bytes.
- **Integrations that return a decision, such as "allow".** A second policy engine inside vendor code, invisible to the policy file and its reviewers.
- **One process per vendor tenant and credential, each keeping its credential.** A company's connector would fail and leave alone, but every tenant adds a unit, which small boards cannot carry, and the credential would sit at rest in each process. A connection that is opened per call has the same separation without the units.
- **An adapter that calls core for what it needs.** It adds an edge from vendor code to an actor that holds keys or state; published data that the adapter reads through its data port gives the same without the edge.
- **Vendor errors passed through.** Core would parse vendor text, and the text could leak a tenant's data into a caller's response.
- **A stream of pushed facts instead of notify-then-pull.** A forged or reordered push would change core's state directly; a pull reads the vendor's own answer.
- **The `FactsSource` and effector services written now.** Principle 8: nothing without a consumer; the first working version needs no directory and no minter.
- **A tenant's connection as config committed by the operator.** A tenant never appears in config, and a customer's change would wait for review ([0004](/decisions/0004-the-data-model/#who-connects-decides)).
- **Mint for any target a caller names.** It makes sluis a proxy for credentials it cannot govern, and an undeclared target has no bound to limit the grant.
- **Accept a caller's own credential and exchange it.** sluis would hold or forward someone else's standing power, which is the secrets-engine role it has declined ([0009](/decisions/0009-export/)).
- **A minter for AWS and Kubernetes as well, for uniformity.** Both accept sluis as an issuer, so a minter would add a standing credential for nothing.
- **Keep what a minter returns, sealed, with rotation and a sweep.** sluis would become a store of vendor credentials, with their lifecycle to carry; the caller keeps what it is given and asks again.
- **Leave the floor to configuration.** The sharpest credential in the integration would then depend on the care of each installation.
- **Mint without bounds, from the minter's own full rights.** The grant could then not be narrower than the vendor account itself.

## Follow-ups

- Directory sync, the first `FactsSource`: [#805](https://github.com/truvity/sluis/issues/805). Its re-sync cost on boards is in [0037](/decisions/0037-capacity-is-measured-before-it-is-promised/#board-capacity).
- Downstream credentials, the first `CredentialMinter`: [#1011](https://github.com/truvity/sluis/issues/1011); the first minters are GitHub installation tokens [#811](https://github.com/truvity/sluis/issues/811), Cloudflare API tokens [#816](https://github.com/truvity/sluis/issues/816) and R2 credentials [#817](https://github.com/truvity/sluis/issues/817).
- Reconcilers and the `Provisioner` contract: [#1012](https://github.com/truvity/sluis/issues/1012).
- The generic OpenID Connect upstream: [#1106](https://github.com/truvity/sluis/issues/1106).
