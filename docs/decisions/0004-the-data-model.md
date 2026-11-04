# 0004 — Data is resource kinds in a compiled registry, each with an address, one storage class, a treatment, a profile and one writer

**Status:** Accepted
**Date:** 2026-11-03

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

sluis keeps many kinds of data: settings that an operator reviews, settings that a tenant admin changes at run time, secrets that the platform supplies, secrets that sluis generates or receives, sessions and codes that may be lost, facts read from outside systems, and things sluis issues. Each raises the same questions: who may write it, where it lives, whether it is backed up, what a restore does with it, whether it may leave sluis, and what an audit record, a log line or a span may say about it. v1 answered these one kind at a time (v1 ADRs 0018 to 0022, 0036 and 0075, on `master`), and the lists for backup, export, audit and telemetry disagreed.

The store ([0005](/decisions/0005-the-store/)) has to enforce every one of those answers for every actor, and an actor holds no storage credential ([0002](/decisions/0002-families-of-actors/#credential-holders)). The store can do that only if the answers are data it can read: one registry, compiled in, that says what each kind is. A setting that several places can set, such as policy from a reviewed repository, from an operator and from a tenant admin, also needs a rule for how the places combine and in which direction each may move. And a customer that arrives at run time cannot wait for a pull request, so the data model has to say what a tenant may write and within which bounds (principle 17: where a thing is written decides its class).

The shape of every kind is read by many consumers: Go and Rust actors, the TypeScript console, Helm and the reference pages. One schema source keeps them in agreement, and Protobuf is already the wire contract ([0002](/decisions/0002-families-of-actors/#contracts)). A spike measured whether Protobuf, with generated JSON Schema and protovalidate, carries every constraint the data model needs in Go and Rust ([#1177](https://github.com/truvity/sluis/issues/1177), 2026-11-03): protovalidate agrees in both languages, and the JSON Schema is a derived subset ([Schemas are Protobuf](/decisions/0004-the-data-model/#schemas-are-protobuf)).

## Decision

Data is **kinds**. A kind is declared once in the compiled kind registry and has an address, one storage class, a treatment, a profile and exactly one writer. The registry is the one source of the store's rules, the deny matrix, the backup list and the generated reference pages.

### Kinds

- **A kind is a typed resource declared in the kind registry.** It names a Protobuf schema, a scope, one storage class, a treatment, a profile, its layers or links, its declared indexes, its rules (actor × kind × verb) and exactly one writer. A kind that is not in the registry cannot be read or written.
- **The registry is compiled into the binaries that use it.** store@ enforces it ([0005](/decisions/0005-the-store/#rules)); the tests and the generated pages [Kinds](/reference/kinds/) and [Rules](/reference/rules/) read it. Adding a kind is a reviewed change to the registry, and it names its consumer (principle 8).
- **A kind's name is PascalCase** (`DataKeyWrap`); its address segment is the kebab-case form (`data-key-wrap`).
- **A new question about data is a new declared index,** not a query ([0005](/decisions/0005-the-store/#the-store-api)).

The fields of a kind:

| Field | Meaning |
|---|---|
| Schema | The Protobuf message, with its constraints ([Schemas are Protobuf](/decisions/0004-the-data-model/#schemas-are-protobuf)) |
| Scope | `boundary`, or `boundary + tenant` for durable and temp kinds ([The address](/decisions/0004-the-data-model/#the-address)) |
| Class | `config`, `secret`, `durable` or `temp` ([Storage classes](/decisions/0004-the-data-model/#storage-classes)) |
| Treatment | `hashed`, `sealed` or `plain` ([Treatment](/decisions/0004-the-data-model/#treatment)) |
| Profile | `Fixed`, `Operable` or `Tenant-adjustable` for settings; `-` for state that only its writer creates in the course of its job ([Profiles](/decisions/0004-the-data-model/#profiles)) |
| Layer or links | The group and layer of a member of a layered kind, or the kinds it is linked to ([Layered and linked kinds](/decisions/0004-the-data-model/#layered-and-linked-kinds)) |
| Writer | The one actor that writes it, or IaC or the publishing pipeline for config and secret ([One writer per kind](/decisions/0004-the-data-model/#one-writer-per-kind)) |
| Readers and rules | The actors with a get, list or watch rule on it |
| Indexes | The declared lookups besides listing by tenant |
| TTL | Temp: mandatory, with a default and a maximum. Durable: only when the kind carries an expiry field |
| Exportable | `yes` for the kinds exporter@ may watch; set by review ([0009](/decisions/0009-export/#what-is-exportable)) |
| Backed up | `yes` only for authoritative durable kinds |
| Status | `planned` for a kind that is in the registry but has no writer yet |

During the design phase the registry is `docs/architecture/kinds.yaml`. When code exists, Protobuf options on each kind message (`option (sluis.kind) = {...}`) become the source, the YAML is generated from them, and CI checks the two for equality, so the generated pages keep their generator.

### The address

- **The address of an item is `<boundary>/<tenant | ->/<kind>/<id>`.** The address space is flat, not a tree: listing by prefix lists items and creates no scope.
- **Only two scope dimensions exist.** The boundary is always there ([0008](/decisions/0008-boundaries-and-tenants/#boundaries)). The tenant ([0008](/decisions/0008-boundaries-and-tenants/#tenants)) appears only on durable and temp kinds; a config or secret kind never has it. A `-` stands where a kind has no tenant, or where an item belongs to the whole boundary.
- **A kind belongs to the tenant that made it.** What a company connects (its directory, its chat workspace, its code host and its account at a provider that sluis mints for), the app or connection it makes through a UI or API flow, and the directory read through it, are kinds of that company's tenant. The desired state belongs to the tenant that owns the container it describes ([0026](/decisions/0026-reconcilers/#the-desired-state)). The operator's own company is a tenant ([0008](/decisions/0008-boundaries-and-tenants/#boundaries)), so an app the operator makes in the UI lives there. A kind with no tenant in its address is a boundary-wide fact such as a switch, a signing ring or an enrolment token.
- **Actor, module, client and quota are parts of the id,** never scopes: a tunable for `session` is `Tunables` with id `session`, an allowance is `Allowance` with the quota name as id.
- **An id never contains personal data.** It is a random value (128 bits), or a keyed hash of a natural key made by key@ ([0006](/decisions/0006-keys-and-sealing/#sign-and-mac)). A person is found by an opaque subject, never by an e-mail address.
- **An installation is not a scope.** Settings that hold for a whole installation are one signed document that IaC writes, with the same content, into every boundary's config source; no boundary reads another's ([0008](/decisions/0008-boundaries-and-tenants/#installation-wide-settings)).
- **A sealed value is bound to its full address,** so a value moved to another item, kind or tenant no longer opens ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)).
- **The encoding of the segments and their limits** are on the store API reference page.

| Address | Kind | Class |
|---|---|---|
| `prod/-/front-host/default` | `FrontHost` | config |
| `prod/acme/tenant-client/portal` | `TenantClient` | durable |
| `prod/acme/session-chain/<id>` | `SessionChain` | temp |
| `prod/-/lease/adapter-github/sync` | `Lease` | temp |
| `prod/acme/data-key-wrap/data/1/board-a` | `DataKeyWrap` | durable |

### Storage classes

Every kind is in **exactly one storage class**. The classes are mutually exclusive, and the class decides who writes, where the value lives and whether it is backed up.

| Class | Access | Where it lives | Written by | Backed up | Tenant |
|---|---|---|---|---|---|
| **config** | Read-only, signed | A file, a ConfigMap or AWS AppConfig | IaC or the publishing pipeline, under review; sluis never writes config | No: the reviewed source is the copy | Never |
| **secret** | Read-only | A systemd credential or AWS SSM | IaC | No | Never |
| **durable** | Read-write, must survive | The durable engine behind store@ | One actor, through the store | Yes, when the kind is authoritative | If the kind has one |
| **temp** | Read-write, may be lost | The temp engine behind store@ | One actor, through the store | Never | If the kind has one |

- **Where a thing is written decides its class** (principle 17). IaC and the publishing pipeline write config and secrets; sluis writes durable and temp data through the store; sluis never writes config. A setting that comes from several places is split into one kind per place ([Layered and linked kinds](/decisions/0004-the-data-model/#layered-and-linked-kinds)).
- **Config is read-only and signed.** It reaches the store as signed documents, one per config kind, loaded as a whole snapshot ([0005](/decisions/0005-the-store/#configuration-loading)). The tenant dimension never appears on a config kind: a tenant never appears in config.
- **A secret is a value from a secret source,** which holds it in the clear for whoever may read it ([0005](/decisions/0005-the-store/#secret-sources)). A secret that sluis generates or receives is not this class: it is sealed or hashed durable data ([Treatment](/decisions/0004-the-data-model/#treatment)).
- **Durable data must survive.** It has one writer. A durable kind that nothing else can recreate is **authoritative**, and only authoritative kinds are backed up ([0010](/decisions/0010-backup-and-recovery/#what-the-archive-holds)).
- **Temp data may be lost,** and losing it costs a sign-in or a retry, never data. A temp kind has a mandatory time to live with a default and a maximum built in ([0005](/decisions/0005-the-store/#time-to-live)). A fact that a re-sync rebuilds is temp: the directory facts have a 24 h default and a 7 d maximum.
- **Built-in TTL defaults of temp kinds** (maximum in brackets): AuthCode 60 s [10 min], DeviceCode 10 min [15 min], WebAuthnChallenge 5 min [10 min], Lease 30 s [10 min], SpentGrant 2 min [5 min], LogLevelOverride 1 h [24 h], PredefinedPolicyLinkTemporary 1 h [24 h], PendingEnrolment 7 d [30 d]; UpstreamMetadata and VerifierKeyCache follow HTTP caching [24 h]. The other TTLs are in the registry. A tunable may shorten a value and never lengthens it past the maximum.

### Built-in

- **Built-in is what the binary carries,** and it is not a storage class. It changes only with a release, and it is the lowest layer of every layered kind.
- **It holds:** the baseline policies and the predefined policies (break-glass among them); the hard caps (token and session lifetimes, the agent chain at 90 d, the maximum TTL of every temp kind, the maximum cache TTL of key@); the default tunables, log levels, sampling and retention floors; the sign-in methods, algorithms and their floors that a release supports (a software key refuses production, [0006](/decisions/0006-keys-and-sealing/#floors-in-code)); the allowance modes (prepaid, limited, unlimited); the client template defaults; the default slot plan per card model; the audit action table; and the kind registry itself.

### Treatment

Every kind has one treatment. **Sealed** is the default, and a kind is declared otherwise on purpose.

| Treatment | For | The store keeps | Examples |
|---|---|---|---|
| **hashed** | A compare-only secret: it is verified, never read back | The hash. The value never reaches key@ | `SessionChain` (the hash of the current refresh token), `AuthCode`, `ClientSecret` |
| **sealed** | A value that is read back: a provider token, personal data, free text | The ciphertext. The writing actor sealed it at key@ | `Person`, `GitHubApp`, `IssuedCertificate` |
| **plain** | A value that is neither secret nor personal: a switch, a mint target, a counter | The value as it is | `Switch`, `Allowance`, `MinterTarget` |

- **Treatment follows the data.** A kind that holds personal data or free text (names, SSH principals, vendor user ids, the reason of a hold, a requester) is sealed, or hashed when it is compare-only. Plain is only for values that are neither secret nor personal. Each kind declares whether it holds personal data (`personal` in the [kind registry](/reference/kinds/)); a personal kind is never plain. The rule covers what sluis stores, durable and temp. Config is the operator's reviewed, signed document and may name people, as the first-admin allow-list, the people bindings of a policy and the operators' break-glass passkeys do, because recovery and the first sign-in must work without the store.
- **The store never seals or opens.** It keeps ciphertext and hashes as they are. To write a sealed value, the actor asks key@ to seal it and then writes; to read, it asks key@ to open it ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)). The plaintext exists only in that actor, for that call.
- **The writing actor validates a sealed field before it seals it,** because the store cannot read it. The schema of a sealed kind describes the plaintext.
- **An index on a sealed kind holds a keyed hash or a date,** computed by the writing actor (a keyed hash is key@'s `Mac`). An index never holds personal data in the clear.
- **A hash uses an algorithm of the approved set** ([0006](/decisions/0006-keys-and-sealing/#algorithms)); the actor that writes a hashed kind computes it.
- **Config and secret kinds are plain in the registry:** config is protected by its signature and a secret by its secret source. A `DataKeyWrap` value is already ciphertext, so its treatment is plain.
- **A generated or received secret is ordinary data.** A secret that sluis generates (a client secret) or receives (a provider token, an app key) is a sealed durable kind, or a hashed durable kind when it is compare-only. An exportable generated secret is stored twice: a hash to verify it (`ClientSecret`, hashed) and a sealed copy to export it (`ClientSecretExport`, sealed) ([0009](/decisions/0009-export/#what-is-exportable)).
- **Audit redaction and the telemetry allowlist come from treatment:** a sealed or hashed value is never in an audit record, a log line or a span ([0016](/decisions/0016-telemetry/), [0030](/decisions/0030-audit-records-and-the-usage-stream/)).

### Profiles

A **profile** says which layers may set a kind's value. It classifies settings, not protocol state: a kind that only its writer creates in the course of its job (a code, a session chain, a certificate record) has profile `-`.

| Profile | Layers | Written at run time by | Examples |
|---|---|---|---|
| **Fixed** | Built-in and config | Nobody: no write path at run time. A change is a reviewed, signed document | Installation shape, trust, the key plan, tunables, login domains, rate bounds, upstreams made by hand or IaC |
| **Operable** | Built-in and config, and an operator at run time | An operator, through the console, routed to the owning actor. The kind may be boundary-scoped or tenant-scoped, for example a hold on one tenant's person | Log levels and their overrides, switches, retention and holds, apps made through a UI flow |
| **Tenant-adjustable** | Built-in and config, and the tenant | A tenant admin, or a product for its tenant, inside bounds declared in config, only in its own tenant, with a grant sealed for that tenant | Policy links, token lifetimes, sign-in methods, clients, branding, the allowance |

- **A bound is a limit declared in config (or built in) that a higher layer may not cross,** such as the redirect hosts a client template allows or a cap on a lifetime. The store reads the bound and refuses an out-of-bound write ([0005](/decisions/0005-the-store/#rules)).
- **A kind may carry a field that a tenant sets within a bound.** A tenant may lower the rate limits of its own clients: those are fields of `TenantClient`, checked against `RateBound` on write. The mint targets of a tenant (`MinterTarget`) are checked against `MinterBounds`, which says which target types and maximum lifetimes an installation allows.
- **A product writes through the same Tenant-adjustable path as a tenant admin,** for its own tenant; what it may write is a policy decision ([0007](/decisions/0007-policy-and-sealed-grants/)).
- **A tenant admin or a product creates an instance under a template.** A client template in config says which slots an instance may fill and the bound on each. The instance is durable data, written by its one owner after policy has decided, and it holds no authority the template did not carry: no new grant name, no claim and no logic ([0021](/decisions/0021-clients/)).

### Layers and the direction rule

The layers of a setting, lowest first, are **built-in**, **config**, **operator** (at run time) and **tenant**. All four apply to policies only. Every other kind uses a subset: lifetimes and sign-in methods use built-in, config and tenant; log levels use built-in, config and a run-time override per boundary, actor and module, never per tenant; keys are built-in limits plus config.

- **The direction rule:** a higher layer tightens freely; it loosens only as far as the layer below allows; a run-time loosening carries an expiry (principle 12).
- **The store checks the rule when a value is written,** and refuses a write that loosens past the layer below ([0005](/decisions/0005-the-store/#rules)). It composes the layers on read, so a bound that config tightens applies at once to values already written. A read of a layered kind returns the effective value with its provenance ([0005](/decisions/0005-the-store/#the-store-api)).
- **A tightening takes effect at once and is durable:** a revocation, a shorter lifetime, a stricter sign-in, a paused job. Deleting a switch returns the value to config, which is not a loosening.
- **A loosening that is made at run time expires.** It is a temp kind with a built-in default and a maximum: a debug log level (`LogLevelOverride`, 1 h, at most 24 h), a break-glass link (`PredefinedPolicyLinkTemporary`, 1 h, at most 24 h). Making a loosening permanent goes through the reviewed path that sets the layer below.
- **A restore never loosens what was tightened after the archive was taken** ([0010](/decisions/0010-backup-and-recovery/#roll-forward)).

#### What a loosening is

- **A loosening makes the effective value more permissive than what the layer below grants.** A client template is config's grant to the tenant layer, so a link inside a template is within the bound: it is durable, and it needs no expiry.
- **Linking a predefined policy that grants beyond config is a loosening** (break-glass recovery is the example), so it is a temp kind and expires. A predefined link that only tightens is durable.
- **A regulated party's policy** is signed by the party as well as the publisher ([0005](/decisions/0005-the-store/#signed-config-documents)).

#### Branding is exempt

Branding has no tighter or looser direction, so it is exempt from the direction rule: the most specific layer wins, bounded by config (allowed assets, hosts, content security policy).

### Layered and linked kinds

**A layered kind is a setting split into one kind per layer,** each in its own class and with its own writer. The store composes the layers by a **combine rule** into one effective value and checks the direction rule on every write. A group offers one effective read, for example `EffectivePolicySet(boundary, tenant)`, which returns every layer's part with its version.

| Group | Profile | Built-in | Config | Operator | Tenant | Combine rule |
|---|---|---|---|---|---|---|
| Policies | Tenant-adjustable | Baseline and predefined policies | `Policy`, `RegulatedPartyPolicy` | `PredefinedPolicyLink`, `PredefinedPolicyLinkTemporary` | `PolicyLink` | Union; a Cedar forbid anywhere wins |
| Token lifetimes | Tenant-adjustable | Hard caps | `TokenLifetime` | | `TokenLifetimeTenant` | Shortest wins |
| Sign-in methods | Tenant-adjustable | The methods a release supports | `SignInMethods` | | `SignInMethodsTenant` | Intersection |
| Logging | Operable | Default levels and sampling | `LogSettings` | `LogLevelOverride` | | The unexpired override wins |
| Retention | Operable | Retention floors | `Retention` | | | Within bounds |
| Tunables | Fixed | Defaults and hard limits | `Tunables` | | | Within bounds |
| Branding | Tenant-adjustable | The default theme | `Branding` | | `TenantBranding` | The most specific wins |
| Rate bounds | Fixed | Maximum rates | `RateBound` | | | Within bounds |

- **Union with forbid-wins** compiles every layer's policies into one Cedar set, so a forbid anywhere wins and the built-in baseline holds ([0007](/decisions/0007-policy-and-sealed-grants/#four-layers)).
- **Shortest wins** takes, field by field, the shortest duration of any layer. A tenant write longer than config is refused at the store.
- **Intersection** keeps the methods every layer allows. A higher layer may remove a method or require a stronger one.
- **The unexpired override wins;** otherwise config; otherwise built-in.
- **Within bounds** takes the config value and refuses it at load when it is outside the built-in bounds.
- **The most specific wins** for branding: tenant client, then tenant, then installation client, then the boundary default.
- **Holds are linked, not layered.** `ErasureHold` and `PersonHold` stop an erasure while they exist; they do not change a retention value.

**Linked kinds** refer to each other by id, each in exactly one class. The store does not join them: an actor that needs two reads two. A write that names a linked item is checked where the registry says so (a `PolicyLink` names a template that exists in config).

The worked example is a chat app:

| Kind | Class | Scope | Treatment | Writer | What it holds |
|---|---|---|---|---|---|
| `SlackApp` | config | boundary | plain | IaC | App id, client id, scopes, redirect URL; made once by hand or IaC |
| `SlackAppSecret` | secret | boundary | plain | IaC | The app's client secret, from a secret source |
| `SlackConnection` | durable | boundary + tenant | sealed | `adapter-slack` | Workspace id, bot user, granted scopes and the bot token, made by the install flow |
| `SlackInstallState` | temp | boundary + tenant | hashed | `adapter-slack` | The state of an install in progress; 10 min |

### One writer per kind

- **Every kind has exactly one writer.** For a durable or temp kind it is an actor, named in the registry, and the store refuses any other caller. For a config or secret kind it is IaC or the publishing pipeline, outside sluis. Every writer and reader in the registry is an actor name; an integration is an adapter named `adapter-<vendor>` ([0025](/decisions/0025-integrations/)).
- **The store knows the caller from the transport,** never from the request ([0003](/decisions/0003-units-transports-and-fusion/#transports)). A work actor's own code is not the check: a compromised actor cannot write what its rules refuse.
- **Two named exceptions.** The first is the restore command of store@ (`sluis restore`), which writes back the kinds it restores and writes `MaintenanceMode` ([0010](/decisions/0010-backup-and-recovery/#restore)). The second is the **declared self-scoped kind**: `Lease`, `ReplayGuard` and `SpentGrant` have an id that starts with the writing actor's name, and the store lets each listed actor write only ids under its own name, so one writer per item still holds.
- **The console writes exactly two kinds itself,** `Switch` and `LogLevelOverride`. It checks the operator's delegation and routes every other write to the owning actor, which validates it with its own logic ([0027](/decisions/0027-the-console/#writes)).
- **Writers of tenant settings.** exchange owns what a tenant has configured: `Tenant`, `TenantClient`, `ClientSecret`, `ClientSecretExport`, `TenantBranding`, `TokenLifetimeTenant`, `SignInMethodsTenant`, `PolicyLink`, `PredefinedPolicyLink` and `PredefinedPolicyLinkTemporary`. session owns everything about people: the person kinds. The adapter that completes a browser flow owns what the flow makes: `GitHubApp` (`adapter-github`), `SlackConnection` (`adapter-slack`), `EntraConnection` (`adapter-upstream-oidc`). The adapter that completes a connect flow owns the connection it makes, under ids that start with its own name: `DirectoryConnection` (`adapter-upstream-oidc` for Google Workspace and Entra, `adapter-github` for a GitHub organisation), `MinterConnection` and `MinterTarget` (the adapter of the provider).
- **Other writers follow the actor that holds the thing:** key@ writes `DataKeyWrap` and `KeyCertificate`, ca writes `TrustBundle`, store@ writes `MaintenanceMode`, exporter@ writes `ExportCursor`.
- **Every run-time write is authorised for a concrete person or caller** and audited under that name.

### The upstream criterion

An upstream or provider app is classed by how it is made.

| How the app is made | Class | Example |
|---|---|---|
| By hand or IaC on the provider side, one app for the whole installation | Config, with its secret in a secret source | `Upstream` and `UpstreamSecret`; `SlackApp` and `SlackAppSecret` |
| By a browser round trip in the UI (an app install, a bot install, a per-customer admin consent) | Durable | `GitHubApp` (the manifest flow), `SlackConnection`, `EntraConnection` |
| A tenant's connection to a provider: its directory, its code host, its chat workspace, its account at a provider that sluis mints for | Durable, per tenant, credential sealed | `DirectoryConnection`, `GitHubApp` and `GitHubInstallation`, `SlackConnection`, `MinterConnection` |

- **The criterion applies to every connection made in the UI, the operator's own included.** A hand- or IaC-made app is config plus a secret source, and config never has a tenant. A flow that needs a browser round trip is run in the UI by the adapter that completes it, and what it makes is durable, with its secrets sealed, and **belongs to the tenant that ran the flow**: `GitHubApp`, `GitHubInstallation`, `SlackConnection` and `EntraConnection`, with the state of the flow in progress (a temp kind) in the same tenant. An operator who makes a GitHub App in the UI makes it in the operator's own company, which is a tenant.
- **An app and a connection are two things.** A provider app that serves the whole installation (`SlackApp`, `Upstream` as a multi-tenant app, and their secrets) stays config and secret at the boundary. Every connection of a tenant to a provider is a durable kind of that tenant with its credential sealed, made through the UI or the API: a directory (Google Workspace, Entra or a GitHub organisation), a Cloudflare account, a Slack workspace, a GitHub organisation or app. The company that runs the installation is a tenant of it, so its own connections are durable too.
- **An IaC tool that writes through the API makes durable data, not config.** IaC may create a connection by calling the API; where a thing is written decides its class ([principle 17](/principles/#17-where-a-thing-is-written-decides-its-class)), and a write through the store's API lands in a durable kind of the tenant. Config stays what IaC commits as a signed document.
- **Linked kinds carry the difference.** The app is config, its secret a secret, its connection per tenant durable and the install in progress temp, and the directory facts a connection reads are temp kinds of the same tenant ([Layered and linked kinds](/decisions/0004-the-data-model/#layered-and-linked-kinds)).

#### Who connects decides

A tenant's connection to its directory, chat workspace or code host is **always durable data** (`DirectoryConnection`, `SlackConnection` and the other connection kinds), entered through the UI or the API, with its credential sealed. It is never config committed by the operator: a tenant never appears in config, and a customer's change does not wait for review. A tenant has no connection to its identity provider in sluis: the upstreams are the operator's config, and a customer installation's one upstream is the broker that holds the tenants' providers ([0033](/decisions/0033-customer-connections/#which-upstreams-an-installation-has)).

### Schemas are Protobuf

- **Protobuf is the only schema source.** Each kind is a Protobuf message, and its constraints are protovalidate rules. The wire contracts are Protobuf over ConnectRPC ([0002](/decisions/0002-families-of-actors/#contracts)); Go and Rust types are generated from the same messages.
- **Protobuf with protovalidate is the authority in code. JSON Schema is a derived subset,** generated from the messages for editors and `helm lint` on what is not on the wire: Helm values, the bootstrap file ([0005](/decisions/0005-the-store/#the-bootstrap-file)) and external configs. It is draft 2020-12, post-processed after generation, committed as a golden file that CI compares, and part of the public API.
- **Each schema has a stable `$id`,** a URL on the sluis site with its version in the path. A published identifier never changes; an incompatible change is a new version under a new path, beside the old one ([0013](/decisions/0013-release-train-packaging-and-distribution/#compatibility-between-releases)).
- **Validation is protovalidate in Go and hand-written checks of the same rules in the Rust kit,** with shared conformance vectors ([0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table)). A validator that disagrees fails the build, and each real disagreement adds a vector. The schema is embedded in each binary that loads it, and every binary validates a document against it before decoding.
- **Strictness comes from the schema.** An unknown key is an error that names the path. An error never shows the value. A retired field in a signed config document is refused; a retired field in an item that sluis wrote is read, ignored and never written again, because refusing it would make an installed item unreadable.
- **The JSON Schema agrees with protovalidate on every constraint it can express** ([#1177](https://github.com/truvity/sluis/issues/1177), MEASURED 2026-11-03). Only protovalidate enforces cross-field CEL rules, duration and timestamp ranges, exact byte lengths, the strictness of `uri`, and the refusal of non-canonical proto3 JSON spellings, so a document that the JSON Schema accepts can still be refused at load.
- **Durations in configuration files are written with a unit:** one whole number and one of `s`, `m`, `h` or `d` (`900s`, `15m`, `12h`, `30d`), with no fraction and no compound. The loader converts them to a Duration, and the generated schema checks the pattern `^[0-9]+(s|m|h|d)$`. In a value that is not a configuration file a duration is a proto3 JSON duration, such as `30s`.
- **Pkl is not used.** <!-- terms-allow: pkl -->

### What is not data

These are not kinds. The registry does not list them, and an actor cannot read or write them through the store.

| Not a kind | Where it lives instead |
|---|---|
| Authority keys and wrapping keys | In their key store (a card or KMS); key@ uses them in place ([0006](/decisions/0006-keys-and-sealing/#key-purposes)) |
| Opened data keys | In key@'s memory only, with a TTL per entry ([0006](/decisions/0006-keys-and-sealing/#data-keys)) |
| Sealed grants | In flight only; a one-shot use leaves a `SpentGrant` hash ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)) |
| Audit records, usage facts, checkpoints, the writer's state and the search index | In the audit family ([0028](/decisions/0028-audit-pieces/), [0029](/decisions/0029-the-audit-log/)). Audit's own documents are config kinds (`AuditLog`, `AuditWitnesses` and `AuditCatalogue`), loaded by the store like the rest |
| The bootstrap file | store@'s own local file ([0005](/decisions/0005-the-store/#the-bootstrap-file)) |
| The credentials of the holders | The engine login and secret-source access of store@, the destination credentials of exporter@, key@'s PIN or KMS permission and the audit blob credential: platform-provided (a systemd credential, an IAM role, a service account), never served to an actor |
| Minted credentials | Never recorded |
| Backup archives | In the backup bucket; each archive's provenance is a `backup.completed` audit fact ([0010](/decisions/0010-backup-and-recovery/)) |
| Exported copies | In the destinations exporter@ writes ([0009](/decisions/0009-export/)) |
| Telemetry settings | Exporters, endpoints and resources: the standard `OTEL_*` environment variables only; the log level and the trace sampling are the layered kind `LogSettings` ([0016](/decisions/0016-telemetry/)) |
| Product-side data | Plans, prices, money balances, organisations, memberships, consent evidence, customer accounts and their credentials, end-user passkeys: the product's, never sluis's |

## Consequences

- One registry answers who writes, where a value lives, whether it is backed up, what a restore does with it, whether it may leave sluis and what audit and telemetry may say. The lists each part kept by hand are generated from it: the deny matrix, the backup list, the export list, the audit redaction and the telemetry allowlist.
- A customer is onboarded, changed and removed with no pull request, no deployment and no operator. Every change is an audited item inside a bound that a reviewer has read, so the reviewed surface stays small: templates and bounds, not one entry per tenant. A stolen tenant-admin session can tighten and change that tenant's settings inside the bounds, and cannot widen anything past them.
- A new setting costs a kind in the registry, a class and a writer, and a setting with layers costs one kind per layer. The cost is accepted so that the store, and not each actor's code, enforces ownership and direction.
- Sealed fields cannot be searched. A question over sealed content needs an index of keyed hashes designed with the kind.
- Temp kinds can be lost, so every writer treats them as such: a lost `SessionChain` costs a sign-in.
- The effective value of a layered kind is composed on read, so a store read of a layered group costs a read per layer. The store caches the config layers in its snapshot.
- Moving a v1 installation is part of the cutover tooling of the parity milestone ([#1017](https://github.com/truvity/sluis/issues/1017)).
- The pages that follow are [Data](/concepts/data/), [Kinds](/reference/kinds/) and [Rules](/reference/rules/); the last two are generated from the registry.

## Roads not taken

- **Pkl as the schema source, with JSON Schema generated from it.** It is a second language beside the Protobuf that the wire contracts need anyway, and the tool is about 95 MiB; Protobuf with protovalidate says the same constraints in one language. <!-- terms-allow: pkl -->
- **Hand-written JSON Schema as the source.** Helm schemas and the reference pages would be written again from it and drift.
- **CUE as the source.** A third language for a job that Protobuf and protovalidate already do.
- **A five-way classification by how a value came to be (written by hand, set by an operator, observed, rebuilt, issued).** It mixed where a value lives with who wrote it, so one setting needed rules from several classes, and the lists for backup and export kept disagreeing. The storage class is decided by where the value is written.
- **A level per field (public, internal, personal, secret).** Every field of every kind would need a reviewed annotation, and the store cannot tell a sealed field from a plain one. Treatment per kind is enforced without parsing the value.
- **An installation as a scope.** A boundary could then read another boundary's data. One signed document written into every boundary keeps each boundary's reads inside itself.
- **One kind per setting with a layer field.** The store could not give each layer its own class, writer and backup, and a config layer could not be read-only beside a writable tenant layer.
- **Several writers for one kind, or one kind per writer for leases and replay caches.** Several writers lose the check that one actor owns the item. One kind per writer multiplies near-identical kinds, and every new job adds one; the declared self-scoped kind keeps one writer per item.
- **Tenant connections as config committed by the operator.** A tenant would appear in config, and every customer single sign-on change would wait for a review.
- **Connections of the operator's own company as config, because the company is the operator.** It would make the operator's directory, chat workspace, code host and DNS account a second shape of the same thing: a connection made in the UI and one made by IaC would live in different classes. The company is a tenant of its installation, and its connections are durable like any tenant's.
- **A commit by a pipeline for every tenant change.** A review and a deployment for each customer change, and a config source that grows with every customer.
- **Treating a tenant's branding as a loosening that expires.** Branding has no tighter or looser direction, so the rule would be absurd.
- **The console writes every operator and tenant-admin kind, or routes every write including switches and log overrides to an owner.** The first loses the owner's domain validation for clients, connections and links; the second needs a split of switches per owner, and `LogLevelOverride` has no owner at all.
- **Config seeds a value and the console overrides it, or the last writer wins.** The reviewed source would no longer show the effective value, and a change on either side could erase the other silently (v1 ADR 0020 removed exactly this take-over).

## Follow-ups

- The schema fidelity spike reported on 2026-11-03; its post-processor, the golden file and the shared vectors land with the first schemas: [#1177](https://github.com/truvity/sluis/issues/1177).
- The cutover of a v1 installation's configuration: [#1017](https://github.com/truvity/sluis/issues/1017).
