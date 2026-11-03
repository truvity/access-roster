# 0004 — Configuration is defined once in Pkl and shipped as JSON Schema, and every record kind has an origin and every field a sensitivity

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

The shape of sluis's configuration is read by many consumers: Go actors, Rust actors and drivers, the TypeScript console, Helm and the reference documentation. If each keeps its own description of the shape, they drift, and the first sign is an installation that starts with a field one of them ignored. v1 settled half of this: one file, validated at start against a JSON Schema that ships with the release, with stable schema identifiers (v1 ADRs 0057, 0063 and 0069, on `master`). v1 then had to move its identifiers twice, with aliases, because archived documents carried the old names.

The Pkl command-line tool is about 95 MiB and the Go binding starts it as a child process, which does not fit a small board, a serverless function or an actor that may not start a process ([0003](/decisions/0003-units-transports-and-fusion/)). JSON Schema has no single validator for Go, Rust and TypeScript, so each language needs its own and they must agree.

sluis also keeps many kinds of data: the install file and policy, records an operator sets on the console, facts read from directories and vendors, an index built from its own log, and things it issues, from client secrets to sessions. Each raises the same questions: who may write it, where it lives, whether it is backed up, what a restore does with it, whether it may leave sluis, and what an audit record, a log line or a span may say about it. v1 answered these one kind at a time (v1 ADRs 0018 to 0022, 0036 and 0075, on `master`), and the lists for backup, export, audit and telemetry disagreed. This record gives all of them one classification, written in the schema.

## Decision

### Pkl and JSON Schema

- **The shape of the configuration is defined once, in Pkl, and Pkl runs at build time only.** There is no Pkl at run time.
- **The build generates from the Pkl sources:** a JSON Schema in draft 2020-12, which is part of the public API; the Helm values schemas, in the dialect Helm's checker accepts; and the reference documentation. Where Pkl has no generator, a separate open-source tool fills the gap; it is a build detail. Generated artifacts are committed and CI fails on a stale one.
- **Go and Rust types are hand-written** behind the JSON Schema check, and the shared vectors prove that they agree with the schema. A small generator for them comes later, when it pays for itself.
- **The schema is embedded in each binary** that loads configuration.
- **Each schema has a stable `$id`**, a URL on the sluis site with its version in the path. A published identifier is never changed; an incompatible change is a new version under a new path, beside the old one. Identifiers and versions are public contract, under the release rule of [0013](/decisions/0013-release-train-packaging-and-distribution/#compatibility-between-releases).
- **One validator per language, with shared conformance vectors.** Go uses `santhosh-tekuri/jsonschema/v6`, Rust the `jsonschema` crate, TypeScript `ajv` in its draft 2020-12 build. Each vector is a document with the expected verdict and error path; a validator that disagrees fails the build, and each real disagreement adds a vector.
- **Strictness comes from the schema.** `unevaluatedProperties: false` makes an unknown key an error that names the path, and format assertions are on. A duration is an ISO 8601 duration, the `duration` format of JSON Schema, pinned by a `pattern` wherever the validators disagree ([the install file](/reference/install-file/#format) has the detail). Errors never show the value.
- **Retired fields:** a retired option set in a declared document is refused. A retired field in a record that sluis wrote itself is read, ignored and never written again, because refusing it would make an installed record unreadable.
- **Telemetry is not configured in the file.** It is configured by the standard `OTEL_*` environment variables only and exported as OTLP over HTTP with protobuf. The schema has no telemetry keys, and a span or a metric never carries what an audit record says. The telemetry conventions, among them the generated allowlist, are [0016](/decisions/0016-telemetry/).
- **The install file is the document the schema describes.** "Installation" is not a key of it ([0008](/decisions/0008-boundaries-and-tenants/)).
- **A v1 configuration file does not carry over unchanged.** Moving a v1 installation is part of the cutover tooling of the parity milestone, tracked in [#1017](https://github.com/truvity/sluis/issues/1017).

### Origins

- **A record kind declares one origin, in the schema.** A record kind is the unit that has one writer; origin is a property of the kind, never of one field. A domain object with parts of several origins is split into kinds: an OIDC client's definition is declared, its generated secret versions are issued.
- **The audit log and non-extractable keys are outside the model.** The log is the record itself ([0029](/decisions/0029-the-audit-log/)); a key never leaves its store ([0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place)).

Ask in order; the first "yes" is the origin.

1. **declared**: written by an operator in a reviewed file (git or infrastructure as code) or, for per-customer defaults, in the project configuration of the configuration service ([0047](/decisions/0047-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/)), and delivered read-only. Examples: the install file, policy, clients and resources, exchange trust, PKI roles, internal-group bindings, integration declarations, quota limits and enforcement rules, backup and export recipients, the card slot map override, tunables.
2. **operator-set**: chosen by a person at run time, through the console, the CLI or the API, as a lasting intent, for the kinds that accept it. Examples: chat channels managed from the console, the owner of a connected workspace, runtime switches (recovery off, a paused reconciler, an acknowledged breaker), a directory tenant connected from the console, a quota limit lowered below the declared one, a secret put at run time.
3. **learned**: observed in an external system and rebuildable from it without a person, by pull or by push. Examples: directory users, groups and memberships, workspace members, discovered channels, the installed-Apps list, the client metadata document cache.
4. **derived**: rebuilt from sluis's own records or log; verification never trusts it. Examples: the search index and its cursor, quota meters and hourly aggregates, desired-state projections.
5. **issued**: sluis created it, or a vendor or a person handed it over once; **durable** or **ephemeral**.
   - Durable: generated client secret versions and their rotation metadata, revocations and revocation state, the certificates that the hand-off returns ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)), held by the actor that installed them, vendor-issued secrets (an App private key, a bot token), pins (the workspace at first install, the first subject, an App id and installation id), account links, approvals and consents, quota balances and top-ups.
   - Ephemeral: sessions, refresh tokens and their spent markers, authorization and device codes, pending sign-in state, short-lived minted credentials, leases, dedupe records, the maintenance flag.
- **A grant is not a stored record.** It is a sealed output of `policy` in flight ([0006](/decisions/0006-keys-and-sealing/#grants-are-sealed-not-signed)).
- **An act is not configuration.** An approval, a confirmed held removal, a consent or an account link is an issued record of that act; a lasting choice is operator-set.
- **A supplied secret is not an origin of its own.** A secret **referenced** from a declared field lives in the operator's own store and sluis never archives it. A secret **put** at run time (`sluis secrets put`, a paste on the console) is an operator-set secret in sluis's own store, the only copy, so it is backed up.

Where each origin lives and who writes it:

| Origin | Where it lives | Its writer |
|---|---|---|
| declared | A configuration source: files, a ConfigMap, a Lambda layer, AWS AppConfig; signed fragments merged by the scope each publisher owns; digest-addressed blobs for desired state | Nobody at run time; the operator, through review and deployment |
| operator-set | `state`, a namespace per kind, revisioned, compare-and-set; secret parts behind `secrets` | The owning actor of the kind, on a request through the console API |
| learned | `state`, in the observing integration's namespace, with the time observed and a maximum age; or memory | The integration actor that observed it |
| derived | `index`; `state` for meters and projections; caches | The deriving actor (the indexer; `quota` for meters) |
| issued, durable | `state` records; `secrets` for values; `blob` for published revocation lists and the issuance log of `ca` | The issuing actor, one per kind |
| issued, ephemeral | `state` with a short lifetime; memory | The protocol's owner (`session` for sessions and codes, `exchange` for enrolments, the lease holder) |

- **Every operator-set kind has one owning actor, and it is that kind's only writer.** The `console` actor behind `entry` ([0041](/decisions/0041-core-actors-with-one-responsibility-each/#the-actors)) checks the operator's delegation and routes each write to the owner, which validates it with its own logic. The manifest declares which kinds accept operator-set writes, and the state backend refuses any other writer ([0005](/decisions/0005-the-store/#one-writer-per-kind)).
- **Namespaces are per origin and trust class.** When pieces share driver instances, operator-set records, learned facts, issued records, sessions and quota state sit in separate namespaces, and the deny matrix generated from the origin annotation keeps each writer to its kind.
- **No actor writes learned and operator-set data of the same object.** Facts observed and an operator's choices about the same object are two kinds with two owners.
- **Every operator change is authorised for a concrete person** and audited under that person's name; there is no extra signature on an operator write in 2.0.
- **Push is notify, then pull.** A small notification reaches `entry`, which routes it to the integration; the integration reads the full state from the product's API, and a periodic full re-sync runs as well. The pushing product authenticates with its workload identity and may touch only its own organisations. A SCIM 2.0 server is a later option.

Precedence:

- **Declared locks.** A declared value is effective, the console shows the field as locked, and an operator write to it is refused. Otherwise the order is declared, operator-set, schema default.
- **Tighten-only switches are the one exception.** An operator may move a tighten-only field in its safe direction even when declared sets it (recovery off, a reconciler paused, a lower quota limit). Moving it back is a declared change that names a new **generation**, so a stale document cannot undo a tightening.
- **An object defined twice is held.** If one identity exists as declared and as operator-set, nothing changes on it, and the console and `sluis config check --live` report it. The console refuses to create a record that declared already defines.
- **Adoption is explicit.** A declared fragment may carry `adopts: <kind>/<id>@<revision>`; at that revision sluis retires the operator-set record in one audited step, otherwise both stay held.
- **Two declared fragments for one object** are resolved by scope ownership: the fragment that writes outside its publisher's scope is refused.
- **Learned never configures.** A declared key for a learned value is refused at load. A mismatch between a declared expectation (an App's permissions, a bot's scopes) and what the vendor granted is drift: reported, and a pass that would act on it is held.
- **Pins refuse.** An issued pin that a later observation contradicts makes sluis refuse and revoke, not learn again.
- **A console action that cannot be undone is an explicit opt-in**, off by default and checked against the vendor first.
- **The effective configuration is declared overlaid with operator-set.** Learned and issued data are referred to by configuration, not part of it.
- **Authority is declared.** A field marked as authority accepts only declared: every input of `policy`, every claim of a token or credential, internal-group bindings, infrastructure grants, exchange trust, PKI roles, the installation's own OIDC clients and console roles. Two things are issued under it at run time, each inside a declared delegation policy and never beyond what a declared template allows: template-linked Cedar policies ([0007](/decisions/0007-policy-and-sealed-grants/#template-links)) and instance records such as tenants, accounts, upstream connections and tenants' clients ([0047](/decisions/0047-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/#instances-are-issued-under-declared-templates)). Tighten-only actions such as suspending a subject or revoking a grant take effect at once. The console can render operator-set records or an authority change as a declared fragment for review ("promote to declared").

Declared configuration and live reload:

- **Layers apply inside declared only:** defaults, runtime, install file, environment overrides; a later layer overrides an earlier one. Operator-set is an origin, not a layer.
- **The install layer can come from several sources** (files, a ConfigMap, a Lambda layer, AWS AppConfig), put together and trusted by the rule of [0057](/decisions/0057-configuration-sources-are-a-port-sources-own-disjoint-paths-authority-is-signed-and-a-failing-source-keeps-the-version-in-force/).
- **Declared configuration may live-reload as whole versioned snapshots**, from a file, a ConfigMap, a Lambda layer or AWS AppConfig. A new snapshot is validated as `sluis config check` does, swapped atomically and audited with its digest; a failing snapshot is refused and the version in force stays. Which paths a reload may change is the rule of [reload classes](/decisions/0004-the-data-model/#reload-classes).
- **Operator-set values are read live**, through `state` with a short cache whose lifetime is part of the field's schema.
- **Tunables and runtime switches are kept apart.** Tunables (log level, timeout, driver choice) are declared and may come from an environment override. Runtime switches are operator-set, tighten-only where they touch safety. Neither reaches authority.
- **`sluis config check` and `explain` are offline by default**, as CI runs them. With `--live` they read operator-set records through the console API, list held objects, and show each field's effective value, origin, layer and, for an operator-set value, who set it and when.

### Reload classes

One rule says what a reload may change, for every runtime and every source:

- **Every path of declared configuration is in one of two classes.** A `live` path is applied on reload, in the running process, without a restart. A `restart` path is applied only by a restart; a reload that changes one is refused.
- **The class is a property of the path, written in the schema** as `x-sluis-reload: live` or `restart`, beside the other annotations ([below](/decisions/0004-the-data-model/#sensitivities)). The class of a path is that of its nearest annotated ancestor; the root is `restart`. So a key that no one has argued for is `restart`, and a pull request that adds a key says its class.
- **Ask one question per path: does changing it need a new process, a new key handle or a new connection pool?** If yes, it is `restart`. If the running process can read the new value on its next use, it is `live`. Wiring is `restart`: what a process is, where it listens, which keys and stores it holds, which drivers it runs, whom it trusts and where it reads from. Declared data is `live`: who a client is, what policy says, which grants and roles exist, how an upstream is reached. Where the answer differs inside one area, the annotation sits on the smaller subtree.
- **A change is a difference at a path.** The path is the shallowest one that differs: a mapping entry that is added or removed is one change at the entry, so a new boundary is `restart` although its `clients` are `live`. A sequence is one value, as in [composition](/reference/config-sources/#composition). The classes by area are in [the install file](/reference/install-file/#which-keys-reload).
- **A reload that changes any `restart` path is refused as a whole.** The version in force stays, none of the `live` changes in the same snapshot is applied, and the refusal is audited with the digest of the snapshot and the paths that need a restart, never their values. It is reported once for each refused digest, not at every poll. A restart reads the snapshot at start, where every class applies.
- **`sluis config check` names the paths of a change that need a restart,** against the previous version it is given ([how](/reference/cli/#sluis-config-check-and-explain)), so a pipeline learns it before it publishes.
- **A tighten-only field is `live`.** `x-sluis-tighten-only` and `x-sluis-reload: restart` on one field fail the schema check. A brake does not wait for a restart (the tighten-only rule under Precedence, above).
- **Operator-set values are outside the rule:** they are read live through `state`, as above.
- **Where the changes go.** Put the `restart` paths in the install file, which a restart or a new function version deploys, and let the sources own paths that are `live`. `sluis config check` warns about a source that owns a `restart` path. How a runtime restarts is its own: a new function version on Lambda, a rollout on Kubernetes, a service restart on bare-metal.

### Sensitivities

| Level | Meaning | In audit records | In telemetry | In logs (stderr) | In `config explain` |
|---|---|---|---|---|---|
| **public** | Meant to be published: key sets, CA certificates, discovery, trust bundles | yes | only if allowlisted | yes | yes |
| **internal** | Not published, personal or secret: client ids, channel names, App ids, digests, revisions | yes | only allowlisted identifiers of bounded cardinality | yes | yes |
| **personal** | About an identifiable person: an email, a subject, a group membership, a display name | yes, pseudonymised ([0029](/decisions/0029-the-audit-log/#pseudonyms)) | never | redacted by default | only to roles that may see it |
| **secret** | Credential material that is read | never; a fingerprint and a revision only | never | never | the reference only |

- **A field may carry the free-text flag**, for text a person typed. Free text never enters telemetry, and its length in an audit record is bounded.
- **A secret lives behind the `secrets` port**, never as a plain record in `state`; a sealed-state driver keeps ciphertext in `state` and is a `secrets` driver ([0005](/decisions/0005-the-store/#sealed-secrets)).
- **Personal data in an archive is reachable by erasure**: crypto-shredding reaches backups as well as live records.
- **The annotations are in the Pkl source and the generated JSON Schema**, checked in CI. The backup list, the deny matrix, the telemetry allowlist and the audit redaction are generated from them:

| Annotation | Values | Drives |
|---|---|---|
| `x-sluis-origin` (kind) | declared, operator-set, learned, derived, issued | writer rule, precedence, backup, restore order |
| `x-sluis-durability` (issued kinds) | durable, ephemeral | backup, invalidation on restore |
| `x-sluis-sensitivity` (field) | public, internal, personal, secret | port, audit redaction, telemetry allowlist, log redaction, `explain` |
| `x-sluis-free-text` (field) | true | telemetry exclusion, audit length bound |
| `x-sluis-authority` (field) | true | declared only |
| `x-sluis-accepts` (field) | a list of origins | precedence |
| `x-sluis-tighten-only` (field) | the safe direction | the one override of declared |
| `x-sluis-reload` (path) | live, restart | what a reload may change ([reload classes](/decisions/0004-the-data-model/#reload-classes)) |
| `x-sluis-external` (kind) | the export kind | `export` port, consumer grants |
| `x-sluis-restore` (kind) | replace, union, skip | restore merge |
| `x-sluis-roll-forward` (kind) | true | the audit record of each write carries the full value apart from secrets |

### Audit and telemetry by origin

| Origin | What the audit log records | Telemetry |
|---|---|---|
| declared | At each start and reload: the digests of the fragments and of the policy, not their content | Allowlisted identifiers and digests |
| operator-set | Every create, update, delete and refused attempt: the person, actor, kind, id, previous and new revision, the full new value apart from secret parts, and the reason. A secret part is a fingerprint and a revision | Counts only |
| learned | Each pass and its outcome, with a digest and counts. A decision that used a fact records the fact, personal data pseudonymised | Counts only |
| derived | Not per item; the indexer's cursor | Allowlisted aggregates |
| issued, durable | Every issuance, rotation and revocation, with enough data apart from secrets to replay it | Counts only |
| issued, ephemeral | Issuance and revocation | Counts and allowlisted identifiers |

The full value of a write sits in the OCSF record's own entity data ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-class-mapping)). Audit records never carry a secret. Telemetry never carries a personal, secret or free-text value.

### Quota by origin

- Limits, enforcement rules and the behaviour on exhaustion or unavailability are declared. An operator may lower a limit on the console, tighten-only.
- Balances and top-ups are issued, durable, backed up and rolled forward from the usage stream ([0030](/decisions/0030-audit-records-and-the-usage-stream/#quota)).
- Meters and hourly aggregates are derived from the log and rebuilt after a restore.

### Backup and restore by origin

| Origin | In the backup | After a restore | Export |
|---|---|---|---|
| declared | No: it lives in version control. The archive keeps the resolved document and its digest as evidence | Redeployed from version control, checked with `sluis config check` against the archived document | Rendered, not exported: grants and vendor objects for the operator to apply |
| operator-set | Yes; secret parts archived sealed | Restored, then rolled forward from the audit log, merged per kind: replaced, or united for tighten-only switches | "Promote to declared"; through `export` only if the kind is marked external |
| learned | No | Learned again: a fresh pull before maintenance lifts, or a live read on the first miss | An authenticated read with a grant |
| derived | No; a snapshot may shorten a restore and is never evidence | Rebuilt after the roll-forward | The query API |
| issued, durable | Yes; vendor-issued secrets archived sealed | Restored, then rolled forward | Per kind through `export` where marked external; public material by static publication |
| issued, ephemeral | No | Invalidated: everyone signs in again | No |

- **Sealed values are archived sealed**, so the backup side never reads a secret and a restore needs no vendor ceremony. How a restore opens them when the sealing key is lost is in [0005](/decisions/0005-the-store/#sealed-secrets); it never copies a key that cannot leave its store.
- **Roll-forward covers every kind marked for it:** operator-set records, tighten-only switches, pins, account links, approvals and consents, quota balances, revocations and revocation state, the issued parts of clients, and the issuance log ([0023](/decisions/0023-certificate-authorities/#issuance-log-and-revocation)). A restore never depends on a serial-number ledger; there is none.
- **A restore never loosens a tighten-only switch**: its merge is a union.
- **A secret written after the last archive cannot be rolled forward**, because audit never carries secrets. The restore preview lists every such secret and raises an alarm, and the operator rotates or reconnects it.
- **Restore order:** check the configuration against the archived document, write the archive, roll forward, rebuild derived data, learn again, lift maintenance.
- **Whether a value may leave sluis is a property of its kind.** A kind marked external is published through `export`. A secret referenced from declared configuration is exported by granting the consumer the operator's own path, not by copying it.

## Consequences

- A field is added in one place: the JSON Schema, the Helm schema, the reference page and the console change with it, and the vectors catch a Go or Rust type or a validator that reads it differently. The schema's identifiers and versions are public surface.
- The build gains a toolchain: Pkl and a Pkl-to-JSON-Schema generator, the part most likely to need patching. Hand-written Go and Rust types are a second place to edit until a generator exists.
- Operators get early, uniform errors: a misspelt field, a wrong type and a retired option fail at `sluis config check` and at start, and name the path.
- One classification answers who writes, where data lives, what is backed up, what a restore does, what may leave sluis and what audit and telemetry may say; the lists each part kept by hand are generated.
- The click-to-configure pattern exists, bounded: an operator-set record is audited with its full value, backed up and rolled forward, and can never grant access. A stolen operator session can tighten and configure operational records, not widen authority.
- Every console page that shows configuration must show the origin, the lock state and the held objects, and `--live` checks need operator credentials.
- Live reload of whole snapshots replaces "a new value is a deploy" (v1 ADR 0036), and is tested on every runtime.
- Every path has a reload class, so an operator knows before publishing whether a change lands at once or waits for a restart. A key that nobody has classified is `restart`, which is safe and slow. The cost is one more annotation to review on every key, and a snapshot that mixes the two classes: it holds back its `live` part in every running process until they restart, because it is refused as a whole. The layout above and `sluis config check` against the previous version keep a mixed snapshot from being published by accident. While a restart rolls out, a process that has restarted and one that has not disagree on a `restart` path, which is the overlap of any rollout ([0015](/decisions/0015-evolution-and-compatibility/)).
- Backups hold more than in v1, and secrets written after the last archive are lost on restore and must be rotated; the preview makes that visible. The recovery switch is backed up with a union merge, which keeps v1 ADR 0075's property that an old archive cannot reopen recovery.
- Requirements for the reload classes: [REQ-OPS-057](/requirements/ops/#REQ-OPS-057) to [REQ-OPS-062](/requirements/ops/#REQ-OPS-062).
- This record succeeds v1 ADRs 0018, 0036, 0063 and 0067, and generalises 0019 to 0022 and 0075.

## Roads not taken

- **Pkl at run time.** The tool is about 95 MiB and runs as a child process, which a board, a function or a sandboxed actor cannot afford.
- **Hand-written JSON Schema as the source.** Helm schemas and documentation would be written again from it and drift; the source should be one typed definition.
- **Protobuf messages as the source.** A message describes a wire format and cannot say "a duration", "retired" or "no other keys"; configuration is not a wire contract.
- **Durations as `90s` or `15m`.** Short to type, but a format of its own that no validator knows; ISO 8601 is the standard one ([principle 5](/principles/#5-open-standards-as-their-consumers-implement-them)).
- **CUE as the source.** Pkl was chosen; the schema, not the source language, is what consumers see, so the choice can change without changing the public API.
- **Generated Go structs and Rust types from the start.** No generator for both exists that we trust today; hand-written types behind the schema check, proven by vectors, come first.
- **One validator called from the other languages.** It needs a child process or a foreign interface and a runtime dependency in functions that must start fast.
- **Telemetry settings, or flags and environment variables, beside the file.** The file would be tied to one environment and the sources would overlap unchecked; `OTEL_*` is the standard every SDK reads.
- **Three origins: declared, learned, operator secrets.** No place for console-made configuration, vendor-issued secrets and pins mislabelled as learned, and configuration only.
- **Derived folded into learned.** Writers, rebuild sources and restore order differ.
- **Declared seeds a value and the console overrides it, or last writer wins.** Git would no longer show the effective value, and a change on either side could silently erase the other (v1 ADR 0020 removed exactly this take-over).
- **Operator-set authority with a second person's approval, or signed operator writes.** It rebuilds a writable policy API and puts passkey friction on every write; a permission-checked write audited under a person is enough for 2.0.
- **The `console` actor or a separate store holding every operator-set record.** One actor would validate other actors' rules and hold write access to every kind, and a second store would need running and replicating on every installation.
- **Everything restarts, as in v1.** A revoked grant or a new client would wait for a rollout, and on Lambda for a new version of every function.
- **Everything reloads.** A key handle, a listener or a connection pool would be rebuilt in a running process while requests are in flight, and a failure half-way leaves a process that is neither the old version nor the new.
- **Apply the `live` part of a mixed snapshot and refuse only the `restart` part.** The process would run a document that nobody reviewed or published, with an audited digest that matches no commit, and the next restart would change its behaviour again. Refusing the whole keeps one rule and one version in force; the price is that a `live` change waits (see Consequences).
- **A class per file or per source instead of per path.** One area holds both: a boundary is wiring and its `clients` are data. A class per file would force a file for each class and could not follow a subtree.
- **A process that exits and is restarted when its configuration changes.** A policy edit would become an outage of the requests in flight, and a Lambda function has no supervisor to restart it.
- **Vendor-issued secrets unsealed and re-wrapped for the archive, or left out of it.** Re-wrapping gives the backup side read access to every secret; leaving them out needs a person at every vendor after a restore.

## Follow-ups

- Backup archive format and the restore tooling: [#1015](https://github.com/truvity/sluis/issues/1015).
- Cutover and migration of v1 configuration, in the parity milestone: [#1017](https://github.com/truvity/sluis/issues/1017).
- Reconcilers (membership only, one per target, under a lease): [#1012](https://github.com/truvity/sluis/issues/1012).
- Live reload on every runtime, with the classes above: [#977](https://github.com/truvity/sluis/issues/977).
