# Architecture decisions

One record per decision that shapes sluis from the outside: what a user must do, what an installation must accept, what a release removes.
A record says why the thing is shaped the way it is, what else was weighed, and what follows.
Explanation pages describe the target state and carry a status badge; a page marked `shipped` describes what shipped. When a page and a record disagree, the record is the reasoning and the page is fixed.

How a decision is made is in [GOVERNANCE.md](../../GOVERNANCE.md).

## Numbering

v2 numbering starts again at `0001`. `0000` is the [template](0000-template.md).
v1 had its own records on the `master` branch. Refer to them as "v1 ADR NNNN" and link to `master`, for example "v1 ADR 0007". Do not renumber them and do not copy them here.
A v2 record that replaces a v1 decision says so in its context.

## Files

A record is `NNNN-short-title-in-kebab-case.md`. A new record takes the number after the highest one in the index. A decision that is planned but not written has an issue and no number: prose names the issue, never a future number.

## Format

Every record has these parts, in this order:

- **Status.** One of `Proposed`, `Accepted`, `Rejected`, `Superseded by NNNN`, or `Accepted; amended by NNNN`.
- **Layer.** Optional. One of `core`, `CIAM module` or `quota module`: the part of the product the decision belongs to ([roadmap](../roadmap.md)). A record with no Layer line is core.
- **Date.** The day the status last changed.
- **Context.** The forces at play. What problem, what constraints, what the reader needs to know.
- **Decision.** What we do, in the active voice.
- **Consequences.** What gets easier, what gets harder, what must follow. Include costs.
- **Roads not taken.** Each other option that was weighed, one bullet each: the option in bold, then why it lost. This part is required.
- **Follow-ups.** The named tasks and planned records that follow, each with its issue, or "None.".

Under the status and the date, one line links the proposal issue: `Proposal: [issue #N](...)`.

## Rules

- **Never edit history** (after the first v2 release; the design phase below waives it until then). A changed mind gets a new record that supersedes the old one. The old record's status line changes to point at the new one. Its body stays.
- **Typos and links** may be fixed in place.
- **One decision per record.** Keep it short. A page of reasoning is better than ten. A rule is stated in one record; the others link to its heading.
- **Accepted means decided.** An `Accepted` record has no open part: it does not say "not decided here" or that another record will decide it. What it leaves out is under Follow-ups, with its issue. A record with an open part is `Proposed` and lists the part under Follow-ups.
- **Public means generic.** A record names no private deployment, account, hostname, ticket or person other than the maintainer. Use neutral examples.
- **Draft ADRs are internal.** Reasoning starts in internal discussion. Only the final record is written here, once the maintainer has decided.
- **Standards.** A deliberate deviation from a standard in the register needs a record.
- **Scope.** New product scope, and changes to the design model, need a record.
- **Links.** A link to a record uses the site path, `/decisions/NNNN-slug/` or `/decisions/NNNN-slug/#heading`. CI checks that every "ADR NNNN" and every such link names a record that exists, and that every anchor is a heading in it.

## Design phase (2026-10-29)

v2 is a clean start. During the v2 design phase, before the first v2 release, the maintainer may rewrite, merge and renumber records in place. The rule "Never edit history" above is waived for this period only. The earlier text stays in git history, and a rewritten record carries no history lines. After the first v2 release, records are append-only: a changed mind gets a new record, as the rules above say, and a number is never reused, even for a rejected record.

On 2026-11-01, before any code was written, the maintainer had the 32 records accepted until then merged into the 20 below and renumbered from 0001, so that each rule is stated once and no accepted record holds an open part. The old numbers and slugs are in [renumbered.json](renumbered.json) and in the table at the end; the site redirects each old address to the record that took it over.

On 2026-11-03 the records were renumbered a second time, without any change of content, so that the numbers follow the design rewrite. The old slugs of both days are in [renumbered.json](renumbered.json); an "ADR NNNN" in an issue or a commit from before 2026-11-03 means the number the record had then.

## Index

Records are grouped by the layer of the product they belong to: the core, then the two later modules ([roadmap](../roadmap.md)). Each record's `Layer` line says which.

### Core

| ADR | Decision | Status |
|-----|----------|--------|
| [0001](0001-v1-and-v2-lines.md) | v1 and v2 are two lines that coexist until v2 replaces v1 | Accepted |
| [0002](0002-families-of-actors.md) | Actors form four families: work actors hold no credential at rest, and only the data, keys and audit families hold credentials | Accepted |
| [0003](0003-units-transports-and-fusion.md) | One model, many transports: a unit per actor, the same calls over sockets, invokes and pods, and fusion only by explicit choice | Accepted |
| [0004](0004-the-data-model.md) | Data is resource kinds in a compiled registry, each with an address, one storage class, a treatment, a profile and one writer | Accepted |
| [0005](0005-the-store.md) | store@ holds every storage credential: one generic store service, typed clients, drivers private to their owner, and signed configuration loaded as a whole | Accepted |
| [0006](0006-keys-and-sealing.md) | key@ holds a boundary's keys: it seals, opens and signs in place, with three data keys per tenant and one key per purpose and algorithm | Accepted |
| [0007](0007-policy-and-sealed-grants.md) | Policy is Cedar in a Rust actor over four layers, and every tenant-scoped write carries a grant that policy sealed | Accepted |
| [0008](0008-boundaries-and-tenants.md) | A boundary is the unit of keys and policy on a cumulative ladder from L0 to L4, and a tenant is a scope with data keys of its own | Accepted |
| [0009](0009-export.md) | exporter@ publishes the kinds marked exportable to destinations outside sluis, never to a secret source | Accepted |
| [0010](0010-backup-and-recovery.md) | A backup is a logical archive of the authoritative kinds through the store; a regional outage is accepted and a drill measures recovery | Accepted |
| [0011](0011-runtimes-and-installations.md) | Runtimes are three kinds, four installations are tested, and delivery goes local first, then boards, Lambda and Kubernetes in parallel | Accepted |
| [0012](0012-the-language-follows-the-executable.md) | The language follows the executable: Go by default, Rust at the edge, in the trusted base, in cloud drivers and on the smallest boards | Accepted |
| [0013](0013-release-train-packaging-and-distribution.md) | One repository, one version, one release train, and packaging follows the runtime | Accepted |
| [0014](0014-the-site-is-static-on-cloudflare-workers.md) | The site is static on Cloudflare Workers, deployed by GitHub Actions, with a live status API | Accepted |
| [0015](0015-evolution-and-compatibility.md) | Evolution and compatibility: N and N-1 inside a major version, a parallel cutover from v1, and neutral artifacts as the deliverable | Accepted |
| [0016](0016-telemetry.md) | Telemetry is OpenTelemetry used directly, with one log format, W3C trace context, fixed span and metric names, and a generated attribute allowlist | Accepted |
| [0017](0017-identity-and-sign-in.md) | Each boundary has its own issuer, a token has one audience, and people sign in with passkeys and step-up | Accepted |
| [0018](0018-sessions.md) | Sessions have three classes: a person's sessions end at an absolute limit, an agent's end with its consent, and a machine client has no session | Accepted |
| [0019](0019-person-and-upstream-link.md) | A person is tied to an upstream account by the issuer and a configured subject claim, never by e-mail, and a directory only adds facts | Accepted |
| [0020](0020-grant-vocabulary-and-token-claims.md) | Grants come from a declared vocabulary, a token carries a fixed set of claims narrowed to its one audience, and token lifetimes have defaults and caps | Accepted |
| [0021](0021-clients.md) | Clients are declared, a resource maps to a registered client, and a self-described client is admitted only from an allow-listed origin | Accepted |
| [0022](0022-workload-identity-and-host-enrolment.md) | Workload identity follows SPIFFE: proofs are exchanged for short-lived credentials, and hosts enrol the same way | Accepted |
| [0023](0023-certificate-authorities.md) | The ca and ssh-ca actors are the X.509 and SSH certificate authorities, SSH uses only sluis's own CA, and databases get short-lived client certificates | Accepted |
| [0024](0024-root-custody-and-the-signing-api.md) | sluis holds no root: it asks root custody to certify its intermediates, and signs artifacts through a signing API | Accepted |
| [0025](0025-integrations.md) | Integrations return facts or carry out effects that core authorised, never decide, and are split by credential | Accepted |
| [0026](0026-reconcilers.md) | A reconciler manages membership only, one per target under a lease, through the Provisioner contract | Accepted |
| [0027](0027-the-console.md) | Console roles are declared grants, and its pages are organised by the origin of what they show | Accepted |
| [0028](0028-audit-pieces.md) | Audit is four pieces joined by a transport port, search is an index fed from the log, and an audit installation has its own front | Accepted |
| [0029](0029-the-audit-log.md) | The audit log is a C2SP tiled log in a blob, sealed in batches by its one writer, with a lock mode, company encryption and a declared retention | Accepted |
| [0030](0030-audit-records-and-the-usage-stream.md) | Audit records are OCSF events with one `unmapped.sluis` object, usage is a separate stream from the same call, and quota is idempotent and strict | Accepted |

### CIAM module (later layer)

| ADR | Decision | Status |
|-----|----------|--------|
| [0031](0031-ciam-is-a-broker.md) | CIAM is a broker: a customer-identity product owns the accounts, sluis owns the session and the tokens, and the contract between them is written down | Accepted |
| [0032](0032-customer-identity-installations.md) | A customer-identity installation is a front, a few customer boundaries and key-less tenants, a tenant's client IDs carry its name, and a move keeps every subject | Accepted |
| [0033](0033-customer-connections.md) | Customer connections run in a pool per customer boundary, and a domain routes only after DNS proof | Accepted |
| [0034](0034-end-users-and-upstream-signals.md) | An end user is a person with five states, erased by deleting its records, and upstream signals end sessions or suspend and erase | Accepted |
| [0035](0035-customer-pages.md) | Customer pages are few, branded per client and login domain, and localised per request | Accepted |
| [0036](0036-volumetric-abuse.md) | Volumetric abuse is stopped at the edge, and sluis bounds what one connection, client or source can cost with a token bucket in its own state | Accepted |
| [0037](0037-capacity-is-measured-before-it-is-promised.md) | Capacity is measured before it is promised: a dated spike of the signing path, the hops to store@ and key@, the engines and the audit writer, and tokens stay signed in place meanwhile | Accepted |
| [0038](0038-fapi-2-profile.md) | FAPI 2.0 is a profile a client declares, with PAR, DPoP, private-key client authentication and its own signing algorithm, and sender constraint is declared per audience | Accepted |

### Quota module (later layer)

| ADR | Decision | Status |
|-----|----------|--------|
| [0039](0039-quota-allowance.md) | Plan templates are declared, and an account is an issued record that a declared client creates at run time | Accepted |
| [0040](0040-meters-and-usage-evidence.md) | A meter has a name, a unit and a kind that never change, only declared outcomes bill, and a usage event belongs to the period of its event time within a stated skew | Accepted |

### Being merged

These records are superseded: the content of each moves into the record its status names, and the pull request that moves it deletes the file.

| ADR | Decision | Status |
|-----|----------|--------|
| [0042](0042-leaf-certificate-profiles-lifetimes-and-revocation.md) | Every leaf certificate has a fixed profile and a short lifetime, intermediates are name-constrained per environment, and one static CRL per intermediate is re-signed daily | Superseded by 0023 |
| [0043](0043-break-glass-recovery-uses-passkeys-only.md) | Break-glass recovery uses passkeys only: two attested hardware keys and one pinned synced passkey, a recovery scope, an alert on every use and a quarterly drill | Superseded by 0017 |
| [0044](0044-audit-pseudonyms-are-keyed-per-company-and-epoch.md) | Audit pseudonyms are HMAC-SHA384 of the subject under a data key per company and month, wrapped by the sealing key, and only the company's audit role reverses them | Superseded by 0029 |
| [0045](0045-the-signing-api-signs-sent-content-for-an-authorised-proof-and-returns-an-armoured-detached-signature.md) | The signing API signs the content it is sent for a proof that policy authorised, and its first stage returns an armoured OpenPGP detached signature | Superseded by 0024 |
| [0048](0048-data-lifecycle-and-evidence-never-share-a-key-with-personal-data.md) | Data lifecycle and evidence: evidence and personal data never share a key, erasure is shredding the key, and v1's history stays where it is | Superseded by 0029 |
| [0049](0049-credential-minters-mint-only-for-declared-targets-whose-entitlement-sluis-governs.md) | Credential minters mint only for declared targets whose entitlement sluis governs, and never where the vendor can trust sluis directly | Superseded by 0025 |
| [0050](0050-audit-lifecycle-tiers-move-only-cold-objects-and-compliance-profiles-are-floors-that-the-configuration-check-enforces.md) | Audit lifecycle tiers move only cold objects, and compliance profiles are floors that the configuration check enforces | Superseded by 0029 |
| [0051](0051-the-finance-export-is-a-statement-per-account-and-period-closed-once-anchored-in-the-usage-log-and-pulled.md) | The finance export is a statement per boundary, account and period, closed once, anchored in the usage log and pulled by the billing system | Superseded by 0039 |
| [0052](0052-a-quota-installation-is-fronted-by-service-identity-for-services-and-exchanged-tokens-for-people.md) | A quota installation is fronted by service identity for services and by exchanged tokens for people, and has no console until a consumer exists | Superseded by 0039 |
| [0053](0053-quota-consistency-and-failure-are-measured-per-state-driver-before-enforcement-is-switched-on.md) | Quota consistency and failure are measured per state driver before enforcement is switched on | Superseded by 0039 |
| [0054](0054-customer-connections-run-in-a-pool-per-customer-boundary.md) | Customer-owned upstream connections run in a pool per customer boundary, and every other connector keeps its own process | Superseded by 0033 |

## Where the old records went

The records before 2026-11-01, by their old number and slug. An "ADR NNNN" in an issue or a commit from before that day means the old number.

| Old | Old slug | Now |
|-----|----------|-----|
| 0002 | `actors-declare-ports-placement-is-derived` | [0002](0002-families-of-actors.md) |
| 0003 | `runtimes-are-runtime-kinds` | [0011](0011-runtimes-and-installations.md) |
| 0004 | `audit-is-four-pieces-joined-by-a-transport-port` | [0028](0028-audit-pieces.md) |
| 0005 | `three-zoom-levels-contracts-and-a-permission-manifest` | [0002](0002-families-of-actors.md) |
| 0007 | `core-is-a-few-actors-with-one-responsibility-each` | [0002](0002-families-of-actors.md) |
| 0008 | `drivers-are-unix-socket-services-and-only-the-public-api-listens-on-tcp` | [0003](0003-units-transports-and-fusion.md) |
| 0009 | `one-installation-per-boundary` | [0008](0008-boundaries-and-tenants.md) |
| 0010 | `cryptography-uses-p384-by-default-with-named-exceptions` | [0006](0006-keys-and-sealing.md) |
| 0011 | `authority-keys-sign-in-place-and-never-leave-their-store` | [0006](0006-keys-and-sealing.md) |
| 0012 | `machine-identity-follows-spiffe-proofs-are-exchanged-for-short-lived-credentials` | [0022](0022-workload-identity-and-host-enrolment.md) |
| 0013 | `ca-and-ssh-ca-are-the-certificate-authorities-and-ssh-uses-only-sluis-own-ca` | [0023](0023-certificate-authorities.md) |
| 0014 | `policy-is-written-in-cedar-and-evaluated-by-a-rust-actor` | [0007](0007-policy-and-sealed-grants.md) |
| 0015 | `configuration-is-defined-once-in-pkl-and-shipped-as-json-schema` | [0004](0004-the-data-model.md) |
| 0016 | `data-has-an-origin-and-a-sensitivity` | [0004](0004-the-data-model.md) |
| 0017 | `state-is-one-port-with-compare-and-set-and-clusters-replicate-with-rqlite` | [0005](0005-the-store.md) |
| 0021 | `the-audit-log-is-sealed-batches-in-a-blob-with-a-lock-mode` | [0029](0029-the-audit-log.md) |
| 0022 | `search-is-an-index-fed-from-the-log-and-the-index-is-one-driver-with-provisioning-modes` | [0028](0028-audit-pieces.md) |
| 0023 | `quotas-api-is-idempotent-and-its-data-follows-the-origin-model` | [0030](0030-audit-records-and-the-usage-stream.md) |
| 0029 | `one-repository-one-version-one-release-train-and-packaging-follows-the-runtime` | [0013](0013-release-train-packaging-and-distribution.md) |
| 0031 | `intermediates-and-the-hand-off-to-root-custody` | [0024](0024-root-custody-and-the-signing-api.md) |
| 0033 | `database-access-uses-short-lived-credentials` | [0023](0023-certificate-authorities.md) |
| 0038 | `the-local-installation-is-docker-compose-with-one-container-per-actor` | [0011](0011-runtimes-and-installations.md) |
| 0039 | `delivery-goes-local-first-then-boards-lambda-and-kubernetes-in-parallel` | [0011](0011-runtimes-and-installations.md) |
| 0048 | `passkeys-step-up-and-device-login` | [0017](0017-identity-and-sign-in.md) |
| 0058 | `boundaries-are-enforced-in-three-layers-per-port-and-every-state-value-is-encrypted` | [0003](0003-units-transports-and-fusion.md) |
| 0059 | `each-boundary-has-its-own-issuer-and-tokens-carry-one-audience` | [0017](0017-identity-and-sign-in.md) |
| 0060 | `the-language-follows-the-executable` | [0012](0012-the-language-follows-the-executable.md) |
| 0061 | `optional-openid-plans-form-post-is-supported-ciba-comes-later` | [0017](0017-identity-and-sign-in.md) |
| 0062 | `audit-front-is-a-slim-entry-the-reader-as-its-api-and-a-console-of-its-own` | [0028](0028-audit-pieces.md) |
| 0063 | `the-site-is-static-on-cloudflare-workers-with-a-live-status-api` | [0014](0014-the-site-is-static-on-cloudflare-workers.md) |
| 0064 | `audit-records-are-ocsf-events-with-one-unmapped-sluis-object-and-usage-is-a-separate-stream` | [0030](0030-audit-records-and-the-usage-stream.md) |
