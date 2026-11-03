# 0025 — Integrations return facts or carry out effects that core authorised, never decide, and are split by credential

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #997](https://github.com/truvity/sluis/issues/997).

## Context

[0002](/decisions/0002-families-of-actors/#the-four-families) says that integration actors return facts or carry out effects that core has authorised, are split by credential, and are named `<vendor>[-<capability>]@<tenant>`. It does not say what an integration may return, how core authorises an effect before it runs, or what each kind of integration is called over its socket. Every integration built after this one, and the sign-in of the first working version, is written against that contract.

The forces are the ones that made `policy` a separate actor ([0007](/decisions/0007-policy-and-sealed-grants/)). A vendor connector is the part of sluis that holds a third party's credential and speaks a third party's protocol; if it also decides who gets what, the decision hides in vendor code that no policy file shows. Vendor error text, vendor identifiers and vendor structs in core would tie core to each vendor. A connector that holds the credentials of several companies would let one company's compromise reach another's.

## Decision

### The rule

- **An integration returns facts, or carries out an effect that core has authorised, and never decides.** Whether a fact entitles anyone to anything is the question of `policy`. A refusal by an integration means "the vendor said no" or "this is outside what core authorised", never "this person may not".
- **Core calls integrations, and an integration never calls a core actor.** `session` calls its upstreams, `exchange` its minters and notifiers, `console` the integrations that own operator-set kinds, and `entry` only routes a push notification to an integration. What an integration needs from core, such as a desired state, core publishes as data in a read-only prefix.
- **Three invariants are tested:** core packages never import vendor packages; there is no edge from an integration to a core actor in any manifest; policy matchers have no vendor-specific fields.

### The contracts

Every contract is a ConnectRPC service in the package `sluis.integration.v2alpha1` ([Contracts and errors](/reference/contracts/#packages-and-files)).

| Contract | Kind | Methods | Returns |
|---|---|---|---|
| `Integration` | base, served by every integration | `Describe`, `Probe` | Its kinds and version, the attributes it can return with their types, and its health |
| `Upstream` | sign-in | `Begin`, `Complete` | An authorization URL; then an assertion of identity |
| `FactsSource` | facts | `Lookup`, `Changes` | Facts about named subjects; the subjects whose facts changed since a cursor |
| `CredentialMinter` | effect | `Mint` | A short-lived credential and a handle, for a sealed grant |
| `Provisioner` | effect | `Reconcile` | The outcome of making an external system equal a desired state |
| `Notifier` | effect | `Send` | The outcome of sending one message |

The workload verifier is not an integration actor but a verifier driver of `exchange`, which holds public material only ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)).

### What an integration may return

- **A fact is a subject reference, named attributes, the time observed (`as_of`), how long it may be used (`max_age`) and whether the source is authoritative.** A fact that has passed its `max_age` is stale, and `policy` is told so; staleness is never repaired by guessing.
- **References are opaque.** A subject or a group is a `{namespace, id}` pair, and core never parses the id. Attributes carry namespaced names (`github.repository`, `k8s.namespace`), declared with their types in `Describe`, so a policy file is validated at load without core knowing the vendor.
- **The sign-in assertion is a fact about one authentication.** `Upstream.Complete` returns the issuer, the value of the upstream's subject claim ([0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)), and the claims of a configured allow-list: the e-mail address and whether the upstream verified it, a display name, and `acr`, `amr` and `auth_time` exactly as the upstream sent them. An absent value is unknown, never a default. Groups and roles that the upstream sends are not read.
- **A refusal carries a reason from a closed list:** `UNAVAILABLE`, `UPSTREAM_REJECTED`, `INVALID`, `NOT_FOUND`, `RATE_LIMITED`, `UNSUPPORTED`, `STALE`, each with one Connect code ([Contracts and errors](/reference/contracts/#connect-codes)). No vendor error text crosses the contract.
- **"I could not ask" is `UNAVAILABLE`, never an empty answer.** A directory that cannot be read must not look like a directory with no members.

### The upstream contract

- **`Begin`** takes the `state`, the `nonce` and the S256 `code_challenge` that `session` made, sluis's callback URL, and optionally `acr_values`, `max_age` and a login hint, and returns the authorization URL. `session` keeps the sign-in's state in a `pending-signin` record; the integration keeps none.
- **`Complete`** takes the callback's `code` and `iss` parameter, the `code_verifier`, the `nonce` and the callback URL. The integration exchanges the code at the upstream's token endpoint with its own client credential, checks the ID token strictly (signature against the upstream's key set, an allow-list of algorithms, `iss`, `aud`, `azp`, `nonce` and the time claims), and returns the assertion. The client credential never leaves the integration, so `session` holds no upstream credential.
- **A missing subject claim, a bad token or a missing `iss` in the response is refused with `INVALID`.** There is no lenient fallback, and no fallback to another claim or to the e-mail address.

### How core authorises an effect

- **A mint is authorised by a grant that `policy` sealed.** The grant carries the decision, the digest of the policy and the hash of the scope, under the sealing key with `purpose=grant` in the encryption context ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). The minter opens it, which fails for a grant of another environment, refuses a scope the grant does not cover and cannot lengthen the lifetime. `exchange` has `quota` admit the operation before it calls the minter.
- **A reconciliation is authorised by a desired state that core published.** The provisioner reads it by its digest from a read-only prefix that core writes; it never asks core a question and cannot choose what the state should be.
- **A notification is authorised by core composing it.** The caller names a template and its parameters and a destination that declared configuration allows; the notifier sends that and nothing else.
- **Business limits live in core.** Caller caps, mint rates and which group may hold which role are policy and quota, checked before an integration is called. An integration enforces only technical limits: the vendor's API rate and maximum lifetime.
- **Every effect is reported as an outcome:** done with its handle and expiry, refused with a reason from the closed list, or failed. A credential or a secret is never in an audit record, a log line or a span.

### Splitting by credential

- **One integration process holds one vendor tenant's credential for one capability.** Sign-in and the directory of one workspace tenant are two credentials and so two processes (`google-signin@acme` and `google-directory@acme`); two companies' connectors to the same vendor are two processes. A company's connector then fails, rotates and leaves on its own. The one exception is a customer organisation's own OpenID Connect provider, which holds only a client credential and runs in the pool of its customer boundary ([0054](/decisions/0054-customer-connections-run-in-a-pool-per-customer-boundary/)).
- **An integration declares the hosts it may reach and the permissions it needs,** and the installer grants no more. Outbound access is limited to the declared hosts: `network_mode: none` locally except for them, an egress policy on Kubernetes ([0011](/decisions/0011-runtimes-and-installations/#kubernetes)).
- **A push is a notification, then a pull.** A small notification reaches `entry`, which routes it to the integration; the integration reads the full state from the vendor's API, and a periodic full pass runs as well ([0004](/decisions/0004-the-data-model/#storage-classes)).
- **Each integration audits what it does:** a facts pass with its digest and counts, a sign-in with its outcome, an effect with its outcome and handle ([0004](/decisions/0004-the-data-model/#what-is-not-data)).

### The first working version

- **The first working version has `Integration` and `Upstream`,** served by one `oidc` upstream per declared connection ([0019](/decisions/0019-person-and-upstream-link/)). `FactsSource` and the three effector contracts are written with their first consumer at the parity milestone, as additions to the package; adding a service or a method is compatible ([Contracts and errors](/reference/contracts/#versions)).

## Consequences

- A flaw in a connector reaches one vendor tenant's credential and the facts it can return. It cannot grant, because it holds no policy, and it cannot mint beyond a grant, because it opens only grants that `policy` sealed.
- Policy and core stay free of vendors: a new vendor is a new process with a `Describe` document, and no core package changes.
- The cost is one process per vendor tenant and capability, and a typed contract per kind to keep compatible. Small machines rely on the fusion rule of [0003](/decisions/0003-units-transports-and-fusion/#fusion).
- Treating an unreachable directory as `UNAVAILABLE` means a directory outage is felt as refusals after the freshness window, not as everyone silently losing access ([0017](/decisions/0017-identity-and-sign-in/#directory-outages)).
- The requirement records for the integrations stay with their areas: the upstream's checks are REQ-FED-001 to REQ-FED-016.

## Roads not taken

- **One generic `Do(request)` call for every integration.** One interface, but no typed contract to test, no schema to validate a policy against, and every caller parses vendor-shaped bytes.
- **Integrations that return a decision, such as "allow".** A second policy engine inside vendor code, invisible to the policy file and its reviewers.
- **One process per vendor, serving every tenant.** One compromise would hold every company's credential, and a company could not rotate or leave alone.
- **An integration that calls core for what it needs.** It adds an edge from vendor code to an actor that holds keys or state; published data in a read-only prefix gives the same without the edge.
- **Vendor errors passed through.** Core would parse vendor text, and the text could leak a tenant's data into a caller's response.
- **A stream of pushed facts instead of notify-then-pull.** A forged or reordered push would change core's state directly; a pull reads the vendor's own answer.
- **The `FactsSource` and effector services written now.** Principle 8: nothing without a consumer; the first working version needs no directory and no minter.

## Follow-ups

- Directory sync, the first `FactsSource`: [#805](https://github.com/truvity/sluis/issues/805).
- Downstream credentials, the first `CredentialMinter`: [#1011](https://github.com/truvity/sluis/issues/1011).
- Reconcilers and the `Provisioner` contract: [#1012](https://github.com/truvity/sluis/issues/1012), [#1018](https://github.com/truvity/sluis/issues/1018).
- The generic OpenID Connect upstream: [#1106](https://github.com/truvity/sluis/issues/1106).
