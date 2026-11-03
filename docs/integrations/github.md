---
title: GitHub
description: How sluis uses GitHub Apps, organisation teams and Actions identity tokens, to mint repository tokens, keep teams in step with the directory and verify CI jobs.
status: target
sidebar:
  order: 2
---

GitHub plays the most kinds of integration. A verifier driver of `exchange` checks Actions identity tokens. `adapter-github@<boundary>` holds no credential at rest; it opens the sealed credential of each tenant's GitHub App at key@ for each call, supplies team facts, mints installation tokens and reconciles team membership.

## What it's for

- **A CI job publishes a package or cuts a release** without a stored secret. It presents its Actions identity token, sluis checks it against GitHub's published keys, and the job receives an installation token for one repository with the one permission it needs, for minutes.
- **A new engineer joins the right teams** because the directory puts them in a group. Leaving the group removes them from the team; an organisation owner is reported, never removed.
- **An infrastructure-as-code run** gets a token for the organisation it manages, instead of a personal access token, and **self-hosted runners register** with an App that can only manage runners.

## Integration kinds

| Kind | What it does for GitHub |
|---|---|
| `WorkloadVerifier` | The `github-oidc` verifier driver of `exchange` checks an Actions identity token against GitHub's key set and returns attributes: `repository`, `ref`, `job_workflow_ref`, `environment`, `visibility`, owner and repository ids. It holds no secret. It is in the first working version, for the callers of the signing API ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)). |
| `FactsSource` | `adapter-github` reports organisation members, team members and maintainers, as the directory facts of the tenant ([0019](/decisions/0019-person-and-upstream-link/#directory-facts-parity)). |
| `CredentialMinter` | `adapter-github` mints an installation token for a catalogued App, for a mint grant that `policy` sealed. |
| `Provisioner` | `adapter-github` makes the organisation's teams equal the desired state that the directory adapters wrote ([0026](/decisions/0026-reconcilers/#the-desired-state)): invites, adds, promotes and removes. |

A person's GitHub account is linked to their directory identity through a separate **link App**, so a team can be filled from a directory group. The link App is a `GitHubApp` of the operator's own tenant, and the link it makes is a `GitHubAccountLink` of its own, not an `UpstreamLink`.

## Connections

One `adapter-github` runs in a boundary and serves every tenant that has connected a GitHub organisation. Each tenant's connection is its own durable items, so two tenants of the same boundary are two sets of items, not two processes ([0025](/decisions/0025-integrations/#adapters-and-connections)).

| Kind | Class | Holds |
|---|---|---|
| `GitHubApp` | Durable, per tenant, sealed | An App made by the manifest flow: the App id, the private key and the webhook secret |
| `GitHubInstallation` | Durable, per tenant, sealed | The pins: App id and installation id per organisation, first seen |
| `GitHubAccountLink` | Durable, per tenant, sealed | The link between a person and their GitHub account, made when the person authorises the link App; the person may narrow or revoke it |
| `MinterTarget` | Durable, per tenant, plain | One for each catalogue App: the permissions a token may hold, checked against `MinterBounds` ([0025](/decisions/0025-integrations/#credential-minters)) |
| `GitHubManifestState` | Temp, hashed, 1 hour | The state of a manifest flow in progress |
| `DirectoryConnection` | Durable, per tenant, sealed | The tenant's connection to its GitHub organisation as a directory |

- **A connection is made in the UI or through the API,** by the manifest flow in [Connecting](/integrations/connecting/#github-app-manifest-flow). An App that the operator makes in the UI belongs to the operator's own company, which is a tenant.
- **The adapter opens a key per call.** It reads the `GitHubApp`, asks key@ to open the private key with a grant sealed for the tenant, signs the App's request to GitHub, and keeps nothing.
- **A pass that no caller starts** (the scheduled re-sync and the reconciler's passes) takes a lease and asks `policy` for a grant for one tenant at a time ([0026](/decisions/0026-reconcilers/#scope)).

## What sluis asks the vendor for

Each App asks for the least its job needs, and one App does one job ([per organisation or per installation](/integrations/connecting/#per-organisation-or-per-installation)).

| App | Purpose | Permissions |
|---|---|---|
| Organisation App, one per organisation | Reads and changes membership | `members`: read for facts only, write when it provisions. `organization_administration`: read. No webhook. Private. |
| Catalogue App, any number | Mints installation tokens for jobs | Exactly the permissions you declare, such as `contents` and `pull_requests`. An App that approves reviews carries no administration permission; an App that administers stays out of the approving path. |
| Link App, one | Lets a person link their account | The person's own e-mail addresses (read), by OAuth, as the person. Installed nowhere. Public, because a private App can be authorised only by members of its owner. |
| Runner App, one per organisation per tier | Registers self-hosted runners | `organization_self_hosted_runners`: write. |

The verifier reads only the public key set of Actions tokens. The adapter's egress is limited to `api.github.com` and GitHub's token issuer, and the App private keys are sealed in their `GitHubApp` items.

## What policy controls

- **Who may mint what.** A grant names a group, the repositories (names or globs) and the permissions. A token never exceeds one grant, and grants are not added together. What a minter may mint at all is bounded by `MinterBounds`, and each catalogue App is a `MinterTarget` that is checked against it when the App is registered ([0025](/decisions/0025-integrations/#credential-minters)).
- **Which jobs count as which group.** Matchers on the verified attributes: repository, ref, `job_workflow_ref`, event, environment, visibility. Pin a grant to one reviewed workflow file, not every job in a repository. The trusted-owner list of the config kind `ExchangeTrust` is the trust boundary: an empty list verifies nothing.
- **Which teams hold which groups**, as members and maintainers.
- **Caps and rate limits**, enforced by `policy` and `quota` before the adapter is called. The adapter enforces only GitHub's own limits.
- **Safety in the reconciler:** dry run until the target is enabled, a seat check, and a breaker that holds a pass which would remove over half of the members ([0026](/decisions/0026-reconcilers/#safety)).

## What is audited

- Every token request: outcome, the verified subject, the App, the grant, the repositories and permissions, the installation and the expiry. **The token is never recorded**, not in the audit record, not in a log line and not in a kind ([0025](/decisions/0025-integrations/#credential-minters)).
- Every membership change, including each change held for an operator, and each organisation owner the directory does not know.
- The lifecycle of an App (created, installed, disconnected) and each account link made, narrowed or lost.

## Setup

The flow is the [GitHub App manifest flow](/integrations/connecting/#github-app-manifest-flow); names and keys are [illustrative](/integrations/#examples-are-illustrative).

1. Start the connection in the console or through the API, naming the organisation and the App's permissions.
2. An organisation owner opens the link and confirms.
3. The owner picks the repositories on GitHub's install page. `adapter-github` seals the private key in the `GitHubApp` and keeps the App id and installation as pins.
4. Write the trust for Actions tokens in config, write the grants in the policy, and read a dry-run pass for the teams before you enable the target.

```yaml
# ExchangeTrust, a config kind (example)
proofs:
  github-oidc:
    owners: [acme]            # the trust boundary for Actions tokens
```

A job then asks for a token:

```yaml
permissions:
  id-token: write          # the job's identity token
steps:
  - run: sluis token github --app publisher --repository app --permission contents=write
```
