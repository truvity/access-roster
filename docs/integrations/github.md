---
title: GitHub
description: How sluis uses GitHub Apps, organisation teams and Actions identity tokens, to mint repository tokens, keep teams in step with the directory and verify CI jobs.
status: target
sidebar:
  order: 2
---

GitHub plays the most kinds of integration. A verifier driver checks Actions identity tokens, and one process per organisation, `github@<org>`, holds the GitHub Apps' credentials, supplies team facts, mints installation tokens and reconciles team membership.

## What it's for

- **A CI job publishes a package or cuts a release** without a stored secret. It presents its Actions identity token, sluis checks it against GitHub's published keys, and the job receives an installation token for one repository with the one permission it needs, for minutes.
- **A new engineer joins the right teams** because the directory puts them in a group. Leaving the group removes them from the team; an organisation owner is reported, never removed.
- **An infrastructure-as-code run** gets a token for the organisation it manages, instead of a personal access token, and **self-hosted runners register** with an App that can only manage runners.

## Integration kinds

| Kind | What it does for GitHub |
|---|---|
| `WorkloadVerifier` | The `github-oidc` verifier driver of `exchange` checks an Actions identity token against GitHub's key set and returns attributes: `repository`, `ref`, `job_workflow_ref`, `environment`, `visibility`, owner and repository ids. It holds no secret. It is in the first working version, for the callers of the signing API ([ADR 0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)). |
| `FactsSource` | Reports organisation members, team members and maintainers. |
| `CredentialMinter` | Mints an installation token for a catalogued App, for a mint grant that `policy` sealed. |
| `Provisioner` | Makes the organisation's teams equal the desired state core publishes: invites, adds, promotes and removes. |

A person's GitHub account is linked to their directory identity through a separate **link App**, so a team can be filled from a directory group.

## What sluis asks the vendor for

Each App asks for the least its job needs, and one App does one job ([per organisation or per installation](/integrations/connecting/#per-organisation-or-per-installation)).

| App | Purpose | Permissions |
|---|---|---|
| Organisation App, one per organisation | Reads and changes membership | `members`: read for facts only, write when it provisions. `organization_administration`: read. No webhook. Private. |
| Catalogue App, any number | Mints installation tokens for jobs | Exactly the permissions you declare, such as `contents` and `pull_requests`. An App that approves reviews carries no administration permission; an App that administers stays out of the approving path. |
| Link App, one | Lets a person link their account | The person's own e-mail addresses (read), by OAuth, as the person. Installed nowhere. Public, because a private App can be authorised only by members of its owner. |
| Runner App, one per organisation per tier | Registers self-hosted runners | `organization_self_hosted_runners`: write. |

The verifier reads only the public key set of Actions tokens. Egress is limited to `api.github.com` and GitHub's token issuer, and the App private keys are vendor-issued secrets referenced as `cred:` values.

## What policy controls

- **Who may mint what.** A grant names a group, the repositories (names or globs) and the permissions. A token never exceeds one grant, and grants are not added together.
- **Which jobs count as which group.** Matchers on the verified attributes: repository, ref, `job_workflow_ref`, event, environment, visibility. Pin a grant to one reviewed workflow file, not every job in a repository. The trusted-owner list is the trust boundary: an empty list verifies nothing.
- **Which teams hold which groups**, as members and maintainers.
- **Caps and rate limits**, enforced by `policy` and `quota` before the minter is called. The integration enforces only GitHub's own limits.
- **Safety in the reconciler:** dry run until the organisation is enabled, a seat check, and a breaker that holds a pass which would remove over half of the members.

## What is audited

- Every token request: outcome, the verified subject, the App, the grant, the repositories and permissions, the installation and the expiry. **The token is never recorded.**
- Every membership change, including each change held for an operator, and each organisation owner the directory does not know.
- The lifecycle of an App (created, installed, disconnected) and each account link made, narrowed or lost.

## Setup

The flow is the [GitHub App manifest flow](/integrations/connecting/#github-app-manifest-flow); names and keys are [illustrative](/integrations/#examples-are-illustrative).

1. Declare the organisation and the Apps, with their permissions.
2. Run `sluis integrations connect github --org example-org --app publisher`; an organisation owner opens the link and confirms.
3. The owner picks the repositories on GitHub's install page. sluis keeps the private key as a vendor-issued secret and the App id and installation as pins.
4. Write the grants in the policy, and read a dry-run pass for the teams before you enable the organisation.

```yaml
# /etc/sluis/install.yaml (example)
integrations:
  github:
    example-org:
      actors: [verifier, facts, minter, provisioner]
      verifier:
        owners: [example-org]            # the trust boundary for Actions tokens
      apps:
        - id: publisher                  # a catalogue App
          permissions: { contents: write, pull_requests: write }
        - id: org                        # the organisation App
          permissions: { members: write, organization_administration: read }
```

A job then asks for a token:

```yaml
permissions:
  id-token: write          # the job's identity token
steps:
  - run: sluis token github --app publisher --repository app --permission contents=write
```
