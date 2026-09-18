# Connect GitHub Actions

**Anchor:** the issuer, by exchange. A workflow holds no secret. It
requests its identity token, exchanges it at the issuer for the clients
its groups admit it to, and uses the result.

Two ways to do that, and they exchange the same thing: **the action** in
this repository (`uses: truvity/access-roster@…`), which is `curl` and
`jq` and downloads nothing of ours, and **`accessctl`** with the same
kubeconfig and AWS profile a person uses. A shared workflow that wants no
stored key picks the action through its own input — see
[a reusable workflow](#in-a-reusable-workflow-token-source-access-roster).

## Issuer side

```yaml
github:
  owners: [acme]
```

That list is the trust boundary, not tuning. Anybody may run a workflow
in their own repository and get a perfectly valid token from GitHub's
issuer, so a signature and an expiry prove only that *a* job ran
somewhere; the owner allow-list is the whole of what makes one of them
ours, and an empty list verifies nothing rather than everything. The
audience a workflow must request is the issuer's own URL, and that is not
configurable: a token minted for a cloud provider is a valid GitHub
token, and one audience per relying party is what stops it being
replayed here.

## Policy

A job becomes a machine group by matcher; the clients it may obtain a
token for list that group:

```yaml
groups:
  ci-deploy:   { matchers: [{ github: { repository: acme/platform, ref: refs/heads/main } }] }
  ci-any-main: { matchers: [{ github: { owner: acme, ref: refs/heads/* } }] }
  ci-private:  { matchers: [{ github: { owner: acme, visibility: private } }] }
lifetimes: { ci-deploy: 1h, ci-any-main: 1h, ci-private: 1h }
clients:
  aws:111122223333:deployer: { kind: exchange, requires: [ci-deploy] }
  k8s:staging:               { kind: public,   requires: [ci-deploy, engineer] }
  k8s:staging-readonly:      { kind: public,   requires: [ci-any-main] }
```

`visibility` admits every private repository of an organisation and
nothing else: not its public ones, and not a fork, which is another
repository. It reads GitHub's `repository_visibility` claim; `public`,
`private` and `internal` are its values, and the policy refuses any
other. Deploy the issuer before writing the key in a policy: an older
one refuses it.

`workflow_ref`, `job_workflow_ref`, `sha`, `event_name` and `ref_type`
pin a job to one workflow file at one ref, what started it, and whether
the ref is a branch or a tag:
`{ repository: acme/platform, ref: refs/heads/main, event_name: push,
job_workflow_ref: acme/platform/.github/workflows/deploy.yml@refs/heads/main }`
admits the deploy workflow on main and not a pull request's run of an
edited copy. The same groups can hold a grant of a
[catalogue App](github-apps-catalogue.md#minting-a-token), and the job
then asks for an installation token with the action's `github-app` input.

## Workflow side: the action

```yaml
permissions:
  id-token: write          # lets the action ask GitHub for this job's identity token
  contents: read
steps:
  - id: access
    # Pin a release by commit; there is no floating `v1` tag.
    uses: truvity/access-roster@<commit-sha>   # vX.Y.Z
    with:
      issuer: https://access.example
      audiences: k8s:staging, aws:111122223333:deployer
      kubeconfig: true
      default-profile: deployer@111122223333
      region: eu-example-1
  - run: kubectl --context staging -n demo rollout status deploy/app
  - run: aws s3 ls
```

**What it exchanges.** The action asks GitHub for the job's OIDC identity
token with the issuer's own URL as its audience — the one audience the
issuer accepts from GitHub — and then makes one RFC 8693 token exchange
per audience at `<issuer>/token`: `grant_type` token-exchange,
`subject_token` the job's token (type `jwt`), `audience` the client, the
same client presented in HTTP Basic with an empty secret. What comes
back is an **access-issuer token for that one client**, carrying the
groups the job's matchers put it in; the client's `requires` decided
whether it was minted at all. For `github-app` the same exchange asks for
`requested_token_type=urn:access-roster:params:oauth:token-type:github-installation-token`
and gets a GitHub installation token back instead
([contract](../reference/contracts.md#installation-tokens-at-token)).
Every token is masked before it is written anywhere.

| Input | Default | |
|---|---|---|
| `issuer` | — | **required.** The issuer's URL, which is also the audience the job's identity token is minted for |
| `audiences` | `""` | the clients to exchange for, comma or newline separated: `k8s:<cluster>` or `aws:<account>:<role>`. Anything else fails the step. May be empty when `github-app` is given |
| `kubeconfig` | `"false"` | `"true"` writes a kubeconfig with one user and one context per `k8s:` audience, the token as bearer, and exports `KUBECONFIG`. The cluster entry (address, CA) is not written: it comes from the platform's own kubeconfig |
| `default-profile` | `""` | a profile to export as `AWS_PROFILE`; it must be one this run wrote, or the step fails |
| `region` | `""` | written into every AWS profile |
| `github-app` | `""` | a [catalogue App](github-apps-catalogue.md#minting-a-token) id to mint an installation token of, under the catalogue's grants |
| `repositories` | `""` | names without the owner, comma, space or newline separated, to narrow that token to. Empty asks for a token not narrowed to any, which only a grant of every repository allows |
| `permissions` | `""` | `name:level` (or `name=level`), to narrow that token to. Empty asks for exactly what the grant allows |

| Output | |
|---|---|
| `profiles` | the AWS profile names written, `<role>@<account>`, space separated |
| `kubeconfig` | the kubeconfig's path, when one was written |
| `github-token` | the installation token, masked, when `github-app` was given |

For every `aws:<account>:<role>` audience the action writes a profile
`<role>@<account>` with `role_arn` and `web_identity_token_file`
(the exchanged token, `0600`, under `$RUNNER_TEMP`), and exports
`AWS_CONFIG_FILE`. A job with no `id-token: write`, an issuer that
refuses an audience, or an audience of neither shape fails the step with
the issuer's own sentence, before anything later runs.

## In a reusable workflow: `token-source: access-roster`

A shared workflow that needs a GitHub App token — to push a tag, open a
pull request — does not have to take a private key from every caller.
It calls the action with `github-app` inside its own job and lets the
caller choose the source with an input; the shared auto-release workflow
this repository's own release uses spells it `token-source`:

```yaml
# the caller
permissions:
  contents: read
  id-token: write            # a called workflow can narrow this, never widen it
jobs:
  tag:
    uses: example-org/shared-workflows/.github/workflows/auto-release.yaml@<commit-sha>   # vX.Y.Z
    with:
      token-source: access-roster
      access-roster-issuer: https://access.example
      github-app: ci-automation          # the catalogue id
```

```yaml
# inside the shared workflow's job
- id: access
  uses: truvity/access-roster@<commit-sha>   # vX.Y.Z
  with:
    issuer: ${{ inputs.access-roster-issuer }}
    github-app: ${{ inputs.github-app }}
    repositories: ${{ github.event.repository.name }}
    permissions: contents:write
- run: gh release create "v${VERSION}" --target "${GITHUB_SHA}" --generate-notes
  env:
    GH_TOKEN: ${{ steps.access.outputs.github-token }}
```

Nothing is stored in the calling repository and nothing needs rotating
there: what the job may have is the catalogue App's grant for the groups
the job's matchers put it in, which is where a `job_workflow_ref` pin
belongs ([pinning a grant](github-apps-catalogue.md#pinning-a-grant-to-one-workflow)).
Keep the two sources in two jobs if the workflow offers both: a job's
`permissions` are static, and one that asks for `id-token: write` fails
every caller that did not grant it.

**Self-hosted runners** are the other GitHub App a deployment needs:
the console creates one [runner App](github-organisation.md#runner-apps)
per organisation per tier, and the deployment hands its key to the runner
scale set. Runners register with it; the jobs on them still exchange
their own identity token as above.

## Or: the same files a laptop uses

A repository that has `accessctl` in its toolchain — each release
carries a Nix flake for devbox ([installing it](../design/accessctl.md#installing-it))
— needs no action and no second copy of its access files. The line a
person's kubeconfig runs,

```yaml
exec:
  command: accessctl
  args: [kube-token, --audience, k8s:staging, --issuer, https://issuer.example.internal]
```

and the line a person's `aws.ini` runs,

```ini
[profile test]
credential_process = accessctl aws --audience aws:111122223333:test --issuer https://issuer.example.internal
```

work unchanged in a job granted `id-token: write`. When
`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` are
set, `accessctl` asks GitHub for the job's identity token — for the
issuer's URL, the one audience it accepts — and exchanges that, presenting
the audience as its client exactly as the action does. Anywhere else it
exchanges the cached sign-in. So one committed file serves both, and what
admits each is the target client's `requires`: list the people's groups
and the job's group together when both should reach it.

Keep credentials off a committed `[default]`: in a job it would shadow
the runner's own identity for every call. Select a named profile instead.
A consumer that is neither kubectl nor an AWS SDK reads `accessctl token
--audience <client>` from stdin, in a job and on a laptop alike.

**Both targets go through the issuer, never directly.** A cluster trusts
one OIDC issuer and that is access-issuer, so a GitHub token can never be
presented to an API server; and cloud accounts trust the issuer's
audiences rather than GitHub's subjects, so the policy stays in one file
instead of in every account's trust policies.

**Token lifetime.** An exchanged token for a CI audience lives as long as
the issuer's client setting for CI says — long enough for a deploy or a
soak step. A job that must outlive it re-runs the action before the long
step.

**Registries and artifacts** — ECR, CodeArtifact, anything else on AWS —
run on top of the profiles the action wrote, with the official actions
and the AWS CLI: [registries-and-artifacts.md](registries-and-artifacts.md).
