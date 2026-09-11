# Registries and artifacts on top of the profiles

> **`accessctl` and the GitHub Action are not built yet (INF-649).**
> Everything on this page that names one describes what it will run, not
> what you can run today. The issuer side is real and can be set up now;
> the laptop and workflow side waits for the CLI.


ECR and CodeArtifact have no trust relationship of their own with the
issuer. Both are an AWS credential plus a tool-specific handshake, and
the credential is what access-roster prepared: a profile per granted role,
named `<role>@<account>`, on a laptop with `accessctl aws` behind it and in
a job with a web-identity token file. Everything on this page is AWS's own
tooling using those profiles. Many registries, many accounts, many
artifact domains: many profiles and many `--profile` flags.

## The rule

Grant roles whose only purpose is registry or artifact access, so a job
or a person who needs to push an image does not also get anything else:

```yaml
groups:
  ci-app:   { matchers: [{ github: { repository: example-org/app, ref: refs/heads/master } }] }
  engineer: { members: [engineers@example.com] }
clients:
  aws:111122223333:ecr-push:         { kind: exchange, requires: [ci-app] }
  aws:444455556666:artifacts-reader: { kind: exchange, requires: [engineer] }
```

## ECR

**In a job**, one step per account, the official action with the profile
selected by environment:

```yaml
- uses: aws-actions/amazon-ecr-login@v2
  env: { AWS_PROFILE: ecr-push@111122223333, AWS_REGION: eu-central-1 }
  with: { registries: "111122223333" }
- uses: aws-actions/amazon-ecr-login@v2
  env: { AWS_PROFILE: artifacts-reader@444455556666, AWS_REGION: eu-west-1 }
  with: { registries: "444455556666" }
```

**On a laptop**, Amazon's credential helper, mapped per registry host so
`docker push` never sees an expired login:

```json
{ "credHelpers": {
    "111122223333.dkr.ecr.eu-central-1.amazonaws.com": "ecr-login",
    "444455556666.dkr.ecr.eu-west-1.amazonaws.com": "ecr-login" } }
```

The helper reads the profile in `AWS_PROFILE`; when two registries need
two roles, set the profile per shell or use the helper's per-registry
profile mapping. `accessctl setup` prints this block for the registries
implied by your granted roles.

## CodeArtifact

One login per domain and tool, always with `--profile`:

| Tool | Command |
|---|---|
| npm, pnpm, yarn | `aws codeartifact login --tool npm --domain d --domain-owner 444455556666 --repository npm-store --profile artifacts-reader@444455556666` |
| pip | `aws codeartifact login --tool pip …` |
| twine | `aws codeartifact login --tool twine …` |
| NuGet / dotnet | `aws codeartifact login --tool nuget …` / `--tool dotnet …` |
| Swift | `aws codeartifact login --tool swift …` |
| Ruby (gem, bundler) | `aws codeartifact login --tool ruby …` |
| Cargo | `aws codeartifact login --tool cargo …` |
| Go | `export GOPROXY=https://aws:$(aws codeartifact get-authorization-token --domain d --domain-owner 444455556666 --query authorizationToken --output text --profile artifacts-reader@444455556666)@d-444455556666.d.codeartifact.eu-west-1.amazonaws.com/go/go-store/` |
| Maven | the same token as `<password>` for the repository's `<server>` in `settings.xml`, endpoint from `aws codeartifact get-repository-endpoint --format maven` |
| Gradle | the same token in `gradle.properties` for the repository credentials |
| generic | `aws codeartifact get-authorization-token` and the repository endpoint from `get-repository-endpoint --format generic` |

Tokens live twelve hours. In a job, run the login after the access-roster
step; on a laptop, `accessctl setup` prints the exact lines for the
domains your granted roles reach, and a shell alias per tool is the usual
way to keep them handy.

## Anything else on AWS

`--profile <role>@<account>`. That is the entire integration.
