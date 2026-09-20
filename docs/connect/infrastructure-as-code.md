# Connect an infrastructure-as-code program

**Anchor:** a [catalogue GitHub App](github-apps-catalogue.md). A Pulumi
or Terraform program that manages a GitHub organisation acts as an App of
its own — never as a person's account, and never as this service.

There is a line through GitHub ownership, and it is worth saying plainly:

> **This service owns identities and credentials. The
> infrastructure-as-code program owns structure, and names identities
> rather than creating them.**

So the program creates repositories, teams, rulesets and organisation
settings; the Apps those repositories are automated by are declared in
this deployment's catalogue, created by an owner from the console, and
their keys are held here. The program's *own* identity is one of those
Apps — `iac` in the [default set](github-apps-catalogue.md#a-default-set)
— and this page is how it gets hold of it.

## Two ways to hold the credential, and which to choose

| | **From a secret store** | **Exchanged at run time** |
|---|---|---|
| The program reads | a path in OpenBAO, Vault or a cloud manager | an installation token from this issuer's `/token` |
| It depends on | the store being up | the issuer being up, and the job having a proof |
| The credential is | the App's **private key**, durable | a token, minted per run, an hour at most |
| Left in the audit trail | nothing here; the store's own log | one `github.token.minted` event per run |
| Right for | an apply that must not be blocked by this service — a program that manages the estate, including this service's own deployment | every CI job, every script, every person |

**Take the exchange unless you cannot.** A job that can ask for a token
holds nothing between runs, is narrowed to the repositories and
permissions one grant allows, and leaves a record of every mint; that is
[minting a token](github-apps-catalogue.md#minting-a-token), and it is
the whole of what CI needs.

The store is for the case the exchange cannot serve: a program whose
apply must run while this service is being upgraded, replaced or
restored — the program that manages the platform this service runs on. It
buys that independence with a second durable copy of a key, which is a
real cost and is [dealt with below](#the-copy-is-a-real-credential).

## Declaring the App and its projection

One entry in the catalogue, with a `push` block:

```yaml
githubApps:
  catalogue:
    - id: iac
      org: example-org
      description: The program that manages the organisation
      permissions:
        organization_administration: write   # org settings, org rulesets
        members: write                       # teams and their membership
        administration: write                # repositories, their settings and rulesets
        contents: read
        metadata: read
      installation: all
      push:
        secretStore:
          name: example-store      # a SecretStore or ClusterSecretStore you already have
          kind: ClusterSecretStore # SecretStore (default) | ClusterSecretStore
        remoteKey: platform/github-apps/iac
        refreshInterval: 1h        # optional; 1h
        deletionPolicy: None       # optional; None (default) | Delete
```

`push` is off unless an entry carries it. The chart invents neither the
store nor the path: both are named here, by whoever runs the deployment.
It renders one External Secrets
[`PushSecret`](https://external-secrets.io/latest/api/pushsecret/) per
entry, `<release>-github-app-<id>`, which copies **three keys and
nothing else** out of the Secret this service keeps every catalogue App
in:

| In the store, at `remoteKey` | From | Is |
|---|---|---|
| `app_id` | `<id>.github_app_id` | the App's numeric id |
| `installation_id` | `<id>.github_app_installation_id` | its installation on the organisation |
| `private_key` | `<id>.github_app_private_key` | the App's private key, PEM, as GitHub issued it |

Never the record, never another App's keys, never the whole Secret. The
three exist only once the App is **installed**, so nothing is pushed for
an App an operator created and stopped at.

Two entries pushing to one path in one store is refused at render: one
would overwrite the other, and whoever read that path could not tell
which App's key they held. `push` also needs `directory.store:
kubernetes`, because with any other store there is no Secret to push
from.

## The operator's steps

1. **Declare.** Add the entry above to the deployment's values and roll
   the release out. The catalogue is read once at start.
2. **Create.** On the console's GitHub page, *Apps* → *Catalogue* → the
   App → *Create*. An owner of the organisation confirms GitHub's
   manifest; GitHub hands this service the key, once.
3. **Install.** The browser goes on to the install page; the owner
   installs on the organisation.
4. **The credential appears.** The service writes the three keys; the
   PushSecret copies them to the store within its refresh interval. From
   then on the program reads them like any other stored secret.

Nothing in steps 2 and 3 is typed, pasted or downloaded, which is the
point of the catalogue. Step 4 is the only moment a key of this service's
leaves it.

## A Pulumi program in Go

The program reads the three properties from the store and builds a GitHub
provider with them. Everything after that is ordinary: resources with
`pulumi.Provider(gh)` act as the App.

```go
package main

import (
	"github.com/pulumi/pulumi-github/sdk/v6/go/github"
	"github.com/pulumi/pulumi-vault/sdk/v6/go/vault/kv"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// The App's credential, where the PushSecret put it. The vault
		// provider is configured by the stack (address, namespace) and
		// authenticates as whoever runs the apply -- a CI job's own
		// identity, or a person's sign-in. Nothing of this service is
		// involved at this moment, which is the reason for this path.
		app, err := kv.LookupSecretV2(ctx, &kv.LookupSecretV2Args{
			Mount: "kv",
			Name:  "platform/github-apps/iac",
		})
		if err != nil {
			return err
		}

		// The key is a secret: mark it so, or it is written to the
		// stack's state in the clear.
		pem := pulumi.ToSecret(pulumi.String(app.Data["private_key"])).(pulumi.StringOutput)

		gh, err := github.NewProvider(ctx, "github", &github.ProviderArgs{
			Owner: pulumi.String("example-org"),
			AppAuth: &github.ProviderAppAuthArgs{
				Id:             pulumi.String(app.Data["app_id"]),
				InstallationId: pulumi.String(app.Data["installation_id"]),
				PemFile:        pem,
			},
		})
		if err != nil {
			return err
		}

		// From here the program owns structure, and only structure.
		_, err = github.NewRepository(ctx, "docs", &github.RepositoryArgs{
			Name:       pulumi.String("docs"),
			Visibility: pulumi.String("private"),
		}, pulumi.Provider(gh))
		return err
	})
}
```

The provider mints its own installation tokens from that key and renews
them as it runs; nothing here caches one.

Two things that bite:

- **The PEM keeps its newlines.** What the store holds is the file GitHub
  issued. A store or a shell that flattens it into one line gives
  *could not parse private key*, and the fix is at the reading end, not
  by re-encoding what this service wrote.
- **Secrets in state.** A provider's inputs are recorded in the stack's
  state. `pulumi.ToSecret` above is what keeps the key encrypted there;
  without it a state file is a copy of the credential too.

### Terraform, in a few lines

```hcl
data "vault_kv_secret_v2" "iac" {
  mount = "kv"
  name  = "platform/github-apps/iac"
}

provider "github" {
  owner = "example-org"
  app_auth {
    id              = data.vault_kv_secret_v2.iac.data["app_id"]
    installation_id = data.vault_kv_secret_v2.iac.data["installation_id"]
    pem_file        = data.vault_kv_secret_v2.iac.data["private_key"]
  }
}
```

The same caveat applies harder: a Terraform state file holds data-source
results in the clear, so the state belongs in a backend with encryption
and access control of its own.

### The other way, for a CI job

A job that can reach this issuer should not read the store at all:

```yaml
permissions:
  id-token: write
steps:
  - id: access
    uses: truvity/access-roster@v1.11.0
    with:
      issuer: https://access.example.com
      github-app: ci-automation      # the catalogue id
      repositories: docs
      permissions: pull_requests:write
  - run: gh pr review --approve "$PR"
    env:
      GH_TOKEN: ${{ steps.access.outputs.github-token }}
```

The job holds no key, the token dies within the hour, and the request is
in the audit trail with the grant it was decided under
([details](github-apps-catalogue.md#minting-a-token)). The same is
available to a laptop and to any script as `accessctl github-token`.

## The copy is a real credential

What lands in the store is **the App's private key**, not a token and not
a derived thing. Anything holding it can act as the App for as long as
the App exists, without asking this service and without appearing in its
audit trail.

That means:

- **Rotate it as a credential.** The App's key is the thing to rotate,
  not the copy; rotating the copy alone changes nothing. GitHub has no
  API to replace an App's key, so the honest procedure is *Disconnect* on
  the App's page and create it again from the catalogue: a new App, a new
  key, pushed to the same path, picked up by the program at its next
  apply. An owner who instead generates a new key in the App's settings
  on GitHub invalidates this service's copy as well, and the App's page
  says so.
- **The store is in the App's blast radius.** Whoever can read that path
  can act as the App; with the `iac` App's permissions that is the
  organisation. Give the path its own policy, and read it only from the
  program.
- **Removing the declaration does not remove the copy.**
  `deletionPolicy: None` leaves what was written for somebody to remove
  deliberately — a chart change should not break a consumer's next apply
  from a distance. `Delete` reverses that trade; pick it knowingly.
- **Push one App, not the catalogue.** Every entry carrying `push` is
  another durable copy. The Apps whose consumers can exchange a token
  should not carry one.

Backing up the *whole* Secret for restore is a different job with a
different shape — one PushSecret over every key, including each App's
record — and it is
[Backing it up](github-apps-catalogue.md#backing-it-up).
