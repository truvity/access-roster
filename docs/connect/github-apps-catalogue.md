# A catalogue of GitHub Apps

> **Built.** Declaring, creating, installing, drift and the kept key ship
> in 1.11. Minting installation tokens under the grants is the next step
> and is not built yet: the grants are declared, validated and shown now.

**Anchor:** none of ours. An App is created on GitHub by an owner of its
organisation, from a manifest this service posts, and GitHub hands the
App's private key to this service once. Nothing is typed or pasted.

A deployment usually needs more GitHub Apps than the three this service
creates for itself — one for dependency updates, one for releases, one
for a bot that labels pull requests. Each is the same chore by hand: fill
in a form on GitHub, pick permissions, download a key, put the key
somewhere, install the App, write down its ids. The catalogue turns each
into a declaration in the deployment's values and two clicks in the
console.

## Declaring an App

```yaml
githubApps:
  catalogue:
    - id: renovate                 # [a-z0-9-], at most 32, unique; never changes
      org: example-org             # the organisation the App is created under
      name: example-org-renovate   # optional; default <org>-<id>, at most 34
      description: Dependency updates for example-org
      public: false                # a private App installs only on example-org
      permissions:                 # GitHub's permission names: read | write | admin
        contents: write
        pull_requests: write
        issues: write
        workflows: write
      events: []                   # optional; the webhook stays inactive regardless
      installation: all            # all | selected (default): what the installer is expected to pick
      grants:
        - group: all:platform:engineer
          repositories: ["*"]
          permissions: {contents: read, pull_requests: read}
        - group: all:docs:writer
          repositories: [docs, "site-*"]
          permissions: {contents: write, pull_requests: write}
```

| Field | Meaning |
|---|---|
| `id` | the App's name **here**: where it is kept and what a token request will name. Lower-case letters, digits and dashes, at most 32. Renaming it forgets the App (see [Disconnecting](#disconnecting)) |
| `org` | the organisation's login. The App is created under it, and an App created under anything else is refused |
| `name` | the App's name on GitHub, which is global across GitHub. Empty is `<org>-<id>`, cut to 34 characters; a declared name over 34 is refused |
| `description` | shown on the App's page on GitHub and in the console |
| `public` | whether any account may install it. Leave it `false` unless something outside the organisation installs the App |
| `permissions` | the App's permissions, by the names GitHub's REST API uses (`contents`, `pull_requests`, `members`, `organization_administration`, …), each `read`, `write` or `admin`. At least one |
| `events` | the webhook events the App subscribes to. The webhook is never active: nothing in this service receives one |
| `installation` | `all` or `selected`. GitHub's install page is where the installer chooses; this says which choice the deployment expects, and the console shows both |
| `grants` | who may ask for a token of this App — see below |

The catalogue is rendered into `ConfigMap <release>-github-apps-catalogue`,
mounted, and read once at start; a change rolls the service out. **The
service refuses to start** on an unknown key, a duplicate id, a level
that is not `read`, `write` or `admin`, a name GitHub would refuse, a
grant above the App, a glob that does not compile, or a grant naming a
group the policy does not declare. A wrong declaration found at start
costs a rollout; one found after the App was created costs an owner's
edit on GitHub, because nothing here can change an App's permissions.

## Grants

A grant says that the holders of one policy group may ask for an
installation token of the App, for some of its repositories, with at most
some of its permissions:

```yaml
grants:
  - group: all:docs:writer            # a group the policy declares
    repositories: [docs, "site-*"]    # names or globs, within the App's organisation
    permissions: {contents: write}    # the most a token may carry
```

- `repositories` are repository names in the App's organisation, or
  globs in Go's `path.Match` syntax (`*`, `?`, `[a-c]`). `["*"]` is every
  repository. No `/`: a grant never reaches another organisation.
- every permission in a grant must be one the App has, at a level no
  higher than the App's: `read` < `write` < `admin`. A grant of
  `contents: write` on an App with `contents: read` is refused.
- a group may appear in several grants; each is read on its own.

**Tokens are not minted yet.** The next release adds an exchange: a
person or a workload holding the group signs in as usual, exchanges its
token for an installation token of the App, and gets one scoped to the
repositories and permissions its grant allows — never more than the
grant, and never more than it asked for. Until then, grants are
validated at start and shown on the App's page, so the declaration can
be reviewed before anything acts on it.

## Creating and installing

The *Apps* tab of the GitHub page links to the **Catalogue**, one row per
declared App; each App has a page of its own.

1. **Create.** An operator presses *Create*. The browser posts the App's
   manifest to GitHub's create page for the organisation; an owner of
   the organisation confirms. GitHub returns to
   `/connect/github/catalogue/callback` with a one-time code, and the
   service exchanges it for the App's id and private key. The App now
   reads *created, not installed*.
2. **Install.** The browser goes straight on to the App's install page.
   The owner picks all or selected repositories and installs. GitHub
   returns to `/connect/github/catalogue/setup`; the service asks GitHub,
   as the App, where it is installed on the organisation — the id in the
   redirect is a browser's word for it — and keeps that.

If the owner stops between the two, the App's page offers *Install*,
which picks up where they left off rather than creating a second App.
Both redirects check the flow cookie against a state signed by this
service naming the App and the operator who started; a state from any
other GitHub flow is refused.

## Where the key is kept

Every catalogue App is in one Secret, `<release>-github-catalogue-apps`,
created empty at the service's first start:

| Key | Holds |
|---|---|
| `<id>.github_app_id` | the App's numeric id |
| `<id>.github_app_installation_id` | the installation on the organisation |
| `<id>.github_app_private_key` | the App's private key, PEM, exactly as GitHub issued it |
| `<id>.record.json` | the App's record: `version`, `id`, `org`, `app_id`, `app_slug`, `installation_id`, `html_url`, `connected_at`, `connected_by` |
| `<id>.pending_private_key` | the key of an App created and **not yet installed**, instead of the three above |

The three property keys exist only once the App is installed, so a copy
taken between the two clicks never hands anything an App that cannot
mint a token. No copy of a key exists anywhere else — not in git, not in
a password manager.

### Backing it up

A deployment copies the Secret to a store that travels with its backups.
An External Secrets `PushSecret` does that for any provider External
Secrets writes to — a Vault or OpenBao, a cloud secret manager — and the
restore is the matching `ExternalSecret`:

```yaml
apiVersion: external-secrets.io/v1alpha1
kind: PushSecret
metadata:
  name: access-issuer-github-catalogue-apps
  namespace: access-issuer
spec:
  refreshInterval: 1h
  deletionPolicy: None            # a forgotten App's copy stays until removed by hand
  secretStoreRefs:
    - name: backup-store          # a SecretStore for your Vault, OpenBao or cloud manager
      kind: SecretStore
  selector:
    secret:
      name: access-issuer-github-catalogue-apps
  data:
    - match:
        secretKey: renovate.github_app_private_key
        remoteRef:
          remoteKey: access-issuer/github-apps/renovate
          property: private_key
    - match:
        secretKey: renovate.github_app_id
        remoteRef:
          remoteKey: access-issuer/github-apps/renovate
          property: app_id
    - match:
        secretKey: renovate.github_app_installation_id
        remoteRef:
          remoteKey: access-issuer/github-apps/renovate
          property: installation_id
    - match:
        secretKey: renovate.record.json
        remoteRef:
          remoteKey: access-issuer/github-apps/renovate
          property: record
```

One block of four entries per App. The same keys are what anything else
that needs the App — a job that mints its own tokens today — reads, under
names that do not change for the life of the App.

**Restoring** is putting the Secret back, with its label
`directory-roster.truvity.com/kind: github-catalogue-apps`, before the
service starts. The records are beside the keys, so nothing else is
needed ([configuration](../reference/configuration.md#restoring-from-the-secrets-alone)).

## State and drift

Each App reads one of four states:

| State | Means |
|---|---|
| *not created* | declared, and nobody has created it on GitHub |
| *created, not installed* | the owner stopped after Create; *Install* finishes |
| *installed* | installed, and GitHub holds what the catalogue declares |
| *differs on GitHub* | GitHub holds something else; the page lists each difference |

The service asks GitHub, as the App, for the App (`GET /app`) and its
installation (`GET /app/installations/{id}`), and compares:

- **the App's permissions with the declaration.** A permission GitHub
  holds that the catalogue does not declare, one it lacks, and one at a
  different level are each a line. `metadata: read` is not drift: GitHub
  gives it to every App that touches repositories.
- **the App's events**, when the catalogue declares any.
- **the installation's accepted permissions with the App's.** When an
  owner adds a permission to an App, every installation keeps the old
  set until somebody approves the request on GitHub; until then the
  page says *approve the permission request on GitHub*.
- **the installation itself.** One uninstalled on GitHub, or suspended,
  is said as such.

What GitHub said is kept for a minute, so a page left open does not spend
the App's rate limit; *Re-check* asks again at once. A failure to ask —
GitHub down, egress closed, a damaged key — is shown as the App's reason,
and the rest of the GitHub page is unaffected.

**Why the fix is a human edit.** GitHub has no API to change an App's
permissions, events or name: a manifest creates an App once, and after
that only its owner can edit it, in the App's settings on GitHub. So the
console shows the difference and links to
`https://github.com/organizations/<org>/settings/apps/<slug>`; the owner
changes the App (or the catalogue changes to match it), approves the
installation's request if one appears, and presses *Re-check*.

## Disconnecting

*Disconnect* uninstalls the App from the organisation, then forgets its
record and every key it had here. A failed uninstall still forgets, and
says what is left to do on GitHub. **It does not delete the App on
GitHub** — the API cannot — so the registration stays for its owner to
delete in the App's settings, which the console links to.

An App whose entry is removed from the catalogue, or whose `id` changes,
stays listed as *no longer declared* so it can be disconnected; it cannot
be created again under that id until it is declared again.

## What it leaves behind

| Object | Holds | Written by |
|---|---|---|
| ConfigMap `<release>-github-apps-catalogue` | the declaration, `catalogue.yaml` | the chart, when `githubApps.catalogue` is not empty |
| Secret `<release>-github-catalogue-apps` | every catalogue App's keys and record, as above | the service, on Create and Install; created empty at start |

Audit events: `github.catalogue-app.created`, `.installed` and
`.disconnected`, each naming the App's id and GitHub id.
