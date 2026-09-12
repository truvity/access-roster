# Connect a GitHub organisation

> **Built, and not yet run against a real organisation.** The bindings,
> the GitHub page, Connect and the controller all exist; the first
> supervised enable is INF-642 on the sandbox organisation, then INF-628
> on the real ones.

**Anchor:** none of ours. The controller holds one GitHub App per
organisation and acts with its own credential; the issuer holds the
bindings, and no part of this service ever proves anything to GitHub.

## The binding

*Internal group → GitHub team* is the same shape as *internal group →
client*, so it is written the same way and read the same way:

```yaml
github:
  truvity:                                  # the organisation's login
    members: [all:truvity:employee]         # in the organisation, with or without a team
    teams:
      team-platform:                        # the team's SLUG, not its display name
        members: [all:platform:engineer]
        maintainers: [all:platform:lead]
      team-security:
        members: [all:security:analyst]
  trust-form:
    teams:
      team-platform:
        members: [all:platform:engineer]
```

The holders of those groups are the people that team should contain. A
team is a consumer of a group exactly as a client is: which accounts hold
one is a question only the directory answers, and the policy answers it
once, in `groups`.

Nothing here reaches a token and no `requires` gates on it: a GitHub team
is not an internal group and opens no client.

**Why it lives in this file rather than the controller's own.** A reader
of the access model sees every GitHub team's source without opening
another file, and `git log` is the history of who was in what. That is
the same reason every other grant lives here.

## Adding one organisation

1. **Name the groups you will bind.** A team's source is an internal
   group, so it must be one the policy declares. Usually it already is —
   the engineers of a project, the leads of a team — and binding it to a
   GitHub team adds one more consumer. Where nothing describes the
   population, declare a group for it the ordinary way and give it a
   provider group to read.
2. **Name the teams** in `github:` under the organisation's login. Both
   halves matter: the organisation is GitHub's login, the team is its
   **slug**, not its display name. Use `maintainers` for the people who
   administer the team, `members` for the rest.
3. **Name the organisation's own members**, if anybody belongs in it
   without a team. Being in a bound team implies membership; this row is
   what accounts for everybody else, and without it they are people no
   binding explains.
4. **Check the Rules page.** Each binding appears beside every other
   rule, with `GitHub team` as its kind, the internal group as its rule,
   and the same *depends on* column that group has.
5. **Connect it**, on the console's GitHub page. An operator presses
   *Connect* beside the organisation; the organisation's **owner** then
   does two things on GitHub and types nothing:
   - **Create** the App GitHub offers. It is private, asks for one
     permission — `members: write` — and has no webhook. GitHub hands its
     key to this service once, on the way back.
   - **Install** it on the organisation, on the page GitHub goes to next.
     Coming back, the service asks GitHub where the App is installed
     rather than trusting the redirect, and the organisation shows as
     connected.

   If the owner stops after Create, the organisation shows *created, not
   installed* and the button becomes *Finish installing*: it picks up at
   Install instead of creating a second App. Only an organisation the
   policy binds can be connected, so a typo in a login is caught here
   rather than on GitHub's 404.
6. **Run the controller**, disabled for the organisation. See *Running the
   controller* below. Its first pass reports on the GitHub page what it
   WOULD do; read it.
7. **Enable the organisation** by adding its login to
   `githubRoster.actsIn`. That is a reviewed change, and the next pass acts.

The service reaches `api.github.com` for Create, Install and Disconnect,
so the cluster's egress policy must allow it.

## Running the controller

The controller is a second process from the same chart:

```yaml
githubRoster:
  enabled: true
  actsIn: []            # born disabled: nothing is changed until an organisation is listed
exchange:
  clusters:
    - name: kernel      # this cluster: the service verifies the controller's token against its key set
      issuer: https://oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLE
      jwksUri: https://oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLE/keys
```

and the policy puts its account in two groups — reading who holds a group,
and recording what it did:

```yaml
groups:
  all:access-roster:viewer:
    matchers:
      - service_account: { cluster: kernel, namespace: access-issuer, name: access-issuer-github-roster }
  all:access-roster:reporter:
    matchers:
      - service_account: { cluster: kernel, namespace: access-issuer, name: access-issuer-github-roster }
```

The account's name is `<release>-github-roster`. The chart refuses to
render the controller without an `exchange.clusters` row or a console
mount, because either absence is a controller that can never read
anything.

**It needs to reach `api.github.com`**, and a default-deny egress policy
has to allow it.

## What it does every pass

For each organisation the policy binds:

1. **Who should be where.** It asks the console who holds each bound
   group. A suspended account is not somebody a team should contain.
2. **What GitHub holds.** Through the organisation's App: members with
   their role and their addresses in the organisation's **verified
   domains**, pending invitations, teams, and each bound team's members
   in both roles. All of it, or the pass fails: a partial read acted on is
   how the wrong people get removed.
3. **Who is who.** A login is matched to a person by a verified-domain
   address, and by nothing else. One account with addresses in two
   workspaces is one member. An address two accounts claim is linked to
   neither, and held.
4. **What to change.**
   - somebody wanted and not a member is **invited** by address, straight
     into every team that wants them — once;
   - a member wanted in a team is **added** in the role wanted, and a
     wrong role is **changed**; a maintainer group wins over a member
     group;
   - a member of a bound team whom no bound group wants is **removed**
     from that team;
   - a member the directory **no longer has** — not found, or suspended —
     is **removed from the organisation**, and so from every team.
5. **Act** where the organisation is in `actsIn`, and **report**: the
   GitHub page shows every person's state and what comes next, and each
   change and each newly held action is recorded in the audit stream.

**A removal never rests on absence.** Before anybody is removed, the
controller asks the console about that one address, and acts only on an
answer the directory vouches for. An unreadable workspace, a truncated
list, a directory mid-outage: each holds the removal, with the reason on
the row, and removes nobody.

**Held, with a reason, rather than done:**

| Held | Because |
|---|---|
| a removal the directory cannot vouch for | absence from a list is not evidence |
| removing an owner from the organisation | owners are declared elsewhere |
| an invitation to a domain no member has a verified address at | it is very likely not a verified domain of the organisation, and an accepted invitation could not be matched back to anybody |
| an address two accounts claim | acting on either is a guess |
| anything in a team GitHub does not have | teams are created by whatever manages the organisation's structure, never here |
| a change GitHub refused | GitHub's words are on the row |

**Never touched:** a member with no verified address (listed as *not
linked*), a team no binding names, and anybody's owner status.

## Disconnecting

*Disconnect* uninstalls the App from the organisation, then forgets the
record and the key. GitHub's API cannot delete an App, so the
registration stays for its owner to delete; the console says where. Once
uninstalled and forgotten nothing can act through it — this service held
its only key. An uninstall that fails still forgets, and says what is
left to do on GitHub.

Nobody is removed from anything by disconnecting: the organisation simply
stops being managed.

## What connecting leaves behind

| Object | Holds | Read by |
|---|---|---|
| ConfigMap `<release>-github-orgs` | one record per organisation: the App's id and slug, where it is installed, when and by whom it was connected | the console |
| Secret `<release>-github-apps` | one credential per organisation: the App's id, its installation, its private key | the controller, as a mounted volume; this service only to uninstall on Disconnect |

Both exist, empty, from the service's first start, so the controller's
volume always has a Secret behind it. Recovery for a lost key is
Disconnect and Connect again; there is no backup, and no copy of the key
anywhere else — not in git, not in a password manager.

## What the render refuses, and why each is silent otherwise

| Refused | Because |
|---|---|
| a group nothing declares | the binding would name something with no meaning, and read as though it worked |
| a team with neither `members` nor `maintainers` | *remove everyone from platform* is not something to express by leaving a list out |
| an organisation binding no group and no team | *stop managing this organisation* is expressed by removing it |
| the same team declared twice across two merged files | the second would replace the first, with nothing to see |
| the same organisation's `members` declared twice | the same reason |

The same team name in two **organisations** is fine — `team-platform` on
two orgs is two different teams.

## What the service never does here

The service never acts on GitHub with the key it keeps: the controller
does, from its own process. The one use the service makes of it is
uninstalling on Disconnect. It mints no token for GitHub. A workflow's identity is the other direction
entirely and is [github-actions.md](github-actions.md): GitHub proves a
job to us, and we never prove anything to GitHub.
