# Connect a GitHub organisation

> **Most of this is built.** The bindings live in the policy and show on
> the Rules page; the console's GitHub page shows each organisation; and
> **Connect** creates and installs the App. **The controller that acts on
> them is not built yet** (INF-697): a connected organisation's teams do
> not move until it exists.

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
6. **The controller comes later** (INF-697): deriving membership from
   these bindings every pass, acting through the connected App, and
   reporting on the same page.

The service reaches `api.github.com` for Create, Install and Disconnect,
so the cluster's egress policy must allow it.

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

## What this service never does here

It never acts on GitHub with the key it keeps: the controller does. The
one use this service makes of it is uninstalling on Disconnect. It mints
no token for GitHub. A workflow's identity is the other direction
entirely and is [github-actions.md](github-actions.md): GitHub proves a
job to us, and we never prove anything to GitHub.
