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
   their role, pending invitations, teams, and each bound team's members
   in both roles. All of it, or the pass fails: a partial read acted on is
   how the wrong people get removed.
3. **Who is who.** A GitHub account belongs to the person who
   [linked it](#linking-accounts), by the work addresses GitHub verified
   on it. On an organisation on GitHub's Enterprise Cloud plan, members'
   addresses in its verified domains count as well; on every other plan
   GitHub discloses no member's address, and a link is the only way. A
   member nobody linked whose public profile shows a work address the
   directory has, live, is [linked from the profile](#where-a-link-comes-from).
   One account with addresses in two workspaces is one member. An address
   two accounts claim is linked to neither, and held.
4. **What to change.**
   - somebody wanted and not a member, who linked an account, is
     **invited** as that account, straight into every team that wants
     them — once. Somebody who has not linked is *not linked*: waiting on
     them, not held, because there is nobody to invite;
   - a member wanted in a team is **added** in the role wanted, and a
     wrong role is **changed**; a maintainer group wins over a member
     group;
   - a member of a bound team whom no bound group wants is **removed**
     from that team;
   - a member the directory **no longer has** — not found, or suspended —
     is **removed from the organisation**, and so from every team;
   - a member whose link **GitHub says is gone** — the address removed or
     unverified, or the authorization revoked — is **removed from the
     organisation** at once. It is the one removal that does not ask the
     directory: the account is no longer shown to be anybody's.
5. **Check the organisation as a whole**, and hold what fails:
   - an account that let **two invitations expire** since it last linked is
     not invited a third time; linking again starts over;
   - nobody is invited without a **free seat** — seats minus taken seats
     minus pending invitations — and nobody at all while the seats cannot
     be read. The controller never buys a seat, and GitHub would either
     buy one or refuse;
   - if the removals concern **more than half the organisation's members**,
     nobody is removed until an operator confirms exactly that set.
6. **Act** where the organisation is in `actsIn`, and **report**: the
   GitHub page shows every person's state and what comes next, and each
   change, each newly held action and each owner the policy would change
   is recorded in the audit stream.

**A removal never rests on absence.** Before anybody is removed, the
controller asks the console about that one address, and acts only on an
answer the directory vouches for. An unreadable workspace, a truncated
list, a directory mid-outage: each holds the removal, with the reason on
the row, and removes nobody.

**Held until a person acts** — shown as *needs you*:

| Held | What to do |
|---|---|
| no free seat | buy seats in the organisation's billing |
| seats cannot be read | approve organisation administration (read) for the App |
| removals over half the organisation | read them, then **Confirm** on the GitHub page — for exactly that set; a different set needs confirming again, and a confirmation lapses after a day |
| anything in a team GitHub does not have | create the team where the organisation's structure is managed |
| an address two accounts claim | the person unlinks one |

**Retried every pass**, because it clears on its own: a removal the
directory cannot vouch for right now, and a change GitHub refused (its
words are on the row).

**Owners are added, never taken away.** Owners and billing are managed
outside, and an organisation's break-glass seat must keep what it has. An
owner is added to the teams the policy wants them in and promoted to
maintainer where it wants that, like anybody; an owner is never removed
from a team, never demoted in one, and never removed from the
organisation. Each of those is said on the page and in the audit stream
(`github.owner.reported`), once.
**Outside collaborators** are listed and never managed.

**Never touched:** a member nobody linked (listed as *not linked*), a
team no binding names, anybody's owner status, and anything the
organisation's `ignore` list names — an address in a bound group that
nobody here can take out of it, a temporary owner. The organisation's page
lists what is ignored.

## Linking accounts

GitHub tells an organisation outside its Enterprise Cloud plan nothing
about which work address a member has — not the App, not an owner. So
each person shows it themselves, once.

**Set up once.** On the GitHub page an operator presses **Create link
App** under an organisation they own. It is a separate App from the
organisations', on purpose:

| | The link App | An organisation's App |
|---|---|---|
| used by | each person, authorizing it as themselves | the controller |
| permission | read the person's own email addresses | `members: write` |
| installed | nowhere | on its organisation |
| visibility | **public**: a private App can only be authorized by members of its owner organisation, which a new hire and a partner's engineer are not | private |
| kept | client id and secret | private key |

A person's token carries its App's permissions, so a token for the link
App reads one person's addresses and nothing else.

**What a person does.** They open the link page the GitHub page shows —
`https://<issuer>/connect/github/link` — press *Continue to GitHub*,
and authorize. No console role is needed: the proof is GitHub's. The
service reads the account and its **verified** addresses and links the
account to each address the directory has, live and vouched for. A
personal address is ignored; an unverified one proves nothing; a
suspended account's address is refused with the reason on the page.
Linking a second account with the same address moves the address to it,
and the first account, proving nothing, is lost.

**Checked every pass.** The link keeps the person's token pair. Every pass
the controller reads the account's verified addresses again:

| GitHub says | The link | The account |
|---|---|---|
| the addresses are still verified | linked | stays |
| a linked address is gone, or unverified, and others remain | narrowed | stays, by what remains |
| every linked address is gone or unverified | lost | **leaves the organisation at once** |
| the authorization was revoked, or the account is gone | lost | **leaves at once** |
| nothing — an outage, a timeout, a rate limit | unchanged | nothing happens |
| the token pair was lost in an interrupted renewal | unverifiable | nothing happens; the person links again |

GitHub rotates the pair on every renewal and kills the old one, so a
renewal is written as *in progress* before it is made and as done right
after; one found in progress on a later pass is never read as a
revocation. A link is only ever checked with the credentials of the App
that issued it.

An owner's link going lost is reported, like anything about an owner.

### Where a link comes from

| Source | Proof | Checked on GitHub every pass | Removed when the address leaves GitHub |
|---|---|---|---|
| **linked by them** | they authorized the link App; GitHub verified the address | yes | yes |
| **public profile** | the account publishes the work address; GitHub lets an account publish only a verified one. Matched automatically, members only | no | no — hiding an address is not removing it |
| **imported** | an approved pairing from github-roster 0.x, imported once | no | no |

All three count as the person: they are invited, moved between teams and
removed when the directory suspends them. A profile match or an import
happens only when the address is a live account the directory vouches
for and the account is a member already, and never displaces a link the
person made. The person linking themselves replaces it.

**Disconnecting the link App** makes every self-link unverifiable — nothing
can check their tokens any more — which adds and removes nobody until
each person links again. A profile match or an import holds no token of
the App's, and stands.

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
| Secret `<release>-github-apps` | one credential per organisation: the App's id, its installation, its private key; and the link App's client id and secret under `_link.json` | the controller, as a mounted volume; this service to uninstall on Disconnect and to redeem a person's authorization |
| Secret `<release>-github-links` | one link per GitHub account (`<id>.json`): its login, the addresses it proves, its state, the person's token pair | this service, which writes a link; the controller, which rewrites it as it checks — the one Secret its Role may update, by name |

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
