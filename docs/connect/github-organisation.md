# Connect a GitHub organisation

> **Half of this is built.** The bindings are: they live in the policy
> and the console lists them on its Rules page, so the model can be
> written and reviewed now. **The controller that acts on them is not**
> (INF-697), and neither is the Connect flow that gives it a credential
> (INF-696). Write the bindings if you want the model in git; teams will
> not move until the controller exists.

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
   and the same *depends on* column that group has. That is the whole of
   what you can verify today.
5. **The controller comes later** (INF-697): one App per organisation,
   created and installed through Connect, deriving membership from these
   bindings every tick and publishing what it did.

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

It holds no GitHub credential it reads, makes no GitHub call, and mints
no token for GitHub. A workflow's identity is the other direction
entirely and is [github-actions.md](github-actions.md): GitHub proves a
job to us, and we never prove anything to GitHub.
