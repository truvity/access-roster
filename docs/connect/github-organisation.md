# Connect a GitHub organisation

> **Half of this is built.** The bindings are: they live in the policy,
> the console lists them on its Rules page, and adding an organisation is
> the row below. **The controller that acts on them is not** (INF-697) —
> nothing yet changes a team's membership on GitHub. Write the bindings
> now if you want the model in git and reviewable; teams will not move
> until the controller exists.

**Anchor:** none of ours. The controller will hold a GitHub App per
organisation and act with its own credential; access-roster holds the
bindings and never talks to GitHub.

## The binding

*Directory group → GitHub team* is the same shape as *directory group →
internal group*, so it is written the same way and read the same way:

```yaml
github:
  truvity:
    platform: [team-platform@truvity.com, sre@truvity.com]
    security: [sec@truvity.com]
  trust-form:
    platform: [team-platform@trustform.eu]
```

The people the directory puts in those groups are the people that team
should contain. Nothing here reaches a token, and no `requires` gates on
it: a GitHub team is not an internal group and opens no client.

**Why it lives in this file rather than the controller's own.** A reader
of the access model sees every GitHub team's source without opening
another file, and `git log` is the history of who was in what. That is
the same reason every other grant lives here.

## Adding one organisation

1. **Name the teams** in `github:` under the organisation's login, each
   with the provider groups that feed it. Both halves of the name matter:
   the organisation is GitHub's login, the team is its **slug**, not its
   display name.
2. **Check the Rules page.** Each binding appears beside every other rule,
   with `provider group` as its kind and the same *depends on* column —
   they depend on the directory, like any membership. That is the whole
   of what you can verify today.
3. **The controller comes later** (INF-697): one App per organisation,
   installed by an owner, with the links it maintains in a ConfigMap the
   console reads.

## What the render refuses, and why each is silent otherwise

| Refused | Because |
|---|---|
| a team fed by an empty list | *remove everyone from platform* is not something to express by leaving a list out |
| the same team declared twice across two merged files | the second would replace the first, with nothing to see |
| an address with no domain | every membership routes by the domain after the `@` |

The same team name in two **organisations** is fine — `platform` on two
orgs is two different teams.

## What access-roster never does here

It holds no GitHub credential, makes no GitHub call, and mints no token
for GitHub. A workflow's identity is the other direction entirely and is
[github-actions.md](github-actions.md): GitHub proves a job to us, and we
never prove anything to GitHub.
