---
title: AI agents
description: How AI agents contribute to sluis, who answers for their work, how a team of agents splits its roles, and what an agent reports back.
status: page
sidebar:
  order: 7
---

AI agents may write issues, code, tests and docs for sluis. Their work is reviewed like any other, and they follow the same pages as people. `AGENTS.md` at the repository root is the short form of these pages for an agent, with the page to read before each kind of change; `CLAUDE.md` loads it for Claude Code.

## A person answers for it

- A person owns the contribution. That person has read it, understands it and answers for it.
- Mention the assistance in the pull request.
- An agent does not decide scope and does not touch governance files unless asked. It presents options with pros, cons and a recommendation, and the maintainer decides ([Decision records](/contributing/decisions/)).
- Output that is plausible but unverified is not a contribution. Run it, test it, and say what you ran ([Tools, checks and verification](/contributing/tools/)).
- Low-effort bulk pull requests may be closed without review.

## Attribution

A commit or a pull request that an agent wrote keeps the attribution lines the tool adds, such as a `Co-Authored-By` trailer. A DCO sign-off, where one is asked for, is the human contributor's legal statement: an agent never adds one on its own.

## Safety tooling

An agent does not work around a safety check, a permission prompt or a refused command. If one blocks the work, the agent stops and reports what blocked it and what it was trying to do.

## Roles in a team

When several agents work on one change, each has one role, and the roles stay separate. There is no single combined "reviewer".

| Role | May change | Does |
|---|---|---|
| implementer | source code, including the site's code in `site/` | builds the change |
| security | nothing: read-only | reviews for faults and reports findings; never edits |
| qa | tests and test data | writes and runs the tests that prove the change |
| docs | docs, `README`, `CONTRIBUTING.md`, `AGENTS.md`, `CLAUDE.md`, the agent files in `.claude/` | keeps the pages and the agent wiring in step with the change |
| devops | CI workflows in `.github/workflows/`, the repository checks in `tools/checks/`, the `Justfile`, `devbox.json`, release configuration | keeps the checks and the release path working |

The review agent of [GOVERNANCE.md](https://github.com/truvity/sluis/blob/main/GOVERNANCE.md) is a different agent from the one that wrote the change. For Claude Code the roles are defined in `.claude/agents/`, and the common tasks have skills in `.claude/skills/` that point back to these pages.

## Skills

Claude Code skills in `.claude/skills/` are checklists that point back to these pages and hold no rules of their own, except the script contract in `maintainer-script`:

| Skill | Use it to |
|---|---|
| `open-pr` | branch, commit, push, open, review and merge a pull request |
| `new-decision` | write, rewrite or renumber a decision record |
| `new-requirement` | add or change a requirement |
| `spike-report` | run a spike and write up its result |
| `docs-page` | create or edit a page of the site |
| `site-change` | change the site's layout, home page, Worker, headers or redirects |
| `design-review` | analyse a milestone or a large topic the principles-first way ([How we design](/contributing/design/)) |
| `maintainer-script` | write the script that the maintainer runs to create, edit or close issues (`.claude/skills/maintainer-script/SKILL.md`) |

An agent writes at most a couple of issues itself. Everything else goes through a `maintainer-script`, which is a dry run until the maintainer passes `--apply` ([Writing to issues and the board](/contributing/workflow/#writing-to-issues-and-the-board)).

## What an agent reports

An agent ends its work with a report:

1. **Verdict.** What was done or found, first.
2. **Numbers.** Measurements, counts, check results, with the commands that produced them.
3. **Changes.** Every change it made to any machine, account, branch or device, and whether it was undone.
4. **Open questions.** Each as options with pros and cons, and a recommendation.

A reviewer, such as the security role, reports each finding with the file and line, what could go wrong, how likely it is, and a test that would show it.
