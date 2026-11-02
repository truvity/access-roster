---
title: Contributing
description: How to take part in sluis v2, for people and AI agents alike. The working rules, one page per task, and the repository files that hold the rest.
status: page
---

People and AI agents work on sluis by the same rules. The rules are written once, on the pages below; the files in the repository point here instead of repeating them.

Who decides what is in [GOVERNANCE.md](https://github.com/truvity/sluis/blob/main/GOVERNANCE.md). How to propose a feature is in [CONTRIBUTING.md](https://github.com/truvity/sluis/blob/main/CONTRIBUTING.md). A suspected vulnerability goes through [SECURITY.md](https://github.com/truvity/sluis/blob/main/SECURITY.md), never through an issue or a pull request. Questions and ideas are welcome as [issues](https://github.com/truvity/sluis/issues).

## The pages

Read the page for what you are about to do, then do it.

| Before you | Read |
|---|---|
| create a branch, commit, push, open a pull request or answer a review | [Branches and pull requests](/contributing/workflow/) |
| run a build, a test or a check, or add a tool | [Tools, checks and verification](/contributing/tools/) |
| analyse a milestone or a large topic, or decide what to ask the maintainer | [How we design](/contributing/design/) |
| propose or write a decision record, add or change a requirement, or run a spike or write up research | [Decisions, requirements and research](/contributing/decisions/) |
| create or edit a page of this site | [Pages and writing style](/contributing/pages/) |
| write a name, an address, an id or anything secret | [Public content and secrets](/contributing/public-content/) |
| contribute with an AI agent, or run a team of agents | [AI agents](/contributing/agents/) |

## The repository files

- `CONTRIBUTING.md`: the entry for a new contributor, the two release lines, and how to propose a feature.
- `GOVERNANCE.md`: roles, how a decision is made, review rules and the release numbering.
- `SECURITY.md`: how to report a vulnerability privately.
- `AGENTS.md`: the short form of these pages for an AI agent, with the page to read before each kind of change. `CLAUDE.md` loads it for Claude Code.
- `.claude/skills/` and `.claude/agents/`: task and role wrappers for Claude Code that point back to these pages. They hold no rules of their own.
- `docs/decisions/README.md` and `docs/requirements/README.md`: the formats of the decision records and of the requirements catalogue.

When a repository file and a page disagree, the page is the rule and the file is fixed.
