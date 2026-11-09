---
name: open-pr
description: Use when starting a change on a new branch or worktree, committing, pushing, opening a pull request against main, answering review feedback on one, or merging one.
---

Read `docs/contributing/workflow.md` and follow it, with `docs/contributing/tools.md` for the checks and `docs/contributing/agents.md` for attribution.

Checklist:

- [ ] `git remote -v` checked. A fresh clone is on `master` (v1): branch from `origin/main`, with `--no-track`, on a `type/short-name` branch, in your own scratch area.
- [ ] One topic in the pull request, with its tests and docs. No stacked pull requests: dependent work is one linear pull request, one commit per part.
- [ ] `devbox run -- just check` passes locally (or the narrow recipes in "Local work" of `docs/contributing/tools.md`, with CI for the rest); say what you ran.
- [ ] Commits are conventional and keep the tool's attribution lines.
- [ ] Rebased on the current `main`; pushed with an explicit refspec, never to `main` or `master`, and never forced.
- [ ] When `main` moved under the branch, never use `gh pr update-branch`, in rebase or merge mode. Rebase the branch locally onto `origin/main`, push it under a new branch name, open a new pull request and close the old one as replaced, or land it in a merge train. Wait for green checks on the new head. Never merge `main` into the branch. When that rebase conflicts, or the branch holds a merge commit ("This branch can't be rebased"), rebuild: a new branch from `origin/main`, `git cherry-pick` or `git diff <base> <head> | git apply -3`, a new pull request, and the old one closed with a pointer.
- [ ] If another open pull request changes the same generated file, re-run the generator on the second branch after the first lands.
- [ ] The pull request follows `.github/pull_request_template.md`.
- [ ] Before each further push, and before the merge, every reviewer and review-bot thread (cubic, code scanning) is read, fixed or answered.
- [ ] CI is green. Merge only as the "Merging" section of `docs/contributing/workflow.md` allows: `gh pr merge <n> -R truvity/sluis --rebase --match-head-commit <head>`, and never `--admin`.
- [ ] After the merge, check the runs on `main`. For a site change, confirm the `Site` workflow's deploy and run the curl checks ("After every deploy" in `docs/contributing/tools.md`). Report the result: "merged" is not "done".
