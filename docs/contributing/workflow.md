---
title: Branches and pull requests
description: How a change reaches main in sluis v2, from the worktree and branch name to commits, the CHANGELOG, review and the merge gate.
status: page
sidebar:
  order: 1
---

## Two lines, two branches

v2 lives on `main`, an orphan branch that shares no history with v1. v1 lives on `master`. A v2 change never targets `master`, and nothing from v2 is pushed to it. The two lines are in [ADR 0001](/decisions/0001-v1-and-v2-lines/). A fresh clone checks out `master`, which is v1: switch to `origin/main` before you start, and treat v1 only as the yardstick for parity. A v1 change branches from `master` and opens its pull request against `master`; [CONTRIBUTING.md](https://github.com/truvity/sluis/blob/main/CONTRIBUTING.md) says which v1 changes are taken.

## One change, one worktree, one branch

1. Check where you are: `git remote -v` must show the sluis repository you mean to change.
2. Fetch, then make a worktree for the change off `origin/main`, on a new topic branch that does not track `main`:

   ```sh
   git fetch origin
   git worktree add --no-track -b docs/adr-readme ../sluis-adr-readme origin/main
   ```

3. Name the branch `type/short-name`, with a conventional-commit type: `feat/token-exchange`, `docs/adr-readme`.
4. Push with an explicit refspec, so the branch can only land where you name it: `git push origin docs/adr-readme:docs/adr-readme`. Never push to `main`.

## One topic per pull request

- Keep a pull request to one change.
- Do not stack pull requests. Merging is by rebase only, so every merge changes the commits of the next pull request and forces it to be rebuilt. Put dependent work in one linear pull request, with one commit per part.
- A change comes with its tests and its documentation in the same pull request. Changes to protocols and stored formats also keep the compatibility rules in [GOVERNANCE.md](https://github.com/truvity/sluis/blob/main/GOVERNANCE.md).
- Open a draft pull request early if you want feedback. Mark it ready when the checks are green.
- Rebase onto the current `main` before you ask for the merge. A green pull request on a stale base can still break `main`.
- After someone has reviewed the branch, do not rewrite the commits they read. Add commits instead, and let the rebase merge tidy them; rebase only to catch up with `main`.
- Do not force-push. The repository allows rebase merges only, so a branch with a merge commit cannot be merged ("This branch can't be rebased"), and a branch that `main` has moved under needs a rebase you cannot push. In both cases rebuild the pull request ([below](#rebuilding-a-pull-request)).

### Rebuilding a pull request

1. Fetch, then start a new branch from the current `origin/main`.
2. Bring the change over: `git cherry-pick` its commits, or `git diff <base> <head> | git apply -3`, then commit.
3. Push the new branch with an explicit refspec and open a new pull request.
4. Close the old pull request with a comment that points to the new one.

## Merging

Merge is by rebase. The maintainer merges. An agent working for the maintainer may merge its own pull request when the checks are green and review is done; it never merges another author's pull request. The rule is in the review rules of [GOVERNANCE.md](https://github.com/truvity/sluis/blob/main/GOVERNANCE.md).

1. Read the head commit of the pull request: `gh pr view <n> -R truvity/sluis --json headRefOid,mergeStateStatus,reviewDecision`.
2. Merge that commit and no other: `gh pr merge <n> -R truvity/sluis --rebase --match-head-commit <sha>`. The flag makes the merge fail when someone pushed after you looked, so what was reviewed is what lands.
3. An agent never uses `--admin`, which skips the required checks and reviews. If the merge is refused, say what refused it and stop.
4. Check what the merge started ([After the merge](#after-the-merge)).

### After the merge

"Merged" is not "done". The merge starts the runs on `main`; find them with `gh run list -R truvity/sluis --branch main --limit 5`, wait for them, and report the result. For a change to the site, the `Site` workflow deploys on every push to `main`; check that its `deploy-workers` job passed and that the live site answers ([After every deploy](/contributing/tools/#after-every-deploy)). A failed run on `main` is yours to report, with its log, before you start anything else.

### Generated files

Some files are generated from others, for example the actor registry and its page (`just actors-write`). When two pull requests change the same generated file, the second collides after the first lands. Re-run the generator on the second branch after the first has merged, commit the result, and let `just check` confirm that nothing is stale.

## Commits

Use conventional commits: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`, `ci:`, `build:`. Add `!` after the type for a breaking change, for example `feat!:`. An optional scope names the part, for example `docs(decisions):`.

Write the subject in the imperative, in one short line. Say why in the body when it is not obvious. The history feeds the release notes.

## CHANGELOG

`CHANGELOG.md` is written by hand, for the person who uses a release. A pull request that changes what a user notices adds a bullet under `## Unreleased`. The maintainer renames that heading to the version at release time.

Start a breaking bullet with **Breaking:** and say what to do first. Pure refactors, tests and dependency bumps need no bullet.

## Checks are the gate

Green CI is the merge gate: a pull request with a red or a skipped required check is not merged. Run the same checks locally first, with `devbox run -- just check` ([Tools, checks and verification](/contributing/tools/)). CI checks the site build and its links, the requirements catalogue, the decision records, file names, the agent wiring, and content that must not be public.

## Review

- Every pull request is reviewed by the maintainer and by the review agent ([GOVERNANCE.md](https://github.com/truvity/sluis/blob/main/GOVERNANCE.md)).
- Before you push again, read every comment on the pull request, from reviewers and from review bots, and answer or fix each one in the same push.
- Expect questions about tests, edge cases and failure modes. Answer them in the pull request, or fix the code.
- Reply to every comment, even if only to say "done". Resolve a thread only when the reviewer agrees.
- Review bots (cubic, GitHub code scanning) comment in threads. Read every thread before you merge, and fix it or reply with the reason. The bot's checks can be green while an unresolved thread holds a real finding.
- Changes to keys, secrets, authorisation, PKI or audit get a security note in the pull request: what could go wrong, and which test shows it does not.
- Review comments are about the change, not the person.

## Writing to issues and the board

An agent opens at most a couple of issues itself. Every other write to issues, comments, labels, milestones, the board or the closing of an issue goes into a script that the maintainer runs. The contract of that script is in the `maintainer-script` skill (`.claude/skills/maintainer-script/SKILL.md`):

- It is a dry run until the maintainer passes `--apply`, and it is idempotent: running it twice changes nothing the second time.
- It reads over REST, because the GraphQL budget is shared by everyone, and it keeps API pages in temporary files, never in shell variables.
- It checks open and closed issues by title, in this repository and in the sibling one for a cross-repo item, before it creates anything.
- Its dry-run output is read, and scanned for private terms ([Public content and secrets](/contributing/public-content/)), before the maintainer runs it.

An issue edit that the script would make is shown to the maintainer, not applied by the agent.
