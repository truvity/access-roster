#!/usr/bin/env bash
# Is a push to main a release candidate (docs/distribution/packages.md, "The release candidate")? It is when the push changed the top
# section of CHANGELOG.md from `## Unreleased` (or from the section of an earlier release) to a section named for a release version
# that has no tag yet: that is this repository's own procedure for a release, the pull request that renames the heading.
#
#   tools/release/candidate-scope.sh <commit before the push> <commit after the push>
#
# Prints, for the workflow to add to $GITHUB_OUTPUT, `run=true` and `version=<version>` for a candidate and `run=false` and a
# `reason=` otherwise. Run it in a clone with the history and the tags. A push of several commits (a train) is compared as a whole:
# the head before it against the head after it. It never fails for a push that is not a candidate; it fails when it cannot read.
set -euo pipefail
before=${1:?usage: candidate-scope.sh <before> <after>}
after=${2:?usage: candidate-scope.sh <before> <after>}
tagre='^2\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-alpha\.(0|[1-9][0-9]*))?$'

no() { echo "run=false"; echo "reason=$*"; exit 0; }

# The first section heading of CHANGELOG.md at a commit.
head_of() { git show "$1:CHANGELOG.md" 2>/dev/null | awk '/^## / { print; exit }'; }

git cat-file -e "$after^{commit}" 2>/dev/null || { echo "candidate-scope: $after is not a commit of this clone" >&2; exit 1; }
[[ "$before" =~ ^0+$ ]] && no "the push has no commit before it to compare with"
git cat-file -e "$before^{commit}" 2>/dev/null || no "the commit before the push, $before, is not in this clone"
new=$(head_of "$after")
old=$(head_of "$before")
[ -n "$new" ] || no "CHANGELOG.md has no section"
[ "$new" != "$old" ] || no "the head of CHANGELOG.md did not change ($new)"
# `## 2.0.0-alpha.2`, or `## [2.0.0-alpha.2]`, with nothing but a date after it.
if [[ "$new" =~ ^##\ \[?([^] ]+)\]?(\ .*)?$ ]]; then
    version=${BASH_REMATCH[1]}
else
    no "the head of CHANGELOG.md is '$new', not a release version"
fi
[[ "$version" =~ $tagre ]] || no "the head of CHANGELOG.md is '$new': '$version' is not a release version (2.<minor>.<patch>, or 2.0.0-alpha.<n>)"
if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
    no "v$version is already tagged"
fi
echo "run=true"
echo "version=$version"
