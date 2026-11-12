#!/usr/bin/env bash
# The run of the release candidate that the tag run promotes (REQ-SUPPLY-048). A release is published from the bytes of a candidate:
# the run of candidate.yaml, from a push to main, for the tagged commit, that built them once and installed them on every system and
# both architectures. This finds that run and prints its id, and refuses unless it is the newest candidate run for the commit, it
# concluded successfully, and it still holds the three artifacts the release needs, not expired.
#
#   tools/release/candidate-run.sh <commit>
#
# Run it with `gh` authenticated for the repository named by GITHUB_REPOSITORY. SLUIS_CANDIDATE_WORKFLOW and SLUIS_GATE_BRANCH name
# the workflow file and the branch (candidate.yaml and main). What the artifacts hold is checked by tools/release check-candidate in
# the job that publishes; this only finds them.
#
# To build a candidate again (the run failed, was cancelled, or its artifacts have expired) a NEW commit is needed whose push changes
# the first `## ` heading line of CHANGELOG.md, because that is all tools/release/candidate-scope.sh looks at: a commit that edits the
# notes below the heading starts nothing. Append a date to the heading (`## 2.0.0-alpha.2 - 2026-11-12`; the notes still belong to the
# release), and tag THAT commit. A failed install job of a candidate is also recovered by `gh run rerun --failed` on the run of
# candidate.yaml (its evidence is uploaded under the name of the attempt), and then the tag is that run's commit.
set -euo pipefail
sha=${1:-}
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "candidate: refused: '$sha' is not a full commit id" >&2; exit 2; }
repo=${GITHUB_REPOSITORY:?candidate: GITHUB_REPOSITORY is not set}
workflow=${SLUIS_CANDIDATE_WORKFLOW:-candidate.yaml}
branch=${SLUIS_GATE_BRANCH:-main}
rebuild="build it again with a new commit that changes the first '## ' heading line of CHANGELOG.md (for example append a date: '## <version> - <date>'; editing the notes below it starts nothing) and tag that commit"
refuse() { echo "candidate: refused: $*" >&2; exit 1; }

runs=$(gh api "repos/$repo/actions/workflows/$workflow/runs?head_sha=$sha&branch=$branch&event=push&per_page=50") ||
    refuse "the runs of $workflow for $sha could not be read"
newest=$(jq -c --arg sha "$sha" --arg branch "$branch" --arg path ".github/workflows/$workflow" '
    [.workflow_runs[]? | select(.head_sha == $sha and .head_branch == $branch and .event == "push" and .path == $path)]
    | sort_by(.created_at) | last // empty' <<<"$runs") || refuse "the runs of $workflow for $sha could not be parsed"
[ -n "$newest" ] || refuse "no run of $workflow on $branch covers $sha: the release candidate is built when the first '## ' heading of CHANGELOG.md becomes the version; push that commit first, or ${rebuild}"
id=$(jq -r '.id // ""' <<<"$newest")
status=$(jq -r '.status // ""' <<<"$newest")
conclusion=$(jq -r '.conclusion // ""' <<<"$newest")
[[ "$id" =~ ^[0-9]+$ ]] || refuse "the run of $workflow for $sha has no id"
[ "$status" = completed ] || refuse "the run $id of $workflow for $sha is $status, not completed"
[ "$conclusion" = success ] || refuse "the run $id of $workflow for $sha concluded $conclusion, not success: re-run its failed jobs ('gh run rerun $id --failed'), or fix the cause and ${rebuild}"

arts=$(gh api --paginate "repos/$repo/actions/runs/$id/artifacts?per_page=100" --jq '.artifacts[] | [.name, .expired] | @tsv') ||
    refuse "the artifacts of the run $id could not be read"
for name in release-dist release-packages evidence; do
    n=$(awk -F '\t' -v n="$name" '$1 == n' <<<"$arts" | grep -c . || true)
    [ "$n" -eq 1 ] || refuse "the run $id holds $n artifacts named $name, want one"
    expired=$(awk -F '\t' -v n="$name" '$1 == n { print $2 }' <<<"$arts")
    [ "$expired" = false ] || refuse "the artifact $name of the run $id has expired (the candidate is kept for 30 days): ${rebuild}"
done
echo "candidate: the run $id of $workflow built and installed $sha, and holds release-dist, release-packages and evidence" >&2
echo "$id"
