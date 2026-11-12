#!/usr/bin/env bash
# The evidence file of one architecture, from the artifacts of the install jobs of a candidate run.
#
#   tools/release/candidate-evidence.sh <dir> <arch> <attempt>
#
# Each install job uploads its artifact as install-evidence-<arch>-<run attempt>, so that `gh run rerun --failed` of a candidate (which
# runs only the install job that failed, in a new attempt) uploads under a new name and does not collide with the artifact of the
# attempt before. <dir> holds the downloaded artifacts, one directory for each. The newest attempt for the architecture that is not
# newer than the running attempt is taken (a name for a later attempt is another job's: no job of this run has made it), and it
# must hold exactly one evidence-<arch>.json. The result is held to completeness and to a pass by `verify evidence-merge`, so an
# older attempt's failed report is never what is published: it is only never chosen over a newer one.
set -euo pipefail
dir=${1:?usage: candidate-evidence.sh <dir> <arch> <attempt>}
arch=${2:?usage: candidate-evidence.sh <dir> <arch> <attempt>}
attempt=${3:?usage: candidate-evidence.sh <dir> <arch> <attempt>}
[[ "$arch" =~ ^(amd64|arm64)$ ]] || { echo "candidate-evidence: the architecture is '$arch'" >&2; exit 2; }
[[ "$attempt" =~ ^[1-9][0-9]*$ ]] || { echo "candidate-evidence: the attempt is '$attempt'" >&2; exit 2; }
best=0
shopt -s nullglob
for d in "$dir/install-evidence-$arch"-*; do
    n=${d##*-}
    [[ "$n" =~ ^[1-9][0-9]*$ ]] || { echo "candidate-evidence: $d does not end in an attempt number" >&2; exit 1; }
    if [ "$n" -gt "$attempt" ]; then
        echo "candidate-evidence: $d is of the attempt $n, which this run (attempt $attempt) has not reached: it is not taken" >&2
        continue
    fi
    [ "$n" -le "$best" ] || best=$n
done
[ "$best" -gt 0 ] || { echo "candidate-evidence: no evidence for $arch up to the attempt $attempt in $dir" >&2; exit 1; }
mapfile -t found < <(find "$dir/install-evidence-$arch-$best" -type f -name "evidence-$arch.json")
[ "${#found[@]}" -eq 1 ] || { echo "candidate-evidence: ${#found[@]} files named evidence-$arch.json in the evidence of $arch, attempt $best, want one" >&2; exit 1; }
echo "candidate-evidence: $arch: ${found[0]} (attempt $best of $attempt)" >&2
echo "${found[0]}"
