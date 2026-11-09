#!/usr/bin/env bash
# The two versions of the install tier (deploy/verify): the previous release, which the upgrade goes from and the downgrade to, and the
# release under test, which is a pre-release above it. The previous release is the highest `v2.*` tag by version order (a pre-release
# sorts before its release); the release under test is made from it, whatever the CHANGELOG says about the real next tag, because the
# packages are built here for the test and published by no one:
#   v2.0.0-alpha.1  ->  2.0.0-alpha.2   a pre-release `-<word>.<n>` has its counter raised by one
#   v2.0.0          ->  2.0.1-alpha.1   a stable release gets the first alpha of its next patch
#
#   versions.sh previous   2.0.0-alpha.1
#   versions.sh current    2.0.0-alpha.2
# A tag that is not `v2.<n>.<n>` with an optional `-<word>.<n>` (a build metadata, a second hyphen) is left out of the choice.
set -euo pipefail
what=${1:?usage: versions.sh previous|current}
tag=$(git tag -l 'v2.*' | grep -E '^v2\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[A-Za-z]+\.[0-9]+)?$' | sed 's/-/~/' | LC_ALL=C sort -V | tail -1 | sed 's/~/-/' || true)
[ -n "$tag" ] || { echo "versions: no v2.* release tag in this clone: fetch the tags" >&2; exit 1; }
prev=${tag#v}
case "$what" in
previous) echo "$prev" ;;
current)
    if [[ "$prev" =~ ^(.+)-([A-Za-z]+)\.([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}-${BASH_REMATCH[2]}.$((BASH_REMATCH[3] + 1))"
    elif [[ "$prev" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$((BASH_REMATCH[3] + 1))-alpha.1"
    else
        echo "versions: cannot make the next version of $prev" >&2
        exit 1
    fi ;;
*) echo "usage: versions.sh previous|current" >&2; exit 2 ;;
esac
