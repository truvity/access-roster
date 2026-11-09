#!/usr/bin/env bash
# The two versions of the install tier (deploy/verify): the previous release, which the upgrade goes from and the downgrade to, and the
# release under test, which is the next pre-release after it. The previous release is the highest `v2.*` tag (a pre-release sorts
# before its release); the release under test is that tag with its pre-release counter raised by one, whatever the CHANGELOG says
# about the real next tag, because the packages are built here for the test and published by no one.
#
#   versions.sh previous   2.0.0-alpha.1
#   versions.sh current    2.0.0-alpha.2
set -euo pipefail
what=${1:?usage: versions.sh previous|current}
tag=$(git tag -l 'v2.*' | sed 's/-/~/' | LC_ALL=C sort -V | tail -1 | sed 's/~/-/')
[ -n "$tag" ] || { echo "versions: no v2.* tag in this clone: fetch the tags" >&2; exit 1; }
prev=${tag#v}
case "$what" in
previous) echo "$prev" ;;
current)
    if [[ "$prev" =~ ^(.+)-alpha\.([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}-alpha.$((BASH_REMATCH[2] + 1))"
    else
        echo "versions: the previous release $prev is not an alpha, and the next version of the install tier is not defined for it: say how in deploy/verify/versions.sh" >&2
        exit 1
    fi ;;
*) echo "usage: versions.sh previous|current" >&2; exit 2 ;;
esac
