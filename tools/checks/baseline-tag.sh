#!/usr/bin/env bash
# The release a compatibility check compares with: it prints the tag, or nothing when there is no release yet.
#
#   - the newest stable tag v2.N.N when there is one; the pre-releases (v2.0.0-alpha.N) promise nothing between them
#     (ADR 0013), so a final release is always the baseline once it exists. Before the first one, the newest alpha is.
#   - a checkout that has no tag while the remote has some is an error, not a repository without releases: the checkout
#     did not fetch them (fetch-tags: true), and the check would say "not run" and pass for ever. Exit status 3.
#
# Used by `just audit-compat` and `just config-schema-compat`; tools/gen/configschema/baseline_test.go holds it to this.
set -euo pipefail
tags=$(git tag --list 'v2.*' --sort=-v:refname)
if [ -z "$tags" ]; then
    if remote=$(git ls-remote --tags --refs origin 'v2.*' 2>/dev/null) && [ -n "$remote" ]; then
        echo "::error::the remote has release tags v2.* and this checkout has none: fetch them (fetch-tags: true in actions/checkout)" >&2
        exit 3
    fi
    exit 0
fi
stable=$(grep -v -- '-' <<<"$tags" | head -n 1 || true)
if [ -n "$stable" ]; then
    echo "$stable"
else
    head -n 1 <<<"$tags"
fi
