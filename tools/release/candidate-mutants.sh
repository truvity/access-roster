#!/usr/bin/env bash
# The gate of the tag run must bite on the bytes of THIS candidate: each case here changes one thing between the candidate and the tag
# run, in a copy, and demands that `release check-candidate` refuses it. A case the gate lets through is a hole in the gate, and the
# script fails. The first run, with nothing changed, must pass, so a refusal is the change's and not the copy's.
#
#   tools/release/candidate-mutants.sh <release tool> <release dir> <packages dir> <evidence.json> <version> <commit>
#
# It reads and writes files and runs the release tool on them; it runs no file of the candidate (nothing is installed or executed), so
# it is safe anywhere. Run from the root of the repository (the gate reads deploy/verify/nodes.tsv).
set -euo pipefail
tool=$(readlink -f "${1:?usage: candidate-mutants.sh <release tool> <release dir> <packages dir> <evidence.json> <version> <commit>}")
rel=$(readlink -f "${2:?}") pkg=$(readlink -f "${3:?}") ev=$(readlink -f "${4:?}") version=${5:?} commit=${6:?}
work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT

fresh() { # a copy of the candidate in $work/c
    rm -rf "${work:?}/c"
    mkdir -p "$work/c/release" "$work/c/packages" "$work/c/candidate"
    cp "$rel"/* "$work/c/release/"
    cp "$pkg"/* "$work/c/packages/"
    cp "$ev" "$work/c/candidate/evidence.json"
}
gate() { "$tool" check-candidate -dist "$work/c/release" -packages "$work/c/packages" -evidence "$work/c/candidate/evidence.json" -version "$version" -commit "$commit"; }
flip() { # change one byte in the middle of a file: its low bit
    local f=$1 off b
    off=$(($(stat -c %s "$f") / 2))
    b=$(dd if="$f" bs=1 skip="$off" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
    printf '%b' "$(printf '\\%03o' $((b ^ 1)))" | dd of="$f" bs=1 seek="$off" count=1 conv=notrunc 2>/dev/null
}

fresh
gate >/dev/null || { echo "mutants: the candidate itself is refused by the gate; no case can say anything" >&2; gate; exit 1; }
bad=0
refused() { # name: the gate must refuse the copy as changed
    local name=$1 out
    if out=$(gate 2>&1); then
        echo "mutants: FAIL: the gate let through: $name" >&2
        bad=1
    else
        echo "mutants: ok: refused: $name ($(grep -m1 -o 'release: .*' <<<"$out" | cut -c1-110))"
    fi
}

first() { find "$1" -maxdepth 1 -type f -name "$2" -printf '%f\n' | LC_ALL=C sort | head -1; }
archive=$(first "$rel" '*.tar.gz')
deb=$(first "$pkg" '*.deb')
rpm=$(first "$pkg" '*.rpm')
[ -n "$archive" ] && [ -n "$deb" ] && [ -n "$rpm" ] || { echo "mutants: the candidate has no archive, .deb or .rpm" >&2; exit 1; }

fresh; flip "$work/c/release/$archive"; refused "one byte of an archive"
fresh; flip "$work/c/release/SHA256SUMS"; refused "one byte of the release's SHA256SUMS"
fresh; flip "$work/c/packages/$deb"; refused "one byte of a .deb"
fresh; flip "$work/c/packages/$rpm"; refused "one byte of an .rpm"
fresh; flip "$work/c/packages/SHA256SUMS"; refused "one byte of the packages' SHA256SUMS"
fresh; flip "$work/c/candidate/evidence.json"; refused "one byte of the evidence"
fresh; echo x >"$work/c/release/extra.tar.gz"; refused "a file added to the release"
fresh; echo x >"$work/c/packages/sluis-extra_${version}_amd64.deb"; refused "a package added"
fresh; rm "$work/c/release/metadata.json"; refused "a file taken from the release"
fresh; rm "$work/c/packages/$deb"; refused "a package taken away"
fresh; "$tool" check-candidate -dist "$work/c/release" -packages "$work/c/packages" -evidence "$work/c/candidate/evidence.json" -version "$version" -commit "0000000000000000000000000000000000000000" >/dev/null 2>&1 \
    && { echo "mutants: FAIL: the gate let through another commit" >&2; bad=1; } || echo "mutants: ok: refused: another commit"
fresh; "$tool" check-candidate -dist "$work/c/release" -packages "$work/c/packages" -evidence "$work/c/candidate/evidence.json" -version "9.9.9" -commit "$commit" >/dev/null 2>&1 \
    && { echo "mutants: FAIL: the gate let through another version" >&2; bad=1; } || echo "mutants: ok: refused: another version"
exit "$bad"
