#!/usr/bin/env bash
# The lifecycle test must bite: each case here breaks ONE .deb of the packages under test in one way a maintainer script must not,
# runs the lifecycle on Ubuntu 26.04 against the broken packages, and demands that exactly the step that watches for it fails (and
# the steps before it pass). A case the lifecycle lets through is a hole in the test, and the script fails. The broken packages are
# made by unpacking the .deb, appending to a maintainer script and packing it again; the scripts of the package tool never produce
# them, and its lint would refuse them (that is a second guard; this is the one that does not read text).
#
#   deploy/verify/mutants.sh        needs the packages in dist/packages and dist/previous, like run.sh; GitHub CI only (run.sh says why)
#
# shellcheck disable=SC2016 # the lines appended to the scripts are for the container's shell
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
[ "${GITHUB_ACTIONS:-}" = true ] || [ "${SLUIS_VERIFY_EPHEMERAL_VM:-}" = 1 ] || { echo "mutants: runs in GitHub CI only (see run.sh)" >&2; exit 2; }
arch=$(case "$(uname -m)" in x86_64) echo amd64 ;; *) echo arm64 ;; esac)
out=${1:-$root/dist/verify-mutants}
mkdir -p "$out"
out=$(cd "$out" && pwd)
version=$(jq -r .version "$root/dist/release/metadata.json")

# mutant NAME PACKAGE SCRIPT STEP LINE-or-@strip: the broken packages, the step that must fail.
fail=0
mutant() {
    local name=$1 pkg=$2 script=$3 step=$4 line=$5
    local dir=$out/$name/packages
    rm -rf "${out:?}/$name"
    mkdir -p "$dir" "$out/$name/work"
    cp "$root"/dist/packages/* "$dir/"
    local deb="$dir/${pkg}_${version}_${arch}.deb"
    dpkg-deb -R "$deb" "$out/$name/work/x"
    if [ "$line" = @strip ]; then
        grep -q 'systemctl stop' "$out/$name/work/x/DEBIAN/$script"
        sed -i '/systemctl stop/d' "$out/$name/work/x/DEBIAN/$script"
    else
        # before the final `exit 0`, so that it runs
        sed -i '$d' "$out/$name/work/x/DEBIAN/$script"
        printf '%s\nexit 0\n' "$line" >>"$out/$name/work/x/DEBIAN/$script"
    fi
    dpkg-deb --root-owner-group -Zgzip -b "$out/$name/work/x" "$deb" >/dev/null
    # the sums of the broken packages (the repository holds a package to the sums beside it)
    (cd "$dir" && sha256sum -- *.deb *.rpm | sed 's/ \*/  /' | LC_ALL=C sort -k2 >SHA256SUMS)
    rm -rf "$out/$name/work"
    SLUIS_VERIFY_PACKAGES=$dir "$here/run.sh" --nodes ubuntu-26.04 --arch "$arch" --out "$out/$name/out" >"$out/$name/run.log" 2>&1 || true
    local ev=$out/$name/out/evidence-$arch.json
    [ -s "$ev" ] || { echo "MUTANT $name: no evidence was written"; cat "$out/$name/run.log"; fail=1; return; }
    local got steps="install serve remove reinstall" before=1 s r
    got=$(jq -r --arg s "lifecycle/$step" '.runs[0].results[] | select(.suite == $s) | .result' "$ev")
    for s in $steps; do
        [ "$s" = "$step" ] && break
        r=$(jq -r --arg s "lifecycle/$s" '.runs[0].results[] | select(.suite == $s) | .result' "$ev")
        [ "$r" = pass ] || before=0
    done
    if [ "$got" = fail ] && [ "$before" = 1 ]; then
        echo "KILLED   $name: $step failed ($(jq -r --arg s "lifecycle/$step" '.runs[0].results[] | select(.suite == $s) | .reason' "$ev" | cut -c1-160))"
    else
        echo "SURVIVED $name: $step is '$got' (the steps before it passed: $before)"
        fail=1
    fi
}

mutant state-deleted-on-remove sluis-driver-writer-spool postrm remove \
    'if [ "$1" = remove ]; then rm -f /var/lib/sluis-state/dev/keepme; fi'
mutant user-deleted-on-remove sluis-driver-writer-spool postrm remove \
    'if [ "$1" = remove ]; then userdel sluis-drv-writer-spool-dev; fi'
mutant unit-started-by-the-install sluis-driver-writer-spool postinst install \
    'systemctl start sluis-drv-writer-spool@dev.service || true'
mutant unit-enabled-by-the-install sluis postinst install \
    'systemctl enable sluis-policy@dev.service'
mutant instance-left-running-by-the-removal sluis-driver-writer-spool prerm remove @strip
mutant postinst-fails sluis-key postinst install \
    'exit 1'
exit "$fail"
