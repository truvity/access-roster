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
{ [ "${GITHUB_ACTIONS:-}" = true ] && [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ]; } || [ "${SLUIS_VERIFY_EPHEMERAL_VM:-}" = 1 ] || { echo "mutants: runs in GitHub CI only (see run.sh)" >&2; exit 2; }
arch=$(case "$(uname -m)" in x86_64) echo amd64 ;; *) echo arm64 ;; esac)
out=${1:-$root/dist/verify-mutants}
mkdir -p "$out"
out=$(cd "$out" && pwd)
version=$(jq -r .version "$root/dist/release/metadata.json")

# mutant NAME PACKAGE SCRIPT STEP LINE-or-@del:WORD-or-@data:PATH:WORD: the broken packages, the step that must fail. @data deletes
# the line that holds WORD from the file PATH of the package (SCRIPT is ignored), and writes the package's md5sums again, so that
# dpkg -V stays silent: the one thing that is broken is the content.
fail=0
mutant() {
    local name=$1 pkg=$2 script=$3 step=$4 line=$5
    local dir=$out/$name/packages
    rm -rf "${out:?}/$name"
    mkdir -p "$dir" "$out/$name/work"
    cp "$root"/dist/packages/* "$dir/"
    local deb="$dir/${pkg}_${version}_${arch}.deb"
    dpkg-deb -R "$deb" "$out/$name/work/x"
    if [[ "$line" == @data:* ]]; then
        local rest=${line#@data:} dpath dword
        dpath=${rest%%:*} dword=${rest#*:}
        grep -q -- "$dword" "$out/$name/work/x$dpath"
        sed -i "/$dword/d" "$out/$name/work/x$dpath"
        ! grep -q -- "$dword" "$out/$name/work/x$dpath"
        (cd "$out/$name/work/x" && find . -path ./DEBIAN -prune -o -type f -print | sed 's|^\./||' | LC_ALL=C sort | xargs md5sum >DEBIAN/md5sums)
    elif [[ "$line" == @del:* ]]; then
        # delete the line that holds a word: the script must have it, or the case does not break what it says
        grep -q -- "${line#@del:}" "$out/$name/work/x/DEBIAN/$script"
        sed -i "/${line#@del:}/d" "$out/$name/work/x/DEBIAN/$script"
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
    local got steps="install serve remove reinstall minimal" before=1 s r
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
mutant instance-left-running-by-the-removal sluis-driver-writer-spool prerm remove '@del:systemctl stop'
mutant instance-not-restarted-by-the-upgrade sluis-driver-writer-spool postinst upgrade '@del:try-restart'
mutant postinst-fails sluis-key postinst install \
    'exit 1'
# Decision 25-D: the store package declares the groups of the store drivers, which only store@ joins, and no package of the smallest
# install (the base package and the store package) owns them. Without the declaration the group does not exist there, and
# systemd would refuse the unit with 216/GROUP. The full install still passes (the driver package declares the group), so only
# the step of the smallest install fails.
mutant group-undeclared-by-the-package-that-joins-it sluis-store x minimal \
    '@data:/usr/lib/sysusers.d/sluis-store.conf:g sluis-drv-store-file-dev'
exit "$fail"
