#!/usr/bin/env bash
# The install tier: the lifecycle of the packages on each system (lifecycle.sh), and the evidence of it. `just install-verify`.
#
#   deploy/verify/run.sh [--arch amd64|arm64] [--nodes ubuntu-26.04,rocky-10,al2023] [--out dist/verify] [--gate]
#
# Needs the packages of the release under test in dist/packages (`just release-build release-packages`; built with
# GORELEASER_CURRENT_TAG=v$(deploy/verify/versions.sh current), because the upgrade must go to a higher version than the previous
# release's) and those of the previous release in dist/previous/packages (deploy/verify/previous.sh). It makes the throwaway
# repository of both releases, builds the test image of each system (nodes.tsv), runs the lifecycles side by side, and writes
# <out>/evidence-<arch>.json. The exit status is 1 when the evidence is not complete and, with --gate, when a blocking suite did not
# pass (the evidence is written first, so a failed run leaves it). Needs docker and go. Leaves no container and no process behind.
#
# IT RUNS IN GITHUB CI ONLY. The containers boot systemd and need what systemd needs of its cgroup (--privileged, the host cgroup
# mounted read-write: MEASURED 2026-11-09, a container with a private cgroup namespace and a read-only cgroup, with or without
# CAP_SYS_ADMIN, cannot boot systemd), and the scripts of the packages run in them. On a hosted runner, a virtual machine that is
# thrown away, that is nothing; on a workstation it is a way to reach the host's systemd. So it refuses to run anywhere else.
# SLUIS_VERIFY_BIN=<dir> names prebuilt `packages` and `verify` executables of the runner's architecture (CI builds them once, and the
# runner then needs no Go); without it they are built with go. SLUIS_VERIFY_PACKAGES=<dir> names the packages under test (default
# dist/packages), which mutants.sh uses.
set -euo pipefail
[ "${GITHUB_ACTIONS:-}" = true ] || [ "${SLUIS_VERIFY_EPHEMERAL_VM:-}" = 1 ] || {
    echo "run: the install tier boots privileged systemd containers and runs the packages' scripts in them: it runs in GitHub CI only (deploy/verify/run.sh, docs/distribution/packages.md, \"The install tier\")" >&2
    exit 2
}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
arch=$(case "$(uname -m)" in x86_64) echo amd64 ;; aarch64 | arm64) echo arm64 ;; *) echo unknown ;; esac)
nodes=
out=$root/dist/verify
gate=
while [ $# -gt 0 ]; do
    case "$1" in
    --arch) arch=$2; shift ;;
    --nodes) nodes=$2; shift ;;
    --out) out=$2; shift ;;
    --gate) gate=-gate ;;
    *) echo "run: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done
case "$arch" in amd64 | arm64) ;; *) echo "run: the architecture is '$arch'" >&2; exit 2 ;; esac
[ -n "$nodes" ] || nodes=$(awk -F'\t' '!/^#/ && NF { printf "%s%s", s, $1; s = "," }' "$here/nodes.tsv")
pk=${SLUIS_VERIFY_PACKAGES:-$root/dist/packages}
prev=$root/dist/previous
[ -f "$pk/SHA256SUMS" ] || { echo "run: $pk/SHA256SUMS is missing: run 'just release-build release-packages'" >&2; exit 1; }
[ -f "$prev/packages/SHA256SUMS" ] || { echo "run: $prev/packages/SHA256SUMS is missing: run deploy/verify/previous.sh" >&2; exit 1; }
version=$(jq -r .version "$root/dist/release/metadata.json")
commit=$(jq -r .commit "$root/dist/release/metadata.json")
pversion=$(jq -r .version "$prev/release/metadata.json")
[ "$version" != "$pversion" ] || { echo "run: the release under test and the previous release are both $version" >&2; exit 1; }
[ "$(printf '%s\n%s\n' "${pversion/-/\~}" "${version/-/\~}" | LC_ALL=C sort -V | tail -1)" = "${version/-/\~}" ] || { echo "run: $version is not above the previous release $pversion: build with GORELEASER_CURRENT_TAG=v$("$here/versions.sh" current)" >&2; exit 1; }

mkdir -p "$out"
out=$(cd "$out" && pwd)
rm -f "$out"/*.tsv "$out"/*.log "$out"/evidence-"$arch".json
work=$(mktemp -d)
cleanup() {
    rm -rf "${work:?}"
    for n in ${nodes//,/ }; do docker rmi --force "sluis-verify-$n" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

# The repository of both releases, as a real one holds every release: the same names at two versions.
mkdir -p "$work/both"
cp "$pk"/*.deb "$pk"/*.rpm "$prev/packages"/*.deb "$prev/packages"/*.rpm "$work/both/"
cat "$pk/SHA256SUMS" "$prev/packages/SHA256SUMS" | LC_ALL=C sort -k2 >"$work/both/SHA256SUMS"
if [ -n "${SLUIS_VERIFY_BIN:-}" ]; then
    cp "$SLUIS_VERIFY_BIN/packages" "$SLUIS_VERIFY_BIN/verify" "$work/"
else
    CGO_ENABLED=0 go -C "$root/tools/release/packages" build -o "$work/packages" .
    CGO_ENABLED=0 go -C "$root" build -o "$work/verify" ./tools/verify
fi
"$work/packages" repo -packages "$work/both" -out "$work/repo"

started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
pids=()
for n in ${nodes//,/ }; do
    IFS=$'\t' read -r _ _ base dockerfile < <(awk -F'\t' -v n="$n" '$1 == n' "$here/nodes.tsv")
    [ -n "$base" ] || { echo "run: $n is not in nodes.tsv" >&2; exit 2; }
    docker build --quiet --build-arg "BASE=$base" --tag "sluis-verify-$n" --file "$here/$dockerfile" "$here/images" >/dev/null
    "$here/lifecycle.sh" --node "$n" --arch "$arch" --repo "$work/repo" --server "$work/packages" --packages "$pk" --version "$version" \
        --previous-packages "$prev/packages" --previous-version "$pversion" --out "$out" >"$out/$n.stdout" 2>&1 &
    pids+=($!)
done
status=0
for p in "${pids[@]}"; do wait "$p" || status=1; done
finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
for n in ${nodes//,/ }; do sed "s/^/  /" "$out/$n.stdout" | grep -E '^  \[[^]]*\] (ok|FAIL|==|NOTE|node|done)' || true; done
[ "$status" -eq 0 ] || echo "run: a lifecycle script itself failed (not a failed check): its output is in $out/*.stdout" >&2

"$work/verify" evidence-write -out "$out/evidence-$arch.json" -version "$version" -commit "$commit" -packages "$pk" \
    -previous-version "$pversion" -previous-source "the archives of the GitHub release v$pversion, packaged by this tree" \
    -previous-packages "$prev/packages" -arch "$arch" -nodes "$nodes" -dir "$out" -started "$started" -finished "$finished" $gate
