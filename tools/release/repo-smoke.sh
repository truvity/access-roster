#!/usr/bin/env bash
# Install the release from a THROWAWAY apt and dnf repository, in containers (`just release-repo-smoke`).
#
#   tools/release/repo-smoke.sh <repo-dir> [<platform>...]
#
# <repo-dir> is the output of `packages repo` (apt/ and dnf/ trees, UNSIGNED, for tests only: not the publication site). The script
# serves it with `packages serve` on 127.0.0.1, and for each distribution starts two containers on the host network with NOTHING
# mounted from the host, so the only way a package gets in is an HTTP request to the repository (the server's log is the record):
#   cli:  `sluis-cli` alone. It installs the command-line tool and no systemd (a workstation with none installs it).
#   base: `sluis` alone. apt or dnf resolve its dependencies: `sluis-cli` at the exact version from the repository and `systemd`
#         from the distribution's own.
# The distributions are Ubuntu 26.04 (apt), Rocky Linux 10 and Amazon Linux 2023 (dnf); the images are pinned by digest (the first two
# are those of .github/workflows/checks.yaml). With names after the directory only those run: ubuntu, rocky, al2023.
#
# SLUIS_SMOKE_EXPECT_VERSION=<release version> also runs `sluis version` in the container and expects that version. The recipe sets it
# for a real build; the stand-in executables of the tests of the tool are not programs.
# It needs docker, curl and go. It leaves no container and no process behind.
# shellcheck disable=SC2016 # the scripts that run in the containers are single-quoted on purpose
set -euo pipefail

repo=${1:?usage: repo-smoke.sh <repo-dir> [ubuntu|rocky|al2023]...}
shift
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
[ -d "$repo/apt/dists/stable" ] && [ -d "$repo/dnf/x86_64/repodata" ] || { echo "repo-smoke: $repo is not the output of 'packages repo'" >&2; exit 2; }
repo=$(cd "$repo" && pwd)

declare -A image=(
    [ubuntu]='ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c'
    [rocky]='rockylinux/rockylinux:10@sha256:827d37bc128288ccf160ee318bb3cb92d591164cb217e92f8bc61e3982ae1834'
    [al2023]='amazonlinux:2023@sha256:3ccfbe800f864982b0a4e124a614b2382518cbd04b3c1cd35202bd46f392675b'
)
declare -A family=([ubuntu]=deb [rocky]=rpm [al2023]=rpm)
platforms=("$@")
[ ${#platforms[@]} -gt 0 ] || platforms=(ubuntu rocky al2023)
for p in "${platforms[@]}"; do [ -n "${image[$p]:-}" ] || { echo "repo-smoke: unknown platform '$p'" >&2; exit 2; }; done

work=$(mktemp -d)
server_pid=
names=()
cleanup() {
    local rc=$?
    for n in "${names[@]}"; do docker rm --force "$n" >/dev/null 2>&1 || true; done
    if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
    rm -rf "${work:?}"
    exit "$rc"
}
trap cleanup EXIT

# The server: built once, started on a free loopback port, killed by its pid at the end.
go -C "$root/tools/release/packages" build -o "$work/packages" .
"$work/packages" serve -dir "$repo" -addr 127.0.0.1:0 >"$work/server.log" 2>&1 &
server_pid=$!
url=
for _ in $(seq 1 50); do
    url=$(sed -n 's|^serving .* on \(http://127\.0\.0\.1:[0-9]*\)$|\1|p' "$work/server.log" | head -1)
    [ -z "$url" ] || break
    sleep 0.2
done
[ -n "$url" ] || { echo "repo-smoke: the server did not start:" >&2; cat "$work/server.log" >&2; exit 1; }
curl --fail --silent --show-error "$url/UNSIGNED-TEST-REPOSITORY.txt" >/dev/null
echo "repo-smoke: serving $repo at $url (unsigned, loopback)"

# The version the repository holds: the Version of sluis-cli in the Packages file, which is what apt shows and what dnf compares.
pv=$(awk '/^Package: sluis-cli$/ { f = 1 } f && /^Version: / { print $2; exit }' "$repo/apt/dists/stable/main/binary-amd64/Packages")
[ -n "$pv" ] || { echo "repo-smoke: no sluis-cli in the Packages file" >&2; exit 1; }
echo "repo-smoke: package version $pv"

# What runs inside a container. Both scripts read SMOKE_URL, SMOKE_PV, SMOKE_SCENARIO (cli or base) and SMOKE_EXPECT_VERSION.
common='
set -euo pipefail
ok() { echo "ok   $*"; }
die() { echo "FAIL $*" >&2; exit 1; }
need() { local what=$1; shift; "$@" >/dev/null 2>&1 && ok "$what" || die "$what"; }
sysver_ge() { [ "$(printf "%s\n%s\n" "$2" "$1" | sort -V | head -1)" = "$2" ]; } # sysver_ge VERSION FLOOR
'
deb_script="$common"'
export DEBIAN_FRONTEND=noninteractive
echo "deb [trusted=yes] $SMOKE_URL/apt stable main" >/etc/apt/sources.list.d/sluis-test.list
apt-get update -qq >/dev/null
systemd_before=no; dpkg -s systemd >/dev/null 2>&1 && systemd_before=yes
if [ "$SMOKE_SCENARIO" = cli ]; then target=sluis-cli; else target=sluis; fi
# The repository is the only source of the package: it is what apt policy says about the candidate.
apt-cache policy "$target" | grep -F "$SMOKE_URL/apt" >/dev/null || die "apt does not offer $target from the repository"
apt-get install -y -qq "$target" >/dev/null
ver() { dpkg-query -W -f="\${Version}" "$1"; }
[ "$(ver sluis-cli)" = "$SMOKE_PV" ] || die "sluis-cli is $(ver sluis-cli), want $SMOKE_PV"
ok "sluis-cli $SMOKE_PV installed"
need "/usr/bin/sluis is an executable" test -x /usr/bin/sluis
need "no half-configured package" test -z "$(dpkg --audit)"
if [ "$SMOKE_SCENARIO" = cli ]; then
    [ "$(dpkg -s systemd >/dev/null 2>&1 && echo yes || echo no)" = "$systemd_before" ] || die "installing sluis-cli changed whether systemd is installed"
    ok "sluis-cli alone added no systemd (systemd installed before: $systemd_before)"
else
    [ "$(ver sluis)" = "$SMOKE_PV" ] || die "sluis is $(ver sluis), want $SMOKE_PV"
    sysver_ge "$(ver systemd)" 252 || die "systemd $(ver systemd) is below the floor 252"
    ok "sluis $SMOKE_PV installed; systemd $(ver systemd) came with it (floor 252)"
    need "the foundation executables are in place" test -x /usr/libexec/sluis/actors/policy -a -x /usr/libexec/sluis/actors/entry
    need "sluis-cli was not asked for and is installed (a dependency)" dpkg -s sluis-cli
    need "no sluis unit was enabled by the install" bash -c "! ls /etc/systemd/system/*.wants/sluis* >/dev/null 2>&1"
fi
if [ -n "$SMOKE_EXPECT_VERSION" ]; then
    says=$(sluis version | sed -n 1p)
    [[ "$says" == "sluis $SMOKE_EXPECT_VERSION "* ]] || die "sluis version says: $says"
    ok "sluis version says $SMOKE_EXPECT_VERSION"
fi
'
rpm_script="$common"'
cat >/etc/yum.repos.d/sluis-test.repo <<REPO
[sluis-test]
name=sluis throwaway repository (UNSIGNED, tests only)
baseurl=$SMOKE_URL/dnf/\$basearch
enabled=1
gpgcheck=0
repo_gpgcheck=0
REPO
dnf -y -q makecache --refresh --disablerepo="*" --enablerepo=sluis-test >/dev/null
systemd_before=no; rpm -q systemd >/dev/null 2>&1 && systemd_before=yes
if [ "$SMOKE_SCENARIO" = cli ]; then target=sluis-cli; else target=sluis; fi
dnf -q repoquery --repo=sluis-test --qf "%{name}" "$target" | grep -Fx "$target" >/dev/null || die "dnf does not offer $target from the repository"
dnf -y -q install "$target" >/dev/null
ver() { rpm -q --qf "%{version}" "$1"; }
pvr="$SMOKE_PV"
[ "$(ver sluis-cli)" = "$pvr" ] || die "sluis-cli is $(ver sluis-cli), want $pvr"
ok "sluis-cli $pvr installed"
dnf -q info installed sluis-cli | grep -E "^From repo +: +sluis-test" >/dev/null || die "dnf does not record sluis-test as the repository of sluis-cli"
ok "dnf records sluis-test as the repository of sluis-cli"
need "/usr/bin/sluis is an executable" test -x /usr/bin/sluis
need "the rpm database is consistent" rpm -Va --nofiles --nodigest sluis-cli
if [ "$SMOKE_SCENARIO" = cli ]; then
    [ "$(rpm -q systemd >/dev/null 2>&1 && echo yes || echo no)" = "$systemd_before" ] || die "installing sluis-cli changed whether systemd is installed"
    ok "sluis-cli alone added no systemd (systemd installed before: $systemd_before)"
else
    [ "$(ver sluis)" = "$pvr" ] || die "sluis is $(ver sluis), want $pvr"
    sysver_ge "$(ver systemd)" 252 || die "systemd $(ver systemd) is below the floor 252"
    ok "sluis $pvr installed; systemd $(ver systemd) came with it (floor 252)"
    need "the foundation executables are in place" test -x /usr/libexec/sluis/actors/policy -a -x /usr/libexec/sluis/actors/entry
    need "no sluis unit was enabled by the install" bash -c "! ls /etc/systemd/system/*.wants/sluis* >/dev/null 2>&1"
    dnf -q info installed sluis | grep -E "^From repo +: +sluis-test" >/dev/null || die "dnf does not record sluis-test as the repository of sluis"
    ok "sluis came from sluis-test, and sluis-cli with it as a dependency"
fi
if [ -n "$SMOKE_EXPECT_VERSION" ]; then
    says=$(sluis version | sed -n 1p)
    [[ "$says" == "sluis $SMOKE_EXPECT_VERSION "* ]] || die "sluis version says: $says"
    ok "sluis version says $SMOKE_EXPECT_VERSION"
fi
'

# run <platform> <scenario>: one fresh container, nothing mounted, the script on its standard input. The log of the server is
# read afterwards: the packages must have been fetched over HTTP.
run() {
    local plat=$1 scen=$2 name="sluis-repo-smoke-$$-$1-$2" script
    names+=("$name")
    [ "${family[$plat]}" = deb ] && script=$deb_script || script=$rpm_script
    local -a envs=(-e "SMOKE_URL=$url" -e "SMOKE_PV=$pv" -e "SMOKE_SCENARIO=$scen" -e "SMOKE_EXPECT_VERSION=${SLUIS_SMOKE_EXPECT_VERSION:-}")
    # The host network, so that 127.0.0.1 in the container is the server on this host: the server only listens on loopback.
    docker run --rm --interactive --name "$name" --network host "${envs[@]}" "${image[$plat]}" bash -s <<<"$script"
}

fail=0
pids=()
labels=()
for p in "${platforms[@]}"; do
    (
        run "$p" cli && run "$p" base
    ) >"$work/$p.log" 2>&1 &
    pids+=($!)
    labels+=("$p")
done
for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then
        echo "repo-smoke: ${labels[$i]}: passed"
    else
        echo "repo-smoke: ${labels[$i]}: FAILED" >&2
        fail=1
    fi
    sed "s/^/  ${labels[$i]}: /" "$work/${labels[$i]}.log"
done

# The record that the bytes came over HTTP: each package a scenario names was requested from the server, and sluis-cli was requested
# by the scenario that never named it, as a dependency of sluis. (The server's log is the only place a client's request is seen
# from outside the container.)
for p in "${platforms[@]}"; do
    if [ "${family[$p]}" = deb ]; then
        pat='^GET /apt/pool/main/s/%s/%s_.*\.deb 200$'
    else
        pat='^GET /dnf/(x86_64|aarch64)/Packages/%s_.*\.rpm 200$'
    fi
    for n in sluis-cli sluis; do
        # shellcheck disable=SC2059 # the pattern is the format
        if [ "${family[$p]}" = deb ]; then re=$(printf "$pat" "$n" "$n"); else re=$(printf "$pat" "$n"); fi
        got=$(grep -Ec "$re" "$work/server.log" || true)
        # sluis-cli is fetched by two scenarios on a distribution, sluis by one; the two rpm distributions share paths, so they
        # add up in the log (more than that only if a client retries).
        peers=0
        for q in "${platforms[@]}"; do [ "${family[$q]}" = "${family[$p]}" ] && peers=$((peers + 1)); done
        want=$peers; [ "$n" = sluis-cli ] && want=$((2 * peers))
        if [ "$got" -lt "$want" ]; then
            echo "repo-smoke: FAILED: the server saw $got download(s) of $n (want at least $want); the log of the server:" >&2
            fail=1
        fi
    done
done
echo "repo-smoke: requests the server saw:"
grep -E '\.(deb|rpm) 200$' "$work/server.log" | sed 's/^/  /' || true
[ "$fail" -eq 0 ] || { echo "--- server log" >&2; cat "$work/server.log" >&2; echo "repo-smoke: FAILED" >&2; exit 1; }
echo "repo-smoke: passed on: ${platforms[*]}"
