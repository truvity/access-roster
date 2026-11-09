#!/usr/bin/env bash
# The lifecycle of the packages on one system (the install tier, docs/distribution/packages.md "The install tier").
#
#   deploy/verify/lifecycle.sh --node NODE --arch amd64|arm64 --repo DIR --server BIN --packages DIR --version V \
#                              --previous-packages DIR --previous-version V --out DIR
#
# NODE is a line of nodes.tsv. The image of the node is built beforehand (run.sh builds it, tag sluis-verify-NODE). DIR of --repo is
# the throwaway repository (`packages repo`) of BOTH releases; BIN is the `packages` executable, which serves it inside the container
# on that container's own loopback address (the repository is unsigned and reachable from nowhere else); --packages and
# --previous-packages hold the SHA256SUMS of each release, which say what the node must install.
#
# Two systemd containers are started from the image, each privileged as the other tests of this repository are, so that units, users,
# tmpfiles and sockets are the real ones; they mount the repository read only and nothing else. In the first (fresh) container:
#   install    every package of the release installs from the repository, at the exact version, with the distribution's own
#              repositories switched off (the dependencies must be met by the image); nothing is half-configured, started or enabled;
#              the users and directories of the packages exist; the executables run and say the version
#   serve      what an operator does after the install (here: the uid plan, the stand-in of `sluis node apply`) and the units
#              verify, start under their own users, stay up, and answer on their sockets
#   remove     the packages are removed: the instances stop, the executables go, and the state, /etc/sluis and the users stay (D7);
#              on a .deb also a purge
#   reinstall  the packages installed again serve on the state that was kept
#   downgrade  this release is replaced by the previous one: installs and serves, or is refused with a named reason (D4: between alphas
#              no compatibility is promised, so a refusal is a result; a failure blocks)
# In the second (upgrade) container:
#   upgrade    the previous release is installed and serves; this release replaces it: it installs and serves, or it is refused with a
#              named reason (D4); a failure blocks
# Leaves in --out, for evidence: NODE.steps.tsv (step, result, reason, installed), NODE.facts.tsv, NODE.server.log and NODE.log.
# Needs docker and a clone with the repository's deploy/boards/units. Leaves no container behind.
# shellcheck disable=SC2016 # the command lines run in the container
# shellcheck disable=SC2015 # `A && ok || bad` reads a check; ok never fails
set -uo pipefail
{ [ "${GITHUB_ACTIONS:-}" = true ] && [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ]; } || [ "${SLUIS_VERIFY_EPHEMERAL_VM:-}" = 1 ] || { echo "lifecycle: runs in GitHub CI only (see run.sh)" >&2; exit 2; }

node='' arch='' repo='' server='' pkgdir='' version='' prevdir='' prevversion='' out=''
while [ $# -gt 0 ]; do
    case "$1" in
    --node) node=$2 ;; --arch) arch=$2 ;; --repo) repo=$2 ;; --server) server=$2 ;; --packages) pkgdir=$2 ;;
    --version) version=$2 ;; --previous-packages) prevdir=$2 ;; --previous-version) prevversion=$2 ;; --out) out=$2 ;;
    *) echo "lifecycle: unknown argument $1" >&2; exit 2 ;;
    esac
    shift 2
done
for v in node arch repo server pkgdir version prevdir prevversion out; do
    [ -n "${!v}" ] || { echo "lifecycle: --${v//_/-} is required" >&2; exit 2; }
done
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
line=$(awk -F'\t' -v n="$node" '$1 == n { print }' "$here/nodes.tsv")
[ -n "$line" ] || { echo "lifecycle: $node is not in nodes.tsv" >&2; exit 2; }
IFS=$'\t' read -r _ fam base _ <<<"$line"
image=sluis-verify-$node
pv=${version/-/\~}          # the version the package managers write: a pre-release after a tilde
pprev=${prevversion/-/\~}
mkdir -p "$out"
out=$(cd "$out" && pwd)
: >"$out/$node.log"
: >"$out/$node.steps.tsv"
: >"$out/$node.server.log"

# ---- recording
say() { printf '%s\n' "$*" | tee -a "$out/$node.log" | sed "s/^/[$node] /" >&2; }
fails=()
notes=()
ok() { say "ok   $*"; }
bad() { say "FAIL $*"; fails+=("$*"); }
# chk WHAT CMD...: a check that is run in the container by x and that must succeed.
chk() { local what=$1; shift; if "$@" >>"$out/$node.log" 2>&1; then ok "$what"; else bad "$what"; fi; }
# finish ID INSTALLED: the result of a step from the failures since it began.
finish() {
    local id=$1 inst=${2:-} res=pass reason=
    [ ${#notes[@]} -eq 0 ] || reason=$(printf '%s; ' "${notes[@]}")
    reason=${reason%; }
    if [ ${#fails[@]} -gt 0 ]; then
        res=fail
        reason=$(printf '%s; ' "${fails[@]:0:3}")
        reason=${reason%; }
        [ ${#fails[@]} -le 3 ] || reason="$reason (and $((${#fails[@]} - 3)) more)"
    fi
    record "$id" "$res" "$reason" "$inst"
}
record() { # id result reason installed
    local reason=${3//$'\t'/ }
    reason=${reason//$'\n'/ }
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "${reason:0:600}" "$4" >>"$out/$node.steps.tsv"
    say "== $1: $2 ${reason:+($reason)}"
}

# ---- containers
ct=
cleanup() {
    local c
    for c in $(docker ps -aq --filter "label=sluis-verify=$$"); do docker rm --force "$c" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT
# x CMD: runs a command line in the current container as root.
x() { docker exec "$ct" bash -c "$*" </dev/null; }
# xo CMD: the same, but the output goes to the log and the status is the command's.
xo() { x "$@" >>"$out/$node.log" 2>&1; }

new_container() { # name
    ct=sluis-verify-$$-$node-$1
    docker run -d --name "$ct" --label "sluis-verify=$$" --privileged --cgroupns=host --network none --tmpfs /run --tmpfs /run/lock \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v "$repo:/opt/verify/repo:ro" -v "$server:/opt/verify/packages:ro" "$image" >/dev/null || return 1
    local state i
    for i in $(seq 1 60); do
        state=$(docker exec "$ct" systemctl is-system-running 2>/dev/null || true)
        case "$state" in running | degraded) break ;; esac
        sleep 1
    done
    case "$state" in running | degraded) ok "systemd is up ($state) in $ct" ;; *) bad "systemd did not come up ($state)"; docker logs "$ct" 2>&1 | tail -5 >>"$out/$node.log"; return 1 ;; esac
    # The repository is served by the container's own process on its own loopback address: nothing else can reach it.
    docker exec -d "$ct" bash -c 'exec /opt/verify/packages serve -dir /opt/verify/repo -addr 127.0.0.1:8080 >/var/log/verify-repo.log 2>&1'
    for i in $(seq 1 30); do
        x 'exec 3<>/dev/tcp/127.0.0.1/8080' 2>/dev/null && break
        sleep 0.5
    done
    x 'exec 3<>/dev/tcp/127.0.0.1/8080' 2>/dev/null || { bad "the repository server did not start"; return 1; }
    case "$fam" in
    deb)
        # The distribution's own repositories are off: the image holds the dependencies the packages declare, and no more.
        x 'rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; echo "deb [trusted=yes] http://127.0.0.1:8080/apt stable main" >/etc/apt/sources.list.d/sluis-test.list; apt-get update -qq 2>&1 | tail -3' >>"$out/$node.log" 2>&1 || { bad "apt-get update"; return 1; } ;;
    rpm)
        x 'mkdir -p /root/off; mv /etc/yum.repos.d/*.repo /root/off/ 2>/dev/null; printf "[sluis-test]\nname=sluis throwaway repository (UNSIGNED, tests only)\nbaseurl=http://127.0.0.1:8080/dnf/\$basearch\nenabled=1\ngpgcheck=0\nrepo_gpgcheck=0\n" >/etc/yum.repos.d/sluis-test.repo; dnf -y -q makecache 2>&1 | tail -3' >>"$out/$node.log" 2>&1 || { bad "dnf makecache"; return 1; } ;;
    esac
    return 0
}
drop_container() {
    [ -z "$ct" ] || {
        docker exec "$ct" cat /var/log/verify-repo.log >>"$out/$node.server.log" 2>/dev/null || true
        docker rm --force "$ct" >/dev/null 2>&1 || true
    }
    ct=
}

# ---- what the release holds, from its SHA256SUMS
names_of() { # dir: the package names of the node's format and architecture
    local ext=$fam an=$arch
    [ "$fam" = rpm ] && { [ "$arch" = amd64 ] && an=x86_64 || an=aarch64; }
    sed -n "s/^[0-9a-f]\{64\}  \(.*\)_[0-9][0-9A-Za-z.-]*_${an}\.${ext}\$/\1/p" "$1/SHA256SUMS" | LC_ALL=C sort -u
}
mapfile -t names < <(names_of "$pkgdir")
[ ${#names[@]} -ge 10 ] || { echo "lifecycle: $pkgdir/SHA256SUMS lists ${#names[@]} packages for $fam $arch" >&2; exit 2; }
# The previous release has the same packages: an upgrade replaces them one for one.
[ "$(names_of "$prevdir")" = "$(printf '%s\n' "${names[@]}")" ] || { echo "lifecycle: the previous release's packages are not the release's" >&2; exit 2; }

specs() { # version: name=version for deb, name-version for rpm, for every package
    local v=$1 n sep='='
    [ "$fam" = rpm ] && sep='-'
    for n in "${names[@]}"; do printf '%s%s%s ' "$n" "$sep" "$v"; done
}

pm_install() { # version: install (or upgrade) every package to the version; the output is in /tmp/pm.out of the container
    case "$fam" in
    deb) x "export DEBIAN_FRONTEND=noninteractive; apt-get install -y -o Dpkg::Options::=--force-confold --allow-downgrades $(specs "$1") >/tmp/pm.out 2>&1" ;;
    rpm) x "dnf -y install $(specs "$1") >/tmp/pm.out 2>&1" ;;
    esac
}
pm_downgrade() { # version
    case "$fam" in
    deb) pm_install "$1" ;;
    rpm) x "dnf -y downgrade $(specs "$1") >/tmp/pm.out 2>&1" ;;
    esac
}
pm_remove() {
    case "$fam" in
    deb) x "export DEBIAN_FRONTEND=noninteractive; apt-get remove -y ${names[*]} >/tmp/pm.out 2>&1" ;;
    # A removal that also removes what was installed only as a dependency would take systemd with it in the middle of the run.
    rpm) x "dnf -y remove --setopt=clean_requirements_on_remove=0 ${names[*]} >/tmp/pm.out 2>&1" ;;
    esac
}
pm_purge() { x "export DEBIAN_FRONTEND=noninteractive; apt-get purge -y ${names[*]} >/tmp/pm.out 2>&1"; }
# The package manager's own statement of what is installed: "name=version" lines.
installed() {
    case "$fam" in
    deb) x "dpkg-query -W -f='\${db:Status-Abbrev}|\${Package}=\${Version}\n' 'sluis*' 2>/dev/null | sed -n 's/^ii *|//p' | LC_ALL=C sort" ;;
    rpm) x "rpm -qa --qf '%{NAME}=%{VERSION}\n' 'sluis*' 2>/dev/null | LC_ALL=C sort" ;;
    esac
}
installed_line() { installed | tr '\n' ' ' | sed 's/ $//'; }
# What dnf prints when a scriptlet fails (it exits 0 all the same); "Running scriptlet:" is the normal line and is not it.
scriptlet_re='scriptlet (failed|failure)|non-fatal|error in (PREIN|POSTIN|PREUN|POSTUN)|%(pre|post|preun|postun)\(.*(failed|error)'
scriptlet_problem() { docker exec "$ct" grep -Ei -e "$scriptlet_re" /tmp/pm.out </dev/null | head -2 | tr '\n' ' '; }
# pm_problem: the first line the package manager gave for a refusal or an error.
pm_problem() {
    x "grep -E '^(E:|Error|error:|  - |Problem|Failed|Transaction failed|Warning: .* scriptlet|.*scriptlet.*(failed|error))' /tmp/pm.out | head -4 | tr '\n' ' '" 2>/dev/null
}
pm_log() { x "cat /tmp/pm.out" >>"$out/$node.log" 2>&1 || true; }
# consistent: the package database holds no package that is half installed or half configured, and the files are the package's.
consistent() {
    case "$fam" in
    deb) x 'test -z "$(dpkg --audit)" && ! dpkg -l "sluis*" | awk "/^[a-z][a-z]/ { print \$1 }" | grep -qv "^ii$"' ;;
    rpm) x 'rpm -V $(rpm -qa "sluis*") 2>&1 | grep -v "^$" | { ! grep -E "^(missing|.{9}  )"; }' ;;
    esac
}
# files_verify: dpkg -V / rpm -V say nothing: every file of every sluis package is as the package made it.
files_verify() {
    case "$fam" in
    deb) x 'out=$(dpkg -V $(dpkg-query -W -f="\${Package} " "sluis*") 2>&1); [ -z "$out" ] || { echo "$out"; false; }' ;;
    rpm) x 'out=$(rpm -V $(rpm -qa "sluis*") 2>&1); [ -z "$out" ] || { echo "$out"; false; }' ;;
    esac
}

# ---- what the packages say about the system
# The users, groups and directories the sysusers.d and tmpfiles.d files of the packages describe, as lines "kind name id" and
# "path mode owner group", read in the container from the files of the packages.
sysusers_lines() { x 'cat /usr/lib/sysusers.d/sluis*.conf 2>/dev/null | awk "/^u /{print \"u\",\$2,\$3} /^g /{print \"g\",\$2,\$3}" | sort -u'; }
tmpfiles_lines() { x 'cat /usr/lib/tmpfiles.d/sluis*.conf 2>/dev/null | awk "/^d /{print \$2,\$3,\$4,\$5}" | sort -u'; }

check_users() {
    local kind name id n=0 miss=0 got
    while read -r kind name id; do
        [ -n "$kind" ] || continue
        n=$((n + 1))
        if [ "$kind" = u ]; then got=$(x "id -u $name 2>/dev/null"); else got=$(x "getent group $name | cut -d: -f3"); fi
        # A group the file gives no number gets one from the system: it only has to exist.
        if [ "$id" = - ]; then [ -n "$got" ] || { miss=$((miss + 1)); say "     $kind $name does not exist"; }
        elif [ "$got" != "$id" ]; then miss=$((miss + 1)); say "     $kind $name is $got, the package says $id"; fi
    done < <(sysusers_lines)
    [ "$n" -ge 30 ] || { say "     only $n users and groups in the sysusers files of the packages"; return 1; }
    [ "$miss" -eq 0 ]
}
check_dirs() {
    local path mode owner group n=0 miss=0 st
    while read -r path mode owner group; do
        [ -n "$path" ] || continue
        n=$((n + 1))
        st=$(x "stat -c '%a %U %G' $path 2>/dev/null")
        [ "$group" = - ] && group=$owner
        mode=${mode#0}
        [ "$mode" = - ] && continue
        if [ "$st" != "$mode $owner $group" ]; then miss=$((miss + 1)); say "     $path is '$st', the package says '$mode $owner $group'"; fi
    done < <(tmpfiles_lines)
    [ "$n" -ge 10 ] || { say "     only $n directories in the tmpfiles files of the packages"; return 1; }
    [ "$miss" -eq 0 ]
}
units_installed() { x 'ls /usr/lib/systemd/system/ | grep "^sluis-.*@\.service$"'; }
# xs: runs the script on the standard input in the current container, as root.
xs() { docker exec -i "$ct" bash -s; }
# Two strict readings of what systemd says about the sluis units. A reading that cannot be made is a failure, never a pass: the list
# of units must come from a systemd that answers, every line must be in the shape of its output, and a state the reader does not know is
# a fault. (An empty answer about started units is a good answer only when systemd has answered about its other units.)
# nothing_running: no sluis unit is active, activating, deactivating, reloading, failed or in maintenance.
nothing_running() {
    xs <<'SCRIPT'
set -u
all=$(systemctl list-units --all --plain --no-legend) || { echo "systemctl list-units failed"; exit 1; }
n=$(printf '%s\n' "$all" | grep -c .)
[ "$n" -ge 5 ] || { echo "systemctl list-units listed $n units: systemd is not answering"; exit 1; }
mine=$(systemctl list-units --all --plain --no-legend 'sluis-*') || { echo "systemctl list-units 'sluis-*' failed"; exit 1; }
bad=0
while IFS= read -r l; do
    [ -n "$l" ] || continue
    set -- $l
    case "${3:-}" in
    inactive) ;;
    active | activating | deactivating | reloading | failed | maintenance) echo "started or failed: $l"; bad=1 ;;
    *) echo "cannot read this line of systemctl: $l"; bad=1 ;;
    esac
done <<<"$mine"
exit $bad
SCRIPT
}
# nothing_enabled: no sluis unit file is enabled or linked, and no .wants link of ours exists. The units must be listed (the packages
# installed them), each line must be a unit and a state.
nothing_enabled() {
    xs <<'SCRIPT'
set -u
files=$(systemctl list-unit-files --plain --no-legend 'sluis-*') || { echo "systemctl list-unit-files failed"; exit 1; }
[ -n "$files" ] || { echo "systemctl lists no sluis unit file: the units of the packages are not there to ask about"; exit 1; }
bad=0
while IFS= read -r l; do
    [ -n "$l" ] || continue
    set -- $l
    case "${2:-}" in
    static | disabled | indirect | generated | transient | alias) ;;
    enabled | enabled-runtime | linked | linked-runtime | masked | masked-runtime) echo "enabled, linked or masked: $l"; bad=1 ;;
    *) echo "cannot read this line of systemctl: $l"; bad=1 ;;
    esac
done <<<"$files"
if ls /etc/systemd/system/*.wants/sluis-* >/dev/null 2>&1; then echo "a .wants link of sluis exists"; bad=1; fi
exit $bad
SCRIPT
}

# ---- the stand-in for what `sluis node apply` will do (later work): the uid plan of the boundary, which the units read
operator_config() {
    x 'mkdir -p /etc/sluis/bootstrap.d' || return 1
    docker cp "$root/deploy/boards/units/uids.env" "$ct:/etc/sluis/uids-dev.env" || return 1
    x 'chown root:root /etc/sluis/uids-dev.env; chmod 0644 /etc/sluis/uids-dev.env; printf "boundary: dev\n" >/etc/sluis/bootstrap.d/dev.yaml'
}

# The units this tier starts: the drivers that need nothing from another process, which answer on their own sockets. The actors
# (store, key, policy and the others) need a signed configuration and a store, which is the full tier's work.
serve_units=(sluis-drv-writer-spool@dev.service sluis-drv-key-software@dev.service)
serve_sockets=(/run/sluis/audit/dev/emit.sock /run/sluis/audit/dev/receive.sock)

# uid_of_unit UNIT: the uid of the unit's main process.
uid_of_unit() { x "pid=\$(systemctl show -p MainPID --value $1); [ \"\$pid\" != 0 ] && stat -c %u /proc/\$pid"; }

health() {
    local u i
    for u in "${serve_units[@]}"; do
        if x "systemctl start $u" >>"$out/$node.log" 2>&1; then ok "started $u"; else bad "systemctl start $u failed: $(x "journalctl -u $u -n 3 --no-pager -o cat 2>/dev/null | tr '\n' ' '")"; fi
    done
    sleep 4
    for u in "${serve_units[@]}"; do
        [ "$(x "systemctl is-active $u")" = active ] && ok "$u is active" || { bad "$u is $(x "systemctl is-active $u"): $(x "journalctl -u $u -n 3 --no-pager -o cat 2>/dev/null | tr '\n' ' '")"; continue; }
        [ "$(x "systemctl show -p NRestarts --value $u")" = 0 ] && ok "$u has not restarted" || bad "$u restarted"
        local want got
        want=$(x "systemctl show -p User --value $u")
        got=$(uid_of_unit "$u")
        [ -n "$got" ] && [ "$got" = "$(x "id -u $want")" ] && [ "$got" != 0 ] && ok "$u runs as $want ($got), not root" || bad "$u runs as uid '$got', not as $want"
        # The unit's sandbox is on the process: no capabilities, no new privileges.
        x "pid=\$(systemctl show -p MainPID --value $u); grep -q '^CapEff:\s*0000000000000000' /proc/\$pid/status && grep -q '^NoNewPrivs:\s*1' /proc/\$pid/status" >>"$out/$node.log" 2>&1 && ok "$u has no capability and no new privileges" || bad "$u has capabilities or may gain privileges"
    done
    # The spool driver answers on its two sockets: a client that connects is accepted.
    for i in "${serve_sockets[@]}"; do
        chk "$i accepts a connection" x "python3 -I -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(\"$i\"); s.close()'"
    done
    chk "the socket of the key driver is made" x 'test -S /run/sluis/key/dev/driver/key-store.sock'
}

# ---- facts
record_facts() {
    {
        printf 'format\t%s\n' "$fam"
        printf 'image\t%s\n' "$base"
        printf 'kernel\t%s\n' "$(uname -r)"
        printf 'systemd\t%s\n' "$(x 'systemctl --version | head -1 | cut -d" " -f2')"
        printf 'os\t%s\n' "$(x '. /etc/os-release; echo "$PRETTY_NAME"')"
        printf 'package_manager\t%s\n' "$(case "$fam" in deb) x 'dpkg --version | head -1' | cut -d' ' -f1-7 ;; rpm) x 'rpm --version' ;; esac)"
        printf 'glibc\t%s\n' "$(x 'ldd --version | head -1 | grep -o "[0-9.]*$"')"
        printf 'docker_image_id\t%s\n' "$(docker image inspect --format '{{.Id}}' "$image")"
    } >"$out/$node.facts.tsv"
}

# ============================================================== the fresh container
step_install() {
    fails=()
    notes=()
    local before
    before=$(x 'ls /usr/libexec/sluis /etc/sluis /var/lib/sluis-state 2>&1 | head -2' || true)
    say "before: $before"
    chk "no sluis outside the packages: /usr/bin/sluis, /usr/local/bin/sluis and /opt/sluis are not there" x 'test ! -e /usr/bin/sluis -a ! -e /usr/local/bin/sluis -a ! -e /opt/sluis'
    pm_install "$pv"
    local rc=$?
    pm_log
    [ "$rc" -eq 0 ] && ok "the package manager exited 0" || bad "the package manager exited $rc: $(pm_problem)"
    # dnf exits 0 when a scriptlet fails (MEASURED 2026-11-07, Rocky 10 and Amazon Linux 2023), so its output is read for it.
    if [ "$fam" = rpm ]; then [ -z "$(scriptlet_problem)" ] && ok "no scriptlet problem in the output of dnf" || bad "dnf reported a scriptlet problem: $(scriptlet_problem)"; fi
    chk "no package is half installed or half configured" consistent
    local got want
    got=$(installed_line)
    want=$(for n in "${names[@]}"; do printf '%s=%s ' "$n" "$pv"; done | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')
    [ "$got" = "$want" ] && ok "all ${#names[@]} packages are installed at $pv" || { bad "the installed packages are not the release's: got '$got'"; }
    chk "every file is as its package made it ($([ "$fam" = deb ] && echo dpkg -V || echo rpm -V))" files_verify
    chk "the users and groups of the packages exist, with the numbers the files give" check_users
    chk "the directories of the packages exist, with the modes and owners the files give" check_dirs
    chk "nothing was started by the install" nothing_running
    chk "nothing was enabled by the install" nothing_enabled
    chk "/usr/bin/sluis is the command-line tool and the only one" x '[ "$(command -v sluis)" = /usr/bin/sluis ] && [ "$(readlink -f /usr/bin/sluis)" = /usr/bin/sluis ]'
    chk "sluis version says $version" x "sluis version | head -1 | grep -q '^sluis $version '"
    local e bad_exe=0 execs want_execs
    execs=$(x 'find /usr/libexec/sluis -type f')
    want_execs=$(grep -c '^    source: archive' "$root/deploy/release/images.yaml")
    # The count is the number of executables the release builds from archives (images.yaml): a find that listed nothing, or fewer, is
    # not a pass of "every executable runs".
    if [ "$(grep -c . <<<"$execs")" -lt "$want_execs" ] || [ "$want_execs" -lt 15 ]; then bad "the packages hold $(grep -c . <<<"$execs") executables below /usr/libexec/sluis, the release builds $want_execs"; fi
    for e in $execs; do
        x "$e version 2>&1 | grep -q '$version'" >>"$out/$node.log" 2>&1 || { say "     $e does not say $version"; bad_exe=$((bad_exe + 1)); }
    done
    [ "$bad_exe" -eq 0 ] && ok "every executable runs and says $version" || bad "$bad_exe executables do not say $version"
    chk "the units are template units, 0644 root:root, and the owner of an executable holds its unit" x \
        'n=0; for f in /usr/lib/systemd/system/sluis-*@.service; do [ "$(stat -c "%a %U:%G" $f)" = "644 root:root" ] || exit 1; n=$((n+1)); done; [ $n -ge 15 ]'
    chk "sluis doctor passes" x 'sluis doctor'
    finish install "$(installed_line)"
}

step_serve() {
    fails=()
    notes=()
    chk "the uid plan and the bootstrap file are placed (what sluis node apply will do)" operator_config
    # systemd-analyze verify of every unit of the packages, as an instance of the boundary dev. The one thing it may say and be
    # forgiven is that a systemd before 254 does not know RestartSteps= and RestartMaxDelaySec= (the floor is 252, ADR 0013; Amazon
    # Linux 2023 has 252): it ignores them, and a restarting unit then restarts every RestartSec= with no back-off. That is recorded
    # as a note of the result, with the number of units, and not hidden.
    local u v bad_units=0 ignored=0 sv
    sv=$(x 'systemctl --version | head -1 | cut -d" " -f2')
    for u in $(units_installed); do
        v=${u/@/@dev}
        x "systemd-analyze verify $v" >"$out/verify.$$" 2>&1 || true
        if [ "$sv" -lt 254 ] 2>/dev/null; then
            if grep -Eq "Unknown key name '(RestartSteps|RestartMaxDelaySec)' in section 'Service', ignoring" "$out/verify.$$"; then ignored=$((ignored + 1)); fi
            grep -Ev "Unknown key name '(RestartSteps|RestartMaxDelaySec)' in section 'Service', ignoring" "$out/verify.$$" >"$out/verify2.$$" || true
            mv "$out/verify2.$$" "$out/verify.$$"
        fi
        if grep -Eqi 'error|failed|not found|invalid|ignoring|unknown' "$out/verify.$$"; then
            bad_units=$((bad_units + 1)); say "     verify $v: $(tr '\n' ' ' <"$out/verify.$$" | cut -c1-300)"
        fi
    done
    rm -f "$out/verify.$$"
    [ "$bad_units" -eq 0 ] && ok "systemd-analyze verify passes for $(units_installed | wc -l) units" || bad "systemd-analyze verify finds a fault in $bad_units units"
    if [ "$ignored" -gt 0 ]; then
        say "NOTE systemd $sv ignores RestartSteps= and RestartMaxDelaySec= in $ignored units"
        notes+=("systemd $sv ignores RestartSteps= and RestartMaxDelaySec= (added in 254) in $ignored of the units: a unit that fails restarts every 2 s with no back-off and, with no start limit, without end")
    fi
    health
    finish serve "$(installed_line)"
}

step_remove() {
    fails=()
    notes=()
    # State the removal must leave: a file in each place, what the units made, and who owns the uids.
    x 'echo kept >/var/lib/sluis-state/dev/keepme; echo kept >/etc/sluis/keepme' >>"$out/$node.log" 2>&1
    local before_state before_users
    before_state=$(x 'find /var/lib/sluis-state /etc/sluis -printf "%p %u %g %m %s\n" | sort | sha256sum')
    before_users=$(x 'getent passwd | grep "^sluis-" | sort; getent group | grep "^sluis-" | sort' | sha256sum)
    local pid
    pid=$(x 'systemctl show -p MainPID --value sluis-drv-writer-spool@dev.service')
    pm_remove
    local rc=$?
    pm_log
    [ "$rc" -eq 0 ] && ok "the removal exited 0" || bad "the removal exited $rc: $(pm_problem)"
    [ "$(installed_line)" = "" ] && ok "no sluis package is left installed" || bad "left installed: $(installed_line)"
    chk "the instances were stopped" nothing_running
    chk "the process of the spool driver is gone" x "[ -z '$pid' ] || [ '$pid' = 0 ] || ! test -d /proc/$pid"
    chk "the executables, the CLI and the units are gone" x 'test ! -e /usr/libexec/sluis -a ! -e /usr/bin/sluis -a -z "$(ls /usr/lib/systemd/system/sluis-* 2>/dev/null)"'
    chk "the state and the configuration were not touched (/var/lib/sluis-state, /etc/sluis)" x "[ \"\$(find /var/lib/sluis-state /etc/sluis -printf '%p %u %g %m %s\n' | sort | sha256sum)\" = '$before_state' ] && [ -f /var/lib/sluis-state/dev/keepme ] && [ -f /etc/sluis/keepme ]"
    chk "the users and groups are all still there, with the same numbers" x "[ \"\$( { getent passwd | grep '^sluis-' | sort; getent group | grep '^sluis-' | sort; } | sha256sum)\" = '$before_users' ]"
    if [ "$fam" = deb ]; then
        # A purge is the one removal a .deb has that an .rpm lacks: it must not delete state or users either (D7).
        pm_purge
        local prc=$?
        pm_log
        [ "$prc" -eq 0 ] && ok "the purge exited 0" || bad "the purge exited $prc: $(pm_problem)"
        chk "a purge keeps the state, /etc/sluis and the users too" x "[ \"\$(find /var/lib/sluis-state /etc/sluis -printf '%p %u %g %m %s\n' | sort | sha256sum)\" = '$before_state' ] && [ \"\$( { getent passwd | grep '^sluis-' | sort; getent group | grep '^sluis-' | sort; } | sha256sum)\" = '$before_users' ]"
    fi
    echo "$before_state" >"$out/.state.$node"
    finish remove ""
}

step_reinstall() {
    fails=()
    notes=()
    local before_users before_files
    before_users=$(x 'getent passwd | grep "^sluis-" | sort' | sha256sum)
    before_files=$(x 'find /var/lib/sluis-state /etc/sluis -type f | LC_ALL=C sort')
    local recovered
    recovered=$(x 'journalctl -u sluis-drv-writer-spool@dev.service -o cat --no-pager | grep -c "spool recovered"')
    pm_install "$pv"
    local rc=$?
    pm_log
    [ "$rc" -eq 0 ] && ok "the package manager exited 0" || bad "the package manager exited $rc: $(pm_problem)"
    [ "$fam" = rpm ] && [ -n "$(scriptlet_problem)" ] && bad "dnf reported a scriptlet problem: $(scriptlet_problem)"
    chk "no package is half installed or half configured" consistent
    local got want
    got=$(installed_line)
    want=$(for n in "${names[@]}"; do printf '%s=%s ' "$n" "$pv"; done | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')
    [ "$got" = "$want" ] && ok "all ${#names[@]} packages are installed again at $pv" || bad "the installed packages are not the release's: got '$got'"
    chk "the users are the same as before the removal" x "[ \"\$(getent passwd | grep '^sluis-' | sort | sha256sum)\" = '$before_users' ]"
    chk "the users and directories are as the packages say" check_users
    chk "the marker files of the kept state are there" x 'grep -qx kept /var/lib/sluis-state/dev/keepme && grep -qx kept /etc/sluis/keepme'
    chk "the uid plan and the bootstrap file, kept by the removal, are still there" x 'test -f /etc/sluis/uids-dev.env -a -f /etc/sluis/bootstrap.d/dev.yaml'
    chk "nothing was started by the reinstall" nothing_running
    health
    chk "every file of the kept state is still there" x "[ -z \"\$(comm -23 <(printf '%s\n' '$before_files') <(find /var/lib/sluis-state /etc/sluis -type f | LC_ALL=C sort))\" ]"
    chk "the state directory is still the driver's (the same uid as before the removal)" x 'test "$(stat -c %U /var/lib/sluis-state/dev/drv-writer-spool)" = sluis-drv-writer-spool-dev'
    chk "the spool driver started again on the spool the first run made, and recovered it" x "[ \$(journalctl -u sluis-drv-writer-spool@dev.service -o cat --no-pager | grep -c 'spool recovered') -gt $recovered ]"
    finish reinstall "$(installed_line)"
}

# The upgrade and the downgrade (D4, "installs and serves, or refuses with a named reason"): the result is pass if it installs and serves, refused with the reason the package manager
# or the service named, and fail if it is neither (a half-configured package, or no word about why).
step_replace() { # id action semver packageversion [old-pids]: the packages are replaced by the target version
    local id=$1 action=$2 tpv=$4 oldpids=${5:-} rc reason
    fails=()
    notes=()
    local nf=0
    if [ "$action" = downgrade ]; then pm_downgrade "$tpv"; else pm_install "$tpv"; fi
    rc=$?
    pm_log
    if [ "$rc" -ne 0 ]; then
        reason=$(pm_problem)
        if consistent >>"$out/$node.log" 2>&1 && [ -n "$reason" ]; then
            record "$id" refused "the package manager refused: $reason" ""
        else
            record "$id" fail "the package manager failed ($reason) and left the packages inconsistent or said nothing" ""
        fi
        return 0
    fi
    [ "$fam" = rpm ] && [ -n "$(scriptlet_problem)" ] && { record "$id" fail "dnf reported a scriptlet problem: $(scriptlet_problem)" ""; return 0; }
    consistent >>"$out/$node.log" 2>&1 || { record "$id" fail "the packages are inconsistent after the $id" ""; return 0; }
    local want got
    want=$(for n in "${names[@]}"; do printf '%s=%s ' "$n" "$tpv"; done | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')
    got=$(installed_line)
    [ "$got" = "$want" ] || { record "$id" fail "after the $id the installed packages are '$got'" ""; return 0; }
    # Serves: the units that ran are running (a new package restarted them), the others start, and they stay up.
    local u
    for u in "${serve_units[@]}"; do x "systemctl start $u" >>"$out/$node.log" 2>&1 || nf=$((nf + 1)); done
    sleep 4
    local why=
    for u in "${serve_units[@]}"; do
        if [ "$(x "systemctl is-active $u")" != active ]; then
            nf=$((nf + 1)); why="$why$u is $(x "systemctl is-active $u"): $(x "journalctl -u $u -n 2 --no-pager -o cat 2>/dev/null | tr '\n' ' '")"
        fi
    done
    for i in "${serve_sockets[@]}"; do x "python3 -I -c 'import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(\"$i\")'" >>"$out/$node.log" 2>&1 || { nf=$((nf + 1)); why="$why $i does not accept a connection;"; }; done
    # An instance that ran before the upgrade has a new process: the maintainer script restarted it. An old one still running is the
    # previous release's code answering under the new release's name.
    local now p
    now=$(for u in "${serve_units[@]}"; do x "systemctl show -p MainPID --value $u"; done | tr '\n' ' ')
    for p in $now; do
        [ "$p" -gt 0 ] 2>/dev/null || { nf=$((nf + 1)); why="$why an instance has no main process after the $id;"; }
    done
    for p in $oldpids; do
        [ "$p" -gt 0 ] 2>/dev/null || { nf=$((nf + 1)); why="$why the previous release's instance had no main process, so what the $id does to a running instance was not tested;"; continue; }
        case " $now" in *" $p "*) nf=$((nf + 1)); why="$why the process $p of the previous release is still running after the $id;" ;; esac
    done
    if [ "$nf" -eq 0 ]; then
        record "$id" pass "" "$got"
    elif [ -n "$why" ] && echo "$why" | grep -Eqi 'refus|incompatib|unsupported'; then
        record "$id" refused "the installed packages do not serve, and say why: $why" ""
    else
        record "$id" fail "the packages installed and do not serve: $why" ""
    fi
}

# ============================================================== the run
facts_done=0
fresh() {
    new_container fresh || { finish install ""; return; }
    [ "$facts_done" -eq 1 ] || { record_facts; facts_done=1; }
    step_install
    # Without the install nothing else is worth running; the steps not reached are recorded as such by the report.
    [ "$(awk -F'\t' '$1 == "install" { print $2 }' "$out/$node.steps.tsv")" = pass ] || return 0
    step_serve
    [ "$(awk -F'\t' '$1 == "serve" { print $2 }' "$out/$node.steps.tsv")" = pass ] || return 0
    step_remove
    [ "$(awk -F'\t' '$1 == "remove" { print $2 }' "$out/$node.steps.tsv")" = pass ] || return 0
    step_reinstall
    [ "$(awk -F'\t' '$1 == "reinstall" { print $2 }' "$out/$node.steps.tsv")" = pass ] || return 0
    # The instances that run now (the reinstall started them) are replaced by new processes when the packages go back.
    local u pids=""
    for u in "${serve_units[@]}"; do pids="$pids $(x "systemctl show -p MainPID --value $u")"; done
    step_replace downgrade downgrade "$prevversion" "$pprev" "$pids"
}
upgrade() {
    local rc
    fails=()
    notes=()
    new_container upgrade || { record upgrade fail "the container for the upgrade did not start" ""; return; }
    # The previous release: installed and serving, with data of its own.
    pm_install "$pprev"
    rc=$?
    pm_log
    if [ "$rc" -ne 0 ]; then record upgrade fail "the previous release $prevversion did not install: $(pm_problem)" ""; return; fi
    operator_config >>"$out/$node.log" 2>&1
    local u pids=""
    for u in "${serve_units[@]}"; do x "systemctl start $u" >>"$out/$node.log" 2>&1 || true; done
    sleep 3
    for u in "${serve_units[@]}"; do pids="$pids $(x "systemctl show -p MainPID --value $u")"; done
    say "the previous release's instances run as$pids"
    step_replace upgrade upgrade "$version" "$pv" "$pids"
}

say "node $node ($base), arch $arch, release $version, previous $prevversion"
fresh
drop_container
upgrade
drop_container
say "done"
