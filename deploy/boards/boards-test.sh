#!/usr/bin/env bash
# shellcheck disable=SC2015,SC2016 # `A && bad || ok` pairs report a check either way; single quotes hold the code of `bash -c`
# A test of the workstation side of the boards scripts (boards.sh, rqlite.sh, rqlite-lib.sh, ssh-lib.sh) against a fake ssh and a fake
# curl: no board, no network. It checks that
#   - the PIN of boards-unlock reaches the board on standard input only: it is in no argument of any ssh, and in no output;
#   - SLUIS_BOARD_SSH_OPTIONS reaches every ssh of boards.sh and rqlite.sh, after the defaults;
#   - a board without tar is refused before anything is sent, with the fix, and an unreachable board is told apart from it;
#   - the m1 profile deploys the twelve units of the spine with the key driver of the run, and cli/sluis is staged;
#   - an rqlite package whose sha256 differs from its pin is refused, in the cache and after a download, and a version without a pin;
#   - the readiness of an rqlite node is read from /status and /nodes, and one that has no leader, or two, is not ready.
# Run from anywhere: deploy/boards/boards-test.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
command -v jq >/dev/null || { echo "boards-test: jq is needed (it is in devbox)" >&2; exit 1; }

fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
check() { # description command...: the command must succeed
	local d=$1
	shift
	if "$@"; then ok "$d"; else bad "$d"; fi
}

# The fake ssh. It logs every argument, one per line between markers, and what arrived on standard input; it answers the commands
# the scripts send. FAKE_TAR_RC is the status of `command -v tar` (255 is an unreachable board), FAKE_HTTP is the body of an answer
# to the GET of rqlite_get (FAKE_HTTP_BODY_<n> by the number of the call is not needed: one body for a test is enough).
cat >"$work/bin/ssh" <<'F'
#!/bin/bash
{
	echo "=== ssh"
	for a in "$@"; do printf 'arg: %s\n' "$a"; done
} >>"$FAKE_SSH_LOG"
cmd=""
seen=0
for a in "$@"; do
	if [ "$seen" = 1 ]; then cmd="$cmd $a"; fi
	[[ "$a" == *@* ]] && seen=1
done
cmd=${cmd# }
in=$(cat)
printf 'stdin: %s\n' "$in" >>"$FAKE_SSH_LOG"
case "$cmd" in
"uname -n") echo "${FAKE_NODE:-board-b}" ;;
*"command -v tar"*) exit "${FAKE_TAR_RC:-0}" ;;
"mktemp -d") echo /tmp/fake-stage ;;
"sudo -n test -x /opt/sluis/bin/cli/sluis") exit "${FAKE_CLI_RC:-0}" ;;
"sudo -n /opt/sluis/bin/cli/sluis node unlock "*) echo "node ${FAKE_NODE:-board-b} is unlocked" ;;
"timeout 15 bash -s -- "*) printf 'HTTP/1.0 %s\r\nContent-Type: application/json\r\n\r\n%s' "${FAKE_HTTP_STATUS:-200 OK}" "${FAKE_HTTP_BODY:-}" ;;
esac
exit 0
F
chmod +x "$work/bin/ssh"
export FAKE_SSH_LOG="$work/ssh.log"
export SLUIS_BOARD_SSH_USER=operator SLUIS_BOARD_SSH_AUTH_SOCK=/nonexistent
export SLUIS_BOARD_SSH_OPTIONS="-o UserKnownHostsFile=$work/known_hosts -o StrictHostKeyChecking=yes"
export PATH="$work/bin:$PATH"

# --- boards-unlock ---------------------------------------------------------------------------------------------------------------
pin=246810
: >"$FAKE_SSH_LOG"
out=$(printf '%s\n' "$pin" | SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock 2>&1)
check "unlock: the board answers that the node is unlocked" grep -q 'node board-b is unlocked' <<<"$out"
check "unlock: the PIN is on the standard input of the command on the board" grep -qx "stdin: $pin" "$FAKE_SSH_LOG"
check "unlock: the PIN is in no argument of any ssh" bash -c '! grep -q "^arg: .*$1" "$2"' _ "$pin" "$FAKE_SSH_LOG"
check "unlock: and not in the output" bash -c '! grep -q "$1" <<<"$2"' _ "$pin" "$out"
check "unlock: the command is the CLI under sudo, with the host name and the boundary" grep -qx "arg: sudo -n /opt/sluis/bin/cli/sluis node unlock board-b --boundary dev" "$FAKE_SSH_LOG"
check "unlock: the ssh options of the run are on the command line" grep -qx "arg: UserKnownHostsFile=$work/known_hosts" "$FAKE_SSH_LOG"
check "unlock: and come after the defaults" bash -c 'awk "/^arg: BatchMode=yes/{b=NR} /^arg: UserKnownHostsFile/{u=NR} END{exit !(b && u && b<u)}" "$1"' _ "$FAKE_SSH_LOG"
if SLUIS_BOARDS="192.0.2.12 192.0.2.13" "$here/boards.sh" unlock </dev/null >/dev/null 2>"$work/err"; then bad "unlock: two boards are refused"; else check "unlock: two boards are refused" grep -q 'exactly one board' "$work/err"; fi
FAKE_CLI_RC=1 SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock </dev/null >/dev/null 2>"$work/err" && bad "unlock: a board without the CLI is refused" || check "unlock: a board without the CLI is refused, with the fix" grep -q 'just build-arm64' "$work/err"
if grep -rn -- "$pin" "$here/boards.sh" "$here/Justfile" >/dev/null 2>&1; then bad "the PIN of the test is in a script"; fi

# --- tar ---------------------------------------------------------------------------------------------------------------------------
: >"$FAKE_SSH_LOG"
FAKE_TAR_RC=1 SLUIS_BOARDS=192.0.2.11 "$here/boards.sh" status >"$work/out" 2>"$work/err" && bad "tar: a board without tar fails the run" || ok "tar: a board without tar fails the run"
check "tar: and the message names tar and the fix" grep -q "has no tar.*dnf install tar" "$work/err"
check "tar: nothing was sent to the board" bash -c '! grep -q "^arg: mktemp" "$1" && ! grep -q "remote.sh" "$1"' _ "$FAKE_SSH_LOG"
FAKE_TAR_RC=255 SLUIS_BOARDS=192.0.2.11 "$here/boards.sh" status >"$work/out" 2>"$work/err" && bad "tar: an unreachable board fails the run" || ok "tar: an unreachable board fails the run"
check "tar: and is not reported as a missing tar" bash -c 'grep -q "cannot reach" "$1" && grep -q SLUIS_BOARD_SSH_OPTIONS "$1" && ! grep -q "has no tar" "$1"' _ "$work/err"

# --- the m1 profile and cli/sluis --------------------------------------------------------------------------------------------------
dist=$work/dist
while IFS=$'\t' read -r _ _ _ binary _; do
	case "$binary" in '' | '#'*) continue ;; esac
	mkdir -p "$dist/$(dirname "$binary")"
	printf '#!/bin/sh\n' >"$dist/$binary"
	chmod +x "$dist/$binary"
done <"$here/units/index.tsv"
mkdir -p "$dist/cli"
printf '#!/bin/sh\n' >"$dist/cli/sluis"
chmod +x "$dist/cli/sluis"
export SLUIS_BOARDS_DIST=$dist SLUIS_BOARDS=192.0.2.12 SLUIS_BOARDS_DRY_RUN=1
sw=$(SLUIS_BOARDS_PROFILE=m1 "$here/boards.sh" deploy 2>/dev/null)
# Twelve executables; the rqlite driver has a unit for each of its two ports and entry has its audit instance, so fourteen units.
execs() { grep -cE '^  files/bin/(actors|drivers)/' <<<"$1" || true; }
check "profile m1: twelve executables, fourteen units" test "$(execs "$sw") $(grep -cE '^  sluis-' <<<"$(sed -n '/^plan:/,/^dry run/p' <<<"$sw")")" = "12 14"
check "profile m1: the software key driver by default" grep -q 'sluis-drv-key-software@dev.service' <<<"$sw"
check "profile m1: and not the card driver" bash -c '! grep -q yubikey-piv <<<"$1"' _ "$sw"
check "profile m1: and no console, which is not in the spine" bash -c '! grep -q "sluis-console@" <<<"$1"' _ "$sw"
check "cli/sluis is staged" grep -q 'files/bin/cli/sluis' <<<"$sw"
card=$(SLUIS_BOARDS_PROFILE=m1 SLUIS_BOARDS_KEY_DRIVER=yubikey-piv SLUIS_BOARD_CARD_SERIALS="192.0.2.12=1234567" "$here/boards.sh" deploy 2>/dev/null)
check "profile m1 with the card: twelve executables" test "$(execs "$card")" = 12
check "profile m1 with the card: the card driver replaces the software one" bash -c 'grep -q "sluis-drv-key-yubikey-piv@dev.service" <<<"$1" && ! grep -q "sluis-drv-key-software@" <<<"$1"' _ "$card"
SLUIS_BOARDS_PROFILE=m1 SLUIS_BOARDS_ONLY="actors/store" "$here/boards.sh" deploy >/dev/null 2>"$work/err" && bad "a profile and SLUIS_BOARDS_ONLY together are refused" || check "a profile and SLUIS_BOARDS_ONLY together are refused" grep -q 'name one of them' "$work/err"
SLUIS_BOARDS_PROFILE=m2 "$here/boards.sh" deploy >/dev/null 2>"$work/err" && bad "an unknown profile is refused" || check "an unknown profile is refused" grep -q 'must be m1' "$work/err"
rm "$dist/cli/sluis"
check "without cli/sluis the deploy warns and goes on" bash -c 'SLUIS_BOARDS_PROFILE=m1 "$1/boards.sh" deploy 2>&1 >/dev/null | grep -q "no .*cli/sluis"' _ "$here"
unset SLUIS_BOARDS_DIST SLUIS_BOARDS_DRY_RUN SLUIS_BOARDS

# --- rqlite.sh ---------------------------------------------------------------------------------------------------------------------
plan=$(SLUIS_BOARDS="192.0.2.11 192.0.2.12 192.0.2.13" SLUIS_RQLITE_BOOTSTRAP=192.0.2.13 SLUIS_BOARDS_DRY_RUN=1 "$here/rqlite.sh")
check "rqlite.sh: the bootstrap node comes first, with no -join" bash -c 'grep -A1 "^dry run" <<<"$1" | tail -1 | grep -q "board 192.0.2.13: .*bootstrap: no -join"' _ "$plan"
check "rqlite.sh: the others join the Raft address of the bootstrap node" grep -q 'board 192.0.2.11: -http-addr 192.0.2.11:4001 -raft-addr 192.0.2.11:4002 -join 192.0.2.13:4002' <<<"$plan"
check "rqlite.sh: all four packages have a pin" test "$(grep -cE '^    rqlite.* [0-9a-f]{64}$' <<<"$plan")" = 4
SLUIS_BOARDS="board.example.com" SLUIS_RQLITE_BOOTSTRAP=192.0.2.13 SLUIS_BOARDS_DRY_RUN=1 "$here/rqlite.sh" >/dev/null 2>"$work/err" && bad "rqlite.sh: a board name that is not an address is refused" || check "rqlite.sh: a board name that is not an address is refused" grep -q 'not an IPv4 address' "$work/err"
SLUIS_BOARDS="192.0.2.12" "$here/rqlite.sh" >/dev/null 2>"$work/err" && bad "rqlite.sh: no bootstrap node is refused" || check "rqlite.sh: no bootstrap node is refused" grep -q 'SLUIS_RQLITE_BOOTSTRAP' "$work/err"

# --- the pins ----------------------------------------------------------------------------------------------------------------------
# Library functions run in subshells with the pins file and the cache of the test.
rl() {
	(
		export here
		rqlite_pins=${PINS:-$here/rqlite.pins}
		# shellcheck source=deploy/boards/ssh-lib.sh
		. "$here/ssh-lib.sh"
		# shellcheck source=deploy/boards/rqlite-lib.sh
		. "$here/rqlite-lib.sh"
		"$@"
	)
}
for fam_arch in deb:aarch64 deb:x86_64 rpm:aarch64 rpm:x86_64; do
	name=$(rl rqlite_asset "${fam_arch%:*}" "${fam_arch#*:}")
	check "pins: $name has a sha256" bash -c '[[ "$1" =~ ^[0-9a-f]{64}$ ]]' _ "$(rl rqlite_pin "$name")"
done
rl rqlite_asset deb riscv64 2>/dev/null && bad "an unknown machine has no package" || ok "an unknown machine has no package"
rl rqlite_pin rqlite_9.9.9_arm64.deb 2>"$work/err" && bad "a name without a pin is refused" || check "a name without a pin is refused" grep -q 'pins no sha256' "$work/err"
printf 'a package\n' >"$work/pkg.deb"
good=$(sha256sum "$work/pkg.deb" | cut -d' ' -f1)
printf '# test pins\n%s  rqlite_10.6.6_arm64.deb\n' "$good" >"$work/pins"
PINS=$work/pins rl rqlite_verify "$work/pkg.deb" rqlite_10.6.6_arm64.deb && ok "verify: the pinned digest is accepted" || bad "verify: the pinned digest is accepted"
printf 'a package, changed\n' >"$work/tampered.deb"
PINS=$work/pins rl rqlite_verify "$work/tampered.deb" rqlite_10.6.6_arm64.deb 2>"$work/err" && bad "verify: another digest is refused" || check "verify: another digest is refused, with both digests" bash -c 'grep -q "not the pinned $1" "$2"' _ "$good" "$work/err"
printf '%s  rqlite_10.6.6_arm64.deb  extra\n' "$good" >"$work/pins-bad"
PINS=$work/pins-bad rl rqlite_pin rqlite_10.6.6_arm64.deb 2>/dev/null && bad "a malformed pin line is refused" || ok "a malformed pin line is refused"
# rqlite_fetch with a fake curl that copies $FAKE_CURL_FILE to --output.
cat >"$work/bin/curl" <<'F'
#!/bin/bash
out=""
while [ $# -gt 0 ]; do
	[ "$1" = --output ] && out=$2
	shift
done
[ -z "${FAKE_CURL_FAIL:-}" ] || exit 22
cp "$FAKE_CURL_FILE" "$out"
F
chmod +x "$work/bin/curl"
cache=$work/cache
got=$(FAKE_CURL_FILE=$work/pkg.deb PINS=$work/pins rl rqlite_fetch rqlite_10.6.6_arm64.deb "$cache")
check "fetch: a download that verifies is kept under its name" bash -c 'test "$1" = "$2/rqlite_10.6.6_arm64.deb" && test -f "$1"' _ "$got" "$cache"
rm -rf "$cache"
FAKE_CURL_FILE=$work/tampered.deb PINS=$work/pins rl rqlite_fetch rqlite_10.6.6_arm64.deb "$cache" >/dev/null 2>"$work/err" && bad "fetch: a download that does not verify is refused" || ok "fetch: a download that does not verify is refused"
check "fetch: and nothing is left in the cache" test -z "$(ls -A "$cache")"
mkdir -p "$cache"
cp "$work/tampered.deb" "$cache/rqlite_10.6.6_arm64.deb"
got=$(FAKE_CURL_FILE=$work/pkg.deb PINS=$work/pins rl rqlite_fetch rqlite_10.6.6_arm64.deb "$cache")
check "fetch: a cached file that does not verify is replaced by a download that does" bash -c 'cmp -s "$1" "$2"' _ "$got" "$work/pkg.deb"
FAKE_CURL_FAIL=1 FAKE_CURL_FILE=$work/pkg.deb PINS=$work/pins rl rqlite_fetch rqlite_10.6.6_x86_64.rpm "$cache" >/dev/null 2>&1 && bad "fetch: a name without a pin is refused before any download" || ok "fetch: a name without a pin is refused before any download"
rm -rf "$cache"
FAKE_CURL_FAIL=1 FAKE_CURL_FILE=$work/pkg.deb PINS=$work/pins rl rqlite_fetch rqlite_10.6.6_arm64.deb "$cache" >/dev/null 2>"$work/err" && bad "fetch: a failed download is an error" || check "fetch: a failed download is an error" grep -q 'cannot download' "$work/err"

# --- the readiness of a node -------------------------------------------------------------------------------------------------------
status_ok='{"store":{"ready":true,"node_id":"board-b","leader":{"addr":"192.0.2.13:4002","node_id":"board-a"}}}'
nodes_ok='{"board-a":{"id":"board-a","reachable":true,"leader":true,"voter":true},"board-b":{"id":"board-b","reachable":true,"leader":false,"voter":true}}'
# A fake ssh that answers /status and /nodes with the bodies of the test.
cat >"$work/bin/ssh" <<'F'
#!/bin/bash
cat >/dev/null
last=${!#}
case "$last" in
/status) body=$FAKE_STATUS ;;
/nodes) body=$FAKE_NODES ;;
*) exit 0 ;;
esac
printf 'HTTP/1.0 %s\r\nContent-Type: application/json\r\n\r\n%s' "${FAKE_HTTP_STATUS:-200 OK}" "$body"
F
ready() { ( FAKE_STATUS=$1 FAKE_NODES=$2 FAKE_HTTP_STATUS=${3:-200 OK} rl rqlite_node_ready 192.0.2.12 192.0.2.12 4001 board-b ) 2>"$work/why"; }
ready "$status_ok" "$nodes_ok" && ok "ready: a ready voter of a cluster with one leader" || { bad "ready: a ready voter"; cat "$work/why"; }
ready '{"store":{"ready":false,"node_id":"board-b","leader":{"node_id":"board-a"}}}' "$nodes_ok" && bad "ready: a store that is not ready" || check "ready: a store that is not ready is not ready" grep -q 'not ready' "$work/why"
ready '{"store":{"ready":true,"node_id":"board-b","leader":{"node_id":""}}}' "$nodes_ok" && bad "ready: no leader" || ok "ready: a node that knows no leader is not ready"
ready '{"store":{"ready":true,"node_id":"other","leader":{"node_id":"board-a"}}}' "$nodes_ok" && bad "ready: another node's answer" || ok "ready: the answer of another node id is not ready"
ready "$status_ok" '{"board-a":{"id":"board-a","reachable":true,"leader":true,"voter":true},"board-b":{"id":"board-b","reachable":false,"leader":false,"voter":true}}' && bad "ready: unreachable" || ok "ready: a node that is not reachable in /nodes is not ready"
ready "$status_ok" '{"board-a":{"id":"board-a","reachable":true,"leader":true,"voter":true},"board-b":{"id":"board-b","reachable":true,"leader":true,"voter":true}}' && bad "ready: two leaders" || ok "ready: two leaders are not a cluster with one leader"
ready "$status_ok" '{"board-a":{"id":"board-a","reachable":true,"leader":true,"voter":true},"board-b":{"id":"board-b","reachable":true,"leader":false,"voter":false}}' && bad "ready: non-voter" || ok "ready: a node that is not a voter is not ready"
ready "$status_ok" "$nodes_ok" "503 Service Unavailable" && bad "ready: a 503" || ok "ready: an answer that is not 200 is not ready"
line=$( ( FAKE_NODES=$nodes_ok rl rqlite_cluster_line 192.0.2.12 192.0.2.12 4001 ) )
check "the cluster line says the nodes, the voters and the leader" test "$line" = "2 nodes (2 voters), leader board-a"

# --- smoke and the scripts share the ssh options -------------------------------------------------------------------------------------
check "the smoke program reads SLUIS_BOARD_SSH_OPTIONS" grep -q 'SLUIS_BOARD_SSH_OPTIONS' "$here/smoke/smoke.go"
check "no script of the boards calls ssh without board_ssh" bash -c '! grep -nE "^[^#]*\bssh -o" "$1"/boards.sh "$1"/rqlite.sh "$1"/rqlite-lib.sh' _ "$here"
[ "$fail" = 0 ] || { echo "boards-test: FAILED" >&2; exit 1; }
echo "boards-test: ok"
