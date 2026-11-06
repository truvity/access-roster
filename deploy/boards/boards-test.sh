#!/usr/bin/env bash
# shellcheck disable=SC2015,SC2016 # `A && bad || ok` pairs report a check either way; single quotes hold the code of `bash -c`
# A test of the workstation side of the boards scripts (boards.sh, rqlite.sh, rqlite-lib.sh, ssh-lib.sh) against a fake ssh and a fake
# curl: no board, no network. It checks that
#   - the PIN of boards-unlock reaches the board on standard input only, byte for byte (the newline included): it is in no argument
#     of any ssh, in no environment of an ssh, and in no output, also when the PIN is typed on a terminal (a pty), also under
#     `bash -x` and SHELLOPTS=xtrace; the ssh that carries it has -T first and refuses -t and StrictHostKeyChecking=no;
#   - SLUIS_BOARD_SSH_OPTIONS reaches every ssh of boards.sh and rqlite.sh, after the defaults;
#   - a board without tar is refused before anything is sent, with the fix, and an unreachable board is told apart from it;
#   - the m1 profile deploys the twelve units of the spine with the key driver of the run, and cli/sluis is staged;
#   - an rqlite package whose sha256 differs from its pin is refused, in the cache and after a download, and a version without a pin;
#   - the readiness of an rqlite node is read from /status and /nodes, and one that has no leader, or two, is not ready.
#   - the command of a board_ssh is ONE string that the shell of the board parses again: the fake ssh joins the arguments after the
#     address like ssh does and checks the string with bash -n (and runs the rqlite reader with bash -c), so an argument with a
#     (, a * or a ? in it that is not quoted is a syntax error here as it is on a board.
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

# The fake ssh. It logs every argument, one per line between markers, and keeps what arrived on standard input; it answers the commands
# the scripts send. FAKE_TAR_RC is the status of `command -v tar` (255 is an unreachable board), FAKE_HTTP is the body of an answer
# to the GET of rqlite_get (FAKE_HTTP_BODY_<n> by the number of the call is not needed: one body for a test is enough).
cat >"$work/bin/ssh" <<'F'
#!/bin/bash
# One set of files for each call, numbered: the arguments (NUL separated), the environment, the command, whether the standard input
# was a terminal, and the standard input byte for byte.
n=$(($(cat "$FAKE_SSH_LOG.n" 2>/dev/null || echo 0) + 1))
echo "$n" >"$FAKE_SSH_LOG.n"
{
	echo "=== ssh $n"
	for a in "$@"; do printf 'arg: %s\n' "$a"; done
} >>"$FAKE_SSH_LOG"
printf '%s\0' "$@" >"$FAKE_SSH_LOG.args.$n"
env >"$FAKE_SSH_LOG.env.$n"
if [ -t 0 ]; then : >"$FAKE_SSH_LOG.tty.$n"; fi
cat >"$FAKE_SSH_LOG.in.$n"
cmd=""
seen=0
for a in "$@"; do
	if [ "$seen" = 1 ]; then cmd="$cmd $a"; fi
	[[ "$a" == *@* ]] && seen=1
done
cmd=${cmd# }
printf '%s' "$cmd" >"$FAKE_SSH_LOG.cmd.$n"
# What ssh does: the words are joined with spaces, and the shell of the board parses the string. A string that does not parse is
# what a board answers with status 2.
bash -n -c "$cmd" 2>/dev/null || { echo "bash: syntax error in the command: $cmd" >&2; exit 2; }
case "$cmd" in
"uname -n") echo "${FAKE_NODE:-board-b}" ;;
*"command -v tar"*) exit "${FAKE_TAR_RC:-0}" ;;
"mktemp -d") echo /tmp/fake-stage ;;
"sudo -n test -x /opt/sluis/bin/cli/sluis") exit "${FAKE_CLI_RC:-0}" ;;
"sudo -n /opt/sluis/bin/cli/sluis node unlock "*) echo "node ${FAKE_NODE:-board-b} is unlocked" ;;
"sudo -n /opt/sluis/bin/cli/sluis node status "*) exit_rc=${FAKE_STATUS_RC:-0}; [ "$exit_rc" != 0 ] || echo "node ${FAKE_NODE:-board-b} is ${FAKE_LOCK:-unlocked}"; exit "$exit_rc" ;;
*"list-units --failed"*) printf '%s' "${FAKE_FAILED:-}" ;;
"timeout 15 bash -s -- "*) bash -c "$cmd" </dev/null ;;
esac
exit 0
F
chmod +x "$work/bin/ssh"
# The fake of `timeout 15 bash -s -- IP PORT PATH`: the board side of rqlite_get. It keeps its arguments (the path as the shell of the
# board gave it) and answers with FAKE_STATUS for /status, FAKE_NODES for /nodes and FAKE_HTTP_BODY for any other path.
cat >"$work/bin/timeout" <<'F'
#!/bin/bash
[ "$1" = 15 ] && [ "$2" = bash ] && [ "$3" = -s ] && [ "$4" = -- ] && [ "$#" = 7 ] || { echo "timeout: unexpected arguments: $*" >&2; exit 2; }
printf '%s\n' "$5" "$6" "$7" >"${FAKE_SSH_LOG:-/dev/null}.get"
case "$7" in
/status) body=${FAKE_STATUS:-} ;;
/nodes) body=${FAKE_NODES:-} ;;
*) body=${FAKE_HTTP_BODY:-} ;;
esac
printf 'HTTP/1.0 %s\r\nContent-Type: application/json\r\n\r\n%s' "${FAKE_HTTP_STATUS:-200 OK}" "$body"
F
chmod +x "$work/bin/timeout"
export FAKE_SSH_LOG="$work/ssh.log"
export SLUIS_BOARD_SSH_USER=operator SLUIS_BOARD_SSH_AUTH_SOCK=/nonexistent
export SLUIS_BOARD_SSH_OPTIONS="-o UserKnownHostsFile=$work/known_hosts -o StrictHostKeyChecking=yes"
export PATH="$work/bin:$PATH"

# --- boards-unlock ---------------------------------------------------------------------------------------------------------------
pin=246810
newlog() { rm -f "$FAKE_SSH_LOG"*; : >"$FAKE_SSH_LOG"; }
# unlock_call prints the number of the call of the fake ssh that carried the unlock command.
unlock_call() { grep -l 'node unlock' "$FAKE_SSH_LOG".cmd.* | head -n 1 | sed 's/.*\.cmd\.//'; }
newlog
out=$(printf '%s\n' "$pin" | SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock 2>&1)
u=$(unlock_call)
check "unlock: the board answers that the node is unlocked" grep -q 'node board-b is unlocked' <<<"$out"
# After the unlock, the lock state comes from the card driver again (sluis node status), not from the word of the unlock command.
check "unlock: and the lock state is read back from the driver, one line for the board" grep -qx 'board 192.0.2.12: unlocked' <<<"$out"
check "unlock: by the status command, as root, with the node and the boundary" grep -qx "arg: sudo -n /opt/sluis/bin/cli/sluis node status board-b --boundary dev" "$FAKE_SSH_LOG"
# A PIN the card took but a driver that still says locked is not a success; a unit that systemd gave up on is named, with the way back.
if printf '%s\n' "$pin" | FAKE_LOCK=locked SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock >"$work/out" 2>&1; then bad "unlock: a driver that still says locked after the unlock fails"; else check "unlock: a driver that still says locked after the unlock fails, and says so" grep -q 'still LOCKED after the unlock' "$work/out"; fi
if printf '%s\n' "$pin" | FAKE_STATUS_RC=1 SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock >"$work/out" 2>&1; then bad "unlock: a driver that cannot be asked after the unlock fails"; else check "unlock: a driver that cannot be asked after the unlock fails, and says so" grep -q 'could not be asked for its lock state' "$work/out"; fi
if printf '%s\n' "$pin" | FAKE_FAILED=$'sluis-writer@dev.service loaded failed failed sluis writer (dev)\n' SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock >"$work/out" 2>&1; then bad "unlock: a unit that systemd gave up on fails the unlock"; else check "unlock: a failed unit is named, with reset-failed and start" grep -q 'unit sluis-writer@dev.service is FAILED.*systemctl reset-failed sluis-writer@dev.service && sudo systemctl start sluis-writer@dev.service' "$work/out"; fi
check "unlock: and the PIN is not in that output either" bash -c '! grep -q -- "$1" "$2"' _ "$pin" "$work/out"
printf '%s\n' "$pin" >"$work/pin.expected"
check "unlock: the PIN is on the standard input of the command on the board, byte for byte (one newline, nothing else)" cmp -s "$work/pin.expected" "$FAKE_SSH_LOG.in.$u"
check "unlock: the PIN is in no argument of any ssh" bash -c '! grep -q -- "$1" "$2" && ! grep -qa -- "$1" "$2".args.*' _ "$pin" "$FAKE_SSH_LOG"
check "unlock: the PIN is in no environment of any ssh" bash -c '! grep -qa -- "$1" "$2".env.*' _ "$pin" "$FAKE_SSH_LOG"
check "unlock: and not in the output" bash -c '! grep -q "$1" <<<"$2"' _ "$pin" "$out"
check "unlock: the command is the CLI under sudo, with the host name and the boundary" grep -qx "arg: sudo -n /opt/sluis/bin/cli/sluis node unlock board-b --boundary dev" "$FAKE_SSH_LOG"
check "unlock: the ssh options of the run are on the command line" grep -qx "arg: UserKnownHostsFile=$work/known_hosts" "$FAKE_SSH_LOG"
check "unlock: and come after the defaults" bash -c 'awk "/^arg: BatchMode=yes/{b=NR} /^arg: UserKnownHostsFile/{u=NR} END{exit !(b && u && b<u)}" "$1"' _ "$FAKE_SSH_LOG"
# -T is the first argument of the ssh that carries the PIN, so before the options of the run; the ssh keeps the first value it sees.
check "unlock: the ssh that carries the PIN has -T first, before the options" bash -c 'tr "\0" "\n" <"$1" | head -n 1 | grep -qx -- -T' _ "$FAKE_SSH_LOG.args.$u"
check "unlock: and its standard input is not a terminal" test ! -e "$FAKE_SSH_LOG.tty.$u"
# StrictHostKeyChecking=yes comes right after -T, before the options of the run (and so before any config file): ssh keeps the first.
check "unlock: the ssh that carries the PIN has -o StrictHostKeyChecking=yes second, before the options of the run" bash -c 'tr "\0" "\n" <"$1" | sed -n "1,3p" | tr "\n" " " | grep -qx -- "-T -o StrictHostKeyChecking=yes "' _ "$FAKE_SSH_LOG.args.$u"
check "unlock: and the ssh that does not carry a secret does not get it" bash -c '! tr "\0" "\n" <"$1" | sed -n 1,3p | grep -q StrictHostKeyChecking' _ "$FAKE_SSH_LOG.args.1"
# A pipe with a CRLF, or no newline at all, is passed as it is: the CLI strips a trailing CR and reads to the end.
newlog
printf '%s' "$pin" | SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock >/dev/null 2>&1
check "unlock: a PIN piped without a newline is passed without one" cmp -s <(printf '%s' "$pin") "$FAKE_SSH_LOG.in.$(unlock_call)"
if SLUIS_BOARDS="192.0.2.12 192.0.2.13" "$here/boards.sh" unlock </dev/null >/dev/null 2>"$work/err"; then bad "unlock: two boards are refused"; else check "unlock: two boards are refused" grep -q 'exactly one board' "$work/err"; fi
FAKE_CLI_RC=1 SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock </dev/null >/dev/null 2>"$work/err" && bad "unlock: a board without the CLI is refused" || check "unlock: a board without the CLI is refused, with the fix" grep -q 'just build-arm64' "$work/err"
# The PIN of the test is in no script (the Justfile and the docs are looked at too: the files must exist, or the check would be vacuous).
for f in "$here/boards.sh" "$here/../../Justfile" "$here/../../docs/runtimes/bare-metal.md"; do
	[ -f "$f" ] || bad "the file to look in is missing: $f"
	if grep -n -- "$pin" "$f" >/dev/null; then bad "the PIN of the test is in $f"; fi
done
# Options that must not carry a PIN. Nothing is sent to the board: the refusal comes before the first ssh.
for opts in "-o StrictHostKeyChecking=no" "-oStrictHostKeyChecking=no" "-o StrictHostKeyChecking=off" "-o stricthostkeychecking=NO" "-o StrictHostKeyChecking=\"no\"" "-o StrictHostKeyChecking='no'" "-o \"StrictHostKeyChecking=no\"" "-o StrictHostKeyChecking = no" "-o UserKnownHostsFile=/dev/null" "-oUserKnownHostsFile=/dev/null" "-o UserKnownHostsFile=\"/dev/null\"" "-o userknownhostsfile=/dev/null -o StrictHostKeyChecking=yes" "-tt" "-t" "-vt"; do
	newlog
	if printf '%s\n' "$pin" | SLUIS_BOARD_SSH_OPTIONS="$opts" SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock >"$work/out" 2>"$work/err"; then
		bad "unlock: the options '$opts' are refused"
	else
		check "unlock: the options '$opts' are refused, and nothing is sent" bash -c '[ ! -e "$1.n" ] && grep -q "^ssh:" "$2"' _ "$FAKE_SSH_LOG" "$work/err"
	fi
done
newlog
printf '%s\n' "$pin" | SLUIS_BOARD_SSH_OPTIONS="-o UserKnownHostsFile=$work/known_hosts -o StrictHostKeyChecking=accept-new" SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock >"$work/out" 2>"$work/err"
check "unlock: accept-new goes on, with a warning that it is ignored" grep -q 'warning: StrictHostKeyChecking=accept-new is ignored' "$work/err"
check "unlock: and the yes before it is what ssh keeps" bash -c 'tr "\0" "\n" <"$1" | grep -n -x -e StrictHostKeyChecking=yes -e StrictHostKeyChecking=accept-new | tr "\n" " " | grep -q "^[0-9]*:StrictHostKeyChecking=yes .*accept-new"' _ "$FAKE_SSH_LOG.args.$(unlock_call)"
newlog
printf '%s\n' "$pin" | SLUIS_BOARD_SSH_OPTIONS="-o RequestTTY=force" SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock >/dev/null 2>&1
check "unlock: RequestTTY=force in the options comes after -T, which wins" bash -c 'tr "\0" "\n" <"$1" | grep -n -x -e -T -e RequestTTY=force | tr "\n" " " | grep -q "^1:-T .*RequestTTY=force"' _ "$FAKE_SSH_LOG.args.$(unlock_call)"
# The terminal branch: the only code that holds the PIN in the shell. It runs on a pty, with a fake ssh, in four ways: plain, under
# bash -x, with SHELLOPTS=xtrace in the environment, and with BASH_XTRACEFD pointing at a file. The transcript of the terminal and the
# trace file must not hold the PIN, and the standard input of the ssh must hold it exactly.
if command -v python3 >/dev/null 2>&1; then
	cat >"$work/pty.py" <<'PY'
import os, pty, select, sys
pin = sys.argv[1]
args = sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(args[0], args)
out = b""
sent = False
while True:
    r, _, _ = select.select([fd], [], [], 60)
    if not r:
        os.kill(pid, 9)
        sys.exit("pty: timeout")
    try:
        d = os.read(fd, 4096)
    except OSError:
        break
    if not d:
        break
    out += d
    if not sent and b"PIN of the card" in out:
        os.write(fd, (pin + "\n").encode())
        sent = True
_, st = os.waitpid(pid, 0)
sys.stdout.buffer.write(out)
sys.exit(os.waitstatus_to_exitcode(st))
PY
	pty_unlock() { # description, then the command to run under the pty (after env)
		local d=$1 u
		shift
		newlog
		if ! SLUIS_BOARDS=192.0.2.12 python3 -I "$work/pty.py" "$pin" "$@" >"$work/pty.out" 2>"$work/pty.err"; then
			bad "pty: $d: the command failed: $(head -c 300 "$work/pty.err")"
			return
		fi
		u=$(unlock_call)
		check "pty: $d: the PIN typed on the terminal reaches the ssh on its standard input, byte for byte" cmp -s "$work/pin.expected" "$FAKE_SSH_LOG.in.$u"
		check "pty: $d: the terminal did not echo it, nor print it in a trace" bash -c '! grep -qa -- "$1" "$2"' _ "$pin" "$work/pty.out"
		check "pty: $d: it is in no argument and no environment of any ssh" bash -c '! grep -qa -- "$1" "$2" "$2".args.* "$2".env.*' _ "$pin" "$FAKE_SSH_LOG"
		check "pty: $d: the ssh has -T first and its standard input is not a terminal" bash -c 'tr "\0" "\n" <"$1" | head -n 1 | grep -qx -- -T && [ ! -e "$2" ]' _ "$FAKE_SSH_LOG.args.$u" "$FAKE_SSH_LOG.tty.$u"
	}
	pty_unlock "plain" "$here/boards.sh" unlock
	pty_unlock "bash -x" bash -x "$here/boards.sh" unlock
	check "pty: bash -x: tracing was on before the PIN (the trace is in the transcript)" grep -qa '^+ ' "$work/pty.out"
	pty_unlock "SHELLOPTS=xtrace" env SHELLOPTS=xtrace bash "$here/boards.sh" unlock
	check "pty: SHELLOPTS=xtrace: tracing was on before the PIN" grep -qa '^+ ' "$work/pty.out"
	# SHELLOPTS=allexport would export every variable that is assigned, the PIN's included, to the ssh: set +a before the read.
	pty_unlock "SHELLOPTS=allexport" env SHELLOPTS=allexport bash "$here/boards.sh" unlock
	: >"$work/xtrace.fd"
	pty_unlock "BASH_XTRACEFD" bash -c 'exec 7>"$1"; exec env SHELLOPTS=xtrace BASH_XTRACEFD=7 bash "$2" unlock' _ "$work/xtrace.fd" "$here/boards.sh"
	check "pty: BASH_XTRACEFD: tracing went to the file before the PIN" test -s "$work/xtrace.fd"
	check "pty: BASH_XTRACEFD: and the trace file does not hold the PIN" bash -c '! grep -qa -- "$1" "$2"' _ "$pin" "$work/xtrace.fd"
else
	echo "SKIP the terminal branch of boards-unlock: python3 is missing"
fi

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
plan=$(SLUIS_BOARDS="192.0.2.11 192.0.2.12 192.0.2.13" SLUIS_BOARDS_DRY_RUN=1 "$here/rqlite.sh")
joins='192.0.2.11:4002,192.0.2.12:4002,192.0.2.13:4002'
for b in 11 12 13; do
	check "rqlite.sh: board 192.0.2.$b has -bootstrap-expect 3 and the join list of all three, itself included" grep -q "board 192.0.2.$b: -http-addr 192.0.2.$b:4001 -raft-addr 192.0.2.$b:4002 -bootstrap-expect 3 -join $joins\$" <<<"$plan"
done
check "rqlite.sh: no board is special (no node without -join)" bash -c '! grep -q "no -join\|bootstrap:" <<<"$1"' _ "$plan"
check "rqlite.sh: all four packages have a pin" test "$(grep -cE '^    rqlite.* [0-9a-f]{64}$' <<<"$plan")" = 4
one=$(SLUIS_BOARDS="192.0.2.11" SLUIS_BOARDS_DRY_RUN=1 "$here/rqlite.sh")
check "rqlite.sh: a cluster of one has neither -bootstrap-expect nor -join" bash -c 'grep -q "board 192.0.2.11: .*cluster of one" <<<"$1" && ! grep -q -- "-join 192" <<<"$1" && ! grep -q -- "-bootstrap-expect [0-9]" <<<"$1"' _ "$one"
SLUIS_RQLITE_BOOTSTRAP=192.0.2.11 SLUIS_BOARDS="192.0.2.11 192.0.2.12" SLUIS_BOARDS_DRY_RUN=1 "$here/rqlite.sh" >/dev/null 2>"$work/err"
check "rqlite.sh: the old SLUIS_RQLITE_BOOTSTRAP is ignored with a warning" grep -q 'SLUIS_RQLITE_BOOTSTRAP is ignored' "$work/err"
rqrefuse() { # description pattern, with SLUIS_BOARDS and the other settings in the environment
	SLUIS_BOARDS_DRY_RUN=1 "$here/rqlite.sh" >/dev/null 2>"$work/err" && bad "rqlite.sh: $1" || check "rqlite.sh: $1" grep -q "$2" "$work/err"
}
SLUIS_BOARDS="board.example.com" rqrefuse "a board name that is not an address is refused" 'not an IPv4 address'
SLUIS_BOARDS="192.0.2.010" rqrefuse "an address with a leading zero is refused" 'not an IPv4 address'
SLUIS_BOARDS="192.0.2.11 192.0.2.12 192.0.2.11" rqrefuse "a board listed twice is refused" 'listed twice'
SLUIS_BOARDS="192.0.2.11" SLUIS_RQLITE_PORT_HTTP=4002 rqrefuse "the same port for HTTP and Raft is refused" 'must differ'
SLUIS_BOARDS="192.0.2.11" SLUIS_RQLITE_PORT_RAFT=0 rqrefuse "port 0 is refused" 'from 1 to 65535'
SLUIS_BOARDS="192.0.2.11" SLUIS_BOARD_SSH_USER='' rqrefuse "no ssh user is refused" 'SLUIS_BOARD_SSH_USER'
# Without jq the recipe says so at once, not after two minutes of "not ready".
nojq=$work/nojq
mkdir -p "$nojq"
for t in bash git dirname mktemp rm cat env sed head tr; do ln -sf "$(command -v "$t")" "$nojq/$t"; done
PATH=$nojq SLUIS_BOARDS=192.0.2.11 "$here/rqlite.sh" >/dev/null 2>"$work/err" && bad "rqlite.sh: no jq is refused" || check "rqlite.sh: no jq is refused before any ssh" grep -q 'jq is needed' "$work/err"

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
[ -z "${FAKE_CURL_LOG:-}" ] || echo "called: $*" >>"$FAKE_CURL_LOG"
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
# A curl that would succeed: the refusal must come from the missing pin, and curl must never be called.
: >"$work/curl.log"
FAKE_CURL_LOG=$work/curl.log FAKE_CURL_FILE=$work/pkg.deb PINS=$work/pins rl rqlite_fetch rqlite_10.6.6_x86_64.rpm "$cache" >/dev/null 2>"$work/err" && bad "fetch: a name without a pin is refused before any download" || check "fetch: a name without a pin is refused (for the pin)" grep -q 'pins no sha256' "$work/err"
check "fetch: and curl was never called" test ! -s "$work/curl.log"
rm -rf "$cache"
FAKE_CURL_FAIL=1 FAKE_CURL_FILE=$work/pkg.deb PINS=$work/pins rl rqlite_fetch rqlite_10.6.6_arm64.deb "$cache" >/dev/null 2>"$work/err" && bad "fetch: a failed download is an error" || check "fetch: a failed download is an error" grep -q 'cannot download' "$work/err"

# --- the readiness of a node -------------------------------------------------------------------------------------------------------
# The id of a node is its Raft address: the nodes are started without -node-id.
status_ok='{"store":{"ready":true,"node_id":"192.0.2.12:4002","leader":{"addr":"192.0.2.13:4002","node_id":"192.0.2.13:4002"}}}'
nodes_ok='{"192.0.2.13:4002":{"id":"192.0.2.13:4002","reachable":true,"leader":true,"voter":true},"192.0.2.12:4002":{"id":"192.0.2.12:4002","reachable":true,"leader":false,"voter":true}}'
# A fake ssh that answers /status and /nodes with the bodies of the test.
cat >"$work/bin/ssh" <<'F'
#!/bin/bash
cat >/dev/null
cmd=""
seen=0
for a in "$@"; do
	if [ "$seen" = 1 ]; then cmd="$cmd $a"; fi
	[[ "$a" == *@* ]] && seen=1
done
# The shell of the board parses the joined string and runs it; the fake timeout (above) answers for the node.
bash -c "${cmd# }" </dev/null
F
id12=$(rl rqlite_node_id 192.0.2.12 4002)
check "the id of a node is its Raft address" test "$id12" = "192.0.2.12:4002"
ready() { ( FAKE_STATUS=$1 FAKE_NODES=$2 FAKE_HTTP_STATUS=${3:-200 OK} rl rqlite_node_ready 192.0.2.12 192.0.2.12 4001 "$id12" 4002 ) 2>"$work/why"; }
ready "$status_ok" "$nodes_ok" && ok "ready: a ready voter of a cluster with one leader" || { bad "ready: a ready voter"; cat "$work/why"; }
ready '{"store":{"ready":false,"node_id":"192.0.2.12:4002","leader":{"node_id":"192.0.2.13:4002"}}}' "$nodes_ok" && bad "ready: a store that is not ready" || check "ready: a store that is not ready is not ready" grep -q 'not ready' "$work/why"
ready '{"store":{"ready":true,"node_id":"192.0.2.12:4002","leader":{"node_id":""}}}' "$nodes_ok" && bad "ready: no leader" || ok "ready: a node that knows no leader is not ready"
ready '{"store":{"ready":true,"node_id":"other","leader":{"node_id":"192.0.2.13:4002"}}}' "$nodes_ok" && bad "ready: another node's answer" || ok "ready: the answer of another node id is not ready"
ready "$status_ok" '{"192.0.2.13:4002":{"id":"192.0.2.13:4002","reachable":true,"leader":true,"voter":true},"192.0.2.12:4002":{"id":"192.0.2.12:4002","reachable":false,"leader":false,"voter":true}}' && bad "ready: unreachable" || ok "ready: a node that is not reachable in /nodes is not ready"
check "ready: and the failure names the ports and the firewall commands" bash -c 'grep -q "reachable voter" "$1" && grep -q "firewall-cmd" "$1" && grep -q "ufw allow" "$1" && grep -q "4001" "$1" && grep -q "4002" "$1"' _ "$work/why"
ready "$status_ok" '{"192.0.2.13:4002":{"id":"192.0.2.13:4002","reachable":true,"leader":true,"voter":true},"192.0.2.12:4002":{"id":"192.0.2.12:4002","reachable":true,"leader":true,"voter":true}}' && bad "ready: two leaders" || ok "ready: two leaders are not a cluster with one leader"
ready "$status_ok" '{"192.0.2.13:4002":{"id":"192.0.2.13:4002","reachable":true,"leader":true,"voter":true},"192.0.2.12:4002":{"id":"192.0.2.12:4002","reachable":true,"leader":false,"voter":false}}' && bad "ready: non-voter" || ok "ready: a node that is not a voter is not ready"
ready "$status_ok" "$nodes_ok" "503 Service Unavailable" && bad "ready: a 503" || ok "ready: an answer that is not 200 is not ready"
line=$( ( FAKE_NODES=$nodes_ok rl rqlite_cluster_line 192.0.2.12 192.0.2.12 4001 ) )
check "the cluster line says the nodes, the voters and the leader" test "$line" = "2 nodes (2 voters), leader 192.0.2.13:4002"
check "the node count is the number of entries of /nodes" test "$( ( FAKE_NODES=$nodes_ok rl rqlite_node_count 192.0.2.12 192.0.2.12 4001 ) )" = 2
# rqlite_get hands its arguments to the shell of the board as one string: a path with (, *, ?, %, a space or a single quote in it
# arrives as it was, and an answer that is not a 200 is a failure. The path of board_data_keys is the one with count(*) in it.
export FAKE_SSH_LOG
get_path='/db/query?q=SELECT%20count(*)%20FROM%20durable_items%20WHERE%20key%20LIKE%20%27%25/data-key-wrap/%25%27'
got=$( ( FAKE_HTTP_BODY='{"results":[{"values":[[3]]}]}' rl rqlite_get 192.0.2.12 192.0.2.12 4001 "$get_path" ) 2>"$work/err" ) || bad "get: the path of the data-key count is read ($(cat "$work/err"))"
check "get: the path with count(*) and % reaches the board as it was written, in one piece" bash -c '[ "$(sed -n 3p "$1")" = "$2" ] && [ "$(sed -n 1p "$1")" = 192.0.2.12 ] && [ "$(sed -n 2p "$1")" = 4001 ]' _ "$FAKE_SSH_LOG.get" "$get_path"
check "get: and its body is what the node answered" test "$got" = '{"results":[{"values":[[3]]}]}'
odd="/a b/it's;\$(x)*?"
( FAKE_HTTP_BODY=x rl rqlite_get 192.0.2.12 192.0.2.12 4001 "$odd" ) >/dev/null 2>"$work/err" || bad "get: an odd path is read ($(cat "$work/err"))"
check "get: a path with a space, a single quote, ;, \$( and a glob in it arrives as it was, and runs nothing" test "$(sed -n 3p "$FAKE_SSH_LOG.get")" = "$odd"
( FAKE_HTTP_STATUS="503 Service Unavailable" FAKE_HTTP_BODY=x rl rqlite_get 192.0.2.12 192.0.2.12 4001 "$get_path" ) >/dev/null 2>&1 && bad "get: an answer that is not a 200 fails" || ok "get: an answer that is not a 200 fails"
# A board that cannot parse the command (what the unquoted form gave) is a failure too, not an empty answer.
( rl board_ssh 192.0.2.12 'timeout 15 bash -s -- 192.0.2.12 4001 /db/query?q=SELECT count(*)' ) >/dev/null 2>"$work/err" && bad "get: the fake ssh parses the string like a shell (an unquoted ( is a syntax error)" || ok "get: the fake ssh refuses a command that the shell of a board would not parse (the unquoted form of rqlite_get)"
q=$(rl shell_quote "a b" "x(*)?" "it's" "")
check "shell_quote: words with a space, a ( * ?, a single quote and nothing at all come out as the same words" test "$(eval "printf '<%s>' $q")" = "<a b><x(*)?><it's><>"
# The wait is bounded by the clock: a ssh that takes 2 s per call (a board that drops packets) ends a wait of 2 s after one poll. When
# the loop counted its own sleeps (0, 2, 4 ...) it would have polled again and again, for 6 s here and for half an hour in the field.
cat >"$work/bin/ssh" <<'F'
#!/bin/bash
cat >/dev/null
sleep 2
exit 1
F
start=$SECONDS
( rl rqlite_wait 192.0.2.12 192.0.2.12 4001 "$id12" 2 4002 ) 2>"$work/why" && bad "wait: a node that never answers fails" || ok "wait: a node that never answers fails"
took=$((SECONDS - start))
check "wait: and by the clock (took ${took} s for a limit of 2 s and a poll of 2 s; counting sleeps would take 6 s)" test "$took" -le 4
check "wait: and says how long it waited" grep -q 'not ready after 2 s' "$work/why"
rqlite_need_jq_ok() { PATH=$nojq rl rqlite_need_jq; }
rqlite_need_jq_ok 2>"$work/err" && bad "jq: a workstation without jq is refused" || check "jq: a workstation without jq is refused, with the fix" grep -q 'jq is needed' "$work/err"
# the ssh defaults and SLUIS_BOARD_SSH_OPTIONS
cat >"$work/bin/ssh" <<'F'
#!/bin/bash
printf 'arg: %s\n' "$@" >"$FAKE_SSH_LOG.opts"
cat >"$FAKE_SSH_LOG.opts.in"
F
( SLUIS_BOARD_SSH_OPTIONS=$'-o UserKnownHostsFile=/x/known_hosts\n-o StrictHostKeyChecking=yes -o LogLevel=ERROR' rl board_ssh 192.0.2.12 true )
check "ssh: the defaults keep a dropped connection short (ServerAliveInterval, ServerAliveCountMax)" bash -c 'grep -qx "arg: ServerAliveInterval=5" "$1" && grep -qx "arg: ServerAliveCountMax=3" "$1"' _ "$FAKE_SSH_LOG.opts"
check "ssh: SLUIS_BOARD_SSH_OPTIONS is read on all its lines (as Go's strings.Fields does)" bash -c 'grep -qx "arg: UserKnownHostsFile=/x/known_hosts" "$1" && grep -qx "arg: StrictHostKeyChecking=yes" "$1" && grep -qx "arg: LogLevel=ERROR" "$1"' _ "$FAKE_SSH_LOG.opts"
check "ssh: and they come after the defaults" bash -c 'awk "/^arg: ServerAliveCountMax/{d=NR} /^arg: UserKnownHostsFile/{u=NR} END{exit !(d && u && d<u)}" "$1"' _ "$FAKE_SSH_LOG.opts"
printf 'x' | rl board_ssh 192.0.2.12 true
check "ssh: board_ssh passes the standard input of its caller" test "$(cat "$FAKE_SSH_LOG.opts.in")" = x
printf 'x' | rl board_ssh_n 192.0.2.12 true
check "ssh: board_ssh_n gives ssh /dev/null instead, so it swallows nothing of a loop" test ! -s "$FAKE_SSH_LOG.opts.in"

# --- smoke and the scripts share the ssh options -------------------------------------------------------------------------------------
check "the smoke program reads SLUIS_BOARD_SSH_OPTIONS" grep -q 'SLUIS_BOARD_SSH_OPTIONS' "$here/smoke/smoke.go"
check "no script of the boards calls ssh without board_ssh" bash -c '! grep -nE "^[^#]*\bssh -o" "$1"/boards.sh "$1"/rqlite.sh "$1"/rqlite-lib.sh' _ "$here"
[ "$fail" = 0 ] || { echo "boards-test: FAILED" >&2; exit 1; }
echo "boards-test: ok"
