#!/usr/bin/env bash
# shellcheck disable=SC2015,SC2016,SC2317,SC2329 # `A && bad || ok` pairs report a check either way; single quotes hold the code of `bash -c`
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
	[[ "$a" == *@* ]] && { seen=1; via=${a#*@}; }
done
cmd=${cmd# }
printf '%s' "$cmd" >"$FAKE_SSH_LOG.cmd.$n"
# What ssh does: the words are joined with spaces, and the shell of the board parses the string. A string that does not parse is
# what a board answers with status 2.
bash -n -c "$cmd" 2>/dev/null || { echo "bash: syntax error in the command: $cmd" >&2; exit 2; }
case "$cmd" in
"uname -n") echo "${FAKE_NODE:-board-b}" ;;
*"command -v tar"*) exit "${FAKE_TAR_RC:-0}" ;;
"test -x /usr/sbin/nft") exit "${FAKE_NFT_RC:-0}" ;;
*"for u in sluis-drv-key-yubikey-piv@dev.service"*) printf 'sluis-drv-key-yubikey-piv@dev.service not-found\nsluis-drv-key-software@dev.service not-found\n' ;;
"mktemp -d") echo /tmp/fake-stage ;;
*" firewall-status "*) n=$(($(cat "$FAKE_SSH_LOG.drops" 2>/dev/null || echo 0) + 1)); echo "$n" >"$FAKE_SSH_LOG.drops"; printf 'rqlite firewall: fake\nSLUIS-FIREWALL-RAFT: %s\nSLUIS-FIREWALL-HTTP: %s\nSLUIS-FIREWALL-DROPS: %s\nSLUIS-FIREWALL: %s\n' "${FAKE_FW_RAFT-192.0.2.11 192.0.2.12 192.0.2.13 203.0.113.5}" "${FAKE_FW_HTTP-203.0.113.5}" "${FAKE_FW_DROPS-$((n * ${FAKE_FW_DROPS_STEP:-5}))}" "${FAKE_FW_STATE:-ok}"; [ "${FAKE_FW_STATE:-ok}" = ok ] ;;
*" firewall-apply "*) echo "firewall: fake apply"; exit "${FAKE_FW_APPLY_RC:-0}" ;;
*" firewall-confirm "*) echo "firewall: fake confirm"; exit "${FAKE_FW_CONFIRM_RC:-0}" ;;
*" firewall-remove "*) echo "firewall: fake remove"; exit "${FAKE_FW_REMOVE_RC:-0}" ;;
*" firewall-boot-order "*) echo "boot order: fake"; exit "${FAKE_FW_ORDER_RC:-0}" ;;
"cat /proc/sys/kernel/random/boot_id") cat "${FAKE_BOOT_FILE:-/dev/null}" ;;
"sudo -n systemctl reboot") echo boot-b >"${FAKE_BOOT_FILE:?}" ;;
"timeout 5 bash -c "*) eval "set -- ${cmd#timeout 5 bash -c }"; exit "$("$FAKE_PROBE_RC" "$via" "$2" "$3")" ;;
"sudo -n test -x /opt/sluis/bin/cli/sluis") exit "${FAKE_CLI_RC:-0}" ;;
"sudo -n /opt/sluis/bin/cli/sluis node unlock "*) echo "node ${FAKE_NODE:-board-b} is unlocked" ;;
"sudo -n /opt/sluis/bin/cli/sluis node status "*) exit_rc=${FAKE_STATUS_RC:-0}; [ "$exit_rc" != 0 ] || { [ -z "${FAKE_LOGLINE:-}" ] || echo "$FAKE_LOGLINE"; [ -z "${FAKE_PINLINE:-}" ] || echo "$FAKE_PINLINE"; echo "node ${FAKE_NODE:-board-b} is ${FAKE_LOCK:-unlocked}"; }; exit "$exit_rc" ;;
*"remote.sh' settle "*) echo "unit sluis-writer@dev.service ${FAKE_SETTLE_LINE:-active}"; echo "SLUIS-BOARD-STATE: ${FAKE_SETTLE:-ok}"; case "${FAKE_SETTLE:-ok}" in ok) exit 0 ;; locked) exit 10 ;; *) exit 1 ;; esac ;;
*"list-units --failed"*) printf '%s' "${FAKE_FAILED:-}" ;;
"timeout 15 bash -s -- "*) bash -c "$cmd" </dev/null ;;
esac
exit 0
F
chmod +x "$work/bin/ssh"
cp "$work/bin/ssh" "$work/ssh.main" # later sections put a simpler ssh in its place; the firewall section takes this one back
# The fake of `timeout 15 bash -s -- IP PORT PATH`: the board side of rqlite_get. It keeps its arguments (the path as the shell of the
# board gave it) and answers with FAKE_STATUS for /status, FAKE_NODES for /nodes and FAKE_HTTP_BODY for any other path.
cat >"$work/bin/timeout" <<'F'
#!/bin/bash
if [ "$1" = 5 ] && [ "$2" = bash ] && [ "$3" = -c ] && [ "$#" = 6 ]; then exit "$("$FAKE_PROBE_RC" local "$5" "$6")"; fi
[ "$1" = 15 ] && [ "$2" = bash ] && [ "$3" = -s ] && [ "$4" = -- ] && [ "$#" = 7 ] || { echo "timeout: unexpected arguments: $*" >&2; exit 2; }
printf '%s\n' "$5" "$6" "$7" >"${FAKE_SSH_LOG:-/dev/null}.get"
case "$7" in
/status) body=${FAKE_STATUS//@IP@/$5} ;;
/nodes) body=${FAKE_NODES:-} ;;
*) body=${FAKE_HTTP_BODY:-} ;;
esac
printf 'HTTP/1.0 %s\r\nContent-Type: application/json\r\n\r\n%s' "${FAKE_HTTP_STATUS:-200 OK}" "$body"
F
chmod +x "$work/bin/timeout"
# The map of the fake probes: FAKE_PROBE_MAP is a list of "via>address:port=status" (via is a board or host address, or "local" for this
# workstation); a probe not in it ends with FAKE_PROBE_DEFAULT (0: the port answered; 124: timeout, which is what a drop looks like).
cat >"$work/probe-rc" <<'F'
#!/bin/bash
for e in ${FAKE_PROBE_MAP:-}; do
	[ "${e%%=*}" = "$1>$2:$3" ] && { echo "${e#*=}"; exit 0; }
done
echo "${FAKE_PROBE_DEFAULT:-0}"
F
chmod +x "$work/probe-rc"
export FAKE_PROBE_RC="$work/probe-rc"
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
check "unlock: and every unit is waited for again after it, as the deploy does (remote.sh settle)" grep -qx 'board 192.0.2.12: every unit is up' <<<"$out"
# A log line before the answer of the CLI does not make the check fail (the deploy takes the last line, too).
check "unlock: a log line before the answer of 'node status' is ignored" bash -c 'printf "%s\n" "$1" | FAKE_LOGLINE="{\"level\":\"INFO\",\"msg\":\"x\"}" SLUIS_BOARDS=192.0.2.12 "$2" unlock 2>&1 | grep -qx "board 192.0.2.12: unlocked"' _ "$pin" "$here/boards.sh"
# The CLI prints a line about the PIN attempts left before the lock line (sluis node status); the deploy reads the last line only.
check "unlock: a PIN counter line before the answer of 'node status' is ignored" bash -c 'printf "%s\n" "$1" | FAKE_PINLINE="node board-b: PIN attempts left: 1, ONE MORE WRONG PIN BLOCKS THE CARD (the PUK procedure is the owners'"'"')" SLUIS_BOARDS=192.0.2.12 "$2" unlock 2>&1 | grep -qx "board 192.0.2.12: unlocked"' _ "$pin" "$here/boards.sh"
# Unlocked, but a unit still loops: it never reaches "failed", so the unlock must fail on the wait, not on systemd's state.
if printf '%s\n' "$pin" | FAKE_SETTLE=failed FAKE_SETTLE_LINE='FAILED: not settled after 90 s: activating (auto-restart), restarted 9 times' SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock >"$work/out" 2>&1; then bad "unlock: a unit that keeps restarting after the unlock fails it"; else check "unlock: a unit that keeps restarting after the unlock fails it, and says why" grep -q 'the units did not settle after the unlock (state .failed.)' "$work/out"; fi
check "unlock: and the unit line is shown" grep -q 'restarted 9 times' "$work/out"
if printf '%s\n' "$pin" | FAKE_SETTLE=locked SLUIS_BOARDS=192.0.2.12 "$here/boards.sh" unlock >"$work/out" 2>&1; then bad "unlock: a board that is locked on the second look fails it"; else ok "unlock: a board that is locked on the second look fails it"; fi
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
# nft: a deploy to a board without /usr/sbin/nft is refused before anything is sent, and says the fix; the modes that only look are not.
unset SLUIS_BOARDS_DRY_RUN
: >"$FAKE_SSH_LOG"
FAKE_NFT_RC=1 SLUIS_BOARDS_PROFILE=m1 "$here/boards.sh" deploy >"$work/out" 2>"$work/err" && bad "nft: a board without nft fails the deploy" || ok "nft: a board without nft fails the deploy"
check "nft: and the message names nft and the fix" grep -q "has no /usr/sbin/nft.*dnf install nftables" "$work/err"
check "nft: and no deploy or preflight ran on the board (the stage was not sent)" bash -c '! grep -q "remote.sh. \(deploy\|preflight\) " "$1"' _ "$FAKE_SSH_LOG"
FAKE_NFT_RC=255 SLUIS_BOARDS_PROFILE=m1 "$here/boards.sh" deploy >"$work/out" 2>"$work/err" && bad "nft: an unreachable board fails the deploy" || check "nft: an unreachable board is not reported as a missing nft" bash -c 'grep -q "cannot reach" "$1" && ! grep -q "has no /usr/sbin/nft" "$1"' _ "$work/err"
FAKE_NFT_RC=1 SLUIS_BOARDS=192.0.2.11 "$here/boards.sh" status >"$work/out" 2>"$work/err" || true; check "nft: boards-status does not need nft" bash -c '! grep -q "has no /usr/sbin/nft" "$1"' _ "$work/err"
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
# --- firewall.sh: the rqlite firewall of the boards, against the fake ssh --------------------------------------------------------
# The rules are text that the board's nft loads; what is checked here is the text (against nft -c where nft is available, and against
# real packets in a network namespace where one can be made), what firewall.sh sends and refuses, and the proofs that a confirm needs
# before it keeps anything. The board side is in prereq-test.sh.
cp "$work/ssh.main" "$work/bin/ssh"
FW3="192.0.2.11 192.0.2.12 192.0.2.13"
nodes3='{"192.0.2.11:4002":{"voter":true,"reachable":true,"leader":false},"192.0.2.12:4002":{"voter":true,"reachable":true,"leader":true},"192.0.2.13:4002":{"voter":true,"reachable":true,"leader":false}}'
# Between the boards only the Raft port answers: the client port of a board times out from another board (REQ-DEPLOY-046, D5).
closed_http=""
for a in 192.0.2.11 192.0.2.12 192.0.2.13; do for b in 192.0.2.11 192.0.2.12 192.0.2.13; do [ "$a" = "$b" ] || closed_http="$closed_http $a>$b:4001=124"; done; done
status3='{"store":{"ready":true,"node_id":"@IP@:4002","leader":{"node_id":"192.0.2.12:4002"}}}'
fw() { # mode [VAR=value]...: firewall.sh with the three boards and an administration host
	local m=$1
	shift
	env SLUIS_BOARDS="$FW3" SLUIS_FIREWALL_ADMIN_HOST=203.0.113.5 SLUIS_FIREWALL_BOARDS=192.0.2.12 SLUIS_FIREWALL_POLL_SECONDS=0 FAKE_PROBE_MAP="$closed_http" "$@" "$here/firewall.sh" "$m"
}
fwrefuse() { # description pattern mode [VAR=value]...
	local d=$1 pat=$2
	shift 2
	newlog
	if fw "$@" >"$work/out" 2>"$work/err"; then bad "firewall.sh: $d: it succeeded"; else check "firewall.sh: $d" grep -q -- "$pat" "$work/err"; fi
	check "firewall.sh: $d: and no ssh was run" test ! -e "$FAKE_SSH_LOG.n"
}
# The calls of the fake ssh whose command holds a word, as the files of the log.
fw_calls() { grep -lF -- "$1" "$FAKE_SSH_LOG".cmd.* 2>/dev/null || true; }
# probe_calls via address port: how many probes from the host `via` to address:port the fake ssh has seen.
probe_calls() {
	local f n=0 i
	for f in "$FAKE_SSH_LOG".cmd.*; do
		[ -e "$f" ] || continue
		i=${f##*.cmd.}
		grep -qF "timeout 5 bash -c" "$f" && grep -qF "'$2' '$3'" "$f" && tr '\0' '\n' <"$FAKE_SSH_LOG.args.$i" | grep -qx "operator@$1" && n=$((n + 1))
	done
	echo "$n"
}

# The dry run prints the exact rules, and touches no board.
newlog
dry=$(fw apply SLUIS_BOARDS_DRY_RUN=1 SLUIS_FIREWALL_BOARDS=192.0.2.12)
check "firewall.sh: a dry run runs no ssh" test ! -e "$FAKE_SSH_LOG.n"
want_rules=$(
	# shellcheck source=/dev/null
	. "$here/remote-lib.sh"
	# shellcheck source=/dev/null
	. "$here/firewall-lib.sh"
	firewall_ruleset 4001 4002 203.0.113.5 192.0.2.11 192.0.2.12 192.0.2.13
)
check "firewall.sh: the dry run prints the rules exactly as they are sent" bash -c '[[ "$1" == *"$2"* ]]' _ "$dry" "$want_rules"
check "firewall.sh: the Raft set holds the three boards and the administration host" grep -q 'elements = { 192.0.2.11, 192.0.2.12, 192.0.2.13, 203.0.113.5 }' <<<"$dry"
check "firewall.sh: the client set holds the administration host alone" bash -c 'grep -A3 "set http {" <<<"$1" | grep -q "elements = { 203.0.113.5 }"' _ "$dry"
check "firewall.sh: the Raft port is admitted from its set and the client port from the other" bash -c 'grep -q "tcp dport 4002 ip saddr @raft accept" <<<"$1" && grep -q "tcp dport 4001 ip saddr @http accept" <<<"$1"' _ "$dry"
check "firewall.sh: the chain has the policy accept and ends in a drop of the two ports" bash -c 'grep -q "policy accept;" <<<"$1" && grep -q "tcp dport { 4001, 4002 } counter drop" <<<"$1"' _ "$dry"
check "firewall.sh: the loopback interface is admitted" grep -q 'iifname "lo" accept' <<<"$dry"
check "firewall.sh: no default deny: the only drop is the one of the two ports" bash -c 'test "$(grep -c " drop$" <<<"$1")" = 1 && ! grep -q "policy drop" <<<"$1"' _ "$dry"
check "firewall.sh: the dry run names the one board it would change, and the dead-man time" bash -c 'grep -q "firewall.sh apply on 192.0.2.12 (peers: 192.0.2.11 192.0.2.12 192.0.2.13)" <<<"$1" && grep -q "waits 300 s" <<<"$1"' _ "$dry"
check "firewall.sh: the dry run shows the command of the dead-man timer, armed before the rules are loaded" bash -c 'grep -q "arm the dead-man timer, before the rules are loaded" <<<"$1" && grep -q "delete table inet sluis_rqlite" <<<"$1"' _ "$dry"
check "firewall.sh: the unit is ordered before rqlited and the network, and is not Required by it" bash -c 'grep -q "^Before=network-pre.target rqlited.service" <<<"$1" && ! grep -q "^Requires=\|^RequiredBy=\|^WantedBy=rqlited" <<<"$1"' _ "$dry"
check "firewall.sh: the unit follows nftables.service, whose stop flushes the whole ruleset (PartOf, ReloadPropagatedFrom), and is ordered after it" bash -c 'grep -qx "PartOf=nftables.service" <<<"$1" && grep -qx "ReloadPropagatedFrom=nftables.service" <<<"$1" && grep -E "^After=" <<<"$1" | grep -q "nftables.service"' _ "$dry"
if command -v systemd-analyze >/dev/null 2>&1; then
	# The unit and a copy of the unit of Debian's nftables package (ExecStop=nft flush ruleset), checked together: no ordering cycle.
	mkdir -p "$work/units"
	sed -n '/^\[Unit\]$/,$p' <<<"$(sed -n '/^--- \/etc\/systemd\/system\//,/^--- on each/p' <<<"$dry" | sed '1d;$d')" >"$work/units/sluis-rqlite-firewall.service"
	printf '[Unit]\nDescription=nftables\nWants=network-pre.target\nBefore=network-pre.target shutdown.target\nConflicts=shutdown.target\nDefaultDependencies=no\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\nExecReload=/bin/true\nExecStop=/bin/true\n' >"$work/units/nftables.service"
	vout=$(systemd-analyze verify "$work/units/nftables.service" "$work/units/sluis-rqlite-firewall.service" 2>&1 || true)
	check "firewall.sh: systemd-analyze finds no ordering cycle between the unit and nftables.service" bash -c '! grep -qiE "cycle|loop|ordering" <<<"$1"' _ "$vout"
	check "firewall.sh: and no error in the unit" bash -c '! grep -i "sluis-rqlite-firewall.service" <<<"$1" | grep -qiE "unknown|invalid|failed|error"' _ "$vout"
else
	echo "skip systemd-analyze: not installed (the unit was not checked together with nftables.service)"
fi
none=$(fw apply SLUIS_BOARDS_DRY_RUN=1 SLUIS_FIREWALL_ADMIN_HOST=)
check "firewall.sh: with no administration host the plan says plainly that it gets no access" grep -q 'NO administration host is set (SLUIS_FIREWALL_ADMIN_HOST is empty): it gets NO access' <<<"$none"
check "firewall.sh: and the Raft set holds the boards only" grep -q 'elements = { 192.0.2.11, 192.0.2.12, 192.0.2.13 }' <<<"$none"
check "firewall.sh: and the client set is empty: nobody but the loopback interface reaches 4001" bash -c 'grep -A3 "set http {" <<<"$1" | grep -q "elements" && exit 1; grep -q "set http {" <<<"$1"' _ "$none"
nobody=$(fw apply SLUIS_BOARDS_DRY_RUN=1 SLUIS_FIREWALL_BOARDS=)
check "firewall.sh: a dry run with no board named says that a real run needs exactly one" grep -q 'a real run needs exactly one in SLUIS_FIREWALL_BOARDS' <<<"$nobody"
unset_admin=$(env -u SLUIS_FIREWALL_ADMIN_HOST SLUIS_BOARDS="$FW3" SLUIS_BOARDS_DRY_RUN=1 "$here/firewall.sh" apply)
check "firewall.sh: an unset administration host is the same as an empty one" grep -q 'it gets NO access' <<<"$unset_admin"
dup=$(fw apply SLUIS_BOARDS_DRY_RUN=1 SLUIS_FIREWALL_ADMIN_HOST=192.0.2.13)
check "firewall.sh: an administration host that is also a board is listed once" grep -q 'elements = { 192.0.2.11, 192.0.2.12, 192.0.2.13 }' <<<"$dup"
ports=$(fw apply SLUIS_BOARDS_DRY_RUN=1 SLUIS_RQLITE_PORT_HTTP=5001 SLUIS_RQLITE_PORT_RAFT=5002)
check "firewall.sh: the ports of the rqlite settings are the ports of the rules" grep -q 'tcp dport { 5001, 5002 } counter drop' <<<"$ports"
check "firewall.sh: the file of the dry run has nothing a public repository must not hold (only documentation addresses)" bash -c '! grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" <<<"$1" | grep -vE "(192\.0\.2|198\.51\.100|203\.0\.113)\.[0-9]+" | grep -q .' _ "$dry"

fwrefuse "a board that is not an IPv4 address is refused" 'not an IPv4 address' apply SLUIS_BOARDS="192.0.2.11 board.example.com"
fwrefuse "a board listed twice is refused" 'listed twice' apply SLUIS_BOARDS="192.0.2.11 192.0.2.12 192.0.2.11"
fwrefuse "a board to change that is not among the peers is refused, with the reason" 'not in SLUIS_BOARDS' apply SLUIS_FIREWALL_BOARDS=192.0.2.99
fwrefuse "an administration host that is not an address is refused" 'SLUIS_FIREWALL_ADMIN_HOST' apply SLUIS_FIREWALL_ADMIN_HOST=admin.example.com
fwrefuse "an administration host with a leading zero is refused" 'SLUIS_FIREWALL_ADMIN_HOST' apply SLUIS_FIREWALL_ADMIN_HOST=203.0.113.05
for secs in 59 3601 abc 0 -5; do fwrefuse "a dead-man time of '$secs' is refused" 'from 60 to 3600' apply SLUIS_FIREWALL_CONFIRM_SECONDS="$secs"; done
fwrefuse "equal ports are refused" 'different numbers' apply SLUIS_RQLITE_PORT_HTTP=4002
fwrefuse "an outside host that is a board is refused" 'it cannot show that a stranger is refused' check SLUIS_FIREWALL_OUTSIDE_HOST=192.0.2.12
fwrefuse "an outside host that is the administration host is refused" 'it cannot show that a stranger is refused' check SLUIS_FIREWALL_OUTSIDE_HOST=203.0.113.5
for m in apply confirm reboot-check; do
	fwrefuse "$m with no board named is refused: it changes one board at a time" 'changes one board at a time: name it in SLUIS_FIREWALL_BOARDS' $m SLUIS_FIREWALL_BOARDS=
	fwrefuse "$m with two boards named is refused" 'changes one board at a time, and SLUIS_FIREWALL_BOARDS names 2' $m SLUIS_FIREWALL_BOARDS="192.0.2.11 192.0.2.12"
	fwrefuse "$m with all three boards named is refused" 'names 3' $m SLUIS_FIREWALL_BOARDS="$FW3"
done
fwrefuse "SLUIS_BOARDS with two boards and no size is refused: a short list drops the Raft traffic of the board left out" 'lists 2 board(s), and the installation has three' apply SLUIS_BOARDS="192.0.2.11 192.0.2.12"
fwrefuse "SLUIS_BOARDS with one board and no size is refused" 'lists 1 board(s)' apply SLUIS_BOARDS="192.0.2.12"
fwrefuse "a cluster size that is not the number of boards listed is refused" 'must be the same number' apply SLUIS_FIREWALL_CLUSTER_SIZE=2
fwrefuse "a cluster size of zero is refused" 'must be the same number' apply SLUIS_FIREWALL_CLUSTER_SIZE=0
for o in "-p 4002" "-p4002" "-o Port=4001" "-oPort=4002" "-o port=4001"; do
	fwrefuse "an ssh port of the options ($o) that is an rqlite port is refused" 'is the port of ssh' apply SLUIS_BOARD_SSH_OPTIONS="$o"
done
fwrefuse "an rqlite port of 22 is refused" 'is the port of ssh' apply SLUIS_RQLITE_PORT_HTTP=22
fwrefuse "an rqlite port of 22 for Raft is refused" 'is the port of ssh' apply SLUIS_RQLITE_PORT_RAFT=22
check "firewall.sh: a cluster that really has two boards is allowed when it says so" bash -c 'SLUIS_BOARDS_DRY_RUN=1 SLUIS_BOARDS="192.0.2.11 192.0.2.12" SLUIS_FIREWALL_CLUSTER_SIZE=2 SLUIS_FIREWALL_BOARDS=192.0.2.11 SLUIS_BOARD_SSH_USER=operator "$1/firewall.sh" apply | grep -q "elements = { 192.0.2.11, 192.0.2.12 }"' _ "$here"
check "firewall.sh: remove and check take several boards, and all of them by default" bash -c 'SLUIS_BOARDS_DRY_RUN=1 SLUIS_BOARDS="$1" SLUIS_BOARD_SSH_USER=operator "$2/firewall.sh" check | grep -q "check on 192.0.2.11 192.0.2.12 192.0.2.13"' _ "$FW3" "$here"
fwrefuse "an unknown mode is refused" 'usage: firewall.sh' frobnicate
newlog
SLUIS_BOARDS="$FW3" SLUIS_BOARD_SSH_USER='' "$here/firewall.sh" apply >/dev/null 2>"$work/err" && bad "firewall.sh: no ssh user is refused" || check "firewall.sh: no ssh user is refused" grep -q SLUIS_BOARD_SSH_USER "$work/err"

# The rules against nft -c, where nft can be asked, and against packets, where a network namespace can be made. A namespace is made
# with unshare -rn (no privilege), or sudo -n unshare -n where the system forbids that to a user. Neither touches this machine's network.
nsrun() { if unshare -rn true 2>/dev/null; then unshare -rn "$@"; elif sudo -n true 2>/dev/null; then sudo -n env "PATH=$PATH" unshare -n "$@"; else return 125; fi; }
fw_rules() { # admin [http raft]: the rules for the three boards, to stdout
	(
		# shellcheck source=/dev/null
		. "$here/remote-lib.sh"
		# shellcheck source=/dev/null
		. "$here/firewall-lib.sh"
		firewall_ruleset "${2:-4001}" "${3:-4002}" "$1" 192.0.2.11 192.0.2.12 192.0.2.13
	)
}
if command -v nft >/dev/null 2>&1 && nsrun true 2>/dev/null; then
	fw_rules 203.0.113.5 >"$work/rules.nft"
	check "nft -c accepts the rules with an administration host" nsrun nft -c -f "$work/rules.nft"
	fw_rules "" >"$work/rules-none.nft"
	check "nft -c accepts the rules with no administration host" nsrun nft -c -f "$work/rules-none.nft"
	fw_rules 203.0.113.5 5001 5002 >"$work/rules-ports.nft"
	check "nft -c accepts the rules with other ports" nsrun nft -c -f "$work/rules-ports.nft"
	printf 'table inet sluis_rqlite {\n\tchain input {\n\t\ttcp dport { 4001, 4002 } ip saddr @nowhere drop\n\t}\n}\n' >"$work/rules-bad.nft"
	if nsrun nft -c -f "$work/rules-bad.nft" 2>/dev/null; then bad "nft -c does refuse a broken file"; else ok "nft -c does refuse a broken file (so the checks above are not empty)"; fi
	# Loading twice replaces the table and leaves one: the file is its own undo.
	check "the rules load twice, and one table is left (the file replaces the table)" nsrun bash -c 'nft -f "$1" && nft -f "$1" && test "$(nft list tables | grep -c sluis_rqlite)" = 1' _ "$work/rules.nft"
	# The board compares the whole table with the one it kept, as nft lists it (firewall_listing, remote-lib.sh), so that a deleted drop
	# rule, a changed priority or a flushed chain is not "kept". Real nft output, in a namespace: it is the same after a reload, it
	# has the hook, the loopback accept and the drop, and each change of the table makes it differ.
	cat >"$work/listing-check.sh" <<'LS'
#!/bin/bash
set -uo pipefail
here=$1 rules=$2 rules_none=$3
. "$here/remote-lib.sh"
firewall_nft=$(command -v nft)
nft -f "$rules" || { echo "load"; exit 1; }
a=$(firewall_listing)
firewall_structure_ok "$a" || { echo "structure of the listing: $a"; exit 1; }
[ "$(firewall_loaded_elements raft)" = "192.0.2.11 192.0.2.12 192.0.2.13 203.0.113.5" ] || { echo "raft elements: $(firewall_loaded_elements raft)"; exit 1; }
[ "$(firewall_loaded_elements http)" = "203.0.113.5" ] || { echo "http elements: $(firewall_loaded_elements http)"; exit 1; }
nft -f "$rules"
[ "$(firewall_listing)" = "$a" ] || { echo "a reload changed the listing"; exit 1; }
for m in '/counter drop/d' 's/priority -10/priority 10/' '/iifname/d' 's/hook input/hook forward/' 's/policy accept/policy drop/' 's/192.0.2.13, 203/192.0.2.99, 203/' '/tcp dport 4001/d'; do
	sed "$m" "$rules" >"$rules.mut"
	nft -f "$rules.mut" || { echo "load of the change $m"; exit 1; }
	c=$(firewall_listing)
	[ "$c" != "$a" ] || { echo "the change $m did not change the listing"; exit 1; }
done
nft -f "$rules"
nft flush chain inet sluis_rqlite input
c=$(firewall_listing)
[ "$c" != "$a" ] && ! firewall_structure_ok "$c" || { echo "a flushed chain was not seen"; exit 1; }
nft -f "$rules_none"
[ -z "$(firewall_loaded_elements http)" ] || { echo "an empty client set lists elements"; exit 1; }
firewall_structure_ok "$(firewall_listing)" || { echo "structure with no administration host"; exit 1; }
echo fine
LS
	out=$(nsrun bash "$work/listing-check.sh" "$here" "$work/rules.nft" "$work/rules-none.nft" 2>&1) && [ "$out" = fine ] && ok "the board's listing of the table: stable across a reload, sane, and different after each change of the table" || bad "the board's listing of the table: $out"
else
	echo "skip nft -c: no nft, or no way to make a network namespace here (the rules were not checked by nft)"
fi
if command -v nft >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 && command -v nsenter >/dev/null 2>&1 && nsrun true 2>/dev/null; then
	cat >"$work/ns-check.sh" <<'NS'
#!/bin/bash
# Runs in a network namespace of its own (the board). Two more namespaces are the peer 192.0.2.12 and a stranger 198.51.100.2 that
# also holds the administration host's address 203.0.113.5. The board listens on 4001, 4002 and 4003. Prints "name=open|closed".
set -euo pipefail
rules=$1 mode=$2
ip link set lo up
unshare -n sleep 120 & peer=$!
unshare -n sleep 120 & out=$!
srv=
trap 'kill $peer $out $srv 2>/dev/null || true' EXIT
sleep 0.3
ip link add vp type veth peer name vp1; ip link set vp1 netns $peer
ip link add vo type veth peer name vo1; ip link set vo1 netns $out
ip addr add 192.0.2.11/24 dev vp; ip link set vp up
ip addr add 198.51.100.1/24 dev vo; ip link set vo up
ip route add 203.0.113.5/32 dev vo
nsenter -t $peer -n bash -c 'ip link set lo up; ip addr add 192.0.2.12/24 dev vp1; ip link set vp1 up'
nsenter -t $out -n bash -c 'ip link set lo up; ip addr add 198.51.100.2/24 dev vo1; ip addr add 203.0.113.5/32 dev vo1; ip link set vo1 up'
python3 -I - <<'PY' &
import socket, threading, time
def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", port)); s.listen(8)
    while True:
        c, _ = s.accept(); c.close()
for p in (4001, 4002, 4003):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
time.sleep(60)
PY
srv=$!
sleep 0.5
probe() { # pid-or-self source destination port
    local prefix=()
    [ "$1" = self ] || prefix=(nsenter -t "$1" -n)
    "${prefix[@]}" python3 -I -c '
import socket, sys
s = socket.socket(); s.settimeout(1.5)
try:
    s.bind((sys.argv[1], 0)); s.connect((sys.argv[2], int(sys.argv[3]))); print("open")
except Exception:
    print("closed")
' "$2" "$3" "$4"
}
case "$mode" in
earlier-accept) # another table, earlier in the hook, accepts the ports: it must not undo our drop
    nft -f - <<'R'
table inet other {
	chain input {
		type filter hook input priority -50; policy accept;
		tcp dport { 4001, 4002 } accept
	}
}
R
    ;;
later-drop) # another firewall, later in the hook, with a default deny that admits nothing: our accept must not open anything
    nft -f - <<'R'
table inet other {
	chain input {
		type filter hook input priority 10; policy drop;
	}
}
R
    ;;
esac
nft -f "$rules"
for port in 4001 4002 4003; do
    echo "peer-$port=$(probe $peer 192.0.2.12 192.0.2.11 $port)"
    echo "admin-$port=$(probe $out 203.0.113.5 198.51.100.1 $port)"
    echo "stranger-$port=$(probe $out 198.51.100.2 198.51.100.1 $port)"
    echo "self-$port=$(probe self 192.0.2.11 192.0.2.11 $port)"
    echo "self-other-address-$port=$(probe self 198.51.100.1 198.51.100.1 $port)"
done
NS
	chmod +x "$work/ns-check.sh"
	nsresult() { # rules mode: the lines the namespace printed
		nsrun bash "$work/ns-check.sh" "$1" "$2" 2>"$work/ns.err" || { echo "ns-check failed: $(cat "$work/ns.err")" >&2; return 1; }
	}
	nsall() { # the expected answers for the rules with an administration host: the Raft port to the peer and the administration host,
		# the client port to the administration host and the loopback interface alone, nothing to a stranger
		local out=$1
		grep -qx "peer-4002=open" <<<"$out" && grep -qx "peer-4001=closed" <<<"$out" \
			&& grep -qx "admin-4001=open" <<<"$out" && grep -qx "admin-4002=open" <<<"$out" \
			&& grep -qx "stranger-4001=closed" <<<"$out" && grep -qx "stranger-4002=closed" <<<"$out" \
			&& grep -qx "self-4001=open" <<<"$out" && grep -qx "self-4002=open" <<<"$out" \
			&& grep -qx "self-other-address-4001=open" <<<"$out" && grep -qx "self-other-address-4002=open" <<<"$out" \
			&& grep -qx "stranger-4003=open" <<<"$out" && grep -qx "peer-4003=open" <<<"$out"
	}
	if res=$(nsresult "$work/rules.nft" plain); then
		check "packets: the Raft port answers the peer, the administration host and the board itself; the client port the administration host and the board itself, not the peer; a stranger gets neither" nsall "$res"
		check "packets: and another port (4003) answers to the stranger as before: only the two ports are touched" grep -qx 'stranger-4003=open' <<<"$res"
	else bad "packets: the namespace test failed to run"; fi
	if res=$(nsresult "$work/rules.nft" earlier-accept); then
		check "packets: an accept of the two ports in another table, earlier in the hook, does not undo the drop (a drop is final)" nsall "$res"
	else bad "packets: the namespace test (earlier accept) failed to run"; fi
	if res=$(nsresult "$work/rules.nft" later-drop); then
		check "packets: a default deny in another table, later in the hook, still closes the ports to the peer (the rules open nothing)" grep -qx 'peer-4001=closed' <<<"$res"
		check "packets: and the rules do not stop that table from closing the other port either" grep -qx 'stranger-4003=closed' <<<"$res"
	else bad "packets: the namespace test (later drop) failed to run"; fi
	if res=$(nsresult "$work/rules-none.nft" plain); then
		check "packets: with no administration host the board's address for it is a stranger like any other" bash -c 'grep -qx "admin-4001=closed" <<<"$1" && grep -qx "admin-4002=closed" <<<"$1" && grep -qx "peer-4002=open" <<<"$1" && grep -qx "peer-4001=closed" <<<"$1" && grep -qx "self-4001=open" <<<"$1"' _ "$res"
	else bad "packets: the namespace test (no administration host) failed to run"; fi
else
	echo "skip packets: no nft, python3, nsenter or network namespace here (the rules were not tried against packets)"
fi

# apply: what is sent, to which boards, and what is refused before anything is sent to a board.
healthy() { FAKE_NODES="$nodes3" FAKE_STATUS="$status3" "$@"; }
newlog
healthy fw apply SLUIS_FIREWALL_BOARDS=192.0.2.12 >"$work/out" 2>"$work/err" || bad "firewall.sh apply: $(cat "$work/err")"
check "firewall.sh apply: only the board named is touched (every ssh goes to it)" bash -c '! grep -E "^arg: operator@" "$1" | grep -vq "operator@192.0.2.12$"' _ "$FAKE_SSH_LOG"
check "firewall.sh apply: the board runs the apply as root with its address, all the peers, the administration host and the time" bash -c 'f=$(grep -lF "firewall-apply" "$1".cmd.* | head -n 1); for w in "sudo -n env FW_SSH_CLIENT=" "SSH_CONNECTION%% *" "$2"; do grep -qF -- "$w" "$f" || exit 1; done' _ "$FAKE_SSH_LOG" "'FW_SELF=192.0.2.12' 'FW_PEERS=192.0.2.11 192.0.2.12 192.0.2.13' 'FW_ADMIN=203.0.113.5' 'FW_SECONDS=300'"
rules_call=$(fw_calls 'firewall/rqlite-firewall.nft' | head -n 1)
check "firewall.sh apply: the rules that reach the board are the rules of the dry run" cmp -s <(printf '%s\n' "$want_rules") "${FAKE_SSH_LOG}.in.${rules_call##*.cmd.}"
check "firewall.sh apply: it says what to do next, and by when" grep -q 'within 300 s: SLUIS_FIREWALL_BOARDS=192.0.2.12 just boards-firewall-confirm' "$work/out"
check "firewall.sh apply: and the options of the run reach every ssh" bash -c 'for f in "$1".args.*; do tr "\0" "\n" <"$f" | grep -qx "UserKnownHostsFile=$2/known_hosts" || exit 1; done' _ "$FAKE_SSH_LOG" "$work"
check "firewall.sh apply: it does not confirm by itself" test -z "$(fw_calls ' firewall-confirm ')"
newlog
FAKE_NODES="$nodes3" FAKE_STATUS="$status3" fw apply SLUIS_FIREWALL_BOARDS=192.0.2.11 SLUIS_FIREWALL_ADMIN_HOST= >"$work/out" 2>&1
check "firewall.sh apply: with no administration host the board is told so (FW_ADMIN is empty)" test -n "$(fw_calls "'FW_ADMIN=' 'FW_SECONDS=300'")"
# A cluster that has a node the rules would drop is refused before anything is sent: too few boards in SLUIS_BOARDS, or a board that
# joined after the list was written.
newlog
nodes4=$(jq -c '. + {"192.0.2.14:4002": {"voter": true, "reachable": true, "leader": false}}' <<<"$nodes3")
if FAKE_NODES="$nodes4" FAKE_STATUS="$status3" fw apply SLUIS_FIREWALL_BOARDS=192.0.2.11 >"$work/out" 2>"$work/err"; then bad "firewall.sh apply: a cluster with a node that SLUIS_BOARDS lacks is refused"; else check "firewall.sh apply: a cluster with a node that SLUIS_BOARDS lacks is refused, naming it" grep -q 'lists a node at 192.0.2.14, which the rules would drop' "$work/err"; fi
check "firewall.sh apply: and the board was sent nothing to apply" test -z "$(fw_calls 'firewall-apply')"
newlog
if FAKE_NODES="$nodes3" FAKE_HTTP_STATUS="503 Service Unavailable" fw apply >"$work/out" 2>"$work/err"; then bad "firewall.sh apply: a node whose /nodes cannot be read is refused"; else check "firewall.sh apply: a node whose /nodes cannot be read is refused, not warned about" grep -q 'does not answer /nodes' "$work/err"; fi
check "firewall.sh apply: and the board was sent nothing to apply" test -z "$(fw_calls 'firewall-apply')"
newlog
if FAKE_NODES="{}" FAKE_STATUS="$status3" fw apply >"$work/out" 2>"$work/err"; then bad "firewall.sh apply: an answer that lists no node is refused"; else check "firewall.sh apply: an answer that lists no node is refused" grep -q 'lists no node' "$work/err"; fi
check "firewall.sh apply: and the board was sent nothing to apply" test -z "$(fw_calls 'firewall-apply')"
newlog
if FAKE_NODES="$nodes3" FAKE_STATUS="$status3" fw apply SLUIS_BOARDS=192.0.2.11 SLUIS_FIREWALL_BOARDS=192.0.2.11 SLUIS_FIREWALL_CLUSTER_SIZE=1 >"$work/out" 2>"$work/err"; then bad "firewall.sh apply: a run that names one board as the only peer is refused"; else check "firewall.sh apply: a run that names one board as the only peer is refused (the others would be cut off)" grep -q 'lists a node at 192.0.2.12, which the rules would drop' "$work/err"; fi
newlog
if healthy fw apply SLUIS_FIREWALL_BOARDS=192.0.2.12 FAKE_FW_APPLY_RC=1 >"$work/out" 2>"$work/err"; then bad "firewall.sh apply: a board that refuses fails the run"; else check "firewall.sh apply: a board that refuses fails the run, and the next board is not tried" grep -q "the apply on '192.0.2.12' failed" "$work/err"; fi

# confirm: the proof comes first, and a failed proof sends no confirm to the board.
confirm_ran() { test -n "$(fw_calls ' firewall-confirm ')"; }
newlog
healthy fw confirm SLUIS_FIREWALL_BOARDS=192.0.2.12 FAKE_FW_STATE=unconfirmed >"$work/out" 2>"$work/err" || bad "firewall.sh confirm: a good proof is confirmed: $(cat "$work/err")"
check "firewall.sh confirm: each of the two other boards is asked to reach the Raft port of the board and to time out on its client port" test "$(probe_calls 192.0.2.11 192.0.2.12 4001)$(probe_calls 192.0.2.11 192.0.2.12 4002)$(probe_calls 192.0.2.13 192.0.2.12 4001)$(probe_calls 192.0.2.13 192.0.2.12 4002)" = 1111
check "firewall.sh confirm: the peers' client port is expected to time out" grep -q 'board 192.0.2.11 -> 192.0.2.12:4001 is timeout' "$work/out"
check "firewall.sh confirm: and the Raft port to be open" grep -q 'board 192.0.2.11 -> 192.0.2.12:4002 is open' "$work/out"
check "firewall.sh confirm: the board is told to keep the rules" confirm_ran
check "firewall.sh confirm: and the administration host was tried from this workstation" grep -q 'this workstation (the administration host 203.0.113.5) -> 192.0.2.12:4001 is open' "$work/out"
for c in "a peer cannot reach the Raft port|192.0.2.11>192.0.2.12:4002=124" "a peer is refused, not dropped, on the client port|192.0.2.13>192.0.2.12:4001=1" "a peer reaches the client port, which it needs not|192.0.2.11>192.0.2.12:4001=0" "the administration host cannot reach the client port|local>192.0.2.12:4001=124"; do
	newlog
	if healthy fw confirm SLUIS_FIREWALL_BOARDS=192.0.2.12 FAKE_FW_STATE=unconfirmed FAKE_PROBE_MAP="${c#*|} $closed_http" >"$work/out" 2>"$work/err"; then bad "firewall.sh confirm: ${c%%|*}: not confirmed"; else check "firewall.sh confirm: ${c%%|*}: not confirmed, and the timer is left to run" grep -q 'NOT confirmed on 192.0.2.12' "$work/err"; fi
	if confirm_ran; then bad "firewall.sh confirm: ${c%%|*}: the board was told to keep the rules"; else ok "firewall.sh confirm: ${c%%|*}: and the board was not told to keep anything"; fi
done
newlog
nodes_no_leader=$(jq -c 'map_values(.leader = false)' <<<"$nodes3")
if FAKE_NODES="$nodes_no_leader" FAKE_STATUS="$status3" fw confirm SLUIS_FIREWALL_BOARDS=192.0.2.12 >"$work/out" 2>"$work/err"; then bad "firewall.sh confirm: a cluster without a leader is not confirmed"; else ok "firewall.sh confirm: a cluster without a leader is not confirmed"; fi
newlog
nodes_two=$(jq -c 'del(."192.0.2.13:4002")' <<<"$nodes3")
if FAKE_NODES="$nodes_two" FAKE_STATUS="$status3" fw confirm SLUIS_FIREWALL_BOARDS=192.0.2.12 >"$work/out" 2>"$work/err"; then bad "firewall.sh confirm: a cluster of two voters is not confirmed"; else check "firewall.sh confirm: a cluster of two voters (three boards) is not confirmed" grep -q 'does not hold 3 voters' "$work/err"; fi
newlog
nodes_unreach=$(jq -c '."192.0.2.13:4002".reachable = false' <<<"$nodes3")
if FAKE_NODES="$nodes_unreach" FAKE_STATUS="$status3" fw confirm SLUIS_FIREWALL_BOARDS=192.0.2.12 >"$work/out" 2>"$work/err"; then bad "firewall.sh confirm: a peer that is not reachable is not confirmed"; else ok "firewall.sh confirm: a node that is not reachable in /nodes is not confirmed"; fi
newlog
if healthy fw confirm SLUIS_FIREWALL_BOARDS=192.0.2.12 FAKE_FW_STATE=absent >"$work/out" 2>"$work/err"; then bad "firewall.sh confirm: rules that are not loaded are not confirmed"; else check "firewall.sh confirm: rules that are not loaded (the timer ran) are not confirmed, with the way on" grep -q 'dead-man timer may have run' "$work/err"; fi
newlog
healthy fw confirm SLUIS_FIREWALL_BOARDS=192.0.2.12 SLUIS_FIREWALL_ADMIN_HOST= FAKE_FW_STATE=unconfirmed >"$work/out" 2>&1 || true
check "firewall.sh confirm: with no administration host this workstation is not tried" grep -q 'no administration host is set, so this workstation is not admitted' "$work/out"
newlog
if healthy fw confirm SLUIS_FIREWALL_BOARDS=192.0.2.12 FAKE_FW_STATE=unconfirmed FAKE_FW_CONFIRM_RC=1 >"$work/out" 2>"$work/err"; then bad "firewall.sh confirm: a board that refuses to keep the rules fails the run"; else check "firewall.sh confirm: a board that refuses to keep the rules fails the run, and the timer is said to be armed" grep -q 'dead-man timer is still armed' "$work/err"; fi

# remove: every named board, idempotently.
newlog
healthy fw remove SLUIS_FIREWALL_BOARDS="192.0.2.11 192.0.2.13" >/dev/null 2>&1
check "firewall.sh remove: the boards named are asked to remove the rules, and no other" test "$(fw_calls ' firewall-remove ' | wc -l)" = 2

# check: the closed half needs a host that is not admitted, and the drop counter of the table must have risen while it tried.
out_closed="198.51.100.77>192.0.2.12:4001=124 198.51.100.77>192.0.2.12:4002=124 $closed_http"
local_closed="local>192.0.2.12:4001=124 local>192.0.2.12:4002=124 $closed_http"
newlog
healthy fw check SLUIS_FIREWALL_OUTSIDE_HOST=198.51.100.77 FAKE_PROBE_MAP="$out_closed" >"$work/out" 2>"$work/err" && ok "firewall.sh check: rules kept, a whole cluster, peers and the administration host reach the ports, an outside host times out" || bad "firewall.sh check: $(cat "$work/err")"
check "firewall.sh check: the peers are asked for the Raft port and the timeout on the client port" grep -q 'board 192.0.2.11 -> 192.0.2.12:4001 is timeout' "$work/out"
check "firewall.sh check: the drop counter of the table rose while the outside host tried" grep -q 'drop counter of the table on 192.0.2.12 rose from' "$work/out"
check "firewall.sh check: it does not change a board (no apply, confirm or remove)" test -z "$(fw_calls ' firewall-apply ')$(fw_calls ' firewall-confirm ')$(fw_calls ' firewall-remove ')"
newlog
if healthy fw check SLUIS_FIREWALL_OUTSIDE_HOST=198.51.100.77 FAKE_FW_DROPS_STEP=0 FAKE_PROBE_MAP="$out_closed" >"$work/out" 2>"$work/err"; then bad "firewall.sh check: a timeout while the drop counter does not rise fails the check"; else check "firewall.sh check: a timeout while the drop counter does not rise (another firewall's drop) fails the check" grep -q 'drop counter of the table on 192.0.2.12 did not rise' "$work/err"; fi
newlog
if healthy fw check SLUIS_FIREWALL_OUTSIDE_HOST=198.51.100.77 FAKE_PROBE_MAP="198.51.100.77>192.0.2.12:4001=0 $out_closed" >"$work/out" 2>"$work/err"; then bad "firewall.sh check: an outside host that reaches a port fails the check"; else check "firewall.sh check: an outside host that reaches a port fails the check" grep -q 'outside host -> 192.0.2.12:4001 is open, want timeout' "$work/err"; fi
newlog
if healthy fw check SLUIS_FIREWALL_OUTSIDE_HOST=198.51.100.77 FAKE_PROBE_MAP="198.51.100.77>192.0.2.12:4001=1 $out_closed" >"$work/out" 2>"$work/err"; then bad "firewall.sh check: a refused connection is not a drop"; else check "firewall.sh check: a refused connection (not a drop) fails the check: it is not this table that refused it" grep -q 'is refused, want timeout' "$work/err"; fi
newlog
if healthy fw check >"$work/out" 2>"$work/err"; then bad "firewall.sh check: with an administration host and no outside host the closed half is not proven"; else check "firewall.sh check: with an administration host and no outside host the closed half is NOT PROVEN and the check fails" grep -q 'not proven' "$work/err"; fi
newlog
healthy fw check SLUIS_FIREWALL_ADMIN_HOST= FAKE_FW_RAFT="192.0.2.11 192.0.2.12 192.0.2.13" FAKE_FW_HTTP= FAKE_PROBE_MAP="$local_closed" >"$work/out" 2>"$work/err" && ok "firewall.sh check: with no administration host this workstation is the stranger, and it times out on both ports" || bad "firewall.sh check (no admin): $(cat "$work/err")"
check "firewall.sh check: with no administration host it proves the first half of the plan: the workstation is dropped" grep -q 'this workstation (not admitted) -> 192.0.2.12:4002 is timeout' "$work/out"
newlog
if healthy fw check SLUIS_FIREWALL_OUTSIDE_HOST=198.51.100.77 FAKE_FW_STATE=unconfirmed FAKE_PROBE_MAP="$out_closed" >"$work/out" 2>"$work/err"; then bad "firewall.sh check: rules that are loaded and not kept fail the check"; else check "firewall.sh check: rules that are loaded and not kept fail the check" grep -q "the rules on 192.0.2.12 are 'unconfirmed', not ok" "$work/err"; fi
newlog
healthy fw check SLUIS_FIREWALL_BOARDS="192.0.2.11 192.0.2.13" SLUIS_FIREWALL_OUTSIDE_HOST=198.51.100.77 FAKE_PROBE_MAP="198.51.100.77>192.0.2.11:4001=124 198.51.100.77>192.0.2.11:4002=124 198.51.100.77>192.0.2.13:4001=124 198.51.100.77>192.0.2.13:4002=124 $closed_http" >"$work/out" 2>"$work/err" && ok "firewall.sh check: it may take several boards" || bad "firewall.sh check (two boards): $(cat "$work/err")"

# reboot-check: one board, only after the rules are kept; it comes back with a new boot, the rules, the order and a whole cluster.
export FAKE_BOOT_FILE="$work/bootid"
echo boot-a >"$FAKE_BOOT_FILE"
newlog
reb=(SLUIS_FIREWALL_BOARDS=192.0.2.12 SLUIS_FIREWALL_OUTSIDE_HOST=198.51.100.77 SLUIS_FIREWALL_REBOOT_WAIT=5 "FAKE_PROBE_MAP=$out_closed")
healthy fw reboot-check "${reb[@]}" >"$work/out" 2>"$work/err" && ok "firewall.sh reboot-check: a board that comes back with its rules, in order, and a whole cluster passes" || bad "firewall.sh reboot-check: $(cat "$work/err") $(cat "$work/out")"
check "firewall.sh reboot-check: the board was rebooted, once" test "$(fw_calls 'systemctl reboot' | wc -l)" = 1
check "firewall.sh reboot-check: and it was asked whether the rules came before rqlited" test -n "$(fw_calls ' firewall-boot-order ')"
echo boot-a >"$FAKE_BOOT_FILE"
newlog
if healthy fw reboot-check "${reb[@]}" FAKE_FW_STATE=unconfirmed >"$work/out" 2>"$work/err"; then bad "firewall.sh reboot-check: rules that are not kept are not rebooted on"; else check "firewall.sh reboot-check: rules that are not kept are refused before the reboot" grep -q 'a reboot would prove nothing' "$work/err"; fi
check "firewall.sh reboot-check: and the board was not rebooted" test -z "$(fw_calls 'systemctl reboot')"
echo boot-a >"$FAKE_BOOT_FILE"
newlog
if healthy fw reboot-check "${reb[@]}" FAKE_FW_ORDER_RC=1 >"$work/out" 2>"$work/err"; then bad "firewall.sh reboot-check: rules loaded after rqlited started fail"; else check "firewall.sh reboot-check: rules loaded after rqlited started fail" grep -q 'not loaded before rqlited started' "$work/err"; fi

# reboot-check with an administration host and no outside host: the boot half is proven and the stranger half is said to be not run,
# without a failure; check, in the same case, still fails (above). A table without its drop rule and counter fails either way.
echo boot-a >"$FAKE_BOOT_FILE"
newlog
reb_no_outside=(SLUIS_FIREWALL_BOARDS=192.0.2.12 SLUIS_FIREWALL_REBOOT_WAIT=5 "FAKE_PROBE_MAP=$out_closed")
healthy fw reboot-check "${reb_no_outside[@]}" >"$work/out" 2>"$work/err" && ok "firewall.sh reboot-check: with an administration host and no outside host it passes" || bad "firewall.sh reboot-check (no outside host): $(cat "$work/err") $(cat "$work/out")"
check "firewall.sh reboot-check: and it says that the stranger half was NOT RUN, on the board's line and at the end" bash -c 'grep -q "NOT RUN: a host that is not admitted times out" "$1" && grep -q "reboot-check ok, but the stranger half was NOT run" "$2"' _ "$work/err" "$work/out"
check "firewall.sh reboot-check: it did prove the boot and the drop rule" bash -c 'grep -q "the rules came back after the reboot" "$1" && grep -q "the drop rule and its counter are in the table on 192.0.2.12" "$1" && ! grep -q "the drop counter of the table on 192.0.2.12 rose" "$1"' _ "$work/out"
echo boot-a >"$FAKE_BOOT_FILE"
newlog
if healthy fw reboot-check "${reb_no_outside[@]}" FAKE_FW_DROPS= >"$work/out" 2>"$work/err"; then bad "firewall.sh reboot-check: a table without a readable drop counter fails even without a stranger"; else check "firewall.sh reboot-check: a table without a readable drop counter fails even without a stranger" grep -q 'drop counter of the table on 192.0.2.12 cannot be read' "$work/err"; fi
echo boot-a >"$FAKE_BOOT_FILE"
newlog
if healthy fw reboot-check "${reb_no_outside[@]}" FAKE_FW_ORDER_RC=1 >"$work/out" 2>"$work/err"; then bad "firewall.sh reboot-check: no outside host does not excuse rules loaded after rqlited"; else check "firewall.sh reboot-check: no outside host does not excuse rules loaded after rqlited started" grep -q 'not loaded before rqlited started' "$work/err"; fi

# boards.sh status: the board's firewall is one more line, and an absent one fails the run.
newlog
FAKE_NODES="$nodes3" FAKE_STATUS="$status3" SLUIS_FIREWALL_ADMIN_HOST=203.0.113.5 SLUIS_BOARDS=192.0.2.12 FAKE_FW_STATE=ok FAKE_FW_RAFT="192.0.2.12 203.0.113.5" "$here/boards.sh" status >"$work/out" 2>"$work/err" || true
check "status: a board with the rules loaded and kept says so" grep -q 'board 192.0.2.12: rqlite firewall present and kept' "$work/out"
newlog
FAKE_NODES="$nodes3" FAKE_STATUS="$status3" SLUIS_BOARDS=192.0.2.12 FAKE_FW_STATE=absent "$here/boards.sh" status >"$work/out" 2>"$work/err" && bad "status: a board without the rules fails" || check "status: a board without the rules fails, and says what that means" grep -q 'rqlite firewall ABSENT: ports 4001 and 4002 answer to anyone who reaches the board' "$work/err"
newlog
FAKE_NODES="$nodes3" FAKE_STATUS="$status3" SLUIS_BOARDS=192.0.2.12 FAKE_FW_STATE=unconfirmed "$here/boards.sh" status >"$work/out" 2>"$work/err" || true
check "status: rules that are loaded and not kept are named as such" grep -q 'rqlite firewall UNCONFIRMED' "$work/err"
newlog
FAKE_NODES="$nodes3" FAKE_STATUS="$status3" SLUIS_BOARDS=192.0.2.12 FAKE_FW_STATE=ok FAKE_FW_RAFT="192.0.2.12 192.0.2.99" FAKE_FW_HTTP="" "$here/boards.sh" status >"$work/out" 2>"$work/err" && bad "status: rules that admit other addresses than SLUIS_BOARDS and the administration host fail the run" || check "status: rules that admit other addresses than SLUIS_BOARDS and the administration host say so, and fail the run" grep -q "rqlite firewall admits '192.0.2.12 192.0.2.99' on the Raft port and '' on the client port; SLUIS_BOARDS and SLUIS_FIREWALL_ADMIN_HOST say '192.0.2.12' and ''" "$work/err"
newlog
FAKE_NODES="$nodes3" FAKE_STATUS="$status3" SLUIS_BOARDS=192.0.2.12 SLUIS_FIREWALL_ADMIN_HOST=203.0.113.5 FAKE_FW_STATE=ok FAKE_FW_RAFT="192.0.2.12 203.0.113.5" FAKE_FW_HTTP=203.0.113.9 "$here/boards.sh" status >"$work/out" 2>"$work/err" && bad "status: another administration host on the client port fails the run" || ok "status: an administration host on the client port that is not the configured one fails the run"

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
check "no script of the boards calls ssh without board_ssh" bash -c '! grep -nE "^[^#]*\bssh -o" "$1"/boards.sh "$1"/rqlite.sh "$1"/rqlite-lib.sh "$1"/firewall.sh "$1"/firewall-lib.sh' _ "$here"
[ "$fail" = 0 ] || { echo "boards-test: FAILED" >&2; exit 1; }
echo "boards-test: ok"
