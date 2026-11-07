#!/usr/bin/env bash
# The peer-only firewall of rqlite on the boards: `firewall.sh apply|confirm|remove|check|reboot-check`. The recipes are
# `just boards-firewall` (apply), `boards-firewall-confirm`, `boards-firewall-remove`, `boards-firewall-check` and
# `boards-firewall-reboot-check`; `just boards-status` shows whether a board has the rules. The design, the reasons and what to do
# when a board cannot be reached are in docs/runtimes/bare-metal.md, "The rqlite firewall".
#
# What it puts on a board: a table of its own, `inet sluis_rqlite`, whose one input chain (policy accept, priority -10) admits TCP
# 4001 and 4002 from the loopback interface, from every board of SLUIS_BOARDS (the board itself included) and from the one
# administration host, and drops them from every other source. It touches no other port, no other table, no firewalld zone and no ufw
# rule. There is still no TLS and no authentication on rqlite: this narrows who can reach it, it does not make it safe.
#
#   apply         per board of SLUIS_FIREWALL_BOARDS, one after the other: checks (nft is there, the board sends to each peer from an
#                 address the rules admit, every node its own rqlite knows is admitted, nft accepts the rules), arms a dead-man
#                 timer, THEN loads the rules. Nothing is kept: the change is gone at the next boot, and the timer takes it back after
#                 SLUIS_FIREWALL_CONFIRM_SECONDS unless it is confirmed.
#   confirm       per board: proves first (ssh works, the board's rqlite is a ready voter of a cluster of all the boards with one
#                 leader, every other board reaches the board's two ports, and the administration host does, if one is set), and only
#                 then keeps the rules: the unit that loads them at boot (ordered before rqlited) is started or reloaded and enabled,
#                 and the timer is stopped. A proof that fails keeps nothing and leaves the timer running.
#   remove        per board: no rules, no unit, no timer, no file. Idempotent.
#   check         the board check of REQ-DEPLOY-046, read only: the rules are kept; the cluster is whole; the other boards and the
#                 administration host reach ports 4001 and 4002; a host that is not a peer does not (it times out).
#   reboot-check  check, after a reboot of ONE board (SLUIS_FIREWALL_BOARDS names it) that comes back with its rules, before rqlited
#                 started, and a whole cluster. A card board comes back locked: give it the PIN after.
#
# The settings come from the environment (the run.env of the build); the repository names no host:
#   SLUIS_BOARDS                   space-separated board addresses, IPv4 (required): ALL the boards, always. They are the peers, so a
#                                  run with one board named here would write rules that cut the others off. To change one board,
#                                  keep all in SLUIS_BOARDS and name that board in SLUIS_FIREWALL_BOARDS
#   SLUIS_BOARD_SSH_USER           the SSH user, with passwordless sudo (required)
#   SLUIS_FIREWALL_ADMIN_HOST      the IPv4 address the boards see the administration host (the machine that runs these recipes) at.
#                                  EMPTY OR UNSET: the administration host gets NO access to ports 4001 and 4002, which is the
#                                  safe default and is said in every plan
#   SLUIS_FIREWALL_BOARDS          the boards to change, a subset of SLUIS_BOARDS (default: all of them). Name one at a time
#   SLUIS_FIREWALL_CONFIRM_SECONDS the dead-man timer, 60 to 3600 (default 300)
#   SLUIS_FIREWALL_OUTSIDE_HOST    for check: a host that is neither a board nor the administration host, reached over ssh with the
#                                  same user, to try the ports from. Unset, an empty SLUIS_FIREWALL_ADMIN_HOST makes this workstation
#                                  the host that is not admitted; with both unset the "closed" half of the check is NOT PROVEN
#   SLUIS_FIREWALL_REBOOT_WAIT     reboot-check: seconds to wait for the board to come back (default 600)
#   SLUIS_FIREWALL_POLL_SECONDS    the step of the waits (default 5; a test sets 0)
#   SLUIS_RQLITE_PORT_HTTP, SLUIS_RQLITE_PORT_RAFT, SLUIS_BOARD_SSH_AUTH_SOCK, SLUIS_BOARD_SSH_OPTIONS   as for rqlite.sh
#   SLUIS_BOARDS_DRY_RUN=1         print the exact rules, the unit and the commands, for any mode; no ssh, no board touched
set -euo pipefail

mode=${1:?usage: firewall.sh apply|confirm|remove|check|reboot-check}
case "$mode" in apply | confirm | remove | check | reboot-check) ;; *) echo "usage: firewall.sh apply|confirm|remove|check|reboot-check" >&2; exit 2 ;; esac
cd "$(git rev-parse --show-toplevel)"
here=deploy/boards

: "${SLUIS_BOARDS:?SLUIS_BOARDS is not set (source the run.env of the build)}"
: "${SLUIS_BOARD_SSH_USER:?SLUIS_BOARD_SSH_USER is not set}"
agent=${SLUIS_BOARD_SSH_AUTH_SOCK:-${SSH_AUTH_SOCK:-}}
dry=${SLUIS_BOARDS_DRY_RUN:-}
http_port=${SLUIS_RQLITE_PORT_HTTP:-4001}
raft_port=${SLUIS_RQLITE_PORT_RAFT:-4002}
admin=${SLUIS_FIREWALL_ADMIN_HOST:-}
secs=${SLUIS_FIREWALL_CONFIRM_SECONDS:-300}
outside=${SLUIS_FIREWALL_OUTSIDE_HOST:-}
reboot_wait=${SLUIS_FIREWALL_REBOOT_WAIT:-600}
poll=${SLUIS_FIREWALL_POLL_SECONDS:-5}

# shellcheck source=deploy/boards/ssh-lib.sh
. "$here/ssh-lib.sh"
# shellcheck source=deploy/boards/rqlite-lib.sh
. "$here/rqlite-lib.sh"
# shellcheck source=deploy/boards/remote-lib.sh
. "$here/remote-lib.sh"
# shellcheck source=deploy/boards/firewall-lib.sh
. "$here/firewall-lib.sh"

die() { echo "firewall: $*" >&2; exit 2; }

# shellcheck disable=SC2206 # the boards are a space-separated list
boards=($SLUIS_BOARDS)
# shellcheck disable=SC2206
targets=(${SLUIS_FIREWALL_BOARDS:-$SLUIS_BOARDS})
[ "${#boards[@]}" -gt 0 ] || die "SLUIS_BOARDS is empty"
declare -A seen=()
for b in "${boards[@]}"; do
	rqlite_valid_ipv4 "$b" || die "'$b' is not an IPv4 address (no leading zeros); the rules are written with the addresses of the boards"
	[ -z "${seen[$b]:-}" ] || die "the board '$b' is listed twice in SLUIS_BOARDS"
	seen[$b]=1
done
declare -A seen_t=()
for b in "${targets[@]}"; do
	[ -n "${seen[$b]:-}" ] || die "the board '$b' of SLUIS_FIREWALL_BOARDS is not in SLUIS_BOARDS: the rules name every board of SLUIS_BOARDS as a peer, so the boards to change are chosen from them"
	[ -z "${seen_t[$b]:-}" ] || die "the board '$b' is listed twice in SLUIS_FIREWALL_BOARDS"
	seen_t[$b]=1
done
[ "${#targets[@]}" -gt 0 ] || die "SLUIS_FIREWALL_BOARDS is empty"
if ! rqlite_valid_port "$http_port" || ! rqlite_valid_port "$raft_port" || [ "$http_port" = "$raft_port" ]; then
	die "the rqlite ports must be two different numbers from 1 to 65535"
fi
if [ -n "$admin" ]; then
	rqlite_valid_ipv4 "$admin" || die "SLUIS_FIREWALL_ADMIN_HOST '$admin' is not an IPv4 address (no leading zeros)"
fi
firewall_valid_seconds "$secs" || die "SLUIS_FIREWALL_CONFIRM_SECONDS must be a number of seconds from 60 to 3600, not '$secs'"
if [ -n "$outside" ]; then
	[[ "$outside" =~ ^[A-Za-z0-9.-]+$ ]] || die "SLUIS_FIREWALL_OUTSIDE_HOST '$outside' is not a host name or address"
	[ -z "${seen[$outside]:-}" ] && [ "$outside" != "$admin" ] || die "SLUIS_FIREWALL_OUTSIDE_HOST is a board or the administration host, which the rules admit: it cannot show that a stranger is refused"
fi
[[ "$reboot_wait" =~ ^[0-9]+$ ]] && [[ "$poll" =~ ^[0-9]+$ ]] || die "SLUIS_FIREWALL_REBOOT_WAIT and SLUIS_FIREWALL_POLL_SECONDS are whole numbers of seconds"
if [ "$mode" = reboot-check ] && [ "${#targets[@]}" -ne 1 ]; then
	die "reboot-check reboots exactly one board: name it in SLUIS_FIREWALL_BOARDS (now ${#targets[@]})"
fi

mapfile -t allowed < <(firewall_allowed "$admin" "${boards[@]}")
ruleset=$(firewall_ruleset "$http_port" "$raft_port" "${allowed[@]}")
unit=$(firewall_unit "$http_port" "$raft_port")
expect=${#boards[@]}

admin_line() {
	if [ -n "$admin" ]; then
		echo "the administration host $admin is admitted (both ports)"
	else
		echo "NO administration host is set (SLUIS_FIREWALL_ADMIN_HOST is empty): it gets NO access to ports $http_port and $raft_port; only the boards are admitted"
	fi
}

if [ -n "$dry" ]; then
	echo "dry run: firewall.sh $mode on ${targets[*]} (peers: ${boards[*]}); no ssh, no board touched"
	echo "  $(admin_line)"
	echo "  the dead-man timer waits ${secs} s"
	case "$mode" in
	apply)
		echo "--- $firewall_rules_path on each board (loaded as a pending change first):"
		printf '%s\n' "$ruleset"
		echo "--- /etc/systemd/system/$firewall_unit_name:"
		printf '%s\n' "$unit"
		echo "--- on each board, as root, in this order (nothing is kept until confirm):"
		echo "  1. refuse unless $firewall_nft_path, systemctl and systemd-run exist, the board owns its address, the board sends to every other board from an address the rules admit, and 'nft -c' accepts the file"
		echo "  2. refuse (before the board, on this workstation) unless every node that the board's own rqlite lists is admitted by the rules"
		echo "  3. write the file as $firewall_rules_path.pending and the unit; the unit is NOT enabled"
		echo "  4. arm the dead-man timer, before the rules are loaded: systemd-run --unit=$firewall_revert --on-active=${secs}s, which after ${secs} s runs, as $firewall_bash_path -c:"
		echo "       $(firewall_revert_script)"
		echo "  5. load the rules: $firewall_nft_path -f $firewall_rules_path.pending (one transaction: the table is replaced, never missing)"
		echo "--- then, to keep them: SLUIS_FIREWALL_BOARDS=<board> just boards-firewall-confirm"
		;;
	confirm)
		echo "  proves, per board, before it keeps anything: ssh; rqlite a ready voter with $expect voters, all reachable, one leader; every other board reaches $http_port and $raft_port of this board$([ -n "$admin" ] && echo "; this workstation reaches them")"
		echo "  then: mv the pending file to $firewall_rules_path, start or reload $firewall_unit_name (the path of a boot), enable it, stop the timer"
		;;
	remove) echo "  per board: stop the timer, disable and stop $firewall_unit_name, delete table inet $firewall_table, remove the files" ;;
	check) echo "  per board: the rules are kept and enabled; the cluster is whole; peers$([ -n "$admin" ] && echo " and the administration host") reach $http_port and $raft_port; a host that is not admitted times out" ;;
	reboot-check) echo "  reboots ${targets[0]}, waits for it, then: rules kept and loaded before rqlited started, the cluster whole, and the check above" ;;
	esac
	exit 0
fi

rqlite_need_jq || exit 1

# run_remote board mode [VAR=value...]: send remote.sh with its library and, for apply, the rules and the unit; run the mode as root.
run_remote() {
	local b=$1 m=$2 d rc=0 w envs=""
	shift 2
	for w in "$@"; do envs="$envs $(shell_quote "$w")"; done
	d=$(board_ssh_n "$b" mktemp -d) || { echo "firewall: cannot reach the board '$b'" >&2; return 1; }
	board_ssh_n "$b" "chmod 0700 '$d' && mkdir '$d/firewall'" || return 1
	board_ssh "$b" "cat >'$d/remote.sh' && chmod 0755 '$d/remote.sh'" <"$here/remote.sh" || return 1
	board_ssh "$b" "cat >'$d/remote-lib.sh'" <"$here/remote-lib.sh" || return 1
	if [ "$m" = firewall-apply ]; then
		board_ssh "$b" "cat >'$d/firewall/rqlite-firewall.nft'" <<<"$ruleset" || return 1
		board_ssh "$b" "cat >'$d/firewall/$firewall_unit_name'" <<<"$unit" || return 1
	fi
	# FW_SSH_CLIENT is read by the shell of the board: the address this session comes from.
	board_ssh_n "$b" "sudo -n env FW_SSH_CLIENT=\"\${SSH_CONNECTION%% *}\"$envs bash '$d/remote.sh' $m '$d'" || rc=$?
	board_ssh_n "$b" "rm -rf '$d'" || true
	return "$rc"
}

probe_word() { # status of the probe
	case "$1" in 0) echo open ;; 124) echo timeout ;; 255) echo unreachable ;; *) echo refused ;; esac
}
# shellcheck disable=SC2016 # the script of bash -c is read by the shell that runs it, with $0 and $1 its own arguments
# probe_from via address port prints open, timeout, refused or unreachable: a TCP connect from the host `via` (a board or the outside
# host, over ssh) or from this workstation (-). A packet that is dropped ends in a timeout, which is what a refused source sees.
probe_from() {
	local rc=0
	if [ "$1" = - ]; then
		timeout 5 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$2" "$3" >/dev/null 2>&1 || rc=$?
	else
		board_ssh_n "$1" "timeout 5 bash -c $(shell_quote 'exec 3<>"/dev/tcp/$0/$1"') $(shell_quote "$2") $(shell_quote "$3")" >/dev/null 2>&1 || rc=$?
	fi
	probe_word "$rc"
}

fw_failed=0
# expect_probe want via_label via address port: print one line and set fw_failed when the word is not the wanted one.
expect_probe() { # want via via_label address port
	local want=$1 via=$2 label=$3 got
	got=$(probe_from "$via" "$4" "$5")
	if [ "$got" = "$want" ]; then
		echo "  ok   $label -> $4:$5 is $got"
	else
		echo "  FAIL $label -> $4:$5 is $got, want $want" >&2
		fw_failed=1
	fi
}

fw_state() { # board: the state line of firewall-status
	{ run_remote "$1" firewall-status 2>/dev/null || true; } | sed -n "s/^${firewall_state_prefix}//p" | tail -n 1
}

# cluster_whole board: the rqlite node of the board is a ready voter and its cluster is whole.
cluster_whole() {
	local b=$1 why
	if ! why=$(rqlite_node_ready "$b" "$b" "$http_port" "$(rqlite_node_id "$b" "$raft_port")" "$raft_port" 2>&1); then
		echo "  FAIL rqlite on $b is not ready: $why" >&2
		return 1
	fi
	if ! rqlite_cluster_healthy "$b" "$b" "$http_port" "$expect"; then
		echo "  FAIL rqlite on $b: /nodes does not hold $expect voters, all reachable, with one leader (${expect} boards are in SLUIS_BOARDS)" >&2
		return 1
	fi
	echo "  ok   rqlite on $b: $(rqlite_cluster_line "$b" "$b" "$http_port" || echo 'cluster unknown')"
}

# peers_reach board: every other board reaches both ports of the board; the administration host does, when one is set.
peers_reach() {
	local b=$1 y p
	for y in "${boards[@]}"; do
		[ "$y" != "$b" ] || continue
		for p in "$http_port" "$raft_port"; do expect_probe open "$y" "board $y" "$b" "$p"; done
	done
	if [ -n "$admin" ]; then
		for p in "$http_port" "$raft_port"; do expect_probe open - "this workstation (the administration host $admin)" "$b" "$p"; done
	else
		echo "  --   no administration host is set, so this workstation is not expected to reach $b:$http_port; it is not tried"
	fi
}

apply_one() {
	local b=$1 nodes id host admitted=" ${allowed[*]} "
	echo "== board $b: apply"
	# Every node that the board's own rqlite lists must be admitted: this is what a run with too few boards in SLUIS_BOARDS, or a
	# cluster that has grown since, would cut off.
	if nodes=$(rqlite_get "$b" "$b" "$http_port" /nodes 2>/dev/null); then
		for id in $(jq -r 'keys[]' <<<"$nodes"); do
			host=${id%:*}
			if [[ "$admitted" != *" $host "* ]]; then
				echo "firewall: the rqlite node on $b lists a node at $host, which the rules would drop. Add the board to SLUIS_BOARDS (all of them, always), or remove the node from the cluster. Nothing was changed." >&2
				return 1
			fi
		done
		if rqlite_cluster_healthy "$b" "$b" "$http_port" "$expect"; then
			echo "firewall: rqlite on $b is whole now ($expect voters, one leader), so a later failure is the rules'"
		else
			echo "firewall: warning: rqlite on $b is not a whole cluster of $expect now; the confirm will not pass until it is" >&2
		fi
	else
		echo "firewall: warning: rqlite does not answer on $b, so the nodes it lists could not be checked against the rules" >&2
	fi
	run_remote "$b" firewall-apply "FW_SELF=$b" "FW_PEERS=${boards[*]}" "FW_ADMIN=$admin" "FW_SECONDS=$secs" || { echo "firewall: the apply on '$b' failed; see above" >&2; return 1; }
	echo "firewall: next, within $secs s: SLUIS_FIREWALL_BOARDS=$b just boards-firewall-confirm (or boards-firewall-remove to take the change back now)"
}

confirm_one() {
	local b=$1 fwst
	echo "== board $b: proof before the rules are kept"
	fw_failed=0
	if ! board_ssh_n "$b" true; then
		echo "  FAIL ssh to $b" >&2
		fw_failed=1
	else
		echo "  ok   ssh to $b"
	fi
	fwst=$(fw_state "$b")
	case "$fwst" in
	unconfirmed | ok) echo "  ok   the rules are loaded on $b ($fwst)" ;;
	*) echo "  FAIL the rules are not loaded on $b (state '${fwst:-unknown}'); the dead-man timer may have run: boards-firewall again" >&2; fw_failed=1 ;;
	esac
	cluster_whole "$b" || fw_failed=1
	peers_reach "$b"
	if [ "$fw_failed" != 0 ]; then
		echo "firewall: NOT confirmed on $b: a proof failed. Nothing is kept, and the dead-man timer takes the rules back by itself; boards-firewall-remove does it now." >&2
		return 1
	fi
	run_remote "$b" firewall-confirm || { echo "firewall: the board refused to keep the rules (above); the dead-man timer is still armed" >&2; return 1; }
}

check_one() {
	local b=$1 fwst p proven=0
	echo "== board $b: check"
	fwst=$(fw_state "$b")
	if [ "$fwst" = ok ]; then echo "  ok   the rules are loaded, kept at boot and enabled on $b"; else echo "  FAIL the rules on $b are '${fwst:-unknown}', not ok" >&2; fw_failed=1; fi
	cluster_whole "$b" || fw_failed=1
	peers_reach "$b"
	# A host that is not admitted: the outside host, or this workstation when no administration host is set.
	if [ -n "$outside" ]; then
		for p in "$http_port" "$raft_port"; do expect_probe timeout "$outside" "outside host" "$b" "$p"; done
		proven=1
	fi
	if [ -z "$admin" ]; then
		for p in "$http_port" "$raft_port"; do expect_probe timeout - "this workstation (not admitted)" "$b" "$p"; done
		proven=1
	fi
	if [ "$proven" = 0 ]; then
		echo "  FAIL not proven: nothing here is a stranger to the rules, so 'a host that is not a peer does not answer' was not tried: set SLUIS_FIREWALL_OUTSIDE_HOST to a host that is neither a board nor the administration host" >&2
		fw_failed=1
	fi
	return "$fw_failed"
}

reboot_one() {
	local b=$1 boot0 boot1="" deadline fwst=""
	echo "== board $b: reboot-check"
	[ "$(fw_state "$b")" = ok ] || { echo "firewall: the rules on $b are not kept (boards-firewall-confirm first); a reboot would prove nothing" >&2; return 1; }
	boot0=$(board_ssh_n "$b" cat /proc/sys/kernel/random/boot_id) || { echo "firewall: cannot read the boot id of $b" >&2; return 1; }
	echo "firewall: rebooting $b (sudo systemctl reboot); waiting up to $reboot_wait s"
	board_ssh_n "$b" "sudo -n systemctl reboot" || true
	deadline=$((SECONDS + reboot_wait))
	while [ "$SECONDS" -lt "$deadline" ]; do
		sleep "$poll"
		boot1=$(board_ssh_n "$b" cat /proc/sys/kernel/random/boot_id 2>/dev/null) || boot1=""
		[ -z "$boot1" ] || [ "$boot1" = "$boot0" ] || break
		boot1=""
	done
	[ -n "$boot1" ] || { echo "firewall: $b did not come back within $reboot_wait s (the serial console is the way in: docs/runtimes/bare-metal.md, The rqlite firewall)" >&2; return 1; }
	echo "  ok   $b is back with a new boot"
	deadline=$((SECONDS + 120))
	while [ "$SECONDS" -lt "$deadline" ]; do
		fwst=$(fw_state "$b")
		[ "$fwst" = ok ] && break
		sleep "$poll"
	done
	if [ "$fwst" = ok ]; then echo "  ok   the rules came back after the reboot"; else echo "  FAIL the rules did not come back: state '${fwst:-unknown}'" >&2; fw_failed=1; fi
	if run_remote "$b" firewall-boot-order; then :; else echo "  FAIL the rules were not loaded before rqlited started" >&2; fw_failed=1; fi
	if ! rqlite_wait "$b" "$b" "$http_port" "$(rqlite_node_id "$b" "$raft_port")" 180 "$raft_port"; then fw_failed=1; fi
	check_one "$b" || true
	return "$fw_failed"
}

rc=0
case "$mode" in
apply) for b in "${targets[@]}"; do apply_one "$b" || { rc=1; break; }; done ;;
confirm) for b in "${targets[@]}"; do confirm_one "$b" || { rc=1; break; }; done ;;
remove) for b in "${targets[@]}"; do echo "== board $b: remove"; run_remote "$b" firewall-remove || { echo "firewall: the remove on '$b' failed" >&2; rc=1; }; done ;;
check) for b in "${targets[@]}"; do fw_failed=0; check_one "$b" || rc=1; done ;;
reboot-check) fw_failed=0; reboot_one "${targets[0]}" || rc=1 ;;
esac
if [ "$rc" = 0 ]; then echo "firewall: $mode ok"; else echo "firewall: $mode FAILED" >&2; fi
exit "$rc"
