#!/usr/bin/env bash
# The peer-only firewall of rqlite on the boards: `firewall.sh apply|confirm|remove|check|reboot-check`. The recipes are
# `just boards-firewall` (apply), `boards-firewall-confirm`, `boards-firewall-remove`, `boards-firewall-check` and
# `boards-firewall-reboot-check`; `just boards-status` shows whether a board has the rules. The design, the reasons and what to do
# when a board cannot be reached are in docs/runtimes/bare-metal.md, "The rqlite firewall".
#
# What it puts on a board: a table of its own, `inet sluis_rqlite`, whose one input chain (policy accept, priority -10) admits TCP
# 4002 (Raft) from the loopback interface, from every board of SLUIS_BOARDS (the board itself included) and from the one
# administration host, and TCP 4001 (the client API) from the loopback interface and the administration host alone, and drops both
# ports from every other source. The boards need no 4001 between them (MEASURED, docs/runtimes/bare-metal.md). It touches no other port, no other table, no firewalld zone and no ufw
# rule. There is still no TLS and no authentication on rqlite: this narrows who can reach it, it does not make it safe.
#
#   apply         ONE board, named in SLUIS_FIREWALL_BOARDS (exactly one is required, so that a wrong assumption cannot cost the
#                 cluster its quorum): checks (nft is there, the board sends to each peer from an
#                 address the rules admit, every node its own rqlite knows is admitted, nft accepts the rules), arms a dead-man
#                 timer, THEN loads the rules. Nothing is kept: the change is gone at the next boot, and the timer takes it back after
#                 SLUIS_FIREWALL_CONFIRM_SECONDS unless it is confirmed.
#   confirm       ONE board: proves first (ssh works, the board's rqlite is a ready voter of a cluster of all the boards with one
#                 leader, every other board reaches the board's Raft port and times out on its client port, and the administration
#                 host reaches both, if one is set), and only then keeps the rules: the unit that loads them at boot (ordered before rqlited) is started or reloaded and enabled,
#                 and the timer is stopped. A proof that fails keeps nothing and leaves the timer running.
#   remove        each board named (default all): no rules, no unit, no timer, no file. Idempotent.
#   check         the board check of REQ-DEPLOY-046, read only, each board named (default all): the rules are kept; the cluster is
#                 whole; the other boards reach the Raft port and the administration host reaches both ports; a host that is not
#                 admitted times out, and the table's drop counter rose while it tried (so it was this table that dropped it).
#   reboot-check  check, after a reboot of ONE board (SLUIS_FIREWALL_BOARDS names it) that comes back with its rules, before rqlited
#                 started, the whole table, the drop rule with its counter, and a whole cluster. Its stranger half (a host that is
#                 not admitted times out) is run when an outside host or an empty administration host gives a stranger; with an
#                 administration host set and no outside host it is reported as NOT RUN and does not fail the reboot-check, while
#                 `check` fails in that case. A card board comes back locked: give it the PIN after.
#
# The settings come from the environment (the run.env of the build); the repository names no host:
#   SLUIS_BOARDS                   space-separated board addresses, IPv4 (required): ALL the boards, always. They are the peers, so a
#                                  run with one board named here would write rules that cut the others off. To change one board,
#                                  keep all in SLUIS_BOARDS and name that board in SLUIS_FIREWALL_BOARDS
#   SLUIS_BOARD_SSH_USER           the SSH user, with passwordless sudo (required)
#   SLUIS_FIREWALL_ADMIN_HOST      the IPv4 address the boards see the administration host (the machine that runs these recipes) at.
#                                  EMPTY OR UNSET: the administration host gets NO access to ports 4001 and 4002, which is the
#                                  safe default and is said in every plan
#   SLUIS_FIREWALL_BOARDS          the board to change: REQUIRED, exactly one, for apply, confirm and reboot-check (a subset of
#                                  SLUIS_BOARDS). remove and check take any number of them, and all of SLUIS_BOARDS by default
#   SLUIS_FIREWALL_CLUSTER_SIZE    unset: SLUIS_BOARDS must list at least three boards. Set to N, equal to the number of boards in
#                                  SLUIS_BOARDS: an installation that really has fewer than three (a cluster of one or two)
#   SLUIS_FIREWALL_CONFIRM_SECONDS the dead-man timer, 60 to 3600 (default 300)
#   SLUIS_FIREWALL_OUTSIDE_HOST    for check: a host that is neither a board nor the administration host, reached over ssh with the
#                                  same user, to try the ports from. Unset, an empty SLUIS_FIREWALL_ADMIN_HOST makes this workstation
#                                  the host that is not admitted; with an administration host set and no outside host the "closed" half is NOT PROVEN:
#                                  `check` fails, `reboot-check` reports it as not run
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
# apply, confirm and reboot-check change exactly one board and must be told which: a default of "all" would load rules on every board
# before the first confirm, and a wrong assumption would then cost the cluster its quorum. remove and check may take several.
one_board=0
case "$mode" in apply | confirm | reboot-check) one_board=1 ;; esac
if [ "$one_board" = 1 ] && [ -z "${SLUIS_FIREWALL_BOARDS:-}" ]; then
	if [ -n "$dry" ]; then
		targets=()
	else
		die "$mode changes one board at a time: name it in SLUIS_FIREWALL_BOARDS (SLUIS_BOARDS stays the list of all the boards, which are the peers)"
	fi
else
	# shellcheck disable=SC2206
	targets=(${SLUIS_FIREWALL_BOARDS:-$SLUIS_BOARDS})
fi
if [ "$one_board" = 1 ] && [ "${#targets[@]}" -gt 1 ]; then
	die "$mode changes one board at a time, and SLUIS_FIREWALL_BOARDS names ${#targets[@]}: ${targets[*]}"
fi
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
if [ "${#targets[@]}" -eq 0 ] && [ -z "$dry" ]; then die "SLUIS_FIREWALL_BOARDS is empty"; fi
# A short list of boards writes rules that drop the Raft traffic of the boards it leaves out. Three is the installation; fewer is
# said on purpose, with the number, and the number must be the number of boards listed.
size=${SLUIS_FIREWALL_CLUSTER_SIZE:-}
if [ -n "$size" ]; then
	{ [[ "$size" =~ ^[1-9][0-9]*$ ]] && [ "$size" -eq "${#boards[@]}" ]; } || die "SLUIS_FIREWALL_CLUSTER_SIZE is '$size' and SLUIS_BOARDS lists ${#boards[@]} board(s): they must be the same number"
elif [ "${#boards[@]}" -lt 3 ]; then
	die "SLUIS_BOARDS lists ${#boards[@]} board(s), and the installation has three: rules written from a short list drop the Raft traffic of the boards left out. If this cluster really has ${#boards[@]}, say so with SLUIS_FIREWALL_CLUSTER_SIZE=${#boards[@]}"
fi
if ! rqlite_valid_port "$http_port" || ! rqlite_valid_port "$raft_port" || [ "$http_port" = "$raft_port" ]; then
	die "the rqlite ports must be two different numbers from 1 to 65535"
fi
# A port of the rules that is the port of ssh would drop the session of every later run. The port is 22 or what the options of the
# run say (-p, -oPort=, -o Port=); the board checks the port of the session it is on as well.
ssh_port=22
for ((i = 0; i < ${#ssh_options[@]}; i++)); do
	t=${ssh_options[i]}
	t=${t,,}
	case "$t" in
	-p) ssh_port=${ssh_options[i + 1]:-22} ;;
	-p[0-9]*) ssh_port=${t#-p} ;;
	-o) v=${ssh_options[i + 1]:-}; v=${v,,}; [[ "$v" != port=* ]] || ssh_port=${v#port=} ;;
	-oport=*) ssh_port=${t#-oport=} ;;
	esac
done
for p in "$http_port" "$raft_port"; do
	if [ "$p" = 22 ] || [ "$p" = "$ssh_port" ]; then die "the rqlite port $p is the port of ssh; rules for it would drop the session of every run"; fi
done
if [ -n "$admin" ]; then
	rqlite_valid_ipv4 "$admin" || die "SLUIS_FIREWALL_ADMIN_HOST '$admin' is not an IPv4 address (no leading zeros)"
fi
firewall_valid_seconds "$secs" || die "SLUIS_FIREWALL_CONFIRM_SECONDS must be a number of seconds from 60 to 3600, not '$secs'"
if [ -n "$outside" ]; then
	[[ "$outside" =~ ^[A-Za-z0-9.-]+$ ]] || die "SLUIS_FIREWALL_OUTSIDE_HOST '$outside' is not a host name or address"
	[ -z "${seen[$outside]:-}" ] && [ "$outside" != "$admin" ] || die "SLUIS_FIREWALL_OUTSIDE_HOST is a board or the administration host, which the rules admit: it cannot show that a stranger is refused"
fi
[[ "$reboot_wait" =~ ^[0-9]+$ ]] && [[ "$poll" =~ ^[0-9]+$ ]] || die "SLUIS_FIREWALL_REBOOT_WAIT and SLUIS_FIREWALL_POLL_SECONDS are whole numbers of seconds"

mapfile -t allowed < <(firewall_allowed "$admin" "${boards[@]}")
ruleset=$(firewall_ruleset "$http_port" "$raft_port" "$admin" "${boards[@]}")
unit=$(firewall_unit "$http_port" "$raft_port")
expect=${#boards[@]}

admin_line() {
	if [ -n "$admin" ]; then
		echo "the administration host $admin is admitted on both ports"
	else
		echo "NO administration host is set (SLUIS_FIREWALL_ADMIN_HOST is empty): it gets NO access to ports $http_port and $raft_port; only the boards are admitted, and only on the Raft port"
	fi
}

if [ -n "$dry" ]; then
	if [ "${#targets[@]}" -gt 0 ]; then
		echo "dry run: firewall.sh $mode on ${targets[*]} (peers: ${boards[*]}); no ssh, no board touched"
	else
		echo "dry run: firewall.sh $mode on no board yet (peers: ${boards[*]}); a real run needs exactly one in SLUIS_FIREWALL_BOARDS; no ssh, no board touched"
	fi
	echo "  $(admin_line)"
	echo "  the dead-man timer waits ${secs} s"
	case "$mode" in
	apply)
		echo "--- $firewall_rules_path on each board (loaded as a pending change first):"
		printf '%s\n' "$ruleset"
		echo "--- /etc/systemd/system/$firewall_unit_name:"
		printf '%s\n' "$unit"
		echo "--- on each board, as root, in this order (nothing is kept until confirm):"
		echo "  1. refuse unless $firewall_nft_path, systemctl and systemd-run exist, neither rqlite port is the port of ssh, the board owns its address, the board sends to every other board from an address the rules admit, and 'nft -c' accepts the file"
		echo "  2. refuse (before the board, on this workstation) unless the board's own rqlite answers /nodes and every node it lists is admitted by the rules"
		echo "  3. write the file as $firewall_rules_path.pending and the unit; the unit is NOT enabled"
		echo "  4. arm the dead-man timer, before the rules are loaded: systemd-run --unit=$firewall_revert --on-active=${secs}s, which after ${secs} s runs, as $firewall_bash_path -c:"
		echo "       $(firewall_revert_script)"
		echo "  5. load the rules: $firewall_nft_path -f $firewall_rules_path.pending (one transaction: the table is replaced, never missing)"
		echo "--- then, to keep them: SLUIS_FIREWALL_BOARDS=<board> just boards-firewall-confirm"
		;;
	confirm)
		echo "  proves, on the board, before it keeps anything: ssh; rqlite a ready voter with $expect voters, all reachable, one leader; every other board reaches $raft_port and times out on $http_port$([ -n "$admin" ] && echo "; this workstation reaches both")"
		echo "  then: mv the pending file to $firewall_rules_path, start or reload $firewall_unit_name (the path of a boot), enable it, stop the timer"
		;;
	remove) echo "  per board: stop the timer, disable and stop $firewall_unit_name, delete table inet $firewall_table, remove the files" ;;
	check) echo "  per board: the rules are kept and enabled and the table is the kept one; the cluster is whole; peers reach $raft_port, times out on $http_port$([ -n "$admin" ] && echo "; the administration host reaches both"); a host that is not admitted times out and the drop counter rises" ;;
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
	# FW_SSH_CLIENT and FW_SSH_PORT are read by the shell of the board: the address this session comes from, and the port of ssh on the
	# board that it is on (the last field of SSH_CONNECTION).
	board_ssh_n "$b" "sudo -n env FW_SSH_CLIENT=\"\${SSH_CONNECTION%% *}\" FW_SSH_PORT=\"\${SSH_CONNECTION##* }\"$envs bash '$d/remote.sh' $m '$d'" || rc=$?
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
fw_stranger_skipped=0
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

# peers_reach board: every other board reaches the Raft port of the board and times out on its client port (rqlite needs no 4001 between
# the boards: docs/runtimes/bare-metal.md, MEASURED); the administration host reaches both ports, when one is set.
peers_reach() {
	local b=$1 y p
	for y in "${boards[@]}"; do
		[ "$y" != "$b" ] || continue
		expect_probe open "$y" "board $y" "$b" "$raft_port"
		expect_probe timeout "$y" "board $y" "$b" "$http_port"
	done
	if [ -n "$admin" ]; then
		for p in "$http_port" "$raft_port"; do expect_probe open - "this workstation (the administration host $admin)" "$b" "$p"; done
	else
		echo "  --   no administration host is set, so this workstation is not admitted and is not expected to reach $b:$http_port or $b:$raft_port; the check tries it as the stranger"
	fi
}

# fw_drops board: the packets the drop rule of the board's table has counted.
fw_drops() {
	{ run_remote "$1" firewall-status 2>/dev/null || true; } | sed -n "s/^${firewall_drops_prefix}//p" | tail -n 1
}

apply_one() {
	local b=$1 nodes id host admitted=" ${allowed[*]} "
	echo "== board $b: apply"
	# Every node that the board's own rqlite lists must be admitted: this is what a run with too few boards in SLUIS_BOARDS, or a
	# cluster that has grown since, would cut off.
	if ! nodes=$(rqlite_get "$b" "$b" "$http_port" /nodes 2>/dev/null); then
		echo "firewall: the rqlite node on $b does not answer /nodes, so it cannot be checked that the rules admit every node of the cluster. Nothing was changed. (boards-firewall comes after boards-rqlite; if rqlite is down, bring it up first.)" >&2
		return 1
	fi
	if ! jq -e 'type == "object" and length > 0' >/dev/null 2>&1 <<<"$nodes"; then
		echo "firewall: the rqlite node on $b answers /nodes with something that lists no node, so it cannot be checked that the rules admit every node of the cluster. Nothing was changed." >&2
		return 1
	fi
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
	run_remote "$b" firewall-apply "FW_SELF=$b" "FW_PEERS=${boards[*]}" "FW_ADMIN=$admin" "FW_SECONDS=$secs" "FW_HTTP=$http_port" "FW_RAFT=$raft_port" || { echo "firewall: the apply on '$b' failed; see above" >&2; return 1; }
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

# check_one board [stranger-optional]: the board check. The stranger half ("a host that is not admitted times out, and this table's drop
# counter rose") needs a host that the rules do not admit. With an administration host set and no outside host there is none, and
# then `check` fails, because it would otherwise report a proof it did not make. The reboot-check passes "stranger-optional": what a
# reboot has to show is the boot (the rules before rqlited, the whole table back, the drop rule with its counter, the cluster
# whole), and the stranger half has its own recipe; it reports that half as not run, in words, and does not fail for it.
check_one() {
	local b=$1 optional=${2:-} fwst p proven=0 d0 d1
	echo "== board $b: check"
	fwst=$(fw_state "$b")
	if [ "$fwst" = ok ]; then echo "  ok   the rules are loaded, kept at boot and enabled on $b"; else echo "  FAIL the rules on $b are '${fwst:-unknown}', not ok" >&2; fw_failed=1; fi
	cluster_whole "$b" || fw_failed=1
	peers_reach "$b"
	# A host that is not admitted: the outside host, or this workstation when no administration host is set. A timeout alone cannot tell
	# this table from another firewall that drops the port anyway (the public zone of firewalld, say), so the drop counter of the table
	# must have risen while the stranger tried.
	d0=$(fw_drops "$b")
	if [ -n "$outside" ]; then
		for p in "$http_port" "$raft_port"; do expect_probe timeout "$outside" "outside host" "$b" "$p"; done
		proven=1
	fi
	if [ -z "$admin" ]; then
		for p in "$http_port" "$raft_port"; do expect_probe timeout - "this workstation (not admitted)" "$b" "$p"; done
		proven=1
	fi
	if [ "$proven" = 1 ]; then
		d1=$(fw_drops "$b")
		if [[ "$d0" =~ ^[0-9]+$ ]] && [[ "$d1" =~ ^[0-9]+$ ]] && [ "$d1" -gt "$d0" ]; then
			echo "  ok   the drop counter of the table on $b rose from $d0 to $d1 while the stranger tried: it was this table that dropped it"
		else
			echo "  FAIL the drop counter of the table on $b did not rise (${d0:-?} before, ${d1:-?} after): the timeout may be another firewall's, not this table's" >&2
			fw_failed=1
		fi
	fi
	if [ "$proven" = 0 ] && [ "$optional" = stranger-optional ]; then
		# The drop rule and its counter are in the table, which the whole-table comparison of the state above already needs; this reads the
		# counter itself, so that a table without the drop rule cannot pass for lack of a stranger.
		if [[ "$d0" =~ ^[0-9]+$ ]]; then
			echo "  ok   the drop rule and its counter are in the table on $b ($d0 packets dropped so far)"
		else
			echo "  FAIL the drop counter of the table on $b cannot be read (${d0:-?}): the drop rule is missing" >&2
			fw_failed=1
		fi
		echo "  --   NOT RUN: a host that is not admitted times out. No outside host exists: the administration host $admin is set and SLUIS_FIREWALL_OUTSIDE_HOST is not. Run boards-firewall-check with an outside host for that half." >&2
		fw_stranger_skipped=1
	elif [ "$proven" = 0 ]; then
		echo "  FAIL not proven: nothing here is a stranger to the rules, so 'a host that is not a peer does not answer' was not tried: set SLUIS_FIREWALL_OUTSIDE_HOST to a host that is neither a board nor the administration host (or run the check before SLUIS_FIREWALL_ADMIN_HOST is set, when this workstation is the stranger)" >&2
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
	check_one "$b" stranger-optional || true
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
if [ "$rc" = 0 ] && [ "$fw_stranger_skipped" = 1 ]; then
	echo "firewall: $mode ok, but the stranger half was NOT run (no outside host): the boot and the table are proven; that a host that is not admitted times out is not. Set SLUIS_FIREWALL_OUTSIDE_HOST and run boards-firewall-check."
elif [ "$rc" = 0 ]; then echo "firewall: $mode ok"; else echo "firewall: $mode FAILED" >&2; fi
exit "$rc"
