#!/usr/bin/env bash
# The rules of the rqlite firewall of the boards, as text (firewall.sh sends them, boards.sh status compares with them, a test
# reads them). Sourced, never run. It needs rqlite_valid_ipv4 and rqlite_valid_port (remote-lib.sh), and prints, from the settings it
# is given, the nftables file and the systemd unit that load it. Nothing here touches a board.
#
# What the rules are (docs/runtimes/bare-metal.md, "The rqlite firewall"):
#   - a table of their own, `inet sluis_rqlite`, with one input chain at priority -10 and the policy accept. The chain has no
#     default deny; it holds a few rules and nothing else:
#       iifname "lo" accept                          the loopback interface: the board's own drivers and probes
#       tcp dport 4002 ip saddr @raft accept         the Raft port: every board (this one included) and the administration host
#       tcp dport 4001 ip saddr @http accept         the client port: the administration host alone (the set is empty without one)
#       tcp dport { 4001, 4002 } drop                every other source, IPv4 and IPv6
#     The boards need no 4001 between them: rqlite 10.6.6 forwards a follower's writes and reads over the Raft port (MEASURED
#     2026-11-07, three nodes in network namespaces with 4001 closed between them; docs/runtimes/bare-metal.md).
#   - `accept` ends this chain only, so it opens nothing that firewalld or ufw closes, and `drop` is final, so no `accept` in
#     another table can undo it. Every other packet runs through this chain untouched.
#   - the file begins with `table`, `delete table` and then the table, which one `nft -f` loads as one transaction: a reload
#     replaces the table with no moment in which it is missing, and a file that nft refuses changes nothing.

firewall_table=sluis_rqlite
firewall_priority=-10
# shellcheck disable=SC2034 # firewall.sh reads it
firewall_unit_name=sluis-rqlite-firewall.service
firewall_rules_path=/etc/sluis/rqlite-firewall.nft
firewall_nft_path=/usr/sbin/nft
firewall_bash_path=/usr/bin/bash

# firewall_allowed admin board...: the addresses the rules admit, one per line, sorted and without duplicates: every board and the
# administration host (an empty admin adds nothing). A board's own address is one of the boards.
firewall_allowed() {
	local admin=$1
	shift
	{
		printf '%s\n' "$@"
		[ -z "$admin" ] || printf '%s\n' "$admin"
	} | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -u
}

# firewall_ruleset http_port raft_port admin board... prints the nftables file. The boards and the administration host (an empty admin:
# none) are admitted on the Raft port; the administration host alone on the client port. It refuses an address that is not an IPv4
# address without leading zeros, a port that is not a port, equal ports, and an empty list of boards.
firewall_ruleset() {
	local http=$1 raft=$2 admin=$3 a elems="" http_elems=""
	shift 3
	if ! rqlite_valid_port "$http" || ! rqlite_valid_port "$raft" || [ "$http" = "$raft" ]; then
		echo "firewall: refusing the ports '$http' '$raft' (two different ports from 1 to 65535)" >&2
		return 1
	fi
	[ "$#" -gt 0 ] || { echo "firewall: refusing an empty list of boards" >&2; return 1; }
	local -a all
	mapfile -t all < <(firewall_allowed "$admin" "$@")
	for a in "${all[@]}"; do
		rqlite_valid_ipv4 "$a" || { echo "firewall: refusing the address '$a' (an IPv4 address without leading zeros)" >&2; return 1; }
		elems="${elems:+$elems, }$a"
	done
	if [ -n "$admin" ]; then
		rqlite_valid_ipv4 "$admin" || { echo "firewall: refusing the address '$admin' (an IPv4 address without leading zeros)" >&2; return 1; }
		http_elems="
		elements = { $admin }"
	fi
	cat <<EOF
# Made by sluis (just boards-firewall). Do not edit: the next run writes it again.
# Admits TCP $raft (rqlite's Raft port) from the loopback interface, the boards and the administration host, and TCP $http (rqlite's
# client port) from the loopback interface and the administration host, and drops both from every other source. The chain has the
# policy accept and no other rule: nothing else of this board is touched.
# There is still no TLS and no authentication on rqlite: this narrows who can reach it, it does not make it safe.
table inet $firewall_table
delete table inet $firewall_table
table inet $firewall_table {
	set raft {
		type ipv4_addr
		elements = { $elems }
	}
	set http {
		type ipv4_addr$http_elems
	}
	chain input {
		type filter hook input priority $firewall_priority; policy accept;
		iifname "lo" accept
		tcp dport $raft ip saddr @raft accept
		tcp dport $http ip saddr @http accept
		tcp dport { $http, $raft } limit rate 6/minute burst 5 packets log prefix "sluis-rqlite-drop: "
		tcp dport { $http, $raft } counter drop
	}
}
EOF
}

# firewall_unit http_port raft_port prints the unit that loads the file at boot. It is ordered before the network comes up
# (network-pre.target, as nftables.service and firewalld.service are) and before rqlited.service, after the other firewalls'
# units so that none of them can flush it, and it does not Require anything and is not Required by anything: a load that fails
# fails this unit alone, the journal says so in one line, and rqlited starts as it would without the unit (fail open).
# PartOf= and ReloadPropagatedFrom= nftables.service: the unit of the nftables package flushes the whole ruleset when it stops (the
# Debian and Ubuntu one has ExecStop=nft flush ruleset, and its configuration file begins with flush ruleset), so a restart of it, or a
# try-restart by the package's upgrade, would remove our table and leave the ports open with nothing to say so. With these lines a
# restart of it restarts this unit after it, and a reload reloads this unit. When nftables.service is not running (the usual case,
# and always with firewalld) neither line does anything: a try-restart of a stopped unit propagates nothing.
firewall_unit() {
	local http=$1 raft=$2
	cat <<EOF
# Made by sluis (just boards-firewall). Do not edit: the next run writes it again.
[Unit]
Description=sluis: admit the rqlite ports $http and $raft from the boards and the administration host only
Documentation=https://sluis.id/runtimes/bare-metal/#the-rqlite-firewall
DefaultDependencies=no
After=local-fs.target nftables.service firewalld.service ufw.service
Before=network-pre.target rqlited.service
Wants=network-pre.target
PartOf=nftables.service
ReloadPropagatedFrom=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$firewall_bash_path -c '$firewall_nft_path -f $firewall_rules_path || { echo "sluis-rqlite-firewall: FAILED to load $firewall_rules_path: the rqlite ports $http and $raft are NOT restricted on this board (rqlited starts anyway)"; exit 1; }'
ExecReload=$firewall_nft_path -f $firewall_rules_path
ExecStop=-$firewall_nft_path delete table inet $firewall_table

[Install]
WantedBy=multi-user.target
EOF
}

# firewall_valid_seconds says whether the argument is a whole number of seconds from 60 to 3600: the time the dead-man timer waits.
firewall_valid_seconds() {
	[[ "$1" =~ ^[1-9][0-9]{1,3}$ ]] && [ "$1" -ge 60 ] && [ "$1" -le 3600 ]
}
