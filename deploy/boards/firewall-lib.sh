#!/usr/bin/env bash
# The rules of the rqlite firewall of the boards, as text (firewall.sh sends them, boards.sh status compares with them, a test
# reads them). Sourced, never run. It needs rqlite_valid_ipv4 and rqlite_valid_port (remote-lib.sh), and prints, from the settings it
# is given, the nftables file and the systemd unit that load it. Nothing here touches a board.
#
# What the rules are (docs/runtimes/bare-metal.md, "The rqlite firewall"):
#   - a table of their own, `inet sluis_rqlite`, with one input chain at priority -10 and the policy accept. The chain has no
#     default deny; it holds three kinds of rule and nothing else:
#       iifname "lo" accept                                  the loopback interface: the board's own drivers and probes
#       tcp dport { 4001, 4002 } ip saddr @allowed accept    the boards (this one included) and the administration host
#       tcp dport { 4001, 4002 } drop                        every other source, IPv4 and IPv6
#   - `accept` ends this chain only, so it opens nothing that firewalld or ufw closes, and `drop` is final, so no `accept` in
#     another table can undo it. Every other packet runs through this chain untouched.
#   - the file begins with `table`, `delete table` and then the table, which one `nft -f` loads as one transaction: a reload
#     replaces the table with no moment in which it is missing, and a file that nft refuses changes nothing.

firewall_table=sluis_rqlite
firewall_priority=-10
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

# firewall_ruleset http_port raft_port address... prints the nftables file. It refuses an address that is not an IPv4 address
# without leading zeros, a port that is not a port, equal ports, and an empty list.
firewall_ruleset() {
	local http=$1 raft=$2 a elems=""
	shift 2
	if ! rqlite_valid_port "$http" || ! rqlite_valid_port "$raft" || [ "$http" = "$raft" ]; then
		echo "firewall: refusing the ports '$http' '$raft' (two different ports from 1 to 65535)" >&2
		return 1
	fi
	[ "$#" -gt 0 ] || { echo "firewall: refusing an empty list of addresses" >&2; return 1; }
	for a in "$@"; do
		rqlite_valid_ipv4 "$a" || { echo "firewall: refusing the address '$a' (an IPv4 address without leading zeros)" >&2; return 1; }
		elems="${elems:+$elems, }$a"
	done
	cat <<EOF
# Made by sluis (just boards-firewall). Do not edit: the next run writes it again.
# Admits TCP $http and $raft (rqlite) from the loopback interface, from the boards and from the administration host, and drops them
# from every other source. The chain has the policy accept and no other rule: nothing else of this board is touched.
# There is still no TLS and no authentication on rqlite: this narrows who can reach it, it does not make it safe.
table inet $firewall_table
delete table inet $firewall_table
table inet $firewall_table {
	set allowed {
		type ipv4_addr
		elements = { $elems }
	}
	chain input {
		type filter hook input priority $firewall_priority; policy accept;
		iifname "lo" accept
		tcp dport { $http, $raft } ip saddr @allowed accept
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
