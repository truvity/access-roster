#!/usr/bin/env bash
# Install rqlite on the boards: `rqlite.sh` (the recipe is `just boards-rqlite`). The sluis store drivers talk to the rqlite node of
# their own board, and rqlite is not part of the units that boards-deploy installs, so this comes first on a fresh board.
#
# What it does, for each board of SLUIS_BOARDS:
#   1. asks the board which package manager it has (apt-get and dpkg: .deb; dnf and rpm: .rpm) and its machine;
#   2. downloads the matching package of the pinned release (rqlite.pins) on this workstation into $SLUIS_BOARDS_STATE/rqlite
#      (default .cache/boards/rqlite), checks its sha256 against the pin, and refuses it if it differs. Upstream publishes no
#      checksum and no signature, so the pin is the whole trust;
#   3. copies the package to the board, which checks it against the pin again (sha256sum -c) and installs it with its package
#      manager (apt-get install -y ./pkg.deb, dnf install -y ./pkg.rpm). The package makes the user and group rqlite,
#      /var/lib/rqlite and rqlited.service;
#   4. writes the drop-in /etc/systemd/system/rqlited.service.d/10-sluis.conf, which resets ExecStart= and sets -http-addr and
#      -raft-addr (the board's address) and, for a cluster of more than one node, -bootstrap-expect N and -join with the Raft
#      address of EVERY node, itself included. There is no -node-id: rqlite takes the Raft address, which differs on every board and
#      does not move with a host name;
#   5. runs restorecon over rqlite's files where SELinux is on, then enables and starts rqlited.service.
# Only when every board has its node started does it wait: it polls each node's /status and /nodes (read on the board) until the
# node is a ready voter of a cluster with one leader, and then checks that /nodes holds as many nodes as there are boards.
#
# Why every node has -bootstrap-expect and the whole join list: a node with no state and no -join forms a cluster of one. A board
# that was wiped or reflashed would then start a second cluster at the address of a node of the first, and the other two nodes,
# still a quorum, would elect a leader of their own: two leaders for one membership, and lost writes. With -bootstrap-expect a node
# without state first tries to join a node that is in a cluster, so a wiped board comes back into the cluster of the others, and
# N nodes that start together form one. The recipe starts them one after another and waits afterwards. A node that is started later than
# about two minutes after the first (rqlite's bootstrap-expect timeout) only makes that first node give up and be started again by
# systemd; the cluster still forms when the last node is up. A board that joins
# later is a run with the longer SLUIS_BOARDS: every drop-in is written again, and the nodes that are running restart onto it.
#
# The settings come from the environment (the run.env of the build); the repository names no host:
#   SLUIS_BOARDS             space-separated board addresses, IPv4 (required): ALL the nodes of the cluster. rqlite binds the
#                            address, and its peers dial it
#   SLUIS_BOARD_SSH_USER     the SSH user, with passwordless sudo (required)
#   SLUIS_RQLITE_PORT_HTTP   default 4001, the port the store drivers use
#   SLUIS_RQLITE_PORT_RAFT   default 4002, the port of the Raft traffic, and the one -join takes
#   SLUIS_BOARD_SSH_AUTH_SOCK, SLUIS_BOARD_SSH_OPTIONS   as for boards.sh
#   SLUIS_BOARDS_DRY_RUN=1   print the plan: which package each board would get; no ssh, no download
#   SLUIS_RQLITE_BOOTSTRAP   no longer used (the first node is no longer special); it is ignored, with a warning
#
# NO TLS AND NO AUTHENTICATION: this is a test installation (docs/runtimes/bare-metal.md, "rqlite on the boards"). Anyone who reaches
# the two ports can read and write the store. Before any real PIN or key goes through these boards, a firewall rule must admit
# 4001 and 4002 from the peers alone.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
here=deploy/boards

: "${SLUIS_BOARDS:?SLUIS_BOARDS is not set (source the run.env of the build)}"
: "${SLUIS_BOARD_SSH_USER:?SLUIS_BOARD_SSH_USER is not set}"
agent=${SLUIS_BOARD_SSH_AUTH_SOCK:-${SSH_AUTH_SOCK:-}}
dry=${SLUIS_BOARDS_DRY_RUN:-}
http_port=${SLUIS_RQLITE_PORT_HTTP:-4001}
raft_port=${SLUIS_RQLITE_PORT_RAFT:-4002}
cache=${SLUIS_BOARDS_STATE:-.cache/boards}/rqlite

# shellcheck source=deploy/boards/ssh-lib.sh
. "$here/ssh-lib.sh"
# shellcheck source=deploy/boards/rqlite-lib.sh
. "$here/rqlite-lib.sh"
# shellcheck source=deploy/boards/remote-lib.sh
. "$here/remote-lib.sh"

[ -z "${SLUIS_RQLITE_BOOTSTRAP:-}" ] || echo "rqlite: warning: SLUIS_RQLITE_BOOTSTRAP is ignored: every node now starts with the whole join list (see the head of $here/rqlite.sh)" >&2

# shellcheck disable=SC2206 # the boards are a space-separated list
boards=($SLUIS_BOARDS)
[ "${#boards[@]}" -gt 0 ] || { echo "rqlite: SLUIS_BOARDS is empty" >&2; exit 2; }
declare -A seen=()
joins=""
for b in "${boards[@]}"; do
	rqlite_valid_ipv4 "$b" || { echo "rqlite: '$b' is not an IPv4 address (no leading zeros); rqlite binds and advertises the address of the board" >&2; exit 2; }
	[ -z "${seen[$b]:-}" ] || { echo "rqlite: the board '$b' is listed twice in SLUIS_BOARDS" >&2; exit 2; }
	seen[$b]=1
	joins="${joins:+$joins,}$b:$raft_port"
done
if ! rqlite_valid_port "$http_port" || ! rqlite_valid_port "$raft_port"; then
	echo "rqlite: the ports must be numbers from 1 to 65535" >&2
	exit 2
fi
if [ "$http_port" = "$raft_port" ]; then
	echo "rqlite: the HTTP port and the Raft port must differ (both are $http_port)" >&2
	exit 2
fi
expect=${#boards[@]}
# A cluster of one has nothing to join and nothing to split from: no -bootstrap-expect, no -join.
[ "$expect" -gt 1 ] || joins=""

if [ -n "$dry" ]; then
	echo "dry run: rqlite v$rqlite_version, $expect node(s), ports $http_port (HTTP) and $raft_port (Raft), node ids are the Raft addresses"
	for b in "${boards[@]}"; do
		flags="(a cluster of one: no -bootstrap-expect, no -join)"
		[ "$expect" -eq 1 ] || flags="-bootstrap-expect $expect -join $joins"
		echo "  board $b: -http-addr $b:$http_port -raft-addr $b:$raft_port $flags"
	done
	echo "  packages (each must have a pin in $rqlite_pins):"
	for fam in deb rpm; do
		for arch in aarch64 x86_64; do
			name=$(rqlite_asset "$fam" "$arch")
			echo "    $name $(rqlite_pin "$name")"
		done
	done
	exit 0
fi

rqlite_need_jq || exit 1

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# install_on installs rqlite on one board and starts it. It does not wait: a node of a cluster of more than one is ready only when
# the others are started too.
install_on() { # board
	local b=$1 probe family arch name pkg d sha rc=0
	probe=$(board_ssh_n "$b" "$rqlite_probe_script") || { echo "rqlite: cannot reach the board '$b'" >&2; return 1; }
	read -r family arch <<<"$probe"
	name=$(rqlite_asset "$family" "$arch") || { echo "rqlite: the board '$b' is $family/$arch: no package for it (apt-get with dpkg, or dnf with rpm, on aarch64 or x86_64)" >&2; return 1; }
	echo "== board $b: $family on $arch, package $name"
	pkg=$(rqlite_fetch "$name" "$cache") || return 1
	sha=$(rqlite_pin "$name") || return 1
	echo "rqlite: $name verified against its pin"
	d=$(board_ssh_n "$b" mktemp -d) || return 1
	# Directory 0711 so that the package manager's unprivileged downloader can open the file it is given (apt warns otherwise).
	board_ssh_n "$b" "chmod 0711 '$d' && mkdir '$d/rqlite'" || return 1
	board_ssh "$b" "cat >'$d/rqlite/$name' && chmod 0644 '$d/rqlite/$name'" <"$pkg" || return 1
	board_ssh "$b" "cat >'$d/remote.sh' && chmod 0755 '$d/remote.sh'" <"$here/remote.sh" || return 1
	board_ssh "$b" "cat >'$d/remote-lib.sh'" <"$here/remote-lib.sh" || return 1
	board_ssh_n "$b" "sudo -n env RQLITE_NODE_IP='$b' RQLITE_HTTP_PORT='$http_port' RQLITE_RAFT_PORT='$raft_port' RQLITE_EXPECT='$expect' RQLITE_JOIN='$joins' RQLITE_SHA256='$sha' bash '$d/remote.sh' rqlite-install '$d'" || rc=$?
	board_ssh_n "$b" "rm -rf '$d'" || true
	[ "$rc" = 0 ] || { echo "rqlite: the install on '$b' failed" >&2; return 1; }
}

for b in "${boards[@]}"; do
	# The nodes of a cluster of more than one wait for each other, so a failure stops the run before the next board; the nodes that
	# are already started wait for about two minutes, and systemd starts them again after that (a run after the fix finds them).
	install_on "$b" || { echo "rqlite: stopped at '$b'; the boards before it are started and wait for the others" >&2; exit 1; }
done

rc=0
for b in "${boards[@]}"; do
	rqlite_wait "$b" "$b" "$http_port" "$(rqlite_node_id "$b" "$raft_port")" 120 "$raft_port" || rc=1
done
[ "$rc" = 0 ] || exit 1
# Every node must see the cluster of all the boards: a node that sees fewer is in a cluster of its own or has not joined.
for b in "${boards[@]}"; do
	n=$(rqlite_node_count "$b" "$b" "$http_port") || { echo "rqlite: cannot read /nodes of '$b'" >&2; rc=1; continue; }
	if [ "$n" != "$expect" ]; then
		echo "rqlite: the node on '$b' sees $n node(s) in /nodes, and there are $expect board(s): it is not in the cluster of the others" >&2
		rc=1
	else
		echo "board $b: rqlite is ready; $(rqlite_cluster_line "$b" "$b" "$http_port" || echo 'cluster unknown')"
	fi
done
exit "$rc"
