#!/usr/bin/env bash
# Install rqlite on the boards: `rqlite.sh` (the recipe is `just boards-rqlite`). The sluis store drivers talk to the rqlite node of
# their own board, and rqlite is not part of the units that boards-deploy installs, so this comes first on a fresh board.
#
# What it does, for each board of SLUIS_BOARDS, the bootstrap node first:
#   1. asks the board which package manager it has (apt-get and dpkg: .deb; dnf and rpm: .rpm) and its machine;
#   2. downloads the matching package of the pinned release (rqlite.pins) on this workstation into $SLUIS_BOARDS_STATE/rqlite
#      (default .cache/boards/rqlite), checks its sha256 against the pin, and refuses it if it differs. Upstream publishes no
#      checksum and no signature, so the pin is the whole trust;
#   3. copies the package to the board and installs it with the board's package manager (apt-get install -y ./pkg.deb,
#      dnf install -y ./pkg.rpm). The package makes the user and group rqlite, /var/lib/rqlite and rqlited.service;
#   4. writes the drop-in /etc/systemd/system/rqlited.service.d/10-sluis.conf, which resets ExecStart= and sets
#      -node-id (the board's host name), -http-addr and -raft-addr (the board's address), and, on every node but the bootstrap
#      one, -join with the Raft address of the bootstrap node;
#   5. runs restorecon over rqlite's files where SELinux is on, then enables and starts rqlited.service;
#   6. polls the node's /status and /nodes (read on the board) until it is a ready voter of a cluster with one leader.
#
# The settings come from the environment (the run.env of the build); the repository names no host:
#   SLUIS_BOARDS             space-separated board addresses, IPv4 (required): rqlite binds the address, and its peers dial it
#   SLUIS_BOARD_SSH_USER     the SSH user, with passwordless sudo (required)
#   SLUIS_RQLITE_BOOTSTRAP   the address of the bootstrap node (required): it starts a cluster of one and the others join it. It need
#                            not be in SLUIS_BOARDS (a board that joins later names only itself), but then it must be up already.
#   SLUIS_RQLITE_PORT_HTTP   default 4001, the port the store drivers use
#   SLUIS_RQLITE_PORT_RAFT   default 4002, the port of the Raft traffic, and the one -join takes
#   SLUIS_BOARD_SSH_AUTH_SOCK, SLUIS_BOARD_SSH_OPTIONS   as for boards.sh
#   SLUIS_BOARDS_DRY_RUN=1   print the plan: which package each board would get; no ssh, no download
#
# NO TLS AND NO AUTHENTICATION: this is a test installation (docs/runtimes/bare-metal.md, "rqlite on the boards"). Anyone who reaches
# the two ports can read and write the store. Before any real PIN or key goes through these boards, a firewall rule must admit
# 4001 and 4002 from the peers alone.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
here=deploy/boards

: "${SLUIS_BOARDS:?SLUIS_BOARDS is not set (source the run.env of the build)}"
: "${SLUIS_BOARD_SSH_USER:?SLUIS_BOARD_SSH_USER is not set}"
: "${SLUIS_RQLITE_BOOTSTRAP:?SLUIS_RQLITE_BOOTSTRAP is not set: the address of the node that starts the cluster}"
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

# shellcheck disable=SC2206 # the boards are a space-separated list
boards=($SLUIS_BOARDS)
[ "${#boards[@]}" -gt 0 ] || { echo "rqlite: SLUIS_BOARDS is empty" >&2; exit 2; }
for b in "${boards[@]}" "$SLUIS_RQLITE_BOOTSTRAP"; do
	rqlite_valid_ipv4 "$b" || { echo "rqlite: '$b' is not an IPv4 address; rqlite binds and advertises the address of the board" >&2; exit 2; }
done
if ! rqlite_valid_port "$http_port" || ! rqlite_valid_port "$raft_port"; then
	echo "rqlite: the ports must be numbers from 1 to 65535" >&2
	exit 2
fi

# The bootstrap node goes first, so that the others find a leader to join.
ordered=()
for b in "${boards[@]}"; do [ "$b" != "$SLUIS_RQLITE_BOOTSTRAP" ] || ordered+=("$b"); done
for b in "${boards[@]}"; do [ "$b" = "$SLUIS_RQLITE_BOOTSTRAP" ] || ordered+=("$b"); done

if [ -n "$dry" ]; then
	echo "dry run: rqlite v$rqlite_version, bootstrap node $SLUIS_RQLITE_BOOTSTRAP, ports $http_port (HTTP) and $raft_port (Raft)"
	for b in "${ordered[@]}"; do
		join="-join $SLUIS_RQLITE_BOOTSTRAP:$raft_port"
		[ "$b" != "$SLUIS_RQLITE_BOOTSTRAP" ] || join="(bootstrap: no -join)"
		echo "  board $b: -http-addr $b:$http_port -raft-addr $b:$raft_port $join"
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

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# install_on installs and starts rqlite on one board.
install_on() { # board
	local b=$1 probe family arch name pkg d join=""
	probe=$(board_ssh "$b" "$rqlite_probe_script") || { echo "rqlite: cannot reach the board '$b'" >&2; return 1; }
	read -r family arch <<<"$probe"
	name=$(rqlite_asset "$family" "$arch") || { echo "rqlite: the board '$b' is $family/$arch: no package for it (apt-get with dpkg, or dnf with rpm, on aarch64 or x86_64)" >&2; return 1; }
	echo "== board $b: $family on $arch, package $name"
	pkg=$(rqlite_fetch "$name" "$cache") || return 1
	echo "rqlite: $name verified against its pin"
	d=$(board_ssh "$b" mktemp -d) || return 1
	# Directory 0711 so that the package manager's unprivileged downloader can open the file it is given (apt warns otherwise).
	board_ssh "$b" "chmod 0711 '$d' && mkdir '$d/rqlite'" || return 1
	board_ssh "$b" "cat >'$d/rqlite/$name' && chmod 0644 '$d/rqlite/$name'" <"$pkg" || return 1
	board_ssh "$b" "cat >'$d/remote.sh' && chmod 0755 '$d/remote.sh'" <"$here/remote.sh" || return 1
	board_ssh "$b" "cat >'$d/remote-lib.sh'" <"$here/remote-lib.sh" || return 1
	[ "$b" = "$SLUIS_RQLITE_BOOTSTRAP" ] || join="$SLUIS_RQLITE_BOOTSTRAP:$raft_port"
	local rc=0
	board_ssh "$b" "sudo -n env RQLITE_NODE_IP='$b' RQLITE_HTTP_PORT='$http_port' RQLITE_RAFT_PORT='$raft_port' RQLITE_JOIN='$join' bash '$d/remote.sh' rqlite-install '$d'" || rc=$?
	board_ssh "$b" "rm -rf '$d'" || true
	[ "$rc" = 0 ] || { echo "rqlite: the install on '$b' failed" >&2; return 1; }
	local node
	node=$(board_ssh "$b" uname -n) || return 1
	rqlite_wait "$b" "$b" "$http_port" "$node" 120 || return 1
	echo "board $b: rqlite is ready; $(rqlite_cluster_line "$b" "$b" "$http_port" || echo 'cluster unknown')"
}

rc=0
for b in "${ordered[@]}"; do
	# A node that cannot join has nobody to join: stop at the first failure, which is the bootstrap node when it is in the run.
	install_on "$b" || { rc=1; break; }
done
exit "$rc"
