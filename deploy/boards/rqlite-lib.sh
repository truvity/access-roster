#!/usr/bin/env bash
# The workstation side of rqlite on the boards (rqlite.sh, boards.sh status): which upstream package a board gets, the check of its
# sha256 against rqlite.pins, and the questions to a node's HTTP API. Sourced, never run. It needs board_ssh (ssh-lib.sh) for the
# questions to a node, and reads:
#   here   the directory of these scripts (rqlite.pins is beside them)

# The release that boards-rqlite installs. Its packages are pinned in rqlite.pins; moving the version means moving the pins.
rqlite_version=10.6.6
rqlite_pins=${rqlite_pins:-${here:-.}/rqlite.pins}
rqlite_release_url=https://github.com/rqlite/rqlite/releases/download/v$rqlite_version

# rqlite_family says which package a board takes, from what its image has: deb (apt-get and dpkg) or rpm (dnf and rpm).
# It is a script for the board, which rqlite.sh sends.
# shellcheck disable=SC2016,SC2034 # the script runs on the board; rqlite.sh uses it
rqlite_probe_script='if command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then f=deb
elif command -v dnf >/dev/null 2>&1 && command -v rpm >/dev/null 2>&1; then f=rpm
else f=unknown; fi
printf "%s %s\n" "$f" "$(uname -m)"'

# rqlite_asset family arch prints the file name of the package for a board of that family and machine, and fails for any other.
rqlite_asset() {
	case "$1:$2" in
	deb:aarch64 | deb:arm64) echo "rqlite_${rqlite_version}_arm64.deb" ;;
	deb:x86_64 | deb:amd64) echo "rqlite_${rqlite_version}_amd64.deb" ;;
	rpm:aarch64 | rpm:arm64) echo "rqlite-${rqlite_version}-1.aarch64.rpm" ;;
	rpm:x86_64 | rpm:amd64) echo "rqlite-${rqlite_version}-1.x86_64.rpm" ;;
	*) return 1 ;;
	esac
}

# rqlite_pin name prints the pinned sha256 of a package file, and fails when the pins file has no line for it.
rqlite_pin() {
	local sum file extra
	[ -r "$rqlite_pins" ] || { echo "rqlite: cannot read $rqlite_pins" >&2; return 1; }
	while read -r sum file extra; do
		case "$sum" in '' | '#'*) continue ;; esac
		[ "$file" = "$1" ] || continue
		[ -z "$extra" ] && [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || { echo "rqlite: the line for $1 in $rqlite_pins is not '<sha256>  <file>'" >&2; return 1; }
		printf '%s\n' "$sum"
		return 0
	done <"$rqlite_pins"
	echo "rqlite: $rqlite_pins pins no sha256 for $1; the version moved without its pins" >&2
	return 1
}

sha256_of() { # file
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -- "$1" | cut -d' ' -f1
	else
		shasum -a 256 -- "$1" | cut -d' ' -f1
	fi
}

# rqlite_verify file name succeeds when the file has the pinned sha256 of the package name. A file with another digest is
# refused, and the message says both.
rqlite_verify() { # file name
	local want got
	want=$(rqlite_pin "$2") || return 1
	got=$(sha256_of "$1")
	if [ "$got" != "$want" ]; then
		echo "rqlite: $2 has the sha256 $got, not the pinned $want: refused" >&2
		return 1
	fi
}

# rqlite_fetch name dir prints the path of the package in dir, downloaded from the release if it is not there, and verified
# against the pin either way: a file that is there and does not verify is removed and fetched again, and a download that does not
# verify is removed and refused. Nothing unverified is left under the name that the board's copy is made from.
rqlite_fetch() { # name dir
	local name=$1 dir=$2 tmp
	rqlite_pin "$name" >/dev/null || return 1
	mkdir -p "$dir"
	if [ -f "$dir/$name" ]; then
		if rqlite_verify "$dir/$name" "$name" 2>/dev/null; then
			printf '%s\n' "$dir/$name"
			return 0
		fi
		rm -f -- "$dir/$name"
	fi
	tmp=$(mktemp "$dir/.$name.XXXXXX")
	if ! curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --output "$tmp" "$rqlite_release_url/$name"; then
		rm -f -- "$tmp"
		echo "rqlite: cannot download $rqlite_release_url/$name" >&2
		return 1
	fi
	if ! rqlite_verify "$tmp" "$name"; then
		rm -f -- "$tmp"
		return 1
	fi
	mv -- "$tmp" "$dir/$name"
	printf '%s\n' "$dir/$name"
}

# rqlite_get board ip port path prints the body of the answer of a node's HTTP API, read on the board itself (bash and /dev/tcp:
# the images carry no curl), and fails when the answer is not a 200. No TLS and no authentication yet (docs/runtimes/bare-metal.md).
rqlite_get() { # board ip port path
	local out
	# ssh joins its arguments into one string that the login shell of the board parses again, so the arguments are quoted for that
	# shell (shell_quote, ssh-lib.sh): a path with count(*) or a ? in it would otherwise be a syntax error or a glob over there.
	out=$(board_ssh "$1" "timeout 15 bash -s -- $(shell_quote "$2") $(shell_quote "$3") $(shell_quote "$4")" <<'REMOTE'
exec 3<>"/dev/tcp/$1/$2" || exit 1
printf 'GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n' "$3" "$1" >&3
cat <&3
REMOTE
	) || return 1
	[[ "$out" == HTTP/1.?\ 200* ]] || return 1
	# The body is what follows the first empty line (the header lines end in CR).
	sed '1,/^\r*$/d' <<<"$out"
}

# rqlite_need_jq refuses, with the fix, a workstation without jq, which every question to a node is read with: without it the
# operator would see "not ready" after the whole wait.
rqlite_need_jq() {
	command -v jq >/dev/null 2>&1 || { echo "rqlite: jq is needed on this workstation to read the answers of the nodes (it is in devbox)" >&2; return 1; }
}

# rqlite_node_id ip raft_port prints the id that rqlite gives a node that is started without -node-id: its Raft address.
rqlite_node_id() { # ip raft_port
	printf '%s:%s\n' "$1" "$2"
}

# rqlite_firewall_hint is the line that follows a node that its peers cannot reach: the usual cause on the boards is the firewall of
# the image, which admits ssh and little else, and the probe of this script runs on the board itself, through the loopback.
rqlite_firewall_hint() { # http_port raft_port
	printf 'the ports %s and %s must be open between the boards (firewalld: firewall-cmd --permanent --add-port=%s/tcp --add-port=%s/tcp && firewall-cmd --reload; ufw: ufw allow from <peer address> to any port %s,%s proto tcp)' "$1" "$2" "$1" "$2" "$1" "$2"
}

# rqlite_node_ready says, with a reason on stderr, whether the node of a board is ready: its store is ready and knows a leader,
# and the node is a reachable voter in /nodes of a cluster with one leader.
rqlite_node_ready() { # board ip port node_id [raft_port]
	local st nodes raft=${5:-4002}
	st=$(rqlite_get "$1" "$2" "$3" /status) || { echo "no answer from /status" >&2; return 1; }
	jq -e --arg id "$4" '.store.ready == true and .store.node_id == $id and ((.store.leader.node_id // "") != "")' >/dev/null <<<"$st" \
		|| { echo "/status: the store is not ready, or knows no leader" >&2; return 1; }
	nodes=$(rqlite_get "$1" "$2" "$3" /nodes) || { echo "no answer from /nodes" >&2; return 1; }
	jq -e --arg id "$4" '(.[$id].reachable == true) and (.[$id].voter == true) and ([.[] | select(.leader == true)] | length == 1)' >/dev/null <<<"$nodes" \
		|| { echo "/nodes: the node is not a reachable voter of a cluster with one leader; $(rqlite_firewall_hint "$3" "$raft")" >&2; return 1; }
}

# rqlite_wait board ip port node_id seconds [raft_port] polls rqlite_node_ready every two seconds until it succeeds or the time is
# up. The time is the clock ($SECONDS), not the number of polls: one poll is up to two ssh probes of 15 s each, so counting polls
# would let "120 s" run for half an hour against a board that drops packets.
rqlite_wait() { # board ip port node_id seconds [raft_port]
	local deadline=$((SECONDS + $5)) why=""
	while :; do
		if why=$(rqlite_node_ready "$1" "$2" "$3" "$4" "${6:-4002}" 2>&1); then return 0; fi
		[ "$SECONDS" -lt "$deadline" ] || { echo "rqlite: the node $4 on $1 is not ready after $5 s: $why" >&2; return 1; }
		sleep 2
	done
}

# rqlite_node_count board ip port prints the number of nodes in /nodes, as the node of that board sees them.
rqlite_node_count() { # board ip port
	local nodes
	nodes=$(rqlite_get "$1" "$2" "$3" /nodes) || return 1
	jq -r 'length' <<<"$nodes"
}

# rqlite_cluster_healthy board ip port n succeeds when the node of that board sees n nodes in /nodes, all voters, all reachable, and
# exactly one leader: the cluster is whole, as that node sees it.
rqlite_cluster_healthy() { # board ip port n
	local nodes
	nodes=$(rqlite_get "$1" "$2" "$3" /nodes) || return 1
	jq -e --argjson n "$4" '(length == $n) and ([.[] | select(.voter == true)] | length == $n) and ([.[] | select(.reachable == true)] | length == $n) and ([.[] | select(.leader == true)] | length == 1)' >/dev/null <<<"$nodes"
}

# rqlite_cluster_line prints one line about the cluster as one node sees it: the nodes and the leader.
rqlite_cluster_line() { # board ip port
	local nodes
	nodes=$(rqlite_get "$1" "$2" "$3" /nodes) || return 1
	jq -r '"\(length) nodes (\([.[] | select(.voter == true)] | length) voters), leader \([.[] | select(.leader == true) | .id] | join(","))"' <<<"$nodes"
}
