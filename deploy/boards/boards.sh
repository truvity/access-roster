#!/usr/bin/env bash
# Put the skeleton on the boards, take it off again, or look at it: `boards.sh deploy|undeploy|status`.
# The recipes are `just boards-deploy`, `boards-undeploy` and `boards-status`.
#
# The repository names no host. The boards come from the environment (the run.env of the build):
#   SLUIS_BOARDS                space-separated host names or addresses (required)
#   SLUIS_BOARD_SSH_USER        the SSH user, with passwordless sudo (required)
#   SLUIS_BOARD_SSH_AUTH_SOCK   the agent socket for ssh; SSH_AUTH_SOCK is the fallback. It is set for the ssh
#                               commands only, never exported for the whole script.
#   SLUIS_BOARD_BIN_DIR         must be /opt/sluis/bin if set: the units are generated for it
#   SLUIS_BOARDS_ONLY           space-separated executables to deploy, as they sit in dist/arm64 (actors/store
#                               drivers/key/software ...); default: every executable that was built. The users of
#                               the groups a unit joins come along.
#   SLUIS_BOARDS_SEED           the directory `just boards-prepare` made (default .cache/boards/seed): the signed
#                               config, the bootstrap file and the credentials. deploy installs them under
#                               /etc/sluis, and writes /etc/sluis/rqlite-dev.env with the board's own rqlite address.
#   SLUIS_RQLITE_PORT_HTTP      the port of the board's rqlite node (default 4001)
#   SLUIS_BOARDS_DRY_RUN=1      stage and print the plan; no ssh, no board touched
#   SLUIS_PURGE_STATE=1         undeploy also removes the state of the units (their keys)
#
# deploy copies only the executables that `just build-arm64` made, with the units, users and directories that go
# with them, then verifies the units and starts them in order. It is idempotent: a second run changes nothing but
# restarts the units. undeploy removes what the board's manifest lists (/etc/sluis/deployed-dev.manifest) and
# nothing else; sluis-rqlite, the user sluis, /opt/sluis/bin/rqlited and /var/lib/sluis are never in it.
set -euo pipefail

mode=${1:?usage: boards.sh deploy|undeploy|status}
cd "$(git rev-parse --show-toplevel)"
here=deploy/boards
units=$here/units
dist=dist/arm64

: "${SLUIS_BOARDS:?SLUIS_BOARDS is not set (source the run.env of the build)}"
: "${SLUIS_BOARD_SSH_USER:?SLUIS_BOARD_SSH_USER is not set}"
if [ "${SLUIS_BOARD_BIN_DIR:-/opt/sluis/bin}" != /opt/sluis/bin ]; then
	echo "boards: SLUIS_BOARD_BIN_DIR is ${SLUIS_BOARD_BIN_DIR}, but the units are generated for /opt/sluis/bin" >&2
	exit 2
fi
agent=${SLUIS_BOARD_SSH_AUTH_SOCK:-${SSH_AUTH_SOCK:-}}
dry=${SLUIS_BOARDS_DRY_RUN:-}
seed=${SLUIS_BOARDS_SEED:-.cache/boards/seed}
rqlite_port=${SLUIS_RQLITE_PORT_HTTP:-4001}
only=${SLUIS_BOARDS_ONLY:-}

# shellcheck disable=SC2206 # the boards are a space-separated list
boards=($SLUIS_BOARDS)
[ "${#boards[@]}" -gt 0 ] || { echo "boards: SLUIS_BOARDS is empty" >&2; exit 2; }
for b in "${boards[@]}"; do
	[[ "$b" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "boards: refusing the board name '$b'" >&2; exit 2; }
done

board_ssh() { # board command...
	local b=$1
	shift
	SSH_AUTH_SOCK=$agent ssh -o BatchMode=yes -o ConnectTimeout=10 "$SLUIS_BOARD_SSH_USER@$b" "$@"
}

# stage builds the tree the board receives, from dist/arm64 and deploy/boards/units. Only executables that exist
# are staged, and so only their units; the users of the groups a unit joins come along without their units.
stage() { # dir
	local s=$1 instance template binary user needs stem n
	mkdir -p "$s/files/bin" "$s/files/systemd" "$s/files/sysusers" "$s/files/tmpfiles"
	: >"$s/plan.tsv"
	local -A want=()
	[ -f "$units/index.tsv" ] || { echo "boards: no $units/index.tsv: run 'just units-gen'" >&2; return 1; }
	while IFS=$'\t' read -r instance template _kind binary user _uid needs; do
		[[ "$instance" != '#'* ]] || continue
		[ -f "$dist/$binary" ] || continue
		if [ -n "$only" ]; then
			case " $only " in *" $binary "*) ;; *) continue ;; esac
		fi
		mkdir -p "$s/files/bin/$(dirname "$binary")"
		install -m 0755 "$dist/$binary" "$s/files/bin/$binary"
		cp "$units/$template" "$s/files/systemd/$template"
		printf '%s\t%s\n' "$instance" "$template" >>"$s/plan.tsv"
		want["${user%-dev}"]=1 # the user's stem: a driver with a unit per port (rqlite) has one user
		if [ "$needs" != - ]; then
			IFS=, read -ra ns <<<"$needs"
			for n in "${ns[@]}"; do want["$n"]=1; done
		fi
	done <"$units/index.tsv"
	[ -s "$s/plan.tsv" ] || { echo "boards: no executable in $dist has a unit: run 'just build-arm64' first" >&2; return 1; }
	cp "$units/base.tmpfiles" "$s/files/tmpfiles/sluis-base-dev.conf"
	for stem in "${!want[@]}"; do
		cp "$units/$stem.sysusers" "$s/files/sysusers/$stem-dev.conf"
		[ ! -f "$units/$stem.tmpfiles" ] || cp "$units/$stem.tmpfiles" "$s/files/tmpfiles/$stem-dev.conf"
	done
	install -m 0755 "$here/remote.sh" "$s/remote.sh"
	# The seed: public documents and the credentials, every board alike. The rqlite address is per board and is
	# written by run_on.
	if [ -d "$seed/config" ]; then
		mkdir -p "$s/files/etc"
		cp -r "$seed/config" "$s/files/etc/config"
		cp "$seed/bootstrap.yaml" "$s/files/etc/bootstrap.yaml"
		[ ! -d "$seed/credentials" ] || cp -r "$seed/credentials" "$s/files/etc/credentials"
	else
		echo "boards: no seed in $seed: the units will start without config (run 'just boards-prepare')" >&2
	fi
}

# run_on copies the stage to the board, runs remote.sh as root there and removes the stage.
run_on() { # board mode stage
	local b=$1 m=$2 s=$3 d rc=0
	d=$(board_ssh "$b" mktemp -d)
	if [ "$m" = deploy ] && [ -d "$s/files/etc" ]; then
		# The board's own rqlite node, per D-13 (no TLS, no authentication yet).
		printf 'SLUIS_RQLITE_URL=http://%s:%s\n' "$b" "$rqlite_port" >"$s/files/etc/rqlite.env"
	fi
	tar -C "$s" -cf - . | board_ssh "$b" "tar -xf - -C '$d'"
	board_ssh "$b" "sudo -n env SLUIS_PURGE_STATE='${SLUIS_PURGE_STATE:-}' bash '$d/remote.sh' $m '$d'" || rc=$?
	board_ssh "$b" "rm -rf '$d'"
	return "$rc"
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
case "$mode" in
deploy)
	stage "$tmp"
	echo "plan: $(wc -l <"$tmp/plan.tsv") units, in this order:"
	sed 's/^/  /' "$tmp/plan.tsv" | cut -f1
	if [ -n "$dry" ]; then
		echo "dry run: staged files"
		(cd "$tmp" && find files -type f | sort | sed 's/^/  /')
		exit 0
	fi
	rc=0
	for b in "${boards[@]}"; do
		echo "== board $b: deploy"
		run_on "$b" deploy "$tmp" || { echo "board $b: deploy FAILED" >&2; rc=1; }
	done
	exit "$rc"
	;;
undeploy | status)
	: >"$tmp/plan.tsv"
	mkdir -p "$tmp/files"
	install -m 0755 "$here/remote.sh" "$tmp/remote.sh"
	if [ -n "$dry" ]; then
		echo "dry run: would run remote.sh $mode on ${boards[*]}"
		exit 0
	fi
	rc=0
	for b in "${boards[@]}"; do
		echo "== board $b: $mode"
		run_on "$b" "$mode" "$tmp" || { echo "board $b: $mode FAILED" >&2; rc=1; }
	done
	exit "$rc"
	;;
*)
	echo "usage: boards.sh deploy|undeploy|status" >&2
	exit 2
	;;
esac
