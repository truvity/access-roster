#!/usr/bin/env bash
# Put the skeleton on the boards, take it off again, or look at it: `boards.sh deploy|undeploy|status|recipients`.
# The recipes are `just boards-deploy`, `boards-undeploy`, `boards-status` and `boards-recipients`.
#
# The KeyPlan lists the wrapping keys that may receive a wrap of a data key (ADR 0006, "Who may receive a wrap"), and a
# board's software key is made at its first start, so the first deploy is two-phase, as `local.sh up` is:
#   1. just boards-prepare && just boards-deploy      the KeyPlan lists nobody; key@ runs, and no actor has a data key
#   2. just boards-recipients                         runs key@'s check on each board and reads its wrapping key id
#                                                     into $SLUIS_BOARDS_STATE/recipients (default .cache/boards)
#   3. just boards-prepare && just boards-deploy      signs the KeyPlan with those ids and puts it on the boards
# A board that joins later takes the same three steps.
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
#   SLUIS_BOARDS_RECIPIENTS_REPLACE  set to replace a recipients file that holds ids no board gave now (default: refuse)
#   SLUIS_BOARDS_STATE          the directory of the harness state (default .cache/boards); `recipients` writes its file
#                               recipients there and `just boards-prepare` signs the KeyPlan with it
#   SLUIS_RQLITE_PORT_HTTP      the port of the board's rqlite node (default 4001)
#   SLUIS_BOARDS_DRY_RUN=1      stage and print the plan; no ssh, no board touched
#   SLUIS_PURGE_STATE=1         undeploy also removes the state of the units (their keys)
#
# deploy copies only the executables that `just build-arm64` made, with the units, users and directories that go
# with them, then verifies the units and starts them in order. It is idempotent: a second run changes nothing but
# restarts the units. undeploy removes what the board's manifest lists (/etc/sluis/deployed-dev.manifest) and
# nothing else; sluis-rqlite, the user sluis, /opt/sluis/bin/rqlited and /var/lib/sluis are never in it.
set -euo pipefail

mode=${1:?usage: boards.sh deploy|undeploy|status|recipients}
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
recipients)
	# The wrapping key id of each board, from the `check` command of its key@, run with the flags of the unit on the
	# board, as local.sh does (never from the journal, which can hold the id of a key that was purged). Every board
	# must give one. The file is written only then, and only if it drops no board that the file already holds.
	state=${SLUIS_BOARDS_STATE:-.cache/boards}
	if [ -n "$dry" ]; then
		echo "dry run: would run key@'s check on ${boards[*]} and write the wrapping key ids to $state/recipients"
		exit 0
	fi
	: >"$tmp/ids"
	rc=0
	for b in "${boards[@]}"; do
		id=$(board_ssh "$b" "sudo -n bash -s" <<'REMOTE' | sed -n 's/^wrapping key id: //p' | head -1 || true
set -eu
u=sluis-key@dev.service
exec_start=$(systemctl show -p ExecStart --value "$u")
argv=$(printf '%s\n' "$exec_start" | sed -n 's/.*argv\[\]=\(.*\) ; ignore_errors=.*/\1/p' | head -1)
[ -n "$argv" ] || exit 1
# The word split below must not expand a glob in an argument.
set -f
# shellcheck disable=SC2086 # the unit's arguments hold no space
set -- ${argv/ serve / check }
set +f
# The probe runs as a transient unit with the unit's user, group and supplementary groups, which is what reaches the
# sockets; it copies none of the unit's hardening (no sandbox, no syscall filter). That is acceptable for one run of
# `check`, which writes nothing: the same binary runs, as the same user, in a unit that has less restriction.
exec systemd-run --pipe --wait --collect --quiet \
	-p "User=$(systemctl show -p User --value "$u")" -p "Group=$(systemctl show -p Group --value "$u")" \
	-p "SupplementaryGroups=$(systemctl show -p SupplementaryGroups --value "$u")" "$@"
REMOTE
)
		if ! [[ "$id" =~ ^[A-Za-z0-9_-]{43}$ ]]; then
			echo "board $b: key@'s check gave no wrapping key id; is sluis-key@dev running?" >&2
			rc=1
			continue
		fi
		echo "board $b: wrapping key id $id"
		printf '%s\n' "$id" >>"$tmp/ids"
	done
	[ "$rc" = 0 ] || exit "$rc"
	sort -u "$tmp/ids" >"$tmp/ids.sorted"
	if [ -s "$state/recipients" ]; then
		grep '^[^#[:space:]]' "$state/recipients" | sort -u >"$tmp/ids.old" || true
		if [ -n "$(comm -23 "$tmp/ids.old" "$tmp/ids.sorted")" ] && [ -z "${SLUIS_BOARDS_RECIPIENTS_REPLACE:-}" ]; then
			echo "recipients: $state/recipients holds $(comm -23 "$tmp/ids.old" "$tmp/ids.sorted" | wc -l) id(s) that no board in SLUIS_BOARDS gave now (a board left out, or a key that was replaced)." >&2
			echo "recipients: nothing was written. Name every board in SLUIS_BOARDS, or set SLUIS_BOARDS_RECIPIENTS_REPLACE=1 to replace the file." >&2
			exit 1
		fi
	fi
	mkdir -p "$state"
	{ echo "# the wrapping keys of the boards (boards.sh recipients)"; cat "$tmp/ids.sorted"; } >"$state/recipients"
	echo "recipients: $(wc -l <"$tmp/ids.sorted") ids in $state/recipients; run 'just boards-prepare' and 'just boards-deploy' to list them"
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
	echo "usage: boards.sh deploy|undeploy|status|recipients" >&2
	exit 2
	;;
esac
