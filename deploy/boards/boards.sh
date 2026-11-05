#!/usr/bin/env bash
# Put the skeleton on the boards, take it off again, or look at it: `boards.sh deploy|undeploy|status|recipients|check`.
# The recipes are `just boards-deploy`, `boards-undeploy`, `boards-status`, `boards-recipients` and `boards-key-check`.
#
# The KeyPlan lists the wrapping keys that may receive a wrap of a data key (ADR 0006, "Who may receive a wrap"), and a
# board's software key is made at its first start, so the first deploy is two-phase, as `local.sh up` is:
#   1. just boards-prepare && just boards-deploy      the KeyPlan lists nobody; key@ runs, and no actor has a data key
#   2. just boards-recipients                         runs key@'s check on each board and reads its wrapping key id
#                                                     into $SLUIS_BOARDS_STATE/recipients (default .cache/boards)
#   3. just boards-prepare && just boards-deploy      signs the KeyPlan with those ids and puts it on the boards
# A board that joins later takes the same three steps.
#
# Switching the key driver of a board (software to the card, or back) changes its wrapping key, and a data key is wrapped
# only to the keys the signed KeyPlan lists (D-24), so the switch is a rewrap and goes ONE board at a time, with the others
# still on the key they have, because only a node that holds an old wrapping key can wrap the data keys for the new one:
#   1. SLUIS_BOARDS=<board> SLUIS_BOARDS_KEY_DRIVER=yubikey-piv SLUIS_BOARD_CARD_SERIALS=<board>=<serial> just boards-deploy
#      then `sluis node unlock` on that board. Its key@ makes a new wrapping key; it cannot open a data key yet, and the
#      other boards keep serving. The deploy first runs the board's checks, which write nothing (remote.sh preflight), then
#      marks the board as pending verification BEFORE it changes anything on it, and the mark stays whatever the deploy does
#      (a card board starts locked, so the wait for its units may end non-zero). The mark is a file on the board itself,
#      /var/lib/sluis-state/dev/switch-pending (root, mode 0600), so a lost checkout cannot fail the guard open;
#      $SLUIS_BOARDS_STATE/switch-pending is a cache of it for the boards a run does not name. Name every board of the fleet
#      when in doubt: the guard reads the mark of each board the run names.
#   2. SLUIS_BOARDS=<board> SLUIS_BOARDS_RECIPIENTS_SWITCHED=1 just boards-recipients
#      reads the new id and replaces that board's old id, and only that one, in $SLUIS_BOARDS_STATE/recipients.
#   3. just boards-prepare, then just boards-deploy for every board, with SLUIS_BOARDS_KEY_DRIVER UNSET: each board keeps the
#      key driver it runs, so no other board switches. The maintainer's publisher key re-signs the KeyPlan with the new id
#      and the boards load it.
#   4. The other boards' key@ wrap the data keys for the new id. Verify with `SLUIS_BOARDS=<board> just boards-key-check`
#      (key@'s own check: "wrapping key listed: true", and it fails while the wrap set is incomplete). A pass is the only
#      thing that clears the board's mark.
#   5. Only then the next board: a deploy that would switch another board, and a switch-mode `recipients` for another board,
#      are refused while a board is pending.
# Rollback is the same five steps with SLUIS_BOARDS_KEY_DRIVER=software. The software key of a board stays in its state
# directory when the card is taken, so the board comes back with the same id. The wraps for the id that left the KeyPlan stay
# in the store, unused until the id is listed again; this script deletes none (0006 deletes the wraps of a lost recipient
# by a procedure of its own). The signer pre-publishes the new token key of the board for 30 minutes before it signs, so a
# smoke right after the switch says the earliest time at which the key is active.
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
#   SLUIS_BOARDS_RECIPIENTS_SWITCHED set, with SLUIS_BOARDS naming exactly one board, to say that this board switched its key
#                               driver: `recipients` replaces the id that board gave last time (recorded in
#                               $SLUIS_BOARDS_STATE/recipients.boards) with its new one and keeps every other id. Without
#                               it the file is refused when a board's id is gone. Rollback uses it too.
#   SLUIS_BOARDS_STATE          the directory of the harness state (default .cache/boards); `recipients` writes its file
#                               recipients there and `just boards-prepare` signs the KeyPlan with it
#   SLUIS_RQLITE_PORT_HTTP      the port of the board's rqlite node (default 4001)
#   SLUIS_BOARDS_KEY_DRIVER     the key driver of key@ for every board of the run: software or yubikey-piv. UNSET, each board keeps
#                               the key driver it runs now (a board with nothing deployed yet gets software), which is what
#                               the deploys of a rollout other than the switch want. The card driver replaces the software
#                               one on a board that gets it: its unit, a key@ unit that requires the card
#                               driver instead (installed in place of the default template), a drop-in that closes the
#                               card service (pcscd.socket) to everyone but the card driver and root, and, where pcscd
#                               is built with polkit, a polkit rule. pcscd is installed if it is missing. It needs drivers/key/yubikey-piv in
#                               dist/arm64, which `just build-arm64-native` makes and `just build-arm64` copies. Switching back is a deploy
#                               with software: the card driver is stopped and its drop-ins removed. A run that would switch
#                               the key driver of more than one board is refused (see the sequence above): set
#                               SLUIS_BOARDS_NO_DATA_KEYS=1 only for a first deploy where no actor has made a data key yet;
#                               it is not taken on trust: the deploy asks the rqlite node of each switching board (read
#                               only) and refuses when it holds a DataKeyWrap item.
#   SLUIS_BOARD_CARD_SERIALS    with the card driver, the serial of each board's card: space-separated board=serial pairs
#                               (the board named as in SLUIS_BOARDS). Required for every board of the run: the driver is
#                               bound to that card and adopts no other, so a genuine YubiKey that is not the board's is
#                               refused. The serial is written to /etc/sluis/yubikey-piv-dev.env on the board and is in
#                               no file of the repository.
#   SLUIS_BOARDS_DRY_RUN=1      stage and print the plan; no ssh, no board touched
#   SLUIS_PURGE_STATE=1         undeploy also removes the state of the units (their keys)
#
# deploy copies only the executables that `just build-arm64` made, with the units, users and directories that go
# with them, then verifies the units and starts them in order. It is idempotent: a second run changes nothing but
# restarts the units. undeploy removes what the board's manifest lists (/etc/sluis/deployed-dev.manifest) and
# nothing else; sluis-rqlite, the user sluis, /opt/sluis/bin/rqlited and /var/lib/sluis are never in it.
set -euo pipefail

mode=${1:?usage: boards.sh deploy|undeploy|status|recipients|check}
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
keydrv_set=${SLUIS_BOARDS_KEY_DRIVER:-} # unset: every board keeps the key driver it runs now (none yet: software)
keydrv=${keydrv_set:-software}
state=${SLUIS_BOARDS_STATE:-.cache/boards}
case "$keydrv" in
software | yubikey-piv) ;;
*) echo "boards: SLUIS_BOARDS_KEY_DRIVER must be software or yubikey-piv, not '$keydrv'" >&2; exit 2 ;;
esac

# shellcheck disable=SC2206 # the boards are a space-separated list
boards=($SLUIS_BOARDS)
[ "${#boards[@]}" -gt 0 ] || { echo "boards: SLUIS_BOARDS is empty" >&2; exit 2; }
for b in "${boards[@]}"; do
	[[ "$b" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "boards: refusing the board name '$b'" >&2; exit 2; }
done

# card_serial prints the serial of the card of a board, from SLUIS_BOARD_CARD_SERIALS, and fails when there is none.
card_serial() { # board
	local pair
	for pair in ${SLUIS_BOARD_CARD_SERIALS:-}; do
		if [ "${pair%%=*}" = "$1" ] && [[ "${pair#*=}" =~ ^[0-9]{1,10}$ ]]; then
			printf '%s\n' "${pair#*=}"
			return 0
		fi
	done
	echo "boards: no card serial for the board '$1': set SLUIS_BOARD_CARD_SERIALS to board=serial pairs" >&2
	return 1
}

board_ssh() { # board command...
	local b=$1
	shift
	SSH_AUTH_SOCK=$agent ssh -o BatchMode=yes -o ConnectTimeout=10 "$SLUIS_BOARD_SSH_USER@$b" "$@"
}

# seed_has_kind refuses a seed whose documents were signed before the protected header named the kind (signed-config.md,
# "The document"): store@ refuses such a document, so a deploy of these binaries with that seed would leave every board
# without config. It only reads the files of the seed on this machine; nothing runs on a board.
seed_has_kind() {
	command -v jq >/dev/null || { echo "boards: jq is needed to check the seed (it is in devbox)" >&2; return 1; }
	local f n=0
	for f in "$seed"/config/*.jws; do
		[ -e "$f" ] || continue
		n=$((n + 1))
		# The protected header of every signature: base64url of a JSON object that has a "kind" member.
		jq -e '[.signatures[].protected | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | has("kind")] | length > 0 and all' "$f" >/dev/null 2>&1 \
			|| { echo "boards: $(basename "$f") in $seed was signed before the header named its kind: re-sign: just boards-prepare" >&2; return 1; }
	done
	[ "$n" -gt 0 ] || { echo "boards: $seed/config holds no signed document: re-sign: just boards-prepare" >&2; return 1; }
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
		# The two key drivers serve one socket: a board runs the one that was asked for.
		case "$binary" in
		drivers/key/software) [ "$keydrv" = software ] || continue ;;
		drivers/key/yubikey-piv) [ "$keydrv" = yubikey-piv ] || continue ;;
		esac
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
	if [ "$keydrv" = yubikey-piv ]; then
		[ -f "$s/files/systemd/sluis-key@.service" ] || { echo "boards: the card driver needs key@ in the plan (SLUIS_BOARDS_ONLY leaves out actors/key)" >&2; return 1; }
		[ -f "$dist/drivers/key/yubikey-piv" ] || { echo "boards: no $dist/drivers/key/yubikey-piv: run 'just build-arm64-native' and 'just build-arm64' first" >&2; return 1; }
		grep -q '^sluis-drv-key-yubikey-piv@' "$s/plan.tsv" || { echo "boards: SLUIS_BOARDS_ONLY leaves out drivers/key/yubikey-piv" >&2; return 1; }
		mkdir -p "$s/files/card"
		cp "$units/pcscd-socket.dropin" "$units/pcsc-polkit.rules" "$s/files/card/"
		# The group of the card service's socket, held by the card driver alone.
		cp "$units/sluis-pcsc.sysusers" "$s/files/sysusers/sluis-pcsc-dev.conf"
		cp "$units/sluis-key@.service.card" "$s/files/systemd/sluis-key@.service" # key@ after the card driver, in place of the default
	fi
	cp "$units/base.tmpfiles" "$s/files/tmpfiles/sluis-base-dev.conf"
	for stem in "${!want[@]}"; do
		cp "$units/$stem.sysusers" "$s/files/sysusers/$stem-dev.conf"
		[ ! -f "$units/$stem.tmpfiles" ] || cp "$units/$stem.tmpfiles" "$s/files/tmpfiles/$stem-dev.conf"
	done
	install -m 0755 "$here/remote.sh" "$s/remote.sh"
	install -m 0644 "$here/remote-lib.sh" "$s/remote-lib.sh"
	# The seed: public documents and the credentials, every board alike. The rqlite address is per board and is
	# written by run_on.
	if [ -d "$seed/config" ]; then
		seed_has_kind || return 1
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
	if [ "$m" = deploy ] && [ -d "$s/files/card" ]; then
		# The driver is bound to this board's card.
		printf 'SLUIS_CARD_SERIAL=%s\n' "$(card_serial "$b")" >"$s/files/card/yubikey-piv.env"
	fi
	tar -C "$s" -cf - . | board_ssh "$b" "tar -xf - -C '$d'"
	board_ssh "$b" "sudo -n env SLUIS_PURGE_STATE='${SLUIS_PURGE_STATE:-}' bash '$d/remote.sh' $m '$d'" || rc=$?
	board_ssh "$b" "rm -rf '$d'"
	return "$rc"
}

# board_key_driver prints which key driver a board runs now: software, yubikey-piv, or none (neither unit exists: nothing
# deployed yet). Each unit is asked on its own and its LoadState is read, because `systemctl is-enabled A B` stops at the first
# unit that does not exist and prints nothing for the rest on systemd 249 (Ubuntu 22.04), and a software board has no card unit.
board_key_driver() { # board
	local out card sw
	# shellcheck disable=SC2016 # the loop runs on the board
	out=$(board_ssh "$1" 'for u in sluis-drv-key-yubikey-piv@dev.service sluis-drv-key-software@dev.service; do
printf "%s %s %s\n" "$u" "$(systemctl show -p LoadState --value "$u" 2>/dev/null)" "$(systemctl show -p UnitFileState --value "$u" 2>/dev/null)"
done') || {
		echo "boards: cannot read the key driver of the board '$1'" >&2
		return 1
	}
	# One line per unit: name, LoadState (loaded, not-found, masked, error), UnitFileState (empty when the unit does not exist).
	card=$(unit_kind "$out" sluis-drv-key-yubikey-piv@dev.service) || { echo "boards: the board '$1' gave an unreadable state for the card driver unit" >&2; return 1; }
	sw=$(unit_kind "$out" sluis-drv-key-software@dev.service) || { echo "boards: the board '$1' gave an unreadable state for the software driver unit" >&2; return 1; }
	# none only when neither unit exists. A board where neither is enabled but a unit exists (a deploy that stopped half way
	# through a switch), masked, static or erroring units are not a state this script knows, and it goes no further.
	case "$card:$sw" in
	enabled:enabled)
		echo "boards: the board '$1' has both key drivers enabled; fix that first" >&2
		return 1
		;;
	enabled:*) echo yubikey-piv ;;
	*:enabled) echo software ;;
	absent:absent) echo none ;;
	*)
		echo "boards: the board '$1' has no enabled key driver (card: $card, software: $sw): a deploy may have stopped half way through a switch. Deploy the driver it should run, or look at the board, before anything else." >&2
		return 1
		;;
	esac
}

# unit_kind reads the line of one unit in the answer of board_key_driver: enabled, disabled, or absent (LoadState not-found).
# Any other state (masked, error, static, ...) is an error.
unit_kind() { # answer unit
	local line load file
	line=$(printf '%s\n' "$1" | awk -v u="$2" '$1 == u { print $2 " " $3 }')
	load=${line%% *}
	file=${line#* }
	case "$load:$file" in
	loaded:enabled) echo enabled ;;
	loaded:disabled) echo disabled ;;
	not-found:*) echo absent ;;
	*) return 1 ;;
	esac
}

# board_data_keys prints how many DataKeyWrap items the board's rqlite node holds, from a read-only query of its own node, at the
# address the actors use (http://<board>:<port>, as run_on writes it to rqlite.env; the board name resolves on the board) (the
# key of an item is <boundary>/<tenant>/<kind>/<id>). A node whose table does not exist yet holds none. It fails when the
# answer cannot be read: the guard that uses it refuses then.
board_data_keys() { # board
	local out
	out=$(board_ssh "$1" "curl -fsS --get --data-urlencode \"q=SELECT count(*) FROM durable_items WHERE key LIKE '%/data-key-wrap/%'\" http://$1:$rqlite_port/db/query") || return 1
	if printf '%s' "$out" | grep -q 'no such table'; then echo 0; return 0; fi
	printf '%s' "$out" | sed -n 's/.*"values":\[\[\([0-9][0-9]*\)\]\].*/\1/p' | grep -E '^[0-9]+$' || return 1
}

# The mark that a board switched its key driver and has not been verified. The board's own file is the truth:
# /var/lib/sluis-state/dev/switch-pending (root, mode 0600), so that a lost checkout of the operator cannot make the guard fail
# open. $state/switch-pending is a cache of it for the boards a run does not name. The mark is made after the board passed the
# checks of remote.sh preflight, which write nothing, and BEFORE the deploy of the board, and it stays whatever the deploy does
# (a card board starts locked, so a deploy that waits for the units may end non-zero with the new driver enabled); only `check`
# clears it.
pending_file=$state/switch-pending
marker=/var/lib/sluis-state/dev/switch-pending
board_marker_set() { # board
	board_ssh "$1" "sudo -n sh -c 'umask 077; mkdir -p $(dirname "$marker") && date -u +%Y-%m-%dT%H:%M:%SZ >$marker'"
}
board_marker_clear() { # board
	board_ssh "$1" "sudo -n rm -f $marker"
}
board_marker_get() { # board: prints the mark, nothing when there is none; fails when the board cannot be read
	board_ssh "$1" "sudo -n sh -c 'if [ -e $marker ]; then cat $marker; fi'"
}
# pending_has_other prints a board other than the given ones that is pending, from the marks of the boards this run names and
# from the cache of the others, and returns 0 if there is one. A board that cannot be read counts as pending (fail closed).
pending_has_other() { # board...
	local p b skip
	for b in "${boards[@]}"; do
		skip=0
		for p in "$@"; do [ "$b" = "$p" ] && skip=1; done
		[ "$skip" = 0 ] || continue
		if ! m=$(board_marker_get "$b"); then printf '%s\n' "$b"; return 0; fi
		if [ -n "$m" ]; then printf '%s\n' "$b"; return 0; fi
	done
	if [ -s "$pending_file" ]; then
		while read -r p; do
			[ -n "$p" ] || continue
			skip=0
			for b in "$@"; do [ "$b" = "$p" ] && skip=1; done
			[ "$skip" = 1 ] || { printf '%s\n' "$p"; return 0; }
		done <"$pending_file"
	fi
	return 1
}

# key_check runs the `check` command of key@ on a board with the flags of its unit, as local.sh does (never from the
# journal, which can hold the id of a key that was purged). It prints what check printed and exits with its status.
key_check() { # board
	board_ssh "$1" "sudo -n bash -s" <<'REMOTE'
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
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
case "$mode" in
deploy)
	if [ -n "$dry" ]; then
		# Nothing is read from the boards: one stage, of the driver the run names (software if none).
		stage "$tmp/stage"
		if [ -d "$tmp/stage/files/card" ]; then
			for b in "${boards[@]}"; do card_serial "$b" >/dev/null || exit 2; done
		fi
		[ "${#boards[@]}" -lt 2 ] || echo "dry run: the key driver of the boards is not read, so the one-board-at-a-time rule is not checked" >&2
		echo "plan: $(wc -l <"$tmp/stage/plan.tsv") units, in this order:"
		sed 's/^/  /' "$tmp/stage/plan.tsv" | cut -f1
		echo "dry run: staged files"
		(cd "$tmp/stage" && find files -type f | sort | sed 's/^/  /')
		if [ -f "$tmp/stage/files/systemd/sluis-key@.service" ]; then
			echo "key@ unit requires: $(grep -E '^Requires=sluis-drv-key-' "$tmp/stage/files/systemd/sluis-key@.service" | tr '\n' ' ')"
		fi
		exit 0
	fi
	# The key driver of each board now, and the one it gets: SLUIS_BOARDS_KEY_DRIVER for every board, or, when it is unset, the
	# one it runs (a board with nothing deployed yet gets software). A switch changes a board's wrapping key, and only a node that
	# still holds an old one can wrap the data keys for the new one (see the header): one board at a time, and the next only
	# after `check` passed for the last.
	declare -A cur drv
	switching=()
	for b in "${boards[@]}"; do
		cur[$b]=$(board_key_driver "$b") || exit 1
		if [ -n "$keydrv_set" ]; then
			drv[$b]=$keydrv_set
		elif [ "${cur[$b]}" = none ]; then
			drv[$b]=software
		else
			drv[$b]=${cur[$b]}
		fi
		if [ "${cur[$b]}" != none ] && [ "${cur[$b]}" != "${drv[$b]}" ]; then switching+=("$b"); fi
	done
	if [ "${#switching[@]}" -gt 0 ]; then
		if [ -z "${SLUIS_BOARDS_NO_DATA_KEYS:-}" ]; then
			if [ "${#switching[@]}" -gt 1 ]; then
				echo "boards: this run switches the key driver of ${#switching[@]} boards (${switching[*]}). Switch one board at a time:" >&2
				echo "boards: a data key is wrapped only to the keys of the signed KeyPlan, and with every board on a new key no node holds an old one to wrap for the new (see the header)." >&2
				echo "boards: set SLUIS_BOARDS_NO_DATA_KEYS=1 only for a first deploy where no actor has made a data key yet." >&2
				exit 2
			fi
			if other=$(pending_has_other "${switching[@]}"); then
				echo "boards: the board '$other' switched its key driver and has not been verified: run 'just boards-key-check' for it (SLUIS_BOARDS=$other) before another board switches." >&2
				exit 2
			fi
		else
			# The override says no data key exists. Ask each switching board's own store (read only) and refuse if one does.
			for b in "${switching[@]}"; do
				n=$(board_data_keys "$b") || { echo "boards: cannot read the data keys of the board '$b'; SLUIS_BOARDS_NO_DATA_KEYS is not taken on trust" >&2; exit 1; }
				if [ "$n" != 0 ]; then
					echo "boards: SLUIS_BOARDS_NO_DATA_KEYS is set, but the store of '$b' holds $n DataKeyWrap items: this is not a first deploy. Switch one board at a time (see the header)." >&2
					exit 2
				fi
			done
		fi
	fi
	# One stage for each key driver that a board gets.
	for d in $(printf '%s\n' "${drv[@]}" | sort -u); do
		keydrv=$d
		stage "$tmp/stage-$d"
	done
	for b in "${boards[@]}"; do
		if [ "${drv[$b]}" = yubikey-piv ]; then card_serial "$b" >/dev/null || exit 2; fi
	done
	first=$tmp/stage-${drv[${boards[0]}]}
	echo "plan: $(wc -l <"$first/plan.tsv") units, in this order:"
	sed 's/^/  /' "$first/plan.tsv" | cut -f1
	# A switching board is first checked (remote.sh preflight: what its image must carry, and that its pinned uids and gids are
	# free or already its own), which writes nothing, so a board the deploy would refuse is never left marked. Then it is marked
	# pending before anything is changed on it, on the board and in the cache. If the check fails or the mark cannot be made,
	# nothing is deployed.
	for b in "${switching[@]}"; do
		run_on "$b" preflight "$tmp/stage-${drv[$b]}" || { echo "boards: the board '$b' failed the checks before its switch; it is not marked pending and nothing was deployed" >&2; exit 1; }
	done
	for b in "${switching[@]}"; do
		board_marker_set "$b" || { echo "boards: cannot mark the board '$b' as pending; nothing was deployed" >&2; exit 1; }
		mkdir -p "$state"
		grep -qxF "$b" "$pending_file" 2>/dev/null || printf '%s\n' "$b" >>"$pending_file"
	done
	rc=0
	for b in "${boards[@]}"; do
		echo "== board $b: deploy (key driver ${drv[$b]})"
		run_on "$b" deploy "$tmp/stage-${drv[$b]}" || { echo "board $b: deploy FAILED" >&2; rc=1; }
		case " ${switching[*]:-} " in
		*" $b "*) echo "board $b: switched to ${drv[$b]} (pending verification, whatever the deploy said); now: unlock it if needed, 'boards-recipients' with SLUIS_BOARDS_RECIPIENTS_SWITCHED=1, re-sign, deploy, then 'boards-key-check'" ;;
		esac
	done
	exit "$rc"
	;;
recipients | check)
	# recipients: the wrapping key id of each board, from the `check` command of its key@. Every board must give one. The
	# file is written only then, and only if it drops no board that the file already holds, unless the run says that a board
	# switched its key driver (SLUIS_BOARDS_RECIPIENTS_SWITCHED). check: key@'s own check on each board, printed as it is.
	state=${SLUIS_BOARDS_STATE:-.cache/boards}
	if [ -n "$dry" ]; then
		echo "dry run: would run key@'s check on ${boards[*]}"
		exit 0
	fi
	if [ "$mode" = check ]; then
		rc=0
		for b in "${boards[@]}"; do
			echo "== board $b: key@ check"
			if ! out=$(key_check "$b"); then
				printf '%s\n' "$out"
				echo "board $b: key@'s check failed (a listed recipient has no key, or key@ is not running)" >&2
				rc=1
				continue
			fi
			printf '%s\n' "$out"
			if printf '%s\n' "$out" | grep -q '^wrapping key listed: true'; then
				# Verified: a board that switched its key driver is no longer pending, on the board and in the cache.
				had=$(board_marker_get "$b" || true)
				if [ -n "$had" ] || { [ -s "$pending_file" ] && grep -qxF "$b" "$pending_file"; }; then
					board_marker_clear "$b" || { echo "board $b: cannot clear its mark" >&2; rc=1; continue; }
					if [ -s "$pending_file" ]; then
						grep -vxF "$b" "$pending_file" >"$tmp/pending.new" || true
						cat "$tmp/pending.new" >"$pending_file"
					fi
					echo "board $b: verified; the next board may switch"
				fi
			else
				echo "board $b: its wrapping key is not in the KeyPlan yet" >&2
				rc=1
			fi
		done
		exit "$rc"
	fi
	switched=${SLUIS_BOARDS_RECIPIENTS_SWITCHED:-}
	if [ -n "$switched" ] && [ "${#boards[@]}" -ne 1 ]; then
		echo "recipients: SLUIS_BOARDS_RECIPIENTS_SWITCHED needs SLUIS_BOARDS to name exactly one board: the board that switched its key driver." >&2
		exit 2
	fi
	if [ -n "$switched" ] && other=$(pending_has_other "${boards[0]}"); then
		echo "recipients: the board '$other' switched its key driver and has not been verified ('just boards-key-check' with SLUIS_BOARDS=$other); another board does not switch before that." >&2
		exit 2
	fi
	: >"$tmp/ids"
	: >"$tmp/pairs"
	rc=0
	: >"$tmp/slots"
	for b in "${boards[@]}"; do
		out=$(key_check "$b" || true)
		id=$(printf '%s\n' "$out" | sed -n 's/^wrapping key id: //p' | head -1)
		if ! [[ "$id" =~ ^[A-Za-z0-9_-]{43}$ ]]; then
			echo "board $b: key@'s check gave no wrapping key id; is sluis-key@dev running?" >&2
			rc=1
			continue
		fi
		echo "board $b: wrapping key id $id"
		printf '%s\n' "$id" >>"$tmp/ids"
		printf '%s=%s\n' "$b" "$id" >>"$tmp/pairs"
		# The board's slot map entry (ADR 0006, "The slot plan"): its keys and the attestation of each card slot, one line
		# of JSON that names the node first. Its peers release its PIN only while the signed KeyPlan carries it.
		entry=$(printf '%s\n' "$out" | sed -n 's/^slot map: //p' | head -1)
		if [[ "$entry" != '{"node":"'* ]]; then
			echo "board $b: key@'s check gave no slot map entry" >&2
			rc=1
			continue
		fi
		printf '%s\n' "$entry" >>"$tmp/slots"
	done
	[ "$rc" = 0 ] || exit "$rc"
	# The slot map: the entries of this run replace those of the same nodes; the other nodes' entries stay.
	node_of() { sed -n 's/^{"node":"\([^"]*\)".*/\1/p'; }
	{
		echo "# the slot map entries of the boards (boards.sh recipients), one JSON object per line"
		if [ -s "$state/slot-map" ]; then
			while IFS= read -r l; do
				n=$(printf '%s\n' "$l" | node_of)
				[ -n "$n" ] || continue
				grep -q "^{\"node\":\"$n\"" "$tmp/slots" || printf '%s\n' "$l"
			done < <(grep '^{' "$state/slot-map")
		fi
		cat "$tmp/slots"
	} >"$tmp/slot-map.new"
	sort -u "$tmp/ids" >"$tmp/ids.sorted"
	boards_file=$state/recipients.boards # board=id, the id each board gave last time
	if [ -s "$state/recipients" ]; then
		grep '^[^#[:space:]]' "$state/recipients" | sort -u >"$tmp/ids.old" || true
	else
		: >"$tmp/ids.old"
	fi
	if [ -n "$switched" ]; then
		old=""
		if [ -s "$boards_file" ]; then old=$(sed -n "s|^${boards[0]}=||p" "$boards_file" | head -1); fi
		if ! [[ "$old" =~ ^[A-Za-z0-9_-]{43}$ ]]; then
			echo "recipients: no record of the id that ${boards[0]} gave before ($boards_file), so the id to replace is not known." >&2
			echo "recipients: nothing was written. Name every board once with SLUIS_BOARDS_RECIPIENTS_REPLACE=1 to record them." >&2
			exit 1
		fi
		if ! grep -qxF "$old" "$tmp/ids.old"; then
			echo "recipients: warning: the id $old that ${boards[0]} gave before is not in $state/recipients (edited by hand, or replaced already); the new id is added and nothing is removed." >&2
		fi
		echo "recipients: ${boards[0]} switched its key driver: its id $old is replaced, every other id is kept"
		{ grep -vxF "$old" "$tmp/ids.old" || true; cat "$tmp/ids.sorted"; } | sort -u >"$tmp/ids.new"
	else
		if [ -n "$(comm -23 "$tmp/ids.old" "$tmp/ids.sorted")" ] && [ -z "${SLUIS_BOARDS_RECIPIENTS_REPLACE:-}" ]; then
			echo "recipients: $state/recipients holds $(comm -23 "$tmp/ids.old" "$tmp/ids.sorted" | wc -l) id(s) that no board in SLUIS_BOARDS gave now (a board left out, or a key that was replaced)." >&2
			echo "recipients: nothing was written. Name every board in SLUIS_BOARDS, or, for a board that switched its key driver, set SLUIS_BOARDS_RECIPIENTS_SWITCHED=1 and name that board alone, or set SLUIS_BOARDS_RECIPIENTS_REPLACE=1 to replace the file." >&2
			exit 1
		fi
		cp "$tmp/ids.sorted" "$tmp/ids.new"
	fi
	mkdir -p "$state"
	{ echo "# the wrapping keys of the boards (boards.sh recipients)"; cat "$tmp/ids.new"; } >"$state/recipients"
	# The record of which board gave which id: the boards of this run replace their lines, the others stay.
	{
		if [ -s "$boards_file" ]; then
			while IFS='=' read -r bn _; do
				grep -q "^${bn}=" "$tmp/pairs" || grep "^${bn}=" "$boards_file"
			done < <(grep '^[^#[:space:]]' "$boards_file")
		fi
		cat "$tmp/pairs"
	} >"$tmp/boards.new"
	{ echo "# the id each board gave last time (boards.sh recipients)"; sort "$tmp/boards.new"; } >"$boards_file"
	cp "$tmp/slot-map.new" "$state/slot-map"
	echo "recipients: $(wc -l <"$tmp/ids.new") ids in $state/recipients and $(grep -c '^{' "$state/slot-map") slot map entries in $state/slot-map; run 'just boards-prepare' and 'just boards-deploy' to list them"
	;;
undeploy | status)
	: >"$tmp/plan.tsv"
	mkdir -p "$tmp/files"
	install -m 0755 "$here/remote.sh" "$tmp/remote.sh"
	install -m 0644 "$here/remote-lib.sh" "$tmp/remote-lib.sh"
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
	echo "usage: boards.sh deploy|undeploy|status|recipients|check" >&2
	exit 2
	;;
esac
