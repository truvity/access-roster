#!/usr/bin/env bash
# A test of `boards.sh recipients`, `check` and the one-board-at-a-time rule of `deploy`, against a stand-in for ssh: no board,
# no host. The stand-in answers like a board: key@'s check prints the wrapping key id the test gives that board, and
# systemctl is-enabled prints the key driver the test gives it. Run from the repository root: deploy/boards/recipients-test.sh
set -euo pipefail

root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/state" "$work/repo/deploy"
# The scripts run in a repository of their own, so that the dist they stage is this test's and not the workstation's.
cp -r "$root/deploy/boards" "$work/repo/deploy/boards"
git -C "$work/repo" init -q
cd "$work/repo"

# The stand-in ssh. The last argument is the command (or "sudo -n bash -s" with the script on standard input). It answers like a
# board with systemd 249 (Ubuntu 22.04): in particular `systemctl is-enabled A B` stops at the first unit that does not exist
# and prints nothing for the rest, which is why boards.sh asks for each unit on its own.
cat >"$work/bin/ssh" <<'STUB'
#!/usr/bin/env bash
board=""
for a in "$@"; do case "$a" in "$SLUIS_BOARD_SSH_USER"@*) board=${a#*@} ;; esac; done
cmd="${*: -1}"
key=${board//./_}
drv_var="DRV_$key"
drv=${!drv_var:-none}

# What exists on this board: the card unit on a card board; the software unit on a software board; both on a board that was
# switched (the one it left is disabled); none before the first deploy.
unit_state() { # unit -> "LoadState UnitFileState"
	case "$1:$drv" in
	*yubikey-piv*:yubikey-piv) echo "loaded enabled" ;;
	*yubikey-piv*:software | *yubikey-piv*:none) echo "not-found " ;;
	*key-software*:software) echo "loaded enabled" ;;
	*key-software*:yubikey-piv) echo "loaded disabled" ;;
	*) echo "not-found " ;;
	esac
}
systemctl() {
	case "$1" in
	show) # show -p LoadState|UnitFileState --value UNIT
		local st
		st=$(unit_state "${@: -1}")
		case "$3" in LoadState) echo "${st%% *}" ;; UnitFileState) echo "${st#* }" ;; esac
		;;
	is-enabled) # systemd 249: stop at the first unit that does not exist
		local u st
		for u in "${@:2}"; do
			st=$(unit_state "$u")
			if [ "${st%% *}" = not-found ]; then return 4; fi
			echo "${st#* }"
		done
		;;
	esac
}

case "$cmd" in
"sudo -n bash -s")
	cat >/dev/null
	id_var="ID_$key"
	[ -n "${!id_var:-}" ] || exit 1
	echo "wrapping key id: ${!id_var}"
	echo "wrapping key listed: ${LISTED:-true}"
	;;
*systemctl*) eval "$cmd" ;;
*db/query*)
	n_var="KEYS_$key"
	echo "{\"results\":[{\"columns\":[\"count(*)\"],\"types\":[\"integer\"],\"values\":[[${!n_var:-0}]]}]}"
	;;
tar\ -xf*) mkdir -p "$STUB_LOG"; tar -tf - >>"$STUB_LOG/$board.files" ;;
*) exit 0 ;;
esac
STUB
chmod +x "$work/bin/ssh"

mkid() { printf '%043d' "$1" | tr 0-9 A-J; } # a 43-character id from a number
export PATH="$work/bin:$PATH" STUB_LOG="$work/log"
export SLUIS_BOARD_SSH_USER=nobody SLUIS_BOARDS_STATE="$work/state"
fail=0
check() { # description, command...
	local d=$1
	shift
	if "$@" >"$work/out" 2>&1; then echo "ok   $d"; else echo "FAIL $d"; sed 's/^/     /' "$work/out"; fail=1; fi
}
refuses() { # description, command...
	local d=$1
	shift
	if "$@" >"$work/out" 2>&1; then echo "FAIL $d: it succeeded"; sed 's/^/     /' "$work/out"; fail=1; else echo "ok   $d"; fi
}
want() { printf '%s\n' "$@" | sort | tr '\n' ' '; }
ids() { grep '^[^#[:space:]]' "$work/state/recipients" | sort | tr '\n' ' '; }

ID_a_test=$(mkid 1) ID_b_test=$(mkid 2) ID_c_test=$(mkid 3)
export ID_a_test ID_b_test ID_c_test
export SLUIS_BOARDS="a.test b.test c.test"
check "three boards give three ids" deploy/boards/boards.sh recipients
[ "$(ids)" = "$(want "$(mkid 1)" "$(mkid 2)" "$(mkid 3)")" ] || { echo "FAIL the file holds: $(ids)"; fail=1; }
grep -q "^b.test=$(mkid 2)$" "$work/state/recipients.boards" || { echo "FAIL the record of b.test is missing"; fail=1; }

# b switches its key driver: a new id.
ID_b_test=$(mkid 22)
export ID_b_test
export SLUIS_BOARDS="b.test"
refuses "a board whose id changed is refused without the switch mode" deploy/boards/boards.sh recipients
[ "$(ids)" = "$(want "$(mkid 1)" "$(mkid 2)" "$(mkid 3)")" ] || { echo "FAIL the refusal changed the file: $(ids)"; fail=1; }
check "the switch mode replaces the id of that board alone" env SLUIS_BOARDS_RECIPIENTS_SWITCHED=1 deploy/boards/boards.sh recipients
[ "$(ids)" = "$(want "$(mkid 1)" "$(mkid 22)" "$(mkid 3)")" ] || { echo "FAIL after the switch the file holds: $(ids)"; fail=1; }
if ! grep -q "^b.test=$(mkid 22)$" "$work/state/recipients.boards" || ! grep -q "^a.test=$(mkid 1)$" "$work/state/recipients.boards"; then echo "FAIL the record: $(cat "$work/state/recipients.boards")"; fail=1; fi

# Rollback: b comes back with its software id.
ID_b_test=$(mkid 2)
export ID_b_test
check "the rollback replaces the card's id with the software id" env SLUIS_BOARDS_RECIPIENTS_SWITCHED=1 deploy/boards/boards.sh recipients
[ "$(ids)" = "$(want "$(mkid 1)" "$(mkid 2)" "$(mkid 3)")" ] || { echo "FAIL after the rollback the file holds: $(ids)"; fail=1; }

# The recorded old id is not in the file (edited by hand): a warning, and the new id is added.
grep -vxF "$(mkid 2)" "$work/state/recipients" >"$work/state/recipients.edit" && cp "$work/state/recipients.edit" "$work/state/recipients"
SLUIS_BOARDS="b.test" check "the switch mode warns when the recorded old id is not in the file" env SLUIS_BOARDS_RECIPIENTS_SWITCHED=1 ./deploy/boards/boards.sh recipients
grep -q "warning: the id .* is not in" "$work/out" || { echo "FAIL no warning: $(cat "$work/out")"; fail=1; }

export SLUIS_BOARDS="a.test b.test"
refuses "the switch mode names exactly one board" env SLUIS_BOARDS_RECIPIENTS_SWITCHED=1 deploy/boards/boards.sh recipients
export SLUIS_BOARDS="d.test"
ID_d_test=$(mkid 4)
export ID_d_test
refuses "the switch mode needs a record of the board's last id" env SLUIS_BOARDS_RECIPIENTS_SWITCHED=1 deploy/boards/boards.sh recipients

export SLUIS_BOARDS="a.test"
LISTED=false refuses "check fails while the board's key is not in the KeyPlan" deploy/boards/boards.sh check
check "check passes when it is" deploy/boards/boards.sh check

# The stand-in is systemd 249: is-enabled with two units stops at the first one that does not exist.
DRV_a_test=software SLUIS_BOARD_SSH_USER=u bash -c 'ssh u@a.test "systemctl is-enabled sluis-drv-key-yubikey-piv@dev.service sluis-drv-key-software@dev.service"' >"$work/out" 2>&1 || true
[ ! -s "$work/out" ] || { echo "FAIL the stand-in is not systemd 249: $(cat "$work/out")"; fail=1; }

# deploy: one board at a time. The dist holds the executables of both variants (empty files: the stand-in copies nothing).
mkdir -p dist/arm64/actors dist/arm64/drivers/key
for f in actors/key drivers/key/software drivers/key/yubikey-piv; do printf '#!/bin/sh\n' >"dist/arm64/$f"; done
export SLUIS_BOARDS="a.test b.test c.test" SLUIS_BOARD_CARD_SERIALS="a.test=1 b.test=2 c.test=3"
export SLUIS_BOARDS_KEY_DRIVER=yubikey-piv
export DRV_a_test=software DRV_b_test=software DRV_c_test=software
refuses "three software boards switching to the card at once are refused" ./deploy/boards/boards.sh deploy
grep -q "switches the key driver of 3 boards" "$work/out" || { echo "FAIL the refusal does not say why: $(cat "$work/out")"; fail=1; }
[ ! -e "$work/state/switch-pending" ] || { echo "FAIL a refused run marked a board pending"; fail=1; }

SLUIS_BOARDS_NO_DATA_KEYS=1 KEYS_b_test=3 refuses "the first-deploy override is refused when a store holds data keys" ./deploy/boards/boards.sh deploy
grep -q "holds 3 DataKeyWrap items" "$work/out" || { echo "FAIL the refusal does not say why: $(cat "$work/out")"; fail=1; }
check "the first-deploy override passes when no store holds a data key" env SLUIS_BOARDS_NO_DATA_KEYS=1 ./deploy/boards/boards.sh deploy
rm -f "$work/state/switch-pending"

# One board switches; the others are not named.
export SLUIS_BOARDS="a.test" DRV_a_test=software
check "one board switching is not refused" ./deploy/boards/boards.sh deploy
[ "$(cat "$work/state/switch-pending" 2>/dev/null)" = "a.test" ] || { echo "FAIL the switched board is not pending: $(cat "$work/state/switch-pending" 2>/dev/null)"; fail=1; }
export DRV_a_test=yubikey-piv SLUIS_BOARDS="b.test" DRV_b_test=software
refuses "a second board does not switch while the first is not verified" ./deploy/boards/boards.sh deploy
grep -q "has not been verified" "$work/out" || { echo "FAIL the refusal does not say why: $(cat "$work/out")"; fail=1; }
SLUIS_BOARDS="b.test" refuses "nor does its id replace another's while one is pending" env SLUIS_BOARDS_RECIPIENTS_SWITCHED=1 ./deploy/boards/boards.sh recipients
grep -q "has not been verified" "$work/out" || { echo "FAIL the refusal does not say why: $(cat "$work/out")"; fail=1; }
SLUIS_BOARDS="a.test" LISTED=false refuses "check keeps the board pending while its key is not listed" ./deploy/boards/boards.sh check
[ -s "$work/state/switch-pending" ] || { echo "FAIL check cleared a board whose key is not listed"; fail=1; }
SLUIS_BOARDS="a.test" check "check passes for the switched board" ./deploy/boards/boards.sh check
[ ! -s "$work/state/switch-pending" ] || { echo "FAIL the board is still pending after a passing check"; fail=1; }
SLUIS_BOARDS="b.test" check "then the next board may switch" ./deploy/boards/boards.sh deploy

# SLUIS_BOARDS_KEY_DRIVER unset: each board keeps the driver it runs, and the files it gets are those of that driver.
unset SLUIS_BOARDS_KEY_DRIVER
rm -f "$work/state/switch-pending"; rm -rf "$work/log"
export SLUIS_BOARDS="a.test b.test c.test" DRV_a_test=yubikey-piv DRV_b_test=software DRV_c_test=none
check "with no driver named every board keeps its own" ./deploy/boards/boards.sh deploy
grep -q "files/card/pcscd-socket.dropin" "$work/log/a.test.files" || { echo "FAIL the card board did not get the card files"; fail=1; }
if grep -q "files/card/" "$work/log/b.test.files" "$work/log/c.test.files"; then echo "FAIL a software board got card files"; fail=1; else echo "ok   the software boards got no card file"; fi
grep -q "bin/drivers/key/software" "$work/log/c.test.files" || { echo "FAIL a board with nothing deployed did not get software"; fail=1; }
[ ! -s "$work/state/switch-pending" ] || { echo "FAIL a run that switched nothing marked a board pending"; fail=1; }
exit "$fail"
