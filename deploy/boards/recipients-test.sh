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

# The stand-in ssh. The last argument is the command (or "sudo -n bash -s" with the script on standard input).
cat >"$work/bin/ssh" <<'STUB'
#!/usr/bin/env bash
board=""
for a in "$@"; do case "$a" in "$SLUIS_BOARD_SSH_USER"@*) board=${a#*@} ;; esac; done
cmd="${*: -1}"
key=${board//./_}
case "$cmd" in
"sudo -n bash -s")
	cat >/dev/null
	id_var="ID_$key"
	[ -n "${!id_var:-}" ] || exit 1
	echo "wrapping key id: ${!id_var}"
	echo "wrapping key listed: ${LISTED:-true}"
	;;
systemctl\ is-enabled*)
	drv_var="DRV_$key"
	case "${!drv_var:-none}" in
	yubikey-piv) printf 'enabled\ndisabled\n' ;;
	software) printf 'disabled\nenabled\n' ;;
	*) printf 'not-found\nnot-found\n' ;;
	esac
	;;
*) exit 0 ;;
esac
STUB
chmod +x "$work/bin/ssh"

mkid() { printf '%043d' "$1" | tr 0-9 A-J; } # a 43-character id from a number
export PATH="$work/bin:$PATH"
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

export SLUIS_BOARDS="a.test b.test"
refuses "the switch mode names exactly one board" env SLUIS_BOARDS_RECIPIENTS_SWITCHED=1 deploy/boards/boards.sh recipients
export SLUIS_BOARDS="d.test"
ID_d_test=$(mkid 4)
export ID_d_test
refuses "the switch mode needs a record of the board's last id" env SLUIS_BOARDS_RECIPIENTS_SWITCHED=1 deploy/boards/boards.sh recipients

export SLUIS_BOARDS="a.test"
LISTED=false refuses "check fails while the board's key is not in the KeyPlan" deploy/boards/boards.sh check
check "check passes when it is" deploy/boards/boards.sh check

# deploy: one board at a time. The dist holds the executables of the card variant (empty files: the stand-in copies nothing).
mkdir -p dist/arm64/actors dist/arm64/drivers/key
printf '#!/bin/sh\n' >dist/arm64/actors/key
printf '#!/bin/sh\n' >dist/arm64/drivers/key/yubikey-piv
export SLUIS_BOARDS="a.test b.test c.test" SLUIS_BOARDS_KEY_DRIVER=yubikey-piv SLUIS_BOARD_CARD_SERIALS="a.test=1 b.test=2 c.test=3"
export DRV_a_test=software DRV_b_test=software DRV_c_test=software
refuses "switching three boards at once is refused" deploy/boards/boards.sh deploy
grep -q "switches the key driver of 3 boards" "$work/out" || { echo "FAIL the refusal does not say why: $(cat "$work/out")"; fail=1; }
export DRV_b_test=yubikey-piv DRV_c_test=yubikey-piv
check "one board switching is not refused" deploy/boards/boards.sh deploy
export DRV_a_test=software DRV_b_test=software DRV_c_test=software
check "the first-deploy override passes the rule" env SLUIS_BOARDS_NO_DATA_KEYS=1 deploy/boards/boards.sh deploy
export DRV_a_test=none DRV_b_test=none DRV_c_test=none
check "a first deploy (nothing deployed yet) is not a switch" deploy/boards/boards.sh deploy
exit "$fail"
