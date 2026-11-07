#!/usr/bin/env bash
# shellcheck disable=SC2015 # `A && ok || fail` pairs report a check either way
# A test of the admin-host side of a board's hand-off (handoff.sh) and of the one switch that adds the key of the intermediate to a
# board's KeyPlan (prepare.sh): no board, no card, no network. The state is a temporary directory. Run from the repository root:
# deploy/boards/handoff-test.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export SLUIS_BOARDS_STATE=$work/state
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
contains() { grep -qF -- "$2" <<<"$1"; }

# --- the root: made once, kept, public files only off the admin host ---
deploy/boards/handoff.sh root >"$work/root.out" 2>&1 || { cat "$work/root.out"; bad "root"; }
state=$SLUIS_BOARDS_STATE/handoff/root
pin=$(<"$state/trust/root.pin")
[[ "$pin" =~ ^[0-9a-f]{64}$ ]] && ok "root: a pin of 64 hex digits" || bad "root: pin '$pin'"
[ "$(stat -c %a "$state/private/root.key")" = 600 ] && ok "root: the key is mode 0600" || bad "root: key mode"
if grep -rl 'PRIVATE KEY' "$state/trust" >/dev/null 2>&1; then bad "root: a private key in trust/"; else ok "root: no private key in trust/"; fi
deploy/boards/handoff.sh root >"$work/root2.out" 2>&1
[ "$(<"$state/trust/root.pin")" = "$pin" ] && ok "root: a second run keeps the root" || bad "root: a second run made a new root"
# The root is for the names of the boards and nothing else, and says it is a test root.
openssl x509 -in "$state/trust/root.pem" -noout -subject -ext nameConstraints >"$work/nc.txt" 2>&1
contains "$(<"$work/nc.txt")" "TEST ONLY" && ok "root: TEST ONLY in the subject" || bad "root: no TEST ONLY"
contains "$(<"$work/nc.txt")" "DNS:boards.test" && ! contains "$(<"$work/nc.txt")" "local.test" && ok "root: permits boards.test only" || bad "root: name constraints: $(<"$work/nc.txt")"
contains "$(<"$work/nc.txt")" "IP:0.0.0.0/0.0.0.0" && ok "root: every IPv4 address excluded" || bad "root: IPs not excluded"

# --- a host that looks like a board is refused ---
if SLUIS_BOARD_MARKERS="$work" deploy/boards/handoff.sh root >"$work/board.out" 2>&1; then bad "a board-like host runs root"; else
	contains "$(<"$work/board.out")" "looks like a board" && ok "a host that looks like a board is refused" || bad "refusal text: $(<"$work/board.out")"
fi

# --- certify needs a request and a serial ---
if deploy/boards/handoff.sh certify b1 >"$work/c1.out" 2>&1; then bad "certify with no serial"; else contains "$(<"$work/c1.out")" "lists no serial" && ok "certify: no serial, refused" || bad "certify text: $(<"$work/c1.out")"; fi
if SLUIS_BOARD_CARD_SERIALS="b1=123" deploy/boards/handoff.sh certify b1 >"$work/c2.out" 2>&1; then bad "certify with no request"; else contains "$(<"$work/c2.out")" "no request of b1" && ok "certify: no request, refused" || bad "certify text: $(<"$work/c2.out")"; fi
if SLUIS_BOARD_CARD_SERIALS="b1=12x" deploy/boards/handoff.sh certify b1 >"$work/c3.out" 2>&1; then bad "certify with a bad serial"; else ok "certify: a serial that is not a number, refused"; fi
if deploy/boards/handoff.sh certify 'b1;rm' >/dev/null 2>&1; then bad "certify with a bad board name"; else ok "certify: a board name with a ; is refused"; fi

# --- the plan: the commands, the pin, public files only ---
SLUIS_BOARD_SSH_USER=ops deploy/boards/handoff.sh plan b1 >"$work/plan.out" 2>&1 || { cat "$work/plan.out"; bad "plan"; }
plan=$(<"$work/plan.out")
for want in "key request --boundary dev --trust-domain dev.boards.test --dns-zone dev.boards.test" "key install /var/lib/sluis/keys/answer" "--root-pin $pin" "--root-list" "ca-bundle.pem" "boards-handoff-certify b1"; do
	contains "$plan" "$want" && ok "plan: $want" || bad "plan lacks: $want"
done
if contains "$plan" "root.key" || contains "$plan" "private"; then bad "plan names the root's key"; else ok "plan: the root's key is not named"; fi
if contains "$plan" "accept-unanchored-list"; then bad "plan: an unanchored root list"; else ok "plan: the root list is read with the pin"; fi

# --- the KeyPlan: the key of the intermediate only when asked ---
mkdir -p "$work/prep"
run_prepare() { SLUIS_BOARDS_STATE=$work/prep "$@" deploy/boards/prepare.sh >"$work/prep.out" 2>&1 || { cat "$work/prep.out"; return 1; }; }
run_prepare env || bad "prepare"
grep -q 'x509-intermediate' "$work/prep/config/key-plan.yaml" && bad "prepare: the plan lists the intermediate by default" || ok "prepare: the plan does not list the intermediate by default"
run_prepare env SLUIS_BOARDS_X509_INTERMEDIATE=1 || bad "prepare with the switch"
grep -qF '{ purpose: x509-intermediate, algorithm: ES384, slot: 9c }' "$work/prep/config/key-plan.yaml" && ok "prepare: the switch adds the key at slot 9c" || bad "prepare: the switch did not add the key"
grep -c 'purpose: pin-release' "$work/prep/config/key-plan.yaml" | grep -qx 1 && ok "prepare: the rest of the plan is as it was" || bad "prepare: the plan changed otherwise"
grep -q 'x509-intermediate' tests/installations/local/config/key-plan.yaml && bad "the committed plan lists the intermediate" || ok "the committed plan does not list the intermediate"

[ "$fail" = 0 ] && echo "handoff-test: all passed" || { echo "handoff-test: FAILED"; exit 1; }
