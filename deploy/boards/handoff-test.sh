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

# --- the state directory is the owner's alone, whatever it was ---
[ "$(stat -c %a "$SLUIS_BOARDS_STATE/handoff")" = 700 ] && ok "root: the state directory is mode 0700" || bad "root: state directory mode $(stat -c %a "$SLUIS_BOARDS_STATE/handoff")"
chmod 0755 "$SLUIS_BOARDS_STATE/handoff"
deploy/boards/handoff.sh root >/dev/null 2>&1
[ "$(stat -c %a "$SLUIS_BOARDS_STATE/handoff")" = 700 ] && ok "root: a wider state directory is made 0700 again" || bad "root: state directory left at $(stat -c %a "$SLUIS_BOARDS_STATE/handoff")"
# The key of the root is the owner's alone, and a run that finds it wider stops.
chmod 0644 "$state/private/root.key"
if deploy/boards/handoff.sh root >"$work/wide.out" 2>&1; then bad "root: a key of mode 0644 is used"; else contains "$(<"$work/wide.out")" "readable by others" && ok "root: a key of mode 0644 stops the run" || bad "root: wide key text: $(<"$work/wide.out")"; fi
chmod 0600 "$state/private/root.key"

# --- certify needs a request and a serial, and takes a card whose chain is the maker's ---
if deploy/boards/handoff.sh certify b1 >"$work/c1.out" 2>&1; then bad "certify with no serial"; else contains "$(<"$work/c1.out")" "lists no serial" && ok "certify: no serial, refused" || bad "certify text: $(<"$work/c1.out")"; fi
if SLUIS_BOARD_CARD_SERIALS="b1=123" deploy/boards/handoff.sh certify b1 >"$work/c2.out" 2>&1; then bad "certify with no request"; else contains "$(<"$work/c2.out")" "no request of b1" && ok "certify: no request, refused" || bad "certify text: $(<"$work/c2.out")"; fi
if SLUIS_BOARD_CARD_SERIALS="b1=12x" deploy/boards/handoff.sh certify b1 >"$work/c3.out" 2>&1; then bad "certify with a bad serial"; else ok "certify: a serial that is not a number, refused"; fi
for name in 'b1;rm' 'b1..x' '-b1' 'b1-' 'a--b' '.b1' 'b 1' ''; do
	if deploy/boards/handoff.sh certify "$name" >/dev/null 2>&1; then bad "certify with the board name '$name'"; else ok "certify: the board name '$name' is refused"; fi
	if SLUIS_BOARD_SSH_USER=ops deploy/boards/handoff.sh plan "$name" >/dev/null 2>&1; then bad "plan with the board name '$name'"; else ok "plan: the board name '$name' is refused"; fi
done
# A made-up card of a made-up maker (not Yubico): its request and proof, and its attestation root and bundle.
go run ./kits/go/handoff/handofftest/cmd/mkcard -dir "$work/card" -serial 31337 >/dev/null 2>&1 || bad "mkcard"
for b in b1 b2 b3; do mkdir -p "$SLUIS_BOARDS_STATE/handoff/requests/$b"; cp "$work/card/dev-x509-intermediate.csr.pem" "$work/card/dev-x509-intermediate.proof.json" "$SLUIS_BOARDS_STATE/handoff/requests/$b/"; done
sha=$(<"$work/card/attest-root.sha256")
env SLUIS_HANDOFF_ATTEST_ROOT="$work/card/attest-root.pem" SLUIS_HANDOFF_ATTEST_BUNDLE="$work/card/attest-bundle.pem" SLUIS_HANDOFF_ATTEST_ROOT_SHA256="$sha" SLUIS_BOARD_CARD_SERIALS="b1=31337" \
	deploy/boards/handoff.sh certify b1 >"$work/ok.out" 2>&1 && ok "certify: a card of the run's serial is certified" || { cat "$work/ok.out"; bad "certify: a good card"; }
contains "$(<"$work/ok.out")" "card serial 31337" && ok "certify: the output names the card's serial" || bad "certify: no serial in the output"
[ -s "$SLUIS_BOARDS_STATE/handoff/answers/b1/dev-x509-intermediate.cert.pem" ] && ok "certify: the answer is written" || bad "certify: no answer"
openssl x509 -in "$SLUIS_BOARDS_STATE/handoff/answers/b1/dev-x509-intermediate.cert.pem" -noout -ext nameConstraints 2>&1 | grep -q 'DNS:dev.boards.test' && ok "certify: the certificate is constrained to the board's names" || bad "certify: name constraints"
env SLUIS_HANDOFF_ATTEST_ROOT="$work/card/attest-root.pem" SLUIS_HANDOFF_ATTEST_BUNDLE="$work/card/attest-bundle.pem" SLUIS_HANDOFF_ATTEST_ROOT_SHA256="$sha" SLUIS_BOARD_CARD_SERIALS="b2=999" \
	deploy/boards/handoff.sh certify b2 >"$work/serial.out" 2>&1 && bad "certify: a serial the run did not list" || { contains "$(<"$work/serial.out")" "refused" && [ ! -e "$SLUIS_BOARDS_STATE/handoff/answers/b2/dev-x509-intermediate.cert.pem" ] && ok "certify: another serial is refused and nothing is written" || bad "certify: serial text: $(<"$work/serial.out")"; }
env SLUIS_HANDOFF_ATTEST_ROOT="$work/card/attest-root.pem" SLUIS_HANDOFF_ATTEST_BUNDLE="$work/card/attest-bundle.pem" SLUIS_HANDOFF_ATTEST_ROOT_SHA256="$(printf '%064d' 0)" SLUIS_BOARD_CARD_SERIALS="b3=31337" \
	deploy/boards/handoff.sh certify b3 >"$work/pin.out" 2>&1 && bad "certify: a root that is not the pinned one" || { contains "$(<"$work/pin.out")" "not the pinned certificate" && ok "certify: the attestation root is held to its pin" || bad "certify: pin text: $(<"$work/pin.out")"; }
for only in SLUIS_HANDOFF_ATTEST_ROOT=$work/card/attest-root.pem SLUIS_HANDOFF_ATTEST_BUNDLE=$work/card/attest-bundle.pem SLUIS_HANDOFF_ATTEST_ROOT_SHA256=$sha; do
	if env "$only" SLUIS_BOARD_CARD_SERIALS="b3=31337" deploy/boards/handoff.sh certify b3 >"$work/part.out" 2>&1; then bad "certify: one override alone (${only%%=*})"; else contains "$(<"$work/part.out")" "go together" && ok "certify: the overrides go together (${only%%=*} alone is refused)" || bad "certify: override text"; fi
done
# Two of the three are not enough either: each is the one that is missing, in turn.
if SLUIS_HANDOFF_ATTEST_BUNDLE="$work/card/attest-bundle.pem" SLUIS_HANDOFF_ATTEST_ROOT_SHA256="$sha" SLUIS_BOARD_CARD_SERIALS="b3=31337" deploy/boards/handoff.sh certify b3 >/dev/null 2>&1; then bad "certify: bundle and pin without a root"; else ok "certify: bundle and pin without a root are refused"; fi
if SLUIS_HANDOFF_ATTEST_ROOT="$work/card/attest-root.pem" SLUIS_HANDOFF_ATTEST_ROOT_SHA256="$sha" SLUIS_BOARD_CARD_SERIALS="b3=31337" deploy/boards/handoff.sh certify b3 >/dev/null 2>&1; then bad "certify: root and pin without a bundle"; else ok "certify: root and pin without a bundle are refused"; fi
if SLUIS_HANDOFF_ATTEST_ROOT="$work/card/attest-root.pem" SLUIS_HANDOFF_ATTEST_BUNDLE="$work/card/attest-bundle.pem" SLUIS_BOARD_CARD_SERIALS="b3=31337" deploy/boards/handoff.sh certify b3 >/dev/null 2>&1; then bad "certify: root and bundle without a pin"; else ok "certify: root and bundle without a pin are refused"; fi
# With the real anchors (the repository's own files and the driver's pin) the made-up card is not the maker's: refused as evidence that does not hold.
SLUIS_BOARD_CARD_SERIALS="b3=31337" deploy/boards/handoff.sh certify b3 >"$work/real.out" 2>&1 && bad "certify: a made-up maker is taken for Yubico" || { contains "$(<"$work/real.out")" "proof-invalid" && ! contains "$(<"$work/real.out")" "not the pinned certificate" && ok "certify: the repository's own anchors load under the driver's pin and refuse a made-up maker" || bad "certify: real anchors text: $(<"$work/real.out")"; }

# --- the plan: the commands, the pin, public files only ---
if deploy/boards/handoff.sh plan b1 >"$work/nouser.out" 2>&1; then bad "plan with no ssh user"; else contains "$(<"$work/nouser.out")" "SLUIS_BOARD_SSH_USER" && ok "plan: no ssh user, refused" || bad "plan text: $(<"$work/nouser.out")"; fi
for u in 'a b' '-oProxyCommand=x' 'a;b' '1x'; do
	if SLUIS_BOARD_SSH_USER=$u deploy/boards/handoff.sh plan b1 >/dev/null 2>&1; then bad "plan with the ssh user '$u'"; else ok "plan: the ssh user '$u' is refused"; fi
done
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
