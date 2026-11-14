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
# A made-up card of a made-up maker (not Yubico): its request and proof, and its attestation root and bundle. handoff.sh has no way to
# trust another maker, so the cases that need one call the certifier itself with the made-up anchors; the script is tested for what
# it passes to the certifier (a stand-in for `go run`, which records the arguments) and, with the real anchors, for what it refuses.
go run ./kits/go/handoff/handofftest/cmd/mkcard -dir "$work/card" -serial 31337 >/dev/null 2>&1 || bad "mkcard"
sha=$(<"$work/card/attest-root.sha256")
for b in b1 b2 b3; do mkdir -p "$SLUIS_BOARDS_STATE/handoff/requests/$b"; cp "$work/card/dev-x509-intermediate.csr.pem" "$work/card/dev-x509-intermediate.proof.json" "$SLUIS_BOARDS_STATE/handoff/requests/$b/"; done
certifier() { go run ./tools/harness/certifier certify -dir "$SLUIS_BOARDS_STATE/handoff/root" "$@"; }
made_up=(-attest-root "$work/card/attest-root.pem" -attest-bundle "$work/card/attest-bundle.pem" -attest-root-sha256 "$sha")
certifier -requests "$SLUIS_BOARDS_STATE/handoff/requests/b1" -answers "$SLUIS_BOARDS_STATE/handoff/answers/b1" "${made_up[@]}" -serial 31337 >"$work/ok.out" 2>&1 && ok "certifier: a card of the run's serial is certified" || { cat "$work/ok.out"; bad "certifier: a good card"; }
contains "$(<"$work/ok.out")" "card serial 31337" && ok "certifier: the output names the card's serial" || bad "certifier: no serial in the output"
openssl x509 -in "$SLUIS_BOARDS_STATE/handoff/answers/b1/dev-x509-intermediate.cert.pem" -noout -ext nameConstraints 2>&1 | grep -q 'DNS:dev.boards.test' && ok "certifier: the certificate is constrained to the board's names" || bad "certifier: name constraints"
certifier -requests "$SLUIS_BOARDS_STATE/handoff/requests/b2" -answers "$SLUIS_BOARDS_STATE/handoff/answers/b2" "${made_up[@]}" -serial 999 >"$work/serial.out" 2>&1 && bad "certifier: a serial the run did not list" || { contains "$(<"$work/serial.out")" "refused" && [ ! -e "$SLUIS_BOARDS_STATE/handoff/answers/b2/dev-x509-intermediate.cert.pem" ] && ok "certifier: another serial is refused and nothing is written" || bad "certifier: serial text: $(<"$work/serial.out")"; }
certifier -requests "$SLUIS_BOARDS_STATE/handoff/requests/b3" -answers "$SLUIS_BOARDS_STATE/handoff/answers/b3" -attest-root "$work/card/attest-root.pem" -attest-bundle "$work/card/attest-bundle.pem" -attest-root-sha256 "$(printf '%064d' 0)" -serial 31337 >"$work/pin.out" 2>&1 && bad "certifier: a root that is not the pinned one" || { contains "$(<"$work/pin.out")" "not the pinned certificate" && ok "certifier: the attestation root is held to its pin" || bad "certifier: pin text: $(<"$work/pin.out")"; }

# What handoff.sh passes to the certifier: the repository's Yubico root and bundle, the driver's pin and the board's serial. A stand-in for go
# records the arguments of `go run ./tools/harness/certifier certify` and runs everything else. The three variables that used to name
# another maker change nothing now: the arguments are the same with them set to the made-up maker's files.
real_go=$(command -v go)
mkdir -p "$work/bin"
cat >"$work/bin/go" <<STUB
#!/usr/bin/env bash
if [ "\$1" = run ] && [ "\$2" = ./tools/harness/certifier ] && [ "\$3" = certify ]; then printf '%s\n' "\$*" >"$work/certify.args"; exit 0; fi
exec "$real_go" "\$@"
STUB
chmod +x "$work/bin/go"
want="run ./tools/harness/certifier certify -dir $SLUIS_BOARDS_STATE/handoff/root -requests $SLUIS_BOARDS_STATE/handoff/requests/b1 -answers $SLUIS_BOARDS_STATE/handoff/answers/b1 -attest-root drivers/key/yubikey-piv/internal/card/certs/yubico-attestation-root-1.pem -attest-bundle drivers/key/yubikey-piv/internal/card/certs/yubico-intermediate.pem -attest-root-sha256 62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8 -serial 31337"
rm -f "$work/certify.args"
PATH="$work/bin:$PATH" SLUIS_BOARD_CARD_SERIALS="b1=31337" deploy/boards/handoff.sh certify b1 >"$work/args.out" 2>&1 || { cat "$work/args.out"; bad "certify through handoff.sh"; }
[ "$(<"$work/certify.args")" = "$want" ] && ok "certify: handoff.sh passes the repository's Yubico anchors, their pin and the board's serial" || bad "certify: arguments were: $(<"$work/certify.args")"
rm -f "$work/certify.args"
PATH="$work/bin:$PATH" SLUIS_BOARD_CARD_SERIALS="b1=31337" SLUIS_HANDOFF_ATTEST_ROOT="$work/card/attest-root.pem" SLUIS_HANDOFF_ATTEST_BUNDLE="$work/card/attest-bundle.pem" SLUIS_HANDOFF_ATTEST_ROOT_SHA256="$sha" \
	deploy/boards/handoff.sh certify b1 >"$work/args2.out" 2>&1 || { cat "$work/args2.out"; bad "certify with the old variables set"; }
[ "$(<"$work/certify.args")" = "$want" ] && ok "certify: variables that named another maker change nothing" || bad "certify: with the variables set the arguments were: $(<"$work/certify.args")"
if grep -n 'SLUIS_HANDOFF_ATTEST' deploy/boards/handoff.sh >/dev/null; then bad "handoff.sh reads a variable that names a maker"; else ok "handoff.sh reads no variable that names a maker"; fi
# With the real anchors (the repository's own files and the driver's pin) the made-up card is not the maker's: refused as evidence that does not hold,
# and the real root is not what the made-up card is held to.
SLUIS_BOARD_CARD_SERIALS="b3=31337" deploy/boards/handoff.sh certify b3 >"$work/real.out" 2>&1 && bad "certify: a made-up maker is taken for Yubico" || { contains "$(<"$work/real.out")" "proof-invalid" && ! contains "$(<"$work/real.out")" "not the pinned certificate" && [ ! -e "$SLUIS_BOARDS_STATE/handoff/answers/b3/dev-x509-intermediate.cert.pem" ] && ok "certify: the repository's own anchors load under the driver's pin and refuse a made-up maker, with the variables set or not" || bad "certify: real anchors text: $(<"$work/real.out")"; }
SLUIS_BOARD_CARD_SERIALS="b3=31337" SLUIS_HANDOFF_ATTEST_ROOT="$work/card/attest-root.pem" SLUIS_HANDOFF_ATTEST_BUNDLE="$work/card/attest-bundle.pem" SLUIS_HANDOFF_ATTEST_ROOT_SHA256="$sha" deploy/boards/handoff.sh certify b3 >"$work/real2.out" 2>&1 && bad "certify: the old variables make a made-up maker the maker" || { [ ! -e "$SLUIS_BOARDS_STATE/handoff/answers/b3/dev-x509-intermediate.cert.pem" ] && ok "certify: the old variables do not make a made-up maker the maker" || bad "certify: a certificate was written"; }

# --- the names of the request: one plain host name, in the form of ritueel's contract and equal to the entry its policy would list ---
n=$(sed -n 's/^names=//p' deploy/boards/handoff.sh)
if [[ "$n" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$ && ${#n} -le 253 && ${n##*.} =~ [^0-9] ]]; then ok "names: '$n' is a lower-case host name of the contract's form"; else bad "names: '$n' is not a host name of the contract's form"; fi
[ "$n" != "${n#.}" ] && bad "names: a period at the start" || ok "names: no period at the start, so the URI host and the DNS name are one entry"

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
