#!/usr/bin/env bash
# The hand-off of a board's intermediate, on the admin host: `handoff.sh root | certify BOARD | plan BOARD`. The recipes are
# `just boards-handoff-root`, `boards-handoff-certify` and `boards-handoff-plan`. Nothing here touches a board: the commands that
# run on a board are printed by `plan` for the person who runs them at the board run, and the files they carry are public.
#
# The test certifier (tools/harness/certifier) stands in for ritueel's software-root mode, which does not exist yet. For the
# boards it makes a throwaway root of its own, for the names of the boards' installation (the zone boards.test, under the reserved
# top-level domain test) and for nothing else, and certifies the request of a board's card after it has checked the card's
# attestation chain to the maker's root, the slot (9c for x509-intermediate), the firmware and the PIN policy, and that the attested
# key is the request's. The root has TEST ONLY in its name and a key that never leaves the admin host:
#   - the key is below $state/handoff/root/private (mode 0600) and the certifier is the only program that reads it;
#   - this script refuses to run on a host that looks like a board (it has /etc/sluis or /opt/sluis);
#   - what goes to a board is the directory trust/ (the CA bundle, the root list and the pin: public), the answer of that board
#     (a certificate and a result file) and nothing else;
#   - `down` of the boards, a new `root`, or deleting $state/handoff makes the next root a new one; a board then needs a new answer.
#
# Input, from the environment and never from the repository:
#   SLUIS_BOARDS_STATE        the state directory (default .cache/boards), never committed
#   SLUIS_BOARD_CARD_SERIALS  <board>=<serial> pairs, space separated, as boards.sh reads them. `certify BOARD` certifies a token
#                             with the serial listed for that board and no other; without an entry it refuses.
#   SLUIS_BOARD_SSH_USER      for the printed commands only
#
# Order (the whole of it, with what each step needs, is in docs/runtimes/local.md, "A board's intermediate"):
#   1. SLUIS_BOARDS_X509_INTERMEDIATE=1 just boards-prepare, then boards-deploy and the unlock of the board: the KeyPlan lists the key
#      of the intermediate at slot 9c and key@ makes it on the card at its start. This is the deliberate step.
#   2. just boards-handoff-root                  once, on the admin host
#   3. just boards-handoff-plan BOARD            prints the commands for the board: the request, then the install
#   4. just boards-handoff-certify BOARD         after the request file is on the admin host
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
state=${SLUIS_BOARDS_STATE:-.cache/boards}
dir=$state/handoff
zone=boards.test
# The names the board's intermediate may certify: the boundary of the boards' installation (prepare.sh names its host
# sluis.dev.boards.test), so one trust domain and one DNS zone below the zone of the root.
names=dev.boards.test
stem=dev-x509-intermediate
certs=drivers/key/yubikey-piv/internal/card/certs
# The SHA-256 of the DER of "Yubico Attestation Root 1": the same pin the card driver holds (internal/card/yubico.go).
root_sha256=62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8

# SLUIS_BOARD_MARKERS is for the test of this script; a board has both.
looks_like_a_board() {
	local m
	for m in ${SLUIS_BOARD_MARKERS:-/etc/sluis /opt/sluis}; do [ ! -e "$m" ] || return 0; done
	return 1
}
looks_like_a_board && { echo "handoff: this host has /etc/sluis or /opt/sluis, so it looks like a board; the root never comes near a board: run this on the admin host" >&2; exit 1; }

board_serial() { # board -> the serial listed for it
	local pair
	for pair in ${SLUIS_BOARD_CARD_SERIALS:-}; do
		[ "${pair%%=*}" = "$1" ] && { printf '%s' "${pair#*=}"; return 0; }
	done
	return 1
}

valid_board() { [[ "${1:-}" =~ ^[A-Za-z0-9._-]+$ ]]; }

cmd_root() {
	mkdir -p "$dir"
	chmod 0700 "$dir"
	go run ./tools/harness/certifier init -dir "$dir/root" -zone "$zone"
	echo "handoff: the root pin is $(<"$dir/root/trust/root.pin")"
}

cmd_certify() {
	local board=${1:-} serial
	valid_board "$board" || { echo "usage: handoff.sh certify BOARD" >&2; exit 2; }
	[ -s "$dir/root/private/root.key" ] || { echo "handoff: no root: run 'just boards-handoff-root' first" >&2; exit 1; }
	serial=$(board_serial "$board") || { echo "handoff: SLUIS_BOARD_CARD_SERIALS lists no serial for $board; the test certifier certifies the token of a board whose serial the run names, and no other" >&2; exit 1; }
	[[ "$serial" =~ ^[0-9]{1,20}$ ]] || { echo "handoff: the serial for $board is not a decimal number" >&2; exit 1; }
	[ -s "$dir/requests/$board/$stem.csr.pem" ] && [ -s "$dir/requests/$board/$stem.proof.json" ] ||
		{ echo "handoff: no request of $board in $dir/requests/$board; run the commands of 'handoff.sh plan $board' first" >&2; exit 1; }
	go run ./tools/harness/certifier certify -dir "$dir/root" -requests "$dir/requests/$board" -answers "$dir/answers/$board" \
		-attest-root "$certs/yubico-attestation-root-1.pem" -attest-bundle "$certs/yubico-intermediate.pem" -attest-root-sha256 "$root_sha256" \
		-serial "$serial"
}

# plan prints the commands that run at the board run. The paths on the board are below a directory made for the purpose, and the
# only files that go there are public.
cmd_plan() {
	local board=${1:-} user=${SLUIS_BOARD_SSH_USER:-<ssh user>} pin
	valid_board "$board" || { echo "usage: handoff.sh plan BOARD" >&2; exit 2; }
	[ -s "$dir/root/trust/root.pin" ] || { echo "handoff: no root: run 'just boards-handoff-root' first" >&2; exit 1; }
	pin=$(<"$dir/root/trust/root.pin")
	cat <<PLAN
# The hand-off of the intermediate of $board. The factory-default PIN of the test card is the only PIN used; nothing is written
# to the card by these commands: \`key install\` keeps the certificate in key@'s store (KeyCertificate), not on the card.
# The files that move are public.
#
# 1. At the board: ask key@ for the request (it signs through the card; the PIN is released as at any start).
ssh $user@$board 'sudo -n /opt/sluis/bin/cli/sluis key request --boundary dev --trust-domain $names --dns-zone $names --out /var/lib/sluis/keys/request'
# 2. Bring the request and its proof to the admin host.
mkdir -p $dir/requests/$board
for f in $stem.csr.pem $stem.proof.json; do ssh $user@$board "sudo -n cat /var/lib/sluis/keys/request/\$f" >$dir/requests/$board/\$f; done
# 3. At the admin host: the certifier checks the card and certifies.
just boards-handoff-certify $board
# 4. Take the answer and the public trust files to the board and install.
ssh $user@$board 'sudo -n install -d -m 0755 /var/lib/sluis/keys/answer /var/lib/sluis/keys/trust'
for f in $stem.cert.pem $stem.result.json; do ssh $user@$board "sudo -n tee /var/lib/sluis/keys/answer/\$f >/dev/null" <$dir/answers/$board/\$f; done
for f in ca-bundle.pem root-list.json root-list.jws; do ssh $user@$board "sudo -n tee /var/lib/sluis/keys/trust/\$f >/dev/null" <$dir/root/trust/\$f; done
ssh $user@$board 'sudo -n /opt/sluis/bin/cli/sluis key install /var/lib/sluis/keys/answer --boundary dev --requests /var/lib/sluis/keys/request --ca-bundle /var/lib/sluis/keys/trust/ca-bundle.pem --root-list /var/lib/sluis/keys/trust/root-list.json --root-pin $pin'
PLAN
}

case "${1:-}" in
root) cmd_root ;;
certify) shift; cmd_certify "$@" ;;
plan) shift; cmd_plan "$@" ;;
*) echo "usage: handoff.sh root | certify BOARD | plan BOARD" >&2; exit 2 ;;
esac
