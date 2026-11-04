#!/usr/bin/env bash
# Make the seed that `boards.sh deploy` puts on the boards: the signed config, the bootstrap file that pins the
# boards' own publisher key, and the credentials the config documents name. `just boards-prepare`.
#
# The state is below .cache/boards and is never committed: the publisher key (P-384, made at the first run and kept,
# so that a second run signs a newer seq with the same pin), the credentials, and the seed itself. Nothing is echoed.
#
# The config is the local installation's (tests/installations/local/config) with the names of the boards' installation
# in place of the local ones. A replacement that matches nothing fails, so the two cannot drift apart unseen.
#
# Input, from the environment and never from the repository:
#   SLUIS_UPSTREAM_CLIENT_BOARDS   the OpenID Connect client of the boards' upstream (the run.env of the build;
#                                  default sluis-boards)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
state=.cache/boards
seed=$state/seed
src=tests/installations/local/config
host=sluis.dev.boards.test
client=${SLUIS_UPSTREAM_CLIENT_BOARDS:-sluis-boards}
[[ "$client" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "prepare: refusing the client id" >&2; exit 2; }

rm -rf "$state/config" "$seed"
mkdir -p "$state/config" "$seed/config" "$seed/credentials"
chmod 0700 "$state"
cp "$src"/* "$state/config/"

# replace FILE OLD NEW: a literal replacement that must change the file.
replace() {
	local f=$state/config/$1 t
	grep -qF -- "$2" "$f" || { echo "prepare: $1 no longer holds '$2'; update deploy/boards/prepare.sh" >&2; exit 1; }
	t=$(mktemp)
	OLD=$2 NEW=$3 awk '{ while ((i = index($0, ENVIRON["OLD"])) > 0) $0 = substr($0, 1, i - 1) ENVIRON["NEW"] substr($0, i + length(ENVIRON["OLD"])); print }' "$f" >"$t"
	cat "$t" >"$f"
	rm -f "$t"
}
replace boundary.yaml "https://sluis.dev.local.test" "https://$host"
replace audit-log.yaml "sluis.local.test/" "sluis.boards.test/"
replace upstream.yaml "client_id: sluis-local" "client_id: $client"

go run ./tools/harness/sign-config -config "$state/config" -bootstrap tests/installations/local/bootstrap.yaml \
	-key-dir "$state/publisher" -out "$seed/config" -bootstrap-out "$seed/bootstrap.yaml"

# The credentials the config documents name (the store's credential driver serves them). The two client secrets are
# random and kept across runs. The upstream's client secret is a random placeholder: M1 needs no upstream, and the
# real secret goes in by the person who wires the upstream (M2), not through this script.
(
	umask 077
	mkdir -p "$seed/credentials/sluis-drv-store-credential"
	for c in client-dev client-example-app upstream-workforce; do
		[ -s "$state/$c" ] || head -c 32 /dev/urandom | base64 -w0 | tr '+/' '-_' | tr -d '=' >"$state/$c"
		cp "$state/$c" "$seed/credentials/sluis-drv-store-credential/$c"
	done
)
echo "prepare: seed in $seed ($(find "$seed/config" -name '*.jws' | wc -l) signed documents, the bootstrap file, $(find "$seed/credentials" -type f | wc -l) credentials)"
