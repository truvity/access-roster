#!/usr/bin/env bash
# The OpenID Foundation conformance suite against the running local installation (docs/standards/conformance.md):
#
#   devbox run -- just local-conformance            (after `just local-up`, with SLUIS_KEYCLOAK_SECRETS as for the smokes)
#
# It starts the suite (tests/conformance/compose.yaml: release v5.3.4, its MongoDB and nginx, every image pinned by digest), runs
# the plans of tests/conformance/expected.yaml with alice signing in where the suite asks a person to (runner), judges each module
# against the table, and then runs the gate: the Go tests that name the requirements the suite is the proof of
# (tests/conformance/runner/gate_test.go). It needs Docker and an Internet route to registry.gitlab.com and Docker Hub for the
# images, and no account. Exit 1 on any difference from the table, or on a gate test that fails or skips.
#
# Inputs, from the environment (none of them in the repository):
#   SLUIS_KEYCLOAK_SECRETS  the identity provider's secrets file, as for `just local-up` (alice's password and one-time key)
#   COMPOSE_PROJECT_NAME    the installation's Compose project (default sluis-local)
#   SLUIS_LOCAL_PORT        the loopback port of the installation's forwarder (default 8443)
#   SLUIS_OIDF_PORT         the loopback port of the suite (default 8453; the suite's own address stays :8443 inside)
#   SLUIS_OIDF_SUBNET       a subnet for the suite's network, where the host's firewall lets only some through (default: Docker's)
#   SLUIS_OIDF_OUT          where results go (default .cache/conformance): results.json, the suite's export of each plan, suite.log
#   SLUIS_OIDF_PLANS        run these plans of the table only (a partial run; the gate then does not run)
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
here=tests/conformance
project=${COMPOSE_PROJECT_NAME:-sluis-local}
out=${SLUIS_OIDF_OUT:-.cache/conformance}
suite_port=${SLUIS_OIDF_PORT:-8453}
forwarder=127.0.0.1:${SLUIS_LOCAL_PORT:-8443}
ca=.cache/local/ca/ca.pem
[ -r "$ca" ] || { echo "conformance: $ca is missing; run \`just local-up\` first" >&2; exit 1; }
: "${SLUIS_KEYCLOAK_SECRETS:?conformance: SLUIS_KEYCLOAK_SECRETS does not name the identity provider's secrets file}"
docker network inspect "${project}_default" >/dev/null 2>&1 || { echo "conformance: the network ${project}_default is missing; run \`just local-up\` first" >&2; exit 1; }

export SLUIS_OIDF_NETWORK=${project}_default
export SLUIS_OIDF_SUITE_NETWORK=${project}-oidf
export SLUIS_OIDF_PORT=$suite_port
export SLUIS_OIDF_CA=$root/$ca
export SLUIS_OIDF_USER="$(id -u):$(id -g)"
trust=$(mktemp -d)
export SLUIS_OIDF_TRUSTSTORE=$trust
compose=(docker compose -p "${project}-oidf" -f "$here/compose.yaml")

mkdir -p "$out"
cleanup() {
	"${compose[@]}" logs --no-color >"$out/suite.log" 2>&1 || true
	"${compose[@]}" --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
	docker network rm "$SLUIS_OIDF_SUITE_NETWORK" >/dev/null 2>&1 || true
	rm -rf "$trust"
}
trap cleanup EXIT

docker network rm "$SLUIS_OIDF_SUITE_NETWORK" >/dev/null 2>&1 || true
docker network create ${SLUIS_OIDF_SUBNET:+--subnet "$SLUIS_OIDF_SUBNET"} "$SLUIS_OIDF_SUITE_NETWORK" >/dev/null
# The JDK's trust store of the suite's image, with the harness CA added: the suite trusts the installation's forwarder.
"${compose[@]}" --profile tools run --rm truststore
"${compose[@]}" up -d

CGO_ENABLED=0 go build -o dist/local/oidf-runner ./tests/conformance/runner
status=0
dist/local/oidf-runner run -suite "https://127.0.0.1:$suite_port" -forwarder "$forwarder" -ca "$ca" \
	-secrets "$SLUIS_KEYCLOAK_SECRETS" -table "$here/expected.yaml" -out "$out" ${SLUIS_OIDF_PLANS:+-plans "$SLUIS_OIDF_PLANS"} || status=1

if [ -n "${SLUIS_OIDF_PLANS:-}" ]; then
	echo "conformance: a partial run (${SLUIS_OIDF_PLANS}); the gate did not run" >&2
	exit "$status"
fi

# The gate: the tests that name the requirements. A test that skips proves nothing, so a skip fails here as a failure does.
echo
echo "== the gate (tests/conformance/runner/gate_test.go)"
SLUIS_OIDF_RESULTS=$PWD/$out/results.json go test -count=1 -tags sluis_test -json ./tests/conformance/runner >"$out/gate.json" || status=1
echo "gate: $(jq -s '[.[] | select(.Action == "pass" and .Test != null)] | length' "$out/gate.json") tests passed"
skips=$(jq -r 'select(.Action == "skip" and .Test != null) | .Test' "$out/gate.json")
fails=$(jq -r 'select(.Action == "fail" and .Test != null) | .Test' "$out/gate.json")
if [ -n "$skips" ]; then echo "::error::gate tests that skipped (a skip proves nothing):" >&2; echo "$skips" >&2; status=1; fi
if [ -n "$fails" ]; then echo "::error::gate tests that failed:" >&2; echo "$fails" >&2; fi
# Every test that carries a requirement tag must have passed: a tag whose test was renamed, or did not run, is no proof.
tagged=$(awk '/^\/\/ verifies:/ { v = 1; next } v && /^func Test/ { sub(/\(.*/, "", $2); print $2; v = 0; next } !/^\/\// { v = 0 }' "$here/runner/gate_test.go")
[ -n "$tagged" ] || { echo "::error::no test of gate_test.go carries a verifies: tag" >&2; status=1; }
for t in $tagged; do
	if [ "$(jq -r --arg t "$t" 'select(.Action == "pass" and .Test == $t) | .Test' "$out/gate.json")" != "$t" ]; then
		echo "::error::the gate test $t did not pass" >&2
		status=1
	fi
done
exit "$status"
