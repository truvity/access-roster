#!/usr/bin/env bash
# The deny matrix against the local installation (WP-29). `just local-deny` runs it.
#
# It starts a Compose project of its own (default name sluis-deny, with its own image names and its own host port), so a
# `just local-up` project on the same machine is left alone: it never stops or removes a container, volume or image that
# is not its own. It builds the probe, runs the matrix (go run ./tests/deny) and removes its own project, its volumes, its
# images and its state, whatever the result. The exit status is the matrix's: 0 with no violation, 1 with any.
#
# Inputs from the environment, as for `just local-up` (never from the repository):
#   SLUIS_UPSTREAM_TARGET    host:port of the upstream identity provider
#   SLUIS_KEYCLOAK_SECRETS   a file with SLUIS_LOCAL_CLIENT_SECRET (default: $SLUIS_BUILD_DIR/keycloak-secrets.env)
#   SLUIS_DENY_PROJECT       the Compose project (default sluis-deny)
#   SLUIS_DENY_PORT          the loopback port of the forwarder (default 18443)
#   SLUIS_DENY_SUBNET        a subnet for the project's network (default: the one Docker picks). Set it when the host's
#                            firewall lets only some subnets reach the upstream, for example SLUIS_DENY_SUBNET=10.99.0.0/24
#   SLUIS_DENY_KEEP=1        leave the project up afterwards (remove it yourself with `docker compose -p <name> down -v`)
#   SLUIS_DENY_REPORT        write the report to this file as well
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
project=${SLUIS_DENY_PROJECT:-sluis-deny}
case "$project" in sluis-local) echo "deny: sluis-local is the project of 'just local-up'; pick another name" >&2; exit 2 ;; esac
state=.cache/deny
seed=$state/seed
work=$state/work
image=$project/probe:dev
host=sluis.dev.local.test
export SLUIS_LOCAL_SEED=$root/$seed
export SLUIS_LOCAL_PORT=${SLUIS_DENY_PORT:-18443}

[ -n "${SLUIS_UPSTREAM_TARGET:-}" ] || { echo "deny: SLUIS_UPSTREAM_TARGET is not set; source the run.env of the build" >&2; exit 1; }
secrets=${SLUIS_KEYCLOAK_SECRETS:-${SLUIS_BUILD_DIR:+$SLUIS_BUILD_DIR/keycloak-secrets.env}}
[ -n "${secrets:-}" ] && [ -r "$secrets" ] || { echo "deny: SLUIS_KEYCLOAK_SECRETS does not name a readable file" >&2; exit 1; }

# The same project file as `just local-up`, with its image names moved under this project's name, so that building here
# cannot retag the images of another project. The paths stay relative to deploy/local.
mkdir -p "$work"
sed "s#sluis-local/#$project/#g; s#^name: .*#name: $project#" deploy/local/compose.yaml >"$work/compose.yaml"
compose=(docker compose --project-directory deploy/local -p "$project" -f "$work/compose.yaml")
if [ -n "${SLUIS_DENY_SUBNET:-}" ]; then
	printf 'networks:\n  default:\n    ipam:\n      config:\n        - subnet: %s\n' "$SLUIS_DENY_SUBNET" >"$work/network.yaml"
	compose+=(-f "$work/network.yaml")
fi

cleanup() {
	if [ "${SLUIS_DENY_KEEP:-}" = 1 ]; then
		echo "deny: project $project left up; remove it with: docker compose -p $project down --volumes --remove-orphans" >&2
		return
	fi
	"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
	docker image ls --format '{{.Repository}}:{{.Tag}}' | grep "^$project/" | xargs -r docker image rm >/dev/null 2>&1 || true
	rm -rf "$state"
}
trap cleanup EXIT

# The state of the run: as deploy/local/local.sh prepare, below .cache/deny. Nothing is echoed.
mkdir -p "$seed/config" "$seed/ca" "$seed/credentials/store" "$seed/credentials/adapter"
go run ./tools/harness/ca -dir "$state/ca" -host "$host"
cp "$state/ca/ca.pem" "$state/ca/leaf.pem" "$state/ca/leaf.key" "$seed/ca/"
go run ./tools/harness/sign-config -config tests/installations/local/config -bootstrap tests/installations/local/bootstrap.yaml \
	-key-dir "$state/publisher" -out "$seed/config" -bootstrap-out "$seed/bootstrap.yaml"
(
	set +x
	umask 077
	set -a
	# shellcheck disable=SC1090
	. "$secrets"
	set +a
	[ -n "${SLUIS_LOCAL_CLIENT_SECRET:-}" ] || { echo "deny: the secrets file has no SLUIS_LOCAL_CLIENT_SECRET" >&2; exit 1; }
	printf '%s' "$SLUIS_LOCAL_CLIENT_SECRET" >"$seed/credentials/store/upstream-workforce"
	printf '%s' "$SLUIS_LOCAL_CLIENT_SECRET" >"$seed/credentials/adapter/upstream.workforce.client-secret"
	for c in client-dev client-example-app; do
		head -c 32 /dev/urandom | base64 -w0 | tr '+/' '-_' | tr -d '=' >"$state/$c"
		cp "$state/$c" "$seed/credentials/store/$c"
	done
)
chmod -R go-rwx "$state/ca" "$state/publisher" "$seed/credentials"
chmod 0644 "$seed/ca/ca.pem" "$seed/ca/leaf.pem"

# The executables and the images of the installation, then the project.
deploy/local/build.sh
mkdir -p dist/local/rqlite
case "$(uname -m)" in x86_64 | amd64) a=amd64 ;; *) a=arm64 ;; esac
[ -x ".cache/rqlite/linux-$a/rqlited" ] || { echo "deny: no rqlited; run 'just rqlite-fetch'" >&2; exit 1; }
install -m 0755 ".cache/rqlite/linux-$a/rqlited" dist/local/rqlite/rqlited
"${compose[@]}" build
"${compose[@]}" up -d --wait --wait-timeout 180 || {
	echo "deny: the project did not become healthy" >&2
	"${compose[@]}" ps --all >&2 || true
	exit 1
}

# The probe: one static binary on the same base as every other executable (deploy/local/Dockerfile).
ctx=$state/probe-ctx
mkdir -p "$ctx"
case "$a" in amd64) goarch=amd64 ;; *) goarch=arm64 ;; esac
CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -trimpath -o "$ctx/probe" ./tests/deny/probe
docker build -q -f deploy/local/Dockerfile --build-arg BINARY=probe -t "$image" "$ctx" >/dev/null

go run ./tests/deny -project "$project" -probe-image "$image" ${SLUIS_DENY_REPORT:+-report "$SLUIS_DENY_REPORT"}
