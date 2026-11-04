#!/usr/bin/env bash
# The local installation (docs/runtimes/local.md): prepare its state, build its images, start it, report on it, stop it.
#
#   deploy/local/local.sh up | down | status | logs [service...] | tamper
#
# Run it from the repository root, inside devbox, through the Justfile: `devbox run -- just local-up`.
#
# Inputs, from the environment and never from the repository:
#   SLUIS_UPSTREAM_TARGET    host:port of the upstream identity provider, which the sidecar of the adapter forwards to
#   SLUIS_KEYCLOAK_SECRETS   a file with SLUIS_LOCAL_CLIENT_SECRET (default: $SLUIS_BUILD_DIR/keycloak-secrets.env)
#   SLUIS_LOCAL_PORT         the loopback port of the forwarder (default 8443)
#   COMPOSE_PROJECT_NAME     the Compose project (default sluis-local); a second project on one machine sets this, a
#                            SLUIS_LOCAL_PORT and a SLUIS_LOCAL_TAG of its own, so that it leaves the first alone
#   SLUIS_LOCAL_TAG          the tag of the images this project builds (default dev)
#   SLUIS_LOCAL_SUBNET       the subnet of the project's network (default: a free /24 of 10.99.0.0/16, chosen from the project
#                            name and kept while the project's network exists; see default_subnet). Set it where the
#                            host's firewall lets only some subnets reach the upstream
# The state of a run (the CA, the publisher key, the signed config, the credentials) is below .cache/local and is
# deleted by `down`; the volumes go with it.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
state=.cache/local
seed=$state/seed
export SLUIS_LOCAL_SEED=$root/$seed
compose=(docker compose -f deploy/local/compose.yaml)

# cidr_range prints the first and last address of an IPv4 CIDR as integers.
cidr_range() {
	local ip=${1%/*} bits=${1#*/} a b c d lo
	IFS=. read -r a b c d <<<"$ip"
	lo=$(((a << 24) | (b << 16) | (c << 8) | d))
	lo=$((lo & (0xFFFFFFFF << (32 - bits) & 0xFFFFFFFF)))
	echo "$lo $((lo | (0xFFFFFFFF >> bits)))"
}

# default_subnet prints the subnet of the project's network when SLUIS_LOCAL_SUBNET is not set. Docker's own pick is the
# next free 172.x /16, which a host firewall may drop (measured on one workstation: the whole of 172.20.0.0/14 was dropped
# on the way to a service on the host's own address, so the upstream adapter stayed unhealthy), and two projects must not
# share it. So: the subnet of the project's network when it exists (a second `up` keeps it), else the first /24 of
# 10.99.0.0/16, counted from a number made of the project name, that no Docker network and no route of the host overlaps.
default_subnet() {
	local project=${COMPOSE_PROJECT_NAME:-sluis-local} have used="" start i cand lo hi ulo uhi u overlap
	have=$(docker network inspect "${project}_default" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | tr ' ' '\n' | grep -m1 '^[0-9.]*/[0-9]*$' || true)
	if [ -n "$have" ]; then echo "$have"; return; fi
	used="$(docker network ls -q 2>/dev/null | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true) $(ip -4 route show 2>/dev/null | cut -d' ' -f1 || true)"
	start=$(($(printf '%s' "$project" | cksum | cut -d' ' -f1) % 256))
	for i in $(seq 0 255); do
		cand=10.99.$(((start + i) % 256)).0/24
		read -r lo hi <<<"$(cidr_range "$cand")"
		overlap=no
		for u in $used; do
			[[ $u =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || continue
			read -r ulo uhi <<<"$(cidr_range "$u")"
			if [ "$lo" -le "$uhi" ] && [ "$ulo" -le "$hi" ]; then overlap=yes; break; fi
		done
		if [ "$overlap" = no ]; then echo "$cand"; return; fi
	done
	echo "local: no free /24 in 10.99.0.0/16; set SLUIS_LOCAL_SUBNET" >&2
	return 1
}

subnet=${SLUIS_LOCAL_SUBNET:-$(default_subnet)}
mkdir -p "$state"
printf 'networks:\n  default:\n    ipam:\n      config:\n        - subnet: %s\n' "$subnet" >"$state/network.yaml"
compose+=(-f "$state/network.yaml")
host=sluis.dev.local.test
audit_host=sluis-audit.dev.local.test

need_env() {
	[ -n "${SLUIS_UPSTREAM_TARGET:-}" ] || { echo "local: SLUIS_UPSTREAM_TARGET (the upstream's host:port) is not set; source the run.env of the build" >&2; exit 1; }
	secrets=${SLUIS_KEYCLOAK_SECRETS:-${SLUIS_BUILD_DIR:+$SLUIS_BUILD_DIR/keycloak-secrets.env}}
	[ -n "${secrets:-}" ] && [ -r "$secrets" ] || { echo "local: SLUIS_KEYCLOAK_SECRETS does not name a readable file" >&2; exit 1; }
}

# prepare makes the state of the run: the harness CA and the forwarder's leaf, the signed config and the bootstrap file
# that pins its publisher, and the credentials. It prints no secret.
prepare() {
	need_env
	mkdir -p "$seed/config" "$seed/ca" "$seed/credentials/store" "$seed/credentials/adapter"
	go run ./tools/harness/ca -dir "$state/ca" -host "$host,$audit_host"
	cp "$state/ca/ca.pem" "$state/ca/leaf.pem" "$state/ca/leaf.key" "$seed/ca/"
	go run ./tools/harness/sign-config -config tests/installations/local/config -bootstrap tests/installations/local/bootstrap.yaml \
		-key-dir "$state/publisher" -out "$seed/config" -bootstrap-out "$seed/bootstrap.yaml"
	# The credentials the config documents name: the upstream's client secret from the harness secrets file, and a random
	# secret for each client of the installation, kept across runs. Nothing is echoed.
	(
		set +x
		umask 077
		set -a
		# shellcheck disable=SC1090
		. "$secrets"
		set +a
		[ -n "${SLUIS_LOCAL_CLIENT_SECRET:-}" ] || { echo "local: the secrets file has no SLUIS_LOCAL_CLIENT_SECRET" >&2; exit 1; }
		printf '%s' "$SLUIS_LOCAL_CLIENT_SECRET" >"$seed/credentials/store/upstream-workforce"
		printf '%s' "$SLUIS_LOCAL_CLIENT_SECRET" >"$seed/credentials/adapter/upstream.workforce.client-secret"
		for c in client-dev client-example-app; do
			[ -s "$state/$c" ] || head -c 32 /dev/urandom | base64 -w0 | tr '+/' '-_' | tr -d '=' >"$state/$c"
			cp "$state/$c" "$seed/credentials/store/$c"
		done
	)
	chmod -R go-rwx "$state/ca" "$state/publisher" "$seed/credentials"
	chmod 0644 "$seed/ca/ca.pem" "$seed/ca/leaf.pem"
}

images() {
	deploy/local/build.sh
	mkdir -p dist/local/rqlite
	case "$(uname -m)" in x86_64 | amd64) a=amd64 ;; *) a=arm64 ;; esac
	[ -x ".cache/rqlite/linux-$a/rqlited" ] || { echo "local: no rqlited; run 'just rqlite-fetch'" >&2; exit 1; }
	install -m 0755 ".cache/rqlite/linux-$a/rqlited" dist/local/rqlite/rqlited
	"${compose[@]}" build
}

# health lists the services of the project that have no health check, which are the two entries and the indexer.
cmd_up() {
	prepare
	images
	"${compose[@]}" up -d --wait --wait-timeout 180 || { echo "local: the project did not become healthy; see 'just local-status' and 'just local-logs'" >&2; cmd_status || true; exit 1; }
	publish_vkey
	cmd_status
}

# publish_vkey gives the indexer the verifier key of the audit log. The writer logs the public half of its log key when it
# starts, and the indexer verifies every checkpoint with it (actors/indexer/src/config.rs); the key is public, so the
# environment of one run of init carries it into the indexer's volume. The indexer reads the file at its next round.
publish_vkey() {
	local vk="" n
	for n in $(seq 1 30); do
		vk=$("${compose[@]}" logs --no-color writer 2>&1 | grep -o '"verifier_key":"[^"]*"' | tail -1 | cut -d'"' -f4 || true)
		[ -z "$vk" ] || break
		sleep 1
	done
	[ -n "$vk" ] || { echo "local: the writer's log has no verifier key; the indexer cannot follow the log" >&2; exit 1; }
	"${compose[@]}" run --rm --no-deps -e SLUIS_AUDIT_VERIFIER_KEY="$vk" init >/dev/null
}

cmd_status() {
	need_env_quiet
	"${compose[@]}" ps --all --format '{{.Service}}\t{{.ID}}\t{{.State}}\t{{.Health}}' | sort | while IFS=$'\t' read -r svc id state health; do
		uid=$(docker inspect --format '{{.Config.User}}' "$id" | cut -d: -f1)
		# entry has no check command; the forwarder's probe goes through it.
		[ -n "$health" ] || { { [ "$svc" = entry ] || [ "$svc" = entry-audit ]; } && health="(no check; probed through the forwarder)"; }
		[ -n "$health" ] || { [ "$svc" = indexer ] && health="(no check; it waits for the log's verifier key)"; }
		printf '%-28s uid %-6s %-9s %s\n' "$svc" "${uid:-root}" "$state" "${health:--}"
	done
}

# status reads the project only; it needs no secret, but compose wants the variable its file names.
need_env_quiet() { : "${SLUIS_UPSTREAM_TARGET:=unset:0}"; export SLUIS_UPSTREAM_TARGET; }

cmd_logs() {
	need_env_quiet
	"${compose[@]}" logs --no-color --tail 200 "$@"
}

cmd_down() {
	need_env_quiet
	"${compose[@]}" down --volumes --remove-orphans
	# The volumes held the keys of the run; so does the state below .cache/local. Both go.
	rm -rf "$state"
}

# tamper is the smoke step of store@'s verification: with one signed document changed, a cold start of store@ refuses, and
# with the document back it starts again. The document is changed in the volume, as the root of the host would: one
# character is put into the payload, so that the signature no longer covers it (signed-config.md, "Verifying a document").
cmd_tamper() {
	need_env_quiet
	local vol=${COMPOSE_PROJECT_NAME:-sluis-local}_config doc=key-plan.jws image
	image=$(grep -m1 -o 'alpine@sha256:[0-9a-f]*' deploy/local/compose.yaml)
	"${compose[@]}" stop store >/dev/null
	docker run --rm -v "$vol:/c" --entrypoint sh "$image" -c \
		"cp /c/$doc /tmp/orig && sed -i 's/\"payload\": \".\{1\}/&Z/' /c/$doc && ! cmp -s /c/$doc /tmp/orig"
	# A new container, so that its log holds this start and no earlier one.
	"${compose[@]}" up -d --no-deps --force-recreate store >/dev/null 2>&1
	local refused="" state=""
	for _ in $(seq 1 30); do
		if "${compose[@]}" logs --no-color store 2>&1 | grep -q 'step 4: a signature does not verify'; then refused=yes; break; fi
		sleep 1
	done
	state=$("${compose[@]}" ps --format '{{.State}} {{.Health}}' store)
	# The document back: init copies the signed documents of the seed into the volume again.
	"${compose[@]}" run --rm --no-deps init >/dev/null 2>&1
	"${compose[@]}" up -d --no-deps --force-recreate --wait --wait-timeout 90 store >/dev/null 2>&1 || { echo "tamper: FAILED: store@ did not start with the document restored" >&2; exit 1; }
	case "$state" in *healthy*) [ "$state" != "running healthy" ] || refused="" ;; esac
	if [ "$refused" = yes ]; then
		echo "tamper: store@ refused the changed document at step 4 (it was '$state'), and started again with the document restored"
	else
		echo "tamper: FAILED: no refusal was logged, or store@ ran healthy with a changed document (state '$state')" >&2
		exit 1
	fi
}

case "${1:-}" in
up) cmd_up ;;
down) cmd_down ;;
status) cmd_status ;;
logs) shift; cmd_logs "$@" ;;
tamper) cmd_tamper ;;
*) echo "usage: local.sh up | down | status | logs [service...] | tamper" >&2; exit 2 ;;
esac
