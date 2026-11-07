#!/usr/bin/env bash
# The local installation (docs/runtimes/local.md): prepare its state, build its images, start it, report on it, stop it.
#
#   deploy/local/local.sh up | down | status | logs [service...] | tamper | handoff | handoff-check
#
# Run it from the repository root, inside devbox, through the Justfile: `devbox run -- just local-up`.
#
# Inputs, from the environment and never from the repository:
#   SLUIS_UPSTREAM_TARGET    host:port of the upstream identity provider, which the sidecar of the adapter forwards to
#   SLUIS_KEYCLOAK_SECRETS   a file with SLUIS_LOCAL_CLIENT_SECRET, and the realm's bootstrap administrator
#                            (KC_BOOTSTRAP_ADMIN_USERNAME and _PASSWORD) to read the test users' sub (default:
#                            $SLUIS_BUILD_DIR/keycloak-secrets.env)
#   SLUIS_LOCAL_PORT         the loopback port of the forwarder (default 8443)
#   COMPOSE_PROJECT_NAME     the Compose project (default sluis-local); a second project on one machine sets this, a
#                            SLUIS_LOCAL_PORT and a SLUIS_LOCAL_TAG of its own, so that it leaves the first alone
#   SLUIS_LOCAL_TAG          the tag of the images this project builds (default dev)
#   SLUIS_LOCAL_IMAGES       build (default): build the executables and the images from this checkout; release: run the
#                            images of a release, pulled from the registry, and build nothing. The release needs
#                            SLUIS_LOCAL_VERSION (the version of the release, 2.0.0-alpha.1, without the v) or
#                            SLUIS_RELEASE_IMAGES (the release-images.txt of the release, a file or an https URL, which pins
#                            every image by its digest); SLUIS_IMAGE_PREFIX moves the namespace from ghcr.io/truvity/sluis.
#                            It also needs SLUIS_RELEASE_CATALOGUE, the audit-catalogue.yaml of the release (a file or an https
#                            URL), which the harness signs in place of the catalogue of this checkout (release 0.0.0): the
#                            writer refuses the records of a release newer than its catalogue
#   SLUIS_LOCAL_SUBNET       the subnet of the project's network (default: a free /24 of 10.99.0.0/16, chosen from the project
#                            name and kept while the project's network exists; see default_subnet). Set it where the
#                            host's firewall lets only some subnets reach the upstream
#   SLUIS_LOCAL_CLI          the sluis command-line tool the hand-off runs (default dist/local/bin/cli/sluis, which the build
#                            makes; a run from published images takes it from the release archive)
# The state of a run (the CA, the publisher key, the signed config, the subjects of the test users, the credentials, the
# throwaway root and the hand-off files) is below .cache/local and is deleted by `down`; the volumes go with it.
#
# The KeyPlan lists the wrapping keys that may receive a wrap of a data key (ADR 0006, "Who may receive a wrap"), and a
# software key is made at the first start, so `up` has two phases. The first start signs the KeyPlan with an empty list
# and starts key@ with what it needs. No actor can have a data key yet (key@ makes none for a key that is not listed), so
# the rest waits. Then `up` asks key@ for the thumbprint of its wrapping key (`key check`), keeps it in $state/recipients,
# signs the KeyPlan again with it, puts the document in the config volume and waits until key@ sees its key in the list.
# Then it starts everything else. A later `up` of the same run signs the list at once and has one phase. The committed
# source, tests/installations/local/config/key-plan.yaml, never holds a thumbprint.
#
# Then `up` hands the boundary's intermediate off (docs/runtimes/local.md, "The hand-off"): the real `sluis key request`
# against key@, a throwaway root made for the run certifies the request (tools/harness/certifier, which stands in for
# ritueel), and the real `sluis key install` checks the answer against the root list and the root's pin and installs it
# through key@. `handoff` runs the same steps again and changes nothing: the request, the certificate and the install
# are all kept. `handoff-check` runs them again and fails if anything was made, issued or installed anew.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
state=.cache/local
seed=$state/seed
export SLUIS_LOCAL_SEED=$root/$seed
compose=(docker compose -f deploy/local/compose.yaml)
# The images: built from this checkout, or the images of a release (deploy/local/compose.release.yaml replaces them).
images_mode=${SLUIS_LOCAL_IMAGES:-build}
exec_key=/sluis
case "$images_mode" in
build) ;;
release)
	compose+=(-f deploy/local/compose.release.yaml)
	exec_key=/usr/libexec/sluis/actors/key
	;;
*) echo "local: SLUIS_LOCAL_IMAGES is '$images_mode', want build or release" >&2; exit 2 ;;
esac

# release_pins exports one variable per image of release-images.txt (SLUIS_RELEASE_IMAGES), each set to the image's
# reference with its digest, which compose.release.yaml reads. Every line is `<repository>:<tag>@sha256:<digest>`.
release_pins() {
	local src=${SLUIS_RELEASE_IMAGES:-} list line repo name n=0
	[ -n "$src" ] || return 0
	case "$src" in
	https://*) list=$(curl --fail --silent --show-error --location "$src") || { echo "local: $src could not be read" >&2; return 1; } ;;
	*) [ -r "$src" ] || { echo "local: SLUIS_RELEASE_IMAGES=$src is not a readable file" >&2; return 1; }; list=$(<"$src") ;;
	esac
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		[[ "$line" =~ ^[a-z0-9./:_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$ ]] || { echo "local: '$line' is not <repository>:<tag>@sha256:<digest>" >&2; return 1; }
		repo=${line%%@*}
		repo=${repo%:*}
		name=${repo##*/}
		export "SLUIS_IMAGE_${name//-/_}=$line"
		n=$((n + 1))
	done <<<"$list"
	[ "$n" -gt 0 ] || { echo "local: $src lists no image" >&2; return 1; }
	# Every image the project runs must be pinned: a variable left unset would fall back to the tag, and the project would
	# run some images by digest and the rest by tag without a word.
	local want var missing=()
	want=$(grep -o 'SLUIS_IMAGE_[A-Za-z0-9_]*' deploy/local/compose.release.yaml | grep -v '^SLUIS_IMAGE_PREFIX$' | sort -u)
	for var in $want; do
		[ -n "${!var:-}" ] || missing+=("$var")
	done
	if [ "${#missing[@]}" -gt 0 ]; then
		echo "local: $src does not pin ${missing[*]}; every image the project runs must be in it" >&2
		return 1
	fi
}
if [ "$images_mode" = release ]; then
	if [ -n "${SLUIS_RELEASE_IMAGES:-}" ]; then
		release_pins
	else
		echo "local: WARNING: SLUIS_RELEASE_IMAGES is not set, so every image is pulled by the tag SLUIS_LOCAL_VERSION=${SLUIS_LOCAL_VERSION:-} and not pinned by digest; a tag can move" >&2
	fi
fi

# release_version prints the version of the release whose images run: SLUIS_LOCAL_VERSION, or the tag of the signer's image in
# release-images.txt (every image of a release has the same tag).
release_version() {
	local ref v=${SLUIS_LOCAL_VERSION:-}
	if [ -z "$v" ]; then
		ref=${SLUIS_IMAGE_actor_signer:-}
		ref=${ref%@*}
		v=${ref##*:}
	fi
	[[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "local: the version of the release is '$v'; set SLUIS_LOCAL_VERSION (2.0.0-alpha.1, without the v)" >&2; return 1; }
	printf '%s' "$v"
}
# release_catalogue puts the audit catalogue of the release at $1, in place of the catalogue of this checkout. The emitters of a
# release report its version in every record, and the writer refuses a record of a release newer than its catalogue
# (REQ-AUDIT-146); the committed catalogue names 0.0.0. The release ships audit-catalogue.yaml (a file or an https URL in
# SLUIS_RELEASE_CATALOGUE), and the harness signs it here as the operator's pipeline signs it in production. A catalogue for
# another version than the images' is refused.
release_catalogue() {
	local dest=$1 src=${SLUIS_RELEASE_CATALOGUE:-} want got
	[ -n "$src" ] || { echo "local: SLUIS_LOCAL_IMAGES=release needs SLUIS_RELEASE_CATALOGUE, the audit-catalogue.yaml of the release: the catalogue of this checkout names release 0.0.0, and the writer refuses the records of a newer release" >&2; return 1; }
	want=$(release_version) || return 1
	case "$src" in
	https://*) curl --fail --silent --show-error --location --output "$dest" "$src" || { echo "local: $src could not be read" >&2; return 1; } ;;
	*) [ -r "$src" ] || { echo "local: SLUIS_RELEASE_CATALOGUE=$src is not a readable file" >&2; return 1; }; cp "$src" "$dest" ;;
	esac
	got=$(sed -nE 's/^  release: *([^ ]+) *$/\1/p' "$dest" | head -n1)
	[ "$got" = "$want" ] || { echo "local: the catalogue is for the release '$got', the project runs '$want'" >&2; return 1; }
}

root_dir=$state/root         # the throwaway root; its key is in $root_dir/private and is never mounted into a container
handoff_dir=$state/handoff   # requests/ and answers/ of the hand-off
handoff_stem=dev-x509-intermediate

# cidr_range prints the first and last address of an IPv4 CIDR as integers.
cidr_range() {
	local ip=${1%/*} bits=${1#*/} a b c d lo
	IFS=. read -r a b c d <<<"$ip"
	lo=$(((a << 24) | (b << 16) | (c << 8) | d))
	lo=$((lo & (0xFFFFFFFF << (32 - bits) & 0xFFFFFFFF)))
	echo "$lo $((lo | (0xFFFFFFFF >> bits)))"
}

# host_routes prints the destinations of the host's IPv4 routes in every table, one a line, as CIDRs. A VPN keeps its
# routes in a table of its own that is consulted before the main one, so `ip route show` alone would miss them. The
# type word some routes start with (blackhole, unreachable, ...) is dropped and a bare address is a /32.
host_routes() {
	ip -4 route show table all 2>/dev/null | awk '{
		f = $1
		if (f ~ /^(blackhole|unreachable|prohibit|throw|local|broadcast|multicast|unicast|anycast|nat)$/) f = $2
		if (f ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) f = f "/32"
		print f
	}' || true
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
	used="$(docker network ls -q 2>/dev/null | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true) $(host_routes)"
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

# Only `up` and `tamper` (which recreates a container) give the network its subnet; down, status and logs read the project.
case "${1:-}" in
up | tamper)
	subnet=${SLUIS_LOCAL_SUBNET:-$(default_subnet)}
	mkdir -p "$state"
	printf 'networks:\n  default:\n    ipam:\n      config:\n        - subnet: %s\n' "$subnet" >"$state/network.yaml"
	compose+=(-f "$state/network.yaml")
	;;
esac
host=sluis.dev.local.test
audit_host=sluis-audit.dev.local.test

need_env() {
	[ -n "${SLUIS_UPSTREAM_TARGET:-}" ] || { echo "local: SLUIS_UPSTREAM_TARGET (the upstream's host:port) is not set; source the run.env of the build" >&2; exit 1; }
	secrets=${SLUIS_KEYCLOAK_SECRETS:-${SLUIS_BUILD_DIR:+$SLUIS_BUILD_DIR/keycloak-secrets.env}}
	[ -n "${secrets:-}" ] && [ -r "$secrets" ] || { echo "local: SLUIS_KEYCLOAK_SECRETS does not name a readable file" >&2; exit 1; }
}

# config_source copies the config sources to $state/config and adds what only the local installation has: the key of the
# boundary's intermediate in the KeyPlan (the hand-off, below). The committed source is shared with the boards' prepare
# (deploy/boards/prepare.sh), which signs a plan of its own; a purpose added there would make key@ on a board make a key on
# its card at the next start, which the board run adds deliberately.
config_source() {
	local line='    - { purpose: data, algorithm: AES-256-GCM }' t
	rm -rf "$state/config"
	mkdir -p "$state/config"
	cp tests/installations/local/config/* "$state/config/"
	if [ "$images_mode" = release ]; then
		release_catalogue "$state/config/audit-catalogue.yaml" || return 1
	fi
	[ "$(grep -cxF -- "$line" "$state/config/key-plan.yaml")" = 1 ] || { echo "local: key-plan.yaml does not hold the line '$line' once; update deploy/local/local.sh" >&2; return 1; }
	t=$(mktemp)
	AT=$line NEW='    - { purpose: x509-intermediate, algorithm: ES384, slot: 9c }' awk '$0 == ENVIRON["AT"] { print ENVIRON["NEW"] } { print }' "$state/config/key-plan.yaml" >"$t"
	cat "$t" >"$state/config/key-plan.yaml"
	rm -f "$t"
}

# sign_config signs the config sources, with the recipients of the KeyPlan when the run has learned them.
sign_config() {
	local extra=()
	[ ! -s "$state/recipients" ] || extra=(-recipients "$state/recipients")
	config_source
	go run ./tools/harness/sign-config -config "$state/config" -bootstrap tests/installations/local/bootstrap.yaml \
		-key-dir "$state/publisher" -out "$seed/config" -bootstrap-out "$seed/bootstrap.yaml" -subjects "$state/subjects" "${extra[@]}"
}

# read_subjects reads the sub of each test user that the policy binds from the identity provider's realm, through its
# admin API, as the bootstrap administrator of the secrets file. The policy binds by sub, never by user name
# (REQ-SUBJ-044), and the realm makes the value when it imports its users, so it is read at every prepare.
read_subjects() {
	go run ./tools/harness/upstream-subjects -config tests/installations/local/config -secrets "$secrets" -out "$state/subjects" ||
		{ echo "local: the subjects of the test users could not be read from the identity provider's realm" >&2; exit 1; }
}

# prepare makes the state of the run: the harness CA and the forwarder's leaf, the signed config and the bootstrap file
# that pins its publisher, and the credentials. It prints no secret.
prepare() {
	need_env
	mkdir -p "$seed/config" "$seed/ca" "$seed/credentials/store"
	go run ./tools/harness/ca -dir "$state/ca" -host "$host,$audit_host"
	cp "$state/ca/ca.pem" "$state/ca/leaf.pem" "$state/ca/leaf.key" "$seed/ca/"
	read_subjects
	sign_config
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
		for c in client-dev client-example-app; do
			[ -s "$state/$c" ] || head -c 32 /dev/urandom | base64 -w0 | tr '+/' '-_' | tr -d '=' >"$state/$c"
			cp "$state/$c" "$seed/credentials/store/$c"
		done
	)
	chmod -R go-rwx "$state/ca" "$state/publisher" "$seed/credentials"
	chmod 0644 "$seed/ca/ca.pem" "$seed/ca/leaf.pem"
}

images() {
	if [ "$images_mode" = release ]; then
		[ -n "${SLUIS_LOCAL_VERSION:-}${SLUIS_RELEASE_IMAGES:-}" ] || { echo "local: SLUIS_LOCAL_IMAGES=release needs SLUIS_LOCAL_VERSION or SLUIS_RELEASE_IMAGES" >&2; exit 1; }
		"${compose[@]}" pull --quiet || { echo "local: the images of the release could not be pulled" >&2; exit 1; }
		return 0
	fi
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
	if [ ! -s "$state/recipients" ]; then
		"${compose[@]}" up -d --wait --wait-timeout 180 key || { echo "local: key@ and what it needs did not become healthy; see 'just local-logs key store'" >&2; exit 1; }
		list_recipients
	fi
	"${compose[@]}" up -d --wait --wait-timeout 180 || { echo "local: the project did not become healthy; see 'just local-status' and 'just local-logs'" >&2; cmd_status || true; exit 1; }
	publish_vkey
	cmd_handoff
	cmd_status
}

# key_check runs key@'s check command inside its container, with the flags the container serves with, and prints its
# report: the thumbprint of the wrapping key, whether the KeyPlan lists it, and how many recipients it lists. The exit
# status is the check's.
key_check() {
	local id args
	id=$("${compose[@]}" ps -q key)
	[ -n "$id" ] || { echo "local: key@ is not running" >&2; return 1; }
	mapfile -t args < <(docker inspect --format '{{range .Config.Cmd}}{{println .}}{{end}}' "$id")
	"${compose[@]}" exec -T key "$exec_key" check "${args[@]:1}"
}

# list_recipients is the second phase of `up`: it reads the thumbprint of key@'s wrapping key, lists it in the signed
# KeyPlan, and waits until key@ reports it as listed. It does nothing when the run already lists it.
list_recipients() {
	local id="" listed="" n
	if [ ! -s "$state/recipients" ]; then
		id=$(key_check 2>/dev/null | sed -n 's/^wrapping key id: //p')
		[[ "$id" =~ ^[A-Za-z0-9_-]{43}$ ]] || { echo "local: key@'s check gave no wrapping key id" >&2; exit 1; }
		printf '# the wrapping key of key@ on this run (key check)\n%s\n' "$id" >"$state/recipients"
		sign_config >/dev/null
		chmod 0644 "$seed"/config/*.jws
		# The signed documents go into the config volume again; store@ sees the new KeyPlan and reloads it.
		"${compose[@]}" run --rm --no-deps init >/dev/null
	fi
	for n in $(seq 1 60); do
		listed=$(key_check 2>/dev/null | sed -n 's/^wrapping key listed: //p' || true)
		[ "$listed" != true ] || { echo "local: the KeyPlan lists key@'s wrapping key"; return 0; }
		sleep 1
	done
	echo "local: key@ does not see its wrapping key in the KeyPlan after 60 s; see 'just local-logs store key'" >&2
	exit 1
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

# handoff_cli runs the sluis command-line tool as root against key@'s admin socket, in a container of its own: the key
# container's image (any image of the project would do; this one is the one key@ runs from), no network, a read-only
# root file system, no capability but the one root needs to open a socket that key@'s user owns with mode 0600. The
# socket is served to root only (the peer's uid is checked by key@), and the container sees nothing of the root's key:
# the requests and the answers are directories of the run, and the trust files are public.
handoff_cli() {
	local cli=${SLUIS_LOCAL_CLI:-dist/local/bin/cli/sluis} id image project=${COMPOSE_PROJECT_NAME:-sluis-local}
	case "$cli" in /*) ;; *) cli=$root/$cli ;; esac
	[ -x "$cli" ] || { echo "local: the hand-off needs the sluis command-line tool: $cli is missing (the build makes it; a run from published images takes it from the release archive: SLUIS_LOCAL_CLI)" >&2; return 1; }
	id=$("${compose[@]}" ps -q key)
	[ -n "$id" ] || { echo "local: key@ is not running" >&2; return 1; }
	image=$(docker inspect --format '{{.Image}}' "$id")
	docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_OVERRIDE --security-opt no-new-privileges:true \
		--user 0:0 -v "${project}_run-key:/run/sluis/key:ro" -v "$cli:/sluis-cli:ro" \
		-v "$root/$handoff_dir/requests:/requests" -v "$root/$handoff_dir/answers:/answers:ro" -v "$root/$root_dir/trust:/trust:ro" \
		--entrypoint /sluis-cli "$image" "$@"
}

# handoff is steps 4 to 6 of docs/runtimes/local.md, "The hand-off": request, certify, install. It makes the throwaway root
# when the run has none, asks key@ for the request only when the run has none (a request is audited, and a second one for
# the same stem is refused), has the root certify a request that has no answer, and installs the answer. The output of the
# install says "installed" the first time and "already-installed" after.
cmd_handoff() {
	local pin out
	need_env_quiet
	mkdir -p "$handoff_dir/requests" "$handoff_dir/answers"
	# The key of the request lives in key@'s state volume. A volume made again with this state kept (a `docker volume rm`, or a
	# `docker compose down -v` without `local-down`) holds another key, and the answer in the state is for the old one: `key
	# install` would refuse it as key-mismatch. The creation time of the volume tells, so it is said here and not after an install.
	local vol_now vol_then
	vol_now=$(docker volume inspect --format '{{.CreatedAt}}' "${COMPOSE_PROJECT_NAME:-sluis-local}_state-key" 2>/dev/null) || vol_now=""
	if [ -s "$handoff_dir/key-volume" ]; then
		vol_then=$(<"$handoff_dir/key-volume")
		[ "$vol_then" = "$vol_now" ] || { echo "local: the volumes of this run were made again, and the hand-off in $handoff_dir was made for the old key (key install would refuse it as key-mismatch); run 'just local-down' and start again" >&2; return 1; }
	fi
	go run ./tools/harness/certifier init -dir "$root_dir" || return 1
	pin=$(<"$root_dir/trust/root.pin")
	if [ ! -s "$handoff_dir/requests/$handoff_stem.csr.pem" ]; then
		handoff_cli key request --boundary dev --trust-domain dev.local.test --dns-zone dev.local.test --out /requests ||
			{ echo "local: sluis key request failed; see 'just local-logs key'" >&2; return 1; }
		printf '%s' "$vol_now" >"$handoff_dir/key-volume"
	fi
	go run ./tools/harness/certifier certify -dir "$root_dir" -requests "$handoff_dir/requests" -answers "$handoff_dir/answers" || return 1
	out=$(handoff_cli key install /answers --boundary dev --requests /requests --ca-bundle /trust/ca-bundle.pem \
		--root-list /trust/root-list.json --root-pin "$pin") ||
		{ printf '%s\n' "$out" >&2; echo "local: sluis key install failed. see 'just local-logs key'" >&2; return 1; }
	printf '%s\n' "$out"
	HANDOFF_OUT=$out
}

# handoff_check is the idempotency smoke: a second hand-off changes nothing. The certificate is the same bytes, the request is
# the same bytes, and the install says it is already installed (a certificate that had to be installed again would say
# "installed"). It does not run key@'s request again, which would be audited.
cmd_handoff_check() {
	local cert=$handoff_dir/answers/$handoff_stem.cert.pem csr=$handoff_dir/requests/$handoff_stem.csr.pem before_cert before_csr
	[ -s "$cert" ] && [ -s "$csr" ] || { echo "handoff-check: no hand-off in this run; run 'just local-up' first" >&2; exit 1; }
	before_cert=$(sha256sum "$cert") before_csr=$(sha256sum "$csr")
	cmd_handoff >/dev/null || exit 1
	[ "$before_cert" = "$(sha256sum "$cert")" ] || { echo "handoff-check: FAILED: the certificate was issued again" >&2; exit 1; }
	[ "$before_csr" = "$(sha256sum "$csr")" ] || { echo "handoff-check: FAILED: the request was made again" >&2; exit 1; }
	case "$HANDOFF_OUT" in
	*"$handoff_stem: already-installed"*) ;;
	*) echo "handoff-check: FAILED: the second install did not say already-installed: $HANDOFF_OUT" >&2; exit 1 ;;
	esac
	# The audit log agrees: key@ audited one install of this purpose, whatever the number of starts, and the record is the
	# real one (the purpose and the trust sequence of the answer). The indexer follows the log a few seconds behind.
	local recs="" n
	for n in $(seq 1 30); do
		recs=$(SLUIS_LOCAL_PORT=${SLUIS_LOCAL_PORT:-8443} go run ./tools/harness/audit-search -ca "$state/ca/ca.pem" -json 'action:key.certificate.install' 2>/dev/null | grep -c '"event_code":"key.certificate.install"' || true)
		[ "${recs:-0}" -ge 1 ] && break
		sleep 2
	done
	[ "${recs:-0}" = 1 ] || { echo "handoff-check: FAILED: the audit log has ${recs:-0} records of key.certificate.install, want 1" >&2; exit 1; }
	echo "handoff-check: the hand-off of $handoff_stem is in place, a second run changed nothing, and the audit log holds one install"
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
handoff) cmd_handoff ;;
handoff-check) cmd_handoff_check ;;
*) echo "usage: local.sh up | down | status | logs [service...] | tamper | handoff | handoff-check" >&2; exit 2 ;;
esac
