#!/usr/bin/env bash
# The upstream identity provider of the local installation for a run that signs people in (CI, and a workstation that has
# no Keycloak of its own): a Keycloak container with the realm of realm.json, and a secrets file for the run.
#
#   tests/installations/local/idp/start.sh SECRETS_FILE
#
# Every secret is random and made here, once: the client secret of `sluis-local`, the bootstrap administrator, and the
# password and the one-time-password key of the test user alice. They go into SECRETS_FILE (mode 0600) and into the realm
# that the container imports, and nowhere else; nothing is printed. The file is the one that SLUIS_KEYCLOAK_SECRETS names for
# `just local-up`, `local-smoke` and `local-person-smoke` (docs/runtimes/local.md, "Sign-in"):
#   SLUIS_LOCAL_CLIENT_SECRET  the secret of the client `sluis-local`
#   KC_BOOTSTRAP_ADMIN_USERNAME, KC_BOOTSTRAP_ADMIN_PASSWORD   the realm's administrator, read by upstream-subjects
#   ALICE_PASSWORD, ALICE_TOTP_RAW (the key as Keycloak keeps it), ALICE_TOTP_BASE32 (the same, as an authenticator takes it)
#
# Environment:
#   SLUIS_IDP_NAME   the container's name (default sluis-idp); an old container of that name is removed first
#   SLUIS_IDP_PORT   the host port (default 8180), which upstream.yaml names in the issuer http://127.0.0.1:8180/realms/sluis-test
# The port is published on every address of the host, because the adapter's forwarder reaches it from the Compose network
# through the network's gateway: use this on a runner or a workstation you trust, not on a shared host.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
secrets=${1:?usage: start.sh SECRETS_FILE}
name=${SLUIS_IDP_NAME:-sluis-idp}
port=${SLUIS_IDP_PORT:-8180}
image=quay.io/keycloak/keycloak@sha256:3f3c5f8e03c614774b4bd9173b88391fefa4153bfc010d8012d59ad825377332 # 26.8

umask 077
rand() { openssl rand -hex "$1"; }
client=$(rand 24)
admin=$(rand 16)
alice=$(rand 16)
# Keycloak keeps the key of a one-time password as the string it made, and shows an authenticator that string in base32.
raw=$(rand 10) # twenty characters
b32=$(printf '%s' "$raw" | base32 | tr -d '=')
if [ -n "${GITHUB_ACTIONS:-}" ]; then
	for v in "$client" "$admin" "$alice" "$raw" "$b32"; do echo "::add-mask::$v"; done
fi
{
	printf 'SLUIS_LOCAL_CLIENT_SECRET=%s\n' "$client"
	printf 'KC_BOOTSTRAP_ADMIN_USERNAME=admin\nKC_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$admin"
	printf 'ALICE_PASSWORD=%s\nALICE_TOTP_RAW=%s\nALICE_TOTP_BASE32=%s\n' "$alice" "$raw" "$b32"
} >"$secrets"

realm=$(mktemp -d)
trap 'rm -rf "$realm"' EXIT
chmod 0755 "$realm"
sed -e "s/__SLUIS_LOCAL_CLIENT_SECRET__/$client/" -e "s/__ALICE_PASSWORD__/$alice/" -e "s/__ALICE_TOTP_RAW__/$raw/" \
	"$here/realm.json" >"$realm/realm.json"
chmod 0644 "$realm/realm.json"

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" -p "$port:8080" \
	-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$admin" \
	-e KC_HTTP_ENABLED=true -e KC_HOSTNAME_STRICT=false \
	-v "$realm/realm.json:/opt/keycloak/data/import/realm.json:ro" \
	"$image" start-dev --import-realm >/dev/null
for _ in $(seq 1 90); do
	if curl -fs --max-time 5 -o /dev/null "http://127.0.0.1:$port/realms/sluis-test/.well-known/openid-configuration"; then
		echo "idp: $name serves the realm sluis-test on port $port; secrets in $secrets"
		exit 0
	fi
	sleep 2
done
docker logs "$name" 2>&1 | tail -40
echo "idp: the realm did not come up" >&2
exit 1
