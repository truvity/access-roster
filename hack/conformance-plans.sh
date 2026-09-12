#!/usr/bin/env bash
#
# Create the four conformance plans against the suite running in the
# cluster, and print their ids -- one for the Config profile and three
# for hack/conformance_drive.py to walk.
#
# The client secrets are read from the cluster at the moment of use, go
# into a temporary directory that is removed on exit, and are never
# printed: a plan configuration is the one place they have to be written
# down, and it lives inside the suite, which is why the suite's control
# plane is not public (docs/operations/conformance.md).
#
# Usage:
#   KUBECTL="kubectl --context kernel@oidc" hack/conformance-plans.sh [<version label>]
#
# KUBECTL is how the cluster is reached (a context that authenticates
# through OIDC needs kubectl-oidc_login on PATH). The label goes into the
# plans' descriptions so a run can be told from the last one.
set -euo pipefail
K="${KUBECTL:-kubectl}"
LABEL="${1:-$(git -C "$(dirname "$0")/.." describe --tags --always 2>/dev/null || echo dev)}"
IP=$($K -n conformance get svc conformance-suite -o jsonpath='{.spec.clusterIP}')
S="http://$IP:8080"; H='X-Forwarded-Proto: https'
echo "SUITE=$S"
curl -sf -H "$H" -o /dev/null "$S/api/runner/available" || { echo "suite not answering at $S"; exit 1; }
DIR=$(mktemp -d); trap 'rm -rf "$DIR"' EXIT
secret() { $K -n access-issuer get secret "$1" -o jsonpath='{.data.client-secret}' | base64 -d; }
# Two pairs of clients (cfg/access.yaml in gitops): `conformance` and
# `conformance-2` register NO back-channel address and serve Basic OP and
# RP-Initiated Logout, whose modules fail a test that receives a logout
# token they did not expect; `conformance-bc` and `conformance-bc-2`
# register one and serve the Back-Channel plan, which expects it.
S1=$(secret conformance-client);    S2=$(secret conformance-2-client)
B1=$(secret conformance-bc-client); B2=$(secret conformance-bc-2-client)
ISS=https://access.truvity.xyz/.well-known/openid-configuration
python3 - "$DIR" "$S1" "$S2" "$B1" "$B2" "$ISS" "$LABEL" <<'PY'
import json, sys, pathlib
d, s1, s2, b1, b2, iss, label = sys.argv[1:]
common = {"server": {"discoveryUrl": iss}}
pathlib.Path(d, "config.json").write_text(json.dumps({**common, "alias": "access-issuer-config",
  "description": "access-issuer " + label + " - Config", "client": {"client_id": "conformance", "client_secret": "unused-here"}}))
pathlib.Path(d, "basic.json").write_text(json.dumps({**common, "alias": "access-issuer",
  "description": "access-issuer " + label,
  "client": {"client_id": "conformance", "client_secret": s1},
  "client2": {"client_id": "conformance-2", "client_secret": s2},
  "client_secret_post": {"client_id": "conformance", "client_secret": s1}}))
pathlib.Path(d, "backchannel.json").write_text(json.dumps({**common, "alias": "access-issuer",
  "description": "access-issuer " + label + " - Back-Channel",
  "client": {"client_id": "conformance-bc", "client_secret": b1},
  "client2": {"client_id": "conformance-bc-2", "client_secret": b2},
  "client_secret_post": {"client_id": "conformance-bc", "client_secret": b1}}))
PY
mk() { curl -s -H "$H" -X POST "$S/api/plan?planName=$1&variant=$2" -H 'Content-Type: application/json' --data-binary @"$DIR/$3" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("id") or d)'; }
BASIC='%7B%22server_metadata%22%3A%22discovery%22%2C%22client_registration%22%3A%22static_client%22%7D'
LOGOUT='%7B%22client_registration%22%3A%22static_client%22%2C%22response_type%22%3A%22code%22%7D'
echo "config      $(mk oidcc-config-certification-test-plan '' config.json)"
echo "basic       $(mk oidcc-basic-certification-test-plan "$BASIC" basic.json)"
echo "rp-logout   $(mk oidcc-rp-initiated-logout-certification-test-plan "$LOGOUT" basic.json)"
echo "backchannel $(mk oidcc-backchannel-rp-initiated-logout-certification-test-plan "$LOGOUT" backchannel.json)"
