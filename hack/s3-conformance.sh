#!/usr/bin/env bash
# The S3 Blob and KMS Sealer adapters against a real S3 and KMS API (LocalStack),
# and a refusal to call an empty run a pass.
#
# ACCESS_ROSTER_S3_URL names the endpoint. The tests SKIP when it is unset so
# that `go test ./...` needs nothing; this script is the one place that sets it,
# so it is also the one place that must notice the tests skipped anyway (a
# renamed test, a changed gate, an endpoint nobody reads any more): a green run
# that tested nothing is how an adapter reaches production unproven.
set -euo pipefail

: "${ACCESS_ROSTER_S3_URL:?set ACCESS_ROSTER_S3_URL to the LocalStack endpoint (just test-s3 does)}"

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

go test -count=1 -v ./internal/port/s3blob/ ./internal/port/kmsseal/ 2>&1 | tee "$out"

if grep -q -- '--- SKIP' "$out"; then
    echo "FAIL: a conformance test skipped although ACCESS_ROSTER_S3_URL is set:" >&2
    grep -- '--- SKIP' "$out" >&2
    exit 1
fi

# Each of these must have RUN and passed, on the real engine.
required=(
    'TestConformance/blob/round-trip'
    'TestConformance/blob/write-if-version'
    'TestConformance/blob/list-delete'
    'TestConformanceWithSSEKMS/blob/write-if-version'
    'TestAMissingBucketIsUnavailableNotNotFound'
    'TestConformance/sealing/context'
    'TestKMSRefusesAWrongBindingAndAForeignKey'
    'TestAnAliasNamesTheKey'
)
for name in "${required[@]}"; do
    if ! grep -q -- "--- PASS: ${name} " "$out"; then
        echo "FAIL: ${name} did not run and pass" >&2
        exit 1
    fi
done
echo "ok: ${#required[@]} required conformance tests ran against ${ACCESS_ROSTER_S3_URL}"
