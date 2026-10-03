#!/usr/bin/env bash
# The DynamoDB adapter, and a migration into it, against a real DynamoDB API
# (LocalStack), and a refusal to call an empty run a pass.
#
# ACCESS_ROSTER_DYNAMODB_URL names the endpoint. The tests SKIP when it is unset
# so that `go test ./...` needs nothing (the adapter runs the same suite over a
# fake there); this script is the one place that sets it, so it is also the one
# place that must notice the tests skipped anyway: a green run that tested
# nothing is how an adapter reaches production unproven.
set -euo pipefail

: "${ACCESS_ROSTER_DYNAMODB_URL:?set ACCESS_ROSTER_DYNAMODB_URL to the LocalStack endpoint (just test-s3 does)}"

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

go test -count=1 -v ./internal/port/dynamodb/ ./internal/migrate/ ./internal/store/ -run 'TestConformance$|TestAMissingTable|TestCreatingAnExistingTable|TestTheTableHasTTL|DynamoDB' 2>&1 | tee "$out"

# The only skips allowed are the ports a DynamoDB table does not hold; each says so.
if grep -- '--- SKIP' "$out" | grep -v -E 'TestConformance/(blob|sealing|identity)/'; then
    echo "FAIL: a test skipped although ACCESS_ROSTER_DYNAMODB_URL is set (only the other ports' assertions may):" >&2
    exit 1
fi

# Each of these must have RUN and passed, on the real engine.
required=(
    'TestConformance/cas/update-race'
    'TestConformance/cas/create-race'
    'TestConformance/cas/delete-if-revision'
    'TestConformance/ttl/visibility'
    'TestConformance/ttl/create-over-expired'
    'TestConformance/ttl/list-omits-expired'
    'TestConformance/ttl/index-expiry'
    'TestConformance/lease/held-cannot-be-taken'
    'TestConformance/lease/takeover-by-one'
    'TestConformance/lease/renewal-after-takeover'
    'TestConformance/paging/every-record-once'
    'TestConformance/paging/concurrent-write'
    'TestConformance/paging/foreign-token'
    'TestConformance/revisions/change-with-content'
    'TestConformance/revisions/change-on-identical-rewrite'
    'TestConformance/revisions/stale-update'
    'TestConformance/watch/put-delete'
    'TestConformance/watch/expiry'
    'TestConformance/watch/recover-by-listing'
    'TestConformance/limits/too-large'
    'TestConformance/limits/no-lifetime'
    'TestConformance/limits/permanent-family'
    'TestConformance/index/members'
    'TestConformance/trigger/notify'
    'TestAMissingTableIsUnavailableNotNotFound'
    'TestCreatingAnExistingTableIsHarmless'
    'TestTheTableHasTTLOnExpires'
    'TestMemoryToDynamoDBCopiesAndVerifies'
    'TestTheDynamoDBAdapterSharesStateAndTheTriggerAcrossStores'
)
for name in "${required[@]}"; do
    if ! grep -q -- "--- PASS: ${name} " "$out"; then
        echo "FAIL: ${name} did not run and pass" >&2
        exit 1
    fi
done
echo "ok: ${#required[@]} required tests ran against ${ACCESS_ROSTER_DYNAMODB_URL}"
