#!/usr/bin/env bash
#
# Run every module of a conformance plan, one after another.
#
# The suite's own page has no "run all": each module is a separate click,
# and the Basic OP plan has THIRTY of them. This starts them in order,
# waits for each to reach a terminal state, and prints the result — so
# the clicking that is left is only the part that genuinely needs a
# person, which is completing the sign-in at the provider.
#
# A module that is waiting for a browser says so, with the URL to open.
# Everything else runs unattended, which on the Basic OP plan is most of
# it: once the issuer holds a sign-in, the modules that do not force a
# fresh one complete on their own.
#
# Usage:
#   hack/conformance-run.sh <plan-id> [--from <module>]
#
#   --from   skip to a module by name, to resume after a failure rather
#            than re-run the ones that already passed.
#
# The suite is at https://localhost.emobix.co.uk:8443 — a public name
# that resolves to 127.0.0.1, which is how it gets a real certificate
# while running on a laptop. `-k` is for that certificate.
set -euo pipefail

SUITE="${SUITE:-https://localhost.emobix.co.uk:8443}"
PLAN="${1:?usage: conformance-run.sh <plan-id> [--from <module>]}"
shift || true

FROM=""
while [ $# -gt 0 ]; do
    case "$1" in
        --from) FROM="$2"; shift 2 ;;
        *)      echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

api() { curl -sk --max-time 30 "$@"; }

modules=$(api "$SUITE/api/plan/$PLAN" | python3 -c '
import json, sys
plan = json.load(sys.stdin)
for module in plan.get("modules", []):
    print(module["testModule"])')

[ -n "$modules" ] || { echo "plan $PLAN has no modules — is the id right?" >&2; exit 1; }

total=$(printf '%s\n' "$modules" | wc -l)
echo "plan $PLAN: $total module(s)"
echo

passed=0
failed=0
skipping=${FROM:+yes}

for module in $modules; do
    if [ -n "$skipping" ]; then
        [ "$module" = "$FROM" ] && skipping="" || { echo "  skipped  $module"; continue; }
    fi

    id=$(api -X POST "$SUITE/api/runner?test=$module&plan=$PLAN" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')

    if [ -z "$id" ]; then
        echo "  FAILED   $module (the suite would not start it)"
        failed=$((failed + 1))
        continue
    fi

    # Poll to a terminal state. WAITING means a person has to finish a
    # sign-in in a browser, so say where rather than sit there silently.
    told=""
    for _ in $(seq 1 120); do
        info=$(api "$SUITE/api/info/$id")
        status=$(printf '%s' "$info" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))')
        result=$(printf '%s' "$info" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("result","") or "")')

        if [ "$status" = "WAITING" ] && [ -z "$told" ]; then
            echo "  waiting  $module — finish the sign-in at $SUITE/log-detail.html?log=$id"
            told=yes
        fi

        [ "$status" = "FINISHED" ] && break
        sleep 5
    done

    case "$result" in
        PASSED|WARNING)
            echo "  $result   $module"
            passed=$((passed + 1))
            ;;
        *)
            echo "  ${result:-TIMEOUT}  $module — $SUITE/log-detail.html?log=$id"
            failed=$((failed + 1))
            ;;
    esac
done

echo
echo "$passed passed, $failed not"
echo "plan: $SUITE/plan-detail.html?plan=$PLAN"
[ "$failed" -eq 0 ]
