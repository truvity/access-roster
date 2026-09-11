#!/usr/bin/env bash
#
# Complete the browser half of a conformance run without a browser.
#
# The suite asks a PERSON to visit a URL and sign in. Nothing in that
# flow is JavaScript — it is a chain of redirects and one form POST — so
# this follows it with curl, and signs in through RECOVERY, which is a
# ServiceAccount token rather than a person at a Google prompt.
#
# What that buys: the attended plans run unattended. Basic OP is thirty
# modules, each of which would otherwise be a sign-in by hand.
#
# It signs in FRESH each time it is asked to, because that is what the
# logout modules exist to check: they end the sign-in, and the next
# module must find it gone.
#
# Usage:
#   hack/conformance-drive.sh <plan-id> [--from <module>]
#
# Run ONE plan at a time. The suite serves every plan's callback under
# its `alias`, so starting a test in a plan that shares an alias with a
# running one interrupts that one — "Stopping test due to alias
# conflict", which reads like a hang.
set -euo pipefail

SUITE="${SUITE:-https://localhost.emobix.co.uk:8443}"
ISSUER="${ISSUER:-https://access.truvity.xyz}"
CONTEXT="${CONTEXT:-kernel@oidc}"
PLAN="${1:?usage: conformance-drive.sh <plan-id> [--from <module>]}"
shift || true

FROM=""
while [ $# -gt 0 ]; do
    case "$1" in
        --from) FROM="$2"; shift 2 ;;
        *)      echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

api() { curl -sk --max-time 30 "$@"; }
field() { python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1],"") or "")' "$1"; }

# visit follows one URL the suite handed us, signing in on the way if the
# issuer asks. The cookie jar is per-visit: a stale jar would carry a
# sign-in the logout modules have just ended, and they would pass by
# accident.
visit() {
    local url="$1" jar="$work/jar-$RANDOM"
    : > "$jar"

    local landed
    landed=$(curl -sk -c "$jar" -b "$jar" -L -o "$work/page.html" -w '%{url_effective}' --max-time 30 "$url")

    # Signed in already, or the issuer completed silently: nothing to do.
    case "$landed" in
        "$ISSUER"/login*) ;;
        *) return 0 ;;
    esac

    local state
    state=$(python3 -c '
import re, sys
html = open(sys.argv[1], encoding="utf-8", errors="replace").read()
m = re.search(r"name=\"state\" value=\"([^\"]+)\"", html)
print(m.group(1) if m else "")' "$work/page.html")
    [ -n "$state" ] || { echo "      no recovery form on the sign-in page" >&2; return 1; }

    local proof
    proof=$(kubectl --context "$CONTEXT" -n access-issuer create token access-issuer-recovery \
        --audience access-issuer-recovery --duration 10m)

    curl -sk -c "$jar" -b "$jar" -L -o /dev/null --max-time 30 \
        -X POST "$ISSUER/login/recovery" \
        --data-urlencode "state=$state" --data-urlencode "proof=$proof"
}

modules=$(api "$SUITE/api/plan/$PLAN" | python3 -c '
import json, sys
for module in json.load(sys.stdin).get("modules", []):
    print(module["testModule"])')
[ -n "$modules" ] || { echo "plan $PLAN has no modules — is the id right?" >&2; exit 1; }

echo "plan $PLAN: $(printf '%s\n' "$modules" | wc -l) module(s), driven unattended"
echo

passed=0; failed=0; skipping=${FROM:+yes}

for module in $modules; do
    if [ -n "$skipping" ]; then
        [ "$module" = "$FROM" ] && skipping="" || { echo "  skipped  $module"; continue; }
    fi

    id=$(api -X POST "$SUITE/api/runner?test=$module&plan=$PLAN" | field id)
    if [ -z "$id" ]; then
        echo "  FAILED   $module (the suite would not start it)"
        failed=$((failed + 1)); continue
    fi

    done_urls=""
    for _ in $(seq 1 60); do
        status=$(api "$SUITE/api/info/$id" | field status)

        # Every terminal state, not just the happy one: INTERRUPTED is
        # what an alias conflict looks like, and polling through it for
        # ten minutes is what made this look like a hang.
        case "$status" in
            FINISHED|INTERRUPTED) break ;;
        esac

        # Hand the suite the visits it is waiting for. A module can ask
        # more than once — logout asks again after ending the session.
        for url in $(api "$SUITE/api/runner/browser/$id" \
            | python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin).get("urls") or []))'); do
            case " $done_urls " in *" $url "*) continue ;; esac
            done_urls="$done_urls $url"
            visit "$url" || true
        done

        sleep 3
    done

    result=$(api "$SUITE/api/info/$id" | field result)
    status=$(api "$SUITE/api/info/$id" | field status)

    case "$result" in
        PASSED|WARNING) echo "  $result   $module"; passed=$((passed + 1)) ;;
        *)              echo "  ${result:-$status}  $module — $SUITE/log-detail.html?log=$id"
                        failed=$((failed + 1)) ;;
    esac
done

echo
echo "$passed passed, $failed not"
echo "plan: $SUITE/plan-detail.html?plan=$PLAN"
[ "$failed" -eq 0 ]
