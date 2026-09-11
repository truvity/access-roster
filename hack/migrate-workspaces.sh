#!/usr/bin/env bash
#
# Move what an operator connected from the old directory-roster release
# into the merged access-issuer release (INF-691).
#
# WHY THIS EXISTS, and why it is not a chart hook: the workspace records
# and their credentials are written by the service itself, into its own
# namespace, named and labelled after its RELEASE. The merged service
# runs as a different release in a different namespace, so it looks for
# objects that are not there — and starts with no directories connected,
# reporting nothing wrong. Every Application reads Synced and three live
# Workspaces are simply gone from the console.
#
# WHAT IT REWRITES, and why each one matters:
#
#   - a workspace record is found by LABEL SELECTOR, so
#     `app.kubernetes.io/part-of` has to become the new release. Its name
#     is cosmetic, and is changed only so the two halves cannot be
#     confused later.
#   - a credential is found by NAME, `<release>-credential-<id>-<digest>`,
#     so renaming it is not cosmetic: leave it and the record is adopted
#     with no reader behind it, which the console reports as a workspace
#     that is unhealthy for no visible reason.
#   - the session key is `<release>-session-key`. Losing it signs
#     everyone out of the console and costs nothing else, but it is free
#     to carry.
#
# It writes nothing by itself. It prints the objects it would apply, so
# the cutover is a diff somebody read rather than a command somebody
# trusted. Pipe it to `kubectl apply -f -` when you have read it.
#
# Usage:
#   hack/migrate-workspaces.sh [--context CTX] [--from NS] [--to NS] \
#                              [--from-release NAME] [--to-release NAME]
#
# Defaults are the live installation's.
set -euo pipefail

CONTEXT="${CONTEXT:-kernel@oidc}"
FROM_NS="${FROM_NS:-directory-roster}"
TO_NS="${TO_NS:-access-issuer}"
FROM_RELEASE="${FROM_RELEASE:-directory-roster}"
TO_RELEASE="${TO_RELEASE:-access-issuer}"

while [ $# -gt 0 ]; do
    case "$1" in
        --context)      CONTEXT="$2"; shift 2 ;;
        --from)         FROM_NS="$2"; shift 2 ;;
        --to)           TO_NS="$2"; shift 2 ;;
        --from-release) FROM_RELEASE="$2"; shift 2 ;;
        --to-release)   TO_RELEASE="$2"; shift 2 ;;
        -h|--help)      sed -n '2,33p' "$0"; exit 0 ;;
        *)              echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

kube() { kubectl --context "$CONTEXT" -n "$FROM_NS" "$@"; }

# The selector the service itself uses. `managed-by` is a constant and
# not the release, which is why only `part-of` is rewritten below.
selector() { echo "app.kubernetes.io/managed-by=directory-roster,app.kubernetes.io/part-of=${FROM_RELEASE},directory-roster.truvity.com/kind=$1"; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

kube get configmap -l "$(selector workspace)" -o json > "$work/records.json"
kube get secret -l "$(selector credential)" -o json > "$work/creds.json"
kube get secret "${FROM_RELEASE}-session-key" -o json > "$work/session.json" 2>/dev/null || echo '{}' > "$work/session.json"

count=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("items",[])))' "$work/records.json")
if [ "$count" = "0" ]; then
    echo "# nothing to move: no workspace records in ${FROM_NS} for release ${FROM_RELEASE}" >&2
    exit 1
fi
echo "# ${count} workspace record(s) from ${FROM_NS} → ${TO_NS}" >&2

python3 - "$TO_NS" "$FROM_RELEASE" "$TO_RELEASE" "$work" <<'PY'
import hashlib
import json
import re
import sys

to_ns, from_release, to_release, work = sys.argv[1:5]


def read(name):
    with open(f"{work}/{name}.json", encoding="utf-8") as handle:
        return json.load(handle)


records, creds, session = read("records"), read("creds"), read("session")


def carry(obj):
    """One object as it must exist under the new release.

    Everything the API server owns is dropped: a resourceVersion or a uid
    from another object is refused on apply, and an ownerReference would
    point at something in a namespace that is being left behind.
    """
    meta = obj["metadata"]
    name = meta["name"]
    if name.startswith(from_release + "-"):
        name = to_release + name[len(from_release):]

    labels = dict(meta.get("labels") or {})
    if labels.get("app.kubernetes.io/part-of") == from_release:
        labels["app.kubernetes.io/part-of"] = to_release

    out = {
        "apiVersion": obj["apiVersion"],
        "kind": obj["kind"],
        "metadata": {"name": name, "namespace": to_ns, "labels": labels},
    }
    for field in ("data", "stringData", "type"):
        if field in obj:
            out[field] = obj[field]
    return out


documents = [carry(item) for item in records.get("items", [])]
documents += [carry(item) for item in creds.get("items", [])]
if session.get("metadata"):
    documents.append(carry(session))

# The check that matters, and the one a rename gets wrong in silence: a
# credential is looked up by a name the service DERIVES from the
# workspace id — `<release>-credential-<readable>-<sha256(id)[:10]>` — so
# it is not enough for the rename to look right. Recompute it here from
# the record's own id and refuse to print anything if the two disagree.
#
# Getting this wrong does not fail loudly. The record is adopted, the
# credential behind it is not found, and the console reports a workspace
# that is unhealthy with no reason a reader can act on.
expected = set()
for item in records.get("items", []):
    workspace = json.loads(item["data"]["workspace.json"])["id"]
    digest = hashlib.sha256(workspace.encode()).hexdigest()[:10]
    readable = re.sub(r"[^a-z0-9-]", "-", workspace.lower()).strip("-")[:24].strip("-")
    expected.add(f"{to_release}-credential-{readable}-{digest}")

renamed = {
    doc["metadata"]["name"]
    for doc in documents
    if doc["metadata"]["name"].startswith(f"{to_release}-credential-")
}
if renamed != expected:
    missing = ", ".join(sorted(expected - renamed)) or "none"
    extra = ", ".join(sorted(renamed - expected)) or "none"
    sys.exit(
        f"refusing to print: the renamed credentials are not what the service will look for.\n"
        f"  it will look for: {missing}\n"
        f"  this produced:    {extra}"
    )

print(json.dumps({"apiVersion": "v1", "kind": "List", "items": documents}, indent=2))
PY
