#!/usr/bin/env bash
#
# Clean up after the INF-691 cutover.
#
# Two separate messes, both of which need a person because neither will
# resolve on its own.
#
# 1. A STUCK ValkeyCluster. `directory-roster`'s store was pruned with
#    foreground propagation, so it waits for its dependents -- and the
#    Valkey operator keeps recreating them, because the cluster object
#    still exists. The tell is that its pod, StatefulSet and Service are
#    a few SECONDS old however long you watch. Dropping the finalizer
#    lets the object go, and the dependents are garbage-collected by
#    their owner references.
#
# 2. ORPHANS. The two retired Applications were pruned without a cascade,
#    so everything they owned is still running with a tracking-id naming
#    an Application that no longer exists. Nothing owns them, so nothing
#    will ever prune them -- and an orphaned HTTPRoute still competes for
#    its hostname. This is the trap the handover's own traps section
#    describes.
#
# WHAT IS DELIBERATELY KEPT, and the reason each would hurt:
#
#   - the `directory-roster` NAMESPACE, and the access-proxy-sessions
#     ValkeyCluster in it: that store is HUBBLE's, not the console's.
#     Moving it is a separate change.
#   - the workspace records and credentials the old release wrote: the
#     migration COPIED them, and they are what makes the rollback a
#     revert. They carry no tracking-id, so nothing below matches them.
#
# It prints what it will do and asks once. Nothing is deleted until you
# answer.
set -euo pipefail

CONTEXT="${CONTEXT:-kernel@oidc}"
NS="${NS:-directory-roster}"

kube() { kubectl --context "$CONTEXT" -n "$NS" "$@"; }

# The objects the two retired Applications owned. Written out rather than
# selected by label: a label selector here would also match what the
# service itself wrote, which is the one thing that must survive.
declare -A ORPHANS=(
  [configmap]="directory-console-access-proxy directory-roster-consumers directory-roster-policy"
  [deployment]="directory-console-access-proxy directory-roster"
  [httproute]="directory-console-access-proxy-prefix directory-roster directory-roster-bootstrap"
  [networkpolicy]="directory-console-access-proxy directory-roster"
  [role]="directory-roster"
  [rolebinding]="directory-roster"
  [securitypolicy]="directory-console-access-proxy"
  [service]="directory-console-access-proxy directory-roster directory-roster-console"
  [serviceaccount]="directory-roster directory-roster-recovery"
)

echo "Context $CONTEXT, namespace $NS."
echo
echo "WILL CLEAR the stuck finalizer on ValkeyCluster/directory-roster."
echo
echo "WILL DELETE these orphans:"
for kind in $(printf '%s\n' "${!ORPHANS[@]}" | sort); do
  for name in ${ORPHANS[$kind]}; do
    printf '  %-16s %s\n' "$kind" "$name"
  done
done
echo
echo "WILL KEEP: the namespace, the access-proxy-sessions Valkey (hubble's"
echo "sessions), and every workspace record and credential."
echo

# The guard that matters. If any of these is missing the cluster is not
# in the state this script was written for, and deleting from it is a
# guess.
for want in "svc/valkey-access-proxy-sessions" "valkeycluster/access-proxy-sessions"; do
  if ! kube get "$want" >/dev/null 2>&1; then
    echo "REFUSING: $want is not here, and this script assumes it is." >&2
    echo "Nothing has been changed." >&2
    exit 1
  fi
done

records=$(kube get configmap -l directory-roster.truvity.com/kind=workspace \
  --no-headers 2>/dev/null | wc -l)
if [ "$records" -eq 0 ]; then
  echo "REFUSING: no workspace records here, so this is not the namespace" >&2
  echo "the cutover left behind. Nothing has been changed." >&2
  exit 1
fi
echo "Checked: hubble's store is present, and $records workspace record(s) are here to keep."
echo

read -r -p "Proceed? [yes/NO] " answer
[ "$answer" = "yes" ] || { echo "Nothing done."; exit 0; }

echo
echo "--- releasing the stuck ValkeyCluster"
kube patch valkeycluster directory-roster --type=merge \
  -p '{"metadata":{"finalizers":null}}' 2>&1 || echo "  (already gone)"

echo
echo "--- deleting the orphans"
for kind in $(printf '%s\n' "${!ORPHANS[@]}" | sort); do
  # --ignore-not-found so a re-run is a no-op rather than an error.
  kube delete "$kind" ${ORPHANS[$kind]} --ignore-not-found
done

echo
echo "--- what is left in $NS"
kube get all 2>/dev/null | head -20
echo
echo "Workspace records kept: $(kube get configmap -l directory-roster.truvity.com/kind=workspace --no-headers 2>/dev/null | wc -l)"
