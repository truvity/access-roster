import type { HeldGroup } from "./gen/directoryroster/v1/access_pb";

/** Renders the whole reason a group is held as one line, walking
 *  `impliedBy` one hop at a time until a directly-granted entry ends the
 *  chain: `stage:k8s:viewer ← implied by stage:k8s:operator ← implied by
 *  stage:k8s:admin ← wildcard *:k8s:admin ← directory group
 *  sre@example.com`.
 *
 *  Walked here, in the frontend, rather than by the server: the server
 *  already sends every [HeldGroup] a proof holds in one Explain call, so
 *  the whole graph needed to walk `impliedBy` is on the page already, and
 *  a second server round trip (or a recursive proto message) would buy
 *  nothing a client-side lookup by group name does not already give for
 *  free. */
export function formatChain(held: HeldGroup, all: readonly HeldGroup[]): string {
  const segments: string[] = [held.group];
  let current: HeldGroup | undefined = held;
  const walked = new Set<string>([held.group]);

  while (current) {
    if (current.impliedBy) {
      segments.push(`implied by ${current.impliedBy}`);
      // A cycle should never occur -- the policy's implies graph is
      // checked acyclic at load -- but a formatter must never hang on
      // data it did not itself validate.
      if (walked.has(current.impliedBy)) break;
      walked.add(current.impliedBy);
      current = routeFor(all, current.impliedBy);
      continue;
    }

    if (current.wildcard && current.grantedByKey) {
      segments.push(`wildcard ${current.grantedByKey}`);
    }
    const vias = viaSegment(current.via);
    if (vias) segments.push(vias);
    current = undefined;
  }

  return segments.join(" ← ");
}

/** The entry that explains how `group` itself came to be held: a direct
 *  grant (concrete or wildcard key) if one exists, else another inherited
 *  entry to keep walking from, else whatever is first. */
function routeFor(all: readonly HeldGroup[], group: string): HeldGroup | undefined {
  const candidates = all.filter((h) => h.group === group);
  return candidates.find((h) => h.grantedByKey) ?? candidates.find((h) => h.impliedBy) ?? candidates[0];
}

/** The root of a chain: the directory groups or matcher that put the
 *  caller in the group, joined onto one segment. A bare address reads as
 *  a directory group; a matcher's own description (already a full
 *  clause, such as "signed in as x@example.com") is used as it is. */
function viaSegment(via: readonly string[]): string | undefined {
  if (via.length === 0) return undefined;
  return via.map((v) => (isBareAddress(v) ? `directory group ${v}` : v)).join(", ");
}

function isBareAddress(v: string): boolean {
  return /^[^\s@]+@[^\s@]+$/.test(v);
}
