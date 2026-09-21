// The wire enum, under this module's own words: every page is written in
// these four, and the generated name is not one of them.
import { GroupState as WireState } from "./gen/directoryroster/v1/openbao_pb";
import type { GroupCounts, PolicyRule, SecretManagerGroup, SecretManagerNamespace, SecretManagerReach } from "./gen/directoryroster/v1/openbao_pb";

/** What one group is, once what this deployment declares is laid beside
 *  what the store holds. Four, not three: a read that was REFUSED must
 *  not be drawn as a store holding nothing — the two look identical
 *  except in the status of the call, and "not applied yet" sends
 *  somebody to look at an apply that is fine. */
export type State = "bound" | "absent" | "unexpected" | "unreadable";

export function stateOf(state: GroupState | undefined): State {
  switch (state) {
    case WireState.BOUND:
      return "bound";
    case WireState.ABSENT:
      return "absent";
    case WireState.UNEXPECTED:
      return "unexpected";
    default:
      return "unreadable";
  }
}

type GroupState = SecretManagerGroup["state"];

/** The one-line summary of a namespace, in the order a reader wants it:
 *  what is wrong first. A namespace with nothing wrong says so in three
 *  words rather than in four numbers. */
export function summary(counts: GroupCounts | undefined, unreadable: boolean): string {
  if (unreadable) return "could not be read";
  const c = counts ?? { bound: 0, absent: 0, unexpected: 0, unreadable: 0 };
  const parts: string[] = [];
  if (c.unexpected) parts.push(`${c.unexpected} not declared`);
  if (c.absent) parts.push(`${c.absent} not applied yet`);
  if (c.unreadable) parts.push(`${c.unreadable} unreadable`);
  if (c.bound) parts.push(`${c.bound} bound`);
  return parts.length ? parts.join(", ") : "nothing here";
}

/** Whether a namespace has anything a reader should look at. The page
 *  sorts on this: a store is opened because something is wrong, and the
 *  namespace with the wrong thing should not be the last row. */
export function needsReading(namespace: SecretManagerNamespace): boolean {
  if (namespace.unreadable) return true;
  const c = namespace.counts;
  return Boolean(c && (c.unexpected || c.absent || c.unreadable));
}

/** The order rows are drawn in: what is wrong, then what is merely not
 *  applied, then everything else, alphabetically inside each band. */
const bandOf: Record<State, number> = { unexpected: 0, unreadable: 1, absent: 2, bound: 3 };

export function byState(a: SecretManagerGroup, b: SecretManagerGroup): number {
  const band = bandOf[stateOf(a.state)] - bandOf[stateOf(b.state)];
  return band !== 0 ? band : a.name.localeCompare(b.name);
}

/** What a group opens, in one line: the paths, with a mark on the ones
 *  it can change. Reading a team's credentials and being able to replace
 *  them are different grants, and a table that showed both as "access"
 *  would be the page's one real lie. */
export function opens(rules: PolicyRule[]): string {
  if (rules.length === 0) return "";
  return rules.map((rule) => `${rule.path}${rule.writes ? " (writes)" : ""}`).join(", ");
}

/** Whether any of a group's rules can change what it reaches. */
export function writes(rules: PolicyRule[]): boolean {
  return rules.some((rule) => rule.writes);
}

/** A person's reach, grouped by store and namespace, because that is how
 *  somebody reads it: "in devel, through these groups, they can read
 *  these prefixes". */
export type ReachGroup = { manager: string; namespace: string; environment: string; reach: SecretManagerReach[] };

export function byNamespace(reach: SecretManagerReach[]): ReachGroup[] {
  const groups = new Map<string, ReachGroup>();
  for (const one of reach) {
    const key = `${one.manager}\u0000${one.namespace}`;
    const group = groups.get(key) ?? { manager: one.manager, namespace: one.namespace, environment: one.environment, reach: [] };
    group.reach.push(one);
    groups.set(key, group);
  }
  return [...groups.values()].sort((a, b) => a.manager.localeCompare(b.manager) || a.namespace.localeCompare(b.namespace));
}

/** Every distinct path a set of reaches opens, sorted, for the sentence
 *  a person's page leads with. */
export function prefixes(reach: SecretManagerReach[]): string[] {
  const seen = new Set<string>();
  for (const one of reach) for (const rule of one.rules) seen.add(rule.path);
  return [...seen].sort();
}
