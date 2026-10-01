import { directoryLabel } from "./ownerModel";

/** Individual addresses on a Slack channel, beside its directory groups.
 *
 *  A record may list people by address as well as by group. Each address is a
 *  user of a directory the channel may draw from: an ordinary channel the one
 *  that owns its workspace, a Slack Connect channel any connected one. The
 *  server checks every rule again, including that the directory actually
 *  knows the user and that the account is active; this file says what can be
 *  told from the form alone, in the server's words. */

/** A directory a channel draws from, as the form knows it. */
export type AllowedDirectory = { label: string; domains: readonly string[] };

const looksLikeAddress = /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/;

/** The addresses in typed or pasted text: split on blanks, commas and
 *  semicolons, trimmed and lowercased. Repeats are kept, so that the form can
 *  say so. */
export function parseAddresses(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

/** The domain of an address, lowercase; empty when it has none. */
export function domainOf(address: string): string {
  const at = address.lastIndexOf("@");
  return at < 0 ? "" : address.slice(at + 1).toLowerCase();
}

/** The directories in a sentence: "the directory that owns this workspace (x)",
 *  or "a connected directory". */
function drawsFrom(allowed: readonly AllowedDirectory[], ordinary: boolean): string {
  if (ordinary) return allowed.length === 1 ? `the directory that owns this workspace (${allowed[0].label})` : "the directory that owns this workspace";
  return "a connected directory";
}

/** What is wrong with one address, "" when nothing is. `groups` are the
 *  addresses of the directory groups the form knows; `allowed` the
 *  directories the channel draws from, empty when the form does not know them
 *  (the server then decides). */
export function memberProblem(address: string, groups: readonly string[], allowed: readonly AllowedDirectory[], ordinary: boolean): string {
  if (!looksLikeAddress.test(address)) return `"${address}" is not an email address`;
  if (groups.includes(address)) return `${address} is a group, not a person: enter it under Directory groups`;
  const domain = domainOf(address);
  if (allowed.length > 0 && !allowed.some((dir) => dir.domains.some((d) => d.toLowerCase() === domain))) {
    return `${address} is not a user of ${drawsFrom(allowed, ordinary)} — individual addresses come from the directories this channel draws from`;
  }
  return "";
}

/** What is wrong with the list, one sentence per fault, in order: each bad
 *  address once, then each repeat. A group address typed as a person is one
 *  of `groups`; an address in `sources` that is a person is not told apart
 *  here (the server knows the users). */
export function memberProblems(members: readonly string[], sources: readonly string[], groups: readonly string[], allowed: readonly AllowedDirectory[], ordinary: boolean): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const address of members) {
    if (seen.has(address)) {
      out.push(`${address} is listed twice`);
      continue;
    }
    seen.add(address);
    const why = memberProblem(address, [...groups, ...sources], allowed, ordinary);
    if (why) out.push(why);
  }
  return out;
}

/** The addresses that are wrong, for the chips: each address once. */
export function badMembers(members: readonly string[], sources: readonly string[], groups: readonly string[], allowed: readonly AllowedDirectory[], ordinary: boolean): Set<string> {
  const bad = new Set<string>();
  const seen = new Set<string>();
  for (const address of members) {
    if (seen.has(address) || memberProblem(address, [...groups, ...sources], allowed, ordinary)) bad.add(address);
    seen.add(address);
  }
  return bad;
}

/** Adds typed or pasted text to the list. */
export function withAddresses(members: readonly string[], text: string): string[] {
  return [...members, ...parseAddresses(text)];
}

/** "2 groups, 3 people": what feeds a channel, for a row. Empty for nothing. */
export function feedCount(groups: number, people: number): string {
  const parts: string[] = [];
  if (groups > 0) parts.push(`${groups} ${groups === 1 ? "group" : "groups"}`);
  if (people > 0) parts.push(`${people} ${people === 1 ? "person" : "people"}`);
  return parts.join(", ");
}

/** The directories a form was offered, as the allowed ones, with the label an
 *  operator knows each by. */
export function allowedDirectories(directories: readonly { workspaceId: string; domains: readonly string[] }[]): AllowedDirectory[] {
  return directories.map((dir) => ({ label: directoryLabel(dir.workspaceId, dir.domains), domains: dir.domains }));
}
