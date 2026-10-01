import { directoryLabel } from "./ownerModel";

/** What a Slack channel's members are drawn from: DIRECTORY groups, by
 *  address, from the directories access-roster has connected. Never internal
 *  groups. The server decides which directories a form may offer (an ordinary
 *  channel its workspace's owning directory's, a Slack Connect channel any);
 *  this file only lays the answer out for a picker and says where the chosen
 *  groups land. */

/** One group a picker offers, with the directory it belongs to. */
export type SourceOption = {
  email: string;
  /** The directory workspace id; empty for a group no connected directory holds. */
  directory: string;
  /** The directory as an operator knows it: its id and domains. */
  label: string;
  members: number;
};

/** The label of a group no connected directory holds any more. */
export const unknownDirectoryLabel = "not in a connected directory";

/** Every group the server offered, grouped by directory (in label order) and
 *  sorted by address inside it, which is the order a grouped picker needs. */
export function sourceOptions(
  directories: readonly { workspaceId: string; domains: readonly string[]; groups: readonly { email: string; members: number }[] }[],
): SourceOption[] {
  const out: SourceOption[] = [];
  for (const dir of directories) {
    const label = directoryLabel(dir.workspaceId, dir.domains);
    for (const group of dir.groups) {
      out.push({ email: group.email, directory: dir.workspaceId, label, members: group.members });
    }
  }
  return out.sort((a, b) => a.label.localeCompare(b.label) || a.email.localeCompare(b.email));
}

/** The option for a chosen address: what the picker offered, or a stand-in
 *  for a group it no longer does, so a record naming one still shows it. */
export function optionOf(options: readonly SourceOption[], email: string): SourceOption {
  return options.find((option) => option.email === email) ?? { email, directory: "", label: unknownDirectoryLabel, members: 0 };
}

/** The options whose address or directory contains every word typed, in any
 *  case: an operator looks for `eng`, or for a domain, or both. */
export function matchingOptions(options: readonly SourceOption[], query: string): SourceOption[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return options.filter((option) => {
    const text = `${option.email} ${option.label}`.toLowerCase();
    return words.every((word) => text.includes(word));
  });
}

/** One side of a channel: the workspace and the directory that owns it. */
export type Side = { workspace: string; owner: string };

/** Which of the chosen groups land on one side. */
export type Landing = { workspace: string; owner: string; groups: string[] };

/** Where the chosen groups land. A person joins on the side whose
 *  workspace's owning directory serves their address, so a group lands on
 *  the sides that directory owns. A group whose directory owns no side of
 *  the channel reaches nobody: its members have no account path on any side
 *  and would be held. That is allowed, and said. */
export function landings(sides: readonly Side[], sources: readonly string[], options: readonly SourceOption[]): { perSide: Landing[]; unreached: string[] } {
  const chosen = sources.map((email) => optionOf(options, email));
  const perSide = sides
    .filter((side) => side.workspace !== "")
    .map((side) => ({
      workspace: side.workspace,
      owner: side.owner,
      groups: side.owner === "" ? [] : chosen.filter((option) => option.directory === side.owner).map((option) => option.email),
    }));
  const unreached = chosen.filter((option) => !sides.some((side) => side.owner !== "" && side.owner === option.directory)).map((option) => option.email);
  return { perSide, unreached };
}

/** The sentence for one side's landing. */
export function landingSentence(landing: Landing, ownerName: string): string {
  if (landing.owner === "") return `${landing.workspace} has no owning directory: nobody joins from it until one is set.`;
  if (landing.groups.length === 0) return `${landing.workspace} (${ownerName}): none of the chosen groups; nobody joins from it.`;
  const n = landing.groups.length;
  return `${landing.workspace} (${ownerName}): ${n} chosen ${n === 1 ? "group" : "groups"}, ${landing.groups.join(", ")}.`;
}

/** The warning for groups no side of the channel can place anybody from, or
 *  empty when every group lands somewhere. */
export function unreachedWarning(unreached: readonly string[]): string {
  if (unreached.length === 0) return "";
  const list = unreached.join(", ");
  return unreached.length === 1
    ? `${list} belongs to a directory that owns no side of this channel: its members have no account path on any side, and would be held.`
    : `${list} belong to directories that own no side of this channel: their members have no account path on any side, and would be held.`;
}
