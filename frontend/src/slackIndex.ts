import type { SlackChannelRecord, ListSlackChannelsResponse } from "./gen/directoryroster/v1/slack_channels_pb";
import type { ListSlackSharedChannelsResponse, SlackSharedChannel } from "./gen/directoryroster/v1/slack_connect_pb";
import type { GetSlackStatusResponse, SlackChannelStatus, SlackMemberStatus } from "./gen/directoryroster/v1/slack_pb";
import { paths } from "./router";
import { channelKind, memberKind } from "./slackModel";
import { stateView, type StateView } from "./slackConnectModel";
import type { StateKind } from "./ui";

/** Every managed Slack channel in one list, whichever way it is managed.
 *
 *  Three things know about channels and none knows about the others: the
 *  controller's report of each workspace (what is in Slack and who is in
 *  it), the console's records of ordinary channels (fed by directory
 *  groups), and its records of Slack Connect channels. The status call
 *  also carries the policy's own channels. This file lays them side by
 *  side so a page can say "this channel" once, and so a group or a person
 *  can be asked which channels it reaches without a call of its own. */

/** How a channel is managed. */
export type ChannelKind = "policy" | "console" | "connect";

export const kindLabel: Record<ChannelKind, string> = {
  policy: "policy",
  console: "console",
  connect: "Slack Connect",
};

/** A kind in a sentence, for a reader who has not seen the three. */
export const kindSentence: Record<ChannelKind, string> = {
  policy: "defined in git, fed by internal groups",
  console: "managed on the console, fed by directory groups",
  connect: "a Slack Connect channel shared between workspaces, fed by directory groups",
};

/** One group a channel is fed by, and which side of the roster it is on. */
export type Source = { address: string; internal: boolean };

/** One workspace's side of a channel: for an ordinary channel the only one,
 *  for a Slack Connect channel the host and each workspace it is shared
 *  with. `status` is what the controller reported there, absent until it
 *  has. */
export type Side = { workspace: string; name: string; id: string; status?: SlackChannelStatus; canOperate: boolean };

export type ChannelRow = {
  kind: ChannelKind;
  /** The workspace the channel is addressed by: where it lives, or the host. */
  workspace: string;
  name: string;
  /** The Slack id, "" until the controller has seen the channel. */
  id: string;
  private: boolean;
  mode: string;
  state: StateView;
  reason: string;
  sources: Source[];
  sides: Side[];
  /** The record the channel is managed by; absent for a policy channel. */
  record?: SlackChannelRecord | SlackSharedChannel;
  /** Whether the caller may edit and delete the record. Never true for a
   *  policy channel: that is edited in git. */
  canOperate: boolean;
  /** Per-side visibility, for a Slack Connect channel whose sides differ. */
  privatePerSide: Record<string, boolean>;
  /** For a policy channel: whether the caller may take it over from git. */
  canTakeOver: boolean;
  /** For a policy channel: the people its strict mode never removes. */
  ignore: string[];
  /** For a console channel that took a policy channel over: what the report
   *  says of the superseded git entry. */
  supersedes?: string;
};

const lower = (s: string) => s.toLowerCase();

function policyState(channel: SlackChannelStatus): StateView {
  return { kind: channelKind(channel), title: channel.reason };
}

/** Every managed channel the caller may see, in workspace and name order. */
export function buildRows(
  status: GetSlackStatusResponse | undefined,
  ordinary: ListSlackChannelsResponse | undefined,
  shared: ListSlackSharedChannelsResponse | undefined,
): ChannelRow[] {
  const workspaces = status?.workspaces ?? [];
  const reported = (workspace: string) => workspaces.find((w) => w.workspace === workspace);
  const operates = (workspace: string) => reported(workspace)?.canOperate ?? false;
  const out: ChannelRow[] = [];
  const taken = new Set<string>();
  const mark = (workspace: string, status: SlackChannelStatus) => taken.add(`${workspace}|${status.name}|${status.host}|${status.id}`);

  // Slack Connect: one row per record, with every side the report has.
  for (const record of shared?.channels ?? []) {
    const def = record.channel;
    if (!def) continue;
    // The host's report names the channel's Slack id, which is the same on
    // every side and finds the others by it when their names differ.
    const onSide = (workspace: string, id: string) =>
      reported(workspace)?.channels.find((c) => c.shared && (c.host === def.host || c.host === "") && ((id !== "" && c.id === id) || c.name === def.name));
    const id = def.channelId || onSide(def.host, "")?.id || "";
    const sides: Side[] = [def.host, ...def.with].map((workspace) => {
      const found = onSide(workspace, id);
      if (found) mark(workspace, found);
      return { workspace, name: found?.name || def.name, id: found?.id ?? id, status: found, canOperate: operates(workspace) };
    });
    const hostSide = sides[0];
    out.push({
      kind: "connect",
      workspace: def.host,
      name: def.name,
      id: hostSide?.id ?? "",
      private: def.private,
      mode: "extend",
      state: stateView(record),
      reason: record.reason,
      sources: def.from.map((address) => ({ address, internal: false })),
      sides,
      record,
      canOperate: record.canOperate,
      privatePerSide: { ...def.privatePerSide },
      canTakeOver: false,
      ignore: [],
    });
  }

  // Console channels: one row per record, joined to the report by name.
  for (const record of ordinary?.channels ?? []) {
    const def = record.channel;
    if (!def) continue;
    const found = reported(def.workspace)?.channels.find((c) => c.console && c.name === def.name);
    if (found) mark(def.workspace, found);
    // A takeover: the report also holds the git entry, marked superseded;
    // it is shown on this row, not as a second row of the same address.
    const superseded = def.supersedesPolicy
      ? reported(def.workspace)?.channels.find((c) => !c.console && !c.shared && c.state === "superseded" && (c.name === def.name || (def.channelId !== "" && c.id === def.channelId)))
      : undefined;
    if (superseded) mark(def.workspace, superseded);
    out.push({
      kind: "console",
      workspace: def.workspace,
      name: def.name,
      id: found?.id || def.channelId,
      private: def.private,
      mode: def.mode || "extend",
      state: stateView({ state: record.state, reason: record.reason }),
      reason: record.reason,
      sources: def.sources.map((address) => ({ address, internal: false })),
      sides: [{ workspace: def.workspace, name: def.name, id: found?.id || def.channelId, status: found, canOperate: record.canOperate }],
      record,
      canOperate: record.canOperate,
      privatePerSide: {},
      canTakeOver: false,
      ignore: [],
      supersedes: superseded?.reason || (def.supersedesPolicy ? "Takes over a policy channel; remove it from git." : undefined),
    });
  }

  // What is left in the reports is the policy's, or a Slack Connect channel
  // whose record the caller may not read.
  for (const ws of workspaces) {
    for (const channel of ws.channels) {
      if (taken.has(`${ws.workspace}|${channel.name}|${channel.host}|${channel.id}`)) continue;
      const connect = channel.shared;
      out.push({
        kind: connect ? "connect" : "policy",
        workspace: connect && channel.host ? channel.host : ws.workspace,
        name: channel.name,
        id: channel.id,
        private: channel.private,
        mode: channel.mode || "extend",
        state: policyState(channel),
        reason: channel.reason,
        sources: channel.sources.map((address) => ({ address, internal: true })),
        sides: [{ workspace: ws.workspace, name: channel.name, id: channel.id, status: channel, canOperate: ws.canOperate }],
        canOperate: false,
        privatePerSide: {},
        canTakeOver: !connect && ws.canOperate && channel.state !== "superseded" && ordinary?.available === true,
        ignore: [...channel.ignore],
      });
    }
  }
  // A Slack Connect channel with no record is seen from each side it
  // reaches: show it once, from the side the report names as host.
  const seen = new Set<string>();
  const unique = out.filter((row) => {
    if (row.kind !== "connect" || row.record) return true;
    const key = `${row.workspace}|${row.id || row.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return unique.sort((a, b) => a.workspace.localeCompare(b.workspace) || a.name.localeCompare(b.name));
}

/** The row an address names: by name in a workspace, or by Slack id, on any
 *  side of the channel. */
export function findRow(rows: ChannelRow[], workspace: string, nameOrId: string): ChannelRow | undefined {
  return (
    rows.find((r) => r.workspace === workspace && (r.name === nameOrId || (r.id !== "" && r.id === nameOrId))) ??
    rows.find((r) => r.sides.some((s) => s.workspace === workspace && (s.name === nameOrId || (s.id !== "" && s.id === nameOrId))))
  );
}

/** The address of a channel's page. */
export function rowPath(row: Pick<ChannelRow, "workspace" | "name">): string {
  return paths.slackChannel(row.workspace, row.name);
}

/** Narrow by workspace (any side) and by kind; an empty filter keeps all. */
export function filterRows(rows: ChannelRow[], filter: { workspace?: string; kind?: string }): ChannelRow[] {
  return rows.filter(
    (row) =>
      (!filter.workspace || row.sides.some((s) => s.workspace === filter.workspace) || row.workspace === filter.workspace) &&
      (!filter.kind || row.kind === filter.kind),
  );
}

/** The people on every side of a channel, the report's rows. */
export function membersOf(row: ChannelRow): SlackMemberStatus[] {
  return row.sides.flatMap((side) => side.status?.members ?? []);
}

export type Bucket = "ok" | "will-invite" | "will-remove" | "waiting-for-them" | "held" | "other";

/** What a person's row in a channel comes to, in the words a reader uses. */
export function bucketOf(member: Pick<SlackMemberStatus, "state" | "reason">): Bucket {
  const kind: StateKind = memberKind(member);
  switch (kind) {
    case "in-channel":
      return "ok";
    case "will-invite":
      return "will-invite";
    case "will-remove":
      return "will-remove";
    case "their-move":
      return "waiting-for-them";
    case "held":
      return "held";
    default:
      return "other";
  }
}

const bucketWords: Record<Bucket, string> = {
  ok: "in step",
  "will-invite": "to be invited",
  "will-remove": "to be removed",
  "waiting-for-them": "waiting for them",
  held: "held",
  other: "other",
};

/** "12 in step, 1 waiting for them": the counts, largest concerns last so
 *  the sentence ends on what needs reading. Empty for nobody. */
export function peopleSentence(members: Pick<SlackMemberStatus, "state" | "reason">[]): string {
  if (members.length === 0) return "";
  const counts = new Map<Bucket, number>();
  for (const m of members) counts.set(bucketOf(m), (counts.get(bucketOf(m)) ?? 0) + 1);
  return (Object.keys(bucketWords) as Bucket[])
    .filter((b) => counts.has(b))
    .map((b) => `${counts.get(b)} ${bucketWords[b]}`)
    .join(", ");
}

/** One person's place in a channel, in a sentence. */
export function memberSentence(member: Pick<SlackMemberStatus, "state" | "reason">): string {
  switch (bucketOf(member)) {
    case "ok":
      return "in the channel";
    case "will-invite":
      return "will be invited";
    case "will-remove":
      return "will be removed";
    case "waiting-for-them":
      return member.reason ? `waiting for them: ${member.reason}` : "waiting for them";
    case "held":
      return member.reason ? `held: ${member.reason}` : "held";
    default:
      return member.reason || member.state;
  }
}

/** The one sentence a channel's page opens with. */
export function summaryLine(row: ChannelRow): string {
  const where = row.kind === "connect" ? `hosted by ${row.workspace}, shared with ${row.sides.slice(1).map((s) => s.workspace).join(", ") || "nobody yet"}` : `in ${row.workspace}`;
  const fed = row.sources.length === 0 ? "" : `, fed by ${row.sources.length} ${row.sources[0]?.internal ? (row.sources.length === 1 ? "internal group" : "internal groups") : row.sources.length === 1 ? "directory group" : "directory groups"}`;
  const people = peopleSentence(membersOf(row));
  const tail = people ? `: ${people}.` : row.sides.every((s) => !s.status) ? ": the controller has not reported it yet." : ": nobody is reported in it.";
  return `A ${kindLabel[row.kind]} channel ${where}${fed}${tail}`;
}

/** A channel a directory group feeds, and how. */
export type Reach = { row: ChannelRow; via?: string };

/** The channels a directory group feeds: the console's and Slack Connect's,
 *  which name directory groups directly, and the policy's, which name
 *  internal groups the directory group feeds (`via`). */
export function reachOfDirectoryGroup(rows: ChannelRow[], address: string, feeds: string[]): Reach[] {
  const group = lower(address);
  const out: Reach[] = [];
  for (const row of rows) {
    if (row.sources.some((s) => !s.internal && lower(s.address) === group)) {
      out.push({ row });
      continue;
    }
    const via = row.sources.find((s) => s.internal && feeds.includes(s.address));
    if (via) out.push({ row, via: via.address });
  }
  return out;
}

/** What the people of one group are doing in one channel, by their rows. */
export function groupPeople(row: ChannelRow, emails: string[]): { present: SlackMemberStatus[]; unreported: number } {
  const wanted = new Set(emails.map(lower));
  const present = membersOf(row).filter((m) => wanted.has(lower(m.email)) || wanted.has(lower(m.person)));
  const seen = new Set(present.flatMap((m) => [lower(m.email), lower(m.person)]));
  return { present, unreported: [...wanted].filter((e) => !seen.has(e)).length };
}

/** One place a person is in Slack. */
export type Place = { workspace: string; channel: ChannelStatusRef; member: SlackMemberStatus; row?: ChannelRow };
type ChannelStatusRef = { name: string; kind: ChannelKind };

/** Every channel a person has a row in, by workspace, from the reports. */
export function placesOfPerson(status: GetSlackStatusResponse | undefined, rows: ChannelRow[], email: string): Place[] {
  const address = lower(email);
  const out: Place[] = [];
  for (const ws of status?.workspaces ?? []) {
    for (const channel of ws.channels) {
      const member = channel.members.find((m) => lower(m.email) === address || lower(m.person) === address);
      if (!member) continue;
      const kind: ChannelKind = channel.shared ? "connect" : channel.console ? "console" : "policy";
      out.push({ workspace: ws.workspace, channel: { name: channel.name, kind }, member, row: findRow(rows, ws.workspace, channel.name) });
    }
  }
  return out.sort((a, b) => a.workspace.localeCompare(b.workspace) || a.channel.name.localeCompare(b.channel.name));
}

/** The channels an internal group feeds: the policy's, which name it directly. */
export function reachOfInternalGroup(rows: ChannelRow[], name: string): Reach[] {
  return rows.filter((row) => row.sources.some((s) => s.internal && s.address === name)).map((row) => ({ row }));
}

/** Channels grouped by the workspace they are in, in workspace order. A
 *  Slack Connect channel is listed under its host. */
export function byWorkspace<T extends { row: ChannelRow }>(items: T[]): { workspace: string; items: T[] }[] {
  const out = new Map<string, T[]>();
  for (const item of items) out.set(item.row.workspace, [...(out.get(item.row.workspace) ?? []), item]);
  return [...out].sort(([a], [b]) => a.localeCompare(b)).map(([workspace, grouped]) => ({ workspace, items: grouped }));
}
