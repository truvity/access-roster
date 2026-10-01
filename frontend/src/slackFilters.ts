import type { SlackDiscoveredOrdinary } from "./gen/directoryroster/v1/slack_channels_pb";
import type { SlackDiscoveredChannel } from "./gen/directoryroster/v1/slack_connect_pb";
import type { ChannelRow } from "./slackIndex";

/** The filters of the Slack tabs live in the address's query, so a link, a
 *  refresh and the back button keep them. Each is a plain string; an empty
 *  one, or a value the tab does not offer, filters nothing. */

const pick = <T extends string>(value: string | null, allowed: readonly T[]): T | "" => (allowed as readonly string[]).includes(value ?? "") ? (value as T) : "";

const lower = (s: string) => s.toLowerCase();

// ---------------------------------------------------------------- Discovered

export const discoveredKinds = ["ordinary", "shared"] as const;
export const discoveredVisibilities = ["public", "private", "unknown"] as const;
export const discoveredSorts = ["name", "members"] as const;

export type DiscoveredFilter = {
  workspace: string;
  kind: "" | (typeof discoveredKinds)[number];
  visibility: "" | (typeof discoveredVisibilities)[number];
  q: string;
  sort: "" | (typeof discoveredSorts)[number];
};

export function discoveredFilterOf(query: URLSearchParams): DiscoveredFilter {
  return {
    workspace: query.get("workspace") ?? "",
    kind: pick(query.get("kind"), discoveredKinds),
    visibility: pick(query.get("visibility"), discoveredVisibilities),
    q: query.get("q") ?? "",
    sort: pick(query.get("sort"), discoveredSorts),
  };
}

/** One channel nothing manages, ordinary or shared, for filtering and sorting
 *  in one list. */
export type DiscoveredItem = {
  kind: "ordinary" | "shared";
  /** Where it lives, or the host; "" for a channel hosted outside. */
  workspace: string;
  /** Every connected workspace it reaches. */
  workspaces: string[];
  name: string;
  channelId: string;
  visibility: "public" | "private" | "unknown";
  members: number;
  ordinary?: SlackDiscoveredOrdinary;
  shared?: SlackDiscoveredChannel;
};

/** The unmanaged channels as one list. A shared channel's visibility and name
 *  are the host side's, and its size the largest side the bots counted. */
export function discoveredItems(ordinary: SlackDiscoveredOrdinary[], shared: SlackDiscoveredChannel[]): DiscoveredItem[] {
  const out: DiscoveredItem[] = [];
  for (const row of ordinary) {
    out.push({
      kind: "ordinary",
      workspace: row.workspace,
      workspaces: [row.workspace],
      name: row.name,
      channelId: row.channelId,
      visibility: row.private ? "private" : "public",
      members: row.members,
      ordinary: row,
    });
  }
  for (const row of shared) {
    const host = row.sides.find((s) => s.workspace === row.hostWorkspace);
    const visibility = host?.privacy === "private" || host?.privacy === "public" ? host.privacy : "unknown";
    out.push({
      kind: "shared",
      workspace: row.hostWorkspace,
      workspaces: row.sides.filter((s) => s.listed || s.workspace === row.hostWorkspace).map((s) => s.workspace),
      name: host?.name || row.sides.find((s) => s.seen)?.name || "",
      channelId: row.channelId,
      visibility,
      members: Math.max(0, ...row.sides.map((s) => (s.seen ? s.members : 0))),
      shared: row,
    });
  }
  return out;
}

/** Narrowed by the filter and ordered: by workspace then name, or, with
 *  sort=members, the largest first. */
export function filterDiscovered(items: DiscoveredItem[], filter: DiscoveredFilter): DiscoveredItem[] {
  const needle = lower(filter.q.trim());
  const kept = items.filter(
    (item) =>
      (!filter.workspace || item.workspaces.includes(filter.workspace)) &&
      (!filter.kind || item.kind === filter.kind) &&
      (!filter.visibility || item.visibility === filter.visibility) &&
      (needle === "" || lower(item.name).includes(needle) || lower(item.channelId).includes(needle)),
  );
  const byName = (a: DiscoveredItem, b: DiscoveredItem) => a.workspace.localeCompare(b.workspace) || a.name.localeCompare(b.name) || a.channelId.localeCompare(b.channelId);
  return kept.sort(filter.sort === "members" ? (a, b) => b.members - a.members || byName(a, b) : byName);
}

/** "251 channels are", or "12 of 251 shown" when a filter hides some. */
export function shownSentence(shown: number, total: number): string {
  return shown === total ? `${total} ${total === 1 ? "channel" : "channels"}` : `${shown} of ${total} shown`;
}

// ---------------------------------------------------------------- Slack Connect

export const connectStates = ["active", "waiting", "pending", "held", "invalid", "not_reported"] as const;

export const connectStateLabel: Record<(typeof connectStates)[number], string> = {
  active: "active",
  waiting: "waiting",
  pending: "pending",
  held: "held",
  invalid: "invalid",
  not_reported: "not reported",
};

export type ConnectFilter = {
  host: string;
  side: string;
  state: "" | (typeof connectStates)[number];
  q: string;
};

export function connectFilterOf(query: URLSearchParams): ConnectFilter {
  return { host: query.get("host") ?? "", side: query.get("side") ?? "", state: pick(query.get("state"), connectStates), q: query.get("q") ?? "" };
}

/** A record's state as the filter names it: what the server said, or "not
 *  reported" for anything else. */
export function connectStateOf(row: Pick<ChannelRow, "record">): (typeof connectStates)[number] {
  const state = (row.record as { state?: string } | undefined)?.state ?? "";
  return (connectStates as readonly string[]).includes(state) && state !== "not_reported" ? (state as (typeof connectStates)[number]) : "not_reported";
}

/** The Slack Connect rows the filter keeps: by host, by a workspace on either
 *  side (the host counts as a side), by state, and by name. */
export function filterConnect(rows: ChannelRow[], filter: ConnectFilter): ChannelRow[] {
  const needle = lower(filter.q.trim());
  return rows.filter(
    (row) =>
      (!filter.host || row.workspace === filter.host) &&
      (!filter.side || row.sides.some((s) => s.workspace === filter.side)) &&
      (!filter.state || connectStateOf(row) === filter.state) &&
      (needle === "" || lower(row.name).includes(needle) || (row.id !== "" && lower(row.id).includes(needle))),
  );
}

/** Every workspace a Slack Connect row names, for the facets' options. */
export function connectWorkspaces(rows: ChannelRow[]): { hosts: string[]; sides: string[] } {
  return {
    hosts: [...new Set(rows.map((r) => r.workspace))].sort(),
    sides: [...new Set(rows.flatMap((r) => r.sides.map((s) => s.workspace)))].sort(),
  };
}

// ---------------------------------------------------------------- Channels

export const channelKinds = ["policy", "console", "connect"] as const;
export const channelStates = ["ok", "pending", "waiting", "held", "invalid", "not_reported"] as const;

export const channelStateLabel: Record<(typeof channelStates)[number], string> = {
  ok: "ok",
  pending: "pending",
  waiting: "waiting",
  held: "held",
  invalid: "invalid",
  not_reported: "not reported",
};

export type ChannelFilter = {
  workspace: string;
  kind: "" | (typeof channelKinds)[number];
  state: "" | (typeof channelStates)[number];
  q: string;
};

export function channelFilterOf(query: URLSearchParams): ChannelFilter {
  return {
    workspace: query.get("workspace") ?? "",
    kind: pick(query.get("kind"), channelKinds),
    state: pick(query.get("state"), channelStates),
    q: query.get("q") ?? "",
  };
}

/** A channel row's state as the filter names it, whatever manages the
 *  channel; pending is a channel the controller is about to create, adopt or
 *  accept. "" for a state the filter does not offer. */
export function channelStateOf(row: Pick<ChannelRow, "state">): "" | (typeof channelStates)[number] {
  switch (row.state.kind) {
    case "ok":
      return "ok";
    case "will-create":
    case "will-adopt":
    case "will-accept":
    case "pending":
      return "pending";
    case "waiting":
    case "their-move":
      return "waiting";
    case "held":
    case "needs-you":
      return "held";
    case "refused":
      return "invalid";
    case "unreported":
      return "not_reported";
    default:
      return "";
  }
}

/** The channel rows the filter keeps: by a workspace on any side, by kind,
 *  by state, and by name or Slack id. */
export function filterChannels(rows: ChannelRow[], filter: ChannelFilter): ChannelRow[] {
  const needle = lower(filter.q.trim());
  return rows.filter(
    (row) =>
      (!filter.workspace || row.workspace === filter.workspace || row.sides.some((s) => s.workspace === filter.workspace)) &&
      (!filter.kind || row.kind === filter.kind) &&
      (!filter.state || channelStateOf(row) === filter.state) &&
      (needle === "" || lower(row.name).includes(needle) || (row.id !== "" && lower(row.id).includes(needle))),
  );
}
