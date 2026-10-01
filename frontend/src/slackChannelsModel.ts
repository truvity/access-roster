import type { SlackChannelWorkspace, SlackDiscoveredOrdinary } from "./gen/directoryroster/v1/slack_channels_pb";

/** Ordinary Slack channels managed from the console: one workspace, members
 *  from DIRECTORY groups of the directory that owns it. The server checks
 *  every rule again against the policy and the directory; this file words the
 *  form and says what is wrong with it before it is sent. */

export const channelName = /^[a-z0-9_-]{1,80}$/;

/** What the form edits. */
export type ChannelForm = {
  workspace: string;
  name: string;
  /** The Slack id of an existing channel the record takes over; empty to take over, or create, by name. */
  channelId: string;
  private: boolean;
  /** extend adds only; strict adds and removes. */
  mode: "extend" | "strict";
  /** People a strict channel never removes: addresses, or Slack user ids. */
  ignore: string[];
  /** Directory group addresses. */
  sources: string[];
};

export const emptyChannelForm: ChannelForm = { workspace: "", name: "", channelId: "", private: false, mode: "extend", ignore: [], sources: [] };

/** The form of a record being edited. */
export function formOfRecord(record: {
  channel?: { workspace: string; name: string; channelId: string; private: boolean; mode: string; ignore: readonly string[]; sources: readonly string[] };
}): ChannelForm {
  const def = record.channel;
  if (!def) return emptyChannelForm;
  return {
    workspace: def.workspace,
    name: def.name,
    channelId: def.channelId,
    private: def.private,
    mode: def.mode === "strict" ? "strict" : "extend",
    ignore: [...def.ignore],
    sources: [...def.sources],
  };
}

/** The form for a discovered channel: where it is, what it is called, its id
 *  and its visibility as the bot sees it, which is never converted. */
export function formOfDiscovered(row: Pick<SlackDiscoveredOrdinary, "workspace" | "channelId" | "name" | "private">): ChannelForm {
  return { ...emptyChannelForm, workspace: row.workspace, name: row.name, channelId: row.channelId, private: row.private };
}

/** The workspaces the caller may manage channels in. */
export function manageableWorkspaces(workspaces: Pick<SlackChannelWorkspace, "key" | "canOperate">[]): string[] {
  return workspaces.filter((w) => w.canOperate).map((w) => w.key);
}

/** The owning directory of a workspace, "" when it has none. */
export function ownerOf(workspaces: Pick<SlackChannelWorkspace, "key" | "owner">[], workspace: string): string {
  return workspaces.find((w) => w.key === workspace)?.owner ?? "";
}

/** Why the console refuses a channel the policy defines. */
export const definedInGit = "This channel is defined in git; remove it there to manage it here.";

/** A channel the policy defines in git: the console never manages one. */
export type GitChannel = { workspace: string; name: string; id: string };

/** What is wrong with the form before it is sent, in the order it is filled
 *  in; empty when nothing is. `inGit` are the policy's channels: a channel
 *  whose name (or Slack id) one of them has in the same workspace is refused,
 *  as the server refuses it. */
export function channelProblems(form: ChannelForm, owner: string, inGit: readonly GitChannel[] = []): string[] {
  const out: string[] = [];
  if (!form.workspace) out.push("Pick the workspace the channel is in.");
  else if (owner === "") out.push(`${form.workspace} has no owning directory yet: set the owner on the Slack page before a channel there is fed by a directory group.`);
  if (!channelName.test(form.name)) out.push("The name is lowercase letters, digits, '-' and '_', at most 80.");
  else if (inGit.some((g) => g.workspace === form.workspace && (g.name === form.name || (form.channelId !== "" && g.id === form.channelId)))) out.push(definedInGit);
  if (form.mode === "strict" && !form.private) out.push("Strict is for private channels only: Slack lets only an administrator remove somebody from a public channel.");
  if (form.ignore.length > 0 && form.mode !== "strict") out.push("The ignore list is only for a strict channel.");
  if (form.sources.length === 0) out.push("Pick at least one directory group: members come only from groups.");
  return out;
}

export type ChannelDefinition = {
  workspace: string;
  name: string;
  channelId: string;
  private: boolean;
  mode: string;
  ignore: string[];
  sources: string[];
};

/** The form as the request's definition. */
export function channelDefinitionOf(form: ChannelForm): ChannelDefinition {
  return {
    workspace: form.workspace,
    name: form.name.trim(),
    channelId: form.channelId,
    private: form.private,
    mode: form.mode,
    ignore: form.mode === "strict" ? form.ignore.map((entry) => entry.trim()).filter(Boolean) : [],
    sources: form.sources,
  };
}

/** The mode in words. */
export function modeLabel(mode: string): string {
  return mode === "strict" ? "strict: adds and removes" : "extend: only adds";
}

/** What the Manage action says when it is unavailable. */
export function manageHint(row: Pick<SlackDiscoveredOrdinary, "canManage">): string {
  return row.canManage ? "" : "Only an operator of the workspace's owning directory, or of the installation, can take a channel under management.";
}

/** What a discovered channel is, in words. */
export function discoveredSentence(row: Pick<SlackDiscoveredOrdinary, "private" | "members">): string {
  return `${row.private ? "private" : "public"}, ${row.members} ${row.members === 1 ? "member" : "members"}`;
}
