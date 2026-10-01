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
  /** The record takes over the policy channel of that workspace and name. */
  supersedesPolicy: boolean;
};

export const emptyChannelForm: ChannelForm = { workspace: "", name: "", channelId: "", private: false, mode: "extend", ignore: [], sources: [], supersedesPolicy: false };

/** The form of a record being edited. */
export function formOfRecord(record: {
  channel?: { workspace: string; name: string; channelId: string; private: boolean; mode: string; ignore: readonly string[]; sources: readonly string[]; supersedesPolicy?: boolean };
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
    supersedesPolicy: def.supersedesPolicy ?? false,
  };
}

/** The form for taking a policy channel over: where it is, its name, its id
 *  from the latest report, its visibility, mode and ignore list as git has
 *  them. The sources are left for the operator: they must be DIRECTORY
 *  groups, which an internal group never is. */
export function formOfTakeover(row: { workspace: string; name: string; id: string; private: boolean; mode: string; ignore: readonly string[] }): ChannelForm {
  const strict = row.mode === "strict" && row.private;
  return {
    ...emptyChannelForm,
    workspace: row.workspace,
    name: row.name,
    channelId: row.id,
    private: row.private,
    mode: strict ? "strict" : "extend",
    ignore: strict ? [...row.ignore] : [],
    supersedesPolicy: true,
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

/** What is wrong with the form before it is sent, in the order it is filled
 *  in; empty when nothing is. */
export function channelProblems(form: ChannelForm, owner: string): string[] {
  const out: string[] = [];
  if (!form.workspace) out.push("Pick the workspace the channel is in.");
  else if (owner === "") out.push(`${form.workspace} has no owning directory yet: set the owner on the Slack page before a channel there is fed by a directory group.`);
  if (!channelName.test(form.name)) out.push("The name is lowercase letters, digits, '-' and '_', at most 80.");
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
  supersedesPolicy: boolean;
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
    supersedesPolicy: form.supersedesPolicy,
  };
}

/** Whether the "Take over from git" action is offered for a channel: a
 *  policy channel, not already taken over, in a workspace the caller may
 *  manage. The server asks the same of the role. */
export function canTakeOver(row: { kind: string; canTakeOver: boolean }): boolean {
  return row.kind === "policy" && row.canTakeOver;
}

/** What taking a channel over does, for the dialog. */
export const takeoverSentence =
  "This channel is defined in git, fed by internal groups. Saving writes a console record that takes it over: from the next pass the controller reconciles the record and not the git entry, so there is no gap and nobody is removed by the takeover itself. " +
  "Strict removals still need the directory to vouch, and the breaker applies to the first pass like any other. Remove the entry from git afterwards; until you do, the console marks it taken over. " +
  "Deleting the record on the console gives the git entry its management back.";

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
