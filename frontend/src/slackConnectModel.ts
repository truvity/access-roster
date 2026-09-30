import type { SlackConnectWorkspace, SlackSharedChannel, SlackSharedChannelDefinition } from "./gen/directoryroster/v1/slack_connect_pb";
import type { StateKind } from "./ui";

/** What the row's chip shows: the shared chip's kind, a word after it,
 *  and the sentence in its tooltip. */
export type StateView = { kind: StateKind; label?: string; title: string };

/** How a record stands, from the server's word for what the host
 *  workspace's controller last reported. */
export function stateView(channel: Pick<SlackSharedChannel, "state" | "reason">): StateView {
  const why = channel.reason ? ` ${channel.reason}` : "";
  switch (channel.state) {
    case "active":
      return { kind: "ok", label: "active", title: "The channel exists and every workspace has accepted it." };
    case "waiting":
      return { kind: "their-move", label: "waiting for acceptance", title: `A guest workspace has not accepted the invitation yet. Nobody here needs to act.${why}` };
    case "pending":
      return { kind: "pending", title: `The controller creates, adopts or accepts it on its next pass.${why}` };
    case "held":
      return { kind: "needs-you", title: `The controller cannot go on until a person acts.${why}` };
    case "invalid":
      return { kind: "refused", label: "invalid", title: `The controller acts on nothing here.${why}` };
    default:
      return { kind: "unreported", title: `The host workspace's controller has not reported this channel yet.${why}` };
  }
}

/** The visibility in words: one for every side, or each side's. */
export function privacyLabel(def: Pick<SlackSharedChannelDefinition, "private" | "privatePerSide">): string {
  const sides = Object.keys(def.privatePerSide ?? {}).sort();
  if (sides.length === 0) return def.private ? "private" : "public";
  return sides.map((side) => `${side} ${def.privatePerSide[side] ? "private" : "public"}`).join(", ");
}

/** What the form edits. `perSide` is undefined for one visibility for
 *  every side. */
export type Form = {
  name: string;
  host: string;
  with: string[];
  from: string[];
  private: boolean;
  perSide?: Record<string, boolean>;
};

export const emptyForm: Form = { name: "", host: "", with: [], from: [], private: false };

export function formOf(def: SlackSharedChannelDefinition): Form {
  const per = Object.keys(def.privatePerSide ?? {}).length > 0 ? { ...def.privatePerSide } : undefined;
  return { name: def.name, host: def.host, with: [...def.with], from: [...def.from], private: def.private, perSide: per };
}

/** The workspaces a channel can be shared with: every other one. */
export function guestChoices(workspaces: Pick<SlackConnectWorkspace, "key">[], host: string): string[] {
  return workspaces.map((w) => w.key).filter((key) => key !== host);
}

/** The workspaces the caller may host from. */
export function hostChoices(workspaces: Pick<SlackConnectWorkspace, "key" | "canOperate">[]): string[] {
  return workspaces.filter((w) => w.canOperate).map((w) => w.key);
}

/** Switching the host drops it from `with` (a host is never its own
 *  guest), and keeps a per-side choice naming exactly the sides left. */
export function withHost(form: Form, host: string): Form {
  const guests = form.with.filter((key) => key !== host);
  return { ...form, host, with: guests, perSide: form.perSide ? sidesOf(form.perSide, host, guests, form.private) : undefined };
}

export function withGuests(form: Form, guests: string[]): Form {
  return { ...form, with: guests, perSide: form.perSide ? sidesOf(form.perSide, form.host, guests, form.private) : undefined };
}

/** Per side, for exactly the host and the guests: a side already chosen
 *  keeps its choice, a new one takes the single visibility. */
function sidesOf(old: Record<string, boolean>, host: string, guests: string[], fallback: boolean): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const side of [host, ...guests]) if (side) out[side] = old[side] ?? fallback;
  return out;
}

/** Turns per-side visibility on (every side starts at the single
 *  choice) or off (back to one visibility for every side). */
export function withPerSide(form: Form, on: boolean): Form {
  return { ...form, perSide: on ? sidesOf({}, form.host, form.with, form.private) : undefined };
}

export const channelName = /^[a-z0-9_-]{1,80}$/;

/** What is wrong with the form before it is sent, in the order the form
 *  is filled in; empty when nothing is. The server checks all of it
 *  again against the policy. */
export function problems(form: Form): string[] {
  const out: string[] = [];
  if (!channelName.test(form.name)) out.push("The name is lowercase letters, digits, '-' and '_', at most 80.");
  if (!form.host) out.push("Pick the workspace that hosts the channel.");
  if (form.with.length === 0) out.push("Share it with at least one other workspace.");
  if (form.from.length === 0) out.push("Pick at least one group: members come only from groups.");
  return out;
}

export type Definition = {
  name: string;
  host: string;
  with: string[];
  from: string[];
  private: boolean;
  privatePerSide: Record<string, boolean>;
};

/** The form as the request's definition. */
export function definitionOf(form: Form): Definition {
  return {
    name: form.name.trim(),
    host: form.host,
    with: form.with,
    from: form.from,
    private: form.perSide ? false : form.private,
    privatePerSide: form.perSide ? { ...form.perSide } : {},
  };
}
