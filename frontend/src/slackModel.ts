import type { SlackChannelStatus, SlackMemberStatus, SlackWorkspaceStatus } from "./gen/directoryroster/v1/slack_pb";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { timestampMs } from "@bufbuild/protobuf/wkt";

import type { StateKind } from "./ui";

/** The one thing a workspace waits for from a person, in the order they
 *  take them: connect it (create the App), install it, reconnect it when
 *  the roster now asks for more than Slack granted. */
export type Step = "connect" | "install" | "reconnect" | "none";

/** What the connection chip shows: the shared chip's kind, an optional word
 *  after it, and the sentence in its tooltip. */
export type ConnectionView = { kind: StateKind; label?: string; title: string };

export function connectionView(ws: Pick<SlackWorkspaceStatus, "connectionState">): ConnectionView {
  switch (ws.connectionState) {
    case "created":
      return {
        kind: "created",
        title: "The App is created in Slack and not installed: there is no bot token yet. An owner of the workspace installs it.",
      };
    case "installed":
      return { kind: "installed", title: "Installed in the Slack team recorded at the first install, and Slack granted every scope the roster asks for." };
    case "scopes_missing":
      return {
        kind: "needs-you",
        label: "scopes missing",
        title: "Installed, and the roster now asks for scopes Slack has not granted. Reconnect so an owner approves them.",
      };
    default:
      return { kind: "not-connected", title: "No Slack App is connected for this workspace." };
  }
}

/** The step a workspace waits for. A viewer, or a caller who may not
 *  operate this workspace, waits for nobody: the server says which through
 *  `canOperate`, never the caller's own role. */
export function nextStep(ws: Pick<SlackWorkspaceStatus, "connectionState" | "declared">): Step {
  // A workspace the policy no longer declares cannot be connected, only
  // disconnected.
  if (!ws.declared && ws.connectionState === "not_connected") return "none";
  switch (ws.connectionState) {
    case "not_connected":
      return "connect";
    case "created":
      return "install";
    case "scopes_missing":
      return "reconnect";
    default:
      return "none";
  }
}

/** Whether Disconnect is offered: anything that holds an App. */
export function offersDisconnect(ws: Pick<SlackWorkspaceStatus, "connectionState">): boolean {
  return ws.connectionState !== "not_connected";
}

/** Whether Reconnect is offered on an installed workspace that holds every
 *  scope: it always may, to re-approve or rotate the token. */
export function offersReconnect(ws: Pick<SlackWorkspaceStatus, "connectionState">): boolean {
  return ws.connectionState === "installed" || ws.connectionState === "scopes_missing";
}

/** Whether Refresh is offered: a pass needs a bot token, so only an
 *  installed workspace has anything to pass with. */
export function offersRefresh(ws: Pick<SlackWorkspaceStatus, "connectionState">): boolean {
  return ws.connectionState === "installed" || ws.connectionState === "scopes_missing";
}

/** Whether a configuration token has to be pasted to take the step. */
export function needsToken(ws: Pick<SlackWorkspaceStatus, "connectionState" | "needsConfigurationToken">, step: Step): boolean {
  return step === "connect" || (step === "reconnect" && ws.needsConfigurationToken);
}

/** The chip a person's row shows. */
/** The hold reason of a person who has no Slack account for their address:
 *  only they can move it forward, so it is theirs, not the operator's. */
export const noAccountReason = "no Slack account yet";

export function memberKind(member: Pick<SlackMemberStatus, "state"> & Partial<Pick<SlackMemberStatus, "reason">>): StateKind {
  if (member.state === "held" && member.reason === noAccountReason) return "their-move";
  switch (member.state) {
    case "will-invite":
      return "will-invite";
    case "will-remove":
      return "will-remove";
    case "held":
      return "held";
    case "retrying":
      return "retrying";
    case "reported":
      return "slack-reported";
    case "ignored":
      return "slack-ignored";
    default:
      return "in-channel";
  }
}

/** The chip a channel shows. */
export function channelKind(channel: Pick<SlackChannelStatus, "state">): StateKind {
  switch (channel.state) {
    case "will-create":
      return "will-create";
    case "will-adopt":
      return "will-adopt";
    case "will-accept":
      return "will-accept";
    case "waiting":
      return "waiting";
    case "held":
      return "held";
    default:
      return "ok";
  }
}

/** Members in an order that puts what needs reading first: what will
 *  change, then what waits for a person, then the rest. Stable within a
 *  group, so the page does not shuffle between reports. */
const rank: Record<string, number> = { "will-remove": 0, held: 1, "will-invite": 2, retrying: 3, reported: 4, ignored: 5, ok: 6 };
export function ordered(members: SlackMemberStatus[]): SlackMemberStatus[] {
  return members
    .map((member, index) => ({ member, index }))
    .sort((a, b) => (rank[a.member.state] ?? 7) - (rank[b.member.state] ?? 7) || a.index - b.index)
    .map(({ member }) => member);
}

/** People in sync, and the rest, for the table that shows the rest and
 *  counts the former. */
export function split(members: SlackMemberStatus[]): { settled: SlackMemberStatus[]; open: SlackMemberStatus[] } {
  const all = ordered(members);
  return { settled: all.filter((m) => m.state === "ok"), open: all.filter((m) => m.state !== "ok") };
}

/** What is shown between an install and the first pass after it. */
export const awaitingText = "Installed \u2014 waiting for the first pass.";

/** What is shown between an operator's Refresh and the report it asked for. */
export const requestedText = "Pass requested \u2014 waiting for the controller to report.";

/** Whether a report is older than a moment: one with no time is older than
 *  anything, and a moment with no time is older than every report. */
function reportOlderThan(tick: SlackWorkspaceStatus["tick"], moment: Timestamp | undefined): boolean {
  if (!moment) return false;
  return !tick?.at || timestampMs(tick.at) < timestampMs(moment);
}

/** Whether the workspace was installed after the last pass the controller
 *  reported. Until a report newer than the connection exists, the previous
 *  pass's banner (a failure, "not installed", or an old all-clear) is about
 *  the workspace as it was, not as it is. */
export function awaitingFirstPass(ws: Pick<SlackWorkspaceStatus, "connectionState" | "tick" | "connection">): boolean {
  if (ws.connectionState !== "installed" && ws.connectionState !== "scopes_missing") return false;
  return reportOlderThan(ws.tick, ws.connection?.connectedAt);
}

/** Whether an operator asked for a pass that has not reported yet. */
export function passRequested(ws: Pick<SlackWorkspaceStatus, "tick" | "passRequestedAt">): boolean {
  return reportOlderThan(ws.tick, ws.passRequestedAt);
}

/** The note under a workspace's header about its last pass: neutral where
 *  the workspace simply is not connected or installed yet (an expected
 *  state, even if an older report recorded it as a failure), red only for a
 *  real failure. */
export function tickNotice(
  ws: Pick<SlackWorkspaceStatus, "connectionState" | "workspace" | "tick" | "connection" | "passRequestedAt">,
): { severity: "info" | "error"; text: string } | undefined {
  if (awaitingFirstPass(ws)) return { severity: "info", text: awaitingText };
  if (passRequested(ws)) return { severity: "info", text: requestedText };
  switch (ws.connectionState) {
    case "not_connected":
      return { severity: "info", text: "Not connected yet \u2014 Connect it to start." };
    case "created":
      return { severity: "info", text: `Installed? Not yet \u2014 an owner of ${ws.workspace} approves the App in Slack.` };
    default:
      break;
  }
  return ws.tick?.error ? { severity: "error", text: `The last pass failed: ${ws.tick.error}` } : undefined;
}

export function summaryOf(ws: SlackWorkspaceStatus): string {
  if (awaitingFirstPass(ws)) return awaitingText;
  switch (ws.connectionState) {
    case "not_connected":
      return `Not connected. Connect it to ${ws.workspace} to let the controller manage its channels.`;
    case "created":
      return `The App is created. An owner of ${ws.workspace} installs it in Slack to give the controller its bot token.`;
    case "scopes_missing":
      return `Granted too little: ${ws.missingScopes.join(", ")} ${ws.missingScopes.length === 1 ? "is" : "are"} asked for and not granted.`;
    default:
      break;
  }
  if (!ws.reported) return "Connected. The controller has not reported on this workspace yet.";
  const tick = ws.tick;
  if (!ws.acting) {
    return tick && tick.changes > 0
      ? `Dry run: the controller would make ${tick.changes} ${tick.changes === 1 ? "change" : "changes"} if it were enabled here.`
      : "Dry run: the controller changes nothing here and would change nothing now.";
  }
  if (tick && tick.outcome === "failed") return "The last pass failed. Nothing was changed on its account.";
  if (tick && tick.held > 0) return `${tick.held} ${tick.held === 1 ? "row waits" : "rows wait"} for a person.`;
  return "In step with the directory.";
}

/** The sentence under a breaker's banner. */
export function breakerSentence(scope: string, affected: number, total: number): string {
  return `Removals held: ${affected} of ${total} ${scope === "workspace" ? "managed members" : "members"} would leave ${scope === "workspace" ? "the workspace" : scope} at once.`;
}

/** Whether a confirmation already covers this breaker's set. */
export function isConfirmed(
  breaker: { fingerprint: string } | undefined,
  confirmation: { fingerprint: string } | undefined,
): boolean {
  return Boolean(breaker && confirmation && breaker.fingerprint === confirmation.fingerprint);
}
