import type { SlackApp } from "./gen/directoryroster/v1/slack_apps_pb";
import type { StateKind } from "./ui";

/** The one step an App is waiting for, in the order an operator takes
 *  them: create it, install it, and — when the declaration asks for more
 *  than Slack granted — reinstall it. */
export type Step = "create" | "install" | "reinstall" | "none";

/** What the row's chip shows: the shared chip's kind, an optional word
 *  after it, and the sentence in its tooltip. */
export type StateView = { kind: StateKind; label?: string; title: string };

export function stateView(app: Pick<SlackApp, "state">): StateView {
  switch (app.state) {
    case "created":
      return {
        kind: "created",
        title: "Created in Slack and not installed: there is no bot token yet. An owner of the workspace installs it.",
      };
    case "installed":
      return { kind: "installed", title: "Installed in the workspace the policy names, and Slack granted every declared scope." };
    case "scopes_missing":
      return {
        kind: "needs-you",
        label: "scopes missing",
        title: "Installed, and the entry declares scopes Slack has not granted. Reinstall so an owner approves them.",
      };
    default:
      return { kind: "not-created", title: "Declared in the values, and nobody has created it in Slack yet." };
  }
}

/** The step an App waits for. A viewer, or a caller who may not operate
 *  this App's workspace, waits for nobody: the server says which through
 *  `canOperate`, never the caller's own role. */
export function nextStep(app: Pick<SlackApp, "state" | "declared">): Step {
  if (!app.declared) return "none";
  switch (app.state) {
    case "declared":
      return "create";
    case "created":
      return "install";
    case "scopes_missing":
      return "reinstall";
    default:
      return "none";
  }
}

/** One sentence on where an App stands and what happens next. */
export function summaryOf(app: SlackApp): string {
  if (!app.declared) {
    return `No longer declared. Created as ${app.appId}; it stays until it is deleted in Slack.`;
  }
  switch (app.state) {
    case "created":
      return `Created in Slack. Install it into ${app.workspace}${app.teamId ? ` (${app.teamId})` : ""} to get its bot token.`;
    case "installed":
      return `Installed in ${app.installedTeamName || app.installedTeamId}.`;
    case "scopes_missing":
      return `Granted too little: ${app.missingScopes.join(", ")} ${app.missingScopes.length === 1 ? "is" : "are"} declared and not granted.`;
    default:
      return app.teamId
        ? `Not created. Create it for ${app.workspace} (${app.teamId}).`
        : `Not created. Connect ${app.workspace} on the Slack page first: an App is created in a workspace that is connected.`;
  }
}

/** Whether Reinstall may be offered on an installed App that holds every
 *  declared scope: it always may, to re-approve or rotate, and says so. */
export function offersReinstall(app: Pick<SlackApp, "state" | "declared">): boolean {
  return app.declared && (app.state === "installed" || app.state === "scopes_missing");
}

/** A configuration token is one word starting `xoxe`; anything else is a
 *  pasted sentence, refused before it leaves the page. */
export function looksLikeConfigurationToken(token: string): boolean {
  const t = token.trim();
  return t.length > 0 && !/\s/.test(t);
}

/** Where to generate one. */
export const configurationTokenUrl = "https://api.slack.com/apps";
