import { paths } from "./router";

/** The tabs of the one Slack entry, in the order the work happens: connect
 *  a workspace, see its channels, share some between workspaces, take over
 *  what is already there, and manage the Apps behind it. */
export const slackTabs = [
  { value: "workspaces", label: "Workspaces", to: paths.slack() },
  { value: "channels", label: "Channels", to: paths.slackChannels() },
  { value: "connect", label: "Slack Connect", to: paths.slackConnect() },
  { value: "discovered", label: "Discovered", to: paths.slackDiscovered() },
  { value: "apps", label: "Apps", to: paths.slackApps() },
] as const;

/** The tab a route names. Anything unknown, and the page's own old address,
 *  is the first. */
export function slackTabOf(section?: string): (typeof slackTabs)[number]["value"] {
  return slackTabs.find((tab) => tab.value === section)?.value ?? "workspaces";
}
