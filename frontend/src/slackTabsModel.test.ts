import { describe, expect, it } from "vitest";

import { parse } from "./router";
import { slackTabOf, slackTabs } from "./slackTabsModel";

describe("the Slack tabs", () => {
  it("are the five, in the order the work happens", () => {
    expect(slackTabs.map((t) => t.label)).toEqual(["Workspaces", "Channels", "Slack Connect", "Discovered", "Apps"]);
  });

  it("each open on their own route", () => {
    for (const tab of slackTabs) expect(slackTabOf(parse(`#${tab.to}`).id)).toBe(tab.value);
  });

  it("send an unknown tab, and the page's own address, to Workspaces", () => {
    expect(slackTabOf(undefined)).toBe("workspaces");
    expect(slackTabOf("nope")).toBe("workspaces");
  });

  it("keep the old Slack Apps and Slack Connect bookmarks on their tabs", () => {
    expect(slackTabOf(parse("#/slack-apps").id)).toBe("apps");
    expect(slackTabOf(parse("#/slack-connect").id)).toBe("connect");
  });
});
