import { describe, expect, it } from "vitest";

import { parse, paths } from "./router";

describe("parse", () => {
  it("reads an App's page", () => {
    expect(parse("#/github/apps/release-bot")).toMatchObject({ view: "github", id: "apps", rest: ["release-bot"] });
  });

  it("sends the old catalogue list to the Apps list", () => {
    expect(parse("#/github/apps/catalogue")).toMatchObject({ view: "github", id: "apps", rest: [] });
  });

  it("sends an old catalogue App's page to its App page", () => {
    expect(parse("#/github/apps/catalogue/release-bot")).toMatchObject({ view: "github", id: "apps", rest: ["release-bot"] });
  });

  it("reaches an App whose id is catalogue", () => {
    expect(parse(`#${paths.githubApp("catalogue")}`).rest).toEqual(["catalogue"]);
    expect(parse(`#${paths.githubApp("release-bot")}`).rest).toEqual(["release-bot"]);
  });

  it("reads Slack as one page with tabs", () => {
    expect(parse(`#${paths.slack()}`)).toMatchObject({ view: "slack", id: undefined, rest: [] });
    expect(parse(`#${paths.slackApps()}`)).toMatchObject({ view: "slack", id: "apps", rest: [] });
    expect(parse(`#${paths.slackConnect()}`)).toMatchObject({ view: "slack", id: "connect", rest: [] });
    expect(parse(`#${paths.slackDiscovered()}`)).toMatchObject({ view: "slack", id: "discovered", rest: [] });
    expect(parse(`#${paths.slackChannels()}`)).toMatchObject({ view: "slack", id: "channels", rest: [] });
  });

  it("sends the old Slack addresses to the tab that took their place", () => {
    // Slack Apps and Slack Connect were entries of their own: bookmarks.
    expect(parse("#/slack-apps")).toMatchObject({ view: "slack", id: "apps", rest: [] });
    expect(parse("#/slack-connect")).toMatchObject({ view: "slack", id: "connect", rest: [] });
    expect(parse("#/slack-connect?x=1").query.get("x")).toBe("1");
  });

  it("narrows the channels by workspace, kind, state and name in the address", () => {
    const route = parse(`#${paths.slackChannels({ workspace: "acme", kind: "console", state: "held", q: "en" })}`);
    expect(route.query.get("state")).toBe("held");
    expect(route.query.get("q")).toBe("en");
    expect(route).toMatchObject({ view: "slack", id: "channels" });
    expect(route.query.get("workspace")).toBe("acme");
    expect(route.query.get("kind")).toBe("console");
    expect(paths.slackChannels({ workspace: "", kind: "" })).toBe("/slack/channels");
  });

  it("reads one channel by workspace and name, or by Slack id", () => {
    expect(parse(`#${paths.slackChannel("acme", "eng")}`)).toMatchObject({ view: "slack", id: "channels", rest: ["acme", "eng"] });
    expect(parse(`#${paths.slackChannel("acme", "C0123ABCD")}`).rest).toEqual(["acme", "C0123ABCD"]);
  });

  it("opens the GitHub Runners tab", () => {
    expect(parse(`#${paths.githubRunners()}`)).toMatchObject({ view: "github", id: "runners", rest: [] });
  });

  it("opens the overview at the root, so the rail can highlight it", () => {
    expect(parse("#/").view).toBe("overview");
    expect(parse("").view).toBe("overview");
  });

  it("opens People narrowed to linked accounts", () => {
    const route = parse(`#${paths.peopleGitHub(true)}`);
    expect(route.view).toBe("people");
    expect(route.query.get("github")).toBe("linked");
  });

  it("keeps renamed views", () => {
    expect(parse("#/matchers").view).toBe("rules");
  });

  it("opens the Audit page narrowed to one App's tokens", () => {
    // The link an App's page offers. It is an address, so it can be
    // sent to somebody: the page opens already narrowed.
    const to = paths.audit("action:roster.github_token.minted target:github_app:release-bot");
    const route = parse(`#${to}`);
    expect(route.view).toBe("audit");
    expect(route.query.get("q")).toBe("action:roster.github_token.minted target:github_app:release-bot");
  });

  it("opens one record in its profile", () => {
    const route = parse(`#${paths.audit("id:0190", "security")}`);
    expect(route.query.get("q")).toBe("id:0190");
    expect(route.query.get("profile")).toBe("security");
  });

  it("leaves the Audit page's address bare when nothing narrows it", () => {
    expect(paths.audit()).toBe("/audit");
    expect(paths.audit("", "")).toBe("/audit");
    expect(parse("#/audit").query.get("q")).toBeNull();
  });
});
