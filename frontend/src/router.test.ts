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
