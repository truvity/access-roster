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
});
