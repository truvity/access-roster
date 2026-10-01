import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";

import { SlackAppSchema } from "./gen/directoryroster/v1/slack_apps_pb";
import { looksLikeConfigurationToken, nextStep, offersReinstall, stateView, summaryOf } from "./slackAppsModel";

const app = (init: MessageInitShape<typeof SlackAppSchema> = {}) =>
  create(SlackAppSchema, { id: "sync", workspace: "acme", teamId: "T0123ABCD", declared: true, state: "declared", ...init });

describe("the Slack App catalogue's steps", () => {
  it("asks for one step at a time, in order", () => {
    expect(nextStep(app())).toBe("create");
    expect(nextStep(app({ state: "created" }))).toBe("install");
    expect(nextStep(app({ state: "scopes_missing" }))).toBe("reinstall");
    expect(nextStep(app({ state: "installed" }))).toBe("none");
  });

  it("asks nothing of an App the deployment no longer declares", () => {
    expect(nextStep(app({ declared: false, state: "created" }))).toBe("none");
    expect(offersReinstall(app({ declared: false, state: "installed" }))).toBe(false);
  });

  it("offers a reinstall of anything installed", () => {
    expect(offersReinstall(app({ state: "installed" }))).toBe(true);
    expect(offersReinstall(app({ state: "scopes_missing" }))).toBe(true);
    expect(offersReinstall(app({ state: "created" }))).toBe(false);
  });

  it("shows scopes missing as needing a person", () => {
    expect(stateView(app({ state: "scopes_missing" }))).toMatchObject({ kind: "needs-you", label: "scopes missing" });
    expect(stateView(app({ state: "installed" })).kind).toBe("installed");
    expect(stateView(app()).kind).toBe("not-created");
  });

  it("says what the missing scopes are", () => {
    expect(summaryOf(app({ state: "scopes_missing", missingScopes: ["users:read.email"] }))).toContain("users:read.email is declared and not granted");
    expect(summaryOf(app({ state: "created" }))).toContain("T0123ABCD");
    // An App of a workspace nobody has connected has no team to name yet.
    expect(summaryOf(app({ state: "declared", teamId: "" }))).toContain("Connect acme on the Slack page first");
  });
});

describe("a configuration token", () => {
  it("is one word", () => {
    expect(looksLikeConfigurationToken(" xoxe.xoxp-1-abc ")).toBe(true);
    expect(looksLikeConfigurationToken("")).toBe(false);
    expect(looksLikeConfigurationToken("my token")).toBe(false);
  });
});
