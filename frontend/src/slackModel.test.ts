import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { describe, expect, it } from "vitest";

import { SlackMemberStatusSchema, SlackWorkspaceStatusSchema } from "./gen/directoryroster/v1/slack_pb";
import {
  awaitingFirstPass,
  awaitingText,
  breakerSentence,
  connectionView,
  isConfirmed,
  memberKind,
  needsToken,
  nextStep,
  offersDisconnect,
  offersReconnect,
  offersRefresh,
  ordered,
  passRequested,
  requestedText,
  split,
  summaryOf,
  tickNotice,
} from "./slackModel";

const ws = (init: MessageInitShape<typeof SlackWorkspaceStatusSchema> = {}) =>
  create(SlackWorkspaceStatusSchema, { workspace: "acme", declared: true, connectionState: "not_connected", ...init });
const member = (state: string, email = `${state}@acme.example`) => create(SlackMemberStatusSchema, { email, state });

describe("a Slack workspace's steps", () => {
  it("asks for one step at a time, in order", () => {
    expect(nextStep(ws())).toBe("connect");
    expect(nextStep(ws({ connectionState: "created" }))).toBe("install");
    expect(nextStep(ws({ connectionState: "scopes_missing" }))).toBe("reconnect");
    expect(nextStep(ws({ connectionState: "installed" }))).toBe("none");
  });

  it("asks nothing to connect a workspace the policy no longer declares", () => {
    expect(nextStep(ws({ declared: false }))).toBe("none");
    expect(offersDisconnect(ws({ declared: false, connectionState: "installed" }))).toBe(true);
  });

  it("offers Disconnect on anything that holds an App, and Reconnect on what is installed", () => {
    expect(offersDisconnect(ws())).toBe(false);
    expect(offersDisconnect(ws({ connectionState: "created" }))).toBe(true);
    expect(offersReconnect(ws({ connectionState: "installed" }))).toBe(true);
    expect(offersReconnect(ws({ connectionState: "created" }))).toBe(false);
  });

  it("needs a token to create, and to reconnect only when the scopes grew", () => {
    expect(needsToken(ws(), "connect")).toBe(true);
    expect(needsToken(ws({ connectionState: "installed" }), "reconnect")).toBe(false);
    expect(needsToken(ws({ connectionState: "scopes_missing", needsConfigurationToken: true }), "reconnect")).toBe(true);
    expect(needsToken(ws({ connectionState: "created" }), "install")).toBe(false);
  });

  it("shows scopes missing as needing a person", () => {
    expect(connectionView(ws({ connectionState: "scopes_missing" }))).toMatchObject({ kind: "needs-you", label: "scopes missing" });
    expect(connectionView(ws({ connectionState: "installed" })).kind).toBe("installed");
    expect(connectionView(ws()).kind).toBe("not-connected");
  });
});

describe("the note about a workspace's last pass", () => {
  const tick = { at: undefined, outcome: "failed", error: "acme is not connected: connect it" };
  it("is neutral for a workspace not connected or not installed yet, even over an old failed report", () => {
    expect(tickNotice(ws({ tick }))).toEqual({ severity: "info", text: "Not connected yet \u2014 Connect it to start." });
    expect(tickNotice(ws({ connectionState: "created", tick }))).toEqual({
      severity: "info",
      text: "Installed? Not yet \u2014 an owner of acme approves the App in Slack.",
    });
  });

  it("stays red for a real failure, and silent without one", () => {
    expect(tickNotice(ws({ connectionState: "installed", tick: { ...tick, error: "slack said no" } }))).toEqual({
      severity: "error",
      text: "The last pass failed: slack said no",
    });
    expect(tickNotice(ws({ connectionState: "installed" }))).toBeUndefined();
  });
});

describe("what the page says about a workspace", () => {
  it("says what is missing, and what is waiting", () => {
    expect(summaryOf(ws({ connectionState: "scopes_missing", missingScopes: ["users:read.email"] }))).toContain("users:read.email is asked for and not granted");
    expect(summaryOf(ws())).toContain("Connect it to acme");
    expect(summaryOf(ws({ connectionState: "installed" }))).toContain("not reported");
  });

  it("tells a dry run from a pass that acts", () => {
    const tick = { changes: 3, held: 0, outcome: "dry-run" };
    expect(summaryOf(ws({ connectionState: "installed", reported: true, acting: false, tick }))).toContain("would make 3 changes");
    expect(summaryOf(ws({ connectionState: "installed", reported: true, acting: true, tick: { ...tick, outcome: "applied" } }))).toBe("In step with the directory.");
    expect(summaryOf(ws({ connectionState: "installed", reported: true, acting: true, tick: { ...tick, held: 1 } }))).toBe("1 row waits for a person.");
    expect(summaryOf(ws({ connectionState: "installed", reported: true, acting: true, tick: { ...tick, outcome: "failed" } }))).toContain("failed");
  });

  it("words a breaker for the workspace and for a channel", () => {
    expect(breakerSentence("workspace", 5, 8)).toBe("Removals held: 5 of 8 managed members would leave the workspace at once.");
    expect(breakerSentence("#eng", 3, 4)).toBe("Removals held: 3 of 4 members would leave #eng at once.");
  });

  it("calls a breaker confirmed only for the same set", () => {
    expect(isConfirmed({ fingerprint: "a" }, { fingerprint: "a" })).toBe(true);
    expect(isConfirmed({ fingerprint: "a" }, { fingerprint: "b" })).toBe(false);
    expect(isConfirmed({ fingerprint: "a" }, undefined)).toBe(false);
    expect(isConfirmed(undefined, { fingerprint: "a" })).toBe(false);
  });
});

describe("the people of a channel", () => {
  it("reads what will change before what is fine", () => {
    const rows = ordered(["ok", "will-invite", "reported", "will-remove", "held", "ok"].map((s, i) => member(s, `${s}${i}@acme.example`)));
    expect(rows.map((m) => m.state)).toEqual(["will-remove", "held", "will-invite", "reported", "ok", "ok"]);
  });

  it("keeps the order of the report within a group", () => {
    const rows = ordered([member("ok", "b@x"), member("ok", "a@x")]);
    expect(rows.map((m) => m.email)).toEqual(["b@x", "a@x"]);
  });

  it("splits the settled from the open", () => {
    const { settled, open } = split([member("ok"), member("will-remove"), member("ignored")]);
    expect(settled).toHaveLength(1);
    expect(open.map((m) => m.state)).toEqual(["will-remove", "ignored"]);
  });

  it("gives every state a chip", () => {
    expect(["ok", "will-invite", "will-remove", "held", "retrying", "reported", "ignored"].map((s) => memberKind(member(s)))).toEqual([
      "in-channel",
      "will-invite",
      "will-remove",
      "held",
      "retrying",
      "slack-reported",
      "slack-ignored",
    ]);
  });
});

const moment = (iso: string) => timestampFromDate(new Date(iso));

describe("the first pass after an install", () => {
  const installed = { connectionState: "installed", connection: { connectedAt: moment("2026-10-01T10:00:00Z") } };

  it("waits, neutrally, until a report newer than the connection exists", () => {
    const old = { at: moment("2026-10-01T09:00:00Z"), outcome: "failed", error: "acme is not installed" };
    expect(awaitingFirstPass(ws({ ...installed, tick: old }))).toBe(true);
    expect(awaitingFirstPass(ws(installed))).toBe(true);
    expect(tickNotice(ws({ ...installed, tick: old }))).toEqual({ severity: "info", text: awaitingText });
    expect(summaryOf(ws({ ...installed, tick: old, reported: true, acting: true }))).toBe(awaitingText);
  });

  it("gives way to the banner once a newer report exists", () => {
    const fresh = { at: moment("2026-10-01T10:00:30Z"), outcome: "failed", error: "slack said no" };
    expect(awaitingFirstPass(ws({ ...installed, tick: fresh }))).toBe(false);
    expect(tickNotice(ws({ ...installed, tick: fresh }))).toEqual({ severity: "error", text: "The last pass failed: slack said no" });
  });

  it("is not about a workspace that is not installed, or whose connection has no time", () => {
    expect(awaitingFirstPass(ws({ connectionState: "created", connection: installed.connection }))).toBe(false);
    expect(awaitingFirstPass(ws({ connectionState: "installed" }))).toBe(false);
  });
});

describe("Refresh", () => {
  it("is offered where there is a bot token to pass with", () => {
    expect(offersRefresh(ws({ connectionState: "installed" }))).toBe(true);
    expect(offersRefresh(ws({ connectionState: "scopes_missing" }))).toBe(true);
    expect(offersRefresh(ws({ connectionState: "created" }))).toBe(false);
    expect(offersRefresh(ws())).toBe(false);
  });

  it("says a pass is requested until a report newer than the request exists", () => {
    const requestedAt = moment("2026-10-01T10:00:00Z");
    const before = { at: moment("2026-10-01T09:59:00Z"), outcome: "applied" };
    const after = { at: moment("2026-10-01T10:00:20Z"), outcome: "applied" };
    expect(passRequested(ws({ passRequestedAt: requestedAt, tick: before }))).toBe(true);
    expect(passRequested(ws({ passRequestedAt: requestedAt }))).toBe(true);
    expect(passRequested(ws({ passRequestedAt: requestedAt, tick: after }))).toBe(false);
    expect(passRequested(ws({ tick: before }))).toBe(false);
    expect(tickNotice(ws({ connectionState: "installed", passRequestedAt: requestedAt, tick: before }))).toEqual({
      severity: "info",
      text: requestedText,
    });
    expect(tickNotice(ws({ connectionState: "installed", passRequestedAt: requestedAt, tick: after }))).toBeUndefined();
  });
});

describe("a person with no Slack account", () => {
  it("waits for them, not for the operator", () => {
    expect(memberKind({ state: "held", reason: "no Slack account yet" })).toBe("their-move");
    expect(memberKind(member("held"))).toBe("held");
    expect(memberKind({ state: "held", reason: "the Slack account is deactivated" })).toBe("held");
  });
});
