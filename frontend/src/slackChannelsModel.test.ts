import { describe, expect, it } from "vitest";

import {
  canTakeOver,
  channelDefinitionOf,
  channelProblems,
  discoveredSentence,
  emptyChannelForm,
  formOfDiscovered,
  formOfRecord,
  formOfTakeover,
  manageableWorkspaces,
  manageHint,
  modeLabel,
  ownerOf,
} from "./slackChannelsModel";

const good = { ...emptyChannelForm, workspace: "acme", name: "eng", sources: ["eng@acme.example"] };

describe("channelProblems", () => {
  it("accepts a complete form", () => {
    expect(channelProblems(good, "C0north")).toEqual([]);
  });

  it("names what is missing in the order it is filled in", () => {
    expect(channelProblems(emptyChannelForm, "")).toEqual([
      "Pick the workspace the channel is in.",
      "The name is lowercase letters, digits, '-' and '_', at most 80.",
      "Pick at least one directory group: members come only from groups.",
    ]);
    expect(channelProblems({ ...good, name: "Not A Name" }, "C0north")[0]).toContain("lowercase");
    expect(channelProblems({ ...good, sources: [] }, "C0north")[0]).toContain("directory group");
  });

  it("says a workspace with no owning directory has nothing to pick from", () => {
    expect(channelProblems(good, "")[0]).toContain("no owning directory");
  });

  it("refuses strict on a public channel and an ignore list without strict", () => {
    expect(channelProblems({ ...good, mode: "strict" }, "C0north")[0]).toContain("private channels only");
    expect(channelProblems({ ...good, mode: "strict", private: true }, "C0north")).toEqual([]);
    expect(channelProblems({ ...good, ignore: ["boss@acme.example"] }, "C0north")[0]).toContain("only for a strict channel");
  });
});

describe("the definition sent", () => {
  it("carries the form, trimming the name", () => {
    expect(channelDefinitionOf({ ...good, name: " eng ", private: true, channelId: "C0123ABCD" })).toEqual({
      workspace: "acme",
      name: "eng",
      channelId: "C0123ABCD",
      private: true,
      mode: "extend",
      ignore: [],
      sources: ["eng@acme.example"],
      supersedesPolicy: false,
    });
  });

  it("sends an ignore list only for a strict channel, without blanks", () => {
    expect(channelDefinitionOf({ ...good, private: true, mode: "strict", ignore: [" boss@acme.example ", ""] }).ignore).toEqual(["boss@acme.example"]);
    expect(channelDefinitionOf({ ...good, ignore: ["boss@acme.example"] }).ignore).toEqual([]);
  });
});

describe("the form of a record or a discovered channel", () => {
  it("reads a record back, extend unless it says strict", () => {
    const record = { channel: { workspace: "acme", name: "eng", channelId: "C0123ABCD", private: true, mode: "strict", ignore: ["a@acme.example"], sources: ["eng@acme.example"] } };
    expect(formOfRecord(record)).toEqual({ workspace: "acme", name: "eng", channelId: "C0123ABCD", private: true, mode: "strict", ignore: ["a@acme.example"], sources: ["eng@acme.example"], supersedesPolicy: false });
    expect(formOfRecord({ channel: { ...record.channel, mode: "" } }).mode).toBe("extend");
    expect(formOfRecord({ channel: undefined })).toEqual(emptyChannelForm);
  });

  it("prefills a discovered channel with what was seen, visibility included", () => {
    expect(formOfDiscovered({ workspace: "acme", channelId: "G0PRIVATE1", name: "secret", private: true })).toEqual({
      ...emptyChannelForm,
      workspace: "acme",
      name: "secret",
      channelId: "G0PRIVATE1",
      private: true,
    });
  });
});

describe("the workspaces", () => {
  const workspaces = [
    { key: "acme", canOperate: true, owner: "C0north" },
    { key: "globex", canOperate: false, owner: "C0south" },
    { key: "initech", canOperate: true, owner: "" },
  ];
  it("offers the ones the caller may manage, and knows each owner", () => {
    expect(manageableWorkspaces(workspaces)).toEqual(["acme", "initech"]);
    expect(ownerOf(workspaces, "globex")).toBe("C0south");
    expect(ownerOf(workspaces, "initech")).toBe("");
    expect(ownerOf(workspaces, "nowhere")).toBe("");
  });
});

describe("words", () => {
  it("says the mode, the hint and the discovered channel", () => {
    expect(modeLabel("strict")).toContain("removes");
    expect(modeLabel("extend")).toContain("only adds");
    expect(manageHint({ canManage: true })).toBe("");
    expect(manageHint({ canManage: false })).toContain("owning directory");
    expect(discoveredSentence({ private: true, members: 1 })).toBe("private, 1 member");
    expect(discoveredSentence({ private: false, members: 40 })).toBe("public, 40 members");
  });
});

describe("taking a policy channel over from git", () => {
  const policyRow = { workspace: "acme", name: "alerts", id: "C0ALERTS1", private: true, mode: "strict", ignore: ["boss@acme.example"] };

  it("prefills what git has and leaves the directory sources to the operator", () => {
    const form = formOfTakeover(policyRow);
    expect(form).toMatchObject({ workspace: "acme", name: "alerts", channelId: "C0ALERTS1", private: true, mode: "strict", ignore: ["boss@acme.example"], sources: [], supersedesPolicy: true });
    expect(channelProblems(form, "C0north")).toEqual(["Pick at least one directory group: members come only from groups."]);
  });

  it("sends the flag, the id and the visibility, so the server can match exactly", () => {
    const def = channelDefinitionOf({ ...formOfTakeover(policyRow), sources: ["eng@acme.example"] });
    expect(def).toMatchObject({ supersedesPolicy: true, channelId: "C0ALERTS1", private: true, mode: "strict", sources: ["eng@acme.example"] });
  });

  it("drops a strict mode git cannot have on a public channel", () => {
    expect(formOfTakeover({ ...policyRow, private: false })).toMatchObject({ mode: "extend", ignore: [] });
  });

  it("offers the action on a policy channel the caller may manage, and nowhere else", () => {
    expect(canTakeOver({ kind: "policy", canTakeOver: true })).toBe(true);
    expect(canTakeOver({ kind: "policy", canTakeOver: false })).toBe(false);
    expect(canTakeOver({ kind: "console", canTakeOver: true })).toBe(false);
    expect(canTakeOver({ kind: "connect", canTakeOver: true })).toBe(false);
  });

  it("keeps the flag when a record is edited", () => {
    expect(formOfRecord({ channel: { ...policyRow, channelId: "C0ALERTS1", ignore: [], sources: ["a@acme.example"], supersedesPolicy: true } }).supersedesPolicy).toBe(true);
  });
});
