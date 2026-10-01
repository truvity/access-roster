import { describe, expect, it } from "vitest";

import {
  channelDefinitionOf,
  channelProblems,
  discoveredSentence,
  emptyChannelForm,
  formOfDiscovered,
  formOfRecord,
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
    expect(formOfRecord(record)).toEqual({ workspace: "acme", name: "eng", channelId: "C0123ABCD", private: true, mode: "strict", ignore: ["a@acme.example"], sources: ["eng@acme.example"] });
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
