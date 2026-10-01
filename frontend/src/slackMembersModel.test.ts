import { describe, expect, it } from "vitest";

import { allowedDirectories, badMembers, feedCount, memberProblem, memberProblems, parseAddresses, withAddresses } from "./slackMembersModel";

const owner = allowedDirectories([{ workspaceId: "C0north", domains: ["acme.example"] }]);

describe("parseAddresses", () => {
  it("splits pasted text and lowercases, keeping repeats", () => {
    expect(parseAddresses(" Ann@Acme.example, bob@acme.example;\n ann@acme.example ")).toEqual(["ann@acme.example", "bob@acme.example", "ann@acme.example"]);
    expect(parseAddresses("  ")).toEqual([]);
    expect(withAddresses(["a@acme.example"], "b@acme.example")).toEqual(["a@acme.example", "b@acme.example"]);
  });
});

describe("memberProblem", () => {
  it("accepts a user of the owner directory", () => {
    expect(memberProblem("ann@acme.example", [], owner, true)).toBe("");
  });
  it("says an address outside the allowed directories is not a user of it", () => {
    expect(memberProblem("gus@globex.example", [], owner, true)).toBe(
      "gus@globex.example is not a user of the directory that owns this workspace (C0north — acme.example) — individual addresses come from the directories this channel draws from",
    );
    expect(memberProblem("gus@globex.example", [], owner, false)).toContain("is not a user of a connected directory");
  });
  it("tells a group from a person and a non-address from both", () => {
    expect(memberProblem("eng@acme.example", ["eng@acme.example"], owner, true)).toContain("is a group, not a person: enter it under Directory groups");
    expect(memberProblem("ann", [], owner, true)).toBe('"ann" is not an email address');
  });
  it("does not guess the directory when the form does not know it", () => {
    expect(memberProblem("gus@globex.example", [], [], true)).toBe("");
  });
});

describe("memberProblems and badMembers", () => {
  it("reports each fault once, repeats as repeats, and marks the chips", () => {
    const members = ["ann@acme.example", "ann@acme.example", "gus@globex.example", "eng@acme.example"];
    expect(memberProblems(members, [], ["eng@acme.example"], owner, true)).toEqual([
      "ann@acme.example is listed twice",
      expect.stringContaining("gus@globex.example is not a user"),
      expect.stringContaining("eng@acme.example is a group"),
    ]);
    expect([...badMembers(members, [], ["eng@acme.example"], owner, true)].sort()).toEqual(["ann@acme.example", "eng@acme.example", "gus@globex.example"]);
  });
  it("refuses an address that is also a source", () => {
    expect(memberProblems(["x@acme.example"], ["x@acme.example"], [], owner, true)[0]).toContain("is a group");
  });
});

describe("feedCount", () => {
  it("says groups and people", () => {
    expect(feedCount(2, 3)).toBe("2 groups, 3 people");
    expect(feedCount(1, 1)).toBe("1 group, 1 person");
    expect(feedCount(0, 2)).toBe("2 people");
    expect(feedCount(0, 0)).toBe("");
  });
});
