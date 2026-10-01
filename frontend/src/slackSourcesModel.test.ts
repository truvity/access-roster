import { describe, expect, it } from "vitest";

import { landings, landingSentence, matchingOptions, optionOf, sourceOptions, unknownDirectoryLabel, unreachedWarning } from "./slackSourcesModel";

const directories = [
  { workspaceId: "C0south", domains: ["south.example"], groups: [{ email: "eng@south.example", members: 4 }] },
  {
    workspaceId: "C0north",
    domains: ["north.example", "alpha.example"],
    groups: [
      { email: "ops@north.example", members: 2 },
      { email: "all@north.example", members: 9 },
    ],
  },
];

describe("sourceOptions", () => {
  it("lists every directory's groups, grouped by directory label and sorted inside it", () => {
    const options = sourceOptions(directories);
    expect(options.map((o) => o.email)).toEqual(["all@north.example", "ops@north.example", "eng@south.example"]);
    expect(options[0]).toMatchObject({ directory: "C0north", label: "C0north — alpha.example, north.example", members: 9 });
    expect(options[2]!.label).toBe("C0south — south.example");
  });

  it("is empty with no directory", () => {
    expect(sourceOptions([])).toEqual([]);
  });
});

describe("optionOf", () => {
  it("stands in for a group no connected directory holds", () => {
    const options = sourceOptions(directories);
    expect(optionOf(options, "ops@north.example").directory).toBe("C0north");
    expect(optionOf(options, "gone@elsewhere.example")).toMatchObject({ directory: "", label: unknownDirectoryLabel });
  });
});

describe("matchingOptions", () => {
  const options = sourceOptions(directories);
  it("searches the address and the directory, every word, any case", () => {
    expect(matchingOptions(options, "").length).toBe(3);
    expect(matchingOptions(options, "ENG").map((o) => o.email)).toEqual(["eng@south.example"]);
    expect(matchingOptions(options, "alpha").map((o) => o.email)).toEqual(["all@north.example", "ops@north.example"]);
    expect(matchingOptions(options, "north ops").map((o) => o.email)).toEqual(["ops@north.example"]);
    expect(matchingOptions(options, "nothing")).toEqual([]);
  });
});

describe("landings", () => {
  const options = sourceOptions(directories);
  const sides = [
    { workspace: "acme", owner: "C0north" },
    { workspace: "globex", owner: "C0south" },
  ];

  it("places each group on the sides its directory owns", () => {
    const { perSide, unreached } = landings(sides, ["ops@north.example", "eng@south.example", "all@north.example"], options);
    expect(perSide).toEqual([
      { workspace: "acme", owner: "C0north", groups: ["ops@north.example", "all@north.example"] },
      { workspace: "globex", owner: "C0south", groups: ["eng@south.example"] },
    ]);
    expect(unreached).toEqual([]);
    expect(unreachedWarning(unreached)).toBe("");
  });

  it("flags a group whose directory owns no side of the channel", () => {
    const { perSide, unreached } = landings([sides[0]!], ["ops@north.example", "eng@south.example"], options);
    expect(perSide[0]!.groups).toEqual(["ops@north.example"]);
    expect(unreached).toEqual(["eng@south.example"]);
    expect(unreachedWarning(unreached)).toContain("eng@south.example belongs to a directory that owns no side");
    expect(unreachedWarning(unreached)).toContain("would be held");
    expect(unreachedWarning(["a@x.example", "b@y.example"])).toContain("belong to directories that own no side");
  });

  it("flags a group no connected directory holds, and a side with no owner reaches nobody", () => {
    const { perSide, unreached } = landings([{ workspace: "acme", owner: "" }, sides[1]!], ["gone@elsewhere.example", "eng@south.example"], options);
    expect(perSide[0]).toEqual({ workspace: "acme", owner: "", groups: [] });
    expect(unreached).toEqual(["gone@elsewhere.example"]);
  });

  it("ignores a side that is not chosen yet", () => {
    expect(landings([{ workspace: "", owner: "" }, sides[1]!], ["eng@south.example"], options).perSide).toHaveLength(1);
  });

  it("says each side in a sentence", () => {
    expect(landingSentence({ workspace: "acme", owner: "C0north", groups: ["ops@north.example"] }, "C0north")).toBe("acme (C0north): 1 chosen group, ops@north.example.");
    expect(landingSentence({ workspace: "acme", owner: "C0north", groups: [] }, "C0north")).toContain("nobody joins from it");
    expect(landingSentence({ workspace: "acme", owner: "", groups: [] }, "")).toContain("no owning directory");
    expect(landingSentence({ workspace: "acme", owner: "C0north", groups: ["a@north.example", "b@north.example"] }, "C0north")).toContain("2 chosen groups");
  });
});
