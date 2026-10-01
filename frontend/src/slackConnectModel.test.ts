import { describe, expect, it } from "vitest";

import { definitionOf, discoveredForm, discoveredStatus, emptyForm, guestChoices, manageBlocked, sideLabel, unplacedSides, withSidePrivate, hostChoices, privacyLabel, problems, stateView, withGuests, withHost, withPerSide } from "./slackConnectModel";

const form = { ...emptyForm, name: "partners", host: "acme", with: ["globex"], from: ["partners@north.example"] };

describe("stateView", () => {
  it("says who moves next", () => {
    expect(stateView({ state: "active", reason: "" }).kind).toBe("ok");
    expect(stateView({ state: "waiting", reason: "" }).label).toBe("waiting for acceptance");
    expect(stateView({ state: "held", reason: "x" }).kind).toBe("needs-you");
    expect(stateView({ state: "invalid", reason: "bad group" })).toMatchObject({ kind: "refused", label: "invalid" });
    expect(stateView({ state: "invalid", reason: "bad group" }).title).toContain("bad group");
    expect(stateView({ state: "not_reported", reason: "" }).kind).toBe("unreported");
  });
});

describe("privacyLabel", () => {
  it("reads one visibility or each side's", () => {
    expect(privacyLabel({ private: true, privatePerSide: {} })).toBe("private");
    expect(privacyLabel({ private: false, privatePerSide: {} })).toBe("public");
    expect(privacyLabel({ private: false, privatePerSide: { globex: false, acme: true } })).toBe("acme private, globex public");
  });
});

describe("the form", () => {
  it("offers only operable hosts, and every other workspace as a guest", () => {
    const workspaces = [
      { key: "acme", canOperate: true },
      { key: "globex", canOperate: false },
      { key: "initech", canOperate: true },
    ];
    expect(hostChoices(workspaces)).toEqual(["acme", "initech"]);
    expect(guestChoices(workspaces, "acme")).toEqual(["globex", "initech"]);
  });

  it("drops a new host from the guests", () => {
    expect(withHost(form, "globex").with).toEqual([]);
  });

  it("keeps per-side visibility to exactly the host and the guests", () => {
    let f = withPerSide({ ...form, private: true }, true);
    expect(f.perSide).toEqual({ acme: true, globex: true });
    f = withGuests({ ...f, perSide: { acme: true, globex: false } }, ["globex", "initech"]);
    expect(f.perSide).toEqual({ acme: true, globex: false, initech: true });
    f = withGuests(f, ["initech"]);
    expect(f.perSide).toEqual({ acme: true, initech: true });
    expect(withPerSide(f, false).perSide).toBeUndefined();
  });

  it("names what is missing, in the order it is filled in", () => {
    expect(problems(form)).toEqual([]);
    expect(problems(emptyForm)).toHaveLength(4);
    expect(problems({ ...form, name: "Not A Name" })[0]).toContain("lowercase");
    expect(problems({ ...form, from: [] })[0]).toContain("groups");
  });

  it("sends one visibility or per side, never both", () => {
    expect(definitionOf({ ...form, private: true })).toMatchObject({ private: true, privatePerSide: {} });
    expect(definitionOf({ ...form, private: true, perSide: { acme: true, globex: false } })).toMatchObject({
      private: false,
      privatePerSide: { acme: true, globex: false },
    });
  });
});

const side = (workspace: string, privacy: string, name = "", seen = privacy !== "unknown", listed = true) => ({ workspace, privacy, name, seen, listed, members: 3 });

describe("a discovered channel", () => {
  const row = {
    channelId: "C0LEGACY1",
    hostWorkspace: "acme",
    sides: [side("acme", "public", "legacy"), side("globex", "private", "legacy-globex"), side("initech", "unknown"), side("hooli", "unknown", "", false, false)],
  };

  it("prefills the host side's name, the host, the other workspaces the channel is placed in, the id and each side as seen", () => {
    const f = discoveredForm(row);
    expect(f).toMatchObject({
      name: "legacy",
      host: "acme",
      with: ["globex", "initech"],
      channelId: "C0LEGACY1",
      perSide: { acme: false, globex: true, initech: false },
      unknownSides: ["initech"],
      from: [],
    });
  });

  it("does not guess at a workspace nothing places the channel in, and says so", () => {
    expect(discoveredForm(row).with).not.toContain("hooli");
    expect(discoveredForm(row).perSide).not.toHaveProperty("hooli");
    expect(unplacedSides(row)).toEqual(["hooli"]);
    expect(unplacedSides({ hostWorkspace: "acme", sides: [side("acme", "public", "x")] })).toEqual([]);
    // The operator adds it by hand: it then needs a visibility chosen like any other side.
    const f = withGuests(discoveredForm(row), ["globex", "initech", "hooli"]);
    expect(f.perSide).toMatchObject({ hooli: false });
  });

  it("requires the groups and a choice for every side that was not seen, and sends the id", () => {
    let f = discoveredForm(row);
    expect(problems(f).join(" ")).toContain("Choose the visibility of initech");
    expect(problems(f).join(" ")).toContain("Pick at least one group");
    f = withSidePrivate({ ...f, from: ["partners@north.example"] }, "initech", true);
    expect(problems(f)).toEqual([]);
    expect(definitionOf(f)).toMatchObject({ channelId: "C0LEGACY1", privatePerSide: { acme: false, globex: true, initech: true }, private: false });
  });

  it("forgets an unknown side that is dropped from the guests", () => {
    const f = withGuests(discoveredForm(row), ["globex"]);
    expect(f.unknownSides).toEqual([]);
  });

  it("starts with no name when the host's bot cannot see its own side", () => {
    expect(discoveredForm({ ...row, sides: [side("acme", "unknown"), side("globex", "public", "x")] }).name).toBe("");
  });

  it("says what each side and the row are", () => {
    expect(sideLabel(side("globex", "private", "legacy-globex"))).toBe("#legacy-globex, private");
    expect(sideLabel(side("initech", "unknown"))).toContain("the bot is not in it");
    expect(sideLabel(side("hooli", "unknown", "", false, false))).toContain("no trace");
    expect(discoveredStatus({ hostWorkspace: "acme", managed: false, managedAs: "" })).toBe("not managed");
    expect(discoveredStatus({ hostWorkspace: "", managed: false, managedAs: "" })).toBe("external, not managed");
    expect(discoveredStatus({ hostWorkspace: "acme", managed: true, managedAs: "legacy" })).toBe("managed as #legacy");
  });

  it("explains why Manage is unavailable", () => {
    expect(manageBlocked({ hostWorkspace: "", managed: false, canManage: false })).toContain("not a connected workspace");
    expect(manageBlocked({ hostWorkspace: "acme", managed: false, canManage: false })).toContain("operator of the host");
    expect(manageBlocked({ hostWorkspace: "acme", managed: false, canManage: true })).toBe("");
    expect(manageBlocked({ hostWorkspace: "acme", managed: true, canManage: false })).toBe("");
  });
});
