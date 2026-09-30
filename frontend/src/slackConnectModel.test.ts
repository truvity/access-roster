import { describe, expect, it } from "vitest";

import { definitionOf, emptyForm, guestChoices, hostChoices, privacyLabel, problems, stateView, withGuests, withHost, withPerSide } from "./slackConnectModel";

const form = { ...emptyForm, name: "partners", host: "acme", with: ["globex"], from: ["all:partners"] };

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
