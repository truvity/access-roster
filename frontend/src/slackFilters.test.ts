import { describe, expect, it } from "vitest";

import { channelFilterOf, channelStateOf, connectFilterOf, filterChannels, connectStateOf, connectWorkspaces, discoveredFilterOf, discoveredItems, filterConnect, filterDiscovered, shownSentence } from "./slackFilters";
import { paths, parse } from "./router";
import type { ChannelRow } from "./slackIndex";
import { visibilityMismatch } from "./slackIndex";

const q = (s: string) => new URLSearchParams(s);

const ordinary = (workspace: string, name: string, priv: boolean, members: number) => ({ workspace, channelId: `C${name}`, name, private: priv, members, canManage: true }) as never;
const side = (workspace: string, privacy: string, name = "", members = 0, listed = true) => ({ workspace, privacy, name, members, seen: privacy !== "unknown", listed });
const shared = (id: string, host: string, sides: ReturnType<typeof side>[]) => ({ channelId: id, hostWorkspace: host, sides, managed: false, canManage: true, externalTeams: 0 }) as never;

const items = discoveredItems(
  [ordinary("globex", "zeta", false, 5), ordinary("acme", "alpha", true, 40), ordinary("acme", "beta", false, 3)],
  [shared("CS1", "acme", [side("acme", "public", "gamma", 12), side("globex", "private", "gamma", 12), side("initech", "unknown", "", 0, false)]), shared("CS2", "initech", [side("initech", "unknown")])],
);

describe("the Discovered filters", () => {
  it("read the query and ignore a value the tab does not offer", () => {
    expect(discoveredFilterOf(q("workspace=acme&kind=shared&visibility=private&q=ga&sort=members"))).toEqual({ workspace: "acme", kind: "shared", visibility: "private", q: "ga", sort: "members" });
    expect(discoveredFilterOf(q("kind=bogus&visibility=x&sort=y"))).toMatchObject({ kind: "", visibility: "", sort: "" });
  });

  it("sort by workspace then name, and keep everything with no filter", () => {
    const all = filterDiscovered(items, discoveredFilterOf(q("")));
    expect(all.map((i) => `${i.workspace}/${i.name}`)).toEqual(["acme/alpha", "acme/beta", "acme/gamma", "globex/zeta", "initech/"]);
  });

  it("narrow by workspace, counting a guest side", () => {
    expect(filterDiscovered(items, discoveredFilterOf(q("workspace=globex"))).map((i) => i.name)).toEqual(["gamma", "zeta"]);
  });

  it("narrow by kind, visibility (unknown included) and name", () => {
    expect(filterDiscovered(items, discoveredFilterOf(q("kind=shared"))).map((i) => i.channelId)).toEqual(["CS1", "CS2"]);
    expect(filterDiscovered(items, discoveredFilterOf(q("visibility=private"))).map((i) => i.name)).toEqual(["alpha"]);
    expect(filterDiscovered(items, discoveredFilterOf(q("visibility=unknown"))).map((i) => i.channelId)).toEqual(["CS2"]);
    expect(filterDiscovered(items, discoveredFilterOf(q("q=ALP"))).map((i) => i.name)).toEqual(["alpha"]);
    expect(filterDiscovered(items, discoveredFilterOf(q("q=cs2"))).map((i) => i.channelId)).toEqual(["CS2"]);
  });

  it("sort by members, the largest first", () => {
    expect(filterDiscovered(items, discoveredFilterOf(q("sort=members"))).map((i) => i.members)).toEqual([40, 12, 5, 3, 0]);
  });

  it("say how many are shown", () => {
    expect(shownSentence(251, 251)).toBe("251 channels");
    expect(shownSentence(12, 251)).toBe("12 of 251 shown");
  });
});

const row = (name: string, host: string, guests: string[], state: string, reason = ""): ChannelRow =>
  ({ kind: "connect", workspace: host, name, id: "", sides: [host, ...guests].map((workspace) => ({ workspace })), record: { state, reason }, reason }) as unknown as ChannelRow;

const rows = [row("one", "acme", ["globex"], "active"), row("two", "acme", ["initech"], "held", "the channel is private in Slack but the policy says public"), row("three", "globex", ["acme", "initech"], "")];

describe("the Slack Connect filters", () => {
  it("read the query", () => {
    expect(connectFilterOf(q("host=acme&side=globex&state=held&q=x"))).toEqual({ host: "acme", side: "globex", state: "held", q: "x" });
    expect(connectFilterOf(q("state=bogus")).state).toBe("");
  });

  it("narrow by host and by a workspace on either end", () => {
    expect(filterConnect(rows, connectFilterOf(q("host=acme"))).map((r) => r.name)).toEqual(["one", "two"]);
    expect(filterConnect(rows, connectFilterOf(q("side=initech"))).map((r) => r.name)).toEqual(["two", "three"]);
    expect(filterConnect(rows, connectFilterOf(q("side=acme"))).map((r) => r.name)).toEqual(["one", "two", "three"]);
    expect(filterConnect(rows, connectFilterOf(q("host=globex&side=acme"))).map((r) => r.name)).toEqual(["three"]);
  });

  it("narrow by state, an unreported record being not reported, and by name", () => {
    expect(connectStateOf(rows[2]!)).toBe("not_reported");
    expect(filterConnect(rows, connectFilterOf(q("state=not_reported"))).map((r) => r.name)).toEqual(["three"]);
    expect(filterConnect(rows, connectFilterOf(q("state=held"))).map((r) => r.name)).toEqual(["two"]);
    expect(filterConnect(rows, connectFilterOf(q("q=ONE"))).map((r) => r.name)).toEqual(["one"]);
  });

  it("offer the hosts and sides the rows name", () => {
    expect(connectWorkspaces(rows)).toEqual({ hosts: ["acme", "globex"], sides: ["acme", "globex", "initech"] });
  });

  it("flag a visibility mismatch hold", () => {
    expect(rows.map((r) => visibilityMismatch(r))).toEqual([false, true, false]);
  });
});

describe("the Channels filters", () => {
  const chan = (name: string, workspace: string, kind: ChannelRow["kind"], state: string, id = "", sides: string[] = []) =>
    ({ name, workspace, kind, id, state: { kind: state }, sides: [workspace, ...sides].map((w) => ({ workspace: w })) }) as unknown as ChannelRow;
  const all = [
    chan("alerts", "acme", "policy", "ok", "C0AAA"),
    chan("eng", "acme", "console", "held"),
    chan("ideas", "globex", "console", "unreported"),
    chan("partners", "globex", "connect", "their-move", "C0PART", ["acme"]),
    chan("old", "globex", "console", "refused"),
    chan("fresh", "globex", "policy", "will-create"),
  ];
  const by = (query: string) => filterChannels(all, channelFilterOf(q(query))).map((r) => r.name);

  it("read the query and ignore a value the tab does not offer", () => {
    expect(channelFilterOf(q("workspace=acme&kind=connect&state=held&q=x"))).toEqual({ workspace: "acme", kind: "connect", state: "held", q: "x" });
    expect(channelFilterOf(q("kind=bogus&state=nope"))).toMatchObject({ kind: "", state: "" });
  });

  it("keep everything with no filter", () => {
    expect(by("")).toHaveLength(6);
  });

  it("narrow by a workspace on any side, and by kind", () => {
    expect(by("workspace=acme")).toEqual(["alerts", "eng", "partners"]);
    expect(by("kind=console")).toEqual(["eng", "ideas", "old"]);
    expect(by("workspace=globex&kind=console")).toEqual(["ideas", "old"]);
  });

  it("name a state whatever manages the channel", () => {
    expect(all.map((r) => channelStateOf(r))).toEqual(["ok", "held", "not_reported", "waiting", "invalid", ""]);
    expect(by("state=ok")).toEqual(["alerts"]);
    expect(by("state=waiting")).toEqual(["partners"]);
    expect(by("state=held")).toEqual(["eng"]);
    expect(by("state=invalid")).toEqual(["old"]);
    expect(by("state=not_reported")).toEqual(["ideas"]);
  });

  it("search by name or Slack id, ignoring case", () => {
    expect(by("q=ENG")).toEqual(["eng"]);
    expect(by("q=c0part")).toEqual(["partners"]);
  });

  it("combine, and say N of M", () => {
    expect(by("workspace=globex&state=not_reported&q=id")).toEqual(["ideas"]);
    expect(shownSentence(by("kind=policy").length, all.length)).toBe("2 of 6 shown");
  });
});

describe("the filters in the address", () => {
  it("round-trip through the router", () => {
    const d = parse(`#${paths.slackDiscovered({ workspace: "acme", kind: "shared", visibility: "private", q: "ga", sort: "members" })}`);
    expect(d).toMatchObject({ view: "slack", id: "discovered" });
    expect(discoveredFilterOf(d.query)).toEqual({ workspace: "acme", kind: "shared", visibility: "private", q: "ga", sort: "members" });
    const c = parse(`#${paths.slackConnect({ host: "acme", side: "globex", state: "held", q: "x" })}`);
    expect(c).toMatchObject({ view: "slack", id: "connect" });
    expect(connectFilterOf(c.query)).toEqual({ host: "acme", side: "globex", state: "held", q: "x" });
    const ch = parse(`#${paths.slackChannels({ workspace: "acme", kind: "console", state: "not_reported", q: "en" })}`);
    expect(ch).toMatchObject({ view: "slack", id: "channels" });
    expect(channelFilterOf(ch.query)).toEqual({ workspace: "acme", kind: "console", state: "not_reported", q: "en" });
    expect(paths.slackChannels({ workspace: "", kind: "", state: "", q: "" })).toBe("/slack/channels");
    expect(paths.slackDiscovered({ workspace: "", q: "" })).toBe("/slack/discovered");
    expect(paths.slackConnect()).toBe("/slack/connect");
  });
});
