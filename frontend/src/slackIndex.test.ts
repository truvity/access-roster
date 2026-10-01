import { create } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";

import { ListSlackChannelsResponseSchema } from "./gen/directoryroster/v1/slack_channels_pb";
import { ListSlackSharedChannelsResponseSchema } from "./gen/directoryroster/v1/slack_connect_pb";
import { GetSlackStatusResponseSchema } from "./gen/directoryroster/v1/slack_pb";
import { parse, paths } from "./router";
import { channelFilterOf, filterChannels } from "./slackFilters";
import { buildRows, findRow, groupPeople, memberSentence, peopleSentence, placesOfPerson, reachOfDirectoryGroup, rowPath, summaryLine } from "./slackIndex";

const member = (email: string, state: string, reason = "") => ({ person: email.split("@")[0], email, state, reason });

const status = create(GetSlackStatusResponseSchema, {
  workspaces: [
    {
      workspace: "acme",
      canOperate: true,
      channels: [
        { name: "infra-alerts", id: "C1", state: "ok", sources: ["all:platform:engineer"], members: [member("ann@acme.example", "ok"), member("bob@acme.example", "held", "no Slack account yet")] },
        { name: "eng", id: "C2", private: true, console: true, mode: "strict", state: "ok", members: [member("ann@acme.example", "ok"), member("cy@acme.example", "will-invite")] },
        { name: "partners", id: "C3", shared: true, host: "acme", state: "ok", members: [member("ann@acme.example", "ok")] },
      ],
    },
    {
      workspace: "globex",
      channels: [{ name: "acme-partners", id: "C3", shared: true, host: "acme", state: "waiting", members: [member("dee@globex.example", "will-invite")] }],
    },
  ],
});
const ordinary = create(ListSlackChannelsResponseSchema, {
  channels: [
    { channel: { workspace: "acme", name: "eng", private: true, mode: "strict", sources: ["eng@acme.example"] }, state: "active", canOperate: true },
    { channel: { workspace: "acme", name: "ideas", sources: ["eng@acme.example", "all@acme.example"], members: ["cy@acme.example", "dan@acme.example", "eve@acme.example"] }, state: "pending", canOperate: true },
  ],
});
const shared = create(ListSlackSharedChannelsResponseSchema, {
  channels: [{ channel: { name: "partners", host: "acme", with: ["globex"], from: ["partners@acme.example"], privatePerSide: { acme: true, globex: false } }, state: "waiting", canOperate: true }],
});

const rows = buildRows(status, ordinary, shared);

describe("buildRows", () => {
  it("lists each managed channel once, whichever way it is managed", () => {
    expect(rows.map((r) => `${r.kind}:${r.workspace}/${r.name}`)).toEqual(["console:acme/eng", "console:acme/ideas", "policy:acme/infra-alerts", "connect:acme/partners"]);
  });

  it("names a policy channel's internal groups and makes it read-only", () => {
    const row = rows[2];
    expect(row.sources).toEqual([{ address: "all:platform:engineer", internal: true }]);
    expect(row.canOperate).toBe(false);
  });

  it("joins a console record to its report, and shows one that is not reported yet", () => {
    const [eng, ideas] = rows.filter((r) => r.kind === "console");
    expect(eng.sides[0].status?.id).toBe("C2");
    expect(eng.id).toBe("C2");
    expect(eng.canOperate).toBe(true);
    expect(ideas.sides[0].status).toBeUndefined();
    expect(ideas.state.kind).toBe("pending");
  });

  it("gathers a Slack Connect channel's sides from each workspace's report", () => {
    const row = rows[3];
    expect(row.sides.map((s) => [s.workspace, s.name, s.status?.state])).toEqual([
      ["acme", "partners", "ok"],
      ["globex", "acme-partners", "waiting"],
    ]);
    expect(row.privatePerSide).toEqual({ acme: true, globex: false });
  });

  it("shows a shared channel with no readable record once, from its host", () => {
    const orphan = buildRows(status, undefined, undefined).filter((r) => r.kind === "connect");
    expect(orphan).toHaveLength(1);
    expect(orphan[0]).toMatchObject({ workspace: "acme", name: "partners", canOperate: false });
  });

  it("builds nothing from nothing", () => {
    expect(buildRows(undefined, undefined, undefined)).toEqual([]);
  });
});

describe("addressing a channel", () => {
  it("finds it by name, by Slack id, or from a guest side", () => {
    expect(findRow(rows, "acme", "eng")?.name).toBe("eng");
    expect(findRow(rows, "acme", "C2")?.name).toBe("eng");
    expect(findRow(rows, "globex", "acme-partners")?.name).toBe("partners");
    expect(findRow(rows, "globex", "C3")?.name).toBe("partners");
    expect(findRow(rows, "acme", "nope")).toBeUndefined();
  });

  it("round trips through the router", () => {
    const route = parse(`#${rowPath(rows[0])}`);
    expect(route).toMatchObject({ view: "slack", id: "channels", rest: ["acme", "eng"] });
    expect(parse(`#${paths.slackChannel("acme", "a b")}`).rest).toEqual(["acme", "a b"]);
  });

  it("narrows by workspace and kind", () => {
    const by = (query: string) => filterChannels(rows, channelFilterOf(new URLSearchParams(query))).map((r) => r.name);
    expect(by("workspace=globex")).toEqual(["partners"]);
    expect(by("kind=console")).toEqual(["eng", "ideas"]);
    expect(by("workspace=acme&kind=policy")).toEqual(["infra-alerts"]);
    expect(by("")).toHaveLength(4);
  });
});

describe("what a channel says about its people", () => {
  it("counts people by what comes next", () => {
    expect(peopleSentence(rows[2].sides[0].status!.members)).toBe("1 in step, 1 waiting for them");
    expect(peopleSentence([])).toBe("");
  });

  it("says a person's place in a sentence, with the reason", () => {
    expect(memberSentence({ state: "held", reason: "no Slack account yet" })).toBe("waiting for them: no Slack account yet");
    expect(memberSentence({ state: "held", reason: "the directory cannot vouch" })).toBe("held: the directory cannot vouch");
    expect(memberSentence({ state: "will-invite", reason: "" })).toBe("will be invited");
    expect(memberSentence({ state: "ok", reason: "" })).toBe("in the channel");
  });

  it("opens each page with one sentence", () => {
    expect(summaryLine(rows[2])).toBe("A policy channel in acme, fed by 1 internal group: 1 in step, 1 waiting for them.");
    expect(summaryLine(rows[1])).toBe("A console channel in acme, fed by 2 directory groups and 3 individual addresses: the controller has not reported it yet.");
    expect(summaryLine(rows[3])).toContain("hosted by acme, shared with globex");
  });
});

describe("reverse links", () => {
  it("finds the channels a directory group feeds, directly and through an internal group", () => {
    const reach = reachOfDirectoryGroup(rows, "ENG@acme.example", ["all:platform:engineer"]);
    expect(reach.map((r) => [r.row.name, r.via ?? ""])).toEqual([
      ["eng", ""],
      ["ideas", ""],
      ["infra-alerts", "all:platform:engineer"],
    ]);
    expect(reachOfDirectoryGroup(rows, "nobody@acme.example", [])).toEqual([]);
  });

  it("marks a channel a person is listed in individually", () => {
    const places = placesOfPerson(status, rows, "cy@acme.example");
    expect(places.map((p) => [p.channel.name, p.individually])).toEqual([["eng", false]]);
    const withCy = buildRows(status, create(ListSlackChannelsResponseSchema, { channels: [{ channel: { workspace: "acme", name: "eng", sources: ["eng@acme.example"], members: ["CY@acme.example"] }, state: "active" }] }), undefined);
    expect(placesOfPerson(status, withCy, "cy@acme.example").find((p) => p.channel.name === "eng")?.individually).toBe(true);
    expect(placesOfPerson(status, withCy, "ann@acme.example").find((p) => p.channel.name === "eng")?.individually).toBe(false);
  });

  it("says what a group's people are doing in a channel, and who is not reported", () => {
    const { present, unreported } = groupPeople(rows[0], ["ann@acme.example", "cy@acme.example", "eve@acme.example"]);
    expect(present.map((m) => m.state)).toEqual(["ok", "will-invite"]);
    expect(unreported).toBe(1);
  });

  it("lists a person's channels per workspace with their state and reason", () => {
    const places = placesOfPerson(status, rows, "BOB@acme.example");
    expect(places.map((p) => [p.workspace, p.channel.name, p.member.state, p.member.reason])).toEqual([["acme", "infra-alerts", "held", "no Slack account yet"]]);
    expect(places[0].row?.kind).toBe("policy");
    const ann = placesOfPerson(status, rows, "ann@acme.example");
    expect(ann.map((p) => p.channel.kind)).toEqual(["console", "policy", "connect"]);
    expect(ann.map((p) => p.channel.name)).toEqual(["eng", "infra-alerts", "partners"]);
    expect(placesOfPerson(undefined, [], "x@y")).toEqual([]);
  });
});
