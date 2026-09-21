import { describe, expect, it } from "vitest";

import { GroupState } from "./gen/directoryroster/v1/openbao_pb";
import type { PolicyRule, SecretManagerGroup, SecretManagerNamespace, SecretManagerReach } from "./gen/directoryroster/v1/openbao_pb";
import { byNamespace, byState, needsReading, opens, prefixes, stateOf, summary, writes } from "./secretStoresModel";

function group(name: string, state: GroupState): SecretManagerGroup {
  return { name, state, declared: true, policies: [], hasPolicy: true, members: 0, doors: [], rules: [] } as unknown as SecretManagerGroup;
}

function rule(path: string, capabilities: string[], write: boolean): PolicyRule {
  return { path, capabilities, writes: write } as unknown as PolicyRule;
}

describe("the four states", () => {
  it("names each one", () => {
    expect(stateOf(GroupState.BOUND)).toBe("bound");
    expect(stateOf(GroupState.ABSENT)).toBe("absent");
    expect(stateOf(GroupState.UNEXPECTED)).toBe("unexpected");
    expect(stateOf(GroupState.UNREADABLE)).toBe("unreadable");
  });

  // A state this console does not know must not be drawn as "bound":
  // the failure of a page like this is a row that looks fine.
  it("treats anything it does not know as unreadable", () => {
    expect(stateOf(GroupState.UNSPECIFIED)).toBe("unreadable");
    expect(stateOf(undefined)).toBe("unreadable");
  });
});

describe("the order rows are drawn in", () => {
  it("puts what is wrong first, then what is merely not applied", () => {
    const rows = [
      group("devel:b:viewer", GroupState.BOUND),
      group("devel:a:viewer", GroupState.ABSENT),
      group("devel:c:viewer", GroupState.UNEXPECTED),
      group("devel:d:viewer", GroupState.UNREADABLE),
      group("devel:a:deployer", GroupState.BOUND),
    ];
    expect([...rows].sort(byState).map((row) => row.name)).toEqual([
      "devel:c:viewer", // not declared: the row the page is opened for
      "devel:d:viewer", // could not be read
      "devel:a:viewer", // declared, not applied yet
      "devel:a:deployer", // bound, alphabetical inside the band
      "devel:b:viewer",
    ]);
  });
});

describe("a namespace's summary", () => {
  it("leads with what is wrong", () => {
    expect(summary({ bound: 40, absent: 1, unexpected: 2, unreadable: 0 } as never, false)).toBe("2 not declared, 1 not applied yet, 40 bound");
  });

  it("says so in three words when nothing is wrong", () => {
    expect(summary({ bound: 12, absent: 0, unexpected: 0, unreadable: 0 } as never, false)).toBe("12 bound");
    expect(summary({ bound: 0, absent: 0, unexpected: 0, unreadable: 0 } as never, false)).toBe("nothing here");
  });

  // The distinction the whole page exists for: a namespace nobody may
  // read is NOT an empty namespace, and must never be summarised as one.
  it("never reports a refused read as empty", () => {
    expect(summary(undefined, true)).toBe("could not be read");
    expect(summary({ bound: 0, absent: 0, unexpected: 0, unreadable: 3 } as never, false)).toBe("3 unreadable");
  });
});

describe("what needs reading", () => {
  const namespace = (counts: Partial<Record<"bound" | "absent" | "unexpected" | "unreadable", number>>, unreadable = false) =>
    ({ name: "devel", environment: "devel", unreadable, reason: "", counts: { bound: 0, absent: 0, unexpected: 0, unreadable: 0, ...counts } }) as unknown as SecretManagerNamespace;

  it("is anything but a namespace that is entirely bound", () => {
    expect(needsReading(namespace({ bound: 9 }))).toBe(false);
    expect(needsReading(namespace({ bound: 9, unexpected: 1 }))).toBe(true);
    expect(needsReading(namespace({ bound: 9, absent: 1 }))).toBe(true);
    expect(needsReading(namespace({}, true))).toBe(true);
  });
});

describe("what a group opens", () => {
  // Reading a team's credentials and being able to replace them are
  // different grants; a line that showed both as "access" would be this
  // page's one real lie.
  it("marks the paths it can change", () => {
    const rules = [rule("kv/data/platform/*", ["read"], false), rule("kv/data/orders/*", ["create", "update"], true)];
    expect(opens(rules)).toBe("kv/data/platform/*, kv/data/orders/* (writes)");
    expect(writes(rules)).toBe(true);
    expect(writes([rules[0]])).toBe(false);
  });

  it("says nothing for a group with no rules", () => {
    expect(opens([])).toBe("");
  });
});

describe("a person's reach", () => {
  const reach = (manager: string, namespace: string, name: string, rules: PolicyRule[]): SecretManagerReach =>
    ({ manager, namespace, environment: namespace, group: name, rules, writes: rules.some((r) => r.writes), unreadable: false }) as unknown as SecretManagerReach;

  it("groups by store and namespace, in a stable order", () => {
    const grouped = byNamespace([
      reach("kernel", "stage", "stage:platform:viewer", []),
      reach("kernel", "devel", "devel:platform:viewer", []),
      reach("kernel", "devel", "devel:platform:deployer", []),
    ]);
    expect(grouped.map((one) => `${one.manager}/${one.namespace}`)).toEqual(["kernel/devel", "kernel/stage"]);
    expect(grouped[0].reach).toHaveLength(2);
  });

  it("counts each path once across every group", () => {
    const shared = rule("kv/data/platform/*", ["read"], false);
    expect(prefixes([reach("kernel", "devel", "a", [shared]), reach("kernel", "devel", "b", [shared, rule("kv/metadata/platform/*", ["list"], false)])])).toEqual([
      "kv/data/platform/*",
      "kv/metadata/platform/*",
    ]);
  });
});
