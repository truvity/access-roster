import { create } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";

import { HeldGroupSchema } from "./gen/directoryroster/v1/access_pb";
import { formatChain } from "./heldChain";

describe("formatChain", () => {
  it("ends a concrete grant at the directory group that put them there", () => {
    const held = create(HeldGroupSchema, {
      group: "stage:k8s:admin",
      via: ["sre@example.com"],
      grantedByKey: "stage:k8s:admin",
      wildcard: false,
    });
    expect(formatChain(held, [held])).toBe("stage:k8s:admin ← directory group sre@example.com");
  });

  it("names the wildcard key when it differs from the group itself", () => {
    const held = create(HeldGroupSchema, {
      group: "devel:k8s:admin",
      via: ["sre@example.com"],
      grantedByKey: "*:k8s:admin",
      wildcard: true,
    });
    expect(formatChain(held, [held])).toBe("devel:k8s:admin ← wildcard *:k8s:admin ← directory group sre@example.com");
  });

  it("walks implied_by one hop at a time back to the wildcard grant", () => {
    const admin = create(HeldGroupSchema, {
      group: "stage:k8s:admin",
      via: ["sre@example.com"],
      grantedByKey: "*:k8s:admin",
      wildcard: true,
    });
    const operator = create(HeldGroupSchema, { group: "stage:k8s:operator", impliedBy: "stage:k8s:admin" });
    const viewer = create(HeldGroupSchema, { group: "stage:k8s:viewer", impliedBy: "stage:k8s:operator" });
    const all = [admin, operator, viewer];

    expect(formatChain(viewer, all)).toBe(
      "stage:k8s:viewer ← implied by stage:k8s:operator ← implied by stage:k8s:admin ← wildcard *:k8s:admin ← directory group sre@example.com",
    );
  });

  it("reads a matcher's own description as it is, never as a directory group", () => {
    const held = create(HeldGroupSchema, {
      group: "all:access-roster:operator",
      via: ["signed in as ada@example.com"],
      grantedByKey: "all:access-roster:operator",
    });
    expect(formatChain(held, [held])).toBe("all:access-roster:operator ← signed in as ada@example.com");
  });

  it("joins more than one directory group behind the same key", () => {
    const held = create(HeldGroupSchema, {
      group: "stage:k8s:admin",
      via: ["sre@example.com", "platform@example.com"],
      grantedByKey: "stage:k8s:admin",
    });
    expect(formatChain(held, [held])).toBe("stage:k8s:admin ← directory group sre@example.com, directory group platform@example.com");
  });

  it("stops rather than hangs if a chain ever cycled", () => {
    const a = create(HeldGroupSchema, { group: "a", impliedBy: "b" });
    const b = create(HeldGroupSchema, { group: "b", impliedBy: "a" });
    expect(formatChain(a, [a, b])).toBe("a ← implied by b ← implied by a");
  });
});
