import { create } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";

import { DirectoryRefSchema } from "./gen/directoryroster/v1/workspace_pb";
import { initialOwner, offersChoice, ownerName, ownerSentence, ownerValid, type OwnerOffer } from "./ownerModel";

const dir = (workspaceId: string, primaryDomain: string) => create(DirectoryRefSchema, { workspaceId, primaryDomain });
const north = dir("C0north", "north.example");
const south = dir("C0south", "south.example");

const installationWide: OwnerOffer = { choices: [north, south], mayBeNone: true };
const one: OwnerOffer = { choices: [north], mayBeNone: false };
const several: OwnerOffer = { choices: [north, south], mayBeNone: false };
const nothing: OwnerOffer = { choices: [], mayBeNone: false };

describe("the owner a connect form offers", () => {
  it("shows a choice to whoever has one", () => {
    expect(offersChoice(installationWide)).toBe(true);
    expect(offersChoice(several)).toBe(true);
    expect(offersChoice(one)).toBe(false);
    expect(offersChoice(nothing)).toBe(false);
  });

  it("starts on none for the installation-wide operator, and on the one directory for a caller with one", () => {
    expect(initialOwner(installationWide)).toBe("");
    expect(initialOwner(one)).toBe("C0north");
    expect(initialOwner(several)).toBe("");
  });

  it("accepts none only where none may be chosen, and only a directory that is offered", () => {
    expect(ownerValid(installationWide, "")).toBe(true);
    expect(ownerValid(installationWide, "C0south")).toBe(true);
    expect(ownerValid(installationWide, "C0nowhere")).toBe(false);
    expect(ownerValid(several, "")).toBe(false);
    expect(ownerValid(several, "C0south")).toBe(true);
    expect(ownerValid(one, "")).toBe(true);
    expect(ownerValid(nothing, "")).toBe(false);
  });
});

describe("how an owner is named", () => {
  it("names a directory by its domain", () => {
    expect(ownerName(north)).toBe("north.example");
    expect(ownerName(dir("C0x", ""))).toBe("C0x");
  });

  it("says who owns it, or that nobody does and what follows", () => {
    expect(ownerSentence("C0north", "north.example", "")).toBe("owned by the north.example directory");
    expect(ownerSentence("C0north", "", "")).toContain("no longer connected");
    expect(ownerSentence("", "", "only the installation-wide role operates it")).toBe("no owning directory: only the installation-wide role operates it");
  });
});
