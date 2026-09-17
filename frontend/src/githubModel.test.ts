import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";

import { GetGitHubStatusResponseSchema, GitHubCatalogueAppSchema, GitHubTeamStatusSchema } from "./gen/directoryroster/v1/github_pb";
import { appsOf, atMost, feedsOnlyItself, fixSentence, groupApps, keyLocation, organisationNeeds, permissionDiffers, sentence, summaryOf } from "./githubModel";

type StatusInit = MessageInitShape<typeof GetGitHubStatusResponseSchema>;
type CatalogueInit = MessageInitShape<typeof GitHubCatalogueAppSchema>;

function status(init: StatusInit) {
  return create(GetGitHubStatusResponseSchema, { reportsAvailable: true, connectingAvailable: true, linkingAvailable: true, ...init });
}

function tokensApp(init: CatalogueInit): CatalogueInit {
  return { org: "example-org", declared: true, installation: "all", ...init };
}

const byId = (s: ReturnType<typeof status>) => new Map(appsOf(s).map((app) => [app.id, app]));

describe("appsOf", () => {
  it("turns every shape the status carries into one kind of row", () => {
    const apps = byId(
      status({
        organisations: [{ org: "example-org", bound: true, reported: true, connection: { appSlug: "example-org-roster", installed: true, appId: 1n } }],
        linkApp: { appSlug: "example-org-link", owner: "example-org", appId: 3n },
        links: [{ login: "ada", emails: ["ada@example.com"], state: "linked" }],
        runnerTiers: ["standard", "large"],
        runnerApps: [{ org: "example-org", tier: "standard", appSlug: "example-org-runners-standard", installed: true }],
        catalogueApps: [tokensApp({ id: "release-bot", state: "installed", appSlug: "example-org-release", grants: [{ group: "all:platform", repositories: ["*"] }] })],
      }),
    );

    expect([...apps.keys()].sort()).toEqual(["example-org-controller", "example-org-runners-large", "example-org-runners-standard", "link", "release-bot"]);

    expect(apps.get("link")).toMatchObject({ purpose: "link", origin: "preset", stage: "installed", label: "done", org: "example-org" });
    expect(apps.get("example-org-controller")).toMatchObject({ purpose: "controller", stage: "installed", label: "done", name: "example-org-roster" });
    expect(apps.get("example-org-runners-standard")).toMatchObject({ purpose: "runners", tier: "standard", stage: "installed", label: "done" });
    expect(apps.get("example-org-runners-large")).toMatchObject({ purpose: "runners", tier: "large", stage: "not-created", label: "needs-you", fix: "create" });
    expect(apps.get("release-bot")).toMatchObject({ purpose: "tokens", origin: "catalogue", stage: "installed", label: "done", repositories: "every repository" });
    expect(apps.get("release-bot")?.settingsUrl).toBe("https://github.com/organizations/example-org/settings/apps/example-org-release");
  });

  it("says who moves next for every stage", () => {
    const apps = byId(
      status({
        organisations: [
          { org: "created-org", bound: true, connection: { appSlug: "created", installed: false } },
          { org: "missing-org", bound: true },
          { org: "quiet-org", bound: true, reported: false, connection: { appSlug: "quiet", installed: true } },
          { org: "dropped-org", bound: false, reported: true, connection: { appSlug: "dropped", installed: true } },
          { org: "forgotten-org", bound: false, reported: true },
        ],
        linkingAvailable: true,
        catalogueApps: [
          tokensApp({ id: "drifted", state: "drifted", appSlug: "d", drift: ["The App lacks contents: write."] }),
          tokensApp({ id: "created", state: "created", appSlug: "c" }),
          tokensApp({ id: "fresh", state: "not_created" }),
          tokensApp({ id: "gone", state: "installed", appSlug: "g", declared: false }),
        ],
      }),
    );

    expect(apps.get("created-org-controller")).toMatchObject({ stage: "created", label: "needs-you", fix: "install" });
    expect(apps.get("missing-org-controller")).toMatchObject({ stage: "not-created", label: "needs-you", fix: "create" });
    expect(apps.get("quiet-org-controller")).toMatchObject({ stage: "installed", label: "waiting-controller" });
    expect(apps.get("dropped-org-controller")).toMatchObject({ label: "needs-you", fix: "disconnect", declared: false });
    // Nothing was ever created for an organisation the policy no longer
    // binds, so there is no App to show.
    expect(apps.has("forgotten-org-controller")).toBe(false);
    expect(apps.get("link")).toMatchObject({ stage: "not-created", label: "needs-you", fix: "create" });
    expect(apps.get("drifted")).toMatchObject({ stage: "drifted", label: "needs-you", fix: "recheck", exact: "differs on GitHub" });
    expect(apps.get("created")).toMatchObject({ stage: "created", label: "needs-you", fix: "install" });
    expect(apps.get("fresh")).toMatchObject({ stage: "not-created", label: "needs-you", fix: "create" });
    expect(apps.get("gone")).toMatchObject({ label: "needs-you", fix: "disconnect" });
  });

  it("waits on people while nobody has linked through the link App", () => {
    const apps = byId(status({ linkApp: { appSlug: "link", owner: "example-org" } }));
    expect(apps.get("link")).toMatchObject({ label: "waiting-person" });
  });

  it("shows no link App where linking is not possible and none was created", () => {
    expect(byId(status({ linkingAvailable: false })).has("link")).toBe(false);
  });

  it("keeps a runner App for a tier no longer declared, to disconnect", () => {
    const apps = byId(
      status({
        organisations: [{ org: "example-org", bound: true }],
        runnerTiers: [],
        runnerApps: [{ org: "example-org", tier: "old", appSlug: "old", installed: true }],
      }),
    );
    expect(apps.get("example-org-runners-old")).toMatchObject({ declared: false, fix: "disconnect" });
  });

  it("lets a catalogue id keep its name and moves the preset aside", () => {
    const apps = byId(
      status({
        organisations: [{ org: "example-org", bound: true }],
        linkingAvailable: true,
        catalogueApps: [tokensApp({ id: "link", state: "not_created" }), tokensApp({ id: "example-org-controller", state: "not_created" })],
      }),
    );
    expect(apps.get("link")).toMatchObject({ origin: "catalogue", purpose: "tokens" });
    expect(apps.get("link-preset")).toMatchObject({ origin: "preset", purpose: "link" });
    expect(apps.get("example-org-controller")).toMatchObject({ origin: "catalogue" });
    expect(apps.get("example-org-controller-preset")).toMatchObject({ origin: "preset", purpose: "controller" });
    expect(new Set(appsOf(status({ catalogueApps: [tokensApp({ id: "link" }), tokensApp({ id: "link-preset" })] })).map((a) => a.id)).size).toBe(3);
  });
});

describe("groupApps", () => {
  it("puts the link App first, then organisations with something to fix, needs-you rows first", () => {
    const groups = groupApps(
      appsOf(
        status({
          organisations: [
            { org: "a-org", bound: true, reported: true, connection: { appSlug: "a", installed: true } },
            { org: "b-org", bound: true, reported: true, connection: { appSlug: "b", installed: true } },
          ],
          linkApp: { appSlug: "link", owner: "a-org" },
          links: [{ state: "linked", emails: ["ada@example.com"] }],
          catalogueApps: [tokensApp({ id: "b-tokens", org: "b-org", state: "created", appSlug: "bt" })],
        }),
      ),
    );
    expect(groups.map((g) => g.org)).toEqual(["", "b-org", "a-org"]);
    expect(groups[1].apps.map((a) => a.id)).toEqual(["b-tokens", "b-org-controller"]);
  });
});

describe("summaryOf", () => {
  const one = (s: ReturnType<typeof status>, id: string) => byId(s).get(id)!;

  it("says what a token App mints, where, and where it stands", () => {
    const s = status({
      catalogueApps: [
        tokensApp({
          id: "release-bot",
          state: "installed",
          appSlug: "r",
          grants: [
            { group: "all:platform", repositories: ["*"] },
            { group: "all:release", repositories: ["*"] },
            { group: "all:release", repositories: ["*"] },
          ],
        }),
        tokensApp({ id: "docs-bot", state: "drifted", appSlug: "d", grants: [{ group: "all:docs", repositories: ["docs"] }] }),
        tokensApp({ id: "lonely", state: "not_created" }),
      ],
    });
    expect(summaryOf(one(s, "release-bot"))).toBe("Mints tokens for 2 internal groups on every repository in example-org; installed, matches its declaration.");
    expect(summaryOf(one(s, "docs-bot"))).toBe("Mints tokens for 1 internal group on docs in example-org; installed, and differs from its declaration on GitHub.");
    expect(summaryOf(one(s, "lonely"))).toBe("No internal group may mint tokens of it in example-org; not created yet.");
  });

  it("says what a preset App is for", () => {
    const s = status({
      organisations: [{ org: "example-org", bound: true, reported: true, connection: { appSlug: "c", installed: false } }],
      runnerTiers: ["standard"],
      runnerApps: [{ org: "example-org", tier: "standard", appSlug: "r", installed: true }],
      linkApp: { appSlug: "l", owner: "example-org" },
    });
    expect(summaryOf(one(s, "example-org-runners-standard"))).toBe("The standard runners register with example-org through it; installed.");
    expect(summaryOf(one(s, "example-org-controller"))).toBe("The controller manages example-org's members and teams through it; created, not installed yet.");
    expect(summaryOf(one(s, "link"), 4)).toBe("People link their GitHub account through it; 4 accounts linked.");
    expect(summaryOf(one(s, "link"), 1)).toBe("People link their GitHub account through it; 1 account linked.");
  });

  it("gives every App that needs you exactly one fix", () => {
    const s = status({
      organisations: [{ org: "example-org", bound: true }],
      catalogueApps: [tokensApp({ id: "drifted", state: "drifted", appSlug: "d" })],
    });
    for (const app of appsOf(s).filter((a) => a.label === "needs-you")) expect(fixSentence(app)).not.toBe("");
  });
});

describe("the rest of the App page", () => {
  it("names the Secret each kind of App keeps its key in", () => {
    const apps = byId(
      status({
        organisations: [{ org: "example-org", bound: true }],
        runnerTiers: ["standard"],
        catalogueApps: [tokensApp({ id: "release-bot", state: "not_created" })],
      }),
    );
    expect(keyLocation(apps.get("example-org-controller")!)).toEqual({ secret: "<release>-github-apps", keys: ["example-org.json"] });
    expect(keyLocation(apps.get("link")!).keys).toEqual(["_link.json"]);
    expect(keyLocation(apps.get("example-org-runners-standard")!).keys[0]).toBe("standard.example-org.github_app_id");
    expect(keyLocation(apps.get("release-bot")!)).toMatchObject({ secret: "<release>-github-catalogue-apps" });
  });

  it("reads GitHub's implied metadata permission as no difference", () => {
    expect(permissionDiffers({ name: "metadata", declared: "", app: "read", installation: "read" } as never)).toBe(false);
    expect(permissionDiffers({ name: "contents", declared: "write", app: "write", installation: "write" } as never)).toBe(false);
    expect(permissionDiffers({ name: "contents", declared: "write", app: "read", installation: "read" } as never)).toBe(true);
    expect(permissionDiffers({ name: "contents", declared: "write", app: "", installation: "" } as never)).toBe(false);
  });

  it("keeps at most short", () => {
    expect(atMost({ contents: "read" })).toBe("contents: read");
    expect(atMost({ contents: "write", issues: "read", pull_requests: "write" })).toBe("3 permissions, 2 above read");
  });
});

describe("organisation pages", () => {
  it("counts an organisation's Apps that need you, not the link App", () => {
    const s = status({
      organisations: [{ org: "example-org", bound: true, reported: true }],
      runnerTiers: ["standard"],
    });
    expect(organisationNeeds(s.organisations[0], appsOf(s))).toEqual(["2 Apps need you"]);
    expect(organisationNeeds(s.organisations[0])).toEqual([]);
  });

  it("hides a Fed by that only repeats the team", () => {
    expect(feedsOnlyItself(create(GitHubTeamStatusSchema, { team: "platform", memberGroups: ["all:github:platform"] }))).toBe(true);
    expect(feedsOnlyItself(create(GitHubTeamStatusSchema, { team: "platform", memberGroups: ["all:github:platform"], maintainerGroups: ["all:github:platform"] }))).toBe(
      true,
    );
    expect(feedsOnlyItself(create(GitHubTeamStatusSchema, { team: "platform", memberGroups: ["devel:k8s:viewer"] }))).toBe(false);
    expect(feedsOnlyItself(create(GitHubTeamStatusSchema, { team: "platform", memberGroups: ["all:platform", "all:security"] }))).toBe(false);
  });

  it("states the owner rule once, not on each owner's row", () => {
    expect(sentence({ state: "reported", reason: "an owner, managed outside" } as never, true)).toBe("");
  });
});

describe("catalogueView", () => {
  it("carries the reason GitHub could not be asked into the exact state", () => {
    const app = byId(status({ catalogueApps: [tokensApp({ id: "x", state: "installed", appSlug: "x", reason: "GitHub could not be asked" })] })).get("x");
    expect(app?.exact).toBe("installed: GitHub could not be asked");
  });
});
