import { create, type MessageInitShape } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";

import {
  AppAttention,
  AppOrigin,
  AppPurpose,
  AppState,
  GetGitHubStatusResponseSchema,
  GitHubAppSchema,
  GitHubTeamStatusSchema,
} from "./gen/directoryroster/v1/github_pb";
import { appView, atMost, feedsOnlyItself, fixSentence, githubCell, groupApps, organisationNeeds, permissionDiffers, sentence, summaryOf } from "./githubModel";

type AppInit = MessageInitShape<typeof GitHubAppSchema>;

/** One App as the server sends it. The defaults are an installed App
 *  the deployment still declares, which is the uninteresting case every
 *  test then varies one thing of. */
function app(init: AppInit) {
  return appView(
    create(GitHubAppSchema, {
      org: "example-org",
      origin: AppOrigin.CATALOGUE,
      purpose: AppPurpose.TOKENS,
      state: AppState.INSTALLED,
      attention: AppAttention.DONE,
      declared: true,
      installation: "all",
      ...init,
    }),
  );
}

describe("appView", () => {
  it("reads every kind of App as one kind of row", () => {
    expect(app({ id: "link", purpose: AppPurpose.LINK, origin: AppOrigin.PRESET, name: "example-org-link", linkedAccounts: 4 })).toMatchObject({
      purpose: "link",
      origin: "preset",
      stage: "installed",
      label: "done",
      fix: "none",
      repositories: "installed nowhere",
      linked: 4,
    });
    expect(app({ id: "example-org-controller", purpose: AppPurpose.CONTROLLER, origin: AppOrigin.PRESET })).toMatchObject({
      purpose: "controller",
      repositories: "none: members and teams only",
    });
    expect(app({ id: "example-org-runners-standard", purpose: AppPurpose.RUNNERS, origin: AppOrigin.PRESET, tier: "standard" })).toMatchObject({
      purpose: "runners",
      tier: "standard",
      repositories: "none: registers runners with the organisation",
    });
    expect(app({ id: "release-bot", repositorySelection: "selected" })).toMatchObject({
      purpose: "tokens",
      origin: "catalogue",
      repositories: "selected repositories",
    });
    // Nothing is installed yet, so what the installer is expected to
    // choose is what the row says.
    expect(app({ id: "release-bot", state: AppState.NOT_CREATED }).repositories).toBe("every repository");
  });

  it("turns each state into the one fix it asks for", () => {
    const fixes = (declared: boolean) =>
      [AppState.NOT_CREATED, AppState.CREATED, AppState.INSTALLED, AppState.DRIFTED].map(
        (state) => app({ id: "x", state, declared }).fix,
      );
    expect(fixes(true)).toEqual(["create", "install", "none", "recheck"]);
    // An App the deployment no longer declares has one thing left to do,
    // and nothing at all if it was never created.
    expect(fixes(false)).toEqual(["none", "disconnect", "disconnect", "disconnect"]);
  });

  it("says who moves next in the server's words, not its own", () => {
    expect(
      app({ id: "link", purpose: AppPurpose.LINK, attention: AppAttention.WAITING_PERSON, stateDetail: "created; nobody has linked an account through it yet" }),
    ).toMatchObject({ label: "waiting-person", exact: "created; nobody has linked an account through it yet" });
    expect(app({ id: "c", attention: AppAttention.WAITING_CONTROLLER }).label).toBe("waiting-controller");
    expect(app({ id: "c", attention: AppAttention.NEEDS_YOU }).label).toBe("needs-you");
  });

  it("carries what the App holds and where its key is kept", () => {
    const view = app({
      id: "release-bot",
      appSlug: "example-org-release-bot",
      settingsUrl: "https://github.com/organizations/example-org/settings/apps/example-org-release-bot",
      permissions: [{ name: "contents", declared: "write", app: "write", installation: "write" }],
      drift: ["The App lacks issues: write. Add it in the App's settings on GitHub."],
      secret: "access-issuer-github-catalogue-apps",
      secretKeys: ["release-bot.record.json", "release-bot.github_app_private_key"],
    });
    expect(view.settingsUrl).toBe("https://github.com/organizations/example-org/settings/apps/example-org-release-bot");
    expect(view.permissions).toHaveLength(1);
    expect(view.drift).toHaveLength(1);
    expect(view.secret).toBe("access-issuer-github-catalogue-apps");
    expect(view.secretKeys).toHaveLength(2);
  });
});

describe("groupApps", () => {
  it("puts the link App first, then organisations with something to fix, needs-you rows first", () => {
    const groups = groupApps([
      app({ id: "link", purpose: AppPurpose.LINK, origin: AppOrigin.PRESET, org: "a-org" }),
      app({ id: "a-org-controller", purpose: AppPurpose.CONTROLLER, origin: AppOrigin.PRESET, org: "a-org" }),
      app({ id: "b-org-controller", purpose: AppPurpose.CONTROLLER, origin: AppOrigin.PRESET, org: "b-org" }),
      app({ id: "b-tokens", org: "b-org", state: AppState.CREATED, attention: AppAttention.NEEDS_YOU }),
    ]);
    expect(groups.map((g) => g.org)).toEqual(["", "b-org", "a-org"]);
    expect(groups[1].apps.map((a) => a.id)).toEqual(["b-tokens", "b-org-controller"]);
  });
});

describe("summaryOf", () => {
  it("says what a token App mints, where, and where it stands", () => {
    const grants = (...groups: string[]) => groups.map((group) => ({ group, repositories: ["*"] }));
    expect(summaryOf(app({ id: "release-bot", grants: grants("all:platform", "all:release", "all:release") }))).toBe(
      "Mints tokens for 2 internal groups on every repository in example-org; installed, matches its declaration.",
    );
    expect(
      summaryOf(app({ id: "docs-bot", state: AppState.DRIFTED, grants: [{ group: "all:docs", repositories: ["docs"] }] })),
    ).toBe("Mints tokens for 1 internal group on docs in example-org; installed, and differs from its declaration on GitHub.");
    expect(summaryOf(app({ id: "lonely", state: AppState.NOT_CREATED }))).toBe("No internal group may mint tokens of it in example-org; not created yet.");
  });

  it("says what a preset App is for, and never claims a match nobody checked", () => {
    expect(summaryOf(app({ id: "r", purpose: AppPurpose.RUNNERS, origin: AppOrigin.PRESET, tier: "standard" }))).toBe(
      "The standard runners register with example-org through it; installed, matches its declaration.",
    );
    expect(summaryOf(app({ id: "c", purpose: AppPurpose.CONTROLLER, origin: AppOrigin.PRESET, state: AppState.CREATED }))).toBe(
      "The controller manages example-org's members and teams through it; created, not installed yet.",
    );
    // GitHub could not be asked: "installed" is all that can be said.
    expect(
      summaryOf(app({ id: "c", purpose: AppPurpose.CONTROLLER, origin: AppOrigin.PRESET, reason: "The App's key is not kept here." })),
    ).toBe("The controller manages example-org's members and teams through it; installed.");
    expect(summaryOf(app({ id: "link", purpose: AppPurpose.LINK, origin: AppOrigin.PRESET, linkedAccounts: 4 }))).toBe(
      "People link their GitHub account through it; 4 accounts linked.",
    );
    expect(summaryOf(app({ id: "link", purpose: AppPurpose.LINK, origin: AppOrigin.PRESET, linkedAccounts: 1 }))).toBe(
      "People link their GitHub account through it; 1 account linked.",
    );
  });

  it("gives every App that needs you exactly one fix", () => {
    for (const state of [AppState.NOT_CREATED, AppState.CREATED, AppState.DRIFTED]) {
      expect(fixSentence(app({ id: "x", state, attention: AppAttention.NEEDS_YOU }))).not.toBe("");
    }
    expect(fixSentence(app({ id: "x", declared: false, attention: AppAttention.NEEDS_YOU }))).not.toBe("");
  });
});

describe("the rest of the App page", () => {
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
    const org = create(GetGitHubStatusResponseSchema, { organisations: [{ org: "example-org", bound: true, reported: true }] }).organisations[0];
    const apps = [
      app({ id: "link", purpose: AppPurpose.LINK, origin: AppOrigin.PRESET, attention: AppAttention.NEEDS_YOU }),
      app({ id: "example-org-controller", purpose: AppPurpose.CONTROLLER, origin: AppOrigin.PRESET, attention: AppAttention.NEEDS_YOU }),
      app({ id: "example-org-runners-large", purpose: AppPurpose.RUNNERS, origin: AppOrigin.PRESET, tier: "large", attention: AppAttention.NEEDS_YOU }),
    ];
    expect(organisationNeeds(org, apps)).toEqual(["2 Apps need you"]);
    expect(organisationNeeds(org)).toEqual([]);
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

describe("the People list's GitHub column", () => {
  it("links a linked account to its page on GitHub", () => {
    expect(githubCell("ada-north", true)).toEqual({
      kind: "linked",
      login: "ada-north",
      url: "https://github.com/ada-north",
      title: "@ada-north on GitHub",
    });
  });

  it("says nobody linked, without claiming it as a state", () => {
    const cell = githubCell("", true);
    expect(cell.kind).toBe("not-linked");
    expect(cell.title).toBe("No GitHub account is linked to this address.");
  });

  it("keeps unknown apart from not linked", () => {
    // The two arrive on the wire identically -- an empty login -- and
    // only the response's github_known tells them apart. A column that
    // merged them would report a whole company as unlinked on a read
    // that simply failed.
    expect(githubCell("", false).kind).toBe("unknown");
    expect(githubCell("ada-north", false).kind).toBe("unknown");
    expect(githubCell("", false).title).toBe("Whether a GitHub account is linked could not be read.");
  });
});
