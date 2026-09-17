import type { Timestamp } from "@bufbuild/protobuf/wkt";
import type {
  GetGitHubStatusResponse,
  GitHubAppGrant,
  GitHubAppPermission,
  GitHubCatalogueApp,
  GitHubMember,
  GitHubOrganisation,
  GitHubRunnerApp,
  GitHubTeamStatus,
} from "./gen/directoryroster/v1/github_pb";

/** What a row means to a reader: done or in hand, waiting on the person,
 *  or waiting on an operator. The controller's exact state stays in the
 *  tooltip; the controller itself never reads these. */
export type Label = "ok" | "their-move" | "needs-you";

export function labelOf(state: string): Label {
  switch (state) {
    case "held":
      return "needs-you";
    case "not-linked":
    case "invited":
    case "ignored":
      return "their-move";
    default:
      return "ok";
  }
}

/** The controller's word for a state, for the tooltip. */
const exact: Record<string, string> = {
  synced: "synced",
  pending: "pending",
  invited: "invited",
  leaving: "leaving",
  retrying: "retrying",
  held: "held",
  ignored: "ignored invitations",
  reported: "an owner, reported",
  "not-linked": "not linked",
};

/** One sentence on what happens next for a row. */
export function sentence(member: GitHubMember, acting: boolean): string {
  switch (member.state) {
    case "synced":
      return "";
    case "pending":
      return member.action === "invite"
        ? `${acting ? "invites" : "would invite"} ${member.login ? `@${member.login}` : "them"}`
        : member.action === "set-role"
          ? `${acting ? "changes" : "would change"} their role to ${member.role}`
          : `${acting ? "adds" : "would add"} them as ${member.role}`;
    case "leaving":
      return `${acting ? "removes" : "would remove"} them${member.reason ? ` — ${member.reason}` : ""}`;
    case "invited":
      return "invited, not accepted yet";
    case "not-linked":
      return member.reason || "has not linked a GitHub account";
    case "retrying":
      return `tried again next pass: ${member.reason}`;
    case "reported":
      // An owner: the rule is stated once above the table (ownerRule), not
      // on every row.
      return "";
    default:
      return member.reason;
  }
}

export function tooltipOf(member: GitHubMember): string {
  const word = exact[member.state] ?? member.state;
  return member.reason ? `${word}: ${member.reason}` : word;
}

/** One membership row, with where it is. */
export type Row = { org: string; team: string; member: GitHubMember };

export function rowsOf(org: GitHubOrganisation): Row[] {
  return [
    ...org.members.map((member) => ({ org: org.org, team: "", member })),
    ...org.teams.flatMap((team) => team.members.map((member) => ({ org: org.org, team: team.team, member }))),
  ];
}

export type Counts = Record<Label, number>;

export function countLabels(members: GitHubMember[]): Counts {
  const out: Counts = { ok: 0, "their-move": 0, "needs-you": 0 };
  for (const member of members) out[labelOf(member.state)]++;
  return out;
}

/** Everything that needs an operator in an organisation, beyond its rows. */
export function organisationNeeds(org: GitHubOrganisation, apps?: GitHubAppView[]): string[] {
  const out: string[] = [];
  // Its Apps are counted where they are listed, so an organisation page and
  // the Apps list agree: not created, not installed, or differing on GitHub.
  const waiting = (apps ?? []).filter((app) => app.org === org.org && app.purpose !== "link" && app.label === "needs-you").length;
  if (waiting) out.push(`${waiting} ${waiting === 1 ? "App needs" : "Apps need"} you`);
  if (org.seats && !org.seats.known) out.push("seats cannot be counted");
  if (org.seats?.known && org.seats.short > 0) out.push(`${org.seats.short} short of seats`);
  if (org.breaker && !org.breaker.confirmed) out.push(`${org.breaker.affected} removals wait for confirmation`);
  if (org.tick?.outcome === "failed") out.push("the last pass failed");
  return out;
}

/** People across every organisation, once each, by address. */
export type Person = { email: string; login: string; places: string[]; label: Label };

export function peopleOf(organisations: GitHubOrganisation[]): Person[] {
  const rank: Record<Label, number> = { "needs-you": 0, "their-move": 1, ok: 2 };
  const byEmail = new Map<string, Person>();
  for (const org of organisations) {
    for (const row of rowsOf(org)) {
      if (!row.member.email) continue;
      const person = byEmail.get(row.member.email) ?? { email: row.member.email, login: "", places: [], label: "ok" as Label };
      if (row.member.login && !person.login) person.login = row.member.login;
      person.places.push(row.team ? `${row.org} / ${row.team}` : row.org);
      const label = labelOf(row.member.state);
      if (rank[label] < rank[person.label]) person.label = label;
      byEmail.set(row.member.email, person);
    }
  }
  return [...byEmail.values()].sort((a, b) => rank[a.label] - rank[b.label] || a.email.localeCompare(b.email));
}

/** Where a person links, at the origin root beside the other GitHub pages. */
export function linkPage(url?: string): string {
  return url || `${window.location.origin}/connect/github/link`;
}

// -------------------------------------------------------------------- apps

/** What an App is for, in the one list every App is in. */
export type AppPurpose = "link" | "controller" | "runners" | "tokens";

/** Where an App stands, for a reader: done, or who has to move next. The
 *  exact state stays in the tooltip. */
export type AppLabel = "done" | "needs-you" | "waiting-person" | "waiting-controller";

/** How far along GitHub's two clicks an App is. */
export type AppStage = "not-created" | "created" | "installed" | "drifted";

/** The single fix an App that needs you asks for. */
export type AppFix = "create" | "install" | "recheck" | "disconnect" | "none";

/** One App, whichever of the four shapes the status carries it in: the
 *  link App, an organisation's controller App, a runner App, or an App the
 *  catalogue declares. Every list row and every App page reads this. */
export type GitHubAppView = {
  /** Stable, and the page's address: `link`, `<org>-controller`,
   *  `<org>-runners-<tier>`, or the catalogue id. */
  id: string;
  /** The organisation it is installed on — for the link App, the one it
   *  is created under. */
  org: string;
  purpose: AppPurpose;
  tier?: string;
  origin: "preset" | "catalogue";
  /** The App's name on GitHub once created; the declared name before. */
  name: string;
  slug: string;
  stage: AppStage;
  label: AppLabel;
  /** The exact state, for the tooltip. */
  exact: string;
  fix: AppFix;
  /** Whether the deployment still declares it: an App created for a tier,
   *  an organisation or a catalogue entry since dropped can only be
   *  disconnected. */
  declared: boolean;
  /** Plain words for the repositories it reaches. */
  repositories: string;
  grants: GitHubAppGrant[];
  /** Declared beside held; absent where the status has none to show. */
  permissions?: GitHubAppPermission[];
  drift: string[];
  events: string[];
  description: string;
  /** Why GitHub could not be asked, when it could not. */
  reason: string;
  htmlUrl: string;
  settingsUrl: string;
  appId: bigint;
  installationId: bigint;
  connectedBy: string;
  connectedAt?: Timestamp;
  checkedAt?: Timestamp;
  installation: string;
  public: boolean;
};

const purposeOrder: Record<AppPurpose, number> = { link: 0, controller: 1, runners: 2, tokens: 3 };

/** The id a preset App would have, unless the catalogue already uses it:
 *  a catalogue id is the operator's own name for an App, so it wins and the
 *  preset moves aside. */
function presetId(base: string, taken: Set<string>): string {
  let id = base;
  while (taken.has(id)) id = `${id}-preset`;
  taken.add(id);
  return id;
}

/** Where an owner edits an App, and deletes it. */
export function appSettingsURL(org: string, slug: string): string {
  return org && slug ? `https://github.com/organizations/${encodeURIComponent(org)}/settings/apps/${encodeURIComponent(slug)}` : "";
}

function scopeWords(scope: string): string {
  return ({ all: "every repository", selected: "selected repositories" } as Record<string, string>)[scope] ?? scope;
}

function stageLabel(stage: AppStage, declared: boolean): { label: AppLabel; fix: AppFix } {
  if (!declared) return { label: "needs-you", fix: stage === "not-created" ? "none" : "disconnect" };
  switch (stage) {
    case "not-created":
      return { label: "needs-you", fix: "create" };
    case "created":
      return { label: "needs-you", fix: "install" };
    case "drifted":
      return { label: "needs-you", fix: "recheck" };
    default:
      return { label: "done", fix: "none" };
  }
}

const exactStage: Record<AppStage, string> = {
  "not-created": "not created",
  created: "created, not installed",
  installed: "installed",
  drifted: "differs on GitHub",
};

/** Every App the status knows of, as one kind of row. */
export function appsOf(status: GetGitHubStatusResponse): GitHubAppView[] {
  const out: GitHubAppView[] = [];
  const taken = new Set(status.catalogueApps.map((app) => app.id));
  const bound = new Set(status.organisations.filter((org) => org.bound).map((org) => org.org));
  const blank = {
    tier: undefined,
    grants: [] as GitHubAppGrant[],
    permissions: undefined,
    drift: [] as string[],
    events: [] as string[],
    description: "",
    reason: "",
    installationId: 0n,
    checkedAt: undefined,
    installation: "",
    public: false,
  };

  // The link App: one, for every organisation.
  if (status.linkApp || status.linkingAvailable) {
    const app = status.linkApp;
    const linked = status.links.filter((l) => l.state === "linked").length;
    const stage: AppStage = app ? "installed" : "not-created";
    let { label, fix } = stageLabel(stage, true);
    let exact = app ? "created; installed nowhere, by design" : "not created";
    if (app && linked === 0) {
      label = "waiting-person";
      exact = "created; nobody has linked an account through it yet";
    }
    out.push({
      ...blank,
      id: presetId("link", taken),
      org: app?.owner ?? "",
      purpose: "link",
      origin: "preset",
      name: app?.appSlug || "link App",
      slug: app?.appSlug ?? "",
      stage,
      label,
      exact,
      fix,
      declared: true,
      repositories: "installed nowhere",
      htmlUrl: app?.htmlUrl ?? "",
      settingsUrl: app ? appSettingsURL(app.owner, app.appSlug) : "",
      appId: app?.appId ?? 0n,
      connectedBy: app?.connectedBy ?? "",
      connectedAt: app?.connectedAt,
      public: true,
    });
  }

  // One controller App per organisation.
  for (const org of status.organisations) {
    const c = org.connection;
    if (!c && !org.bound) continue;
    const stage: AppStage = !c ? "not-created" : c.installed ? "installed" : "created";
    let { label, fix } = stageLabel(stage, org.bound);
    let exact = org.bound ? exactStage[stage] : `${exactStage[stage]}; ${org.org} is no longer bound in the policy`;
    if (org.bound && stage === "installed" && status.reportsAvailable && !org.reported) {
      label = "waiting-controller";
      exact = "installed; the controller has not reported on the organisation yet";
    }
    out.push({
      ...blank,
      id: presetId(`${org.org}-controller`, taken),
      org: org.org,
      purpose: "controller",
      origin: "preset",
      name: c?.appSlug || `${org.org} controller App`,
      slug: c?.appSlug ?? "",
      stage,
      label,
      exact,
      fix,
      declared: org.bound,
      repositories: "none: members and teams only",
      htmlUrl: c?.htmlUrl ?? "",
      settingsUrl: c ? appSettingsURL(org.org, c.appSlug) : "",
      appId: c?.appId ?? 0n,
      connectedBy: c?.connectedBy ?? "",
      connectedAt: c?.connectedAt,
    });
  }

  // One runner App per bound organisation per declared tier, and any
  // created for a tier or an organisation since dropped.
  const runners = new Map<string, { org: string; tier: string; app?: GitHubRunnerApp }>();
  for (const org of [...bound].sort()) for (const tier of status.runnerTiers) runners.set(`${org}/${tier}`, { org, tier });
  for (const app of status.runnerApps) runners.set(`${app.org}/${app.tier}`, { org: app.org, tier: app.tier, app });
  for (const { org, tier, app } of runners.values()) {
    const declared = bound.has(org) && status.runnerTiers.includes(tier);
    const stage: AppStage = !app ? "not-created" : app.installed ? "installed" : "created";
    const { label, fix } = stageLabel(stage, declared);
    out.push({
      ...blank,
      id: presetId(`${org}-runners-${tier}`, taken),
      org,
      purpose: "runners",
      tier,
      origin: "preset",
      name: app?.appSlug || `${org} ${tier} runner App`,
      slug: app?.appSlug ?? "",
      stage,
      label,
      exact: declared ? exactStage[stage] : `${exactStage[stage]}; the ${tier} tier in ${org} is no longer declared`,
      fix,
      declared,
      repositories: "none: registers runners with the organisation",
      htmlUrl: app?.htmlUrl ?? "",
      settingsUrl: app ? appSettingsURL(org, app.appSlug) : "",
      appId: app?.appId ?? 0n,
      connectedBy: app?.connectedBy ?? "",
      connectedAt: app?.connectedAt,
    });
  }

  // Every App the catalogue declares, or was created from.
  for (const app of status.catalogueApps) out.push(catalogueView(app));

  return out;
}

/** One catalogue App as a row. Exported for the page that re-checks one
 *  App on its own and has only the answer to show. */
export function catalogueView(app: GitHubCatalogueApp): GitHubAppView {
  const stage: AppStage = app.state === "installed" ? "installed" : app.state === "created" ? "created" : app.state === "drifted" ? "drifted" : "not-created";
  const { label, fix } = stageLabel(stage, app.declared);
  const word = app.declared ? exactStage[stage] : `${exactStage[stage]}; the catalogue no longer declares it`;
  return {
    id: app.id,
    org: app.org,
    purpose: "tokens",
    origin: "catalogue",
    name: app.appSlug || app.name || app.id,
    slug: app.appSlug,
    stage,
    label,
    exact: app.reason ? `${word}: ${app.reason}` : word,
    fix,
    declared: app.declared,
    repositories: scopeWords(app.repositorySelection || app.installation),
    grants: app.grants,
    permissions: app.permissions,
    drift: app.drift,
    events: app.events,
    description: app.description,
    reason: app.reason,
    htmlUrl: app.htmlUrl,
    settingsUrl: appSettingsURL(app.org, app.appSlug),
    appId: app.appId,
    installationId: app.installationId,
    connectedBy: app.connectedBy,
    connectedAt: app.connectedAt,
    checkedAt: app.checkedAt,
    installation: app.installation,
    public: app.public,
  };
}

/** What an App is for, in plain words. */
export function purposeWords(app: GitHubAppView): string {
  switch (app.purpose) {
    case "link":
      return "links accounts (every organisation)";
    case "controller":
      return "manages teams";
    case "runners":
      return `runners · ${app.tier}`;
    default:
      return "tokens";
  }
}

/** The Apps list's shape: the link App on its own, then each organisation,
 *  and within each the Apps that need you first, then by purpose. An
 *  organisation with something to fix comes before one without. */
export function groupApps(apps: GitHubAppView[]): { org: string; apps: GitHubAppView[] }[] {
  const rank = (app: GitHubAppView) => (app.label === "needs-you" ? 0 : 1);
  const groups = new Map<string, GitHubAppView[]>();
  for (const app of apps) {
    const key = app.purpose === "link" ? "" : app.org;
    groups.set(key, [...(groups.get(key) ?? []), app]);
  }
  return [...groups.entries()]
    .map(([org, list]) => ({
      org,
      apps: list.sort((a, b) => rank(a) - rank(b) || purposeOrder[a.purpose] - purposeOrder[b.purpose] || a.id.localeCompare(b.id)),
    }))
    .sort(
      (a, b) =>
        (a.org === "" ? -1 : 0) - (b.org === "" ? -1 : 0) ||
        Math.min(...a.apps.map(rank)) - Math.min(...b.apps.map(rank)) ||
        a.org.localeCompare(b.org),
    );
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** Where a token App's grants reach, as words. */
function grantReach(app: GitHubAppView): string {
  const everywhere = app.grants.length > 0 && app.grants.every((g) => g.repositories.includes("*"));
  if (everywhere) return `every repository in ${app.org}`;
  const names = [...new Set(app.grants.flatMap((g) => g.repositories).filter((r) => r !== "*"))];
  return names.length === 1 && app.grants.every((g) => !g.repositories.includes("*")) ? `${names[0]} in ${app.org}` : `some repositories in ${app.org}`;
}

function stageClause(app: GitHubAppView): string {
  if (!app.declared) return app.stage === "not-created" ? "no longer declared" : "no longer declared: disconnect it";
  switch (app.stage) {
    case "not-created":
      return "not created yet";
    case "created":
      return "created, not installed yet";
    case "drifted":
      return "installed, and differs from its declaration on GitHub";
    default:
      return app.purpose === "tokens" ? "installed, matches its declaration" : "installed";
  }
}

/** The one line an App's page opens with, from its facts. */
export function summaryOf(app: GitHubAppView, linked = 0): string {
  switch (app.purpose) {
    case "link":
      return app.stage === "not-created"
        ? "People link their GitHub account through it, once it is created; nobody can link until then."
        : `People link their GitHub account through it; ${plural(linked, "account", "accounts")} linked.`;
    case "controller":
      return `The controller manages ${app.org}'s members and teams through it; ${stageClause(app)}.`;
    case "runners":
      return `The ${app.tier} runners register with ${app.org} through it; ${stageClause(app)}.`;
    default: {
      const groups = new Set(app.grants.map((g) => g.group)).size;
      return groups === 0
        ? `No internal group may mint tokens of it in ${app.org}; ${stageClause(app)}.`
        : `Mints tokens for ${plural(groups, "internal group", "internal groups")} on ${grantReach(app)}; ${stageClause(app)}.`;
    }
  }
}

/** The fix an App that needs you asks for, in a sentence. */
export function fixSentence(app: GitHubAppView): string {
  switch (app.fix) {
    case "create":
      return app.purpose === "link"
        ? "Create it: an owner of an organisation creates it in one click, and it is installed nowhere."
        : `Create it: an owner of ${app.org} creates it, then installs it — two clicks.`;
    case "install":
      return `Finish installing it: an owner of ${app.org} installs it on GitHub.`;
    case "recheck":
      return `An owner of ${app.org} edits its permissions in the App's settings on GitHub — or the declaration changes to match — then Re-check.`;
    case "disconnect":
      return "The deployment no longer declares it: disconnect it here, and delete it on GitHub.";
    default:
      return "";
  }
}

/** A short "at most" for a grant: the permissions it allows, by name. */
export function atMost(permissions: Record<string, string>): string {
  const entries = Object.entries(permissions).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) return "nothing";
  if (entries.length <= 2) return entries.map(([name, level]) => `${name}: ${level}`).join(", ");
  const writes = entries.filter(([, level]) => level !== "read").length;
  return `${plural(entries.length, "permission", "permissions")}${writes ? `, ${writes} above read` : ", all read"}`;
}

/** The repositories a grant names, in words. */
export function repositoryWords(repositories: string[], org: string): string {
  return repositories.map((r) => (r === "*" ? `every repository in ${org}` : r)).join(", ");
}

/** Where an App's key is kept, for a deployment copying it. */
export function keyLocation(app: GitHubAppView): { secret: string; keys: string[] } {
  const properties = (prefix: string) => ["github_app_id", "github_app_installation_id", "github_app_private_key", "record.json"].map((k) => `${prefix}.${k}`);
  switch (app.purpose) {
    case "link":
      return { secret: "<release>-github-apps", keys: ["_link.json"] };
    case "controller":
      return { secret: "<release>-github-apps", keys: [`${app.org}.json`] };
    case "runners":
      return { secret: "<release>-github-runner-apps", keys: properties(`${app.tier}.${app.org}`) };
    default:
      return { secret: "<release>-github-catalogue-apps", keys: properties(app.id) };
  }
}

/** Whether a permission row differs anywhere. GitHub adds metadata: read
 *  to every App on its own, which is not a difference. */
export function permissionDiffers(p: GitHubAppPermission): boolean {
  const implied = p.name === "metadata" && !p.declared;
  const app = implied && p.app === "read" ? "" : p.app;
  const installation = implied && p.installation === "read" ? "" : p.installation;
  return (app !== "" && app !== p.declared) || (installation !== "" && installation !== (p.app || p.declared));
}

/** The rule every GitHub membership table states once: owners are managed
 *  outside the policy. */
export const ownerRule = "Organisation owners are managed outside the policy: they are reported here and never changed.";

/** Whether a team is fed only by the internal group named for it, so a
 *  "Fed by" column would repeat the team's own name on every row. */
export function feedsOnlyItself(team: GitHubTeamStatus): boolean {
  const groups = [...new Set([...team.memberGroups, ...team.maintainerGroups])];
  const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
  return groups.length === 1 && norm(team.team) !== "" && norm(groups[0]).endsWith(norm(team.team));
}

/** How many of an organisation's Apps need you. */
export function appsNeedingYou(apps: GitHubAppView[], org: string): number {
  return apps.filter((app) => app.org === org && app.purpose !== "link" && app.label === "needs-you").length;
}
