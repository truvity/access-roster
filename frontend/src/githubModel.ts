import type { Timestamp } from "@bufbuild/protobuf/wkt";
// The wire enums, under other names: this module's own words for the
// same four things are what every page is written in.
import {
  AppAttention as WireAttention,
  AppOrigin as WireOrigin,
  AppPurpose as WirePurpose,
  AppState as WireState,
} from "./gen/directoryroster/v1/github_pb";
import type { GitHubApp, GitHubAppGrant, GitHubAppPermission, GitHubMember, GitHubOrganisation, GitHubTeamStatus } from "./gen/directoryroster/v1/github_pb";

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

/** What the People list's GitHub column says about one person: the
 *  account they linked, that they linked none, or that links could not be
 *  read at all.
 *
 *  The third is a separate answer on purpose. A deployment where nobody
 *  can link, and a link store that would not read, both come back with
 *  every login empty — and a column that drew those the same way would
 *  quietly report an entire company as having linked nothing. */
export type GitHubCell =
  | { kind: "linked"; login: string; url: string; title: string }
  | { kind: "not-linked"; title: string }
  | { kind: "unknown"; title: string };

/** The cell for one person, from the login the search returned and
 *  whether the search could read links at all. A login is a name, so it
 *  is a link to the account it names; the other two are states, and a
 *  state is never a chip on a row that already has one. */
export function githubCell(login: string, known: boolean): GitHubCell {
  if (!known) {
    return { kind: "unknown", title: "Whether a GitHub account is linked could not be read." };
  }
  if (!login) {
    return { kind: "not-linked", title: "No GitHub account is linked to this address." };
  }
  return { kind: "linked", login, url: `https://github.com/${login}`, title: `@${login} on GitHub` };
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

/** One App, whatever kind: the list, the App page, an organisation's
 *  Apps section and a group's minting section all read this. */
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
  /** Declared beside held, once there is anything to hold. */
  permissions: GitHubAppPermission[];
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
  /** Where its key is kept, for a deployment copying it. */
  secret: string;
  secretKeys: string[];
  /** Accounts linked through it. The link App only. */
  linked: number;
};

const purposeOrder: Record<AppPurpose, number> = { link: 0, controller: 1, runners: 2, tokens: 3 };

/** Where an owner edits an App, and deletes it. Only for a name the
 *  server did not give us one for. */
export function appSettingsURL(org: string, slug: string): string {
  return org && slug ? `https://github.com/organizations/${encodeURIComponent(org)}/settings/apps/${encodeURIComponent(slug)}` : "";
}

function scopeWords(scope: string): string {
  return ({ all: "every repository", selected: "selected repositories" } as Record<string, string>)[scope] ?? scope;
}

/** The single fix an App that needs you asks for. Which one follows from
 *  how far along it is and whether the deployment still declares it. */
function fixOf(stage: AppStage, declared: boolean): AppFix {
  if (!declared) return stage === "not-created" ? "none" : "disconnect";
  switch (stage) {
    case "not-created":
      return "create";
    case "created":
      return "install";
    case "drifted":
      return "recheck";
    default:
      return "none";
  }
}

function purposeOf(purpose: WirePurpose): AppPurpose {
  switch (purpose) {
    case WirePurpose.LINK:
      return "link";
    case WirePurpose.CONTROLLER:
      return "controller";
    case WirePurpose.RUNNERS:
      return "runners";
    default:
      return "tokens";
  }
}

function stageOf(state: WireState): AppStage {
  switch (state) {
    case WireState.CREATED:
      return "created";
    case WireState.INSTALLED:
      return "installed";
    case WireState.DRIFTED:
      return "drifted";
    default:
      return "not-created";
  }
}

function attentionOf(attention: WireAttention): AppLabel {
  switch (attention) {
    case WireAttention.DONE:
      return "done";
    case WireAttention.WAITING_PERSON:
      return "waiting-person";
    case WireAttention.WAITING_CONTROLLER:
      return "waiting-controller";
    default:
      return "needs-you";
  }
}

/** What the repositories an App reaches amount to, in words. Three of the
 *  four reach none, each for its own reason. */
function repositoryScope(app: GitHubApp): string {
  switch (purposeOf(app.purpose)) {
    case "link":
      return "installed nowhere";
    case "controller":
      return "none: members and teams only";
    case "runners":
      return "none: registers runners with the organisation";
    default:
      return scopeWords(app.repositorySelection || app.installation);
  }
}

/** One App as every page reads it: the server's answer, with the words
 *  the pages are written in. Nothing is derived here that the server
 *  knows — it says which state an App is in and who moves next; this
 *  turns that into the one fix to offer and the repositories in words. */
export function appView(app: GitHubApp): GitHubAppView {
  const stage = stageOf(app.state);
  return {
    id: app.id,
    org: app.org,
    purpose: purposeOf(app.purpose),
    tier: app.tier || undefined,
    origin: app.origin === WireOrigin.CATALOGUE ? "catalogue" : "preset",
    name: app.name,
    slug: app.appSlug,
    stage,
    label: attentionOf(app.attention),
    exact: app.stateDetail,
    fix: fixOf(stage, app.declared),
    declared: app.declared,
    repositories: repositoryScope(app),
    grants: app.grants,
    permissions: app.permissions,
    drift: app.drift,
    events: app.events,
    description: app.description,
    reason: app.reason,
    htmlUrl: app.htmlUrl,
    settingsUrl: app.settingsUrl,
    appId: app.appId,
    installationId: app.installationId,
    connectedBy: app.connectedBy,
    connectedAt: app.connectedAt,
    checkedAt: app.checkedAt,
    installation: app.installation,
    public: app.public,
    secret: app.secret,
    secretKeys: app.secretKeys,
    linked: app.linkedAccounts,
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
      // Only an App whose declaration was actually checked may claim a
      // match: the link App is never asked about, and neither is one
      // whose key could not be read.
      return app.purpose === "link" || app.reason ? "installed" : "installed, matches its declaration";
  }
}

/** The one line an App's page opens with, from its facts. */
export function summaryOf(app: GitHubAppView): string {
  switch (app.purpose) {
    case "link":
      return app.stage === "not-created"
        ? "People link their GitHub account through it, once it is created; nobody can link until then."
        : `People link their GitHub account through it; ${plural(app.linked, "account", "accounts")} linked.`;
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

/** What *Recent tokens* says when it has none to show.
 *
 *  Two different facts, and saying the wrong one would be a lie: this
 *  service keeps the last requests in memory, since it started, so
 *  "nothing has been asked for" is only true of the time it has been
 *  keeping them. `since` is that moment, already in words ("3h ago"), or
 *  empty where the service does not say. */
export function recentTokensEmpty(since: string): string {
  return since ? `No token has been asked for since this service started, ${since}.` : "No token has been asked for yet.";
}

/** The line under the table, for the same reason: what is above it is
 *  this service's memory and not the record. */
export function recentTokensKept(since: string): string {
  return since ? `Kept by this service since it started, ${since}; a restart forgets them.` : "Kept by this service; a restart forgets them.";
}

/** A section that could not be read says so in words — never a code, and
 *  never an empty table, which would read as "nothing was asked for". */
export function recentTokensProblem(error: string): string {
  const said = error.trim() || "the reason is not known";
  return `Recent tokens could not be read: ${said.replace(/\.$/, "")}.`;
}
