import type { GitHubMember, GitHubOrganisation } from "./gen/directoryroster/v1/github_pb";

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
export function organisationNeeds(org: GitHubOrganisation): string[] {
  const out: string[] = [];
  if (!org.connection?.installed) out.push("its App is not installed");
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
