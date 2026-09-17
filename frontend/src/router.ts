import { useEffect, useState } from "react";

/** One place in the console: a view and, for a detail page, the thing it
 *  is about. Views live in the URL fragment, so deep links, the back
 *  button and a refresh all work without a server route. */
export type Route = { view: string; id?: string; rest: string[]; query: URLSearchParams };

export function parse(hash: string): Route {
  const raw = hash.replace(/^#/, "") || "/";
  // A query after the fragment path is how a page is opened in a
  // particular state — the consent callback landing on a directory with
  // its domain chooser open, rather than the operator having to find it.
  const [path, search = ""] = raw.split("?");
  const [, view, id, ...rest] = path.split("/");
  const normalised = renamed[view] ?? view ?? "overview";
  return {
    view: normalised,
    id: id ? decodeURIComponent(id) : undefined,
    // Deeper segments, for the pages nested more than one level: an
    // organisation's team, an App.
    rest: movedRest(normalised, id, rest.filter(Boolean).map(decodeURIComponent)),
    query: new URLSearchParams(search),
  };
}

/** Deeper paths that moved, for the same reason views are renamed: a
 *  bookmark is a URL. Catalogue Apps had a list and pages of their own a
 *  level below every other App; every App is now one list and one page at
 *  the same level, so `apps/catalogue` is the list and
 *  `apps/catalogue/<id>` is that App's page. */
function movedRest(view: string, id: string | undefined, rest: string[]): string[] {
  if (view === "github" && id === "apps" && rest[0] === "catalogue") return rest.slice(1);
  return rest;
}

/** Views that have been renamed, and the name they answer to now.
 *  An operator's bookmark is a URL; one that silently lands on the
 *  overview reads as the page having been removed. Normalising here
 *  rather than in the switch also keeps the rail highlighted, which is
 *  what makes the old name invisible rather than merely working. */
const renamed: Record<string, string> = {
  // Matchers showed the rules that admit a proof by its shape, which was
  // two thirds of them (INF-689).
  matchers: "rules",
};

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parse(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parse(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

/** Navigate. Every name in the console is a link to one of these. */
export function go(to: string) {
  window.location.hash = to;
}

/** How the Audit page can be narrowed, and what its address carries. */
export type AuditFilters = { source?: string; kind?: string; subject?: string; target?: string };

/** Two hierarchies, joined by the membership. The identity side is where
 *  people come from: a directory, its groups, its accounts, and the
 *  rules that put them into an internal group. The access side is what
 *  they get: an internal group and the clients it opens. Every level on
 *  either side is a page. */
export const paths = {
  overview: () => "/",
  // identity
  directories: () => "/directories",
  directory: (id: string) => `/directories/${encodeURIComponent(id)}`,
  // A directory opened on the question a connect leaves behind.
  directoryChoosing: (id: string) => `/directories/${encodeURIComponent(id)}?choose=domains`,
  directoryGroups: () => "/directory-groups",
  directoryGroup: (email: string) => `/directory-groups/${encodeURIComponent(email)}`,
  people: () => "/people",
  // People, narrowed to whether they linked a GitHub account.
  peopleGitHub: (linked: boolean) => `/people?github=${linked ? "linked" : "not-linked"}`,
  person: (email: string) => `/people/${encodeURIComponent(email)}`,
  rules: () => "/rules",
  // access
  groups: () => "/groups",
  group: (name: string) => `/groups/${encodeURIComponent(name)}`,
  clients: () => "/clients",
  client: (id: string) => `/clients/${encodeURIComponent(id)}`,
  // GitHub teams consume internal groups the way clients do.
  github: () => "/github",
  githubOrganisations: () => "/github/organisations",
  githubOrganisation: (org: string) => `/github/organisations/${encodeURIComponent(org)}`,
  githubTeam: (org: string, team: string) => `/github/organisations/${encodeURIComponent(org)}/teams/${encodeURIComponent(team)}`,
  githubApps: () => "/github/apps",
  // Every App, whatever made it, is a page of its own. An App whose id is
  // literally "catalogue" keeps the old prefix, which the parser strips,
  // so it is not read as the old list's address.
  githubApp: (id: string) => (id === "catalogue" ? "/github/apps/catalogue/catalogue" : `/github/apps/${encodeURIComponent(id)}`),
  // Every open session in the installation (INF-682). Operator-only, and
  // only present at all once an issuer shares this console's origin.
  sessions: () => "/sessions",
  // What happened lately, installation-wide. Operator-only.
  //
  // A narrowing is part of the address, not a state the page happens to
  // be in: an App's page links here filtered to its own tokens, and an
  // operator who narrows the page by hand gets a link they can send.
  audit: (filters?: AuditFilters) => {
    const query = new URLSearchParams(Object.entries(filters ?? {}).filter(([, value]) => value) as [string, string][]).toString();
    return query ? `/audit?${query}` : "/audit";
  },
  settings: () => "/settings",
};
