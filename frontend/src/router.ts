import { useEffect, useState } from "react";

/** One place in the console: a view and, for a detail page, the thing it
 *  is about. Views live in the URL fragment, so deep links, the back
 *  button and a refresh all work without a server route. */
export type Route = { view: string; id?: string; query: URLSearchParams };

export function parse(hash: string): Route {
  const raw = hash.replace(/^#/, "") || "/";
  // A query after the fragment path is how a page is opened in a
  // particular state — the consent callback landing on a directory with
  // its domain chooser open, rather than the operator having to find it.
  const [path, search = ""] = raw.split("?");
  const [, view, id] = path.split("/");
  return { view: view || "overview", id: id ? decodeURIComponent(id) : undefined, query: new URLSearchParams(search) };
}

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

/** Two hierarchies, joined by the membership. The identity side is where
 *  people come from: a directory, its groups, its accounts, and the
 *  matchers that admit a proof by its shape instead. The access side is what
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
  person: (email: string) => `/people/${encodeURIComponent(email)}`,
  matchers: () => "/matchers",
  // access
  groups: () => "/groups",
  group: (name: string) => `/groups/${encodeURIComponent(name)}`,
  clients: () => "/clients",
  client: (id: string) => `/clients/${encodeURIComponent(id)}`,
  // Every open session in the installation (INF-682). Operator-only, and
  // only present at all once an issuer shares this console's origin.
  sessions: () => "/sessions",
  settings: () => "/settings",
};
