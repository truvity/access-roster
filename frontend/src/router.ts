import { useEffect, useState } from "react";

/** One place in the console: a view and, for a detail page, the thing it
 *  is about. Views live in the URL fragment, so deep links, the back
 *  button and a refresh all work without a server route. */
export type Route = { view: string; id?: string };

export function parse(hash: string): Route {
  const path = hash.replace(/^#/, "") || "/";
  const [, view, id] = path.split("/");
  return { view: view || "overview", id: id ? decodeURIComponent(id) : undefined };
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

export const paths = {
  overview: () => "/",
  directories: () => "/directories",
  directory: (id: string) => `/directories/${encodeURIComponent(id)}`,
  groups: () => "/groups",
  group: (name: string) => `/groups/${encodeURIComponent(name)}`,
  clients: () => "/clients",
  client: (id: string) => `/clients/${encodeURIComponent(id)}`,
  person: (email: string) => `/people/${encodeURIComponent(email)}`,
  explain: () => "/explain",
  settings: () => "/settings",
};
