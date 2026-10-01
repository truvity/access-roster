import { paths } from "./router";

/** One destination in the rail. `value` is the route's view, which is what
 *  highlights it. */
export type NavEntry = { value: string; label: string; to: string };

/** A heading and what is under it. The first cluster has no heading: it is
 *  the one place everybody starts. */
export type NavCluster = { heading?: string; hint?: string; entries: NavEntry[] };

/** What the rail may show to this caller. Sessions exist only once an
 *  issuer shares this console's origin and are operator-only; Audit only
 *  once an installation is connected. */
export type NavOptions = { sessions: boolean; audit: boolean };

/** The navigation is the model, in five clusters:
 *
 *  - Identity: where people come from — a directory, its groups, its
 *    accounts, and the rules that admit a proof by its shape.
 *  - Access: what they get here — internal groups, the clients those open,
 *    and the sessions that result.
 *  - Systems: what the roster keeps in step, one entry each (GitHub, Slack),
 *    each with tabs of its own rather than an entry per concept.
 *  - Admin: the trail and the settings.
 *
 *  The two sides are mirrored: both have groups, and the heading above is
 *  the adjective, so the labels say "Directory groups" and "Internal
 *  groups" only to tell the two apart in a list of results. The URLs of
 *  the views are unchanged, because a bookmark is a URL. */
export function clusters(options: NavOptions): NavCluster[] {
  return [
    { entries: [{ value: "overview", label: "Overview", to: paths.overview() }] },
    {
      heading: "Identity",
      hint: "Where people come from",
      entries: [
        { value: "directories", label: "Directories", to: paths.directories() },
        { value: "directory-groups", label: "Directory groups", to: paths.directoryGroups() },
        { value: "people", label: "People", to: paths.people() },
        { value: "rules", label: "Rules", to: paths.rules() },
      ],
    },
    {
      heading: "Access",
      hint: "What they get here",
      entries: [
        { value: "groups", label: "Internal groups", to: paths.groups() },
        { value: "clients", label: "Clients", to: paths.clients() },
        ...(options.sessions ? [{ value: "sessions", label: "Sessions", to: paths.sessions() }] : []),
      ],
    },
    {
      heading: "Systems",
      hint: "What the roster keeps in step",
      entries: [
        { value: "github", label: "GitHub", to: paths.github() },
        { value: "slack", label: "Slack", to: paths.slack() },
      ],
    },
    {
      heading: "Admin",
      entries: [...(options.audit ? [{ value: "audit", label: "Audit", to: paths.audit() }] : []), { value: "settings", label: "Settings", to: paths.settings() }],
    },
  ];
}
