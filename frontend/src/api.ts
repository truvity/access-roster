// The only file that touches the Connect clients. Views call these
// functions and get view types back, so a contract change is a compile
// error here rather than a runtime surprise in a table cell.
import { createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";

import { WorkspaceService, Backend } from "./gen/directoryroster/v1/workspace_pb";
import { SettingsService } from "./gen/directoryroster/v1/settings_pb";
import { AccessService, Role } from "./gen/directoryroster/v1/access_pb";
import { SessionService, How } from "./gen/accessissuer/v1/session_pb";

// The hub's own services, reached under wherever this console is
// mounted. `import.meta.env.BASE_URL` is "/" by default and carries
// `route.pathPrefix` (INF-687, e.g. "/console/") when the build sets one
// — see vite.config.ts. A bare "/" would resolve to the ORIGIN root
// regardless of that prefix, which is right for the issuer below and
// wrong for the hub: its services live only under the console's own
// path, behind the gateway rule that rewrites the prefix away before
// the hub ever sees it.
const transport = createConnectTransport({ baseUrl: import.meta.env.BASE_URL });

export const workspaces = createClient(WorkspaceService, transport);
export const settings = createClient(SettingsService, transport);
export const access = createClient(AccessService, transport);

// The issuer's SessionService, same-origin at the domain root (INF-687,
// INF-682) — never under this console's own path, however it is
// mounted. A plain "/" is exactly that root, unaffected by the prefix
// above. The fetch override is what carries the browser's issuer SSO
// cookie on a same-origin call, the same cookie `/account` on the issuer
// itself would read, so a call here needs no bearer and no CORS.
const issuerTransport = createConnectTransport({
  baseUrl: "/",
  fetch: (input, init) => globalThis.fetch(input, { ...init, credentials: "include" }),
});

export const sessions = createClient(SessionService, issuerTransport);

export { Backend, Role, How };

/** WhoAmI, as the standard endpoint every adapter serves. */
export type Me = {
  status: "signed-in" | "signed-out";
  email?: string;
  name?: string;
  givenName?: string;
  familyName?: string;
  roles?: string[];
  /** roles held over ONE directory each, keyed by its id. `roles` is the
   *  installation-wide answer and is not a summary of these. */
  scopes?: Record<string, string[]>;
  source?: string;
  /** the internal groups the policy puts the caller in */
  groups?: string[];
  /** the build this hub is running */
  version?: string;
  signOutUrl?: string;
  /** the issuer this console shares its origin with (INF-687), or empty
   *  for a hub deployed alone with no issuer. Sessions sections render
   *  only when this is set, because there is nothing to read or end
   *  otherwise. */
  issuerUrl?: string;
};

export async function whoami(): Promise<Me> {
  const response = await fetch("/.access/whoami", { headers: { accept: "application/json" } });
  if (!response.ok) return { status: "signed-out" };
  return (await response.json()) as Me;
}

/** A protobuf timestamp, as a Date. */
export function at(stamp?: { seconds: bigint; nanos: number }): Date | undefined {
  if (!stamp) return undefined;
  return new Date(Number(stamp.seconds) * 1000 + stamp.nanos / 1e6);
}

/** A duration, as human minutes. */
export function every(d?: { seconds: bigint }): string {
  if (!d) return "—";
  const seconds = Number(d.seconds);
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

/** How long ago, in the words an operator uses. */
export function ago(when?: Date): string {
  if (!when) return "never";
  const seconds = Math.max(0, Math.round((Date.now() - when.getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

/** How long until, the mirror of `ago` for something still ahead — a
 *  session's expiry rather than its birth. */
export function until(when?: Date): string {
  if (!when) return "—";
  const seconds = Math.round((when.getTime() - Date.now()) / 1000);
  if (seconds <= 0) return "expired";
  if (seconds < 60) return `in ${seconds}s`;
  if (seconds < 3600) return `in ${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `in ${Math.round(seconds / 3600)}h`;
  return `in ${Math.round(seconds / 86400)}d`;
}

/** "1 person", "3 people": a count a reader does not have to translate. */
export function people(n: number): string {
  return n === 1 ? "1 person" : `${n} people`;
}

/** What a group's claim fragment adds, in words. */
export function adds(claims?: Record<string, unknown>): string {
  if (!claims) return "adds only its own name to a token";
  const values = Array.isArray(claims.groups) ? claims.groups.length : 0;
  const others = Object.keys(claims).filter((key) => key !== "groups");
  const parts: string[] = [];
  if (values) parts.push(`${values} value${values === 1 ? "" : "s"} to the groups claim`);
  for (const key of others) parts.push(key);
  return parts.length ? `adds ${parts.join(" and ")}` : "adds only its own name to a token";
}

/** How the caller was established, in words. */
export function sourceName(source?: string): string | undefined {
  switch (source) {
    case "forwarded":
      return "forwarded by the gateway";
    case "directory":
      return "directory sign-in";
    case "oidc":
      return "OIDC sign-in";
    case "recovery":
      return "recovery sign-in";
    default:
      return source || undefined;
  }
}

/** How a session began, in words -- "revoke Ada's kubectl login" and
 *  "revoke the console she left open" are different acts, and this is
 *  what tells them apart on a row. */
export function howName(how: How): string {
  switch (how) {
    case How.CODE:
      return "browser sign-in";
    case How.DEVICE:
      return "device sign-in";
    case How.EXCHANGE:
      return "token exchange";
    default:
      return "unknown";
  }
}

/** A matcher's kind, in words. */
export function matcherKind(kind: string): string {
  switch (kind) {
    case "ci":
      return "CI job";
    case "workload":
      return "workload";
    case "sign-in":
      return "sign-in";
    default:
      return kind;
  }
}

/** A person's name as the directory has it, or their address. */
export function personName(given?: string, family?: string, email?: string): string {
  const name = [given, family].filter(Boolean).join(" ");
  return name || email || "";
}

export function backendName(b: Backend): string {
  switch (b) {
    case Backend.GOOGLE:
      return "Google Workspace";
    case Backend.ENTRA:
      return "Microsoft Entra";
    case Backend.DEMO:
      return "demonstration";
    default:
      return "unknown";
  }
}

/** A duration, in the words an operator uses. */
export function forHowLong(d?: { seconds: bigint }): string {
  if (!d) return "—";
  const hours = Number(d.seconds) / 3600;
  return hours >= 1 ? `${Math.round(hours)}h` : `${Math.round(Number(d.seconds) / 60)}m`;
}

export function roleName(r: Role): string {
  switch (r) {
    case Role.OPERATOR:
      return "operator";
    case Role.VIEWER:
      return "viewer";
    default:
      return "none";
  }
}

/** The message a failed call should show, without the transport noise. */
export function reason(err: unknown): string {
  if (err instanceof Error) return err.message.replace(/^\[[a-z_]+\]\s*/, "");
  return String(err);
}
