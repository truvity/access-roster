/// <reference types="node" />
/** access-roster's consumer half, for a Node service behind the gateway.
 *
 * The same contract as the Go `identity` package: point it at the issuer
 * with this service's own client id, and it turns the token the gateway
 * forwards into the caller — who they are, what the directory calls them,
 * and the internal groups the policy put them in. No group is re-mapped
 * anywhere: the name in the policy is the name in the token is the name in
 * the role check.
 *
 * And the same endpoint: `whoami` answers the browser package's
 * `fetchIdentity()` with the body Go's `WhoAmI` writes, so a console
 * renders the caller the same way whichever language serves it.
 *
 * Only the issuer anchor is here. A ServiceAccount token from the pod next
 * door is Go's `Cluster`, which needs the Kubernetes API; a Node service
 * reaches this one through the issuer like anything further away. */
import type { IncomingMessage, ServerResponse } from "node:http";

import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

/** A caller, after the signature was checked.
 *
 * What a listener authorizes on and what it displays, and nothing saying
 * how the caller was proven, on purpose. */
export interface Verified {
  /** The token's `sub`: an address for a person, and
   * `<cluster>:k8s:<namespace>:<name>` for a workload. */
  subject: string;
  /** The person's address, absent for a workload. */
  email?: string;
  /** What the directory calls the person. Display only: never authorize
   * on it. Absent for a workload or a person the directory names nothing. */
  name?: string;
  givenName?: string;
  familyName?: string;
  /** The internal groups the policy put the caller in, verbatim. */
  groups: string[];
  /** Set when the caller is a workload rather than a person. */
  serviceAccount?: ServiceAccountRef;
}

export interface ServiceAccountRef {
  /** Which cluster vouched for it; empty where the subject names none. */
  cluster: string;
  namespace: string;
  name: string;
}

/** Whether the caller is in an internal group. */
export function has(who: Verified, group: string): boolean {
  return who.groups.includes(group);
}

/** Whether the caller is in any of them — how a client's `requires` reads,
 * and how a listener should gate. */
export function hasAny(who: Verified, ...groups: string[]): boolean {
  return groups.some((group) => has(who, group));
}

/** The token did not verify, or was not this verifier's to judge.
 *
 * Deliberately one error. A response that told "wrong signature" from
 * "wrong audience" would tell an attacker which half to fix. */
export class Unverified extends Error {
  override readonly name = "Unverified";
}

/** The check could not happen: the issuer's discovery or keys were out of
 * reach. Not the caller's fault, so never answer it with a 401 — that
 * sends a legitimate caller back to sign in, repeatedly, for an outage. */
export class IssuerUnreachable extends Error {
  override readonly name = "IssuerUnreachable";
}

export interface IssuerOptions {
  /** The issuer, exactly as it appears in a token's `iss`. */
  url: string;
  /** This service's own client id, which the token must be minted for.
   *
   * Required, where Go's is only strongly advised: a token minted for
   * another service is a perfectly valid token, and accepting it here
   * would make every audience that issuer serves a way in. */
  audience: string;
  /** Replaces the global fetch for discovery, for tests and for a proxy. */
  fetch?: typeof fetch;
}

type KeySet = ReturnType<typeof createRemoteJWKSet>;

/** Verifies a token access-roster signed, against the key set it publishes.
 *
 * Discovery is lazy and cached: a service must start whether or not the
 * issuer is up. The first request after it returns pays for discovery, and
 * the key set refetches itself when a signature names a key it has not
 * seen, which makes rotation a non-event. */
export class Issuer {
  private readonly url: string;
  private readonly audience: string;
  private readonly fetch: typeof fetch;
  private keys?: Promise<KeySet>;

  constructor(options: IssuerOptions) {
    if (!options.url) throw new Error("access-roster: an issuer url is required");
    if (!options.audience) throw new Error("access-roster: an audience — this service's client id — is required");
    this.url = trimTrailingSlashes(options.url);
    this.audience = options.audience;
    this.fetch = options.fetch ?? fetch;
  }

  /** Checks a bearer token and returns the caller. Throws Unverified for a
   * token that does not verify, IssuerUnreachable when it could not ask. */
  async verify(token: string): Promise<Verified> {
    const keys = await this.resolve();
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, keys, {
        issuer: this.url,
        audience: this.audience,
        algorithms: ["RS256"],
        clockTolerance: 10,
      }));
    } catch (cause) {
      if (unreachable(cause)) {
        throw new IssuerUnreachable(`access-roster: the issuer's keys are out of reach: ${message(cause)}`);
      }
      throw new Unverified("access-roster: the token did not verify", { cause });
    }
    return fromClaims(payload);
  }

  private resolve(): Promise<KeySet> {
    if (!this.keys) {
      this.keys = this.discover().catch((cause: unknown) => {
        // Forget the failure, so the next request asks again rather than
        // this outage becoming the answer until a restart.
        this.keys = undefined;
        throw cause;
      });
    }
    return this.keys;
  }

  private async discover(): Promise<KeySet> {
    let config: { issuer?: string; jwks_uri?: string };
    try {
      const response = await this.fetch(`${this.url}/.well-known/openid-configuration`, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) throw new Error(`discovery answered ${response.status}`);
      config = (await response.json()) as typeof config;
    } catch (cause) {
      throw new IssuerUnreachable(`access-roster: discover ${this.url}: ${message(cause)}`);
    }
    // A discovery document naming another issuer is a misconfiguration, and
    // trusting its keys would verify tokens this issuer never signed.
    if (trimTrailingSlashes(config.issuer ?? "") !== this.url) {
      throw new IssuerUnreachable(`access-roster: ${this.url} describes itself as ${config.issuer ?? "nothing"}`);
    }
    if (!config.jwks_uri) {
      throw new IssuerUnreachable(`access-roster: ${this.url} publishes no key set`);
    }
    return createRemoteJWKSet(new URL(config.jwks_uri), { timeoutDuration: 10_000 });
  }
}

function fromClaims(claims: JWTPayload): Verified {
  const subject = typeof claims.sub === "string" ? claims.sub : "";
  const out: Verified = { subject, groups: groupsOf(claims) };

  const account = parseServiceAccountSubject(subject);
  if (account) {
    out.serviceAccount = account;
    return out;
  }

  // The subject IS the address for a corporate sign-in, and `email` is only
  // present when the scope asked for it. Prefer the claim.
  const email = (text(claims.email) || subject).trim().toLowerCase();
  if (email.includes("@")) out.email = email;

  const name = text(claims.name).trim();
  const givenName = text(claims.given_name).trim();
  const familyName = text(claims.family_name).trim();
  if (name) out.name = name;
  if (givenName) out.givenName = givenName;
  if (familyName) out.familyName = familyName;

  return out;
}

function groupsOf(claims: JWTPayload): string[] {
  const raw = claims.groups;
  if (!Array.isArray(raw)) return [];
  return raw.filter((one): one is string => typeof one === "string" && one !== "");
}

/** The workload forms a subject takes, exactly as Go's policy parses them. */
export function parseServiceAccountSubject(subject: string): ServiceAccountRef | undefined {
  const legacy = "system:serviceaccount:";
  if (subject.startsWith(legacy)) {
    const rest = subject.slice(legacy.length);
    const at = rest.indexOf(":");
    const namespace = at < 0 ? "" : rest.slice(0, at);
    const name = at < 0 ? "" : rest.slice(at + 1);
    return namespace && name ? { cluster: "", namespace, name } : undefined;
  }
  const parts = subject.split(":");
  if (parts.length === 3 && parts[0] === "k8s" && parts[1] && parts[2]) {
    return { cluster: "", namespace: parts[1], name: parts[2] };
  }
  if (parts.length === 4 && parts[1] === "k8s" && parts[0] && parts[2] && parts[3]) {
    return { cluster: parts[0], namespace: parts[2], name: parts[3] };
  }
  return undefined;
}

/** Where the token arrives: the proxy's header, else the bearer. */
export const headerForwarded = "x-auth-request-access-token";

type HeaderBag = Headers | Record<string, string | string[] | undefined>;

/** Reads the token a request carries, from either header. */
export function tokenFrom(headers: HeaderBag): string {
  const read = (name: string): string => {
    if (headers instanceof Headers) return headers.get(name) ?? "";
    const value = headers[name] ?? headers[name.toLowerCase()];
    return (Array.isArray(value) ? value[0] : value) ?? "";
  };
  const forwarded = read(headerForwarded).trim();
  if (forwarded) return forwarded;
  // The scheme is case-insensitive (RFC 6750 §2.1).
  const header = read("authorization").trim();
  return /^bearer\s+/i.test(header) ? header.replace(/^bearer\s+/i, "").trim() : "";
}

/** The body `whoami` answers, the one Go's `WhoAmI` writes. */
export function whoamiBody(who?: Verified, version?: string): Record<string, unknown> {
  const body: Record<string, unknown> = { status: "signed-out" };
  if (version) body.version = version;
  if (!who) return body;
  body.status = "signed-in";
  body.sub = who.subject;
  if (who.email) body.email = who.email;
  if (who.name) body.name = who.name;
  if (who.givenName) body.givenName = who.givenName;
  if (who.familyName) body.familyName = who.familyName;
  if (who.groups.length > 0) body.groups = who.groups;
  return body;
}

/** Something that can verify a token. */
export interface Verifier {
  verify(token: string): Promise<Verified>;
}

type Next = (error?: unknown) => void;

const established = new WeakMap<IncomingMessage, Verified>();

/** The caller the middleware established for this request, if any. */
export function identityOf(request: IncomingMessage): Verified | undefined {
  return established.get(request);
}

/** Connect-style middleware (Express, and Nest on Express) that establishes
 * the caller.
 *
 * It does NOT refuse an unverified request, as Go's does not: a service has
 * routes that run before anybody is established, and a middleware deciding
 * for them would be one every such route had to be excluded from. Gate with
 * `requireGroups`, or read `identityOf` in the handler.
 *
 * A token one verifier RECOGNISED and refused stops the chain, and an
 * unreachable issuer stops it too: trying the next verifier would turn an
 * outage into "your token is bad". */
export function middleware(...verifiers: Verifier[]) {
  return async (request: IncomingMessage, _response: ServerResponse, next: Next): Promise<void> => {
    const token = tokenFrom(request.headers);
    if (!token) return next();
    for (const verifier of verifiers) {
      try {
        established.set(request, await verifier.verify(token));
        return next();
      } catch (cause) {
        if (!(cause instanceof Unverified)) break;
      }
    }
    return next();
  };
}

/** Refuses anything the middleware did not establish, and anything holding
 * none of the groups named. Naming none means any caller this installation
 * vouches for. Never names the groups that would have worked. */
export function requireGroups(...groups: string[]) {
  return (request: IncomingMessage, response: ServerResponse, next: Next): void => {
    const who = identityOf(request);
    if (!who) return refuse(response, 401, "not signed in");
    if (groups.length > 0 && !hasAny(who, ...groups)) return refuse(response, 403, "not allowed");
    next();
  };
}

/** The `/.access/whoami` handler. Answers rather than refuses when nobody is
 * established: "signed out" is something a console has to render. */
export function whoami(version?: string) {
  return (request: IncomingMessage, response: ServerResponse): void => {
    response.statusCode = 200;
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify(whoamiBody(identityOf(request), version)));
  };
}

export { whoamiPath } from "../identity.js";

function refuse(response: ServerResponse, status: number, body: string): void {
  response.statusCode = status;
  response.setHeader("Content-Type", "text/plain; charset=utf-8");
  response.end(body);
}

function unreachable(cause: unknown): boolean {
  const code = (cause as { code?: string } | null)?.code ?? "";
  // A key set that cannot be fetched is an outage; a key it does not hold
  // is a token this issuer never signed with a live key, which is the
  // caller's.
  return code === "ERR_JWKS_TIMEOUT" || cause instanceof TypeError;
}

/** Drops trailing slashes without a regular expression: `/\/+$/` backtracks
 * quadratically on a long run of slashes, and the input is configuration a
 * caller supplies. */
function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47) end--;
  return value.slice(0, end);
}

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function message(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
