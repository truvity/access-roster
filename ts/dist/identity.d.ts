/** The caller, as the application's own origin reports them.
 *
 * Nothing here parses a token. The browser asks the application it is
 * already talking to who it thinks the caller is, and the application —
 * which has verified whatever the proxy or the issuer gave it — answers.
 * A package that verified tokens in a browser would be a package that
 * needs the issuer's keys, its clock and its rules in every console. */
export interface Identity {
    status: Status;
    email?: string;
    name?: string;
    givenName?: string;
    familyName?: string;
    /** Roles the policy grants, e.g. ["operator", "viewer"]. */
    roles?: string[];
    /** Internal groups the caller is in. */
    groups?: string[];
    /** How the caller was established: "directory", "forwarded", "recovery". */
    source?: string;
    /** The build the application is running, so a console can show it
     * without a second call. */
    version?: string;
    /** Where "sign out" goes. Empty when signed out. */
    signOutUrl?: string;
    /** Why the answer is "unknown". Never set otherwise. */
    error?: string;
}
/** What is known about the caller.
 *
 * "unknown" is the one worth explaining: it means the question could not
 * be asked, which is not the same as being signed out. A console that
 * showed a signed-in person a sign-in button because one request failed
 * would send them to authenticate again for nothing — the same mistake,
 * in a browser, that this project refuses to make in a directory. */
export type Status = "loading" | "signed-in" | "signed-out" | "unknown";
/** Where every adapter in this family answers. */
export declare const whoamiPath = "/.access/whoami";
export interface FetchOptions {
    /** Override the path, for an application that mounts it elsewhere. */
    path?: string;
    /** Abort, so a component that unmounts does not resolve into nothing. */
    signal?: AbortSignal;
}
/** Ask the application who the caller is.
 *
 * Resolves rather than throws, because every outcome is something a
 * console has to render: signed in, signed out, or unable to say. The
 * distinction between the last two is the whole reason this returns a
 * status rather than an identity or null. */
export declare function fetchIdentity(options?: FetchOptions): Promise<Identity>;
//# sourceMappingURL=identity.d.ts.map