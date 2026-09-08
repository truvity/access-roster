import type { Identity } from "../identity.js";
export interface UserBadgeProps {
    /** The caller, from useIdentity(). */
    identity: Identity;
    /** Roles shown in the accent colour; every other role is neutral. */
    emphasize?: string[];
    /** Where "Sign in" goes when nobody is signed in. */
    signInHref?: string;
}
/** The header block every console in this family shows: who you are, what
 * that gets you, and the way out.
 *
 * It renders all four states, including the one consoles usually skip.
 * "Unknown" means the application could not be asked — showing a sign-in
 * button there would send a signed-in person to authenticate again for
 * nothing, and showing nothing would leave them wondering. */
export declare function UserBadge({ identity, emphasize, signInHref }: UserBadgeProps): import("react").JSX.Element | null;
//# sourceMappingURL=UserBadge.d.ts.map