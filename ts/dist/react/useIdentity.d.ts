import { type FetchOptions, type Identity } from "../identity.js";
/** Ask the application who the caller is, once, on mount.
 *
 * Once, because the answer changes when a session ends, and a session
 * ending is something the application discovers on its next call rather
 * than something a poll would catch usefully. A console that polled this
 * would spend a request every few seconds to learn nothing.
 *
 * It starts at "loading" and never goes back: a component that flickered
 * through "signed out" on every re-render would show a sign-in button to
 * somebody who is signed in. */
export declare function useIdentity(options?: FetchOptions): Identity;
//# sourceMappingURL=useIdentity.d.ts.map