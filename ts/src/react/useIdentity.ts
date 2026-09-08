import { useEffect, useState } from "react";

import { fetchIdentity, type FetchOptions, type Identity } from "../identity.js";

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
export function useIdentity(options: FetchOptions = {}): Identity {
  const [identity, setIdentity] = useState<Identity>({ status: "loading" });
  const path = options.path;

  useEffect(() => {
    const abort = new AbortController();
    void fetchIdentity({ ...(path ? { path } : {}), signal: abort.signal }).then((answer) => {
      // An aborted fetch resolves as "loading", which is what an unmounted
      // component should never be told about anyway.
      if (!abort.signal.aborted) setIdentity(answer);
    });
    return () => abort.abort();
  }, [path]);

  return identity;
}
