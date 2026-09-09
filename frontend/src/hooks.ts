import { useCallback, useEffect, useState } from "react";
import { reason } from "./api";

export type Async<T> = {
  loading: boolean;
  value?: T;
  error?: string;
  reload: () => void;
};

/** Load something, keep the last value while reloading, surface failures. */
export function useAsync<T>(load: () => Promise<T>, deps: unknown[] = []): Async<T> {
  const [state, setState] = useState<{ loading: boolean; value?: T; error?: string }>({ loading: true });

  const run = useCallback(() => {
    setState((previous) => ({ ...previous, loading: true, error: undefined }));
    load()
      .then((value) => setState({ loading: false, value }))
      .catch((error: unknown) => setState({ loading: false, error: reason(error) }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(run, [run]);
  return { ...state, reload: run };
}

/** Re-run something every `every` milliseconds while `while_` is true.
 *
 *  For ONE state, and a transient one: a directory whose first snapshot
 *  is still running. That page is otherwise a photograph of the first
 *  two hundred milliseconds after a connect — "0 accounts, snapshot
 *  never" — and it stays that way while the read it is waiting for
 *  finishes five seconds later behind it. The poll stops the moment the
 *  snapshot lands, so nothing here polls a steady state. */
export function useWhile(while_: boolean, every: number, run: () => void) {
  useEffect(() => {
    if (!while_) return;
    const timer = setInterval(run, every);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [while_, every]);
}

/** The view in the URL fragment, so deep links and the back button work. */
export function useHashView(fallback: string): [string, (next: string) => void] {
  const read = () => window.location.hash.replace(/^#/, "") || fallback;
  const [view, setView] = useState(read);
  useEffect(() => {
    const onChange = () => setView(read());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return [view, (next: string) => { window.location.hash = next; }];
}
