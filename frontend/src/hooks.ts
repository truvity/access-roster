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
