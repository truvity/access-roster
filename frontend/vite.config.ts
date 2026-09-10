import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The console is served by the hub itself, from the same origin, so the
// API needs no base URL and no CORS. `dev` proxies to a hub run locally
// with DEMO=1.
//
// `base` is RELATIVE, and that is the whole trick. The built bundle is
// committed and embedded in the hub's binary, so one build has to work
// wherever the chart mounts it: at its host's root, or under a path when
// the console shares its issuer's origin (`route.pathPrefix`, INF-687).
// An absolute "/assets/..." cannot do that — served under /console/ the
// browser resolves it against the ORIGIN, asks the issuer at the root,
// and gets a 404 for every asset. A build-time env var cannot do it
// either: it would bake one deployment's prefix into an artifact that
// ships to all of them.
//
// "./" resolves against the page instead, so index.html served at
// /console/ asks for /console/assets/..., and at / asks for /assets/... .
// The gateway strips the prefix before the hub sees it, so the hub's own
// routes (GET /assets/, GET /{$}) never learn it exists.
//
// It does require the console to be reached WITH a trailing slash —
// "/console" alone would resolve "./" against the root — which the chart
// guarantees with a redirect.
//
// The console's OWN routing lives in the URL fragment (router.ts), which
// `base` never touches: a hash resolves against whatever page it is
// already on, prefixed or not.
const base = "./";

export default defineConfig({
  base,
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    proxy: {
      "/directoryroster.v1.": "http://localhost:8081",
      "/.access": "http://localhost:8081",
      "/logout": "http://localhost:8081",
      "/connect": "http://localhost:8081",
    },
  },
});
