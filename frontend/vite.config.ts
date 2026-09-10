import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The console is served by the hub itself, from the same origin, so the
// API needs no base URL and no CORS. `dev` proxies to a hub run locally
// with DEMO=1.
//
// `base` is where the BUILT ASSETS are referenced from — index.html's
// script/link tags, and every `import.meta.env.BASE_URL`-relative fetch
// Vite itself makes. It defaults to "/", today's shape: the console at
// its host's root. Set CONSOLE_BASE_PATH (a trailing slash, as Vite
// requires) to build for the console mounted under a path instead —
// "/console/", to match `route.pathPrefix: /console` in the hub chart
// (INF-687). The hub's own routes (GET /assets/, GET /{$}) do not
// change: the gateway strips the prefix before a request reaches the
// hub, so the hub still sees "/assets/..." and "/" exactly as it always
// has. Only the HTML this build emits needs to know the prefix, because
// that HTML is what the browser resolves relative URLs against.
//
// The console's OWN routing lives in the URL fragment (router.ts), which
// `base` never touches — a hash is resolved against whatever page it is
// already on, prefixed or not.
const base = process.env.CONSOLE_BASE_PATH || "/";

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
