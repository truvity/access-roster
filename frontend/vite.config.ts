import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The console is served by the hub itself, from the same origin, so the
// API needs no base URL and no CORS. `dev` proxies to a hub run locally
// with DEMO=1.
export default defineConfig({
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
