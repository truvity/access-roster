// The Worker of sluis.id (ADR 0014). Static assets are served before any of this runs; the
// Worker runs first for /api/* only, and is a plain module that Wrangler bundles, with no
// Astro server in it (src/cloudflare-worker-main.mjs names it in the generated configuration).
//
// - fetch: the routes of src/worker/api.ts.
// - scheduled: every 15 minutes, a refresh of the board in KV, in case a webhook delivery
//   was missed.
import { api } from './api.ts';
import { refresh, type Env } from './status.ts';

interface Ctx { waitUntil(p: Promise<unknown>): void }

export default {
  fetch(request: Request, env: Env, ctx: Ctx): Promise<Response> {
    return api(request, env, ctx);
  },
  async scheduled(_controller: unknown, env: Env, ctx: Ctx): Promise<void> {
    ctx.waitUntil(refresh(env, 'cron').then((line) => console.log(line)));
  },
};
