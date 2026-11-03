// Names the Worker's code, src/worker/index.ts, as `main` in the Worker configuration the
// build generates (ADR 0014).
//
// Every page of the site is prerendered, so the Cloudflare adapter builds an assets-only
// Worker: the configuration it writes has no `main`, even when wrangler.jsonc names one,
// and no assets binding. The Worker's code is not an Astro server: it is the /api/* routes
// and the cron, a plain module that `wrangler deploy` bundles itself. An Astro server route
// would pull the Astro runtime and the Markdown processor into the Worker (the processor's
// browser build cannot be bundled for workerd). This integration adds `main`, and the
// ASSETS binding through which the Worker reads /data/repo.json, after the adapter has
// written the file; the cron (`triggers`) and `assets.run_worker_first` come through from
// wrangler.jsonc as they are. src/cloudflare-kv-id.mjs rewrites the same file for the KV id.
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ENTRY = new URL('./worker/index.ts', import.meta.url);

export default function cloudflareWorkerMain() {
  return {
    name: 'sluis:cloudflare-worker-main',
    hooks: {
      'astro:build:done': async ({ dir, logger }) => {
        const file = fileURLToPath(new URL('./wrangler.json', dir));
        const config = JSON.parse(await readFile(file, 'utf8'));
        if (config.main) throw new Error(`${file} already names a main module (${config.main}); the adapter now builds one, so drop this integration.`);
        if (!config.assets?.run_worker_first?.length || config.assets.run_worker_first.includes('/*')) {
          throw new Error(`${file} must run the Worker first for /api/* only (assets.run_worker_first in wrangler.jsonc).`);
        }
        config.main = relative(dirname(file), fileURLToPath(ENTRY)).split('\\').join('/');
        // The name wrangler.jsonc gives the binding, and src/worker/status.ts uses.
        config.assets.binding ??= 'ASSETS';
        await writeFile(file, JSON.stringify(config));
        logger.info(`the Worker's main module is ${config.main}`);
      },
    },
  };
}
