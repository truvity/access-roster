import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import type { Loader } from 'astro/loaders';
import { docsSchema, i18nSchema } from '@astrojs/starlight/schema';
import { i18nLoader } from '@astrojs/starlight/loaders';
import { z } from 'astro/zod';

// The documentation lives in ../docs (the repository's docs/ directory), so
// it reads the same on GitHub as on sluis.id. The ADRs in docs/decisions are
// their own collection: their front matter is not the site's, and the site
// indexes them instead of treating them as ordinary pages.
const docsRoot = fileURLToPath(new URL('../../docs', import.meta.url));
const decisionsRoot = `${docsRoot}/decisions`;

// Astro warns about an empty collection, and the build must have no warnings.
// While docs/decisions is missing or holds no records (it arrives with the
// governance change), the collection holds one placeholder entry whose id
// starts with an underscore; the decisions pages skip every such id.
const decisionsLoader = (): Loader => ({
  name: 'sluis-decisions-loader',
  load: async (context) => {
    if (existsSync(decisionsRoot)) {
      await glob({
        base: decisionsRoot,
        pattern: ['*.md', '!README.md', '!_*'],
      }).load(context);
    }
    if (context.store.keys().length === 0) {
      context.store.set({ id: '_empty', data: {} });
    }
  },
});

// Every page says how far its content is from being built: `target` is a
// design that is not built, `partial` is partly built, `page` is a page about the
// project itself (complete, and describing nothing that is built), `shipped` describes
// what exists (nothing uses it until code ships). The badge, the sidebar, llms.txt and the CI check read it.
// `badge: false` is for the pages built in src/pages (the 404 page, the ADRs),
// which are not documentation of a feature and show no badge.
export const PAGE_STATUSES = ['target', 'partial', 'page', 'shipped'] as const;

export const collections = {
  docs: defineCollection({
    loader: glob({
      base: 'src/content/docs',
      pattern: ['**/[^_]*.{md,mdx}', '!decisions/**', '!requirements/**'],
    }),
    schema: docsSchema({ extend: z.object({ status: z.enum(PAGE_STATUSES), badge: z.boolean().default(true) }) }),
  }),
  i18n: defineCollection({ loader: i18nLoader(), schema: i18nSchema() }),
  decisions: defineCollection({
    loader: decisionsLoader(),
    schema: z.object({
      title: z.string().optional(),
      status: z.string().optional(),
      date: z.coerce.date().optional(),
      description: z.string().optional(),
    }).passthrough(),
  }),
};
