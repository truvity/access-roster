import { readFileSync } from 'node:fs';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import mermaid from 'astro-mermaid';
import starlightLinksValidator from 'starlight-links-validator';
import starlightLlmsTxt from 'starlight-llms-txt';
import cloudflare from '@astrojs/cloudflare';
import cloudflareKvId from './src/cloudflare-kv-id.mjs';
import cloudflareWorkerMain from './src/cloudflare-worker-main.mjs';
import { satteri } from '@astrojs/markdown-satteri';
import { statusPlugin } from './src/remark-status.mjs';

// Starlight's default (prefetch every link on hover), stated here so the Vite
// plugin below fills in the same values Astro's prefetch script is configured with.
const prefetch = { prefetchAll: true, defaultStrategy: 'hover' };

// Astro's prefetch script (astro/dist/prefetch/index.js) holds the placeholders
// __PREFETCH_PREFETCH_ALL__, __PREFETCH_DEFAULT_STRATEGY__ and
// __EXPERIMENTAL_CLIENT_PRERENDER__, which Astro's `astro:prefetch` Vite plugin
// replaces in a transform hook (astro/dist/prefetch/vite-plugin-prefetch.js,
// unchanged in astro 7.4.4). That hook matches the module id against the literal
// path `astro/dist/prefetch/index.js`. With `nodeLinker: pnpm` (site/.yarnrc.yml)
// the id is the real path, node_modules/.store/astro-virtual-<hash>/package/dist/...,
// which does not match, so the placeholders shipped. Starlight enables prefetch,
// so the script lands in the one bundled page script and throws a ReferenceError
// before astro-mermaid's init runs: every diagram stayed a raw <pre>.
// This plugin does the same replacement whatever the layout. Drop it once Astro
// matches the package directory rather than a path containing `astro/`;
// site/scripts/check-built.sh fails the build if a placeholder ever ships again.
const fillPrefetchPlaceholders = () => ({
  name: 'sluis:fill-prefetch-placeholders',
  enforce: 'pre',
  transform(code, id) {
    if (!/[\\/]dist[\\/]prefetch[\\/]index\.js(\?|$)/.test(id)) return null;
    if (!code.includes('__PREFETCH_PREFETCH_ALL__')) return null;
    return {
      code: code
        .replace('__PREFETCH_PREFETCH_ALL__', JSON.stringify(prefetch.prefetchAll))
        .replace('__PREFETCH_DEFAULT_STRATEGY__', JSON.stringify(prefetch.defaultStrategy))
        .replace('__EXPERIMENTAL_CLIENT_PRERENDER__', 'false'),
      map: null,
    };
  },
});

// Mermaid draws every diagram at its natural size: with `useMaxWidth` true (the
// default) the SVG is scaled down to the ~720 px content column and a wide
// sequence diagram ends up with 6 px text. The diagram types below all take the
// option; src/styles/mermaid.css lets a wide diagram scroll inside its box, and
// src/scripts/mermaid-zoom.ts adds the Expand button (pan and zoom).
const naturalSize = Object.fromEntries(
  ['flowchart', 'sequence', 'class', 'state', 'er', 'gantt', 'journey', 'timeline', 'pie', 'requirement',
    'architecture', 'mindmap', 'kanban', 'gitGraph', 'c4', 'quadrantChart', 'xyChart', 'sankey', 'packet',
    'block', 'radar'].map((t) => [t, { useMaxWidth: false }]),
);

// Where the build is going. 'pages' is the plain static build into dist/, with the
// renamed pages redirected by meta-refresh pages: the build of `just site-build`
// and the pull request checks. Nothing deploys it; the name is from when GitHub
// Pages served the site, which is off since 2026-11-01.
// 'workers' is Cloudflare Workers static assets (ADR 0014; the deploy job of
// site.yaml sets SLUIS_TARGET=workers): the @astrojs/cloudflare adapter writes the site to dist/client with
// its Worker configuration, and the redirects below become a `_redirects` file
// instead of pages. Both targets build the same pages.
const workers = (process.env.SLUIS_TARGET ?? 'pages') === 'workers';
const workersOptions = {
  // Every docs page is prerendered, so Pagefind search keeps working; the adapter
  // is only the way to a Worker. No `cacheCloudflare()`: it turns on Workers Cache,
  // which bills static asset requests (ADR 0014).
  //
  // prerenderEnvironment 'node': the default, workerd, resolves the browser build of
  // the Markdown processor (Sätteri), which cannot be bundled. Pages are rendered by
  // Node at build time either way. The Worker's own code (/api/* and the cron) is not
  // built by Astro: src/cloudflare-worker-main.mjs names it in the generated configuration
  // and `wrangler deploy` bundles it.
  // imageService 'compile': images are optimised at build time, so the build holds no
  // Images binding that the Worker would need an account feature for.
  adapter: cloudflare({ prerenderEnvironment: 'node', imageService: 'compile' }),
  // The adapter would otherwise add a KV namespace for sessions and have wrangler
  // create it on deploy. The site has no sessions.
  session: false,
};

// The decision records were merged and renumbered on 2026-11-01. Every old record
// address redirects to the record that took it over; the map is
// docs/decisions/renumbered.json, which tools/checks/decisions.mjs checks.
const renumbered = JSON.parse(readFileSync(new URL('../docs/decisions/renumbered.json', import.meta.url), 'utf8'));
const decisionRedirects = Object.fromEntries(
  renumbered.records.filter((r) => r.old !== r.new).map((r) => [`/decisions/${r.old}/`, `/decisions/${r.new}/`]),
);

// https://sluis.id. The custom domain and its DNS are managed outside this
// repository; the site is served from the root, with the v1 documentation
// copied in under /v1/ (site/scripts/build-v1.sh).
export default defineConfig({
  site: 'https://sluis.id',
  trailingSlash: 'always',
  // The v2 taxonomy renamed the "shapes" pages to "runtimes" (bare-metal,
  // serverless, kubernetes) and merged the five bare-metal shapes into the
  // runtimes page; "roles" became "actors". The old paths keep working.
  // Each redirect points at the final page, so nothing chains. The /environments/
  // paths were the previous name of /runtimes/.
  redirects: {
    '/environments/': '/runtimes/',
    '/environments/bare-metal/': '/runtimes/bare-metal/',
    '/environments/serverless/': '/runtimes/serverless/',
    '/environments/kubernetes/': '/runtimes/kubernetes/',
    '/environments/presets/': '/runtimes/',
    '/shapes/': '/runtimes/',
    '/shapes/local/': '/runtimes/#local',
    '/shapes/single-node/': '/runtimes/',
    '/shapes/cluster/': '/runtimes/#boards',
    '/shapes/aws-ec2-single/': '/runtimes/bare-metal/',
    '/shapes/aws-ec2-cluster/': '/runtimes/bare-metal/',
    '/shapes/aws-lambda/': '/runtimes/serverless/',
    '/shapes/kubernetes/': '/runtimes/kubernetes/',
    '/concepts/roles/': '/concepts/families/',
    '/concepts/actors/': '/concepts/families/',
    '/concepts/drivers/': '/concepts/data/#the-store',
    '/concepts/configuration/': '/concepts/data/#configuration',
    '/concepts/backup/': '/concepts/data/#backup-and-restore',
    // The pages merged or moved on 2026-11-01 (one fact, one page). The 404 page
    // sends an unknown path to /v1/ when v1 has it, so every old path is listed here.
    '/open-decisions/': '/decisions/',
    '/concepts/principles/': '/principles/',
    '/concepts/machine-identity/': '/concepts/identity/',
    '/concepts/secrets/': '/concepts/data/#storage-classes',
    '/concepts/integrations/': '/integrations/',
    '/runtimes/boundaries/': '/concepts/boundaries/',
    '/architecture/processes/': '/architecture/components/',
    '/architecture/listeners/': '/architecture/deployment/#listeners',
    '/tutorials/': '/tutorials/single-node-install/',
    '/distribution/platforms/': '/distribution/packages/',
    '/integrations/slack/': '/integrations/more/#slack',
    '/integrations/outline/': '/integrations/more/#outline-wiki',
    '/integrations/oncall/': '/integrations/more/#goalert',
    '/contributing/requirements/': '/contributing/decisions/',
    '/contributing/research/': '/contributing/decisions/#spikes-and-research',
    '/contributing/writing/': '/contributing/pages/#writing-style',
    // The pages merged on 2026-11-03 (wave 2 of the v2 design).
    '/architecture/context/': '/architecture/',
    '/architecture/source-layout/': '/architecture/components/#source-layout',
    '/architecture/manifest/': '/reference/rules/',
    '/reference/storage/': '/reference/store-api/',
    '/reference/install-file/': '/reference/bootstrap-file/',
    '/reference/config-sources/': '/reference/signed-config/',
    '/reference/vocabulary/': '/reference/policy/#the-grant-vocabulary',
    '/runtimes/installations/': '/runtimes/',
    '/distribution/': '/distribution/packages/',
    '/integrations/aws/': '/integrations/cloud/#aws',
    '/integrations/cloudflare/': '/integrations/cloud/#cloudflare',
    '/integrations/postgresql/': '/integrations/infrastructure-access/#postgresql',
    '/integrations/ssh/': '/integrations/infrastructure-access/#ssh',
    ...decisionRedirects,
  },
  ...(workers ? workersOptions : {}),
  prefetch,
  vite: {
    plugins: [fillPrefetchPlaceholders()],
    // Mermaid's diagram engines are one large lazily loaded chunk; the size
    // warning is expected for it and the build allows no other warning.
    build: { chunkSizeWarningLimit: 4000 },
  },
  // Astro's Markdown processor is Sätteri; statusPlugin puts each page's status
  // in its first paragraph (src/remark-status.mjs). Starlight adds its own
  // plugins (asides, heading links) to the same processor.
  markdown: { processor: satteri({ mdastPlugins: [statusPlugin] }) },
  integrations: [
    ...(workers ? [cloudflareKvId(), cloudflareWorkerMain()] : []),
    // Must come before Starlight so the ```mermaid fences are claimed first.
    mermaid({
      theme: 'neutral',
      autoTheme: true,
      enableLog: false,
      mermaidConfig: { ...naturalSize, themeVariables: { fontSize: '16px' } },
    }),
    starlight({
      title: 'sluis',
      description:
        'sluis is a pluggable identity and access broker for people, robots and external systems. Open source, designed in the open.',
      favicon: '/favicon.svg',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/truvity/sluis' },
      ],
      editLink: { baseUrl: 'https://github.com/truvity/sluis/edit/main/' },
      lastUpdated: false,
      // The 404 page is src/pages/404.astro.
      disable404Route: true,
      head: [
        { tag: 'meta', attrs: { property: 'og:site_name', content: 'sluis' } },
        { tag: 'meta', attrs: { property: 'og:type', content: 'website' } },
        {
          tag: 'script',
          attrs: { type: 'application/ld+json' },
          content: JSON.stringify({
            '@context': 'https://schema.org',
            '@type': 'SoftwareSourceCode',
            name: 'sluis',
            description: 'A pluggable identity and access broker for people, robots and external systems.',
            url: 'https://sluis.id/',
            codeRepository: 'https://github.com/truvity/sluis',
            license: 'https://opensource.org/license/mit',
          }),
        },
      ],
      // The status badge beside each page title, its colours and the rule that
      // hides the status paragraph on the page (it stays in llms.txt). Footer
      // is the default one plus the diagram Expand script. TwoColumnContent and
      // PageSidebar drop the right-hand "On this page" column for the dropdown
      // at the top of the content (src/styles/layout.css sets the wide column).
      components: {
        PageTitle: './src/components/PageTitle.astro',
        Footer: './src/components/Footer.astro',
        TwoColumnContent: './src/components/TwoColumnContent.astro',
        PageSidebar: './src/components/PageSidebar.astro',
      },
      customCss: ['./src/styles/layout.css', './src/styles/status.css', './src/styles/mermaid.css'],
      routeMiddleware: './src/route-middleware.ts',
      sidebar: [
        { label: 'Overview', slug: 'overview' },
        { label: 'Design principles', slug: 'principles' },
        { label: 'Concepts', items: [{ autogenerate: { directory: 'concepts' } }] },
        { label: 'Architecture', items: [{ autogenerate: { directory: 'architecture' } }] },
        { label: 'Reference', items: [{ autogenerate: { directory: 'reference' } }] },
        { label: 'Security', items: [{ autogenerate: { directory: 'security' } }] },
        { label: 'Runtimes', items: [{ autogenerate: { directory: 'runtimes' } }] },
        { label: 'Integrations', items: [{ autogenerate: { directory: 'integrations' } }] },
        {
          label: 'Install and release',
          items: [{ slug: 'tutorials/single-node-install' }, { autogenerate: { directory: 'distribution' } }],
        },
        { label: 'Standards and conformance', items: [{ autogenerate: { directory: 'standards' } }] },
        {
          label: 'Project',
          items: [
            { label: 'Roadmap', slug: 'roadmap' },
            // Built from the project board and the repository (src/pages/status.astro).
            { label: 'Project status', link: '/status/' },
            { label: 'v1 parity checklist', slug: 'features' },
            { label: 'Decisions', link: '/decisions/' },
            // Generated from docs/requirements/*.yaml (src/pages/requirements/).
            { label: 'Requirements', link: '/requirements/' },
            { label: 'Requirements matrix', link: '/requirements/matrix/' },
            { label: 'Requirements coverage', link: '/requirements/coverage/' },
          ],
        },
        {
          label: 'Contributing',
          items: [{ label: 'Overview', slug: 'contributing' }, { autogenerate: { directory: 'contributing' } }],
        },
        { label: 'v1 documentation', link: '/v1/' },
      ],
      plugins: [
        // Fails the build on a broken internal link or anchor.
        starlightLinksValidator({
          errorOnRelativeLinks: false,
          // The ADR pages and the v1 documentation are not Starlight content.
          // The two explorer pages are MDX (they import components), and the
          // validator collects no headings from an MDX page, so a link to one
          // would always fail; the pages themselves are still built and checked.
          // The requirements pages are generated in src/pages from the catalogue
          // (custom pages the validator cannot see); lychee checks links to them.
          // So are the status page and /data/repo.json. The home page is MDX too, so a link to
          // it ('/') fails the same way.
          exclude: [
            '/', '/v1/', '/v1/**', '/decisions/', '/decisions/**', '/architecture/explorer/', '/architecture/audit-explorer/',
            '/requirements/', '/requirements/**', '/status/', '/data/**',
          ],
        }),
        starlightLlmsTxt({
          projectName: 'sluis',
          description:
            'sluis is a pluggable identity and access broker for people, robots and external systems. v2 is being designed in the open; v1 documentation is at /v1/. Each page starts with its status: target state, partly built, page complete (a page about the project itself) or shipped.',
          // Keep the Proposed asides (notes) in llms-small.txt as well.
          minify: { note: false },
        }),
      ],
    }),
  ],
});
