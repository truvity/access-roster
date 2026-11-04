// Draws the coverage table of docs/standards/conformance.md at build time, so that the page holds no number
// that a pull request must keep in step with the catalogue. The page has one paragraph that reads
// `[[coverage-table]]`; this plugin replaces it with the table computed from docs/requirements/ (the same figure
// as coverage() in src/lib/requirements.ts, /data/repo.json and the console line of check-requirements.mjs).
// A Sätteri mdast plugin, like remark-status.mjs. site/scripts/check-repo-json.mjs reads the figures back from the
// built page and fails when they differ from /data/repo.json, or when the placeholder was not replaced.
import { coverage } from './lib/requirements.ts';

export const PLACEHOLDER = '[[coverage-table]]';
const text = (value) => ({ type: 'text', value });
const cell = (value) => ({ type: 'tableCell', children: [text(value)] });
const row = (...values) => ({ type: 'tableRow', children: values.map(cell) });

export function coveragePlugin({ source }) {
  if (!source?.includes(PLACEHOLDER)) return null;
  return {
    name: 'sluis-coverage',
    before(root, ctx) {
      const c = coverage();
      const holder = root.children.find((n) => n.type === 'paragraph' && n.children?.length === 1 && n.children[0].value === PLACEHOLDER);
      if (!holder) throw new Error(`coverage: the paragraph ${PLACEHOLDER} was not found`);
      ctx.replaceNode(holder, {
        type: 'table',
        align: [null, null, null],
        children: [
          row('Requirements', 'Externally checked', 'Share'),
          row(`All, not withdrawn (${c.all.requirements})`, String(c.all.externallyChecked), `${c.all.share.toFixed(1)}%`),
          row(`MUST (${c.must.requirements})`, String(c.must.externallyChecked), `${c.must.share.toFixed(1)}%`),
        ],
      });
    },
  };
}
