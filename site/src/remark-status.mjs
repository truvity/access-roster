// Puts the page's status in its first paragraph, so it reaches the rendered
// page and llms.txt, llms-full.txt and llms-small.txt (which are built from
// the rendered content). The paragraph carries the class `sluis-status-note`;
// src/styles/status.css hides it on the HTML page, where the badge says the
// same thing, and the llms output keeps it.
//
// Astro's Markdown processor is Sätteri, so this is a Sätteri mdast plugin
// (the equivalent of a remark plugin); a factory is called once per document.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const STATUS_TEXT = {
  target: 'Status: target state. This page describes the design of sluis v2; it is not built yet.',
  partial: 'Status: partly built. This page describes the design of sluis v2; some of it is built and some is not yet.',
  page: 'Status: page complete. This page is about the project itself. It is complete and describes nothing that is built.',
  shipped: 'Status: shipped. This page describes what sluis does today.',
};

// The `status:` value in a document's front matter, or undefined.
function statusOf(text) {
  const fm = /^---\r?\n([\s\S]*?)\r?\n---(\r?\n|$)/.exec(text);
  const m = fm && /^status:[ \t]*["']?(\w+)["']?[ \t]*$/m.exec(fm[1]);
  return m ? m[1] : undefined;
}

export function statusPlugin({ fileURL, source, data }) {
  // Pages under docs/ only; the front matter is read from the source, or from
  // the file when the processor hands over the body alone.
  const frontmatter = data.astro?.frontmatter?.status;
  let status = typeof frontmatter === 'string' ? frontmatter : statusOf(source);
  if (!status && fileURL?.protocol === 'file:') {
    try {
      status = statusOf(readFileSync(fileURLToPath(fileURL), 'utf8'));
    } catch {
      return null;
    }
  }
  const text = STATUS_TEXT[status];
  if (!text) return null;
  return {
    name: 'sluis-status',
    before(root, ctx) {
      ctx.prependChild(root, {
        type: 'paragraph',
        data: { hName: 'p', hProperties: { class: 'sluis-status-note' } },
        children: [{ type: 'text', value: text }],
      });
    },
  };
}
