#!/usr/bin/env node
// The vocabulary page, docs/concepts/index.md, against docs/glossary.yaml: the terms by category, each
// with its meaning and where to read more, then the retired terms with what replaces them. The block
// between the markers is generated; the check fails while it is stale (`--write` rewrites it).
//
//   - the glossary: every term has a term, a definition and a category of `categories`; terms are unique;
//     a `see` is a decision record (`NNNN-slug` or `NNNN-slug#heading`, which must exist) or a site path;
//   - the page: the generated block equals the generator's output.
//
// The glossary's own shape and the retired-terms scan are tools/checks/terms.mjs's.
//
// usage: tools/checks/glossary-page.mjs [--write] [repo-root]
import { anchor, code, generator, list, md, slug, table } from './pages-lib.mjs';

const SOURCE = 'docs/glossary.yaml';
const PAGE = 'docs/concepts/index.md';
const g = generator('check-glossary-page', 'glossary-page.mjs', { source: SOURCE, page: PAGE, recipe: 'glossary-write' });
const { error, load, adrRef, claim, heading } = g;

const gl = load(SOURCE);
const categories = gl && typeof gl.categories === 'object' ? gl.categories : {};
const terms = Array.isArray(gl?.terms) ? gl.terms : [];
const retired = Array.isArray(gl?.retired) ? gl.retired : [];
if (gl) {
  const seen = new Set();
  for (const [i, t] of terms.entries()) {
    const at = `${SOURCE}: terms[${i}]${t?.term ? ` (${t.term})` : ''}`;
    if (typeof t?.term !== 'string' || typeof t?.definition !== 'string') { error(`${at}: needs a term and a definition`); continue; }
    if (!(t.category in categories)) error(`${at}: category ${t.category} is not in categories`);
    if (seen.has(t.term.toLowerCase())) error(`${at}: the term is defined twice`);
    seen.add(t.term.toLowerCase());
    if ('see' in t && !(Array.isArray(t.see) && t.see.every((s) => typeof s === 'string'))) error(`${at}: see must be a list of strings`);
  }
}

// The title of a category's section: its key, with the acronym in capitals.
const title = (key) => (key === 'ciam' ? 'CIAM' : key[0].toUpperCase() + key.slice(1));
// A site path as a link text: its last segment, or the section's name for a path with a fragment.
const pathLabel = (p) => {
  const [path, frag] = p.split('#');
  const last = path.split('/').filter(Boolean).pop() ?? 'Concepts';
  const base = last.replace(/-/g, ' ').replace(/^./, (c) => c.toUpperCase());
  return frag ? `${base} (${frag.replace(/^\d+-/, '').replace(/-/g, ' ')})` : base;
};
const see = (t) => (t.see ?? []).map((s) => (s.startsWith('/') ? `[${pathLabel(s)}](${s})` : adrRef(s))).join(', ');
const termId = (t) => slug(t.term.replace(/[@<>]/g, ' ').trim().replace(/\s+/g, ' '));

function render() {
  const out = [];
  // an A-to-Z line for lookup
  const sorted = [...terms].sort((a, b) => a.term.toLowerCase().localeCompare(b.term.toLowerCase()));
  out.push(`${terms.length} terms in ${Object.keys(categories).length} categories. A to Z: ${sorted.map((t) => `[${md(t.term)}](#${termId(t)})`).join(' · ')}.`, '');
  for (const [key, desc] of Object.entries(categories)) {
    const inCat = terms.filter((t) => t.category === key);
    if (!inCat.length) { error(`${SOURCE}: the category ${key} has no term`); continue; }
    out.push(heading(2, `Category: ${title(key)}`), '', `${md(desc)}.`, '');
    out.push(...table(['Term', 'Meaning', 'Read more'], inCat.map((t) => {
      const parts = [md(t.definition)];
      if (t.avoid?.length) parts.push(`*Avoid:* ${md(t.avoid.join('; '))}.`);
      if (t.notes) parts.push(`*Note:* ${md(t.notes)}`);
      const name = `**${md(t.term)}**${t.code && t.code !== t.term ? ` ${code(t.code)}` : ''}`;
      claim(termId(t), `the term "${t.term}"`);
      return [`${anchor(termId(t))}${name}`, parts.join('<br>'), see(t) || '—'];
    })), '');
  }
  out.push(heading(2, 'Retired terms'), '',
    'These words are not used in the documentation. `just check-terms` reads the glossary and reports each hit; the replacement is the word to write instead.', '');
  out.push(...table(['Retired term', 'Write instead', 'Still correct in'], retired.map((r) => [
    md(r.term),
    md(r.replacement) + (r.notes ? `<br>*Note:* ${md(r.notes)}` : ''),
    r.allowed_in?.length ? md(list(r.allowed_in, '', '; ')) : '—',
  ])));
  return out;
}

g.sync(render, terms.length, 'terms');
