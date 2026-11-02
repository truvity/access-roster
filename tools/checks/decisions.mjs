#!/usr/bin/env node
// Decision records in docs/decisions/ (the rules of docs/decisions/README.md).
//
// The format is read from the repository, not written down here:
//   - the header fields (`**Status:**`, `**Layer:**`, `**Date:**`) and the sections (`## Context` ...)
//     are the ones 0000-template.md has, in its order; `**Layer:**` is optional (no line means core)
//     and its value is one of the backticked values of the README's "Layer." bullet;
//   - a road not taken is one bullet, `- **Option.** why it lost`, as in the template;
//   - the allowed statuses are the backticked values of the README's "Status." bullet, and the
//     template's comment must list the same set; NNNN in a status is a record number that must exist;
//   - the parts the README's "Format" list names must be the template's fields and sections.
//
// Then, for every record:
//   - the file name is NNNN-kebab-case.md, and no two records share a number;
//   - the title is `# NNNN — ...` with the number of the file;
//   - each header field appears once, before the first section, in the template's order (an
//     optional one may be absent); the status and the layer are allowed values and the date a real
//     YYYY-MM-DD day;
//   - each section appears exactly once, in the template's order, and is not empty;
//   - "Roads not taken" holds only road bullets (`- **Option.** reason` or `- **Option:** reason`),
//     at least one, and no `###` option;
//   - one `Proposal: [issue #N](https://github.com/truvity/sluis/issues/N)` line comes before the first section;
//   - no line of the template's instructions comment (<!-- ... -->) is left, no "(inferred" marker and no
//     "Rewritten in place" history line; an Accepted record says nothing is "not decided" or "will be decided";
//   - the README index has exactly one row for it, linking the file, with the same status.
// And the index has no row without a file.
//
// Then the citations, in docs/ (Markdown and YAML), site/src/, the root Markdown files and .claude/:
//   - every "ADR NNNN" (and "ADRs NNNN and NNNN") names a record that exists; "v1 ADR NNNN" and a
//     ritueel record ("ritueel's ADR NNNN", "ADR NNNN in its repository") are someone else's numbers;
//   - every link to a record, `/decisions/NNNN-slug/` or `decisions/NNNN-slug.md`, names a record file,
//     and its `#anchor`, if any, is a heading of that record (GitHub's slug rules, as the site uses);
//   - docs/decisions/renumbered.json, the map of the 2026-11-01 renumbering, names as `new` only records
//     that exist and as `old` only slugs that are not files, and site/astro.config.mjs reads it (the redirects).
//
// usage: tools/checks/decisions.mjs [repo-root]
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { reporter, repoRoot, trackedFiles } from './lib.mjs';

const root = repoRoot();
const dir = join(root, 'docs', 'decisions');
const r = reporter('check-decisions');
const E = r.error;

const TEMPLATE = '0000-template.md';
// Header fields a record may leave out.
const OPTIONAL_FIELDS = new Set(['Layer']);
const FILE = /^(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$/;
const read = (name) => readFileSync(join(dir, name), 'utf8');

// Lines outside fenced code blocks, with their 1-based numbers.
function lines(text) {
  const out = [];
  let fence = null;
  text.split('\n').forEach((line, i) => {
    const f = /^\s*(```|~~~)/.exec(line);
    if (f) fence = fence === f[1] ? null : fence ?? f[1];
    else if (!fence) out.push({ n: i + 1, line });
  });
  return out;
}

// Split into the part before the first `## ` and one entry per `## ` section.
function sections(text) {
  const head = [];
  const secs = [];
  for (const l of lines(text)) {
    const h = /^## (.+?)\s*$/.exec(l.line);
    if (h) secs.push({ title: h[1], n: l.n, body: [] });
    else (secs.length ? secs[secs.length - 1].body : head).push(l);
  }
  return { head, secs };
}

const FIELD = /^\*\*([A-Z][A-Za-z ]*):\*\*\s*(.*?)\s*$/;
// A road not taken: the option in bold, ending in a full stop or a colon, then why it lost.
const ROAD = /^- \*\*(.+?)[.:]\*\*\s+\S/;
const PROPOSAL = /^Proposal: \[issue #(\d+)\]\(https:\/\/github\.com\/truvity\/sluis\/issues\/(\d+)\)/;
// Words an Accepted record does not use about its own content.
const OPEN_PART = /\bnot (?:yet )?decided\b|\bwill be decided\b|\bto be decided\b|\bundecided\b|\bdecided later\b/i;

// ---- the format, from the template
if (!existsSync(join(dir, TEMPLATE))) {
  E(`docs/decisions/${TEMPLATE} is missing; the format is read from it`);
  r.finish(0, 'records');
}
const template = read(TEMPLATE);
const tpl = sections(template);
const FIELDS = tpl.head.map((l) => FIELD.exec(l.line)?.[1]).filter(Boolean);
const SECTIONS = tpl.secs.map((s) => s.title);
const ROADS = 'Roads not taken';
const tplRoads = tpl.secs.find((s) => s.title === ROADS);
const tplRoadLines = (tplRoads?.body ?? []).filter((l) => l.line.trim());
// The lines of the template's instructions comment; a record keeps none of them.
const tplComment = (/<!--([\s\S]*?)-->/.exec(template)?.[1] ?? '').split('\n').map((l) => l.trim()).filter((l) => l.length >= 12);
if (!FIELDS.includes('Status') || !FIELDS.includes('Date')) E(`${TEMPLATE}: no **Status:** and **Date:** fields found`);
if (!SECTIONS.length) E(`${TEMPLATE}: no ## sections found`);
if (!SECTIONS.includes(ROADS)) E(`${TEMPLATE}: no "## ${ROADS}" section`);
if (!tplRoadLines.length || !tplRoadLines.every((l) => ROAD.test(l.line))) E(`${TEMPLATE}: "## ${ROADS}" must hold only road bullets, "- **Option.** why it lost"`);

// ---- the allowed statuses, from the README, cross-checked with the template comment
const readme = existsSync(join(dir, 'README.md')) ? read('README.md') : '';
if (!readme) E('docs/decisions/README.md is missing');
const statusBullet = /^- \*\*Status\.\*\*(.*)$/m.exec(readme)?.[1] ?? '';
const STATUSES = [...statusBullet.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
// The layers a record may name, from the README's "Layer." bullet.
const layerBullet = /^- \*\*Layer\.\*\*(.*)$/m.exec(readme)?.[1] ?? '';
const LAYERS = [...layerBullet.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
if (FIELDS.includes('Layer') && !LAYERS.length) E('README.md: no "- **Layer.** ... `core` ..." bullet with backticked values');
if (!STATUSES.length) E('README.md: no "- **Status.** One of `...`" bullet with backticked values');
const tplStatuses = (/^Status:\s*(.+?)\.?\s*$/m.exec(template)?.[1] ?? '')
  .split(/,\s*/).map((s) => s.replace(/^or\s+/, '').trim()).filter(Boolean);
if (JSON.stringify([...tplStatuses].sort()) !== JSON.stringify([...STATUSES].sort())) {
  E(`the statuses of README.md (${STATUSES.join(' | ')}) and of ${TEMPLATE}'s comment (${tplStatuses.join(' | ')}) differ`);
}
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const STATUS_RX = STATUSES.map((s) => new RegExp(`^${esc(s).replace(/NNNN/g, '(\\d{4})')}$`));

// The README's "Format" list must name the template's fields and sections, in order.
const format = /^## Format\s*$([\s\S]*?)^## /m.exec(readme)?.[1] ?? '';
const parts = [...format.matchAll(/^- \*\*([^*]+?)\.\*\*/gm)].map((m) => m[1]);
if (JSON.stringify(parts) !== JSON.stringify([...FIELDS, ...SECTIONS])) {
  E(`README.md "Format" lists ${JSON.stringify(parts)}, ${TEMPLATE} has ${JSON.stringify([...FIELDS, ...SECTIONS])}`);
}
if (r.errors.length) r.finish(0, 'records');

// ---- the files
const names = readdirSync(dir).sort();
const records = new Map();
for (const name of names) {
  if (name === 'README.md' || name === TEMPLATE || name === 'renumbered.json') continue;
  const m = FILE.exec(name);
  if (!m) { E(`docs/decisions/${name}: not NNNN-kebab-case.md (or README.md, ${TEMPLATE})`); continue; }
  if (m[1] === '0000') { E(`docs/decisions/${name}: 0000 is the template's number`); continue; }
  if (records.has(m[1])) E(`docs/decisions/${name}: number ${m[1]} is also used by ${records.get(m[1]).name}`);
  else records.set(m[1], { name, num: m[1] });
}

const isDay = (s) => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(`${s}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
};

// ---- each record
for (const rec of records.values()) {
  const where = `docs/decisions/${rec.name}`;
  const text = read(rec.name);
  const { head, secs } = sections(text);

  const title = /^# (\d{4}) — \S.*$/.exec(text.split('\n')[0]);
  if (!title) E(`${where}:1: the title must be "# ${rec.num} — <decision>"`);
  else if (title[1] !== rec.num) E(`${where}:1: the title has number ${title[1]}, the file ${rec.num}`);

  const fields = head.map((l) => ({ ...l, m: FIELD.exec(l.line) })).filter((l) => l.m && FIELDS.includes(l.m[1]));
  let last = -1;
  for (const f of FIELDS) {
    const hits = fields.filter((l) => l.m[1] === f);
    if (hits.length === 0 && OPTIONAL_FIELDS.has(f)) continue;
    if (hits.length !== 1) { E(`${where}: **${f}:** appears ${hits.length} times before the first section, expected once`); continue; }
    const at = fields.indexOf(hits[0]);
    if (at < last) E(`${where}:${hits[0].n}: **${f}:** is out of the template's order (${FIELDS.join(', ')})`);
    last = at;
    rec[f] = hits[0].m[2];
  }
  if (rec.Status !== undefined) {
    const ok = STATUS_RX.map((rx) => rx.exec(rec.Status)).find(Boolean);
    if (!ok) E(`${where}: status "${rec.Status}" is not one of ${STATUSES.join(', ')}`);
    for (const n of ok?.slice(1) ?? []) {
      if (!records.has(n)) E(`${where}: status "${rec.Status}" names record ${n}, which does not exist`);
      if (n === rec.num) E(`${where}: status "${rec.Status}" names the record itself`);
    }
  }
  if (rec.Layer !== undefined && !LAYERS.includes(rec.Layer)) E(`${where}: layer "${rec.Layer}" is not one of ${LAYERS.join(', ')}`);
  if (rec.Date !== undefined && !isDay(rec.Date)) E(`${where}: date "${rec.Date}" is not a YYYY-MM-DD day`);

  let prev = -1;
  for (const s of SECTIONS) {
    const hits = secs.filter((x) => x.title === s);
    if (hits.length !== 1) { E(`${where}: "## ${s}" appears ${hits.length} times, expected once`); continue; }
    const at = secs.indexOf(hits[0]);
    if (at < prev) E(`${where}:${hits[0].n}: "## ${s}" is out of the template's order (${SECTIONS.join(', ')})`);
    prev = at;
    if (!hits[0].body.some((l) => l.line.trim() && !/^<!--.*-->$/.test(l.line.trim()))) E(`${where}:${hits[0].n}: "## ${s}" is empty`);
  }

  const roads = secs.find((x) => x.title === ROADS);
  if (roads) {
    const body = roads.body.filter((l) => l.line.trim() && !/^<!--.*-->$/.test(l.line.trim()));
    if (!body.some((l) => ROAD.test(l.line))) E(`${where}:${roads.n}: "## ${ROADS}" has no road; every other option weighed is one bullet, "- **Option.** why it lost"`);
    for (const l of body) {
      if (/^### /.test(l.line)) E(`${where}:${l.n}: "## ${ROADS}" has a "###" option; a road is one bullet, "- **Option.** why it lost"`);
      else if (!ROAD.test(l.line)) E(`${where}:${l.n}: "## ${ROADS}" holds a line that is not a road bullet ("- **Option.** why it lost")`);
    }
  }

  const proposals = head.filter((l) => /^Proposal:/.test(l.line));
  if (proposals.length !== 1) E(`${where}: ${proposals.length} "Proposal: [issue #N](https://github.com/truvity/sluis/issues/N)" lines before the first section, expected one`);
  else {
    const p = PROPOSAL.exec(proposals[0].line);
    if (!p || p[1] !== p[2]) E(`${where}:${proposals[0].n}: the proposal line is "Proposal: [issue #N](https://github.com/truvity/sluis/issues/N)" with one number`);
  }

  for (const l of lines(text)) {
    if (/\(inferred\b/i.test(l.line)) E(`${where}:${l.n}: an "(inferred ...)" marker; state the point or drop it`);
    if (/\bRewritten in place\b/i.test(l.line)) E(`${where}:${l.n}: a history line; git keeps the history`);
    if (rec.Status === 'Accepted' && OPEN_PART.test(l.line)) E(`${where}:${l.n}: an Accepted record has no open part ("${OPEN_PART.exec(l.line)[0]}"); settle it, or name it under Follow-ups with its issue`);
  }

  if (tplComment.some((l) => text.includes(l))) E(`${where}: still has a line of the template's instructions comment`);
}

// ---- the index
const idx = /^## Index\s*$([\s\S]*?)(?=^## |(?![\s\S]))/m.exec(readme);
if (!idx) E('README.md: no "## Index" section');
const rows = new Map();
const indexStart = readme.slice(0, idx?.index ?? 0).split('\n').length;
(idx?.[1] ?? '').split('\n').forEach((line, i) => {
  if (!line.startsWith('|') || /^\|\s*-/.test(line) || /^\|\s*ADR\s*\|/.test(line)) return;
  const n = indexStart + i;
  const cells = line.replace(/^\|/, '').replace(/\|\s*$/, '').split('|').map((c) => c.trim());
  const link = /^\[(\d{4})\]\(([^)#\s]+)\)$/.exec(cells[0] ?? '');
  if (cells.length !== 3 || !link) { E(`README.md:${n}: an index row is "| [NNNN](NNNN-slug.md) | decision | status |"`); return; }
  const [, num, target] = link;
  if (rows.has(num)) E(`README.md:${n}: a second index row for ${num}`);
  rows.set(num, { n, target, status: cells[2] });
  const rec = records.get(num);
  if (!rec) { E(`README.md:${n}: index row ${num} has no record in docs/decisions/`); return; }
  if (target !== rec.name) E(`README.md:${n}: index row ${num} links ${target}, the file is ${rec.name}`);
  if (rec.Status !== undefined && cells[2] !== rec.Status) E(`README.md:${n}: index row ${num} says "${cells[2]}", the record says "${rec.Status}"`);
});
for (const rec of records.values()) {
  if (!rows.has(rec.num)) E(`docs/decisions/${rec.name}: no row in the README index`);
}

// ---- citations: "ADR NNNN" and links to a record, across the docs and the site
// GitHub's heading slugs (github-slugger), which the site's Markdown uses: lower case, markup and
// punctuation dropped, spaces to hyphens, a repeated slug numbered.
function headingSlugs(text) {
  const seen = new Map();
  const out = new Set();
  for (const l of lines(text)) {
    const h = /^#{1,6}\s+(.+?)\s*#*\s*$/.exec(l.line);
    if (!h) continue;
    const plain = h[1].replace(/\[([^\]]*)\]\([^)]*\)/g, '$1').replace(/<[^>]+>/g, '').replace(/[`*_]/g, (c) => (c === '_' ? '_' : ''));
    let s = plain.toLowerCase().replace(/[^\p{L}\p{M}\p{N}\p{Pc} -]/gu, '').replace(/ /g, '-');
    const n = seen.get(s) ?? 0;
    seen.set(s, n + 1);
    if (n) s = `${s}-${n}`;
    out.add(s);
  }
  return out;
}
const slugs = new Map([...records.values()].map((rec) => [rec.name.replace(/\.md$/, ''), rec]));
const anchorsOf = (slug) => {
  const rec = slugs.get(slug);
  rec.anchors ??= headingSlugs(read(rec.name));
  return rec.anchors;
};
const CITE_FILE = /^(?:docs\/.+\.(?:md|mdx|yaml)|site\/src\/.+|[^/]+\.md|\.claude\/.+\.md)$/;
const ADR_RX = /\bADRs? (\d{4})((?:(?:,? and |, | or |\/)\d{4})*)/g;
const LINK_RX = /\/?decisions\/(\d{4}-[a-z0-9]+(?:-[a-z0-9]+)*)(\/|\.md)?(#[\w-]+)?/g;
let cited = 0;
let files = [];
try { files = trackedFiles(root).filter((f) => CITE_FILE.test(f)); } catch { /* not a git checkout */ }
for (const f of files) {
  let text;
  try { text = readFileSync(join(root, f), 'utf8'); } catch { continue; }
  if (!/ADR|decisions\/|\]\(\d{4}-/.test(text)) continue;
  text.split('\n').forEach((line, i) => {
    const at = `${f}:${i + 1}`;
    for (const m of line.matchAll(ADR_RX)) {
      const before = line.slice(Math.max(0, m.index - 40), m.index);
      const after = line.slice(m.index + m[0].length, m.index + m[0].length + 30);
      if (/\bv1\s*$|ritueel/i.test(before) || /^\s*(?:in its repository|of ritueel|in ritueel)/.test(after)) continue;
      for (const n of [m[1], ...[...m[2].matchAll(/\d{4}/g)].map((x) => x[0])]) {
        cited++;
        if (n !== '0000' && !records.has(n)) E(`${at}: "${m[0]}" names record ${n}, which does not exist; a planned decision is named by its issue`);
      }
    }
    for (const m of line.matchAll(LINK_RX)) {
      const [, slug, , anchor] = m;
      const ctx = line.slice(Math.max(0, m.index - 80), m.index);
      // v1's records (/v1/decisions/, master) and ritueel's are someone else's numbers.
      if (/\/v1$|\/master(?:\/docs)?$|ritueel\S*$/.test(ctx)) continue;
      if (slug === TEMPLATE.replace(/\.md$/, '')) continue;
      cited++;
      if (!slugs.has(slug)) { E(`${at}: a link to the record "${slug}", which is not a file in docs/decisions/`); continue; }
      if (anchor && !anchorsOf(slug).has(anchor.slice(1))) E(`${at}: the link to ${slug} has the anchor ${anchor}, which is no heading of that record`);
    }
  });
}

// ---- the renumbering map and the redirects made from it
const mapFile = join(dir, 'renumbered.json');
if (existsSync(mapFile)) {
  let map;
  try { map = JSON.parse(readFileSync(mapFile, 'utf8')); } catch (e) { E(`docs/decisions/renumbered.json: not JSON (${e.message})`); }
  for (const [k, row] of (map?.records ?? []).entries()) {
    if (!slugs.has(row.new)) E(`docs/decisions/renumbered.json: records[${k}] points "${row.old}" at "${row.new}", which is not a record`);
    if (row.old !== row.new && existsSync(join(dir, `${row.old}.md`))) E(`docs/decisions/renumbered.json: records[${k}]: "${row.old}" is still a file, so it cannot be redirected`);
  }
  for (const [from, to] of Object.entries(map?.anchors ?? {})) {
    const [slug, anchor] = to.split('#');
    if (!slugs.has(slug)) E(`docs/decisions/renumbered.json: anchors["${from}"] points at "${slug}", which is not a record`);
    else if (anchor && !anchorsOf(slug).has(anchor)) E(`docs/decisions/renumbered.json: anchors["${from}"] points at #${anchor}, which is no heading of ${slug}`);
  }
  const astro = join(root, 'site', 'astro.config.mjs');
  if (existsSync(astro) && !readFileSync(astro, 'utf8').includes('renumbered.json')) E('site/astro.config.mjs does not read docs/decisions/renumbered.json, so the old record addresses would not redirect');
}

r.finish(records.size, `records (${SECTIONS.length} sections, ${STATUSES.length} statuses from the template and README; ${cited} citations in ${files.length} files)`);
