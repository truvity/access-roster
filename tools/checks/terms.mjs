#!/usr/bin/env node
// The retired-terms lint. docs/glossary.yaml names the words the design no longer uses (`retired`)
// and how to find them (`lint`); this check scans the docs and the site content for them.
//
//   - the glossary itself: schema 1, the six top-level keys, every `lint.rules[].id` is a
//     `retired[].id` and the reverse, every pattern compiles, every term has a category of
//     `categories` and a unique `term`;
//   - the scan: every tracked file that `lint.scope.include` matches and `lint.scope.exclude`
//     does not, line by line. `lint.strip_before_match` is removed from the line first (link
//     targets, bare URLs, old record slugs), then each rule's `pattern` is looked for. A hit is
//     not counted when the rule's `context_allow` also matches the line, when the line or the line
//     before it carries `terms-allow: <id>`, or when it lies in a requirement record that
//     `lint.skip_records` skips (a withdrawn record keeps its old text for ever);
//   - the markers: every `terms-allow: <id>` found is listed, so a reviewer sees each exception. A
//     marker with an id that is not a retired id is an error.
//
// Mode: WARN by default (the hits are printed, the exit code is 0). `--error` (or TERMS_MODE=error)
// makes any hit fail the run; it is switched on at the end of wave 3 of the design rewrite.
// A glossary or a scan that finds nothing to check fails in both modes: an empty sweep proves nothing.
//
// Needs the `yaml` package of site/ (`just site-install`).
//
// usage: tools/checks/terms.mjs [--error] [--quiet] [repo-root]
//   --error   a hit fails the run (default: warn)
//   --quiet   print the summary and the markers, not every hit
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { reporter, repoRoot, trackedFiles } from './lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const { parse } = createRequire(join(here, '..', '..', 'site', 'package.json'))('yaml');

const root = repoRoot();
const strict = process.argv.includes('--error') || process.env.TERMS_MODE === 'error';
const quiet = process.argv.includes('--quiet');
const { error, errors, finish } = reporter('check-terms');

const GLOSSARY = 'docs/glossary.yaml';
const TOP = ['schema', 'checked', 'categories', 'terms', 'retired', 'lint'];
const ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const MARKER = /terms-allow:\s*([a-z][a-z0-9-]*(?:\s*,\s*[a-z][a-z0-9-]*)*)/;

// ---- the glossary
if (!existsSync(join(root, GLOSSARY))) {
  error(`${GLOSSARY} is missing`);
  finish(0, 'glossary');
}
let g;
try { g = parse(readFileSync(join(root, GLOSSARY), 'utf8')); } catch (e) { error(`${GLOSSARY}: not valid YAML: ${e.message}`); finish(0, 'glossary'); }
if (!g || typeof g !== 'object') { error(`${GLOSSARY}: not a mapping`); finish(0, 'glossary'); }
if (g.schema !== 1) error(`${GLOSSARY}: schema must be 1`);
for (const k of Object.keys(g)) if (!TOP.includes(k)) error(`${GLOSSARY}: unknown top-level key ${k}`);
for (const k of TOP) if (!(k in g)) error(`${GLOSSARY}: missing top-level key ${k}`);

const retired = Array.isArray(g.retired) ? g.retired : [];
const lint = g.lint ?? {};
const rulesIn = Array.isArray(lint.rules) ? lint.rules : [];
const retiredById = new Map();
for (const [i, r] of retired.entries()) {
  const at = `${GLOSSARY}: retired[${i}]${r?.id ? ` (${r.id})` : ''}`;
  if (!r || typeof r.id !== 'string' || !ID.test(r.id)) { error(`${at}: id must be lower-case words joined by hyphens`); continue; }
  if (retiredById.has(r.id)) error(`${at}: the id is used twice`);
  retiredById.set(r.id, r);
  if (typeof r.term !== 'string' || !r.term) error(`${at}: term is missing`);
  if (typeof r.replacement !== 'string' || !r.replacement) error(`${at}: replacement is missing`);
  if ('allowed_in' in r && !(Array.isArray(r.allowed_in) && r.allowed_in.every((s) => typeof s === 'string'))) error(`${at}: allowed_in must be a list of strings`);
}
const flags = lint.case_insensitive === true ? 'i' : '';
if (typeof lint.case_insensitive !== 'boolean') error(`${GLOSSARY}: lint.case_insensitive must be true or false`);
const compile = (src, at) => {
  if (typeof src !== 'string' || !src) { error(`${at}: not a regular expression`); return null; }
  try { return new RegExp(src, flags); } catch (e) { error(`${at}: ${e.message}`); return null; }
};
const strips = (Array.isArray(lint.strip_before_match) ? lint.strip_before_match : [])
  .map((s, i) => compile(s, `${GLOSSARY}: lint.strip_before_match[${i}]`)).filter(Boolean)
  .map((rx) => new RegExp(rx.source, `${rx.flags}g`));
const rules = [];
const ruleIds = new Set();
for (const [i, r] of rulesIn.entries()) {
  const at = `${GLOSSARY}: lint.rules[${i}]${r?.id ? ` (${r.id})` : ''}`;
  if (!r || !retiredById.has(r.id)) { error(`${at}: id is not a retired id`); continue; }
  ruleIds.add(r.id);
  const pattern = compile(r.pattern, `${at}: pattern`);
  const allow = r.context_allow === undefined ? null : compile(r.context_allow, `${at}: context_allow`);
  for (const k of Object.keys(r)) if (!['id', 'pattern', 'context_allow'].includes(k)) error(`${at}: unknown field ${k}`);
  if (pattern) rules.push({ id: r.id, pattern, allow });
}
for (const id of retiredById.keys()) if (!ruleIds.has(id)) error(`${GLOSSARY}: retired term ${id} has no rule in lint.rules`);

const categories = g.categories && typeof g.categories === 'object' ? g.categories : {};
const seen = new Set();
for (const [i, t] of (Array.isArray(g.terms) ? g.terms : []).entries()) {
  const at = `${GLOSSARY}: terms[${i}]${t?.term ? ` (${t.term})` : ''}`;
  if (!t || typeof t.term !== 'string') { error(`${at}: term is missing`); continue; }
  if (seen.has(t.term)) error(`${at}: the term is listed twice`);
  seen.add(t.term);
  if (typeof t.definition !== 'string' || !t.definition) error(`${at}: definition is missing`);
  if (!Object.hasOwn(categories, t.category)) error(`${at}: category ${t.category} is not a key of categories`);
}

// ---- globs: ** crosses directories, * does not, {a,b} alternates, ? is one character
function expandBraces(p) {
  const m = /\{([^{}]*)\}/.exec(p);
  if (!m) return [p];
  return m[1].split(',').flatMap((alt) => expandBraces(p.slice(0, m.index) + alt + p.slice(m.index + m[0].length)));
}
function globRegex(p) {
  const alts = expandBraces(p).map((one) => one
    .replace(/[.+^$()|[\]\\]/g, '\\$&')
    .replace(/\*\*\//g, '\u0000')
    .replace(/\*\*/g, '\u0001')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/\u0000/g, '(?:.*/)?')
    .replace(/\u0001/g, '.*'));
  return new RegExp(`^(?:${alts.join('|')})$`);
}
const globs = (list, at) => {
  if (!Array.isArray(list) || !list.length || list.some((s) => typeof s !== 'string')) { error(`${GLOSSARY}: ${at} must be a list of globs`); return []; }
  return list.map(globRegex);
};
const include = globs(lint.scope?.include, 'lint.scope.include');
const exclude = Array.isArray(lint.scope?.exclude) ? lint.scope.exclude.map(globRegex) : [];
const skips = [];
for (const [i, s] of (Array.isArray(lint.skip_records) ? lint.skip_records : []).entries()) {
  if (typeof s?.files !== 'string' || !s.where || typeof s.where !== 'object' || !Object.keys(s.where).length) { error(`${GLOSSARY}: lint.skip_records[${i}] needs files and where`); continue; }
  skips.push({ files: globRegex(s.files), where: Object.entries(s.where) });
}

// The lines of a requirement file that belong to a record the glossary says to skip. A record is a
// list item that starts with `- id:`; it runs to the line before the next non-blank line that is not
// indented deeper than the item (the next record, or a top-level key), or to the end of the file.
function skippedLines(rel, lines) {
  const rules = skips.filter((s) => s.files.test(rel));
  const out = new Set();
  if (!rules.length) return out;
  const esc = (v) => String(v).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  for (const [start, line] of lines.entries()) {
    const m = /^(\s*)- id:/.exec(line);
    if (!m) continue;
    let end = start + 1;
    while (end < lines.length && (/^\s*(?:#.*)?$/.test(lines[end]) || lines[end].search(/\S/) > m[1].length)) end++;
    const body = lines.slice(start, end);
    const has = (field, value) => body.some((l) => new RegExp(`^\\s+${field}:\\s*["']?${esc(value)}["']?\\s*(?:#.*)?$`).test(l));
    if (rules.some((r) => r.where.every(([f, v]) => has(f, v)))) for (let j = start; j < end; j++) out.add(j);
  }
  return out;
}

// ---- the scan
const counts = new Map([...retiredById.keys()].map((id) => [id, 0]));
const perFile = new Map();
const markers = [];
const hits = [];
let scanned = 0;
for (const rel of trackedFiles(root)) {
  if (!include.some((rx) => rx.test(rel)) || exclude.some((rx) => rx.test(rel))) continue;
  if (!existsSync(join(root, rel))) continue;
  scanned++;
  const lines = readFileSync(join(root, rel), 'utf8').split(/\r?\n/);
  const skip = skippedLines(rel, lines);
  const allowed = (i, id) => [lines[i], lines[i - 1]].some((l) => {
    const m = l === undefined ? null : MARKER.exec(l);
    return m && m[1].split(/\s*,\s*/).includes(id);
  });
  for (const [i, line] of lines.entries()) {
    const m = MARKER.exec(line);
    if (m) {
      const ids = m[1].split(/\s*,\s*/);
      markers.push(`${rel}:${i + 1}: terms-allow ${ids.join(', ')}`);
      for (const id of ids) if (!retiredById.has(id)) error(`${rel}:${i + 1}: terms-allow names ${id}, which is not a retired term of ${GLOSSARY}`);
    }
    if (skip.has(i)) continue;
    let text = line;
    for (const rx of strips) text = text.replace(rx, '');
    for (const r of rules) {
      if (!r.pattern.test(text)) continue;
      if (r.allow && r.allow.test(text)) continue;
      if (allowed(i, r.id)) continue;
      const t = retiredById.get(r.id);
      hits.push(`${rel}:${i + 1}: retired term "${t.term}" (${r.id}): use ${t.replacement}`);
      counts.set(r.id, counts.get(r.id) + 1);
      perFile.set(rel, (perFile.get(rel) ?? 0) + 1);
    }
  }
}

if (errors.length || !scanned) finish(scanned, 'files in the scope of the lint');

// ---- the report
if (!quiet) for (const h of hits) (strict ? console.error : console.log)(`${strict ? 'error' : 'warning'}: ${h}`);
if (markers.length) {
  console.log(`check-terms: ${markers.length} terms-allow marker${markers.length === 1 ? '' : 's'} for the reviewer:`);
  for (const m of markers) console.log(`  ${m}`);
}
const ranked = [...counts].filter(([, n]) => n).sort((a, b) => b[1] - a[1]);
if (ranked.length) {
  console.log('check-terms: hits per retired term:');
  for (const [id, n] of ranked) console.log(`  ${String(n).padStart(5)}  ${id}`);
}
console.log(`check-terms: ${hits.length} hits in ${perFile.size} files (${scanned} files scanned, ${retiredById.size} retired terms, ${strict ? 'error' : 'warn'} mode)`);
if (strict && hits.length) {
  console.error(`check-terms: ${hits.length} retired terms; fix them or add \`terms-allow: <id>\` where the old word is named on purpose`);
  process.exit(1);
}
console.log(`check-terms: ${scanned} files, ${strict ? 'no retired terms' : 'warn mode, exit 0'}`);
process.exit(0);
