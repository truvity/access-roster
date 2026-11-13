#!/usr/bin/env node
// The terms that sluis shares with ritueel (docs/shared-terms.yaml), offline.
//
// docs/shared-terms.yaml is one file with one wording, copied byte for byte into truvity/ritueel and
// truvity/sluis. A word has one owner, who changes it; the other repository copies the file after the
// owner's change has merged. This check keeps the copy in this repository honest, with no network:
//
//   - the file in docs/ equals the pinned copy of the other repository's file, byte for byte
//     (third_party/ritueel/shared-terms.yaml);
//   - the pinned copy has the sha256 that third_party/ritueel/PIN records, and the PIN names the source
//     repository and a commit of it (`pending` until ritueel has merged its copy);
//   - the file's own shape: schema 1, unique terms, an owner (ritueel or sluis), a status (decided or
//     proposed), `not` lines as strings, and `see` only as absolute https URLs on ritueel.id or sluis.id,
//     never a repository path, because the file lives in two repositories;
//   - the glossary: every shared term is in docs/glossary.yaml with `shared: true` and exactly the shared
//     definition, and every glossary term with `shared: true` is a shared term.
//
// Whether ritueel's main has moved on is not this check's: it never fetches. Bumping the pin is a change of
// the two files third_party/ritueel/ and, when the owner's wording changed, docs/shared-terms.yaml together.
//
// Needs the `yaml` package of site/ (`just site-install`).
//
// usage: tools/checks/shared-terms.mjs [repo-root]
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { reporter, repoRoot } from './lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const { parse } = createRequire(join(here, '..', '..', 'site', 'package.json'))('yaml');

const root = repoRoot();
const { error, finish } = reporter('check-shared-terms');

const SHARED = 'docs/shared-terms.yaml';
const COPY = 'third_party/ritueel/shared-terms.yaml';
const PIN = 'third_party/ritueel/PIN';
const GLOSSARY = 'docs/glossary.yaml';
const OWNERS = ['ritueel', 'sluis'];
const STATUSES = ['decided', 'proposed'];
const FIELDS = ['term', 'definition', 'owner', 'status', 'not', 'see'];

const bytes = (rel) => (existsSync(join(root, rel)) ? readFileSync(join(root, rel)) : null);
const mine = bytes(SHARED);
const copy = bytes(COPY);
const pin = bytes(PIN);
for (const [rel, b] of [[SHARED, mine], [COPY, copy], [PIN, pin]]) if (!b) error(`${rel} is missing`);
if (!mine || !copy || !pin) finish(0, 'shared terms');

// ---- the pin and the vendored copy
const pinned = {};
for (const [i, line] of pin.toString('utf8').split('\n').entries()) {
  if (!line.trim() || line.startsWith('#')) continue;
  const m = /^(source|commit|sha256): (\S+)$/.exec(line);
  if (!m) { error(`${PIN}:${i + 1}: expected "source: ...", "commit: ..." or "sha256: ..."`); continue; }
  if (m[1] in pinned) error(`${PIN}:${i + 1}: ${m[1]} is given twice`);
  pinned[m[1]] = m[2];
}
for (const k of ['source', 'commit', 'sha256']) if (!(k in pinned)) error(`${PIN}: ${k} is missing`);
if (pinned.source !== undefined && pinned.source !== 'truvity/ritueel') error(`${PIN}: source must be truvity/ritueel`);
if (pinned.commit !== undefined && !/^(pending|[0-9a-f]{40})$/.test(pinned.commit)) error(`${PIN}: commit must be "pending" or a full 40-digit commit id of ${pinned.source ?? 'the source'}`);
if (pinned.sha256 !== undefined && !/^[0-9a-f]{64}$/.test(pinned.sha256)) error(`${PIN}: sha256 must be 64 lower-case hexadecimal digits`);
const digest = createHash('sha256').update(copy).digest('hex');
if (pinned.sha256 && pinned.sha256 !== digest) error(`${COPY}: its sha256 is ${digest}, but ${PIN} pins ${pinned.sha256}`);
if (!mine.equals(copy)) {
  const a = mine.toString('utf8').split('\n');
  const b = copy.toString('utf8').split('\n');
  const at = a.findIndex((l, i) => l !== b[i]);
  const where = at === -1 ? `one ends at line ${Math.min(a.length, b.length)}` : `first difference at line ${at + 1}`;
  error(`${SHARED} differs from the pinned copy ${COPY} (${mine.length} and ${copy.length} bytes; ${where}); both repositories must hold the same bytes`);
}

// ---- the shape of the file
let doc;
try { doc = parse(mine.toString('utf8')); } catch (e) { error(`${SHARED}: not valid YAML: ${e.message}`); }
const terms = Array.isArray(doc?.terms) ? doc.terms : [];
if (doc) {
  if (doc.schema !== 1) error(`${SHARED}: schema must be 1`);
  for (const k of Object.keys(doc)) if (!['schema', 'terms'].includes(k)) error(`${SHARED}: unknown top-level key ${k}`);
}
const seen = new Set();
for (const [i, t] of terms.entries()) {
  const at = `${SHARED}: terms[${i}]${t?.term ? ` (${t.term})` : ''}`;
  if (!t || typeof t.term !== 'string' || !t.term) { error(`${at}: term is missing`); continue; }
  if (seen.has(t.term.toLowerCase())) error(`${at}: the term is listed twice`);
  seen.add(t.term.toLowerCase());
  for (const k of Object.keys(t)) if (!FIELDS.includes(k)) error(`${at}: unknown field ${k}`);
  if (typeof t.definition !== 'string' || !t.definition) error(`${at}: definition is missing`);
  if (!OWNERS.includes(t.owner)) error(`${at}: owner must be one of ${OWNERS.join(', ')}`);
  if (!STATUSES.includes(t.status)) error(`${at}: status must be one of ${STATUSES.join(', ')}`);
  if ('not' in t && !(Array.isArray(t.not) && t.not.length && t.not.every((s) => typeof s === 'string' && s))) error(`${at}: not must be a non-empty list of strings`);
  if ('see' in t) {
    if (!(Array.isArray(t.see) && t.see.length && t.see.every((s) => typeof s === 'string'))) error(`${at}: see must be a non-empty list of strings`);
    else for (const u of t.see) if (!/^https:\/\/(ritueel|sluis)\.id\/\S*$/.test(u)) error(`${at}: see "${u}" must be an absolute URL on ritueel.id or sluis.id, not a repository path`);
  }
}

// ---- the glossary
let gl;
try { gl = parse(readFileSync(join(root, GLOSSARY), 'utf8')); } catch (e) { error(`${GLOSSARY}: cannot be read: ${e.message}`); }
const glTerms = new Map((Array.isArray(gl?.terms) ? gl.terms : []).map((t) => [t.term, t]));
for (const t of terms) {
  const g = glTerms.get(t.term);
  if (!g) { error(`${GLOSSARY}: has no term "${t.term}" of ${SHARED}`); continue; }
  if (g.shared !== true) error(`${GLOSSARY}: "${t.term}" is a shared term and must have shared: true`);
  if (g.definition !== t.definition) error(`${GLOSSARY}: the definition of "${t.term}" differs from ${SHARED}; change the owner's word in ${SHARED} and copy it, never edit it here`);
}
for (const [term, g] of glTerms) if (g.shared === true && !seen.has(term.toLowerCase())) error(`${GLOSSARY}: "${term}" has shared: true, but ${SHARED} has no such term`);

finish(terms.length, 'shared terms');
