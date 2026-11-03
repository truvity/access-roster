#!/usr/bin/env node
// Lint for the requirements catalogue in docs/requirements/ (index.yaml, standards.yaml and one
// <area>.yaml per area). The rules are the ones in the catalogue's design notes (L1 to L17):
//
//   L1  every file validates against requirements.schema.json (closed objects, enums, patterns)
//   L2  every area has its file and every file is declared; ids are unique; the id prefix equals the area
//   L3  the vocabularies in index.yaml equal the schema's enums
//   L5  split_from exists, is in the same area and is not itself a split clause
//   L6  a statement has exactly one RFC 2119 keyword, `level` equals its class, one sentence
//   L7  a rationale is one sentence
//   L8  no two statements are equal after normalising case and punctuation
//   L10 public safety: no ticket key, e-mail address, URL outside .example, or term of the private
//       deny-list (PUBLIC_CONTENT_DENYLIST, see below). Account-id-shaped numbers and tokens are
//       left to tools/checks/public-content.mjs (`just check-public`), which scans every tracked
//       file, these included, with one set of placeholders
//   L11 every MUST has a verification
//   L12 a MUST verified by manual review only has manual_reason; manual_reason is forbidden elsewhere
//   L13 every cited standard is a row of standards.yaml; a Full citation has a section (warning)
//   L14 a planned record links an issue (issues) or a feature entry (parity or design)
//   L15 an open or partial record names a declared gap key; gap is allowed on no other status
//   L16 a standard that no requirement cites (warning)
//   L17 an out-of-scope record is a MUST NOT or a MAY and has a verification
//   L18 a done record names its evidence: `tests` lists repository paths, each a file that exists
//       inside the repository and that names the record's id (a test carries its id in its name)
//   L19 an area with `retired: true` in index.yaml has only withdrawn records; it keeps its file and its ids
//   ISS a planned or partial record links the issues that deliver it (one warning with the count;
//       the summary line gives the count per area). The schema checks the numbers themselves.
//   COV the coverage figures on docs/standards/conformance.md equal the catalogue: the share of
//       requirements (not withdrawn), and of MUSTs, whose verification includes an external suite
//       or a vector set (`conformance-suite` or `test-vectors`). --write-coverage rewrites the block.
//
// No dependency beyond `yaml`: the JSON Schema subset the schema uses is checked by the small
// validator below. Errors fail the run; warnings print and do not, unless --strict is given.
//
// usage: site/scripts/check-requirements.mjs [--strict] [--write-coverage] [dir]   (dir defaults to docs/requirements)
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const args = process.argv.slice(2);
const strict = args.includes('--strict');
const writeCoverage = args.includes('--write-coverage');
const dir = resolve(args.find((a) => !a.startsWith('--')) ?? join(root, 'docs', 'requirements'));
const repoDir = resolve(dir, '..', '..'); // the repository the catalogue sits in: the `tests` paths are relative to it

// ---- public safety: patterns, not names. A hit is an error; the data must not need an exception.
// A ticket key is LETTERS-DIGITS; the prefixes below are standards, algorithms and the catalogue's own ids.
const NOT_TICKET = new Set([
  'REQ', 'OD', 'ST', 'NC', 'SU', 'RFC', 'BCP', 'FIPS', 'SP', 'ISO', 'IEC', 'UTF', 'SHA', 'AES', 'RSA', 'ES', 'PS', 'RS', 'HS',
  'EC', 'ECDSA', 'EDDSA', 'ED', 'X', 'TLS', 'SSL', 'IPV', 'HTTP', 'SHA3', 'P', 'SECP', 'WCAG', 'AAL', 'IAL', 'FAL', 'CVE',
  'CWE', 'EN', 'TS', 'ETSI', 'NIST', 'PKCS', 'SEC', 'BLAKE', 'ML', 'KEM', 'DSA', 'SLH', 'SHAKE', 'HMAC', 'GCM', 'CBC', 'ECB',
  'CTR', 'SSH', 'DNS', 'UUID', 'COSE', 'JWT', 'JWS', 'JWE', 'JWK', 'OAUTH', 'OIDC', 'FIDO', 'FIDO2', 'UTC', 'RS256', 'ES256',
]);
const DENY = [
  [/[\w.+-]+@[\w-]+(\.[\w-]+)+/, 'e-mail address'],
];
// The private deny-list: the environment variable PUBLIC_CONTENT_DENYLIST (a repository secret)
// holds one term per line; empty lines and lines starting with # are ignored. A term matches
// case-insensitively when no letter or digit touches it. A hit names the record, never the term
// or the text. Without the variable this part is skipped, and the run says so.
const denyTerms = (process.env.PUBLIC_CONTENT_DENYLIST ?? '')
  .split(/\r?\n/).map((t) => t.trim()).filter((t) => t && !t.startsWith('#'));
const PRIVATE = denyTerms.length
  ? new RegExp(`(?<![\\p{L}\\p{N}])(?:${denyTerms.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})(?![\\p{L}\\p{N}])`, 'iu')
  : null;
const denied = new Set(); // one error per record or file
console.log(PRIVATE ? 'check-requirements: private deny-list loaded' : 'private deny-list not available, skipped');
const TICKET = /(?<!REQ-)\b([A-Z][A-Z0-9]{1,9})-(\d{1,6})\b/g;
const URLISH = /https?:\/\/(?![a-z0-9.-]*\.example\b)/i;

const errors = [];
const warnings = [];
const E = (m) => errors.push(m);
const W = (m) => warnings.push(m);
const unlinkedByArea = new Map(); // ISS: area -> planned or partial records without issues

const load = (name) => parse(readFileSync(join(dir, name), 'utf8'));
const schema = JSON.parse(readFileSync(join(dir, 'requirements.schema.json'), 'utf8'));

// ---- the JSON Schema subset the schema file uses
function validate(node, value, path, out) {
  if (node.$ref) {
    const target = node.$ref.replace(/^#\//, '').split('/').reduce((n, k) => n?.[k], schema);
    if (!target) return out.push(`${path}: unknown $ref ${node.$ref}`);
    return validate(target, value, path, out);
  }
  const type = Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value;
  if ('const' in node && value !== node.const) return out.push(`${path}: must be ${JSON.stringify(node.const)}`);
  if (node.enum && !node.enum.includes(value)) return out.push(`${path}: ${JSON.stringify(value)} is not one of ${node.enum.join(', ')}`);
  if (node.oneOf) {
    const hits = node.oneOf.filter((n) => { const o = []; validate(n, value, path, o); return o.length === 0; });
    if (hits.length !== 1) out.push(`${path}: matches ${hits.length} of the allowed shapes, expected exactly one`);
    return;
  }
  if (node.type) {
    const ok = node.type === 'integer' ? Number.isInteger(value) : node.type === type;
    if (!ok) return out.push(`${path}: expected ${node.type}, got ${type}`);
  }
  if (type === 'number') {
    if (node.minimum !== undefined && value < node.minimum) out.push(`${path}: less than ${node.minimum}`);
  }
  if (type === 'string') {
    if (node.minLength !== undefined && value.length < node.minLength) out.push(`${path}: shorter than ${node.minLength} characters`);
    if (node.maxLength !== undefined && value.length > node.maxLength) out.push(`${path}: longer than ${node.maxLength} characters`);
    if (node.pattern && !new RegExp(node.pattern).test(value)) out.push(`${path}: ${JSON.stringify(value.slice(0, 60))} does not match ${node.pattern}`);
  }
  if (type === 'array') {
    if (node.minItems !== undefined && value.length < node.minItems) out.push(`${path}: fewer than ${node.minItems} items`);
    if (node.maxItems !== undefined && value.length > node.maxItems) out.push(`${path}: more than ${node.maxItems} items`);
    if (node.uniqueItems && new Set(value.map((v) => JSON.stringify(v))).size !== value.length) out.push(`${path}: items are not unique`);
    if (node.items) value.forEach((v, i) => validate(node.items, v, `${path}/${i}`, out));
  }
  if (type === 'object') {
    for (const k of node.required ?? []) if (!(k in value)) out.push(`${path}: missing ${k}`);
    const props = node.properties ?? {};
    for (const [k, v] of Object.entries(value)) {
      if (node.propertyNames) validate(node.propertyNames, k, `${path}/${k} (name)`, out);
      if (k in props) validate(props[k], v, `${path}/${k}`, out);
      else if (node.additionalProperties === false) out.push(`${path}: unknown key ${k}`);
      else if (node.additionalProperties && typeof node.additionalProperties === 'object') validate(node.additionalProperties, v, `${path}/${k}`, out);
    }
  }
}

// ---- load
const files = new Map();
const index = load('index.yaml');
files.set('index.yaml', index);
for (const name of readdirSync(dir).filter((f) => f.endsWith('.yaml')).sort()) {
  if (name !== 'index.yaml' && name !== 'standards.yaml') files.set(name, load(name));
}
const standardsDoc = load('standards.yaml');

// L1
for (const [name, doc] of files) {
  const out = [];
  validate(schema.$defs[name === 'index.yaml' ? 'indexFile' : 'areaFile'], doc, '', out);
  out.forEach((m) => E(`L1 ${name}${m}`));
}
if (!Array.isArray(standardsDoc?.standards) || standardsDoc.standards.length === 0) E('L1 standards.yaml: no standards list');
for (const s of standardsDoc?.standards ?? []) {
  if (!/^(ST|NC)-\d{2,3}$/.test(s.id ?? '') || !s.name || typeof s.register !== 'boolean') E(`L1 standards.yaml: bad row ${JSON.stringify(s)}`);
}
if (errors.length) finish(0);

const cat = index.catalogue;
const register = new Map(standardsDoc.standards.map((s) => [s.id, s]));
if (register.size !== standardsDoc.standards.length) E('L1 standards.yaml: duplicate id');

// L3
const enumOf = (def) => schema.$defs[def].enum;
for (const [key, def] of [['level', 'level'], ['source', 'source'], ['status', 'status'], ['runtimes', 'runtime'], ['verification', 'verificationKind'], ['depth', 'depth']]) {
  if (JSON.stringify(cat.vocabulary[key]) !== JSON.stringify(enumOf(def))) E(`L3 index.yaml: vocabulary ${key} differs from the schema`);
}

// L2
const reqs = [];
const byId = new Map();
const declared = new Set(Object.values(cat.areas).map((a) => a.file));
for (const [code, a] of Object.entries(cat.areas)) {
  if (a.file !== `${code.toLowerCase()}.yaml`) E(`L2 area ${code}: its file must be ${code.toLowerCase()}.yaml`);
  const doc = files.get(a.file);
  if (!doc) E(`L2 area ${code}: file ${a.file} is missing`);
  else if (doc.area !== code) E(`L2 ${a.file}: area is ${doc.area}, expected ${code}`);
}
for (const [name, doc] of files) {
  if (name === 'index.yaml') continue;
  if (!declared.has(name)) E(`L2 ${name}: not declared in index.yaml`);
  for (const r of doc.requirements) {
    if (r.area !== doc.area) E(`L2 ${r.id}: area ${r.area} differs from its file (${doc.area})`);
    if (r.id.split('-')[1] !== r.area) E(`L2 ${r.id}: the id prefix does not equal the area ${r.area}`);
    if (byId.has(r.id)) E(`L2 ${r.id}: duplicate id`);
    byId.set(r.id, r);
    reqs.push(r);
  }
}

// L19: a retired area keeps its file and its ids and has only withdrawn records
for (const [code, a] of Object.entries(cat.areas)) {
  if (!a.retired) continue;
  const live = (files.get(a.file)?.requirements ?? []).filter((r) => r.status !== 'withdrawn');
  if (live.length) E(`L19 area ${code}: retired, but ${live.length} record(s) are not withdrawn (${live.slice(0, 3).map((r) => r.id).join(', ')})`);
}

// ---- per-record rules
const KW = /\b(MUST NOT|MUST|SHOULD NOT|SHOULD|MAY)\b/g;
const strings = (v, out = []) => {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => strings(x, out));
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => strings(x, out));
  return out;
};
const seen = new Map();
const cited = new Map();
for (const r of reqs) {
  const i = r.id;
  const ks = r.statement.match(KW) ?? [];
  if (ks.length !== 1) E(`L6 ${i}: the statement has ${ks.length} RFC 2119 keywords, expected exactly one`);
  else {
    const cls = ks[0].startsWith('MUST') ? 'MUST' : ks[0].startsWith('SHOULD') ? 'SHOULD' : 'MAY';
    if (cls !== r.level) E(`L6 ${i}: level ${r.level} does not match the keyword ${ks[0]}`);
  }
  if (/\.\s+[A-Z]/.test(r.statement)) E(`L6 ${i}: the statement is more than one sentence`);
  if (/\.\s+[A-Z]/.test(r.rationale)) E(`L7 ${i}: the rationale is more than one sentence`);
  const norm = r.statement.toLowerCase().replace(/\W+/g, ' ');
  if (seen.has(norm)) E(`L8 ${i}: the same statement as ${seen.get(norm)}`);
  seen.set(norm, i);

  if (r.split_from) {
    const parent = byId.get(r.split_from);
    if (!parent) E(`L5 ${i}: split_from ${r.split_from} does not exist`);
    else {
      if (parent.split_from) E(`L5 ${i}: split_from ${r.split_from} is itself a split clause`);
      if (parent.area !== r.area) E(`L5 ${i}: split_from ${r.split_from} is in another area`);
    }
  }

  // L10
  // The free text of a record; ids, enums and standard references are not prose.
  for (const text of [r.statement, r.rationale, r.manual_reason ?? '', ...r.verification.map((v) => v.ref), ...(r.tests ?? [])]) {
    for (const [rx, what] of DENY) if (rx.test(text)) E(`L10 ${i}: ${what} in ${JSON.stringify(text.slice(0, 60))}`);
    if (PRIVATE?.test(text) && !denied.has(i)) { denied.add(i); E(`L10 ${i}: matches a deny-listed term`); }
    if (URLISH.test(text)) E(`L10 ${i}: a URL that is not under .example`);
    for (const m of text.matchAll(TICKET)) if (!NOT_TICKET.has(m[1])) E(`L10 ${i}: ticket-key shaped text ${m[0]}`);
  }

  const ver = r.verification;
  const live = r.status !== 'withdrawn';
  if (r.level === 'MUST' && live && ver.length === 0) E(`L11 ${i}: a MUST without a verification`);
  const manualOnly = ver.length > 0 && ver.every((v) => v.kind === 'manual');
  if (r.level === 'MUST' && manualOnly && !r.manual_reason) E(`L12 ${i}: a MUST verified by manual review only needs manual_reason`);
  if (r.manual_reason && !manualOnly) E(`L12 ${i}: manual_reason is set but the record has an automated verification`);

  for (const s of r.standards) {
    (cited.get(s.id) ?? cited.set(s.id, []).get(s.id)).push(i);
    if (!register.has(s.id)) E(`L13 ${i}: standard ${s.id} is not a row of standards.yaml`);
    if (s.depth === 'Full' && !s.section) W(`L13 ${i}: standard ${s.id} has depth Full but no section`);
  }
  checkTests(r);
  if (r.status === 'planned' && !r.issues?.length && !r.features?.length) E(`L14 ${i}: a planned record needs issues, or features parity or design`);
  if ((r.status === 'open' || r.status === 'partial') && !r.gap) E(`L15 ${i}: an ${r.status} record needs a gap key`);
  if (r.gap) {
    if (!(r.gap in cat.gaps)) E(`L15 ${i}: gap key ${r.gap} is not declared in index.yaml`);
    if (r.status !== 'open' && r.status !== 'partial') E(`L15 ${i}: gap is set on a ${r.status} record`);
  }
  if (r.status === 'out-of-scope') {
    if (!(r.level === 'MAY' || r.statement.includes('MUST NOT'))) E(`L17 ${i}: an out-of-scope record must be a MUST NOT or a MAY`);
    if (ver.length === 0) E(`L17 ${i}: an out-of-scope record needs a verification`);
  }
  if (r.status === 'withdrawn' && !r.superseded_by?.length && !r.moved_to) E(`L4 ${i}: a withdrawn record needs superseded_by or moved_to`);
  if (r.moved_to && r.status !== 'withdrawn') E(`L4 ${i}: moved_to is set on a ${r.status} record`);
  for (const s of r.superseded_by ?? []) if (!byId.has(s)) E(`L4 ${i}: superseded_by ${s} does not exist`);
  if (r.superseded_by && r.status !== 'withdrawn') E(`L4 ${i}: superseded_by is set on a ${r.status} record`);
}

// L18: the evidence of a done record. A test file that was named but does not hold the id proves nothing.
function checkTests(r) {
  if (r.status === 'done' && !r.tests?.length) E(`L18 ${r.id}: a done record needs tests, the repository paths of its passing tests`);
  for (const t of r.tests ?? []) {
    const file = resolve(repoDir, t);
    if (t.split('/').includes('..') || !file.startsWith(repoDir + sep)) { E(`L18 ${r.id}: tests path ${t} leaves the repository`); continue; }
    let text;
    try {
      if (!statSync(file).isFile()) throw new Error('not a file');
      text = readFileSync(file, 'utf8');
    } catch { E(`L18 ${r.id}: tests path ${t} is not a file in the repository`); continue; }
    if (!text.includes(r.id)) E(`L18 ${r.id}: tests path ${t} does not name ${r.id}`);
  }
}

// the index and the register carry text too
for (const [where, doc] of [['index.yaml', index], ['standards.yaml', standardsDoc]]) {
  for (const text of strings(where === 'index.yaml' ? doc : standardsDoc.standards.map((s) => [s.id, s.name, s.group]))) {
    for (const [rx, what] of DENY) if (rx.test(text)) E(`L10 ${where}: ${what} in ${JSON.stringify(text.slice(0, 60))}`);
    if (PRIVATE?.test(text) && !denied.has(where)) { denied.add(where); E(`L10 ${where}: matches a deny-listed term`); }
    if (where === 'index.yaml' && URLISH.test(text)) E(`L10 ${where}: a URL that is not under .example`);
  }
}

// L16
for (const s of standardsDoc.standards) {
  if (!cited.has(s.id) && s.register) W(`L16 standard ${s.id} (${s.name}) is a register row that no requirement cites`);
}

// ISS: one warning for the whole catalogue, not one per record, while the links are filled in.
const unlinked = reqs.filter((r) => (r.status === 'planned' || r.status === 'partial') && !r.issues?.length);
for (const r of unlinked) unlinkedByArea.set(r.area, (unlinkedByArea.get(r.area) ?? 0) + 1);
if (unlinked.length) W(`ISS ${unlinked.length} planned or partial requirements link no delivering issue (issues)`);

// COV
const coverage = computeCoverage(reqs);
checkCoverage(coverage);

finish(reqs.length);

// The share of requirements whose verification includes an external suite or vector set.
function computeCoverage(all) {
  const EXTERNAL = new Set(['conformance-suite', 'test-vectors']);
  const live = all.filter((r) => r.status !== 'withdrawn');
  const external = (r) => r.verification.some((v) => EXTERNAL.has(v.kind));
  const musts = live.filter((r) => r.level === 'MUST');
  return {
    total: live.length,
    external: live.filter(external).length,
    musts: musts.length,
    mustsExternal: musts.filter(external).length,
  };
}

// The generated block between the coverage markers of the conformance page. Only the default
// catalogue has a page; a run against another directory computes the figures and checks nothing.
function checkCoverage(c) {
  const share = (a, b) => (b === 0 ? '0.0' : ((100 * a) / b).toFixed(1));
  const body = [
    '| Requirements | Externally checked | Share |',
    '|---|---|---|',
    `| All, not withdrawn (${c.total}) | ${c.external} | ${share(c.external, c.total)}% |`,
    `| MUST (${c.musts}) | ${c.mustsExternal} | ${share(c.mustsExternal, c.musts)}% |`,
  ].join('\n');
  console.log(`check-requirements: coverage ${c.external}/${c.total} (${share(c.external, c.total)}%), MUST ${c.mustsExternal}/${c.musts} (${share(c.mustsExternal, c.musts)}%)`);
  if (dir !== join(root, 'docs', 'requirements')) return;
  const page = join(root, 'docs', 'standards', 'conformance.md');
  const text = readFileSync(page, 'utf8');
  const m = /(<!-- coverage:begin[^>]*-->\n)([\s\S]*?)(<!-- coverage:end -->)/.exec(text);
  if (!m) return E(`COV ${relative(root, page)}: no coverage:begin / coverage:end markers`);
  const want = `${body}\n`;
  if (m[2] === want) return;
  if (!writeCoverage) return E(`COV ${relative(root, page)}: the coverage block is stale; run site/scripts/check-requirements.mjs --write-coverage`);
  writeFileSync(page, text.slice(0, m.index) + m[1] + want + m[3] + text.slice(m.index + m[0].length));
  console.log(`check-requirements: wrote the coverage block of ${relative(root, page)}`);
}

function finish(n) {
  const perArea = unlinkedByArea.size === 0 ? '' : `; without issues: ${[...unlinkedByArea].map(([a, k]) => `${a} ${k}`).join(', ')}`;
  for (const m of warnings) console.warn(`warning: ${m}`);
  for (const m of errors) console.error(`error: ${m}`);
  const rel = relative(root, dir);
  if (errors.length || (strict && warnings.length)) {
    console.error(`check-requirements: ${errors.length} errors, ${warnings.length} warnings in ${rel}${perArea}`);
    process.exit(1);
  }
  if (n === 0) {
    console.error('check-requirements: no requirement was checked; an empty sweep proves nothing');
    process.exit(1);
  }
  console.log(`check-requirements: ${n} requirements in ${files.size - 1} areas, ${warnings.length} warnings, no errors${perArea}`);
  process.exit(0);
}
