#!/usr/bin/env node
// /data/repo.json in the built site (ADR 0014), checked against what it is built from:
//   - it validates against site/public/data/repo.schema.json, and the built site serves
//     the same schema at /data/repo.schema.json;
//   - its decisions are exactly the records in docs/decisions (NNNN-*.md, not the
//     template), each with the status and date of its own header lines;
//   - its requirements are exactly the records of /requirements.json, with the same
//     area, level, status and issues, and `auto` true exactly when a verification is not manual;
//   - its coverage equals the generated block on docs/standards/conformance.md.
// Fails closed: no file, no record or no requirement is a failure.
//
// usage: site/scripts/check-repo-json.mjs [dist]   (dist relative to the repository root, default site/dist)
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const dist = resolve(root, process.argv[2] ?? 'site/dist');
const errors = [];
const E = (m) => errors.push(m);
const readJson = (f) => JSON.parse(readFileSync(f, 'utf8'));

const schemaFile = join(root, 'site', 'public', 'data', 'repo.schema.json');
const schema = readJson(schemaFile);
const file = join(dist, 'data', 'repo.json');
if (!existsSync(file)) {
  console.error(`check-repo-json: no ${file}`);
  process.exit(1);
}
const repo = readJson(file);

// ---- the JSON Schema subset repo.schema.json uses (the same subset as check-requirements.mjs)
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
  if (type === 'number' && node.minimum !== undefined && value < node.minimum) out.push(`${path}: less than ${node.minimum}`);
  if (type === 'string') {
    if (node.minLength !== undefined && value.length < node.minLength) out.push(`${path}: shorter than ${node.minLength} characters`);
    if (node.pattern && !new RegExp(node.pattern).test(value)) out.push(`${path}: ${JSON.stringify(value.slice(0, 60))} does not match ${node.pattern}`);
  }
  if (type === 'array') {
    if (node.minItems !== undefined && value.length < node.minItems) out.push(`${path}: fewer than ${node.minItems} items`);
    if (node.uniqueItems && new Set(value.map((v) => JSON.stringify(v))).size !== value.length) out.push(`${path}: items are not unique`);
    if (node.items) value.forEach((v, i) => validate(node.items, v, `${path}/${i}`, out));
  }
  if (type === 'object') {
    for (const k of node.required ?? []) if (!(k in value)) out.push(`${path}: missing ${k}`);
    const props = node.properties ?? {};
    for (const [k, v] of Object.entries(value)) {
      if (k in props) validate(props[k], v, `${path}/${k}`, out);
      else if (node.additionalProperties === false) out.push(`${path}: unknown key ${k}`);
    }
  }
}
const out = [];
validate(schema, repo, '', out);
out.forEach((m) => E(`schema ${m || '/'}`));
const served = join(dist, 'data', 'repo.schema.json');
if (!existsSync(served) || readFileSync(served, 'utf8') !== readFileSync(schemaFile, 'utf8')) E('/data/repo.schema.json is not served, or differs from site/public/data/repo.schema.json');

// ---- decisions: the records on disk
const decDir = join(root, 'docs', 'decisions');
const records = readdirSync(decDir).filter((f) => /^\d{4}-.+\.md$/.test(f) && f !== '0000-template.md').sort();
if (!records.length) E('no decision records in docs/decisions');
const got = (repo.decisions ?? []).map((d) => d.id);
const want = records.map((f) => f.replace(/\.md$/, ''));
if (JSON.stringify(got) !== JSON.stringify(want)) E(`decisions: repo.json has ${got.length} records, docs/decisions has ${want.length}, or the order differs`);
if (got.includes('0000-template')) E('decisions: repo.json lists the template');
for (const d of repo.decisions ?? []) {
  const f = join(decDir, `${d.id}.md`);
  if (!existsSync(f)) continue;
  const text = readFileSync(f, 'utf8');
  const status = /^\*\*Status:\*\*\s*(.+?)\s*$/m.exec(text)?.[1];
  const date = /^\*\*Date:\*\*\s*(.+?)\s*$/m.exec(text)?.[1] ?? null;
  const proposal = /Proposal:\s*\[issue #(\d+)\]/.exec(text)?.[1];
  if (d.status !== status) E(`decisions: ${d.id} says "${d.status}", the record says "${status}"`);
  if (d.date !== date) E(`decisions: ${d.id} date ${d.date}, the record says ${date}`);
  if (d.proposal !== (proposal ? Number(proposal) : null)) E(`decisions: ${d.id} proposal ${d.proposal}, the record links ${proposal ?? 'none'}`);
}

// ---- requirements: the same records as /requirements.json
const reqFile = join(dist, 'requirements.json');
if (!existsSync(reqFile)) E('no requirements.json in the built site');
else {
  const full = readJson(reqFile).requirements;
  const mine = repo.requirements ?? [];
  if (!full.length) E('requirements.json holds no requirement');
  if (full.length !== mine.length) E(`requirements: repo.json has ${mine.length}, requirements.json ${full.length}`);
  full.forEach((r, i) => {
    const m = mine[i];
    const same = m && m.id === r.id && m.area === r.area && m.level === r.level && m.status === r.status &&
      JSON.stringify(m.issues) === JSON.stringify(r.issues ?? []) &&
      m.auto === (r.verification ?? []).some((v) => v.kind !== 'manual');
    if (!same) E(`requirements: entry ${i} (${r.id}) differs from requirements.json`);
  });
}

// ---- coverage: the conformance page's generated block
const page = readFileSync(join(root, 'docs', 'standards', 'conformance.md'), 'utf8');
const rowOf = (label) => {
  const m = new RegExp(`^\\| ${label} \\((\\d+)\\) \\| (\\d+) \\| ([\\d.]+)% \\|$`, 'm').exec(page);
  return m ? { requirements: Number(m[1]), externallyChecked: Number(m[2]), share: Number(m[3]) } : null;
};
for (const [key, label] of [['all', 'All, not withdrawn'], ['must', 'MUST']]) {
  const want = rowOf(label);
  if (!want) E(`coverage: no "${label}" row in the coverage block of docs/standards/conformance.md`);
  else if (JSON.stringify(repo.coverage?.[key]) !== JSON.stringify(want)) {
    E(`coverage: repo.json ${key} ${JSON.stringify(repo.coverage?.[key])}, the conformance page ${JSON.stringify(want)}`);
  }
}

if (errors.length) {
  for (const m of errors) console.error(`check-repo-json: ${m}`);
  process.exit(1);
}
console.log(`check-repo-json: ok (${repo.decisions.length} decision records, ${repo.requirements.length} requirements, coverage ${repo.coverage.all.share}%)`);
