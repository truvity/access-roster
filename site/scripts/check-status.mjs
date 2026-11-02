#!/usr/bin/env node
// Page-status lint: every page under docs/ must carry `status: target |
// partial | page | shipped` in its front matter, and every `:::note[Proposed]` aside
// must link the open issue that tracks the point
// (https://github.com/truvity/sluis/issues/N): a decided point is plain prose,
// and a proposal with no issue has no one to decide it (docs/contributing/pages.md,
// "Asides"). The retired `Open decision` aside is refused.
// The ADRs in docs/decisions/ are not pages of the site and are not linted here. Nor is docs/requirements/ (see check-requirements.mjs).
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const STATUSES = ['target', 'partial', 'page', 'shipped'];
const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const docs = join(root, 'docs');
const ISSUE = /https:\/\/github\.com\/truvity\/(?:sluis|ritueel)\/issues\/\d+/;

function* walk(dir) {
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (path === join(docs, 'decisions') || path === join(docs, 'requirements')) continue;
      yield* walk(path);
    } else if (/\.(md|mdx)$/.test(name) && !name.startsWith('_')) {
      yield path;
    }
  }
}

function frontMatter(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---(\r?\n|$)/.exec(text);
  return m ? m[1] : null;
}

// The value of a top-level `status:` key on one line, unquoted.
function status(fm) {
  const m = /^status:[ \t]*(.*)$/m.exec(fm);
  return m ? m[1].trim().replace(/^(["'])(.*)\1$/, '$2') : undefined;
}

// The asides outside code fences: { line, kind, title, body }.
function* asides(text) {
  let fence = null;
  let open = null;
  for (const [i, line] of text.split('\n').entries()) {
    const f = /^\s*(`{3,}|~{3,})/.exec(line);
    if (f) {
      if (fence === null) fence = f[1][0];
      else if (f[1][0] === fence) fence = null;
      if (open) open.body.push(line);
      continue;
    }
    if (fence !== null) {
      if (open) open.body.push(line);
      continue;
    }
    const start = /^\s*:{3,}\s*(note|tip|caution|danger)(?:\[([^\]]*)\])?/.exec(line);
    if (start && !open) {
      open = { line: i + 1, kind: start[1], title: start[2] ?? '', body: [] };
      continue;
    }
    if (open && /^\s*:{3,}\s*$/.test(line)) {
      yield { ...open, body: open.body.join('\n') };
      open = null;
      continue;
    }
    if (open) open.body.push(line);
  }
  if (open) yield { ...open, body: open.body.join('\n'), unclosed: true };
}

let failures = 0;
let checked = 0;
let proposed = 0;
for (const file of walk(docs)) {
  const rel = relative(root, file);
  const text = readFileSync(file, 'utf8');
  const fm = frontMatter(text);
  const problems = [];
  if (fm === null) problems.push('no front matter');
  else {
    const s = status(fm);
    if (s === undefined) problems.push(`no status, want one of ${STATUSES.join(', ')}`);
    else if (!STATUSES.includes(s)) problems.push(`status "${s}", want one of ${STATUSES.join(', ')}`);
  }
  for (const a of asides(text)) {
    if (a.unclosed) problems.push(`line ${a.line}: the aside is never closed`);
    if (/^Open decision\b/i.test(a.title)) problems.push(`line ${a.line}: "${a.title}": open-decision asides are retired; write the point as plain prose, or as a Proposed note that links its issue`);
    if (a.kind === 'note' && /^Proposed$/i.test(a.title.trim())) {
      proposed++;
      if (!ISSUE.test(a.body)) problems.push(`line ${a.line}: a Proposed note must link the open issue that tracks it`);
    }
  }
  if (/\]\(\/open-decisions\//.test(text)) problems.push('links /open-decisions/, which is retired');
  checked++;
  for (const p of problems) {
    failures++;
    console.error(`${rel}: ${p}`);
  }
}

if (checked === 0) {
  console.error(`check-status: no pages found under ${relative(root, docs)}; an empty sweep proves nothing`);
  process.exit(1);
}
if (failures > 0) {
  console.error(`check-status: ${failures} problems in ${checked} pages`);
  process.exit(1);
}
console.log(`check-status: ${checked} pages with a valid status, ${proposed} Proposed notes, each with its issue`);
