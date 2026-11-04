#!/usr/bin/env node
// The evidence collector for the requirements catalogue (docs/requirements/README.md, "How a test names a
// requirement"). It scans the source trees for tests that carry a requirement id and writes the map
//
//   REQ id -> [{file, line, test, via}]
//
// The tag is one rule for Go and for Rust: the id follows `verifies:` in the comment block directly above
// the test,
//
//   // verifies: REQ-AUTHN-002                    (Go: above `func TestXxx`)
//   /// verifies: REQ-AUTHN-002, REQ-AUTHN-003    (Rust: above `#[test]`, `#[tokio::test]`, ...)
//
// and a Go sub-test whose name starts with the id counts as the same tag on that line:
//
//   t.Run("REQ-AUTHN-002/plain_method", func(t *testing.T) { ... })
//
// An id that is only mentioned (in a comment inside a body, in an assertion message, in a doc of a function that is
// not a test) is not a tag. A test with no tag is ignored.
//
// usage: site/scripts/collect-evidence.mjs [--root dir] [--out file]
//   --root  the repository (default: the one this script sits in)
//   --out   write the JSON there instead of standard output
// Exit 1 when no test file was scanned: an empty sweep proves nothing.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

// The source trees that hold tests. Files elsewhere (docs, site, the generated code) are not scanned.
export const SCAN_DIRS = ['actors', 'cli', 'drivers', 'kits', 'tests', 'tools'];
const SKIP_DIRS = new Set(['node_modules', 'target', 'dist', '.git', 'testdata']);

const ID = 'REQ-[A-Z][A-Z0-9]{1,11}-[0-9]{3}';
// `verifies:` then one id or a list of them (comma, "and" or space between), in one line.
const TAG = new RegExp(`\\bverifies:\\s*(${ID}(?:(?:\\s*,\\s*|\\s+and\\s+|\\s+)${ID})*)`, 'g');
const SUBTEST = new RegExp(`\\bt\\.Run\\(\\s*"(${ID})(?:[/\\s"])`);
const GO_TEST = /^func\s+((?:Test|Fuzz)(?:[^a-z(\s]\w*)?)\s*\(/;
const RUST_TEST_ATTR = /^\s*#\[(?:[A-Za-z_]\w*::)*(?:test|test_case|rstest)\b/;
const RUST_FN = /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)/;

export const idsIn = (text) => {
  const out = [];
  for (const m of text.matchAll(TAG)) out.push(...m[1].match(new RegExp(ID, 'g')));
  return out;
};

// The comment lines (and attributes, for Rust) directly above line `i`, no blank line between.
function blockAbove(lines, i, isLine) {
  const out = [];
  for (let k = i - 1; k >= 0 && isLine(lines[k]); k--) out.unshift(lines[k]);
  return out;
}

export function scanGo(text, file) {
  const lines = text.split('\n');
  const found = [];
  let current = null; // the test function the scan is in
  lines.forEach((line, i) => {
    const t = GO_TEST.exec(line);
    if (t) {
      current = t[1];
      if (current === 'TestMain') { current = null; return; }
      const doc = blockAbove(lines, i, (l) => /^\s*\/\//.test(l)).join('\n');
      for (const id of idsIn(doc)) found.push({ id, file, line: i + 1, test: current, via: 'comment' });
    } else if (/^func\s/.test(line)) current = null;
    const s = SUBTEST.exec(line);
    if (s && current) {
      const name = /t\.Run\(\s*"([^"]*)"/.exec(line)[1];
      found.push({ id: s[1], file, line: i + 1, test: `${current}/${name}`, via: 'subtest' });
    }
  });
  return found;
}

export function scanRust(text, file) {
  const lines = text.split('\n');
  const found = [];
  const seen = new Set(); // one test function with two test attributes is one test
  lines.forEach((line, i) => {
    if (!RUST_TEST_ATTR.test(line)) return;
    let j = i + 1;
    while (j < lines.length && /^\s*(#\[|\/\/)/.test(lines[j])) j++;
    const fn = RUST_FN.exec(lines[j] ?? '');
    if (!fn || seen.has(j)) return;
    seen.add(j);
    const above = blockAbove(lines, i, (l) => /^\s*(\/\/|#\[)/.test(l));
    const between = lines.slice(i + 1, j);
    const doc = [...above, ...between].filter((l) => /^\s*\/\//.test(l)).join('\n');
    for (const id of idsIn(doc)) found.push({ id, file, line: j + 1, test: fn[1], via: 'comment' });
  });
  return found;
}

function* walk(dir) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) yield* walk(join(dir, e.name)); }
    else if (e.isFile() && (e.name.endsWith('_test.go') || e.name.endsWith('.rs'))) yield join(dir, e.name);
  }
}

// The tagged tests of a repository: {files, tests, evidence: Map<id, [{file, line, test, via}]>}.
// `files` is the number of Go test files and Rust files looked at; `tests` the number of tags found.
export function collectEvidence(repoRoot) {
  const root = resolve(repoRoot);
  const evidence = new Map();
  let files = 0;
  let tests = 0;
  for (const top of SCAN_DIRS) {
    for (const path of walk(join(root, top))) {
      files++;
      const file = relative(root, path).split(sep).join('/');
      const text = readFileSync(path, 'utf8');
      for (const { id, ...rest } of path.endsWith('.go') ? scanGo(text, file) : scanRust(text, file)) {
        (evidence.get(id) ?? evidence.set(id, []).get(id)).push(rest);
        tests++;
      }
    }
  }
  return { files, tests, evidence };
}

export function toJson({ files, tests, evidence }) {
  return {
    schema: 1,
    scanned: { files, tags: tests },
    evidence: Object.fromEntries([...evidence].sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([id, list]) => [id, list.map((e) => ({ file: e.file, line: e.line, test: e.test }))])),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opt = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
  const root = opt('--root') ?? join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const result = collectEvidence(root);
  if (result.files === 0) {
    console.error('collect-evidence: no Go test file or Rust file was scanned; an empty sweep proves nothing');
    process.exit(1);
  }
  const json = `${JSON.stringify(toJson(result), null, 2)}\n`;
  const out = opt('--out');
  if (out) writeFileSync(out, json);
  else process.stdout.write(json);
  console.error(`collect-evidence: ${result.tests} tags for ${result.evidence.size} requirements in ${result.files} files`);
}
