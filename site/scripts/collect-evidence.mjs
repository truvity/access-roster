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
// and a Go case name that starts with the id and a slash counts as the same tag on that line, in exactly three places
// inside a test function (not after it ends, and never in a message or a log line): the first argument of t.Run, the key
// of a map of cases, and a `name:` field of a table of cases:
//
//   t.Run("REQ-AUTHN-002/plain_method", func(t *testing.T) { ... })
//   "REQ-AUTHN-002/plain method": {...},
//   {name: "REQ-AUTHN-002/plain method", ...},
//
// A test that CI does not run is no evidence: Rust `#[ignore]` and a `#[cfg(...)]` other than cfg(test) (on the test or
// on its module), a Go file whose build constraint is not satisfied by the tags CI runs with (sluis_test), and a Go test
// whose first statement is an unconditional t.Skip. A test that only a smoke program (tests/e2e, a main with
// harness = false) exercises is not a #[test] or a func TestXxx(t *testing.T), so it has no tag form at all.
//
// An older spelling is read too, so that no test has to be renamed: a Go test function named
// `TestREQ_AUTHN_002_...` verifies REQ-AUTHN-002.
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
// A tag is a whole comment line: `verifies:` then one id or a list of them (comma, "and" or space between). A comment
// that only says "no longer verifies: ..." in the middle of a sentence is not a tag.
const TAG = new RegExp(`^\\s*//[/]?\\s*verifies:\\s*(${ID}(?:(?:\\s*,\\s*|\\s+and\\s+|\\s+)${ID})*)`);
const FUNC_NAME = new RegExp(`^Test(REQ_[A-Z][A-Z0-9]{1,11}_[0-9]{3})(?:_|$)`);
// A Go test: `func TestXxx(t *testing.T)`. The name after Test does not start with a lower-case letter.
const GO_TEST = /^func\s+(Test(?:[^a-z(\s]\w*)?)\s*\(\s*(\w+)\s+\*testing\.T\s*\)/gm;
const RUN_CASE = new RegExp(`\\.Run\\(\\s*"(${ID})/([^"]*)"`, 'g'); // the first argument of t.Run
const TABLE_KEY = new RegExp(`(?:^|[{,])\\s*"(${ID})/([^"]*)"\\s*:`, 'gm'); // the key of a map of cases
const TABLE_NAME = new RegExp(`\\bname:\\s*"(${ID})/([^"]*)"`, 'g'); // the name: field of a struct of cases
const RUST_TEST_ATTR = /^#\[\s*(?:[A-Za-z_]\w*::)*(?:test|test_case|rstest)\b/;
const RUST_IGNORE = /^#\[\s*ignore\b/;
const RUST_CFG = /^#\[\s*cfg\s*\(([\s\S]*)\)\s*\]\s*$/;
const RUST_FN = /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)/;
const RUST_MOD = /^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{?/;

// The build tags CI runs Go tests with (`go test -tags sluis_test`, the Justfile), and the platform it runs on. A file
// constrained by any other tag (sluis_card, ignore, ...) is not run, so its tests are no evidence.
const GO_TAGS_TRUE = new Set(['sluis_test', 'linux', 'unix', 'gc']);
const GO_OTHER_OS = /_(?:windows|darwin|freebsd|netbsd|openbsd|plan9|js|wasip1|solaris|aix|android|ios|illumos|dragonfly)_test\.go$/;

export const idsIn = (text) => {
  const out = [];
  for (const line of text.split('\n')) {
    const m = TAG.exec(line);
    if (m) out.push(...m[1].match(new RegExp(ID, 'g')));
  }
  return out;
};

// The comment lines (and attributes, for Rust) directly above line `i`, no blank line between.
function blockAbove(lines, i, isLine) {
  const out = [];
  for (let k = i - 1; k >= 0 && isLine(lines[k]); k--) out.unshift(lines[k]);
  return out;
}

// `text` with the comments blanked (and the contents of strings and runes too, when `strings`), same length and same
// newlines, so an index into it is an index into `text`.
function mask(text, { strings, lang }) {
  const out = text.split('');
  const n = text.length;
  const blank = (a, b) => { for (let k = a; k < b; k++) if (out[k] !== '\n') out[k] = ' '; };
  let i = 0;
  while (i < n) {
    const c = text[i];
    const d = text[i + 1];
    if (c === '/' && d === '/') { let j = text.indexOf('\n', i); if (j < 0) j = n; blank(i, j); i = j; }
    else if (c === '/' && d === '*') { let j = text.indexOf('*/', i + 2); j = j < 0 ? n : j + 2; blank(i, j); i = j; }
    else if (c === '"') {
      let j = i + 1;
      while (j < n && text[j] !== '"' && (lang === 'rust' || text[j] !== '\n')) { if (text[j] === '\\') j++; j++; }
      if (strings) blank(i + 1, j);
      i = j + 1;
    } else if (c === '`' && lang === 'go') {
      let j = text.indexOf('`', i + 1); if (j < 0) j = n;
      if (strings) blank(i + 1, j);
      i = j + 1;
    } else if (c === 'r' && lang === 'rust' && /^r#*"/.test(text.slice(i, i + 12)) && !/\w/.test(text[i - 1] ?? ' ')) {
      const hashes = /^r(#*)"/.exec(text.slice(i, i + 12))[1];
      const open = i + 2 + hashes.length;
      let j = text.indexOf(`"${hashes}`, open); if (j < 0) j = n;
      blank(open, j);
      i = j + 1 + hashes.length;
    } else if (c === "'") {
      // a rune (Go) or char (Rust) literal; a Rust lifetime has no closing quote
      if (text[i + 1] === '\\') { const j = text.indexOf("'", i + 3); if (j > 0 && j - i < 12) { blank(i + 1, j); i = j + 1; } else i++; }
      else if (text[i + 2] === "'") { blank(i + 1, i + 2); i += 3; }
      else i++;
    } else i++;
  }
  return out.join('');
}

// The index of the brace that closes the one at `open`, in text whose comments and strings are blanked.
function closeOf(masked, open) {
  let depth = 0;
  for (let k = open; k < masked.length; k++) {
    if (masked[k] === '{') depth++;
    else if (masked[k] === '}' && --depth === 0) return k;
  }
  return masked.length;
}

// A Go build constraint: `//go:build` lines before the package clause, evaluated with GO_TAGS_TRUE.
function evalBuild(expr) {
  const toks = expr.match(/&&|\|\||!|\(|\)|[A-Za-z0-9_.]+/g) ?? [];
  let p = 0;
  const atom = () => {
    if (toks[p] === '!') { p++; return !atom(); }
    if (toks[p] === '(') { p++; const v = or(); p++; return v; }
    const id = toks[p++];
    return GO_TAGS_TRUE.has(id) || /^go1\.\d+$/.test(id);
  };
  const and = () => { let v = atom(); while (toks[p] === '&&') { p++; const r = atom(); v = v && r; } return v; };
  const or = () => { let v = and(); while (toks[p] === '||') { p++; const r = and(); v = v || r; } return v; };
  return or();
}
function goFileRuns(text, file) {
  if (GO_OTHER_OS.test(file)) return false;
  for (const line of text.split('\n')) {
    if (/^package\s/.test(line)) break;
    const m = /^\/\/go:build\s+(.+?)\s*$/.exec(line);
    if (m) return evalBuild(m[1]);
  }
  return true;
}

export function scanGo(text, file) {
  if (!goFileRuns(text, file)) return [];
  const lines = text.split('\n');
  const code = mask(text, { strings: true, lang: 'go' }); // for the structure
  const plain = mask(text, { strings: false, lang: 'go' }); // for the case names
  const lineOf = (idx) => text.slice(0, idx).split('\n').length;
  const found = [];
  for (const m of code.matchAll(GO_TEST)) {
    const [head, name, param] = m;
    if (name === 'TestMain') continue;
    const open = code.indexOf('{', m.index + head.length);
    if (open < 0) continue;
    const close = closeOf(code, open);
    // A test whose first statement is an unconditional skip runs nothing.
    if (new RegExp(`^${param}\\.(?:Skip|Skipf|SkipNow)\\b`).test(code.slice(open + 1, close).trimStart())) continue;
    const line = lineOf(m.index);
    const doc = blockAbove(lines, line - 1, (l) => /^\s*\/\//.test(l)).join('\n');
    for (const id of idsIn(doc)) found.push({ id, file, line, test: name, via: 'comment' });
    const named = FUNC_NAME.exec(name);
    if (named) found.push({ id: named[1].replaceAll('_', '-'), file, line, test: name, via: 'name' });
    const body = plain.slice(open + 1, close);
    for (const re of [RUN_CASE, TABLE_KEY, TABLE_NAME]) {
      for (const c of body.matchAll(re)) {
        const at = open + 1 + c.index + c[0].indexOf('"');
        found.push({ id: c[1], file, line: lineOf(at), test: `${name}/${c[1]}/${c[2]}`, via: 'subtest' });
      }
    }
  }
  return found;
}

export function scanRust(text, file) {
  const lines = text.split('\n');
  const code = mask(text, { strings: true, lang: 'rust' }).split('\n');
  const codeText = code.join('\n');
  const starts = [];
  lines.reduce((off, l) => { starts.push(off); return off + l.length + 1; }, 0);
  const lineAt = (idx) => starts.findLastIndex((s) => s <= idx);
  // An inner `#![cfg(...)]` other than cfg(test) leaves the whole file out of the build that runs the tests.
  for (const l of lines) {
    const m = /^#!\[\s*cfg\s*\((.*)\)\s*\]/.exec(l);
    if (m && m[1].trim() !== 'test') return [];
  }
  const found = [];
  let prefix = []; // the doc comments and attributes above the item
  let disabledUntil = -1;
  for (let i = 0; i < lines.length; i++) {
    if (i <= disabledUntil) continue;
    const line = lines[i];
    if (/^\s*\/\//.test(line)) { prefix.push({ doc: line }); continue; }
    if (/^\s*#\[/.test(line)) {
      // an attribute may span several lines: read to the closing bracket
      let attr = line.trim();
      let depth = 0;
      const delta = (t) => (t.match(/\[/g)?.length ?? 0) - (t.match(/\]/g)?.length ?? 0);
      depth = delta(attr);
      while (depth > 0 && i + 1 < lines.length) { i++; attr += ` ${lines[i].trim()}`; depth += delta(lines[i]); }
      prefix.push({ attr });
      continue;
    }
    if (line.trim() === '') { prefix = []; continue; }
    const attrs = prefix.filter((p) => p.attr).map((p) => p.attr);
    const cfgOff = attrs.some((a) => { const c = RUST_CFG.exec(a); return c && c[1].trim() !== 'test'; });
    if (RUST_MOD.test(line) && !RUST_FN.test(line)) {
      // a module behind a cfg other than cfg(test) is not in the build that runs the tests: skip its extent
      if (cfgOff || attrs.some((a) => RUST_IGNORE.test(a))) {
        const open = codeText.indexOf('{', starts[i]);
        if (open >= 0) disabledUntil = lineAt(closeOf(codeText, open));
      }
      prefix = [];
      continue;
    }
    const fn = RUST_FN.exec(line);
    if (fn && attrs.some((a) => RUST_TEST_ATTR.test(a)) && !cfgOff && !attrs.some((a) => RUST_IGNORE.test(a))) {
      const doc = prefix.filter((p) => p.doc).map((p) => p.doc).join('\n');
      for (const id of idsIn(doc)) found.push({ id, file, line: i + 1, test: fn[1], via: 'comment' });
    }
    prefix = [];
  }
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
