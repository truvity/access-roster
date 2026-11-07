#!/usr/bin/env node
// No tracked text file holds a committed merge conflict marker: a line that starts with seven `<` or seven `>` and a
// space (git's own marker lines of a conflict, the ours-side opener and the theirs-side closer). A cherry-pick or a
// rebase that was committed half-resolved leaves them, and a file that still parses (a CHANGELOG, a Markdown page) passes
// every job that only reads it. The `=======` line is not looked for: it is a legitimate Markdown underline.
//
// The marker strings are built here and not written out, so that this file does not hold a line that the check refuses.
//
// usage: tools/checks/conflict-markers.mjs [repo-root]
import { lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { reporter, repoRoot, trackedFiles } from './lib.mjs';

const OPEN = '<'.repeat(7) + ' ';
const CLOSE = '>'.repeat(7) + ' ';
const MAX_BYTES = 8 << 20;

const root = repoRoot();
const r = reporter('check-conflict-markers');
let files = 0;
for (const path of trackedFiles(root)) {
  let st;
  try {
    st = lstatSync(join(root, path));
  } catch {
    continue; // listed and deleted in the working tree: nothing to read
  }
  if (!st.isFile() || st.size === 0 || st.size > MAX_BYTES) continue; // a symlink or a submodule is not text
  const buf = readFileSync(join(root, path));
  if (buf.subarray(0, 8192).includes(0)) continue; // binary
  files++;
  const lines = buf.toString('utf8').split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith(OPEN) || lines[i].startsWith(CLOSE)) {
      r.error(`${path}:${i + 1}: a committed conflict marker (${lines[i].slice(0, 40)})`);
    }
  }
}
r.finish(files, 'tracked text files');
