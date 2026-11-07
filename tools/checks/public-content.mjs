#!/usr/bin/env node
// Public content: this is a public repository, so no tracked file may carry a secret, a real
// account id or a private name.
//
// Generic part (the patterns are public, they name nothing; see GENERIC in lib.mjs):
//   - a 12-digit number shaped like an AWS account id, or one written 1234-5678-9012, other than
//     the documented placeholders (use 123456789012 in examples). Digits inside a UUID or inside
//     a long mixed base64 run are not account ids;
//   - a PEM private key block, an age secret key;
//   - a token with a well-known prefix: GitHub (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_),
//     AWS access key ids (AKIA, ASIA), Slack (xox?-), GitLab (glpat-), Google API keys (AIza),
//     Stripe live keys (sk_live_, rk_live_), npm (npm_), Vault (hvs.), and sk- secret keys
//     (the FIDO SSH key types sk-ssh-* and sk-ecdsa-* are not tokens).
//   A hit prints the file, the line and the kind, never the value.
//
// Private part: the terms of PUBLIC_CONTENT_DENYLIST (a repository secret; see denyList in
// lib.mjs), in each file's text and in each tracked path. A hit in a file prints the file and
// line and "matches a deny-listed term"; a hit in a path prints only the file's number in
// `git ls-files` order, since the path itself would show the term. Never the term or the line.
// Without the variable this part prints one line and is skipped, unless REQUIRE_DENYLIST=true.
//
// Every tracked text file is scanned. Symbolic links and binary files (a NUL byte in the first
// 8000 bytes) are not: images and other Git LFS objects are not scanned.
//
// Size and binaries: no tracked file is larger than MAX_BYTES, and none starts with the magic
// number of a compiled executable (ELF, Mach-O or PE). Source is text; a built binary was once
// committed by accident (15 MB, 2026-11-06), and git keeps it in every clone's history.
//
// usage: tools/checks/public-content.mjs [repo-root]
import { lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { denyList, genericHits, reporter, repoRoot, trackedFiles } from './lib.mjs';

const MAX_BYTES = 1 << 20;
const EXECUTABLE_MAGIC = [
  Buffer.from('\x7fELF'), // ELF
  Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), Buffer.from([0xce, 0xfa, 0xed, 0xfe]), // Mach-O, little endian
  Buffer.from([0xfe, 0xed, 0xfa, 0xcf]), Buffer.from([0xfe, 0xed, 0xfa, 0xce]), // Mach-O, big endian
  Buffer.from([0x4d, 0x5a, 0x90, 0x00]), // PE (MZ header)
];

const root = repoRoot();
const r = reporter('check-public');
const deny = denyList('check-public', r.error);

let scanned = 0;
trackedFiles(root).forEach((path, k) => {
  // A path with a term in it is never printed, not even for a hit in its text.
  const hidden = deny?.test(path);
  const label = hidden ? `file #${k + 1}` : path;
  if (hidden) r.error(`a tracked path matches a deny-listed term (${label})`);
  const abs = join(root, path);
  let st;
  try { st = lstatSync(abs); } catch { return; } // deleted in the working tree
  if (!st.isFile()) return;
  if (st.size > MAX_BYTES) r.error(`${label}: ${st.size} bytes, more than ${MAX_BYTES}; a large file is not kept in git`);
  const buf = readFileSync(abs);
  if (EXECUTABLE_MAGIC.some((m) => buf.subarray(0, m.length).equals(m))) {
    r.error(`${label}: a compiled executable (ELF, Mach-O or PE), not source`);
    return;
  }
  if (buf.subarray(0, 8000).includes(0)) return;
  scanned++;
  buf.toString('utf8').split('\n').forEach((line, i) => {
    for (const h of genericHits(line)) r.error(`${label}:${i + 1}:${h.col}: ${h.kind}`);
    if (deny?.test(line)) r.error(`${label}:${i + 1}: matches a deny-listed term`);
  });
});

r.finish(scanned, 'tracked text files');
