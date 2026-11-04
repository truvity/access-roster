// The evidence of the requirements, read at build time: the tests that carry `verifies: REQ-...`
// (site/scripts/collect-evidence.mjs scans actors/, cli/, drivers/, kits/, tests/ and tools/) and the
// attestations of docs/requirements/attestations.yaml. The same data the lint (check-requirements.mjs) judges.
// The build runs in site/ (as src/lib/requirements.ts assumes), so the repository is its parent.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse } from 'yaml';
import { collectEvidence } from '../../scripts/collect-evidence.mjs';

export type Evidence = { file: string; line: number; test: string } | { attestation: { by: string; on: string; checked: string } };

let cached: Map<string, Evidence[]> | undefined;
export function evidenceMap(): Map<string, Evidence[]> {
  if (cached) return cached;
  const root = resolve(process.cwd(), '..');
  const found = collectEvidence(root);
  if (found.files === 0) throw new Error('evidence: no Go test file or Rust file was scanned, so there is nothing to count');
  const map = new Map<string, Evidence[]>();
  for (const [id, list] of found.evidence) map.set(id, list.map(({ file, line, test }) => ({ file, line, test })));
  const att = parse(readFileSync(resolve(root, 'docs/requirements/attestations.yaml'), 'utf8'))?.attestations ?? [];
  for (const a of att as { req: string; by: string; on: string; checked: string }[]) {
    (map.get(a.req) ?? map.set(a.req, []).get(a.req)!).push({ attestation: { by: a.by, on: a.on, checked: a.checked } });
  }
  cached = map;
  return map;
}
