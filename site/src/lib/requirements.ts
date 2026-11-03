// Reads the requirements catalogue in ../docs/requirements at build time (the YAML is the
// source of truth; site/scripts/check-requirements.mjs validates it before the build).
// The pages under src/pages/requirements/ and the requirements.json endpoint share this module.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse } from 'yaml';

export interface StandardRef { id: string; section?: string; depth: 'Full' | 'Partial' }
export interface Verification { kind: 'conformance-suite' | 'test-vectors' | 'integration-test' | 'manual'; ref: string; suite?: string }
export interface Req {
  id: string; area: string; split_from?: string; statement: string; rationale: string;
  level: 'MUST' | 'SHOULD' | 'MAY'; source: string; status: string; runtimes: 'all' | string[];
  standards: StandardRef[]; features: ('parity' | 'design')[]; issues?: number[]; tests?: string[]; verification: Verification[]; actors?: string[];
  gap?: string; manual_reason?: string; superseded_by?: string[]; moved_to?: string;
}
export interface Area { code: string; title: string; file: string; reqs: Req[] }
export interface Standard { id: string; name: string; group: string; register: boolean; url?: string }

export const ISSUES = 'https://github.com/truvity/sluis/issues/';
export const SOURCE = 'https://github.com/truvity/sluis/blob/main/docs/requirements/';

export const KIND_LABEL: Record<string, string> = {
  'conformance-suite': 'conformance suite',
  'test-vectors': 'test vectors',
  'integration-test': 'integration test',
  manual: 'manual review',
};
export const STATUS_HINT: Record<string, string> = {
  done: 'Implemented, and the named tests pass.',
  planned: 'Covered by an agreed feature or design.',
  partial: 'The plan is weaker than the requirement.',
  open: 'Needs a decision or has no plan.',
  'out-of-scope': 'A boundary kept as a refusal.',
  withdrawn: 'A tombstone; see the superseding record, or the product it moved to.',
};

const dir = resolve(process.cwd(), '../docs/requirements');
const read = (name: string) => parse(readFileSync(resolve(dir, name), 'utf8'));

export interface Catalogue {
  title: string; checked: string; gaps: Record<string, string>;
  vocabulary: { level: string[]; source: string[]; status: string[]; runtimes: string[]; verification: string[]; depth: string[] };
  areas: Area[]; areaByCode: Map<string, Area>; reqs: Req[]; byId: Map<string, Req>;
  standards: Standard[]; standardById: Map<string, Standard>;
}

let cached: Catalogue | undefined;
export function catalogue(): Catalogue {
  if (cached) return cached;
  const { catalogue: c } = read('index.yaml');
  const areas: Area[] = Object.entries<{ title: string; file: string }>(c.areas).map(([code, a]) => {
    // features is optional in the YAML (issue numbers live in issues); the pages and requirements.json always see a list.
    const reqs: Req[] = read(a.file).requirements.map((r: Req) => ({ ...r, features: r.features ?? [] }));
    return { code, title: a.title, file: a.file, reqs };
  });
  const reqs = areas.flatMap((a) => a.reqs);
  const standards: Standard[] = read('standards.yaml').standards;
  cached = {
    title: c.title, checked: c.checked, gaps: c.gaps, vocabulary: c.vocabulary,
    areas, areaByCode: new Map(areas.map((a) => [a.code, a])), reqs, byId: new Map(reqs.map((r) => [r.id, r])),
    standards, standardById: new Map(standards.map((s) => [s.id, s])),
  };
  return cached;
}

export const areaPath = (code: string) => `/requirements/${code.toLowerCase()}/`;
export const reqPath = (r: Req) => `${areaPath(r.area)}#${r.id}`;
// The issues that deliver a record (`issues`), linked at build time; no live state is fetched.
export const issueUrl = (n: number) => `${ISSUES}${n}`;
export const runtimesOf = (r: Req) => (r.runtimes === 'all' ? 'all' : r.runtimes.join(' '));

export function count<T>(items: T[], key: (t: T) => string | string[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const it of items) for (const k of [key(it)].flat()) m.set(k, (m.get(k) ?? 0) + 1);
  return m;
}
export const hasKind = (r: Req, ...kinds: string[]) => r.verification.some((v) => kinds.includes(v.kind));

// What test tools read: every record flattened, with the facts the pages derive.
export function exportJson() {
  const c = catalogue();
  return {
    schema: 1,
    title: c.title,
    checked: c.checked,
    source: 'docs/requirements/*.yaml',
    counts: {
      requirements: c.reqs.length,
      level: Object.fromEntries(count(c.reqs, (r) => r.level)),
      status: Object.fromEntries(count(c.reqs, (r) => r.status)),
      source: Object.fromEntries(count(c.reqs, (r) => r.source)),
    },
    areas: c.areas.map((a) => ({ code: a.code, title: a.title, requirements: a.reqs.length })),
    standards: c.standards,
    requirements: c.reqs.map((r) => ({ ...r, url: `https://sluis.id${reqPath(r)}` })),
  };
}

// The coverage figure of docs/standards/conformance.md: the share of requirements that are not
// withdrawn, and of their MUSTs, whose verification includes an external suite or a vector set.
// site/scripts/check-requirements.mjs computes the same figure for the page's generated block,
// and site/scripts/check-repo-json.mjs checks that /data/repo.json and the page agree.
export function coverage() {
  const external = (r: Req) => hasKind(r, 'conformance-suite', 'test-vectors');
  const live = catalogue().reqs.filter((r) => r.status !== 'withdrawn');
  const musts = live.filter((r) => r.level === 'MUST');
  const share = (a: number, b: number) => (b === 0 ? 0 : Number(((100 * a) / b).toFixed(1)));
  const all = { requirements: live.length, externallyChecked: live.filter(external).length };
  const must = { requirements: musts.length, externallyChecked: musts.filter(external).length };
  return {
    all: { ...all, share: share(all.externallyChecked, all.requirements) },
    must: { ...must, share: share(must.externallyChecked, must.requirements) },
  };
}

// A record that something other than a person can verify: a suite, vectors or an integration test.
export const autoVerifiable = (r: Req) => r.verification.some((v) => v.kind !== 'manual');
