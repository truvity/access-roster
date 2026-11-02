// The repository facts the build publishes as /data/repo.json (ADR 0020): the decision
// records with their status and proposal issue, the requirements with the issues that
// deliver them, and the coverage figure. They change only by a merged pull request.
// The shape is public/data/repo.schema.json; site/scripts/check-repo-json.mjs validates
// the built file against it. Bump `schema` when a field is removed or changes meaning.
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { decisionFacts, listDecisions } from '../lib-decisions';
import { autoVerifiable, catalogue, coverage } from './requirements';

export const REPO_SCHEMA = 1;

export async function repoFacts(builtAt: string) {
  const decisions = (await listDecisions()).map(decisionFacts);
  const c = catalogue();
  return {
    $schema: 'https://sluis.id/data/repo.schema.json',
    schema: REPO_SCHEMA,
    builtAt,
    source: { decisions: 'docs/decisions/NNNN-*.md', requirements: 'docs/requirements/*.yaml' },
    decisions,
    requirements: c.reqs.map((r) => ({ id: r.id, area: r.area, level: r.level, status: r.status, issues: r.issues ?? [], auto: autoVerifiable(r) })),
    coverage: coverage(),
  };
}

// One build time for every page and endpoint of a build.
export const BUILT_AT = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

// How much of sluis v2 exists as design and how much as code, counted at the build so the
// home page and /status/ turn by themselves when code arrives. The design is the decision
// records and the live requirements. The code is what git tracks as source outside the
// docs and outside the tooling of the site and of the repository checks (site/, tools/,
// .github/, .claude/), which are not sluis; test files are counted apart.
// The build runs in site/ (as src/lib/requirements.ts assumes), so the repository is its parent.
const REPO_ROOT = `${resolve(process.cwd(), '..')}/`;
const CODE_EXT = /\.(go|rs|c|h|cc|cpp|hpp|proto|py|java|kt|swift|zig|js|jsx|ts|tsx|mjs|cjs|sh|sql|nix)$/;
const NOT_SLUIS = /^(docs|site|tools|\.github|\.claude|\.git)\//;
const TEST_FILE = /(_test\.[a-z]+|\.test\.[a-z]+|\.spec\.[a-z]+|(^|\/)test_[^/]*\.py|(^|\/)tests?\/)/;

// The tracked files; a checkout with no git (a source archive) is walked instead.
function trackedFiles(): string[] {
  try {
    return execFileSync('git', ['ls-files', '-z'], { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
      .split('\0')
      .filter(Boolean);
  } catch {
    const out: string[] = [];
    const walk = (rel: string) => {
      for (const e of readdirSync(REPO_ROOT + rel, { withFileTypes: true })) {
        if (e.name === '.git' || e.name === 'node_modules' || e.name === 'dist') continue;
        if (e.isDirectory()) walk(`${rel}${e.name}/`);
        else if (e.isFile()) out.push(rel + e.name);
      }
    };
    walk('');
    return out;
  }
}

export function codeFacts() {
  const files = trackedFiles();
  if (files.length === 0) throw new Error('codeFacts: no tracked file found, so there is nothing to count');
  const source = files.filter((f) => CODE_EXT.test(f) && !NOT_SLUIS.test(f));
  const tests = source.filter((f) => TEST_FILE.test(f));
  const lines = source
    .filter((f) => !TEST_FILE.test(f))
    .reduce((n, f) => n + (readFileSync(REPO_ROOT + f, 'utf8').match(/\n/g)?.length ?? 0), 0);
  return { lines, testFiles: tests.length };
}

// "Design: 56 decision records, 211 requirements. Code: 0 lines. Tests: none."
export async function designLine() {
  const records = (await listDecisions()).length;
  const requirements = coverage().all.requirements;
  const { lines, testFiles } = codeFacts();
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
  return `Design: ${plural(records, 'decision record', 'decision records')}, ${plural(requirements, 'requirement', 'requirements')}. `
    + `Code: ${plural(lines, 'line', 'lines')}. Tests: ${testFiles === 0 ? 'none' : plural(testFiles, 'file', 'files')}.`;
}
