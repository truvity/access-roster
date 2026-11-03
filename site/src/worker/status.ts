// The live status documents in KV (ADR 0014), and the view the status API and the status
// page's live block make of them.
//
// - `board`: the project board and the latest workflow run of each workflow on `main`,
//   refreshed by the cron and by GitHub webhooks (refresh below).
// - `ci`: the coverage and conformance summaries that CI runs on `main` post to /api/ci.
//
// The Free plan allows 1,000 KV writes a day. A refresh writes only when the content changed,
// or when the stored copy is more than an hour old (so its "as of" time stays honest), and
// each document stops writing for the rest of the UTC day at its own cap. The two caps add
// up to well under the limit.
import { readBoard, type Board } from '../lib/board.ts';
import { groupStatus, type Group, type RepoLike } from '../lib/status-groups.ts';
import { installationToken, mainRuns, USER_AGENT, type AppSecrets, type Run } from './github.ts';

// The part of a KV namespace binding the Worker uses.
export interface KV {
  get<T>(key: string, type: 'json'): Promise<T | null>;
  put(key: string, value: string): Promise<void>;
}

export interface Env extends AppSecrets {
  STATUS: KV;
  ASSETS: { fetch(request: Request | string): Promise<Response> };
  GITHUB_WEBHOOK_SECRET?: string;
}

export const BOARD_KEY = 'board';
export const CI_KEY = 'ci';
export const BOARD_WRITE_CAP = 800;
export const CI_WRITE_CAP = 100;
const HEARTBEAT_MS = 60 * 60_000;

interface Writes { day: string; n: number }
export interface BoardDoc {
  schema: 1;
  checkedAt: string;
  changedAt: string;
  hash: string;
  writes: Writes;
  runsEtag: string | null;
  board: Board;
  runs: Run[] | null;
}
export interface Summary { sha: string; run: string; workflow: string; at: string }
export interface CiDoc {
  schema: 1;
  writes: Writes;
  coverage: ({ percent: number } & Summary) | null;
  conformance: ({ passing: number; total: number } & Summary) | null;
}

const isoNow = (now: number) => new Date(now).toISOString().replace(/\.\d{3}Z$/, 'Z');
const dayOf = (now: number) => new Date(now).toISOString().slice(0, 10);
const writesToday = (w: Writes | undefined, now: number) => (w && w.day === dayOf(now) ? w.n : 0);

export async function sha256(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  return [...d].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Whether a refresh that produced `hash` must write, and why. Pure, for the tests.
export function writeDecision(prev: Pick<BoardDoc, 'hash' | 'checkedAt' | 'writes'> | null, hash: string, now: number):
  'first' | 'changed' | 'heartbeat' | 'unchanged' | 'over budget' {
  const why = !prev ? 'first' : prev.hash !== hash ? 'changed' : now - Date.parse(prev.checkedAt) > HEARTBEAT_MS ? 'heartbeat' : 'unchanged';
  if (why === 'unchanged') return why;
  return writesToday(prev?.writes, now) >= BOARD_WRITE_CAP ? 'over budget' : why;
}

// Read the board and the runs on `main` from GitHub, and write the document if it must.
// Returns one line for the log; never throws, and never logs a secret.
export async function refresh(env: Env, cause: string, now = Date.now()): Promise<string> {
  try {
    const prev = await env.STATUS.get<BoardDoc>(BOARD_KEY, 'json');
    const token = await installationToken(env);
    const board = await readBoard(token, USER_AGENT);
    let runs = prev?.runs ?? null;
    let runsEtag = prev?.runsEtag ?? null;
    try {
      const r = await mainRuns(token, prev?.runs ? runsEtag : null);
      if (r.runs) {
        runs = r.runs;
        runsEtag = r.etag;
      }
    } catch (e) {
      console.log(`status refresh (${cause}): workflow runs not read: ${e instanceof Error ? e.message : e}`);
    }
    const hash = await sha256(JSON.stringify({ board, runs }));
    const decision = writeDecision(prev, hash, now);
    if (decision === 'unchanged' || decision === 'over budget') return `status refresh (${cause}): ${decision}`;
    const doc: BoardDoc = {
      schema: 1,
      checkedAt: isoNow(now),
      changedAt: decision === 'heartbeat' && prev ? prev.changedAt : isoNow(now),
      hash,
      writes: { day: dayOf(now), n: writesToday(prev?.writes, now) + 1 },
      runsEtag,
      board,
      runs,
    };
    await env.STATUS.put(BOARD_KEY, JSON.stringify(doc));
    return `status refresh (${cause}): wrote (${decision}, ${board.issues.length} issues, write ${doc.writes.n} today)`;
  } catch (e) {
    return `status refresh (${cause}): failed: ${e instanceof Error ? e.message : e}`;
  }
}

// A CI summary, checked. Returns the parts to store, or the reason it is refused.
export function parseSummary(body: unknown): { coverage?: { percent: number }; conformance?: { passing: number; total: number } } | string {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'the body is not a JSON object';
  const b = body as Record<string, any>;
  const extra = Object.keys(b).filter((k) => k !== 'coverage' && k !== 'conformance');
  if (extra.length) return `unknown keys: ${extra.join(', ')}`;
  const out: { coverage?: { percent: number }; conformance?: { passing: number; total: number } } = {};
  if (b.coverage !== undefined) {
    const p = b.coverage?.percent;
    if (typeof p !== 'number' || !Number.isFinite(p) || p < 0 || p > 100) return 'coverage.percent must be a number from 0 to 100';
    out.coverage = { percent: Math.round(p * 10) / 10 };
  }
  if (b.conformance !== undefined) {
    const { passing, total } = b.conformance ?? {};
    if (!Number.isInteger(passing) || !Number.isInteger(total) || passing < 0 || total < passing) {
      return 'conformance must be { passing, total }, whole numbers with 0 <= passing <= total';
    }
    out.conformance = { passing, total };
  }
  if (!out.coverage && !out.conformance) return 'nothing to store: give coverage, conformance or both';
  return out;
}

export async function storeSummary(env: Env, parts: Exclude<ReturnType<typeof parseSummary>, string>, from: Omit<Summary, 'at'>, now = Date.now()):
  Promise<'stored' | 'over budget'> {
  const prev = await env.STATUS.get<CiDoc>(CI_KEY, 'json');
  const n = writesToday(prev?.writes, now);
  if (n >= CI_WRITE_CAP) return 'over budget';
  const meta = { ...from, at: isoNow(now) };
  const doc: CiDoc = {
    schema: 1,
    writes: { day: dayOf(now), n: n + 1 },
    coverage: parts.coverage ? { ...parts.coverage, ...meta } : prev?.coverage ?? null,
    conformance: parts.conformance ? { ...parts.conformance, ...meta } : prev?.conformance ?? null,
  };
  await env.STATUS.put(CI_KEY, JSON.stringify(doc));
  return 'stored';
}

export interface Live {
  asOf: string;
  changedAt: string;
  repoBuiltAt: string;
  options: string[];
  groups: Group[];
  runs: Run[] | null;
  coverage: CiDoc['coverage'];
  conformance: CiDoc['conformance'];
}

// The live view: the board in KV joined with the /data/repo.json of this deployment, read
// from the static assets (no Worker request, no KV read). Null when KV holds no board yet.
export async function liveStatus(env: Env, base: string): Promise<Live | null> {
  const [doc, ci] = await Promise.all([env.STATUS.get<BoardDoc>(BOARD_KEY, 'json'), env.STATUS.get<CiDoc>(CI_KEY, 'json')]);
  if (!doc) return null;
  const res = await env.ASSETS.fetch(new Request(new URL('/data/repo.json', base)));
  if (!res.ok) throw new Error(`the static assets answered HTTP ${res.status} for /data/repo.json`);
  const repo = (await res.json()) as RepoLike & { builtAt: string };
  return {
    asOf: doc.checkedAt,
    changedAt: doc.changedAt,
    repoBuiltAt: repo.builtAt,
    options: doc.board.options,
    groups: groupStatus(doc.board, repo),
    runs: doc.runs,
    coverage: ci?.coverage ?? null,
    conformance: ci?.conformance ?? null,
  };
}

// The JSON of /api/status: the groups without the records the page links, and the checks.
export function statusJson(live: Live) {
  const issue = ({ number, title, labels }: { number: number; title: string; labels: string[] }) => ({ number, title, labels });
  return {
    schema: 1,
    asOf: live.asOf,
    changedAt: live.changedAt,
    repoBuiltAt: live.repoBuiltAt,
    source: { project: 'https://github.com/orgs/truvity/projects/9', field: 'Product milestone', repo: 'https://sluis.id/data/repo.json' },
    milestones: live.groups.map((g) => ({
      name: g.name,
      milestone: g.milestone,
      current: g.current,
      issues: g.issues,
      requirements: g.reqs,
      decisions: { accepted: g.adrs.accepted, proposed: g.adrs.proposed, toWrite: g.adrs.toWrite },
      openIssues: [...g.openDecisionIssues, ...g.otherOpenIssues].sort((a, b) => a.number - b.number).map(issue),
    })),
    ci: { main: live.runs },
    coverage: live.coverage,
    conformance: live.conformance,
  };
}
