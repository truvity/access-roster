// The routes of the Worker (ADR 0014), all under /api/:
//
//   GET  /api/status        the live status as JSON (src/worker/status.ts)
//   GET  /api/status/live/  the status page's live block, an HTML fragment drawn by the
//                           renderer the build uses for the snapshot (src/lib/status-html.ts)
//   POST /api/hooks/github  a GitHub App webhook delivery: checks X-Hub-Signature-256, then
//                           refreshes the board in the background
//   POST /api/ci            a coverage or conformance summary from a CI run on `main`,
//                           authenticated by its GitHub Actions OIDC token
//
// The Worker runs first for /api/* only (wrangler.jsonc); every other path is a static asset.
import { statusBodyHtml } from '../lib/status-html.ts';
import { liveStatus, parseSummary, refresh, statusJson, storeSummary, BOARD_KEY, type BoardDoc, type Env } from './status.ts';
import { verifyOidc, verifyWebhook } from './verify.ts';

interface Ctx { waitUntil(p: Promise<unknown>): void }

// Response headers of every API answer. The _headers file applies to static assets only.
const BASE = {
  'x-content-type-options': 'nosniff',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
  'referrer-policy': 'strict-origin-when-cross-origin',
  'strict-transport-security': 'max-age=31536000',
};
// The status changes within seconds of a board edit; a minute in a browser or proxy is enough.
export const STATUS_CACHE = 'public, max-age=60';

export const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body, null, 1) + '\n', {
    status,
    headers: { ...BASE, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra },
  });

// The webhook events that can change the page. GitHub sends only the events the App
// subscribes to; anything else is acknowledged and ignored.
export const HOOK_EVENTS = new Set(['issues', 'label', 'projects_v2_item', 'workflow_run']);
const MAX_HOOK_BYTES = 1 << 20;
const MAX_CI_BYTES = 16 << 10;

// Whether a delivery concerns what the page shows: the sluis repository, the status board,
// or a workflow run on `main`.
export function hookMatters(event: string, payload: any, projectId: string | null): boolean {
  if (!HOOK_EVENTS.has(event)) return false;
  if (event === 'projects_v2_item') return !projectId || payload?.projects_v2_item?.project_node_id === projectId;
  if (payload?.repository && payload.repository.full_name !== 'truvity/sluis') return false;
  if (event === 'workflow_run') return payload?.workflow_run?.head_branch === 'main';
  return true;
}

async function status(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'GET' && request.method !== 'HEAD') return json({ error: 'method not allowed' }, 405, { allow: 'GET, HEAD' });
  const live = await liveStatus(env, request.url);
  if (!live) return json({ error: 'no live status yet; the build-time snapshot is on https://sluis.id/status/' }, 503, { 'retry-after': '300' });
  return json(statusJson(live), 200, { 'cache-control': STATUS_CACHE, 'access-control-allow-origin': '*' });
}

// The fragment is fetched by the page's own script and inserted, never navigated to; if it
// is, it is a bare HTML document under a policy that allows nothing but this origin's styles.
async function liveBlock(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'GET' && request.method !== 'HEAD') return json({ error: 'method not allowed' }, 405, { allow: 'GET, HEAD' });
  const live = await liveStatus(env, request.url);
  const headers = {
    ...BASE,
    'content-security-policy': "default-src 'none'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
    'x-robots-tag': 'noindex',
  };
  if (!live) {
    return new Response('The live status is not available yet; the page keeps its build-time snapshot.\n', {
      status: 503,
      headers: { ...headers, 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'retry-after': '300' },
    });
  }
  const html = statusBodyHtml({
    groups: live.groups, mode: 'live', asOf: live.asOf, available: true, runs: live.runs, coverage: live.coverage, conformance: live.conformance,
  });
  return new Response(html, { headers: { ...headers, 'content-type': 'text/html; charset=utf-8', 'cache-control': STATUS_CACHE } });
}

async function hook(request: Request, env: Env, ctx: Ctx): Promise<Response> {
  if (request.method !== 'POST') return json({ error: 'method not allowed' }, 405, { allow: 'POST' });
  if (!env.GITHUB_WEBHOOK_SECRET) return json({ error: 'webhooks are not configured' }, 503);
  if (Number(request.headers.get('content-length') ?? 0) > MAX_HOOK_BYTES) return json({ error: 'too large' }, 413);
  const body = new Uint8Array(await request.arrayBuffer());
  if (body.length > MAX_HOOK_BYTES) return json({ error: 'too large' }, 413);
  if (!(await verifyWebhook(env.GITHUB_WEBHOOK_SECRET, body, request.headers.get('x-hub-signature-256')))) {
    return json({ error: 'bad signature' }, 401);
  }
  const event = request.headers.get('x-github-event') ?? '';
  if (event === 'ping') return json({ ok: true });
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return json({ error: 'the body is not JSON' }, 400);
  }
  const prev = event === 'projects_v2_item' ? await env.STATUS.get<BoardDoc>(BOARD_KEY, 'json') : null;
  if (!hookMatters(event, payload, prev?.board.project ?? null)) return new Response(null, { status: 204, headers: BASE });
  // GitHub waits ten seconds at most; the refresh runs after the answer.
  ctx.waitUntil(refresh(env, `webhook ${event}`).then((line) => console.log(line)));
  return json({ ok: true, refreshing: true }, 202);
}

async function ci(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') return json({ error: 'method not allowed' }, 405, { allow: 'POST' });
  const auth = request.headers.get('authorization') ?? '';
  if (!auth.startsWith('Bearer ')) return json({ error: 'a GitHub Actions OIDC token is required' }, 401);
  const verdict = await verifyOidc(auth.slice('Bearer '.length).trim());
  if ('problem' in verdict) return json({ error: `token refused: ${verdict.problem}` }, 401);
  if (Number(request.headers.get('content-length') ?? 0) > MAX_CI_BYTES) return json({ error: 'too large' }, 413);
  const text = await request.text();
  if (text.length > MAX_CI_BYTES) return json({ error: 'too large' }, 413);
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return json({ error: 'the body is not JSON' }, 400);
  }
  const parts = parseSummary(body);
  if (typeof parts === 'string') return json({ error: parts }, 400);
  const c = verdict.claims;
  const result = await storeSummary(env, parts, { sha: c.sha, run: c.run_id, workflow: c.workflow_ref.replace(/@.*$/, '') });
  return result === 'stored' ? json({ ok: true }) : json({ error: 'the daily write budget is spent; try tomorrow' }, 429);
}

// Every request that reaches the Worker. A trailing slash is optional on each route.
export async function api(request: Request, env: Env, ctx: Ctx): Promise<Response> {
  const path = new URL(request.url).pathname.replace(/\/+$/, '');
  try {
    if (path === '/api/status') return await status(request, env);
    if (path === '/api/status/live') return await liveBlock(request, env);
    if (path === '/api/hooks/github') return await hook(request, env, ctx);
    if (path === '/api/ci') return await ci(request, env);
  } catch (e) {
    console.log(`${path}: failed: ${e instanceof Error ? e.message : e}`);
    return json({ error: 'internal error' }, 500);
  }
  return json({ error: 'not found', routes: ['/api/status', '/api/status/live/', '/api/hooks/github', '/api/ci'] }, 404);
}
