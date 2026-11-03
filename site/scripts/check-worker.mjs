#!/usr/bin/env node
// Tests of the site's Worker (src/worker/, ADR 0014), in Node, with GitHub and KV replaced
// by fakes: no network, no Cloudflare account, no secret. Node runs the TypeScript modules
// directly (type stripping), the same modules Wrangler bundles.
//
// - the webhook signature (X-Hub-Signature-256) and the OIDC claim rules of /api/ci;
// - the GitHub App JWT, signed with a PKCS#1 key the way GitHub issues them;
// - the KV write rules: write on a change or an hour-old copy, never past the daily cap;
// - the routes end to end: /api/status, /api/status/live/, /api/hooks/github, /api/ci;
// - the live block's HTML escapes what it is given, and matches the snapshot's renderer.
//
// usage: site/scripts/check-worker.mjs
import { generateKeyPairSync, createHmac, createVerify } from 'node:crypto';
import assert from 'node:assert/strict';

const { verifyWebhook, claimsProblem, CI_AUDIENCE } = await import('../src/worker/verify.ts');
const { appJwt, pemToPkcs8 } = await import('../src/worker/github.ts');
const { writeDecision, parseSummary, refresh, BOARD_KEY, BOARD_WRITE_CAP } = await import('../src/worker/status.ts');
const { api, hookMatters, STATUS_CACHE } = await import('../src/worker/api.ts');
const { groupStatus } = await import('../src/lib/status-groups.ts');
const { statusBodyHtml } = await import('../src/lib/status-html.ts');

let cases = 0;
const failures = [];
async function test(name, fn) {
  cases++;
  try {
    await fn();
  } catch (e) {
    failures.push(`${name}: ${e.message}`);
  }
}

// ---- fakes
class FakeKV {
  constructor() { this.data = new Map(); this.puts = 0; }
  async get(key, type) { const v = this.data.get(key); return v === undefined ? null : type === 'json' ? JSON.parse(v) : v; }
  async put(key, value) { this.puts++; this.data.set(key, value); }
}
const REPO = {
  builtAt: '2026-11-01T10:00:00Z',
  decisions: [{ id: '0001-a', number: '0001', title: 'A <b>', status: 'Accepted', proposal: 1 }],
  requirements: [
    { id: 'REQ-AA-001', area: 'AA', status: 'open', issues: [1], auto: true },
    { id: 'REQ-BB-001', area: 'BB', status: 'withdrawn', issues: [], auto: false },
  ],
};
const assets = { fetch: async (req) => (new URL(req.url ?? req).pathname === '/data/repo.json' ? Response.json(REPO) : new Response('no', { status: 404 })) };

// A GitHub that answers the four calls the Worker makes. `state.board` and `state.runs` can
// change between calls; `state.calls` counts them.
function fakeGitHub(state) {
  return async (input, init = {}) => {
    const url = String(input.url ?? input);
    state.calls.push(url);
    if (url.endsWith('/repos/truvity/sluis/installation')) return Response.json({ id: 7 });
    if (url.endsWith('/app/installations/7/access_tokens')) return Response.json({ token: 'test-installation-token', expires_at: new Date(Date.now() + 3600e3).toISOString() });
    if (url === 'https://api.github.com/graphql') {
      return Response.json({ data: { organization: { projectV2: {
        id: 'PVT_test', field: { options: state.board.options.map((name) => ({ id: name, name })) },
        items: { pageInfo: { hasNextPage: false, endCursor: null }, nodes: state.board.issues.map((i) => ({
          content: { __typename: 'Issue', number: i.number, title: i.title, state: i.open ? 'OPEN' : 'CLOSED', labels: { nodes: i.labels.map((name) => ({ name })) }, repository: { nameWithOwner: 'truvity/sluis' } },
          fieldValueByName: i.milestone ? { name: i.milestone } : null,
        })) },
      } } } });
    }
    if (url.includes('/actions/runs')) {
      const etag = `"runs-${state.runsVersion}"`;
      if (new Headers(init.headers).get('if-none-match') === etag) return new Response(null, { status: 304 });
      return Response.json({ workflow_runs: state.runs }, { headers: { etag } });
    }
    return new Response('unexpected', { status: 500 });
  };
}

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const PKCS1 = privateKey.export({ type: 'pkcs1', format: 'pem' });
const SECRET = 'test-webhook-secret';
const sign = (body) => `sha256=${createHmac('sha256', SECRET).update(body).digest('hex')}`;

function world() {
  const state = {
    calls: [],
    runsVersion: 1,
    board: { options: ['M1', 'M2'], issues: [
      { number: 1, title: 'First <script>', open: true, labels: ['type:decision'], milestone: 'M1' },
      { number: 2, title: 'Second', open: false, labels: [], milestone: 'M2' },
    ] },
    runs: [{ name: 'Site', head_branch: 'main', status: 'completed', conclusion: 'success', html_url: 'https://github.com/truvity/sluis/actions/runs/1', head_sha: 'a'.repeat(40), updated_at: '2026-11-01T10:00:00Z' }],
  };
  const env = { STATUS: new FakeKV(), ASSETS: assets, GITHUB_APP_CLIENT_ID: 'Iv-test', GITHUB_APP_PRIVATE_KEY: PKCS1, GITHUB_WEBHOOK_SECRET: SECRET };
  globalThis.fetch = fakeGitHub(state);
  return { state, env };
}
const waits = [];
const ctx = { waitUntil: (p) => waits.push(p) };
const settle = async () => { await Promise.all(waits.splice(0)); };
const req = (path, init) => new Request(`https://sluis.id${path}`, init);

// ---- signatures and claims
await test('webhook signature: the right HMAC passes', async () => {
  const body = new TextEncoder().encode('{"a":1}');
  assert.equal(await verifyWebhook(SECRET, body, sign('{"a":1}')), true);
});
await test('webhook signature: a wrong secret, a changed body, a missing or malformed header fail', async () => {
  const body = new TextEncoder().encode('{"a":1}');
  assert.equal(await verifyWebhook('other', body, sign('{"a":1}')), false);
  assert.equal(await verifyWebhook(SECRET, body, sign('{"a":2}')), false);
  assert.equal(await verifyWebhook(SECRET, body, null), false);
  assert.equal(await verifyWebhook(SECRET, body, 'sha1=00'), false);
  assert.equal(await verifyWebhook(SECRET, body, 'sha256=zz'), false);
  assert.equal(await verifyWebhook('', body, sign('{"a":1}')), false);
});

const good = {
  iss: 'https://token.actions.githubusercontent.com', aud: CI_AUDIENCE, exp: 2_000_000_000, nbf: 1_000_000_000,
  repository: 'truvity/sluis', ref: 'refs/heads/main', event_name: 'push',
  workflow_ref: 'truvity/sluis/.github/workflows/site.yaml@refs/heads/main', sha: 'a'.repeat(40), run_id: '1',
};
await test('OIDC claims: a run of site.yaml on main passes', () => assert.equal(claimsProblem(good, 1_500_000_000), null));
await test('OIDC claims: each pinned claim is enforced', () => {
  const now = 1_500_000_000;
  assert.equal(claimsProblem({ ...good, iss: 'https://example.com' }, now), 'issuer');
  assert.equal(claimsProblem({ ...good, aud: 'sluis' }, now), 'audience');
  assert.equal(claimsProblem({ ...good, exp: now - 120 }, now), 'expired');
  assert.equal(claimsProblem({ ...good, nbf: now + 120 }, now), 'not yet valid');
  assert.equal(claimsProblem({ ...good, repository: 'someone/sluis' }, now), 'repository');
  assert.equal(claimsProblem({ ...good, ref: 'refs/heads/feature' }, now), 'ref');
  assert.equal(claimsProblem({ ...good, event_name: 'pull_request' }, now), 'event');
  assert.equal(claimsProblem({ ...good, workflow_ref: 'truvity/sluis/.github/workflows/other.yaml@refs/heads/main' }, now), 'workflow');
  assert.equal(claimsProblem({ ...good, workflow_ref: 'truvity/sluis/.github/workflows/site.yaml@refs/heads/feature' }, now), 'workflow');
});

await test('GitHub App JWT: a PKCS#1 key signs an RS256 token that its public key verifies', async () => {
  assert.equal(pemToPkcs8(PKCS1)[0], 0x30);
  const now = 1_700_000_000;
  const jwt = await appJwt('Iv-test', PKCS1, now);
  const [h, p, s] = jwt.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(h, 'base64url')), { alg: 'RS256', typ: 'JWT' });
  assert.deepEqual(JSON.parse(Buffer.from(p, 'base64url')), { iat: now - 60, exp: now + 540, iss: 'Iv-test' });
  const v = createVerify('RSA-SHA256');
  v.update(`${h}.${p}`);
  assert.equal(v.verify(publicKey, Buffer.from(s, 'base64url')), true);
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.ok((await appJwt('Iv-test', pkcs8, now)).split('.').length === 3);
});

// ---- write rules
await test('KV writes: first, changed and hour-old copies write; the same content within the hour does not', () => {
  const now = Date.parse('2026-11-01T12:00:00Z');
  const prev = { hash: 'h', checkedAt: '2026-11-01T11:30:00Z', writes: { day: '2026-11-01', n: 3 } };
  assert.equal(writeDecision(null, 'h', now), 'first');
  assert.equal(writeDecision(prev, 'other', now), 'changed');
  assert.equal(writeDecision(prev, 'h', now), 'unchanged');
  assert.equal(writeDecision({ ...prev, checkedAt: '2026-11-01T10:30:00Z' }, 'h', now), 'heartbeat');
});
await test('KV writes: the daily cap stops writes until the next UTC day', () => {
  const now = Date.parse('2026-11-01T12:00:00Z');
  const full = { hash: 'h', checkedAt: '2026-11-01T11:59:00Z', writes: { day: '2026-11-01', n: BOARD_WRITE_CAP } };
  assert.equal(writeDecision(full, 'other', now), 'over budget');
  assert.equal(writeDecision({ ...full, writes: { day: '2026-10-31', n: BOARD_WRITE_CAP } }, 'other', now), 'changed');
});
await test('CI summaries: shapes are checked', () => {
  assert.deepEqual(parseSummary({ coverage: { percent: 81.27 } }), { coverage: { percent: 81.3 } });
  assert.deepEqual(parseSummary({ conformance: { passing: 3, total: 4 } }), { conformance: { passing: 3, total: 4 } });
  for (const bad of [null, [], {}, { coverage: { percent: 101 } }, { conformance: { passing: 5, total: 4 } }, { other: 1 }]) {
    assert.equal(typeof parseSummary(bad), 'string', JSON.stringify(bad));
  }
});

// ---- refresh against the fake GitHub
await test('refresh: writes once, then not again until something changes; the runs read is conditional', async () => {
  const { state, env } = world();
  const t0 = Date.parse('2026-11-01T12:00:00Z');
  assert.match(await refresh(env, 'test', t0), /wrote \(first/);
  assert.equal(env.STATUS.puts, 1);
  assert.match(await refresh(env, 'test', t0 + 60e3), /unchanged/);
  assert.equal(env.STATUS.puts, 1);
  const runsCalls = state.calls.filter((u) => u.includes('/actions/runs')).length;
  assert.equal(runsCalls, 2);
  state.board.issues[0].open = false;
  assert.match(await refresh(env, 'test', t0 + 120e3), /wrote \(changed/);
  assert.equal(env.STATUS.puts, 2);
  const doc = JSON.parse(env.STATUS.data.get(BOARD_KEY));
  assert.equal(doc.board.issues[0].open, false);
  assert.equal(doc.runs[0].workflow, 'Site');
  assert.ok(!JSON.stringify(doc).includes('test-installation-token'), 'the token must not be stored');
});
await test('refresh: a GitHub failure writes nothing and says why, without the key', async () => {
  const { env } = world();
  globalThis.fetch = async () => new Response('nope', { status: 401 });
  const line = await refresh({ ...env, GITHUB_APP_CLIENT_ID: 'Iv-other' }, 'test');
  assert.match(line, /failed/);
  assert.ok(!line.includes('PRIVATE KEY'));
  assert.equal(env.STATUS.puts, 0);
});

// ---- routes end to end
await test('/api/status: 503 before the first refresh, then JSON with a short cache', async () => {
  const { env } = world();
  const empty = await api(req('/api/status'), env, ctx);
  assert.equal(empty.status, 503);
  assert.equal(empty.headers.get('cache-control'), 'no-store');
  await refresh(env, 'test');
  const res = await api(req('/api/status'), env, ctx);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), STATUS_CACHE);
  assert.ok(!/immutable/.test(res.headers.get('cache-control')));
  assert.match(res.headers.get('content-type'), /^application\/json/);
  const body = await res.json();
  assert.equal(body.schema, 1);
  assert.deepEqual(body.milestones.map((m) => m.name), ['M1', 'M2', 'Not in a milestone']);
  assert.equal(body.milestones[0].current, true);
  assert.deepEqual(body.milestones[0].issues, { open: 1, closed: 0, blocked: 0, needsDecision: 0 });
  assert.equal(body.milestones[0].requirements.total, 1);
  assert.equal(body.ci.main[0].conclusion, 'success');
  assert.equal((await api(req('/api/status/'), env, ctx)).status, 200);
  assert.equal((await api(req('/api/status', { method: 'POST' }), env, ctx)).status, 405);
});
await test('/api/status/live/: the live block as escaped HTML', async () => {
  const { env } = world();
  assert.equal((await api(req('/api/status/live/'), env, ctx)).status, 503);
  await refresh(env, 'test');
  const res = await api(req('/api/status/live/'), env, ctx);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /^text\/html/);
  assert.match(res.headers.get('content-security-policy'), /default-src 'none'/);
  const html = await res.text();
  assert.match(html, /^<div class="ps-body" data-mode="live"/);
  assert.ok(html.includes('First &lt;script&gt;') && !html.includes('<script'), 'issue titles are escaped');
  assert.ok(html.includes('live, as of'));
});
await test('/api/hooks/github: a bad signature is refused; a good one refreshes in the background', async () => {
  const { env } = world();
  const body = JSON.stringify({ action: 'edited', repository: { full_name: 'truvity/sluis' } });
  const hook = (sig, event = 'issues') => req('/api/hooks/github', { method: 'POST', body, headers: { 'x-github-event': event, 'x-hub-signature-256': sig } });
  assert.equal((await api(hook('sha256=' + '0'.repeat(64)), env, ctx)).status, 401);
  assert.equal(env.STATUS.puts, 0);
  assert.equal((await api(hook(sign(body), 'ping'), env, ctx)).status, 200);
  assert.equal((await api(hook(sign(body), 'star'), env, ctx)).status, 204);
  assert.equal((await api(hook(sign(body)), env, ctx)).status, 202);
  await settle();
  assert.equal(env.STATUS.puts, 1);
  const off = { ...env, GITHUB_WEBHOOK_SECRET: undefined };
  assert.equal((await api(hook(sign(body)), off, ctx)).status, 503);
});
await test('/api/hooks/github: only deliveries about this board, repository and main count', () => {
  assert.equal(hookMatters('projects_v2_item', { projects_v2_item: { project_node_id: 'PVT_test' } }, 'PVT_test'), true);
  assert.equal(hookMatters('projects_v2_item', { projects_v2_item: { project_node_id: 'PVT_other' } }, 'PVT_test'), false);
  assert.equal(hookMatters('issues', { repository: { full_name: 'truvity/other' } }, null), false);
  assert.equal(hookMatters('workflow_run', { repository: { full_name: 'truvity/sluis' }, workflow_run: { head_branch: 'feature' } }, null), false);
  assert.equal(hookMatters('workflow_run', { repository: { full_name: 'truvity/sluis' }, workflow_run: { head_branch: 'main' } }, null), true);
});
await test('/api/ci: no token or a malformed one is refused; other paths are 404', async () => {
  const { env } = world();
  assert.equal((await api(req('/api/ci', { method: 'POST', body: '{}' }), env, ctx)).status, 401);
  assert.equal((await api(req('/api/ci', { method: 'POST', body: '{}', headers: { authorization: 'Bearer not.a.jwt' } }), env, ctx)).status, 401);
  assert.equal((await api(req('/api/ci'), env, ctx)).status, 405);
  assert.equal((await api(req('/api/nothing'), env, ctx)).status, 404);
  assert.equal(env.STATUS.puts, 0);
});

// ---- the renderer
await test('the snapshot and the live block come from one renderer', () => {
  const groups = groupStatus({ options: ['M1'], issues: [{ number: 1, title: 'x', open: true, labels: [], milestone: 'M1' }] }, REPO);
  const snap = statusBodyHtml({ groups, mode: 'snapshot', asOf: '2026-11-01T10:00:00Z', available: true });
  const live = statusBodyHtml({ groups, mode: 'live', asOf: '2026-11-01T10:00:00Z', available: true });
  assert.ok(snap.includes('snapshot as of 2026-11-01 10:00 UTC'));
  assert.ok(live.includes('live, as of 2026-11-01 10:00 UTC'));
  assert.equal(snap.replace(/snapshot as of/g, 'X').replace(/data-mode="snapshot"/, ''),
    live.replace(/live, as of/g, 'X').replace(/data-mode="live"/, '').replace(/No workflow run on <code>main<\/code> was read\./, 'Read live; not part of the build-time snapshot.'));
  const none = groupStatus(null, REPO);
  assert.equal(none.length, 1);
  assert.equal(none[0].issues, null);
});

await test('the milestone cards: a Design group and a Build group, named, with their own figures', () => {
  // M1 holds the open requirement REQ-AA-001, the accepted record 0001-a and one open issue.
  const groups = groupStatus({ options: ['M1'], issues: [{ number: 1, title: 'x', open: true, labels: [], milestone: 'M1' }] }, REPO);
  const html = statusBodyHtml({ groups, mode: 'live', asOf: '2026-11-01T10:00:00Z', available: true });
  const card = /<article class="ps-card[^"]*"[\s\S]*?<\/article>/.exec(html)?.[0] ?? '';
  assert.ok(card, 'one card for the milestone');
  assert.ok(card.includes('ps-bargroup-design') && card.includes('ps-bargroup-build'), 'a Design group and a Build group');
  assert.ok(card.indexOf('ps-bargroup-design') < card.indexOf('ps-bargroup-build'));
  assert.ok(card.includes('aria-label="Design: 1 of 1 ADRs accepted, 0 of 1 requirements decided"'), card);
  assert.ok(card.includes('aria-label="Build: 0 of 1 requirements done, 0 of 1 issues closed"'), card);
  for (const k of ['ADRs accepted', 'Requirements decided', 'Requirements done', 'Issues closed']) assert.ok(card.includes(`<dt>${k}</dt>`), k);
  assert.equal(card.match(/<meter /g).length, 4);
  // A decided requirement moves the Design bar and not the Build bar.
  const decided = { ...REPO, requirements: [{ ...REPO.requirements[0], status: 'planned' }] };
  const g2 = groupStatus({ options: ['M1'], issues: [{ number: 1, title: 'x', open: true, labels: [], milestone: 'M1' }] }, decided);
  const card2 = statusBodyHtml({ groups: g2, mode: 'snapshot', asOf: '2026-11-01T10:00:00Z', available: true });
  assert.ok(card2.includes('1 of 1 requirements decided') && card2.includes('0 of 1 requirements done'), 'planned counts as decided, not as done');
});

if (failures.length) {
  for (const f of failures) console.error(`check-worker: FAIL ${f}`);
  console.error(`check-worker: ${failures.length} of ${cases} cases failed`);
  process.exit(1);
}
if (cases === 0) {
  console.error('check-worker: no cases ran');
  process.exit(1);
}
console.log(`check-worker: ok (${cases} cases)`);
