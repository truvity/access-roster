// The browser test of the passkey registration (docs/runtimes/local.md, "Sign-in", "Passkeys: a browser"), run against the
// running local installation (`just local-up` first): `just local-passkey-smoke`.
//
// A real Chromium, headless, with a virtual authenticator of the DevTools protocol (WebAuthn.addVirtualAuthenticator), driven
// over the protocol by this script and nothing else (no npm package, as site/scripts/check-render.mjs). The root of the
// run is imported into a NSS database of a home that belongs to the browser, so the chain is the real chain and the page is
// a secure context; the host names are mapped to the forwarder's published port. The identity provider (Keycloak) is driven
// through its own forms in the browser, with the one-time code computed from the user's secret, as a person would use an
// authenticator app.
//
// What it shows, each with its evidence printed:
//   1. the whole flow of adding a passkey: a sign-in, /passkeys/add, the identity provider again, the registration page, the
//      browser's ceremony with the virtual authenticator, the answer, the done page; a device-bound key (class hardware) and a
//      synced passkey (class synced); the first authenticator is refused a second credential by the exclude list;
//   2. the script of the registration page runs under its Content-Security-Policy, and the hash in the policy is the hash of
//      the script (computed here from the page, not read from the product); and that the policy is enforced: the same page
//      with a policy whose hash is wrong does nothing;
//   3. the cookie __Host-sluis_ceremony (SameSite=Strict), set in the answer to a navigation that came across sites from the
//      identity provider, is stored, and is sent on the page's own post; and that Strict is enforced: it is not sent on a
//      navigation that comes from another site;
//   4. the refusals: an authentication that is not from this request (the identity provider answers from its session),
//      an origin that is not in the list (the page served from another host of the installation), and a held person.
//
// It leaves nothing behind: the browser, its profile and the home are removed, a hold is lifted, no container is started.

import { spawn, spawnSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ROOT = resolve(process.env.SLUIS_ROOT ?? process.cwd());
const PORT = process.env.SLUIS_LOCAL_PORT ?? '8443';
const CA = process.env.SSL_CERT_FILE ?? join(ROOT, '.cache/local/ca/ca.pem');
const SECRETS = process.env.SLUIS_KEYCLOAK_SECRETS ?? join(process.env.SLUIS_BUILD_DIR ?? '', 'keycloak-secrets.env');
const SPINE = process.env.SLUIS_SPINE ?? join(ROOT, 'dist/local/spine');
const AUDIT = process.env.SLUIS_AUDIT_SEARCH ?? join(ROOT, 'dist/local/audit-search');
const FRONT = 'sluis.dev.local.test';
const BASE = `https://${FRONT}`;
const OTHER = 'app.local.test'; // a host of the installation that the FrontHost does not list as an origin
const IDP = '127.0.0.1:8180';
const ONLY = (process.env.SLUIS_PASSKEY_RIG_ONLY ?? '').split(',').filter(Boolean); // sections to run, for work on one: sync, csp, stale, origin, hold
const want = (name) => ONLY.length === 0 || ONLY.includes(name);
const OUT = process.env.SLUIS_PASSKEY_RIG_REPORT; // a file for the machine-readable report, if wanted

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256b64 = (s) => createHash('sha256').update(s).digest('base64');

// ---- the report -------------------------------------------------------------------------------------------------------

const checks = [];
const notes = [];
function check(ok, what, evidence = '') {
  checks.push({ ok: !!ok, what, evidence });
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}${evidence ? `: ${evidence}` : ''}`);
  return !!ok;
}
function note(what) {
  notes.push(what);
  console.log(`     ${what}`);
}
function must(ok, what, evidence) {
  if (!check(ok, what, evidence)) throw new Error(`failed: ${what}`);
}

// ---- the secrets of the identity provider's user ----------------------------------------------------------------------

function secrets() {
  const m = {};
  for (const l of readFileSync(SECRETS, 'utf8').split('\n')) {
    const i = l.indexOf('=');
    if (i > 0) m[l.slice(0, i)] = l.slice(i + 1);
  }
  if (!m.ALICE_PASSWORD || !m.ALICE_TOTP_BASE32) throw new Error('SLUIS_KEYCLOAK_SECRETS has no ALICE_PASSWORD or ALICE_TOTP_BASE32');
  return m;
}

// RFC 6238 with HMAC-SHA1, six digits, 30 s. The identity provider takes a code once, so a second code is the one of the next
// step (it looks one step ahead), and one further ahead is waited for: the same rule as tools/harness/kclogin.
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32decode(s) {
  let bits = 0, val = 0;
  const out = [];
  for (const c of s.toUpperCase().replace(/=+$/, '').replace(/ /g, '')) {
    val = (val << 5) | B32.indexOf(c);
    bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function totp(key, step) {
  const c = Buffer.alloc(8);
  c.writeBigUInt64BE(BigInt(step));
  const h = createHmac('sha1', key).update(c).digest();
  const o = h[h.length - 1] & 0x0f;
  return String(((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000)).padStart(6, '0');
}
let lastStep = 0;
async function nextCode(base32, retry = false) {
  const now = Date.now() / 1000;
  const step = Math.floor(now / 30);
  let use = step;
  if (lastStep >= use) use = lastStep + 1;
  // After a refusal the provider may not look ahead (a code of another run took the step), so the step to use must have begun.
  if (retry) await sleep(Math.max(0, use * 30 - now) * 1000 + 300);
  else if (use > step + 1) await sleep(((use - 1) * 30 - now) * 1000 + 300);
  lastStep = use;
  return totp(b32decode(base32), use);
}

// ---- the browser ------------------------------------------------------------------------------------------------------

function findChrome() {
  for (const c of [process.env.CHROME, 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser'].filter(Boolean)) {
    const r = spawnSync(c, ['--version'], { encoding: 'utf8', timeout: 60000 });
    if (r.status === 0) return { path: c, version: r.stdout.trim() };
  }
  throw new Error('no Chrome or Chromium found: set CHROME, or put google-chrome or chromium on PATH');
}

// The PEM certificates of the harness CA file, one by one.
function certificates() {
  return readFileSync(CA, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
}

// A home for the browser with the root of the run in the NSS database that Chromium reads on Linux ($HOME/.pki/nssdb).
// Without `certutil` the browser is told the public key of the certificates instead (--ignore-certificate-errors-spki-list),
// which makes the connection valid for the page and so a secure context, but it does not test the chain: the run says so.
function trust(dir) {
  const certs = certificates();
  if (!certs.length) throw new Error(`${CA} holds no certificate`);
  const home = join(dir, 'home');
  const db = join(home, '.pki', 'nssdb');
  mkdirSync(db, { recursive: true });
  const certutil = process.env.CERTUTIL ?? 'certutil';
  const probe = spawnSync(certutil, ['--version'], { encoding: 'utf8' });
  const have = !probe.error && (probe.status === 0 || /certutil/.test(`${probe.stderr}${probe.stdout}`));
  if (have) {
    must(spawnSync(certutil, ['-d', `sql:${db}`, '-N', '--empty-password']).status === 0, 'the NSS database of the browser is made');
    certs.forEach((pem, i) => {
      const f = join(dir, `ca-${i}.pem`);
      writeFileSync(f, pem + '\n');
      must(spawnSync(certutil, ['-d', `sql:${db}`, '-A', '-n', `sluis-test-root-${i}`, '-t', 'C,,', '-i', f]).status === 0, `certificate ${i} of the run is imported`);
    });
    return { home, args: [], how: 'the root of the run imported into the NSS database of the browser (certutil)' };
  }
  const { X509Certificate } = await_import_crypto();
  const hashes = certs.map((pem) => createHash('sha256').update(new X509Certificate(pem).publicKey.export({ type: 'spki', format: 'der' })).digest('base64'));
  return { home, args: [`--ignore-certificate-errors-spki-list=${hashes.join(',')}`], how: 'FALLBACK, no certutil: the public key of the run\'s root passed with --ignore-certificate-errors-spki-list (the chain is not tested)' };
}
import * as nodeCrypto from 'node:crypto';
function await_import_crypto() { return nodeCrypto; }

// One Chrome, one profile, and the CDP over the browser's websocket with sessions per target.
async function launch(chrome, home, extra) {
  const profile = mkdtempSync(join(tmpdir(), 'passkey-rig-'));
  const child = spawn(chrome.path, [
    '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-extensions', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
    `--host-resolver-rules=MAP *.local.test 127.0.0.1:${PORT}`, ...extra, 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, HOME: home } });
  let err = '';
  const ws = await new Promise((ok, fail) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); fail(new Error(`Chrome did not print its DevTools address in 60 s\n${err.slice(-2000)}`)); }, 60000);
    child.stderr.on('data', (d) => {
      err += d;
      const m = err.match(/DevTools listening on (ws:\/\/\S+)/);
      if (m) { clearTimeout(timer); ok(m[1]); }
    });
    child.on('exit', (code) => { clearTimeout(timer); fail(new Error(`Chrome exited early (${code})\n${err.slice(-2000)}`)); });
  });
  const sock = new WebSocket(ws);
  await new Promise((ok, fail) => { sock.onopen = ok; sock.onerror = () => fail(new Error('CDP socket failed')); });
  let id = 0;
  const pending = new Map();
  const handlers = new Map(); // sessionId -> [fn]
  sock.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      const { ok, fail, method } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? fail(new Error(`${method}: ${msg.error.message}`)) : ok(msg.result);
    } else if (msg.method) (handlers.get(msg.sessionId ?? '') ?? []).forEach((h) => h(msg));
  };
  const send = (method, params = {}, sessionId) => new Promise((ok, fail) => {
    const n = ++id;
    pending.set(n, { ok, fail, method });
    sock.send(JSON.stringify({ id: n, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
  const browser = {
    child, profile, version: chrome.version,
    send,
    async tab() { // a new tab, attached
      const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
      const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
      const list = [];
      handlers.set(sessionId, list);
      const s = {
        targetId, sessionId, events: [],
        send: (method, params) => send(method, params, sessionId),
        on: (h) => list.push(h),
        async close() { await send('Target.closeTarget', { targetId }).catch(() => {}); handlers.delete(sessionId); },
      };
      list.push((m) => s.events.push(m));
      return s;
    },
    async stop() {
      try { sock.close(); } catch { /* gone */ }
      child.kill('SIGKILL');
      await sleep(200);
      rmSync(profile, { recursive: true, force: true });
    },
  };
  return browser;
}

// ---- the page, as the script sees it ----------------------------------------------------------------------------------

async function ev(tab, expr) {
  const r = await tab.send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error(`evaluate: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
  return r.result.value;
}
async function waitFor(tab, expr, what, ms = 45000) {
  const end = Date.now() + ms;
  let last;
  while (Date.now() < end) {
    try { last = await ev(tab, expr); if (last) return last; } catch { /* a page in transition */ }
    await sleep(150);
  }
  const where = await ev(tab, '`${location.href.split("?")[0]} | ${(document.body && document.body.innerText || "").slice(0, 160).replace(/\\s+/g, " ")}`').catch(() => '(no page)');
  throw new Error(`timed out waiting for ${what}; the page is ${where}`);
}

// Navigates and returns when the navigation has committed: the page that was there is gone, so that what is read next is the
// new one's (Page.navigate returns when the request starts, and a wait for "a page of sluis" would be answered by the old one).
async function go(tab, url) {
  const nav = await tab.send('Page.navigate', { url });
  if (nav.errorText) throw new Error(`navigation to ${url.split('?')[0]}: ${nav.errorText}`);
  if (!nav.loaderId) return; // a same-document navigation
  const end = Date.now() + 30000;
  while (Date.now() < end) {
    const t = await tab.send('Page.getFrameTree');
    if (t.frameTree.frame.loaderId === nav.loaderId) return;
    await sleep(50);
  }
  throw new Error(`the navigation to ${url.split('?')[0]} did not commit`);
}
const here = (tab) => ev(tab, 'location.href').catch(() => '');

async function setup(tab) {
  // One handler for a request that Fetch pauses, replaced by each scenario that intercepts and cleared after it.
  tab.paused = null;
  tab.on((m) => { if (m.method === 'Fetch.requestPaused' && tab.paused) Promise.resolve(tab.paused(m.params)).catch((e) => console.error(`intercept: ${e.message}`)); });
  // The page's own report of a policy violation, from a script that the protocol adds to every new document (so that the policy
  // does not apply to it): what the browser enforced, as the page saw it.
  await tab.send('Page.addScriptToEvaluateOnNewDocument', { source: "window.__csp = []; document.addEventListener('securitypolicyviolation', (e) => window.__csp.push({ directive: e.violatedDirective, blocked: e.blockedURI, sample: (e.sample || '').slice(0, 40) }), true);" });
  await tab.send('Page.enable');
  await tab.send('Network.enable');
  await tab.send('Runtime.enable');
  await tab.send('Log.enable');
}

// The events of a tab, reduced to what the checks read.
const requests = (tab) => tab.events.filter((m) => m.method === 'Network.requestWillBeSent').map((m) => m.params);
const extraReq = (tab) => tab.events.filter((m) => m.method === 'Network.requestWillBeSentExtraInfo').map((m) => m.params);
const extraRes = (tab) => tab.events.filter((m) => m.method === 'Network.responseReceivedExtraInfo').map((m) => m.params);
const responses = (tab) => tab.events.filter((m) => m.method === 'Network.responseReceived').map((m) => m.params);
const logs = (tab) => tab.events.filter((m) => m.method === 'Log.entryAdded').map((m) => m.params.entry);

// ---- the identity provider's forms -----------------------------------------------------------------------------------

// Signs in at the identity provider with the forms it shows: the user name and password, or the password alone when it knows
// the person (prompt=login), then the one-time code. Returns when the page is back at the installation's host (or at `stop`).
async function keycloak(tab, s, stop) {
  let otpRefused = 0; // a code of the same step may have been taken by another run: try the next steps
  for (let i = 0; i < 10; i++) {
    const st = await waitFor(tab, `(() => {
      const u = location.href;
      if (!u.startsWith('${IDP.startsWith('http') ? IDP : `http://${IDP}`}')) return { done: true, url: u };
      const st = { done: false, user: !!document.querySelector('#username'), pass: !!document.querySelector('#password'), otp: !!document.querySelector('#otp') };
      return st.user || st.pass || st.otp || !!document.querySelector('.kc-feedback-text') ? st : null;
    })()`, 'a form of the identity provider or the way back');
    if (st.done) return st.url;
    const before = await here(tab);
    if (st.otp) {
      const code = await nextCode(s.ALICE_TOTP_BASE32, otpRefused > 0);
      await ev(tab, `document.querySelector('#otp').value = '${code}'; document.querySelector('#kc-login').click(); true`);
    } else if (st.user || st.pass) {
      await ev(tab, `(() => { const u = document.querySelector('#username'); if (u) u.value = 'alice'; document.querySelector('#password').value = ${JSON.stringify(s.ALICE_PASSWORD)}; document.querySelector('#kc-login').click(); return true; })()`);
    } else {
      throw new Error(`the identity provider shows a form the rig cannot fill: ${await ev(tab, 'document.body.innerText.slice(0, 200)').catch(() => '')}`);
    }
    // Taken: the page is another one (the address differs, or the document is not the one we filled), or it shows a refusal.
    await waitFor(tab, `(() => { if (location.href !== ${JSON.stringify(before)}) return true; return !document.querySelector('#kc-login') || !!document.querySelector('.kc-feedback-text, #input-error-otp, #input-error'); })()`, 'the form to be taken');
    const err = await ev(tab, `(document.querySelector('.kc-feedback-text, #input-error-otp, #input-error') || {}).textContent || ''`).catch(() => '');
    if (err && /Invalid authenticator code/i.test(err) && ++otpRefused <= 3) continue;
    if (err && err.trim()) throw new Error(`the identity provider refused the form: ${err.trim()}`);
    if (stop && (await here(tab)).startsWith(stop)) return;
  }
  throw new Error('too many forms at the identity provider');
}

// ---- the flows --------------------------------------------------------------------------------------------------------

// A catcher for the redirect of the ordinary sign-in (the loopback redirect of the CLI client).
function catcher() {
  let resolveCode;
  const got = new Promise((r) => { resolveCode = r; });
  const srv = createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    res.writeHead(200, { 'content-type': 'text/plain' }).end('signed in');
    if (u.pathname === '/callback') resolveCode(u.searchParams.get('code') ? 'code' : (u.searchParams.get('error') ?? 'nothing'));
  });
  return new Promise((ok) => srv.listen(0, '127.0.0.1', () => ok({ port: srv.address().port, got, close: () => srv.close() })));
}

// The ordinary sign-in of alice at the client sluis-cli, so that she exists as a person (a passkey is added to someone who has
// signed in before).
async function signIn(tab, s) {
  const c = await catcher();
  const verifier = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
  const q = new URLSearchParams({
    response_type: 'code', client_id: 'sluis-cli', redirect_uri: `http://127.0.0.1:${c.port}/callback`, scope: 'openid',
    state: 'rig-state', nonce: 'rig-nonce', code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
  });
  await go(tab, `${BASE}/authorize?${q}`);
  await keycloak(tab, s, `http://127.0.0.1:${c.port}`);
  const code = await Promise.race([c.got, sleep(30000).then(() => 'timeout')]);
  c.close();
  must(code === 'code', 'the ordinary sign-in of alice ends in a code for the client', code);
}

const REGISTER_PAGE = `(() => document.body && document.body.dataset.sluisPage === 'passkey-register')()`;

// /passkeys/add, the identity provider again, and the registration page. Returns when the page is there.
async function toRegistrationPage(tab, s, { stripFresh } = {}) {
  await go(tab, `${BASE}/passkeys/add`);
  await keycloak(tab, s);
  await waitFor(tab, `(() => document.body && document.body.dataset.sluisPage)()`, 'a page of sluis');
}

async function authenticator(tab, { synced }) {
  const { authenticatorId } = await tab.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: synced ? 'internal' : 'usb',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
      defaultBackupEligibility: synced, defaultBackupState: synced,
    },
  });
  return authenticatorId;
}

// ---- the scenarios ----------------------------------------------------------------------------------------------------

const tabs = [];
async function newTab(browser) {
  const tab = await browser.tab();
  tabs.push(tab);
  await setup(tab);
  await tab.send('WebAuthn.enable', { enableUI: false });
  return tab;
}

// The parts of the rig that are arithmetic, against the published vectors, before anything is started: RFC 6238 appendix B
// (the key of the SHA-1 vectors, at 59 s and at 1111111109 s, six digits of the eight) and RFC 4648 section 10 (base32).
function selfTest() {
  const key = Buffer.from('12345678901234567890');
  must(totp(key, Math.floor(59 / 30)) === '287082' && totp(key, Math.floor(1111111109 / 30)) === '081804', 'the one-time code agrees with RFC 6238 appendix B');
  must(b32decode('MZXW6YTBOI======').toString() === 'foobar' && b32decode('MZXW6===').toString() === 'foo', 'base32 agrees with RFC 4648 section 10');
}

async function main() {
  selfTest();
  const t0 = Date.now();
  const s = secrets();
  const chrome = findChrome();
  const dir = mkdtempSync(join(tmpdir(), 'passkey-rig-home-'));
  const tr = trust(dir);
  note(`browser: ${chrome.version}, headless`);
  note(`trust: ${tr.how}`);
  const auditBefore = ONLY.length === 0 ? auditCounts() : {};
  const browser = await launch(chrome, tr.home, tr.args);
  const hold = { on: false };
  // A person has at most ten passkeys and the rig adds three: it starts and ends with none, so that it can run again.
  note(`spine forget: ${runSpine('forget')}`);
  try {
    const tab = await newTab(browser);

    // 0. alice signs in once, so that she is a person.
    await signIn(tab, s);

    // 1. The whole flow, with a device-bound authenticator.
    console.log('\n== 1. Adding a passkey: the whole flow');
    const usb = await authenticator(tab, { synced: false });
    tab.events.length = 0;
    await toRegistrationPage(tab, s);
    const page = await ev(tab, `({ url: location.href, kind: document.body.dataset.sluisPage, action: document.querySelector('form').getAttribute('action'),
      scripts: [...document.scripts].map((x) => x.textContent), hasOptions: !!document.querySelector('form').dataset.options })`);
    must(page.kind === 'passkey-register' && page.url.startsWith(`${BASE}/callback`), 'the callback of the sign-in ends in the registration page', page.url.split('?')[0]);
    check(page.action === '/passkeys/register', 'the form posts to /passkeys/register on the same origin');

    // 2. The script and its policy.
    console.log('\n== 2. The script of the page runs under its Content-Security-Policy');
    const doc = responses(tab).find((r) => r.type === 'Document' && r.response.url.startsWith(`${BASE}/callback`));
    const csp = doc?.response.headers['content-security-policy'] ?? doc?.response.headers['Content-Security-Policy'] ?? '';
    must(csp, 'the registration page carries a Content-Security-Policy', csp);
    const hash = sha256b64(page.scripts[0]);
    check(page.scripts.length === 1, 'the page has exactly one script', `${page.scripts.length}`);
    check(csp.includes(`script-src 'sha256-${hash}'`), 'the policy allows the hash of the script the page holds (computed here from the page)', `sha256-${hash}`);
    check(!/unsafe-inline|unsafe-eval|connect-src/.test(csp) && csp.includes("default-src 'none'"), "the policy has default-src 'none' and no unsafe-inline, unsafe-eval or connect-src");
    const violations = await ev(tab, 'window.__csp');
    check(violations.length === 0, 'the browser reports no policy violation for the page', `${violations.length}`);

    // 3. The ceremony cookie, as the browser stored it and as it will send it.
    console.log('\n== 3. The cookie __Host-sluis_ceremony (SameSite=Strict)');
    const callbackExtra = extraRes(tab).filter((r) => (r.headers['set-cookie'] ?? r.headers['Set-Cookie'] ?? '').includes('__Host-sluis_ceremony'));
    must(callbackExtra.length === 1, 'the answer to the callback sets the ceremony cookie', `${callbackExtra.length} response`);
    const setCookie = callbackExtra[0].headers['set-cookie'] ?? callbackExtra[0].headers['Set-Cookie'];
    const setLine = setCookie.split('\n').find((l) => l.startsWith('__Host-sluis_ceremony='));
    check(/SameSite=Strict/.test(setLine) && /Secure/.test(setLine) && /HttpOnly/.test(setLine) && /Path=\//.test(setLine) && !/Domain/.test(setLine), 'it is set with Secure, HttpOnly, SameSite=Strict, Path=/ and no Domain', setLine.replace(/=[^;]*/, '=<sealed>'));
    const cameFrom = requests(tab).filter((r) => r.type === 'Document').map((r) => r.request.url.split('?')[0]);
    check(cameFrom.some((u) => u.startsWith(`http://${IDP}/`)) && cameFrom.at(-1).startsWith(`${BASE}/callback`),
      'the callback is the end of a navigation that came across sites from the identity provider', cameFrom.join(' -> '));
    const blocked = callbackExtra[0].blockedCookies ?? [];
    check(blocked.length === 0, 'the browser did not block the cookie when it was set (cross-site redirect into /callback)', blocked.length ? JSON.stringify(blocked.map((b) => b.blockedReasons)) : 'blockedCookies is empty');
    const stored = (await tab.send('Network.getCookies', { urls: [BASE] })).cookies.find((c) => c.name === '__Host-sluis_ceremony');
    must(stored, 'the browser stored the cookie', stored ? `domain ${stored.domain}, path ${stored.path}` : 'it is not in the jar');
    check(stored.sameSite === 'Strict' && stored.secure && stored.httpOnly && stored.path === '/' && !stored.domain.startsWith('.'), 'the stored cookie is Strict, Secure, HttpOnly, Path=/ and host-only', `sameSite=${stored.sameSite} secure=${stored.secure} httpOnly=${stored.httpOnly} domain=${stored.domain}`);
    check(stored.session === false && stored.expires > Date.now() / 1000 && stored.expires < Date.now() / 1000 + 330, 'its lifetime is the five minutes of the ceremony', `${Math.round(stored.expires - Date.now() / 1000)} s left`);

    // ... and that Strict is enforced: another tab, at a page of another site, navigates to the installation: the cookie is not sent.
    const probe = await newTab(browser);
    await probe.send('Page.navigate', { url: `http://${IDP}/realms/sluis-test/.well-known/openid-configuration` });
    await waitFor(probe, `location.href.startsWith('http://${IDP}')`, 'a page of the other site');
    probe.events.length = 0;
    await ev(probe, `location.href = '${BASE}/healthz'; true`); // from the page: a navigation that comes from another site
    await waitFor(probe, `location.href.startsWith('${BASE}')`, 'the navigation to the installation');
    await sleep(300);
    const crossId = requests(probe).find((r) => r.request.url === `${BASE}/healthz`)?.requestId;
    const crossReq = extraReq(probe).find((r) => r.requestId === crossId);
    const crossAssoc = (crossReq?.associatedCookies ?? []).find((a) => a.cookie.name === '__Host-sluis_ceremony');
    check(!!crossAssoc && (crossAssoc.blockedReasons ?? []).some((r) => /SameSite/i.test(r)) && !/__Host-sluis_ceremony/.test(JSON.stringify(crossReq.headers)),
      'a navigation from another site does not carry the cookie (Strict is enforced)', crossAssoc ? `blockedReasons ${JSON.stringify(crossAssoc.blockedReasons)}` : `the cookie was not considered (${crossReq ? 'request seen' : 'no request seen'})`);
    await probe.close();

    // The ceremony: the button, the virtual authenticator, the post.
    tab.events.length = 0;
    await ev(tab, `document.querySelector('button[type=submit]').click(); true`);
    await waitFor(tab, `location.pathname === '/passkeys/register' && !!document.body && document.body.dataset.sluisPage`, 'the answer to the registration');
    const done = await ev(tab, `({ kind: document.body.dataset.sluisPage, text: document.body.innerText })`);
    must(done.kind === 'passkey-done' && /Passkey added/.test(done.text), 'the browser made the credential and the post was taken: the done page', done.text.split('\n').slice(0, 2).join(' | '));
    check(/device-bound/.test(done.text), 'the page says what kind it is: a device-bound passkey');
    const post = requests(tab).find((r) => r.request.method === 'POST' && r.request.url === `${BASE}/passkeys/register`);
    check(!!post, 'the page posted to /passkeys/register on its own origin');
    const postExtra = extraReq(tab).find((r) => r.requestId === post?.requestId);
    const sent = (postExtra?.associatedCookies ?? []).find((a) => a.cookie.name === '__Host-sluis_ceremony');
    check(!!sent && (sent.blockedReasons ?? []).length === 0 && /__Host-sluis_ceremony=/.test(postExtra.headers.Cookie ?? postExtra.headers.cookie ?? ''),
      'the cookie was sent on that post (the Cookie header carries it, nothing blocked it)', sent ? `blockedReasons ${JSON.stringify(sent.blockedReasons)}` : 'not considered');
    const csrf = requests(tab).find((r) => r.request.method === 'POST')?.request.headers;
    check(!!csrf && !('Authorization' in csrf) && !('authorization' in csrf), 'the post carries no Authorization header');
    const after = (await tab.send('Network.getCookies', { urls: [BASE] })).cookies.some((c) => c.name === '__Host-sluis_ceremony');
    check(!after, 'the done page cleared the cookie');
    const creds = (await tab.send('WebAuthn.getCredentials', { authenticatorId: usb })).credentials;
    check(creds.length === 1 && creds[0].isResidentCredential && creds[0].rpId === 'local.test' && Buffer.from(creds[0].userHandle, 'base64').length === 32,
      'the authenticator holds one discoverable credential for local.test with a 32-byte user handle', `${creds.length} credential, rpId ${creds[0]?.rpId}`);

    if (want('sync')) {
    // A synced passkey of the same person: a second authenticator with backup eligibility, the same user handle.
    console.log('\n== 1b. A synced passkey, and the exclude list');
    const syncedAuth = await authenticator(tab, { synced: true });
    await tab.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId: usb, enabled: false });
    await toRegistrationPage(tab, s);
    await ev(tab, `document.querySelector('button[type=submit]').click(); true`);
    await waitFor(tab, `location.pathname === '/passkeys/register' && !!document.body && document.body.dataset.sluisPage`, 'the answer to the second registration');
    const done2 = await ev(tab, `document.body.innerText`);
    check(/synced passkey/.test(done2), 'a credential made with backup eligibility is a synced passkey', done2.split('\n').slice(0, 2).join(' | '));
    const c2 = (await tab.send('WebAuthn.getCredentials', { authenticatorId: syncedAuth })).credentials[0];
    check(c2 && c2.userHandle === creds[0].userHandle, 'both credentials carry the same user handle (the person\'s)');

    // The first authenticator alone is excluded: it already holds a credential of the person.
    await tab.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: syncedAuth });
    await tab.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId: usb, enabled: true });
    await toRegistrationPage(tab, s);
    await ev(tab, `document.querySelector('button[type=submit]').click(); true`);
    const msg = await waitFor(tab, `(() => { const m = document.getElementById('message'); return m && m.textContent ? m.textContent : ''; })()`, 'the message of the page', 15000);
    check(/not made/.test(msg) && (await ev(tab, `location.pathname`)) !== '/passkeys/register', 'an authenticator that holds a credential of the person is refused a second one (the exclude list), and nothing is posted', msg);
    await tab.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: usb });
    }

    if (want('csp')) {
    // 4. The same page with a policy whose hash is not the script's: the browser blocks the script and nothing happens.
    console.log('\n== 2b. The policy is enforced: a wrong hash stops the script');
    const auth3 = await authenticator(tab, { synced: false });
    await tab.send('Fetch.enable', { patterns: [{ urlPattern: `${BASE}/callback*`, requestStage: 'Response' }] });
    let altered = '';
    tab.paused = async (p) => {
      const headers = (p.responseHeaders ?? []).map((h) => (h.name.toLowerCase() === 'content-security-policy' ? { name: h.name, value: (altered = h.value.replace(/sha256-./, (x) => `sha256-${x.endsWith('A') ? 'B' : 'A'}`)) } : h));
      // continueResponse does not reach the policy the renderer enforces (measured: the page ran its script under the original),
      // so the answer is made again with the body it had.
      const body = await tab.send('Fetch.getResponseBody', { requestId: p.requestId });
      await tab.send('Fetch.fulfillRequest', { requestId: p.requestId, responseCode: p.responseStatusCode, responseHeaders: headers,
        body: body.base64Encoded ? body.body : Buffer.from(body.body).toString('base64') });
    };
    tab.events.length = 0;
    await toRegistrationPage(tab, s);
    tab.paused = null;
    await tab.send('Fetch.disable');
    // The violation happens when the page is parsed: read what the page saw before anything is clicked.
    const blockedByPolicy = await ev(tab, 'window.__csp');
    check(altered !== '' && blockedByPolicy.length > 0 && blockedByPolicy.every((v) => /script-src/.test(v.directive)),
      'with a hash that is not the script\'s the browser refuses to run the script and reports the violation', blockedByPolicy[0] ? `${blockedByPolicy[0].directive} blocked an inline script` : 'no violation reported');
    // Pressing the button now posts the form as a form (no script, so no credential and an empty answer), and the answer is refused.
    tab.events.length = 0;
    await ev(tab, `document.querySelector('button[type=submit]').click(); true`);
    await waitFor(tab, `location.pathname === '/passkeys/register' && !!document.body && document.body.dataset.sluisPage`, 'the answer to the plain post');
    const plainPost = requests(tab).find((r) => r.request.method === 'POST');
    const credsNow = (await tab.send('WebAuthn.getCredentials', { authenticatorId: auth3 })).credentials;
    const plain = await ev(tab, 'document.body.dataset.sluisPage');
    check(credsNow.length === 0 && /^response=$/.test(plainPost?.request.postData ?? 'x') && plain === 'passkey-error',
      'with the script blocked no credential is made, the form posts an empty answer, and it is refused', `${credsNow.length} credentials, body "${plainPost?.request.postData}", page ${plain}`);
    }

    if (want('stale')) {
    // 5. Refusals.
    console.log('\n== 4. Refusals');
    // 5a. An authentication that is not from this request: the identity provider is asked for none (prompt and max_age removed
    // from its request, as an identity provider that answers from its own session would), and answers from the session of
    // the sign-in above, which is older than the request.
    await sleep(12000); // older than the 10 seconds of tolerance
    await tab.send('Fetch.enable', { patterns: [{ urlPattern: `http://${IDP}/realms/*/protocol/openid-connect/auth*`, requestStage: 'Request' }] });
    let stripped = false;
    tab.paused = async (p) => {
      if (p.responseStatusCode) return;
      const u = new URL(p.request.url);
      stripped = u.searchParams.has('prompt') && u.searchParams.has('max_age');
      u.searchParams.delete('prompt');
      u.searchParams.delete('max_age');
      await tab.send('Fetch.continueRequest', { requestId: p.requestId, url: u.toString() });
    };
    await go(tab, `${BASE}/passkeys/add`);
    await waitFor(tab, `location.pathname === '/callback' && !!document.body && document.body.dataset.sluisPage`, 'the callback after the old session');
    tab.paused = null;
    await tab.send('Fetch.disable');
    const stale = await ev(tab, `({ kind: document.body.dataset.sluisPage, text: document.body.innerText, form: !!document.querySelector('form') })`);
    check(stripped, 'the request to the identity provider carried prompt=login and max_age=0 (the rig took them off)');
    check(stale.kind === 'passkey-error' && !stale.form, 'an authentication from the identity provider\'s old session is refused: the fixed page, no registration page', stale.text.split('\n')[0]);
    check(!(await tab.send('Network.getCookies', { urls: [BASE] })).cookies.some((c) => c.name === '__Host-sluis_ceremony'), 'no ceremony cookie was set for it');
    }

    if (want('origin')) {
    // 5b. An origin that is not in the list: the registration page served from another host of the installation. Same site, so
    // the Strict cookie is sent on its post; the origin the browser writes in the answer is not the FrontHost's.
    await toRegistrationPage(tab, s);
    const html = await ev(tab, `document.documentElement.outerHTML`);
    const cspNow = responses(tab).filter((r) => r.type === 'Document' && r.response.url.startsWith(`${BASE}/callback`)).at(-1).response.headers['content-security-policy'];
    const auth4 = await authenticator(tab, { synced: false });
    await tab.send('Fetch.enable', { patterns: [{ urlPattern: `https://${OTHER}/*`, requestStage: 'Request' }] });
    tab.paused = async (p) => {
      if (p.responseStatusCode) return;
      const body = `<!doctype html>${html.replace('action="/passkeys/register"', `action="${BASE}/passkeys/register"`)}`;
      await tab.send('Fetch.fulfillRequest', {
        requestId: p.requestId, responseCode: 200, body: Buffer.from(body).toString('base64'),
        responseHeaders: [{ name: 'Content-Type', value: 'text/html; charset=utf-8' }, { name: 'Content-Security-Policy', value: cspNow.replace("form-action 'self'", `form-action ${BASE}`) }],
      });
    };
    await go(tab, `https://${OTHER}/rig-origin`);
    await waitFor(tab, `location.host === '${OTHER}' && !!document.querySelector('form')`, 'the page at the other host');
    tab.events.length = 0;
    await ev(tab, `document.querySelector('button[type=submit]').click(); true`);
    await waitFor(tab, `location.host === '${FRONT}' && location.pathname === '/passkeys/register' && !!document.body`, 'the answer to the post from the other host');
    tab.paused = null;
    await tab.send('Fetch.disable');
    const wrong = await ev(tab, `({ kind: document.body.dataset.sluisPage, text: document.body.innerText })`);
    const wrongPost = requests(tab).find((r) => r.request.method === 'POST');
    const wrongCreds = (await tab.send('WebAuthn.getCredentials', { authenticatorId: auth4 })).credentials;
    check(wrongCreds.length === 1, 'the browser made a credential for the page at the other host (the relying party is local.test, which it may claim)');
    check(wrongPost?.request.headers.Origin === `https://${OTHER}`, 'the post says its origin is the other host', wrongPost?.request.headers.Origin);
    check(wrong.kind === 'passkey-error', 'the answer is refused: the origin is not in the list of FrontHost', wrong.text.split('\n')[0]);
    await tab.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: auth4 });
    }

    if (want('hold')) {
    // 5c. A held person: at the finish (held after the page was made) and at the callback (held before it).
    const auth5 = await authenticator(tab, { synced: false });
    await toRegistrationPage(tab, s);
    hold.on = true;
    note(`spine hold: ${runSpine('hold')}`);
    await ev(tab, `document.querySelector('button[type=submit]').click(); true`);
    await waitFor(tab, `location.pathname === '/passkeys/register' && !!document.body && document.body.dataset.sluisPage`, 'the answer for the held person');
    const heldFinish = await ev(tab, `document.body.dataset.sluisPage`);
    const heldCreds = (await tab.send('WebAuthn.getCredentials', { authenticatorId: auth5 })).credentials;
    check(heldFinish === 'passkey-error', 'a person held after the page was made is refused at the answer', `${heldCreds.length} credential made by the browser, none stored`);
    await go(tab, `${BASE}/passkeys/add`);
    await keycloak(tab, s);
    await waitFor(tab, `location.pathname === '/callback' && !!document.body && document.body.dataset.sluisPage`, 'the callback for the held person');
    const heldCb = await ev(tab, `({ kind: document.body.dataset.sluisPage, form: !!document.querySelector('form') })`);
    check(heldCb.kind === 'passkey-error' && !heldCb.form, 'a held person gets no registration page at the callback');
    note(`spine unhold: ${runSpine('unhold')}`);
    hold.on = false;
    }

    if (ONLY.length === 0) {
      console.log('\n== 5. What the server decided (the audit log)');
      await auditChecks(auditBefore);
    }
  } finally {
    if (hold.on) { try { runSpine('unhold'); } catch (e) { console.error(`unhold failed: ${e.message}`); } }
    try { note(`spine forget: ${runSpine('forget')}`); } catch (e) { console.error(`forget failed: ${e.message}`); }
    await browser.stop();
    rmSync(dir, { recursive: true, force: true });
  }
  const failed = checks.filter((c) => !c.ok);
  console.log(`\n${checks.length - failed.length} of ${checks.length} checks passed in ${((Date.now() - t0) / 1000).toFixed(0)} s`);
  if (OUT) writeFileSync(OUT, JSON.stringify({ checks, notes }, null, 1));
  if (failed.length) {
    for (const f of failed) console.error(`FAILED: ${f.what} ${f.evidence}`);
    process.exit(1);
  }
}

// What the server decided, not only what the browser was shown: the audit records of the registration steps in the window of this
// run, counted by action and by the reason of the failures (tools/harness/audit-search). Every refusal above is one failure with
// its own reason; the pages are the same for all of them.
const WINDOW = '24h'; // the whole log of the project that the run can see; the checks use the difference from before the run
function auditCounts() {
  if (!existsSync(AUDIT)) throw new Error(`${AUDIT} is missing: build it with go build -o dist/local/audit-search ./tools/harness/audit-search`);
  const out = {};
  for (const action of ['session.passkey_add', 'session.passkey_enrol', 'session.passkey_register']) {
    const r = spawnSync(AUDIT, ['-ca', CA, '-addr', `127.0.0.1:${PORT}`, '-group', '-limit', '1000', `since:${WINDOW}`, `action:${action}`], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`audit-search: ${r.stderr || r.stdout}`);
    for (const l of r.stdout.split('\n')) {
      const m = l.match(/^\s*(\d+)\s+(session\.passkey_\w+)\s+\S+\s*(\S*)\s*$/);
      if (m) out[`${m[2]} ${m[3]}`] = Number(m[1]);
    }
  }
  return out;
}

async function auditChecks(before) {
  const want = [
    ['session.passkey_enrol', 'fresh', 1, 'an authentication that is not from the request'],
    ['session.passkey_enrol', 'held', 1, 'a person held before the page'],
    ['session.passkey_register', 'held', 1, 'a person held after the page'],
    ['session.passkey_register', 'passkey', 2, 'an answer from another origin, and an empty answer'],
    ['session.passkey_register', '', 2, 'the two registrations that succeeded, a device-bound and a synced passkey'],
    ['session.passkey_add', '', 8, 'every request of the run: the five registrations and the exclude-list attempt that reached the identity provider, and the two of the held person'],
    ['session.passkey_enrol', '', 6, 'the registration pages that were shown'],
  ];
  const counts = () => {
    const now = auditCounts();
    const out = {};
    for (const k of new Set([...Object.keys(now), ...Object.keys(before)])) out[k] = (now[k] ?? 0) - (before[k] ?? 0);
    return out;
  };
  const end = Date.now() + 60000; // the writer seals every 5 s and the reader follows
  let got = counts();
  while (Date.now() < end && !want.every(([a, r, n]) => (got[`${a} ${r}`] ?? 0) >= n)) { await sleep(4000); got = counts(); }
  for (const [a, r, n, why] of want) check(got[`${a} ${r}`] === n, r ? `the audit log holds ${n} ${a} failure with the reason ${r}: ${why}` : `the audit log holds ${n} ${a} success: ${why}`, `${got[`${a} ${r}`] ?? 0} (all: ${JSON.stringify(got)})`);
}

function runSpine(cmd) {
  if (!existsSync(SPINE)) throw new Error(`${SPINE} is missing: build it with go build -o dist/local/spine ./tests/e2e/spine`);
  const r = spawnSync(SPINE, [cmd], { encoding: 'utf8', env: process.env });
  if (r.status !== 0) throw new Error(`spine ${cmd}: ${r.stderr || r.stdout}`);
  return r.stdout.trim();
}

main().catch((e) => {
  console.error(`passkey rig: ${e.stack ?? e.message}`);
  process.exit(1);
});
