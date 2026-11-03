// The Worker's read access to GitHub (ADR 0014): an installation token of the read-only
// GitHub App, minted from the App's private key, which is a Worker secret. The token lives
// in this isolate's memory until shortly before it expires, and is never logged or stored.
//
// GitHub hands out App keys as PKCS#1 PEM ("BEGIN RSA PRIVATE KEY"); Web Crypto imports
// only PKCS#8, so a PKCS#1 key is wrapped in the PKCS#8 structure here. A PKCS#8 PEM
// ("BEGIN PRIVATE KEY", as `openssl pkcs8 -topk8 -nocrypt` writes it) is taken as it is.
export const API = 'https://api.github.com';
export const USER_AGENT = 'sluis-site-worker';
const OWNER = 'truvity';
const REPO = 'sluis';

// The permissions the Worker asks for: read-only, and only what the status page shows.
const PERMISSIONS = { issues: 'read', organization_projects: 'read', actions: 'read', metadata: 'read' };

const enc = new TextEncoder();
const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlJson = (v: unknown) => b64url(enc.encode(JSON.stringify(v)));

function fromBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// A DER length: short form below 128, long form above.
function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return [0x80 | bytes.length, ...bytes];
}
const der = (tag: number, body: Uint8Array) => new Uint8Array([tag, ...derLength(body.length), ...body]);

// PKCS#8 PrivateKeyInfo around a PKCS#1 RSAPrivateKey: version 0, the rsaEncryption
// algorithm identifier with NULL parameters, and the key as an OCTET STRING.
export function pkcs1ToPkcs8(pkcs1: Uint8Array): Uint8Array {
  const version = [0x02, 0x01, 0x00];
  const algorithm = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  const key = der(0x04, pkcs1);
  return der(0x30, new Uint8Array([...version, ...algorithm, ...key]));
}

// The DER bytes of a PEM private key, as PKCS#8.
export function pemToPkcs8(pem: string): Uint8Array {
  const m = /-----BEGIN (RSA )?PRIVATE KEY-----([\s\S]+?)-----END (RSA )?PRIVATE KEY-----/.exec(pem.replace(/\\n/g, '\n'));
  if (!m) throw new Error('the GitHub App private key is not a PEM private key');
  const bytes = fromBase64(m[2].replace(/\s+/g, ''));
  return m[1] ? pkcs1ToPkcs8(bytes) : bytes;
}

// A GitHub App JWT (RS256), valid for nine minutes and back-dated one minute for clock skew.
export async function appJwt(clientId: string, pem: string, now = Math.floor(Date.now() / 1000)): Promise<string> {
  const key = await crypto.subtle.importKey('pkcs8', pemToPkcs8(pem), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const signing = `${b64urlJson({ alg: 'RS256', typ: 'JWT' })}.${b64urlJson({ iat: now - 60, exp: now + 540, iss: clientId })}`;
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(signing)));
  return `${signing}.${b64url(sig)}`;
}

export interface AppSecrets { GITHUB_APP_CLIENT_ID?: string; GITHUB_APP_PRIVATE_KEY?: string }

let cached: { token: string; expires: number } | undefined;

// An installation token for the repository, from this isolate's cache when it has more
// than five minutes left. Throws with a reason that holds no secret.
export async function installationToken(env: AppSecrets): Promise<string> {
  if (cached && cached.expires - Date.now() > 5 * 60_000) return cached.token;
  if (!env.GITHUB_APP_CLIENT_ID || !env.GITHUB_APP_PRIVATE_KEY) throw new Error('the GitHub App secrets of the Worker are not set');
  const jwt = await appJwt(env.GITHUB_APP_CLIENT_ID, env.GITHUB_APP_PRIVATE_KEY);
  const headers = { authorization: `Bearer ${jwt}`, accept: 'application/vnd.github+json', 'user-agent': USER_AGENT, 'x-github-api-version': '2022-11-28' };
  const inst = await fetch(`${API}/repos/${OWNER}/${REPO}/installation`, { headers, signal: AbortSignal.timeout(15_000) });
  if (!inst.ok) throw new Error(`GitHub answered HTTP ${inst.status} for the App's installation`);
  const { id } = (await inst.json()) as { id: number };
  const res = await fetch(`${API}/app/installations/${id}/access_tokens`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({ repositories: [REPO], permissions: PERMISSIONS }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`GitHub answered HTTP ${res.status} for an installation token`);
  const body = (await res.json()) as { token: string; expires_at: string };
  cached = { token: body.token, expires: Date.parse(body.expires_at) };
  return body.token;
}

// The latest run of each workflow on `main`, read with a conditional request: when the
// ETag still matches, GitHub answers 304, which costs no rate limit, and `runs` is null.
export interface Run { workflow: string; status: string; conclusion: string | null; url: string; sha: string; at: string }
export async function mainRuns(token: string, etag: string | null): Promise<{ runs: Run[] | null; etag: string | null }> {
  const headers: Record<string, string> = {
    authorization: `Bearer ${token}`,
    accept: 'application/vnd.github+json',
    'user-agent': USER_AGENT,
    'x-github-api-version': '2022-11-28',
  };
  if (etag) headers['if-none-match'] = etag;
  const res = await fetch(`${API}/repos/${OWNER}/${REPO}/actions/runs?branch=main&exclude_pull_requests=true&per_page=50`, {
    headers,
    signal: AbortSignal.timeout(15_000),
  });
  if (res.status === 304) return { runs: null, etag };
  if (!res.ok) throw new Error(`GitHub answered HTTP ${res.status} for the workflow runs`);
  const body = (await res.json()) as { workflow_runs: any[] };
  const latest = new Map<string, Run>();
  for (const r of body.workflow_runs ?? []) {
    if (r.head_branch !== 'main' || latest.has(r.name)) continue;
    latest.set(r.name, { workflow: r.name, status: r.status, conclusion: r.conclusion ?? null, url: r.html_url, sha: r.head_sha, at: r.updated_at });
  }
  const runs = [...latest.values()].sort((a, b) => a.workflow.localeCompare(b.workflow));
  return { runs, etag: res.headers.get('etag') };
}
