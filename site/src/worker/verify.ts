// The two ways a caller proves itself to the Worker (ADR 0014):
// - a GitHub webhook delivery carries X-Hub-Signature-256, the HMAC-SHA256 of the raw body
//   under the App's webhook secret (a Worker secret);
// - a CI run on `main` carries a GitHub Actions OIDC token, pinned here to the issuer, the
//   audience, the repository, the branch and the workflow. No secret is stored for it.
const enc = new TextEncoder();

function fromHex(hex: string): Uint8Array | null {
  if (!/^[0-9a-f]*$/i.test(hex) || hex.length % 2) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function fromBase64url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// True when `header` is "sha256=<hex>" and the HMAC matches. crypto.subtle.verify compares
// in constant time.
export async function verifyWebhook(secret: string, body: Uint8Array, header: string | null): Promise<boolean> {
  if (!secret || !header?.startsWith('sha256=')) return false;
  const sig = fromHex(header.slice('sha256='.length));
  if (!sig || sig.length !== 32) return false;
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  return crypto.subtle.verify('HMAC', key, sig, body);
}

export const OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
export const CI_AUDIENCE = 'https://sluis.id/api/ci';
export const CI_REPOSITORY = 'truvity/sluis';
export const CI_REF = 'refs/heads/main';
// The workflows whose runs on `main` may post summaries. Adding one is a reviewed change here.
export const CI_WORKFLOWS = ['.github/workflows/checks.yaml', '.github/workflows/site.yaml'];

export interface Claims {
  iss: string; aud: string | string[]; exp: number; nbf?: number; iat?: number;
  repository: string; ref: string; workflow_ref: string; event_name: string; sha: string; run_id: string;
}

// The claim rules alone, so that they can be tested without a signature. Returns the reason
// a token is refused, or null.
export function claimsProblem(c: Partial<Claims>, now = Math.floor(Date.now() / 1000)): string | null {
  const skew = 60;
  if (c.iss !== OIDC_ISSUER) return 'issuer';
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes(CI_AUDIENCE)) return 'audience';
  if (typeof c.exp !== 'number' || c.exp + skew < now) return 'expired';
  if (typeof c.nbf === 'number' && c.nbf - skew > now) return 'not yet valid';
  if (c.repository !== CI_REPOSITORY) return 'repository';
  if (c.ref !== CI_REF) return 'ref';
  if (c.event_name === 'pull_request' || c.event_name === 'pull_request_target') return 'event';
  if (!CI_WORKFLOWS.some((w) => c.workflow_ref === `${CI_REPOSITORY}/${w}@${CI_REF}`)) return 'workflow';
  return null;
}

type Jwks = { keys: (JsonWebKey & { kid?: string })[] };
let jwks: { at: number; keys: Jwks } | undefined;

async function issuerKeys(refresh: boolean): Promise<Jwks> {
  if (!refresh && jwks && Date.now() - jwks.at < 60 * 60_000) return jwks.keys;
  const res = await fetch(`${OIDC_ISSUER}/.well-known/jwks`, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`the OIDC issuer answered HTTP ${res.status} for its keys`);
  jwks = { at: Date.now(), keys: (await res.json()) as Jwks };
  return jwks.keys;
}

// The claims of a valid token, or the reason it is refused.
export async function verifyOidc(token: string): Promise<{ claims: Claims } | { problem: string }> {
  const parts = token.split('.');
  if (parts.length !== 3) return { problem: 'malformed' };
  let header: { alg?: string; kid?: string };
  let claims: Claims;
  try {
    header = JSON.parse(new TextDecoder().decode(fromBase64url(parts[0])));
    claims = JSON.parse(new TextDecoder().decode(fromBase64url(parts[1])));
  } catch {
    return { problem: 'malformed' };
  }
  if (header.alg !== 'RS256' || !header.kid) return { problem: 'algorithm' };
  let jwk = (await issuerKeys(false)).keys.find((k) => k.kid === header.kid);
  // A key the cache does not know yet: the issuer may have rotated. Read the keys once more.
  jwk ??= (await issuerKeys(true)).keys.find((k) => k.kid === header.kid);
  if (!jwk) return { problem: 'unknown key' };
  const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, n: jwk.n, e: jwk.e }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, fromBase64url(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`));
  if (!ok) return { problem: 'signature' };
  const problem = claimsProblem(claims);
  return problem ? { problem } : { claims };
}
