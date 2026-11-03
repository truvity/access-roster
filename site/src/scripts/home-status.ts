// The figures of the home page's status block (src/components/home/HomeStatus.astro), read
// from the site's status API (/api/status, ADR 0014) in place of the build-time ones. The
// answer is JSON from this origin and is written with textContent, never as markup. On any
// failure the build-time figures stay and the note under them says where they come from.
const root = document.querySelector<HTMLElement>('[data-home-status]');
const cell = (name: string) => root?.querySelector<HTMLElement>(`[data-f="${name}"]`) ?? null;

interface Milestone {
  name: string;
  current: boolean;
  issues: { open: number | null; closed: number | null };
  decisions: { accepted: number };
}

const fmt = (n: number | null | undefined) => (typeof n === 'number' ? String(n) : '–');

async function load() {
  try {
    const res = await fetch('/api/status', { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(10_000) });
    const type = res.headers.get('content-type')?.split(';')[0].trim();
    if (res.status !== 200 || type !== 'application/json') throw new Error(`HTTP ${res.status}`);
    const live = await res.json();
    const ms: Milestone[] = live.milestones;
    const current = ms.find((m) => m.current);
    if (!Array.isArray(ms) || !current) throw new Error('no current milestone');
    cell('milestone')!.textContent = current.name;
    cell('closed')!.textContent = fmt(current.issues.closed);
    cell('open')!.textContent = fmt(current.issues.open);
    cell('accepted')!.textContent = fmt(ms.reduce((n, m) => n + m.decisions.accepted, 0));
    const asOf = String(live.asOf).replace('T', ' ').replace(/:\d{2}Z$/, ' UTC');
    cell('note')!.textContent = `Live figures from the status API, as of ${asOf}. The issue figures are those of the current milestone; the decision records are counted across every milestone.`;
  } catch {
    // The build-time figures stay, and so does the note that says so.
  }
}

if (root) load();
