// The live block of the status page (/status/, ADR 0014): swaps the build-time snapshot for
// the same component rendered by the Worker from the live board (/api/status/live/). This
// does what an Astro server island does, from a bundled script: Astro's own island loader
// is an inline script holding a random id and an encrypted token that change on every
// build, which a hash-listed Content-Security-Policy (public/_headers) cannot allow.
//
// The fragment comes from this site and holds no script. It is parsed into a <template>,
// so nothing in it runs. On any failure the snapshot stays, and the note above it says so.
const root = document.querySelector<HTMLElement>('[data-live-src]');
const body = root?.querySelector<HTMLElement>('[data-live-body]');
const note = root?.querySelector<HTMLElement>('[data-live-note]');

async function load(src: string) {
  try {
    const res = await fetch(src, { headers: { accept: 'text/html' }, signal: AbortSignal.timeout(10_000) });
    const type = res.headers.get('content-type')?.split(';')[0].trim();
    if (res.status !== 200 || type !== 'text/html') throw new Error(`HTTP ${res.status}`);
    const t = document.createElement('template');
    t.innerHTML = await res.text();
    if (!t.content.querySelector('.ps-body[data-mode="live"]')) throw new Error('not a live block');
    // Keep the open or closed state of each milestone's details as the reader left it.
    const open = new Map([...body!.querySelectorAll<HTMLDetailsElement>('details[data-group]')].map((d) => [d.dataset.group, d.open]));
    for (const d of t.content.querySelectorAll<HTMLDetailsElement>('details[data-group]')) {
      const was = open.get(d.dataset.group);
      if (was !== undefined) d.open = was;
    }
    body!.replaceChildren(t.content);
    root!.dataset.live = 'live';
    note!.hidden = true;
  } catch {
    root!.dataset.live = 'snapshot';
    note!.hidden = false;
  }
}

if (root && body && note && root.dataset.liveSrc) load(root.dataset.liveSrc);
