// The data part of the status page (ADR 0014) as HTML: the milestone cards, the ledger, the
// checks on `main` and the open work. One renderer for both places it is drawn:
// - at build time, src/pages/status.astro puts the snapshot of the board into the page;
// - in the Worker, /api/status/live/ draws the same from the board in KV, and the page's
//   script (src/scripts/status-live.ts) swaps it in.
// The Worker is a plain module bundled by Wrangler, not an Astro server, so this is a
// function of its inputs with no Astro component in it. The styles are
// src/styles/project-status.css, which /status/ loads. It imports nothing at run time:
// site/scripts/check-worker.mjs runs it in Node.
import type { Group, ReqCounts } from './status-groups.ts';

export interface Run { workflow: string; status: string; conclusion: string | null; url: string; sha: string; at: string }
export interface BodyInput {
  groups: Group[];
  mode: 'snapshot' | 'live';
  // When the data is as of, ISO 8601 UTC.
  asOf: string;
  // Whether the board was read; the snapshot of a build without a token has no issue data.
  available: boolean;
  runs?: Run[] | null;
  coverage?: { percent: number; sha: string; at: string } | null;
  conformance?: { passing: number; total: number; sha: string; at: string } | null;
}

const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
export const esc = (v: unknown) => String(v).replace(/[&<>"']/g, (c) => ESC[c]);
const cls = (...names: (string | false | null | undefined)[]) => names.filter(Boolean).join(' ');

export const utc = (iso: string) => iso.replace('T', ' ').replace(/:\d{2}(\.\d+)?Z$/, ' UTC');
const ISSUES = 'https://github.com/truvity/sluis/issues/';
const COMMITS = 'https://github.com/truvity/sluis/commit/';
const shortSha = (sha: string) => (/^[0-9a-f]{7,40}$/.test(sha) ? sha.slice(0, 7) : '');
const COLS = 1 + 6 + 3 + 4;

const tag = (text: string, kind: 'live' | 'build' | 'current') => `<span class="ps-tag ps-tag-${kind}">${esc(text)}</span>`;
const num = (v: number | null, first: boolean, title?: string) =>
  v === null
    ? `<td class="${cls('ps-num', 'ps-zero', first && 'ps-first')}"${title ? ` title="${esc(title)}"` : ''}>—</td>`
    : `<td class="${cls('ps-num', first && 'ps-first', v === 0 && 'ps-zero')}">${esc(v)}</td>`;
const reqCells = (c: ReqCounts) => [c.total, c.open, c.planned, c.partial, c.done, c.auto].map((v, k) => num(v, k === 0)).join('');
const frac = (a: number, b: number) => (b ? Math.round((100 * a) / b) : 0);
const label = (g: Group, i: number) => (g.milestone ? `${i + 1}. ${g.name}` : g.name);
const runState = (r: Run) => (r.status === 'completed' ? (r.conclusion ?? 'completed') : r.status.replace(/_/g, ' '));
const runFailed = (r: Run) => r.status === 'completed' && !['success', 'skipped', 'neutral'].includes(r.conclusion ?? '');

// A bar group on a milestone card: a heading that says what the bars measure, and the bars.
// Design and Build are drawn apart and named, so that a record or a requirement decided on
// paper is never read as code that runs.
type Bar = [label: string, value: number, total: number];
function barGroup(kind: 'design' | 'build', head: string, sub: string, summary: string, bars: Bar[]): string {
  return `<div class="ps-bargroup ps-bargroup-${kind}" role="group" aria-label="${esc(summary)}">`
    + `<p class="ps-bars-k">${esc(head)} <span class="ps-bars-s">${esc(sub)}</span></p>`
    + `<dl class="ps-bars">${bars.map(([k, a, b]) =>
      `<div><dt>${esc(k)}</dt><dd><meter class="ps-meter" min="0" max="${b || 1}" value="${a}" aria-hidden="true">${frac(a, b)}%</meter>`
      + `<span class="ps-v">${a} of ${b}</span></dd></div>`).join('')}</dl></div>`;
}

function cards(groups: Group[]): string {
  const milestones = groups.filter((g) => g.milestone && g.issues);
  if (!milestones.length) return '';
  const items = milestones.map((g, i) => {
    const iss = g.issues!;
    // Design: what is decided on paper. A requirement is decided once it is no longer open
    // (planned, partial or done); an ADR is accepted, out of accepted, proposed and to write.
    const adrTotal = g.adrs.accepted + g.adrs.proposed + (g.adrs.toWrite ?? 0);
    const decided = g.reqs.total - g.reqs.open;
    const design = barGroup('design', 'Design', 'decided on paper, not built',
      `Design: ${g.adrs.accepted} of ${adrTotal} ADRs accepted, ${decided} of ${g.reqs.total} requirements decided`,
      [['ADRs accepted', g.adrs.accepted, adrTotal], ['Requirements decided', decided, g.reqs.total]]);
    // Build: requirements marked done (set by hand in the pull request that adds the passing
    // tests), and the issues closed, which also count decision issues.
    const build = barGroup('build', 'Build', 'code and tests',
      `Build: ${g.reqs.done} of ${g.reqs.total} requirements done, ${iss.closed} of ${iss.open + iss.closed} issues closed`,
      [['Requirements done', g.reqs.done, g.reqs.total], ['Issues closed', iss.closed, iss.open + iss.closed]]);
    return `<article class="${cls('ps-card', g.current && 'ps-current')}" aria-labelledby="card-${esc(g.slug)}">`
      + `<p class="ps-card-k">Milestone ${i + 1}${g.current ? ' · <strong>current</strong>' : ''}</p>`
      + `<p class="ps-card-n" id="card-${esc(g.slug)}"><a href="#${esc(g.slug)}">${esc(g.name)}</a></p>`
      + design + build + '</article>';
  });
  return `<section class="ps-cards" aria-label="Milestones at a glance">${items.join('')}</section>`;
}

function ledger(groups: Group[], when: string): string {
  const head = '<thead><tr class="ps-groups">'
    + '<th scope="col" rowspan="2">Milestone / area</th>'
    + `<th scope="colgroup" colspan="6">Requirements ${tag('build-time', 'build')}</th>`
    + `<th scope="colgroup" colspan="3">ADRs ${tag('build-time', 'build')}</th>`
    + `<th scope="colgroup" colspan="4">Issues ${tag('live', 'live')}<span class="ps-asof">${esc(when)}</span></th>`
    + '</tr><tr>'
    + '<th scope="col" class="ps-first" title="Not withdrawn and not out of scope">Total</th>'
    + '<th scope="col" title="status: open, not decided yet">Undecided</th>'
    + '<th scope="col" title="status: planned">Planned</th>'
    + '<th scope="col" title="status: partial">Partial</th>'
    + '<th scope="col" title="status: done, set by hand in the pull request that adds the passing tests">Done</th>'
    + '<th scope="col" title="Has a verification other than manual review">Auto-verifiable</th>'
    + '<th scope="col" class="ps-first">Accepted</th>'
    + '<th scope="col">Proposed</th>'
    + '<th scope="col" title="An open type:decision issue with no record yet">To write</th>'
    + '<th scope="col" class="ps-first">Open</th>'
    + '<th scope="col">Closed</th>'
    + '<th scope="col" title="Open, labelled status:blocked">Blocked</th>'
    + '<th scope="col" title="Open, labelled status:needs-decision">Needs decision</th>'
    + '</tr></thead>';
  const NA = 'project data not available';
  const bodies = groups.map((g, i) => {
    const issues = g.issues ? [g.issues.open, g.issues.closed, g.issues.blocked, g.issues.needsDecision] : [null, null, null, null];
    const row = `<tr class="ps-group-row"><th scope="rowgroup" id="${esc(g.slug)}">${esc(label(g, i))}${g.current ? ` ${tag('current milestone', 'current')}` : ''}</th>`
      + reqCells(g.reqs)
      + [g.adrs.accepted, g.adrs.proposed, g.adrs.toWrite].map((v, k) => num(v, k === 0, NA)).join('')
      + issues.map((v, k) => num(v, k === 0, NA)).join('')
      + '</tr>';
    const areas = g.areas.map((a) => `<tr class="ps-area-row"><th scope="row"><a href="/requirements/${esc(a.code.toLowerCase())}/">${esc(a.code)}</a></th>`
      + reqCells(a.counts)
      + Array.from({ length: COLS - 7 }, (_, k) => `<td class="${cls('ps-num', 'ps-zero', [0, 3].includes(k) && 'ps-first')}">—</td>`).join('')
      + '</tr>');
    return `<tbody class="${cls('ps-group', g.current && 'ps-current', !g.milestone && 'ps-none-group')}" data-group="${esc(g.name)}">${row}${areas.join('')}</tbody>`;
  });
  return '<div class="ps-wrap" tabindex="0" role="region" aria-labelledby="ps-caption"><table class="ps-table">'
    + `<caption id="ps-caption">Status by milestone and requirement area: requirements and ADRs from the build, issues ${esc(when)}</caption>`
    + '<colgroup><col class="ps-col-name" /></colgroup><colgroup span="6" class="ps-cg"></colgroup><colgroup span="3" class="ps-cg"></colgroup><colgroup span="4" class="ps-cg"></colgroup>'
    + head + bodies.join('') + '</table></div>'
    + '<p class="ps-note">Area rows count requirements only; decision records and issues are counted per milestone.</p>';
}

function checks(input: BodyInput): string {
  const live = input.mode === 'live';
  const none = (text: string) => `<span class="ps-none">${text}</span>`;
  const at = (sha: string, when: string) => {
    const s = shortSha(sha);
    return ` <span class="ps-state">${s ? `at <a href="${COMMITS}${esc(sha)}">${s}</a>, ` : ''}${esc(utc(when))}</span>`;
  };
  const runs = !live
    ? none('Read live; not part of the build-time snapshot.')
    : !input.runs?.length
      ? none('No workflow run on <code>main</code> was read.')
      : `<ul class="ps-chips">${input.runs.map((r) => `<li><a class="${cls('ps-chip', runFailed(r) && 'ps-blocked')}" href="${esc(r.url)}">${esc(r.workflow)} `
        + `<span class="ps-state">${esc(runState(r))}${shortSha(r.sha) ? ` · ${shortSha(r.sha)}` : ''} · ${esc(utc(r.at))}</span></a></li>`).join('')}</ul>`;
  const coverage = input.coverage ? `<span>${esc(input.coverage.percent)}%${at(input.coverage.sha, input.coverage.at)}</span>` : none('No CI data yet.');
  const conformance = input.conformance
    ? `<span>${esc(input.conformance.passing)} of ${esc(input.conformance.total)}${at(input.conformance.sha, input.conformance.at)}</span>`
    : none('No CI data yet.');
  const item = (title: string, value: string) => `<div><dt>${title} ${tag('live', 'live')}</dt><dd>${value}</dd></div>`;
  return '<h2 id="checks">Checks on main</h2><dl class="ps-checks">'
    + item('CI on <code>main</code>', runs) + item('Test coverage', coverage) + item('Conformance suites passing', conformance)
    + '</dl>';
}

function openWork(groups: Group[], when: string, available: boolean): string {
  const chip = (href: string, no: string, title: string, state: string, blocked = false) =>
    `<li><a class="${cls('ps-chip', blocked && 'ps-blocked')}" href="${esc(href)}"><span class="ps-no">${esc(no)}</span> ${esc(title)} <span class="ps-state">${esc(state)}</span></a></li>`;
  const list = (items: string[]) => (items.length ? `<ul class="ps-chips">${items.join('')}</ul>` : '<p class="ps-none">None.</p>');
  const issueState = (labels: string[]) =>
    labels.includes('status:blocked') ? 'open, blocked' : labels.includes('status:needs-decision') ? 'open, needs decision' : 'open';
  const details = groups.map((g, i) => {
    const counts = g.issues ? `${g.openDecisionIssues.length} open ADR issues, ${g.otherOpenIssues.length} other open issues` : 'issues not available';
    const summary = `<summary><strong>${esc(label(g, i))}</strong>${g.current ? ` ${tag('current milestone', 'current')}` : ''}`
      + `<span class="ps-asof">${esc(counts)} · ${esc(when)}</span></summary>`;
    const issues = !g.issues
      ? `<p>Project data not available${available ? '' : ' at build time'}.</p>`
      : `<p class="ps-chips-k">Open ADR issues (${g.openDecisionIssues.length})</p>`
        + list(g.openDecisionIssues.map((x) => chip(`${ISSUES}${x.number}`, `#${x.number}`, x.title, 'open')))
        + `<p class="ps-chips-k">Other open issues (${g.otherOpenIssues.length})</p>`
        + list(g.otherOpenIssues.map((x) => chip(`${ISSUES}${x.number}`, `#${x.number}`, x.title, issueState(x.labels), x.labels.includes('status:blocked'))));
    const records = g.adrs.records.length
      ? `<p class="ps-chips-k">Decision records (${g.adrs.records.length})</p>`
        + list(g.adrs.records.map((d) => chip(`/decisions/${d.id}/`, d.number, d.title, d.status)))
      : '';
    return `<details class="${cls('ps-detail', g.current && 'ps-current')}"${g.current ? ' open' : ''} data-group="${esc(g.name)}">${summary}${issues}${records}</details>`;
  });
  return `<h2 id="open-work">Open work by milestone</h2>${details.join('')}`;
}

export function statusBodyHtml(input: BodyInput): string {
  const when = input.mode === 'live' ? `live, as of ${utc(input.asOf)}` : `snapshot as of ${utc(input.asOf)}`;
  return `<div class="ps-body" data-mode="${input.mode}" data-as-of="${esc(input.asOf)}">`
    + cards(input.groups) + ledger(input.groups, when) + checks(input) + openWork(input.groups, when, input.available)
    + '</div>';
}
