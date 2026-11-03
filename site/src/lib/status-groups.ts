// The rows of the status page (/status/, ADR 0014): one group per option of the project's
// `Product milestone` field, in the field's order, then "Unassigned".
//
// Every decision record and every live requirement is in exactly one group, so the groups
// add up to the totals in the page's header (totalsOf below, drawn as the table's last row).
// - An issue belongs to the group of its own milestone value.
// - A requirement belongs to the group of the issues it links (`issues:`); with several, the
//   earliest group in option order. A requirement that links no issue, whose issues are not
//   on the board, or whose issues have no milestone (or one that is not an option) is
//   "Unassigned". Withdrawn requirements are not live and are in no group; out-of-scope
//   ones are live (they are in the header's total) and have their own column.
// - A decision record belongs to the group of its proposal issue, and to "Unassigned" when
//   that issue is not on the board or has no milestone. Records that share a proposal issue
//   are in the same group; each is counted once.
// - A decision still "to write" is an open `type:decision` issue that no record names as
//   its proposal.
// - The current milestone is the first option, in order, that still has open issues.
//
// A pure function of the board and the repository facts, so that the build (with the board
// it reads and the facts it publishes as /data/repo.json) and the Worker (with the board in
// KV and the deployed /data/repo.json) compute the same groups. Without a board every
// requirement and record is "Unassigned", and the issue figures are unknown (null).
// This module imports nothing at run time: site/scripts/check-worker.mjs runs it in Node.

export const NO_MILESTONE = 'Unassigned';
export const LABEL_DECISION = 'type:decision';
export const LABEL_BLOCKED = 'status:blocked';
export const LABEL_NEEDS_DECISION = 'status:needs-decision';

export interface BoardIssue { number: number; title: string; open: boolean; labels: string[]; milestone: string | null }
export interface BoardLike { options: string[]; issues: BoardIssue[] }

// The facts of /data/repo.json that the groups need (src/lib/repo.ts writes them).
export interface DecisionFact { id: string; number: string; title: string; status: string; proposal: number | null }
export interface RequirementFact { id: string; area: string; status: string; issues: number[]; auto: boolean }
export interface RepoLike { decisions: DecisionFact[]; requirements: RequirementFact[] }

export interface ReqCounts { total: number; open: number; planned: number; partial: number; done: number; outOfScope: number; auto: number }
export interface AreaRow { code: string; counts: ReqCounts }
export interface Group {
  name: string;
  slug: string;
  milestone: boolean;
  current: boolean;
  reqs: ReqCounts;
  areas: AreaRow[];
  adrs: { accepted: number; proposed: number; other: number; toWrite: number | null; records: DecisionFact[] };
  issues: { open: number; closed: number; blocked: number; needsDecision: number } | null;
  openDecisionIssues: BoardIssue[];
  otherOpenIssues: BoardIssue[];
}

// The status family a record counts under on the status page.
export const isAccepted = (status: string) => status.startsWith('Accepted');
export const isProposed = (status: string) => status === 'Proposed';
// A requirement the status page counts: every live one, that is, not withdrawn. This is the
// header's figure (coverage().all.requirements in src/lib/requirements.ts).
export const counted = (r: { status: string }) => r.status !== 'withdrawn';

const countReqs = (rs: RequirementFact[]): ReqCounts => ({
  total: rs.length,
  open: rs.filter((r) => r.status === 'open').length,
  planned: rs.filter((r) => r.status === 'planned').length,
  partial: rs.filter((r) => r.status === 'partial').length,
  done: rs.filter((r) => r.status === 'done').length,
  outOfScope: rs.filter((r) => r.status === 'out-of-scope').length,
  auto: rs.filter((r) => r.auto).length,
});

export const slugOf = (name: string) => name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'group';

export function groupStatus(board: BoardLike | null, repo: RepoLike): Group[] {
  const options = board ? board.options : [];
  const names = [...options, NO_MILESTONE];
  const last = names.length - 1;
  const byNumber = new Map((board?.issues ?? []).map((i) => [i.number, i]));
  const indexOfIssue = (n: number | null) => {
    const m = n === null ? null : byNumber.get(n)?.milestone;
    const k = m ? options.indexOf(m) : -1;
    return k < 0 ? last : k;
  };
  // Areas in catalogue order: the order in which the requirements name them.
  const areaCodes = [...new Set(repo.requirements.map((r) => r.area))];

  const reqsBy = names.map(() => [] as RequirementFact[]);
  for (const r of repo.requirements.filter(counted)) reqsBy[Math.min(last, ...r.issues.map(indexOfIssue))].push(r);

  const recordsBy = names.map(() => [] as DecisionFact[]);
  for (const d of repo.decisions) recordsBy[indexOfIssue(d.proposal)].push(d);
  const proposals = new Set(repo.decisions.map((d) => d.proposal).filter((n) => n !== null));

  const issuesBy = names.map(() => [] as BoardIssue[]);
  for (const i of board?.issues ?? []) issuesBy[indexOfIssue(i.number)].push(i);

  const sortByNumber = (a: BoardIssue, b: BoardIssue) => a.number - b.number;
  const decisionIssue = (i: BoardIssue) => i.labels.includes(LABEL_DECISION);
  const groups: Group[] = names.map((name, gi) => {
    const rs = reqsBy[gi];
    const is = issuesBy[gi];
    const open = is.filter((i) => i.open).sort(sortByNumber);
    return {
      name,
      slug: slugOf(name),
      milestone: gi < last,
      current: false,
      reqs: countReqs(rs),
      areas: areaCodes
        .map((code) => ({ code, counts: countReqs(rs.filter((r) => r.area === code)) }))
        .filter((a) => a.counts.total > 0),
      adrs: {
        accepted: recordsBy[gi].filter((d) => isAccepted(d.status)).length,
        proposed: recordsBy[gi].filter((d) => isProposed(d.status)).length,
        other: recordsBy[gi].filter((d) => !isAccepted(d.status) && !isProposed(d.status)).length,
        toWrite: board ? open.filter((i) => decisionIssue(i) && !proposals.has(i.number)).length : null,
        records: recordsBy[gi],
      },
      issues: board
        ? {
            open: open.length,
            closed: is.length - open.length,
            blocked: open.filter((i) => i.labels.includes(LABEL_BLOCKED)).length,
            needsDecision: open.filter((i) => i.labels.includes(LABEL_NEEDS_DECISION)).length,
          }
        : null,
      openDecisionIssues: open.filter(decisionIssue),
      otherOpenIssues: open.filter((i) => !decisionIssue(i)),
    };
  });
  const current = groups.find((g) => g.milestone && g.issues && g.issues.open > 0);
  if (current) current.current = true;
  return groups;
}

// The sums of the groups, which must equal the page's header: `records` is every decision
// record and `requirements` every live requirement (see the rules at the top).
export interface Totals { reqs: ReqCounts; records: number; accepted: number; proposed: number; other: number; toWrite: number | null }
export function totalsOf(groups: Group[]): Totals {
  const sum = (f: (g: Group) => number) => groups.reduce((n, g) => n + f(g), 0);
  return {
    reqs: {
      total: sum((g) => g.reqs.total), open: sum((g) => g.reqs.open), planned: sum((g) => g.reqs.planned),
      partial: sum((g) => g.reqs.partial), done: sum((g) => g.reqs.done), outOfScope: sum((g) => g.reqs.outOfScope), auto: sum((g) => g.reqs.auto),
    },
    records: sum((g) => g.adrs.records.length),
    accepted: sum((g) => g.adrs.accepted),
    proposed: sum((g) => g.adrs.proposed),
    other: sum((g) => g.adrs.other),
    toWrite: groups.some((g) => g.adrs.toWrite === null) ? null : sum((g) => g.adrs.toWrite ?? 0),
  };
}
