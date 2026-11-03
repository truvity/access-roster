// The rows of the status page (/status/, ADR 0014): one group per option of the project's
// `Product milestone` field, in the field's order, then "Not in a milestone".
//
// - An issue belongs to the group of its own milestone value.
// - A requirement belongs to the group of the issues it links (`issues:`); with several, the
//   earliest group in option order. A requirement whose issues have no milestone, or that
//   links none, is "Not in a milestone".
// - A decision record belongs to the group of its proposal issue.
// - A decision still "to write" is an open `type:decision` issue that no record names as
//   its proposal.
// - The current milestone is the first option, in order, that still has open issues.
//
// A pure function of the board and the repository facts, so that the build (with the board
// it reads and the facts it publishes as /data/repo.json) and the Worker (with the board in
// KV and the deployed /data/repo.json) compute the same groups. Without a board every
// requirement and record is "Not in a milestone", and the issue figures are unknown (null).
// This module imports nothing at run time: site/scripts/check-worker.mjs runs it in Node.

export const NO_MILESTONE = 'Not in a milestone';
export const LABEL_DECISION = 'type:decision';
export const LABEL_BLOCKED = 'status:blocked';
export const LABEL_NEEDS_DECISION = 'status:needs-decision';

export interface BoardIssue { number: number; title: string; open: boolean; labels: string[]; milestone: string | null }
export interface BoardLike { options: string[]; issues: BoardIssue[] }

// The facts of /data/repo.json that the groups need (src/lib/repo.ts writes them).
export interface DecisionFact { id: string; number: string; title: string; status: string; proposal: number | null }
export interface RequirementFact { id: string; area: string; status: string; issues: number[]; auto: boolean }
export interface RepoLike { decisions: DecisionFact[]; requirements: RequirementFact[] }

export interface ReqCounts { total: number; open: number; planned: number; partial: number; done: number; auto: number }
export interface AreaRow { code: string; counts: ReqCounts }
export interface Group {
  name: string;
  slug: string;
  milestone: boolean;
  current: boolean;
  reqs: ReqCounts;
  areas: AreaRow[];
  adrs: { accepted: number; proposed: number; toWrite: number | null; records: DecisionFact[] };
  issues: { open: number; closed: number; blocked: number; needsDecision: number } | null;
  openDecisionIssues: BoardIssue[];
  otherOpenIssues: BoardIssue[];
}

// The status family a record counts under on the status page.
export const isAccepted = (status: string) => status.startsWith('Accepted');
export const isProposed = (status: string) => status === 'Proposed';
// A record the status page counts: not withdrawn and not a refusal kept as out of scope.
export const counted = (r: { status: string }) => r.status !== 'withdrawn' && r.status !== 'out-of-scope';

const countReqs = (rs: RequirementFact[]): ReqCounts => ({
  total: rs.length,
  open: rs.filter((r) => r.status === 'open').length,
  planned: rs.filter((r) => r.status === 'planned').length,
  partial: rs.filter((r) => r.status === 'partial').length,
  done: rs.filter((r) => r.status === 'done').length,
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
    return m ? options.indexOf(m) : last;
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
