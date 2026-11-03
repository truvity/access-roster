// The v2 project board, read once per build (ADR 0014) with src/lib/board.ts. The status
// page groups by the options of its `Product milestone` field, so a new or reordered
// option changes the page with no code change; the Worker reads the same board live.
//
// The token is GH_TOKEN or GITHUB_TOKEN from the environment, tried in that order; it is
// sent only to api.github.com and never logged. Reading an organisation's project needs a
// token with that permission: a workstation's `gh auth token` has it, the GITHUB_TOKEN of
// GitHub Actions does not. Without one the build does not fail: it says so in one log line,
// and the page shows that the project data was not available at build time.
import { readBoard, type Board } from './board';

export { FIELD, ORG, PROJECT_NUMBER, REPO, type BoardIssue } from './board';

export type Project = ({ available: true } & Board) | { available: false; reason: string };

let cached: Promise<Project> | undefined;
export function project(): Promise<Project> {
  cached ??= (async () => {
    const tokens = [process.env.GH_TOKEN, process.env.GITHUB_TOKEN].filter((t): t is string => !!t);
    if (!tokens.length) return say({ available: false, reason: 'no GH_TOKEN or GITHUB_TOKEN in the environment' });
    let reason = '';
    for (const token of tokens) {
      try {
        return say({ available: true, ...(await readBoard(token, 'sluis-site-build')) });
      } catch (e) {
        reason = e instanceof Error ? e.message : String(e);
      }
    }
    return say({ available: false, reason });
  })();
  return cached;
}

// One line in the build log, worded so that the strict build (which fails on "warning:")
// does not mistake the expected fallback for a fault.
function say(p: Project): Project {
  if (p.available) console.log(`status page: read the project board (${p.items} items, ${p.issues.length} sluis issues, options: ${p.options.join(' | ')})`);
  else console.log(`status page: project data not available at build time: ${p.reason}`);
  return p;
}
