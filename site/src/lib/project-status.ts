// The status page's groups at build time (/status/, ADR 0014): the board as read during the
// build (src/lib/project.ts) joined with the repository facts the build publishes as
// /data/repo.json (src/lib/repo.ts). The rules are in src/lib/status-groups.ts, which the
// Worker's live block applies to the board in KV and the deployed /data/repo.json.
import { project } from './project';
import { BUILT_AT, repoFacts } from './repo';
import { groupStatus } from './status-groups';

export async function statusGroups() {
  const board = await project();
  const repo = await repoFacts(BUILT_AT);
  return { board, groups: groupStatus(board.available ? board : null, repo) };
}
