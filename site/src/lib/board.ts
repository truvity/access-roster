// The v2 project board as plain JSON (ADR 0014): the options of its `Product milestone`
// field, in their order, and every sluis issue on the board with its state, labels and
// milestone. Read with the GitHub GraphQL API and a token given by the caller: the build
// (src/lib/project.ts) passes its own, the Worker (src/worker/) an installation token of
// the read-only GitHub App. Nothing here reads the environment, so both can import it.
export const ORG = 'truvity';
export const PROJECT_NUMBER = 9;
export const FIELD = 'Product milestone';
export const REPO = 'truvity/sluis';

export interface BoardIssue {
  number: number;
  title: string;
  open: boolean;
  labels: string[];
  milestone: string | null;
}

// `project` is the board's node id, which project webhooks name.
export interface Board {
  project: string;
  options: string[];
  issues: BoardIssue[];
  items: number;
}

const QUERY = `query($org: String!, $number: Int!, $field: String!, $after: String) {
  organization(login: $org) {
    projectV2(number: $number) {
      id
      field(name: $field) { ... on ProjectV2SingleSelectField { options { id name } } }
      items(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          content { __typename ... on Issue { number title state labels(first: 50) { nodes { name } } repository { nameWithOwner } } }
          fieldValueByName(name: $field) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
        }
      }
    }
  }
}`;

// At most this many pages of 100 items; a board that grows past it fails closed with a reason.
const MAX_PAGES = 20;

async function page(token: string, userAgent: string, after: string | null) {
  const res = await fetch('https://api.github.com/graphql', {
    method: 'POST',
    headers: { authorization: `bearer ${token}`, 'content-type': 'application/json', 'user-agent': userAgent },
    body: JSON.stringify({ query: QUERY, variables: { org: ORG, number: PROJECT_NUMBER, field: FIELD, after } }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`GitHub GraphQL answered HTTP ${res.status}`);
  const body = (await res.json()) as any;
  const project = body?.data?.organization?.projectV2;
  if (!project) {
    const kinds = [...new Set((body?.errors ?? []).map((e: { type?: string }) => e.type ?? 'error'))].join(', ');
    throw new Error(`the token cannot read the ${ORG} project ${PROJECT_NUMBER}${kinds ? ` (${kinds})` : ''}`);
  }
  return project;
}

// The whole board, issues in number order. Throws with a reason that names no token.
export async function readBoard(token: string, userAgent: string): Promise<Board> {
  const issues = new Map<number, BoardIssue>();
  let options: string[] | null = null;
  let id = '';
  let after: string | null = null;
  let items = 0;
  for (let n = 0; n < MAX_PAGES; n++) {
    const project = await page(token, userAgent, after);
    if (!options) {
      id = project.id;
      options = (project.field?.options ?? []).map((o: { name: string }) => o.name);
      if (!options!.length) throw new Error(`the project has no single-select field "${FIELD}" with options`);
    }
    for (const node of project.items.nodes) {
      items++;
      const c = node.content;
      if (c?.__typename !== 'Issue' || c.repository?.nameWithOwner !== REPO) continue;
      const value: string | null = node.fieldValueByName?.name ?? null;
      issues.set(c.number, {
        number: c.number,
        title: c.title,
        open: c.state === 'OPEN',
        labels: (c.labels?.nodes ?? []).map((l: { name: string }) => l.name),
        milestone: value && options!.includes(value) ? value : null,
      });
    }
    if (!project.items.pageInfo.hasNextPage) {
      return { project: id, options: options!, issues: [...issues.values()].sort((a, b) => a.number - b.number), items };
    }
    after = project.items.pageInfo.endCursor;
  }
  throw new Error(`the project has more than ${MAX_PAGES * 100} items`);
}
