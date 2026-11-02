import { getCollection, type CollectionEntry } from 'astro:content';

type Decision = CollectionEntry<'decisions'>;

// The file every record is copied from; it is not a decision.
export const TEMPLATE_ID = '0000-template';

// The records, without the template and without the placeholder the loader
// keeps in an empty collection.
export async function listDecisions(): Promise<Decision[]> {
  const entries = await getCollection('decisions');
  return entries
    .filter((entry) => !entry.id.startsWith('_') && entry.id !== TEMPLATE_ID)
    .sort((a, b) => a.id.localeCompare(b.id));
}

// The title of an ADR: its front matter, else its first level-one heading,
// else its file name.
export function decisionTitle(entry: Decision): string {
  if (entry.data.title) return entry.data.title;
  const heading = /^#\s+(.+)$/m.exec(entry.body ?? '');
  return heading ? heading[1].trim() : entry.id;
}

// Starlight's page description must be a sentence; fall back to a fixed one.
export function decisionDescription(entry: Decision): string {
  return entry.data.description ?? `Architecture decision record ${entry.id} for sluis.`;
}

export const sourceUrl = (entry: Decision): string =>
  `https://github.com/truvity/sluis/blob/main/docs/decisions/${entry.id}.md`;

export const editUrl = (entry: Decision): string =>
  `https://github.com/truvity/sluis/edit/main/docs/decisions/${entry.id}.md`;

// A record keeps its status and date as the `**Status:**` and `**Date:**` lines
// under its heading (docs/decisions/README.md, checked by tools/checks/decisions.mjs),
// and links its proposal issue in the context as "Proposal: [issue #N](...)".
const field = (body: string, name: string): string | undefined =>
  new RegExp(`^\\*\\*${name}:\\*\\*\\s*(.+?)\\s*$`, 'm').exec(body)?.[1];

// The layer of the product a record belongs to (docs/decisions/README.md, "Layer."): the
// optional `**Layer:**` line, and core when there is none. It is not part of the facts the
// build publishes as /data/repo.json, which the status page's rules use.
export const decisionLayer = (entry: Decision): string => field(entry.body ?? '', 'Layer') ?? 'core';

export interface DecisionFacts {
  id: string;
  number: string;
  title: string;
  status: string;
  date: string | null;
  proposal: number | null;
  url: string;
}

export function decisionFacts(entry: Decision): DecisionFacts {
  const body = entry.body ?? '';
  const proposal = /Proposal:\s*\[issue #(\d+)\]/.exec(body)?.[1];
  const date = field(body, 'Date');
  return {
    id: entry.id,
    number: entry.id.slice(0, 4),
    title: decisionTitle(entry).replace(/^\d{4}\s+[—-]\s+/, ''),
    status: entry.data.status ?? field(body, 'Status') ?? 'Unknown',
    date: date && /^\d{4}-\d{2}-\d{2}$/.test(date) ? date : null,
    proposal: proposal ? Number(proposal) : null,
    url: `https://sluis.id/decisions/${entry.id}/`,
  };
}

// The status family a record counts under on the status page.
export { isAccepted, isProposed } from './lib/status-groups';
