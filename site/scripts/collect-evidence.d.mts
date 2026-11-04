export interface TaggedTest { file: string; line: number; test: string; via: 'comment' | 'subtest' }
export const SCAN_DIRS: string[];
export function idsIn(text: string): string[];
export function scanGo(text: string, file: string): Array<TaggedTest & { id: string }>;
export function scanRust(text: string, file: string): Array<TaggedTest & { id: string }>;
export function collectEvidence(repoRoot: string): { files: number; tests: number; evidence: Map<string, TaggedTest[]> };
export function toJson(r: { files: number; tests: number; evidence: Map<string, TaggedTest[]> }): unknown;
