#!/usr/bin/env node
// Reads the JSON report of `lychee --format json` (see `just site-links`) and decides whether
// the link check fails.
//
// Why this exists: github.com now and then answers CI runners with a 504 for pages that load
// fine a moment later (2026-11-05, two runs, five links; githubstatus.com said all systems
// operational). lychee 0.24.2 sends one request for a 5xx (max_retries covers only network
// errors and timeouts, measured: one hit per 504) and cannot accept a status for one host
// only. So `just site-links` runs lychee, asks this script for the 5xx links, checks those
// again after a wait (twice), and this script merges the reports and decides.
//
//   - a 5xx from github.com or raw.githubusercontent.com that is still there after the
//     repeated checks is a WARNING (an `::warning::` annotation in GitHub Actions); it does
//     not fail;
//   - a 4xx is a broken link: it fails, whatever the host;
//   - a 5xx from any other host fails;
//   - a timeout fails; so does anything this script cannot account for (a report that cannot
//     be read, an exit status other than lychee's 0 and 2, counts that do not match the
//     entries, a check of no link at all).
//
// usage:
//   links-report.mjs retry-urls <report.json>
//       print the URLs of the 5xx errors of a report, one per line (nothing: none to repeat)
//   links-report.mjs merge <report.json> <exit status> [<retry.json> <exit status>]...
//       print the merged report
//   links-report.mjs judge <report.json> <exit status> [<retry.json> <exit status>]...
//       merge the reports (a retry report supersedes the 5xx entries of the ones before it)
//       and judge the result; exit 0 nothing failed (warnings may be printed), 1 something failed.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Hosts whose 5xx is a warning. Exact host names; a subdomain is another host.
export const TOLERATED_5XX_HOSTS = new Set(['github.com', 'raw.githubusercontent.com']);

const hostOf = (url) => {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
};

const is5xx = (e) => Number.isInteger(e.status?.code) && e.status.code >= 500 && e.status.code <= 599;

// The 5xx errors of a report: [{ file, entry }].
const serverErrors = (report) =>
  Object.entries(report?.error_map ?? {}).flatMap(([file, list]) => list.filter(is5xx).map((entry) => ({ file, entry })));

export const retryUrls = (report) => [...new Set(serverErrors(report).map(({ entry }) => entry.url))];

// `retry` is the report of a second check of retryUrls(base). Its answer replaces the 5xx
// entries of base: a link that passed is gone, one that still fails is the retry's entry
// (kept under the file of base). Whatever else base holds stays.
export function merge(base, retry) {
  const urls = new Set(retryUrls(base));
  // A retry that checked fewer links than it was asked to would turn the rest into passes.
  if (typeof retry?.total !== 'number' || retry.total < urls.size) {
    throw new Error(`the repeated check covered ${retry?.total} links, ${urls.size} were asked for`);
  }
  const files = new Map(serverErrors(base).map(({ file, entry }) => [entry.url, file]));
  const error_map = {};
  for (const [file, list] of Object.entries(base.error_map ?? {})) {
    const kept = list.filter((e) => !(is5xx(e) && urls.has(e.url)));
    if (kept.length) error_map[file] = kept;
  }
  const timeout_map = { ...(base.timeout_map ?? {}) };
  const add = (map, list, file) => ((map[file] ??= []), map[file].push(...list));
  for (const list of Object.values(retry.error_map ?? {})) {
    for (const e of list) add(error_map, [e], files.get(e.url) ?? 'unknown');
  }
  for (const list of Object.values(retry.timeout_map ?? {})) {
    for (const e of list) add(timeout_map, [e], files.get(e.url) ?? 'unknown');
  }
  const count = (m) => Object.values(m).reduce((n, l) => n + l.length, 0);
  return { ...base, error_map, timeout_map, errors: count(error_map), timeouts: count(timeout_map) };
}

// report: the parsed JSON of lychee. status: lychee's exit status.
// Returns { errors: [string], warnings: [string], checked: number }.
export function judge(report, status) {
  const errors = [];
  const warnings = [];
  if (status !== 0 && status !== 2) {
    errors.push(`lychee exited with status ${status}, which is neither success (0) nor link errors (2)`);
  }
  if (!report || typeof report !== 'object' || typeof report.total !== 'number') {
    errors.push('the lychee report has no "total": it is not a lychee JSON report');
    return { errors, warnings, checked: 0 };
  }

  let entries = 0;
  for (const [file, list] of Object.entries(report.error_map ?? {})) {
    for (const e of list) {
      entries++;
      const what = `${e.url} (${e.status?.text ?? 'no status'}) in ${file}`;
      if (is5xx(e) && TOLERATED_5XX_HOSTS.has(hostOf(e.url))) {
        warnings.push(`${what}: server error from ${hostOf(e.url)} after the repeated checks, not counted as a dead link`);
      } else {
        errors.push(what);
      }
    }
  }
  for (const [file, list] of Object.entries(report.timeout_map ?? {})) {
    for (const e of list) {
      entries++;
      errors.push(`${e.url} (timeout) in ${file}`);
    }
  }

  // Every error lychee counted must be an entry we judged, or a link could slip through.
  const counted = (report.errors ?? 0) + (report.timeouts ?? 0);
  if (counted !== entries) {
    errors.push(`lychee counted ${counted} errors and timeouts but the report lists ${entries}`);
  }
  if (status === 2 && entries === 0) {
    errors.push('lychee exited with link errors (2) but the report lists none');
  }
  if (report.total === 0) {
    errors.push('lychee checked no link at all; an empty sweep proves nothing');
  }
  return { errors, warnings, checked: report.total };
}

const load = (file) => {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    console.error(`links-report: cannot read ${file}: ${err.message}`);
    process.exit(1);
  }
};

function main() {
  const [cmd, ...args] = process.argv.slice(2);
  if (cmd === 'retry-urls' && args.length === 1) {
    for (const u of retryUrls(load(args[0]))) console.log(u);
    return;
  }
  if ((cmd !== 'judge' && cmd !== 'merge') || args.length < 2 || args.length % 2) {
    console.error('usage: links-report.mjs retry-urls <report.json> | judge|merge <report.json> <status> [<retry.json> <status>]...');
    process.exit(1);
  }
  let report = load(args[0]);
  const statuses = [Number(args[1])];
  for (let i = 2; i < args.length; i += 2) {
    try {
      report = merge(report, load(args[i]));
    } catch (err) {
      console.error(`error: ${err.message}`);
      process.exit(1);
    }
    statuses.push(Number(args[i + 1]));
  }
  if (cmd === 'merge') {
    console.log(JSON.stringify(report));
    return;
  }
  const bad = statuses.find((s) => !Number.isInteger(s) || (s !== 0 && s !== 2));
  const { errors, warnings, checked } = judge(report, bad ?? (args.length > 2 ? 0 : statuses[0]));
  const annotate = process.env.GITHUB_ACTIONS === 'true';
  for (const w of warnings) console.log(annotate ? `::warning title=link check::${w}` : `warning: ${w}`);
  for (const e of errors) console.error(`error: ${e}`);
  if (errors.length) {
    console.error(`links-report: ${errors.length} failed, ${warnings.length} warnings, ${checked} links`);
    process.exit(1);
  }
  console.log(`links-report: ${checked} links, ${warnings.length} warnings, no failures`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
