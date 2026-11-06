#!/usr/bin/env node
// Reads the JSON report of `lychee --format json` (see `just site-links`) and decides whether
// the link check fails.
//
// Why this exists: external sites now and then fail a runner for a moment and answer fine later.
// github.com answered CI runners with a 504 for pages that loaded a moment later (2026-11-05, two
// runs, five links; githubstatus.com said all systems operational), and on 2026-11-06 a page of
// kubernetes.io failed four unrelated pull requests, each green again on a rerun, each stopping the
// merge queue. lychee 0.24.2 sends one request for a 5xx (max_retries covers only network errors and
// timeouts, measured: one hit per 504) and cannot accept a status for one host only. So
// `just site-links` runs lychee, asks this script for the links worth another try (a 5xx, a network
// error, a timeout, from an http(s) host), checks those again after a wait (twice), and this script
// merges the reports and decides.
//
// The mode (SLUIS_LINKS_MODE, "strict" when unset) says what a failure that persists is worth:
//
//   - strict (a run on main, and a developer's machine): a 5xx from github.com or
//     raw.githubusercontent.com is a WARNING (an `::warning::` annotation in GitHub Actions); a 5xx
//     from any other host, a network error and a timeout fail;
//   - lenient (a pull request, the merge queue): a 5xx, a network error (DNS, TLS, connection reset)
//     or a timeout from ANY external host is a warning, reported and not failing. The strict run on
//     main still notices a host that is gone for good.
//
// In both modes:
//
//   - a 4xx is a broken link: it fails, whatever the host (404 and 410 above all);
//   - every internal link (a file in the built site, a missing page or anchor) fails;
//   - anything this script cannot account for fails (a report that cannot be read, an exit status
//     other than lychee's 0 and 2, counts that do not match the entries, a check of no link at all).
//
// usage:
//   links-report.mjs retry-urls <report.json>
//       print the URLs worth another try (see retryable), one per line (nothing: none to repeat)
//   links-report.mjs merge <report.json> <exit status> [<retry.json> <exit status>]...
//       print the merged report
//   links-report.mjs judge <report.json> <exit status> [<retry.json> <exit status>]...
//       merge the reports (a retry report supersedes the retryable entries of the ones before it)
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

// An external link is an http(s) one; lychee resolves the links of the site itself (with
// --root-dir) to file:// URLs.
const isExternal = (e) => /^https?:$/.test((() => {
  try {
    return new URL(e.url).protocol;
  } catch {
    return '';
  }
})());

// lychee words a failure of the connection (DNS, TLS, reset, no route) "Network error: ..." and gives
// it no status code. A 4xx has a code, a missing file or anchor says something else.
const isNetworkError = (e) => !Number.isInteger(e.status?.code) && /^Network error/i.test(e.status?.text ?? '');

// The error entries that may be an accident of the moment, not a fact about the link: a 5xx or a
// network error from an external host.
const isTransientError = (e) => isExternal(e) && (is5xx(e) || isNetworkError(e));

// The entries of a report that are worth another try: [{ file, entry, map }], map being
// "error_map" or "timeout_map". A timeout of an external host is one.
const retryable = (report) => [
  ...Object.entries(report?.error_map ?? {}).flatMap(([file, list]) =>
    list.filter(isTransientError).map((entry) => ({ file, entry, map: 'error_map' }))),
  ...Object.entries(report?.timeout_map ?? {}).flatMap(([file, list]) =>
    list.filter(isExternal).map((entry) => ({ file, entry, map: 'timeout_map' }))),
];

export const retryUrls = (report) => [...new Set(retryable(report).map(({ entry }) => entry.url))];

// `retry` is the report of a second check of retryUrls(base). Its answer replaces the 5xx
// entries of base: a link that passed is gone, one that still fails is the retry's entry
// (kept under the file of base). Whatever else base holds stays.
export function merge(base, retry) {
  const urls = new Set(retryUrls(base));
  // A retry that checked fewer links than it was asked to would turn the rest into passes.
  if (typeof retry?.total !== 'number' || retry.total < urls.size) {
    throw new Error(`the repeated check covered ${retry?.total} links, ${urls.size} were asked for`);
  }
  const files = new Map(retryable(base).map(({ file, entry }) => [entry.url, file]));
  const drop = (map, keep) => {
    const out = {};
    for (const [file, list] of Object.entries(base[map] ?? {})) {
      const kept = list.filter((e) => !(keep(e) && urls.has(e.url)));
      if (kept.length) out[file] = kept;
    }
    return out;
  };
  const error_map = drop('error_map', isTransientError);
  const timeout_map = drop('timeout_map', isExternal);
  const add = (map, entry) => {
    const file = files.get(entry.url) ?? 'unknown';
    (map[file] ??= []).push(entry);
  };
  for (const list of Object.values(retry.error_map ?? {})) for (const e of list) add(error_map, e);
  for (const list of Object.values(retry.timeout_map ?? {})) for (const e of list) add(timeout_map, e);
  const count = (m) => Object.values(m).reduce((n, l) => n + l.length, 0);
  return { ...base, error_map, timeout_map, errors: count(error_map), timeouts: count(timeout_map) };
}

// report: the parsed JSON of lychee. status: lychee's exit status. mode: "strict" or "lenient"
// (see the top of the file). Returns { errors: [string], warnings: [string], checked: number }.
export function judge(report, status, mode = 'strict') {
  if (mode !== 'strict' && mode !== 'lenient') throw new Error(`unknown mode "${mode}", expected strict or lenient`);
  const lenient = mode === 'lenient';
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
      if (lenient && isTransientError(e)) {
        warnings.push(`${what}: ${hostOf(e.url)} failed after the repeated checks, not counted as a dead link on a pull request (the run on main is strict)`);
      } else if (is5xx(e) && isExternal(e) && TOLERATED_5XX_HOSTS.has(hostOf(e.url))) {
        warnings.push(`${what}: server error from ${hostOf(e.url)} after the repeated checks, not counted as a dead link`);
      } else {
        errors.push(what);
      }
    }
  }
  for (const [file, list] of Object.entries(report.timeout_map ?? {})) {
    for (const e of list) {
      entries++;
      if (lenient && isExternal(e)) {
        warnings.push(`${e.url} (timeout) in ${file}: ${hostOf(e.url)} did not answer after the repeated checks, not counted as a dead link on a pull request (the run on main is strict)`);
      } else {
        errors.push(`${e.url} (timeout) in ${file}`);
      }
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
  const mode = process.env.SLUIS_LINKS_MODE || 'strict';
  if (mode !== 'strict' && mode !== 'lenient') {
    console.error(`error: SLUIS_LINKS_MODE is "${mode}", expected strict or lenient`);
    process.exit(1);
  }
  const { errors, warnings, checked } = judge(report, bad ?? (args.length > 2 ? 0 : statuses[0]), mode);
  const annotate = process.env.GITHUB_ACTIONS === 'true';
  for (const w of warnings) console.log(annotate ? `::warning title=link check::${w}` : `warning: ${w}`);
  for (const e of errors) console.error(`error: ${e}`);
  if (errors.length) {
    console.error(`links-report: ${errors.length} failed, ${warnings.length} warnings, ${checked} links (${mode})`);
    process.exit(1);
  }
  console.log(`links-report: ${checked} links, ${warnings.length} warnings, no failures (${mode})`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
