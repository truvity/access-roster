#!/usr/bin/env node
// Self-test of links-report.mjs on fake lychee reports. No network, no lychee.
// usage: node --test site/scripts/links-report.test.mjs   (or `just site-test-links`)
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { judge, merge, retryUrls } from './links-report.mjs';

// A lychee JSON report with the given error entries ([url, code]) and timeouts.
const report = (errs, { timeouts = [], total = 10 } = {}) => ({
  total,
  errors: errs.length,
  timeouts: timeouts.length,
  error_map: errs.length
    ? { 'site/dist/a/index.html': errs.map(([url, code]) => ({ url, status: { text: `Rejected status code: ${code}`, code } })) }
    : {},
  timeout_map: timeouts.length ? { 'site/dist/a/index.html': timeouts.map((url) => ({ url })) } : {},
});

test('a clean report passes', () => {
  const r = judge(report([]), 0);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.warnings, []);
});

test('a 404 on github.com fails', () => {
  const r = judge(report([['https://github.com/C2SP/C2SP/blob/main/gone.md', 404]]), 2);
  assert.equal(r.errors.length, 1);
  assert.equal(r.warnings.length, 0);
});

test('a 504 on github.com warns and does not fail', () => {
  const r = judge(report([['https://github.com/C2SP/wycheproof', 504]]), 2);
  assert.deepEqual(r.errors, []);
  assert.equal(r.warnings.length, 1);
});

test('a 504 on raw.githubusercontent.com warns', () => {
  const r = judge(report([['https://raw.githubusercontent.com/o/r/main/f', 502]]), 2);
  assert.deepEqual(r.errors, []);
  assert.equal(r.warnings.length, 1);
});

test('a 504 on another host fails', () => {
  const r = judge(report([['https://example.com/spec', 504]]), 2);
  assert.equal(r.errors.length, 1);
  assert.equal(r.warnings.length, 0);
});

test('a look-alike or sub host of github.com is another host', () => {
  for (const url of ['https://api.github.com/x', 'https://github.com.example.com/x', 'https://notgithub.com/x']) {
    const r = judge(report([[url, 503]]), 2);
    assert.equal(r.errors.length, 1, url);
  }
});

test('a mix: the github 504 warns, the 404 and the other 504 fail', () => {
  const r = judge(
    report([
      ['https://github.com/truvity/sluis/issues/1052', 504],
      ['https://github.com/truvity/sluis/issues/1', 404],
      ['https://example.org/', 500],
    ]),
    2,
  );
  assert.equal(r.errors.length, 2);
  assert.equal(r.warnings.length, 1);
});

test('a timeout fails, even on github.com', () => {
  const r = judge(report([], { timeouts: ['https://github.com/x'] }), 2);
  assert.equal(r.errors.length, 1);
});

test('fails closed: odd exit status, a report that does not add up, an empty sweep', () => {
  assert.ok(judge(report([]), 1).errors.length > 0, 'lychee crashed');
  assert.ok(judge(report([]), 2).errors.length > 0, 'exit 2 with nothing listed');
  const odd = report([['https://github.com/x', 504]]);
  odd.errors = 2; // lychee counted an error that the map does not list
  assert.ok(judge(odd, 2).errors.length > 0, 'counts do not match');
  assert.ok(judge(report([], { total: 0 }), 0).errors.length > 0, 'no link checked');
  assert.ok(judge({}, 0).errors.length > 0, 'not a report');
});

test('retry: only 5xx links are repeated, and the repeat supersedes them', () => {
  const first = report([
    ['https://github.com/C2SP/wycheproof', 504],
    ['https://github.com/cloudevents/spec', 504],
    ['https://example.org/', 503],
    ['https://github.com/gone', 404],
  ]);
  assert.deepEqual(retryUrls(first).sort(), [
    'https://example.org/',
    'https://github.com/C2SP/wycheproof',
    'https://github.com/cloudevents/spec',
  ]);
  // On the repeat: wycheproof answers, spec is still 504, example.org is still 503.
  const again = report([
    ['https://github.com/cloudevents/spec', 504],
    ['https://example.org/', 503],
  ], { total: 3 });
  const merged = merge(first, again);
  const r = judge(merged, 0);
  assert.equal(r.warnings.length, 1, 'github 504 that persists warns');
  assert.equal(r.errors.length, 2, 'the 404 and the other host fail');
  assert.ok(r.errors.some((e) => e.includes('github.com/gone')));
  assert.ok(r.errors.some((e) => e.includes('example.org')));
});

test('retry: github 504s that pass on the repeat leave nothing', () => {
  const first = report([['https://github.com/C2SP/wycheproof', 504]]);
  const r = judge(merge(first, report([], { total: 1 })), 0);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.warnings, []);
});

test('retry: a repeat that checked fewer links than asked is refused', () => {
  const first = report([['https://github.com/a', 504], ['https://github.com/b', 504]]);
  assert.throws(() => merge(first, report([], { total: 1 })));
  assert.throws(() => merge(first, {}));
});
