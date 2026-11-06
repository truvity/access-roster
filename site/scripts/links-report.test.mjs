#!/usr/bin/env node
// Self-test of links-report.mjs on fake lychee reports. No network, no lychee.
// usage: node --test site/scripts/links-report.test.mjs   (or `just site-test-links`)
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { judge, merge, retryUrls } from './links-report.mjs';

// A lychee JSON report with the given error entries ([url, code]) and timeouts. A code of 'net'
// is lychee's network error (no status code), 'file' an internal link whose file is missing.
const statusOf = (code) =>
  code === 'net'
    ? { text: 'Network error: connection reset (error sending request for url)', details: 'connection reset' }
    : code === 'file'
      ? { text: 'File not found. Check if file exists and path is correct', details: 'File not found.' }
      : { text: `Rejected status code: ${code}`, code };
const report = (errs, { timeouts = [], total = 10 } = {}) => ({
  total,
  errors: errs.length,
  timeouts: timeouts.length,
  error_map: errs.length
    ? { 'site/dist/a/index.html': errs.map(([url, code]) => ({ url, status: statusOf(code) })) }
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

// Lenient mode: a pull request and the merge queue.
const lenient = (rep, status) => judge(rep, status, 'lenient');
const K8S = 'https://kubernetes.io/docs/reference/access-authn-authz/authentication/';

test('lenient: a 5xx, a network error and a timeout from an external host warn', () => {
  const r = lenient(report([[K8S, 503], ['https://example.org/a', 'net']], { timeouts: ['https://example.com/slow'] }), 2);
  assert.deepEqual(r.errors, []);
  assert.equal(r.warnings.length, 3);
});

test('strict (the default) still fails on the same three', () => {
  const rep = () => report([[K8S, 503], ['https://example.org/a', 'net']], { timeouts: ['https://example.com/slow'] });
  assert.equal(judge(rep(), 2).errors.length, 3);
  assert.equal(judge(rep(), 2, 'strict').errors.length, 3);
});

test('lenient: a 404 and a 410 on an external host fail, so does any other 4xx', () => {
  for (const code of [404, 410, 403, 401]) {
    const r = lenient(report([[K8S, code]]), 2);
    assert.equal(r.errors.length, 1, String(code));
    assert.equal(r.warnings.length, 0, String(code));
  }
});

test('lenient: an internal link fails, whatever it says', () => {
  const r = lenient(report([['file:///site/dist/missing', 'file'], ['file:///site/dist/gone', 503], ['file:///site/dist/net', 'net']], { timeouts: [] }), 2);
  assert.equal(r.errors.length, 3);
  assert.equal(r.warnings.length, 0);
});

test('lenient: a mix: the transient ones warn, the 404 and the internal link fail', () => {
  const r = lenient(
    report([[K8S, 504], ['https://example.org/gone', 404], ['https://example.org/dns', 'net'], ['file:///site/dist/x', 'file']]),
    2,
  );
  assert.equal(r.warnings.length, 2);
  assert.equal(r.errors.length, 2);
});

test('lenient still fails closed: odd exit status, counts that do not add up, an empty sweep', () => {
  assert.ok(lenient(report([]), 1).errors.length > 0, 'lychee crashed');
  assert.ok(lenient(report([]), 2).errors.length > 0, 'exit 2 with nothing listed');
  const odd = report([[K8S, 503]]);
  odd.errors = 2;
  assert.ok(lenient(odd, 2).errors.length > 0, 'counts do not match');
  assert.ok(lenient(report([], { total: 0 }), 0).errors.length > 0, 'no link checked');
  assert.ok(lenient({}, 0).errors.length > 0, 'not a report');
});

test('an unknown mode is refused', () => {
  assert.throws(() => judge(report([]), 0, 'lax'));
});

test('retry: network errors and external timeouts are repeated, internal ones and 4xx are not', () => {
  const first = report(
    [[K8S, 503], ['https://example.org/dns', 'net'], ['https://example.org/gone', 404], ['file:///site/dist/x', 'file']],
    { timeouts: ['https://example.com/slow'] },
  );
  assert.deepEqual(retryUrls(first).sort(), ['https://example.com/slow', 'https://example.org/dns', K8S]);
});

test('retry: what passes on the repeat is gone, what still fails stays, 404 and internal stay', () => {
  const first = report(
    [[K8S, 503], ['https://example.org/dns', 'net'], ['https://example.org/gone', 404], ['file:///site/dist/x', 'file']],
    { timeouts: ['https://example.com/slow'] },
  );
  // On the repeat: kubernetes answers, dns is still down, slow now answers 404.
  const again = report([['https://example.org/dns', 'net'], ['https://example.com/slow', 404]], { total: 3 });
  const merged = merge(first, again);
  assert.equal(merged.timeouts, 0, 'the timeout is superseded');
  const r = lenient(merged, 2);
  assert.equal(r.warnings.length, 1, 'only dns is still a transient failure');
  assert.deepEqual(r.errors.map((e) => e.split(' ')[0]).sort(), [
    'file:///site/dist/x',
    'https://example.com/slow',
    'https://example.org/gone',
  ]);
});

test('retry: a timeout that persists stays a timeout', () => {
  const first = report([], { timeouts: ['https://example.com/slow'] });
  const merged = merge(first, report([], { timeouts: ['https://example.com/slow'], total: 1 }));
  assert.equal(merged.timeouts, 1);
  assert.equal(lenient(merged, 2).warnings.length, 1);
  assert.equal(judge(merged, 2).errors.length, 1);
});
