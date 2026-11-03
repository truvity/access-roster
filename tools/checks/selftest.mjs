#!/usr/bin/env node
// Self-test for the checks in tools/checks/: each check runs against scratch repositories that
// must pass or must fail. A check that passes everything is not a check.
//
// The fixtures are built here at run time, so no token-shaped string or deny-listed term is
// committed; the names are invented (examplecorp).
//
// usage: tools/checks/selftest.mjs
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..', '..');
const { parse: parseYaml } = createRequire(join(repo, 'site', 'package.json'))('yaml');
const scratch = mkdtempSync(join(tmpdir(), 'sluis-checks-'));
let failures = 0;
let cases = 0;

// A git repository holding `files` (path -> content), and the `commits` (messages) made on top
// of a first commit on the branch `base`. Scratch commits are unsigned: they never leave this machine.
function fixture(files, commits = []) {
  const dir = mkdtempSync(join(scratch, 'repo-'));
  for (const [path, text] of Object.entries(files)) {
    if (text === undefined) continue;
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  execFileSync('git', ['init', '-q', dir]);
  execFileSync('git', ['-C', dir, 'add', '-A']);
  if (commits.length) {
    const git = (...a) => execFileSync('git', ['-C', dir, '-c', 'user.name=Example', '-c', 'user.email=dev@example.com', '-c', 'commit.gpgsign=false', ...a]);
    git('commit', '-q', '--allow-empty', '-m', 'base');
    git('branch', 'base');
    for (const m of commits) git('commit', '-q', '--allow-empty', '-m', m);
  }
  return dir;
}

// Run `check` on `files`; `want` is 'pass' or 'fail'; `has`/`lacks` are strings the output must
// or must not contain (case-insensitive).
function expect(name, check, files, want, { env = {}, has = [], lacks = [], commits = [], script = join(here, `${check}.mjs`), target = '', args = [] } = {}) {
  cases++;
  const dir = fixture(files, commits);
  const res = spawnSync(process.execPath, [script, ...args, join(dir, target)], {
    encoding: 'utf8',
    env: { ...process.env, PUBLIC_CONTENT_DENYLIST: '', REQUIRE_DENYLIST: '', PR_TITLE: '', PR_BODY: '', BASE: 'base', ...env },
  });
  const out = `${res.stdout}${res.stderr}`;
  const got = res.status === 0 ? 'pass' : 'fail';
  const problems = [];
  if (got !== want) problems.push(`expected ${want}, got ${got}`);
  for (const s of has) if (!out.toLowerCase().includes(s.toLowerCase())) problems.push(`output lacks "${s}"`);
  for (const s of lacks) if (out.toLowerCase().includes(s.toLowerCase())) problems.push(`output contains "${s}"`);
  if (problems.length) {
    failures++;
    console.error(`FAIL ${check}: ${name}: ${problems.join('; ')}\n${out.replace(/^/gm, '  | ')}`);
  } else console.log(`ok   ${check}: ${name}`);
}

// ---- C1 decisions: the real template and README, with an index of one record
const template = readFileSync(join(repo, 'docs/decisions/0000-template.md'), 'utf8');
const readme = readFileSync(join(repo, 'docs/decisions/README.md'), 'utf8')
  .replace(/(## Index\n)[\s\S]*$/, '$1\n| ADR | Decision | Status |\n|-----|----------|--------|\n');
const row = (n, slug, status) => `| [${n}](${n}-${slug}.md) | A decision | ${status} |\n`;
const GOOD = ['- **Another way.** It lost, for a reason.'];
const PROPOSAL = 'Proposal: [issue #1](https://github.com/truvity/sluis/issues/1).';
const record = ({ num = '0001', status = 'Accepted', layer = '', date = '2026-10-31', drop = '', roads = GOOD, extra = [], proposal = PROPOSAL, body = 'Text.' } = {}) =>
  [
    `# ${num} — We use the example`, '', `**Status:** ${status}`, ...(layer ? [`**Layer:** ${layer}`] : []), `**Date:** ${date}`, '', ...(proposal ? [proposal, ''] : []), ...extra,
    ...['Context', 'Decision', 'Consequences'].filter((s) => s !== drop).flatMap((s) => [`## ${s}`, '', body, '']),
    '## Roads not taken', '', ...roads, '',
    ...(drop === 'Follow-ups' ? [] : ['## Follow-ups', '', 'None.', '']),
  ].join('\n');
const adr = (extra = {}, idx = row('0001', 'we-use-the-example', 'Accepted')) => ({
  'docs/decisions/0000-template.md': template,
  'docs/decisions/README.md': readme + idx,
  'docs/decisions/0001-we-use-the-example.md': record(),
  ...extra,
});
const one = (opts) => ({ 'docs/decisions/0001-we-use-the-example.md': record(opts) });
expect('a good record', 'decisions', adr(), 'pass', { has: ['1 records'] });
expect('a road whose name ends in a colon', 'decisions', adr(one({ roads: ['- **Another way:** it lost.'] })), 'pass');
expect('a road in the old form, an option with Pros and Cons', 'decisions', adr(one({ roads: ['### Another way', '', '- Pros: one.', '- Cons: two.', '- Why not: three.'] })), 'fail', { has: ['"###" option'] });
expect('a line under the roads that is not a road', 'decisions', adr(one({ roads: [...GOOD, 'And a paragraph.'] })), 'fail', { has: ['not a road bullet'] });
expect('a road with no reason', 'decisions', adr(one({ roads: ['- **Another way.**'] })), 'fail', { has: ['has no road'] });
expect('no proposal line', 'decisions', adr(one({ proposal: '' })), 'fail', { has: ['"Proposal:'] });
expect('a proposal line with two numbers', 'decisions', adr(one({ proposal: 'Proposal: [issue #1](https://github.com/truvity/sluis/issues/2).' })), 'fail', { has: ['one number'] });
expect('an inferred marker', 'decisions', adr(one({ body: 'A point (inferred from the old record).' })), 'fail', { has: ['(inferred'] });
expect('a history line', 'decisions', adr(one({ extra: ['Rewritten in place on 2026-10-30.', ''] })), 'fail', { has: ['history line'] });
expect('an Accepted record with an open part', 'decisions', adr(one({ body: 'The format is not decided here.' })), 'fail', { has: ['no open part'] });
expect('a Proposed record with an open part', 'decisions', adr(one({ status: 'Proposed', body: 'The format is not decided here.' }), row('0001', 'we-use-the-example', 'Proposed')), 'pass');
expect('a line of the template comment left in', 'decisions', adr(one({ extra: [template.split('\n').find((l) => /^Keep the text public/.test(l)), ''] })), 'fail', { has: ["template's instructions comment"] });
expect('no records', 'decisions', { ...adr({}, ''), 'docs/decisions/0001-we-use-the-example.md': undefined }, 'fail', { has: ['empty sweep'] });
expect('a missing section', 'decisions', adr(one({ drop: 'Consequences' })), 'fail', { has: ['## Consequences'] });
expect('no follow-ups', 'decisions', adr(one({ drop: 'Follow-ups' })), 'fail', { has: ['## Follow-ups'] });
expect('a layer of a later module', 'decisions', adr(one({ layer: 'CIAM module' })), 'pass');
expect('an unknown layer', 'decisions', adr(one({ layer: 'billing' })), 'fail', { has: ['layer "billing" is not one of'] });
expect('the layer line after the date', 'decisions', adr({ 'docs/decisions/0001-we-use-the-example.md': record().replace('**Date:** 2026-10-31', '**Date:** 2026-10-31\n**Layer:** core') }), 'fail', { has: ['out of the template'] });
expect('an unknown status', 'decisions', adr(one({ status: 'Maybe' })), 'fail', { has: ['not one of'] });
expect('superseded by a missing record', 'decisions', adr(one({ status: 'Superseded by 0099' }), row('0001', 'we-use-the-example', 'Superseded by 0099')), 'fail', { has: ['0099'] });
expect('a date that is no day', 'decisions', adr(one({ date: '2026-02-30' })), 'fail', { has: ['YYYY-MM-DD'] });
expect('a title with another number', 'decisions', adr(one({ num: '0002' })), 'fail', { has: ['number 0002'] });
expect('an index status that differs', 'decisions', adr({}, row('0001', 'we-use-the-example', 'Proposed')), 'fail', { has: ['says "Proposed"'] });
expect('a record not in the index', 'decisions', adr({}, ''), 'fail', { has: ['no row in the README index'] });
expect('an index row without a file', 'decisions', adr({}, row('0001', 'we-use-the-example', 'Accepted') + row('0003', 'gone', 'Accepted')), 'fail', { has: ['0003 has no record'] });
expect('a file name that is not kebab-case', 'decisions', adr({ 'docs/decisions/0004_Bad.md': record({ num: '0004' }) }), 'fail', { has: ['0004_Bad.md'] });
expect('two records with one number', 'decisions', adr({ 'docs/decisions/0001-again.md': record() }), 'fail', { has: ['also used by'] });
const page = (text) => ({ 'docs/page.md': `# A page\n\n${text}\n` });
expect('a page citing a record and its heading', 'decisions', adr(page('See [ADR 0001](/decisions/0001-we-use-the-example/#roads-not-taken).')), 'pass', { has: ['citations'] });
expect('a page citing a record that does not exist', 'decisions', adr(page('As ADR 0099 says.')), 'fail', { has: ['record 0099'] });
expect('a page citing v1 and ritueel records', 'decisions', adr(page("As v1 ADR 0099 and ritueel's ADR 0098 say, and [v1](/v1/decisions/0097-old/).")), 'pass');
expect('a link to a record that is not a file', 'decisions', adr(page('See [it](/decisions/0002-gone/).')), 'fail', { has: ['"0002-gone"'] });
expect('a link to a heading a record does not have', 'decisions', adr(page('See [it](/decisions/0001-we-use-the-example/#nowhere).')), 'fail', { has: ['#nowhere'] });
const renumbered = (rows) => ({ 'docs/decisions/renumbered.json': JSON.stringify({ records: rows, anchors: {} }) });
expect('a renumbering map of an old slug', 'decisions', adr(renumbered([{ old: '0007-old-name', new: '0001-we-use-the-example' }])), 'pass');
expect('a renumbering map whose old slug is still a file', 'decisions', adr({ ...renumbered([{ old: '0002-still-here', new: '0001-we-use-the-example' }]), 'docs/decisions/0002-still-here.md': record({ num: '0002' }) }, row('0001', 'we-use-the-example', 'Accepted') + row('0002', 'still-here', 'Accepted')), 'fail', { has: ['still a file'] });
expect('a renumbering map pointing at no record', 'decisions', adr(renumbered([{ old: '0007-old-name', new: '0009-nothing' }])), 'fail', { has: ['not a record'] });

// ---- requirements catalogue: the evidence of a done record (L18). A scratch catalogue of one area,
// built with the real schema and vocabulary, one record, and the files its `tests` may name.
const reqIndex = readFileSync(join(repo, 'docs/requirements/index.yaml'), 'utf8');
const vocabulary = /^ {2}vocabulary:\n(?: {4}.*\n)+/m.exec(reqIndex)[0];
const catalogueFiles = (record, extra = {}) => ({
  'docs/requirements/requirements.schema.json': readFileSync(join(repo, 'docs/requirements/requirements.schema.json'), 'utf8'),
  'docs/requirements/standards.yaml': 'standards:\n  - {id: ST-01, name: "Example standard", group: "Example", register: false}\n',
  'docs/requirements/index.yaml': `schema: 1\ncatalogue:\n  title: "example"\n  checked: "2026-10-31"\n${vocabulary}  areas:\n    EX: {title: "Example area", file: ex.yaml}\n  gaps:\n    example-gap: "A gap that the scratch catalogue declares."\n`,
  'docs/requirements/ex.yaml': `schema: 1\narea: EX\nrequirements:\n  - id: REQ-EX-001\n    area: EX\n    statement: "An example MUST do one thing."\n    rationale: "The scratch catalogue needs one record."\n    level: MUST\n    source: design-decision\n    runtimes: all\n    standards: []\n    verification:\n      - {kind: integration-test, ref: "the example test"}\n${record}`,
  ...extra,
});
const reqCheck = join(repo, 'site/scripts/check-requirements.mjs');
const reqExpect = (name, files, want, opts = {}) => expect(name, 'check-requirements', files, want, { script: reqCheck, target: 'docs/requirements', ...opts });
const withTests = (...paths) => `    tests:\n${paths.map((t) => `      - ${t}\n`).join('')}`;
const testFile = (text = 'func Test(t *testing.T) { t.Run("REQ-EX-001/case", nil) }\n') => ({ 'tests/example_test.go': text });
reqExpect('a planned record needs no tests', catalogueFiles('    status: planned\n    features: [design]\n'), 'pass', { has: ['1 requirements'] });
reqExpect('a done record with an existing test file that names it', catalogueFiles(`    status: done\n${withTests('tests/example_test.go')}`, testFile()), 'pass');
reqExpect('a done record without tests', catalogueFiles('    status: done\n'), 'fail', { has: ['L18 REQ-EX-001', 'needs tests'] });
reqExpect('a done record whose test file is missing', catalogueFiles(`    status: done\n${withTests('tests/missing_test.go')}`), 'fail', { has: ['L18 REQ-EX-001', 'tests/missing_test.go is not a file'] });
reqExpect('a done record whose test path is a directory', catalogueFiles(`    status: done\n${withTests('tests')}`, testFile()), 'fail', { has: ['tests is not a file'] });
reqExpect('a done record whose test file does not name it', catalogueFiles(`    status: done\n${withTests('tests/example_test.go')}`, testFile('func Test(t *testing.T) {}\n')), 'fail', { has: ['does not name REQ-EX-001'] });
reqExpect('a done record whose test path leaves the repository', catalogueFiles(`    status: done\n${withTests('../outside_test.go')}`), 'fail', { has: ['L1', 'tests'] });
reqExpect('an empty tests list', catalogueFiles('    status: done\n    tests: []\n'), 'fail', { has: ['fewer than 1 items'] });
reqExpect('a planned record that names a missing test file', catalogueFiles(`    status: planned\n    features: [design]\n${withTests('tests/missing_test.go')}`), 'fail', { has: ['tests/missing_test.go is not a file'] });
const retiredIndex = (withRetired) => ({ 'docs/requirements/index.yaml': `schema: 1\ncatalogue:\n  title: "example"\n  checked: "2026-10-31"\n${vocabulary}  areas:\n    EX: {title: "Example area", file: ex.yaml${withRetired ? ', retired: true' : ''}}\n  gaps:\n    example-gap: "A gap that the scratch catalogue declares."\n` });
reqExpect('a retired area whose record is live', catalogueFiles('    status: planned\n    features: [design]\n', retiredIndex(true)), 'fail', { has: ['L19 area EX', 'REQ-EX-001'] });
reqExpect('a retired area whose only record is withdrawn', catalogueFiles('    status: withdrawn\n    superseded_by: [REQ-EX-001]\n', retiredIndex(true)), 'pass');
reqExpect('an area that is not retired may hold a live record', catalogueFiles('    status: planned\n    features: [design]\n', retiredIndex(false)), 'pass');

// ---- C4 public content. The token-shaped strings are assembled here, not written out.
const pub = (text) => ({ 'README.md': `# Example\n\n${text}\n` });
const pem = `${'-'.repeat(5)}BEGIN EC PRIVATE KEY${'-'.repeat(5)}`;
expect('clean text', 'public-content', pub('Use sluis.example.com and account 123456789012.'), 'pass', { has: ['private deny-list not available, skipped'] });
expect('an account-id-shaped number', 'public-content', pub(`arn:aws:iam::${'48392017'}${'4655'}:role/x`), 'fail', { has: ['README.md:3', 'account-id-shaped'], lacks: ['4655'] });
expect('a private key block', 'public-content', pub(pem), 'fail', { has: ['private key block'] });
expect('a GitHub token', 'public-content', pub(`token ${'ghp'}_${'a1B2'.repeat(9)}`), 'fail', { has: ['GitHub token'], lacks: ['a1B2'] });
expect('an AWS access key id', 'public-content', pub(`${'AK'}IA${'Q'.repeat(16)}`), 'fail', { has: ['AWS access key id'] });
expect('an sk- key', 'public-content', pub(`${'sk'}-proj-${'x9'.repeat(12)}`), 'fail', { has: ['sk- secret key'] });
expect('an sk- word with no digit', 'public-content', pub(`${'sk'}-${'abcdefghij'.repeat(3)}`), 'pass');
expect('a dashed account id', 'public-content', pub(`account ${'4839'}-${'2017'}-${'4655'}`), 'fail', { has: ['dashed account-id-shaped'], lacks: ['4655'] });
expect('a dashed placeholder', 'public-content', pub('account 1234-5678-9012'), 'pass');
expect('a UUID whose last group is digits', 'public-content', pub(`id 9f1c2d3e-4b5a-4c6d-8e7f-${'48392017'}${'4655'}`), 'pass');
expect('digits inside a base64 run', 'public-content', pub(`sha512-Qx7Lm2${'48392017'}${'4655'}Zp9KdR3tWv0Ys==`), 'pass');
expect('a Stripe live key', 'public-content', pub(`${'sk'}_live_${'a1'.repeat(12)}`), 'fail', { has: ['Stripe live key'] });
expect('an npm token', 'public-content', pub(`${'npm'}_${'a1B2'.repeat(9)}`), 'fail', { has: ['npm token'] });
expect('an age secret key', 'public-content', pub(`${'AGE-SECRET'}-KEY-1${'QZ'.repeat(29)}`), 'fail', { has: ['age secret key'] });
expect('a Vault token', 'public-content', pub(`${'hvs'}.${'a1B2'.repeat(7)}`), 'fail', { has: ['Vault token'] });
expect('FIDO SSH key types are not tokens', 'public-content', pub('sk-ssh-ed25519@openssh.com and sk-ecdsa-sha2-nistp256-cert-v01@openssh.com'), 'pass');
expect('a deny-listed term', 'public-content', pub('Deployed at ExampleCorp in 2026.'), 'fail',
  { env: { PUBLIC_CONTENT_DENYLIST: '# comment\n\nexamplecorp\nglobexample\n' }, has: ['README.md:3: matches a deny-listed term'], lacks: ['examplecorp', 'globexample', 'Deployed'] });
expect('a deny-listed term in a path', 'public-content', { 'README.md': 'x\n', 'docs/examplecorp/notes.md': `${'4839'}-${'2017'}-${'4655'}\n` }, 'fail',
  { env: { PUBLIC_CONTENT_DENYLIST: 'examplecorp' }, has: ['a tracked path matches a deny-listed term (file #2)', 'file #2:1:1'], lacks: ['examplecorp', 'notes.md'] });
expect('a term inside a longer word is no match', 'public-content', pub('The examplecorpus is fine.'), 'pass',
  { env: { PUBLIC_CONTENT_DENYLIST: 'examplecorp' }, has: ['private deny-list loaded'], lacks: ['examplecorpus'] });
expect('a required deny-list that is empty', 'public-content', pub('Text.'), 'fail', { env: { REQUIRE_DENYLIST: 'true' }, has: ['required here'] });
expect('a required deny-list that is set', 'public-content', pub('Text.'), 'pass', { env: { REQUIRE_DENYLIST: 'true', PUBLIC_CONTENT_DENYLIST: 'examplecorp' }, lacks: ['examplecorp'] });
expect('a deny-list that is not required', 'public-content', pub('Text.'), 'pass', { env: { REQUIRE_DENYLIST: 'false' }, has: ['skipped'] });

// ---- C4 public text: commit messages and the pull request text
const msgs = { 'README.md': 'x\n' };
const term = { PUBLIC_CONTENT_DENYLIST: 'examplecorp' };
expect('clean messages', 'public-messages', msgs, 'pass', { commits: ['docs: a change', 'ci: another'], env: { ...term, PR_TITLE: 'docs: a change' }, has: ['3 commit messages'] });
expect('a term in a commit message', 'public-messages', msgs, 'fail', { commits: ['docs: a change', 'docs: for ExampleCorp\n\nBody.'], env: term, has: ['line 1: matches a deny-listed term'], lacks: ['examplecorp', 'Body.'] });
expect('a term in the pull request body', 'public-messages', msgs, 'fail', { commits: ['docs: a change'], env: { ...term, PR_TITLE: 'docs: a change', PR_BODY: 'Intro.\nSee examplecorp.' }, has: ['pull request body, line 2: matches a deny-listed term'], lacks: ['examplecorp'] });
expect('a token in a commit message', 'public-messages', msgs, 'fail', { commits: [`ci: ${'ghp'}_${'a1B2'.repeat(9)}`], has: ['GitHub token'], lacks: ['a1B2'] });
expect('no commits and no pull request text', 'public-messages', msgs, 'fail', { commits: ['docs: one'], env: { BASE: 'HEAD' }, has: ['empty sweep'] });
expect('nothing to scan', 'public-content', {}, 'fail', { has: ['empty sweep'] });

// ---- C5 YAML extension
expect('.yaml files', 'yaml-ext', { 'a.yaml': 'a: 1\n' }, 'pass');
expect('the files tools require', 'yaml-ext', { '.github/ISSUE_TEMPLATE/config.yml': 'blank_issues_enabled: false\n', 'site/.yarnrc.yml': 'nodeLinker: node-modules\n' }, 'pass');
expect('a .yml file', 'yaml-ext', { 'a.yaml': 'a: 1\n', 'deploy/values.yml': 'a: 1\n' }, 'fail', { has: ['deploy/values.yml'] });
expect('no YAML at all', 'yaml-ext', { 'README.md': 'x\n' }, 'fail', { has: ['empty sweep'] });

// ---- C5b MDX only for pages that place components
const MDX_HOME = "---\ntitle: Home\n---\nimport '../site/home.css';\nimport Marks from '../site/Marks.astro';\nimport { Chain as Links, helper } from '../site/Chain.astro';\n\n<div>\n  <Marks />\n</div>\n";
expect('an .mdx page that places a component', 'mdx-pages', { 'docs/index.mdx': MDX_HOME }, 'pass');
expect('an .mdx page that places a renamed named import', 'mdx-pages', { 'docs/a/b.mdx': "import { Chain as Links } from '../x.astro';\n\n<Links part=\"a\" />\n" }, 'pass');
expect('an .mdx page with plain Markdown', 'mdx-pages', { 'docs/index.mdx': MDX_HOME, 'docs/learn/x.mdx': '# Title\n\nText.\n' }, 'fail', { has: ['docs/learn/x.mdx: use .md: MDX only for pages that place components'] });
expect('an .mdx page that imports a component and never places it', 'mdx-pages', { 'docs/x.mdx': "import Marks from '../Marks.astro';\n\nText.\n" }, 'fail', { has: ['docs/x.mdx: use .md'] });
expect('an .mdx page that imports only a stylesheet', 'mdx-pages', { 'docs/x.mdx': "import '../home.css';\n\n<div>Text.</div>\n" }, 'fail', { has: ['docs/x.mdx: use .md'] });
expect('no .mdx file at all', 'mdx-pages', { 'docs/index.md': 'x\n' }, 'fail', { has: ['empty sweep'] });

// ---- C6 agent links
const docs = { 'docs/contributing/index.md': 'x\n', Justfile: 'default:\n', 'CLAUDE.md': '@AGENTS.md\n' };
expect('no agent files at all', 'agent-links', { 'docs/contributing/index.md': 'x\n' }, 'fail', { has: ['AGENTS.md is missing', 'CLAUDE.md is missing'] });
expect('AGENTS.md is missing', 'agent-links', { ...docs, '.claude/skills/example/SKILL.md': 'See `docs/contributing/`.\n' }, 'fail', { has: ['AGENTS.md is missing'] });
expect('CLAUDE.md is missing', 'agent-links', { 'docs/contributing/index.md': 'x\n', 'AGENTS.md': 'Read `docs/contributing/`.\n' }, 'fail', { has: ['CLAUDE.md is missing'] });
expect('CLAUDE.md does not import AGENTS.md', 'agent-links', { ...docs, 'CLAUDE.md': 'Read AGENTS.md.\n', 'AGENTS.md': 'Read `docs/contributing/`.\n' }, 'fail', { has: ['CLAUDE.md does not import AGENTS.md'] });
expect('every pointer exists', 'agent-links', {
  ...docs,
  'AGENTS.md': 'Read [the guide](docs/contributing/index.md#start), run `just site-check` from the `Justfile`.\nPush `origin/main`, see `docs/requirements/<area>.yaml` and https://example.com/x.\n```\n[not a link](docs/missing.md)\n```\n',
  'CLAUDE.md': '@AGENTS.md\n',
  '.claude/skills/example/SKILL.md': 'See [the guide](../../../docs/contributing/index.md) and `docs/contributing/`.\n',
}, 'pass', { has: ['5 pointers in 3 agent files'] });
expect('a link to a missing file', 'agent-links', { ...docs, 'AGENTS.md': 'Read [this](docs/contributing/gone.md).\n' }, 'fail', { has: ['AGENTS.md:1: docs/contributing/gone.md does not exist'] });
expect('a code path to a missing file', 'agent-links', { ...docs, '.claude/skills/example/SKILL.md': 'Edit `docs/contributing/gone.md`.\n' }, 'fail', { has: ['gone.md does not exist'] });
expect('a subagent file with a missing path', 'agent-links', { ...docs, '.claude/agents/docs.md': 'Edit `docs/contributing/gone.md`.\n' }, 'fail', { has: ['.claude/agents/docs.md:1: docs/contributing/gone.md does not exist'] });
expect('an agent file with no pointer', 'agent-links', { ...docs, 'AGENTS.md': 'Be careful.\n' }, 'fail', { has: ['empty sweep'] });

// ---- C7 actors: the repository's own registry, explorer, requirements and page, with stub decision
// records that name every actor, then one change each
const real = (p) => readFileSync(join(repo, p), 'utf8');
const registry = parseYaml(real('docs/architecture/actors.yaml'));
const everyActor = [...registry.actors, ...registry.platform];
// One stub record per number the registry lists; the language record has the per-actor table.
const stubRecords = () => {
  const numbers = new Set(everyActor.flatMap((a) => a.adrs));
  const names = everyActor.map((a) => `\`${a.name}\``).join(' ');
  const table = ['| Component | Language | Rule |', '|---|---|---|',
    ...registry.actors.map((a) => `| ${a.language_row ?? `\`${a.name}\``} | ${a.language} | ${a.language_rule} |`)].filter((r, i, all) => all.indexOf(r) === i).join('\n');
  // The stubs take the file names of the real records, so that the links on the generated page agree.
  const realNames = readdirSync(join(repo, 'docs/decisions')).filter((f) => /^[0-9]{4}-.*\.md$/.test(f));
  const fileName = (n) => realNames.find((f) => f.startsWith(`${n}-`)) ?? `${n}-${n === '0012' ? 'the-language-follows-the-executable' : 'stub'}.md`;
  return Object.fromEntries([...numbers].map((n) => [
    `docs/decisions/${fileName(n)}`,
    `# ${n}\n\n${names}\n\n${n === '0012' ? `### Per-actor table\n\n${table}\n\n` : ''}Text.\n`,
  ]));
};
const actorFiles = {
  ...Object.fromEntries([
    'docs/architecture/actors.yaml', 'site/src/data/explorer/architecture.yaml', 'docs/reference/actors.md',
    'docs/requirements/index.yaml', 'docs/requirements/standards.yaml', 'docs/requirements/policy.yaml',
  ].map((p) => [p, real(p)])),
  ...stubRecords(),
};
const edit = (path, from, to) => {
  if (!actorFiles[path].includes(from)) throw new Error(`selftest fixture: ${path} lacks ${from}`);
  return { ...actorFiles, [path]: actorFiles[path].replace(from, to) };
};
const lang = Object.keys(actorFiles).find((p) => p.includes('the-language-follows-the-executable'));
const stub = Object.keys(actorFiles).find((p) => p.startsWith('docs/decisions/0002-'));
const actorsYaml = 'docs/architecture/actors.yaml';
const nActors = registry.actors.length;
expect('the repository as it is', 'actors', actorFiles, 'pass', { has: [`${nActors} actors, no errors`], lacks: ['warning'] });
expect('a label that is not actor:<name>', 'actors', edit(actorsYaml, 'label: actor:signer', 'label: signer'), 'fail', { has: ['label must be actor:signer'] });
expect('a record naming an unknown actor', 'actors', edit('docs/requirements/policy.yaml', 'actors: [policy]', 'actors: [decider]'), 'fail', { has: ['decider is not an actor'] });
expect('a record outside the actor\'s areas', 'actors', edit('docs/requirements/policy.yaml', 'actors: [policy]', 'actors: [signer]'), 'fail', { has: ['area POLICY is not a requirement area of signer'] });
expect('a work actor that holds a credential', 'actors', edit(actorsYaml, 'family: work\n    holder: false', 'family: work\n    holder: true'), 'fail', { has: ['a work actor holds no credential at rest'] });
expect('a holder that says nothing about what it holds', 'actors', edit(actorsYaml, '    holds: ["the card PIN, or the permission to use the cloud key service"]\n', ''), 'fail', { has: ['says what it holds'] });
expect('a work actor without a keys port', 'actors', edit(actorsYaml, 'ports: [data, keys, audit-emit, listener]', 'ports: [data, audit-emit, listener]'), 'fail', { has: ['a work actor has a keys port'] });
expect('a work actor with a port of the data family', 'actors', edit(actorsYaml, 'ports: [data, keys, audit-emit, fetch]', 'ports: [data, keys, audit-emit, fetch, durable]'), 'fail', { has: ['a port is never shared between families'] });
expect('store with three ports downward', 'actors', edit(actorsYaml, 'ports: [config-source, secret-source, durable, temp, keys, audit-emit]', 'ports: [config-source, secret-source, durable, keys, audit-emit]'), 'fail', { has: ['exactly four ports downward'] });
expect('a call to key', 'actors', edit(actorsYaml, 'calls: [session, exchange, console, ssh-ca, quota, adapter-<vendor>]', 'calls: [session, key]'), 'fail', { has: ['calls key'] });
expect('a call to an unknown actor', 'actors', edit(actorsYaml, 'calls: [policy, signer, exchange, adapter-upstream-oidc]', 'calls: [policy, signr]'), 'fail', { has: ['calls signr, which is not an actor'] });
expect('an egress class that is not declared', 'actors', edit(actorsYaml, 'egress: [client-document-hosts]', 'egress: [anywhere]'), 'fail', { has: ['egress class anywhere is not declared'] });
expect('an egress class that nothing uses', 'actors', edit(actorsYaml, 'egress_classes:\n', 'egress_classes:\n  never-used: "Nothing reaches it."\n'), 'fail', { has: ['never-used is declared and no actor uses it'] });
expect('an unknown op in key_purposes', 'actors', edit(actorsYaml, '- { purpose: pseudonym, ops: [mac] }', '- { purpose: pseudonym, ops: [hash] }'), 'fail', { has: ['ops must list'] });
expect('a record the actor lists that does not exist', 'actors', edit(actorsYaml, "adrs: ['0002', '0006', '0012', '0021', '0022', '0024']", "adrs: ['0002', '0006', '0012', '0021', '0022', '0024', '0099']"), 'fail', { has: ['ADR 0099 is not a record'] });
expect('a record that does not name the actor: a warning', 'actors', edit(stub, '`entry`', '`entr`'), 'pass', { has: ['warning', 'does not name the actor', 'entry: ADR 0002'] });
expect('a record that does not name the actor: an error when strict', 'actors', edit(stub, '`entry`', '`entr`'), 'fail', { args: ['--strict-adrs'], has: ['entry: ADR 0002'] });
expect('a language that the language record does not give', 'actors', edit(lang, '| `policy` | Rust |', '| `policy` | Go |'), 'fail', { args: ['--strict-adrs'], has: ['language Rust, but the language record says "Go"'] });
expect('an instance name that is no actor', 'actors', edit(stub, 'Text.', 'See `exchanger@prod`.'), 'fail', { args: ['--strict-adrs'], has: ['names exchanger'] });
expect('a role the registry lacks', 'actors', edit('site/src/data/explorer/architecture.yaml', '  quota:\n    status: decided', '  meter:\n    status: decided'), 'fail', { has: ['role meter is not an actor'] });
expect('a stale generated page', 'actors', edit('docs/reference/actors.md', '| work | no | Rust (R2) |', '| work | no | Rust |'), 'fail', { has: ['generated block is stale'] });
expect('no registry', 'actors', { ...actorFiles, [actorsYaml]: undefined }, 'fail', { has: ['actors.yaml is missing'] });
expect('an external caller that uses a purpose other than pseudonym', 'actors', edit(actorsYaml, '- { purpose: pseudonym, ops: [mac] }\n    adrs: [\'0029\']', '- { purpose: data, ops: [open] }\n    adrs: [\'0029\']'), 'fail', { has: ['an external caller may use only pseudonym'] });
expect('an external caller that seals', 'actors', edit(actorsYaml, '- { purpose: pseudonym, ops: [mac] }\n    adrs: [\'0029\']', '- { purpose: pseudonym, ops: [mac, seal] }\n    adrs: [\'0029\']'), 'fail', { has: ['pseudonym allows only mac for an external caller'] });
expect('an external caller named like an actor', 'actors', edit(actorsYaml, '  - name: product-emitter', '  - name: policy'), 'fail', { has: ['the name is also an actor'] });
expect('an external caller with an unknown field', 'actors', edit(actorsYaml, '    identity: "The product\'s own platform identity."', '    identity: "The product\'s own platform identity."\n    ports: [data]'), 'fail', { has: ['unknown field ports'] });

// ---- C8 examples: a block on a page equals the file it names
const exPage = (body) => `---\ntitle: x\n---\n\n<!-- example: tests/x/install.yaml -->\n\`\`\`yaml\n${body}\`\`\`\n`;
expect('an example equal to its file', 'examples', { 'docs/a.md': exPage('a: 1\n'), 'tests/x/install.yaml': 'a: 1\n' }, 'pass', { has: ['1 examples'] });
expect('an example that differs', 'examples', { 'docs/a.md': exPage('a: 2\n'), 'tests/x/install.yaml': 'a: 1\n' }, 'fail', { has: ['differs from tests/x/install.yaml'] });
expect('an example of a missing file', 'examples', { 'docs/a.md': exPage('a: 1\n') }, 'fail', { has: ['does not exist'] });
expect('a mark with no block', 'examples', { 'docs/a.md': '<!-- example: tests/x/install.yaml -->\nText.\n', 'tests/x/install.yaml': 'a: 1\n' }, 'fail', { has: ['not followed by a fenced block'] });
expect('no examples', 'examples', { 'docs/a.md': 'Text.\n' }, 'fail', { has: ['empty sweep'] });

// ---- C9 installations: the org of an upstream and the vocabulary file of an example installation
const instFiles = (install, vocab, extra = {}) => ({
  'tests/installations/x/install.yaml': install,
  'tests/installations/x/policy/vocabulary.yaml': vocab,
  'tests/installations/x/policy/x.cedar': 'permit (principal, action, resource == Grant::"dev:app:user");\n',
  ...extra,
});
const instYaml = (upstream = '    org: acme\n', requires = '[dev:app:user]') =>
  `boundaries:\n  dev:\n    kind: environment\n    clients:\n      app:\n        requires: ${requires}\n  acme:\n    kind: company\nupstreams:\n  u:\n    kind: oidc\n${upstream}policy:\n  files: [policy/x.cedar]\n  vocabulary: policy/vocabulary.yaml\n`;
const vocabYaml = (roles = '      user: []\n      admin: [user]\n', scopes = '  dev: {}\n  prod: { sensitive: true }\n') => `scopes:\n${scopes}things:\n  app:\n    roles:\n${roles}`;
expect('a good installation', 'installations', instFiles(instYaml(), vocabYaml()), 'pass', { has: ['1 example installations'] });
expect('an upstream with no org', 'installations', instFiles(instYaml(''), vocabYaml()), 'fail', { has: ['upstreams.u.org is missing'] });
expect('an org that is an environment', 'installations', instFiles(instYaml('    org: dev\n'), vocabYaml()), 'fail', { has: ['names no boundary of kind company'] });
expect('an org that is no boundary', 'installations', instFiles(instYaml('    org: nobody\n'), vocabYaml()), 'fail', { has: ['names no boundary of kind company'], lacks: ['nobody'] });
expect('a role in the long form with scopes', 'installations', instFiles(instYaml(), vocabYaml('      user: []\n      admin: { implies: [user], scopes: [dev] }\n')), 'pass');
expect('an implied role that is missing', 'installations', instFiles(instYaml(), vocabYaml('      user: []\n      admin: [owner]\n')), 'fail', { has: ['an implied role is not a role of the thing'] });
expect('a role that implies itself', 'installations', instFiles(instYaml(), vocabYaml('      user: [user]\n')), 'fail', { has: ['implies itself'] });
expect('a cycle in the ladder', 'installations', instFiles(instYaml(), vocabYaml('      user: [admin]\n      admin: [user]\n')), 'fail', { has: ['has a cycle'] });
expect('a role scope that is not declared', 'installations', instFiles(instYaml(), vocabYaml('      user: []\n      admin: { implies: [user], scopes: [staging] }\n')), 'fail', { has: ['a scope is not declared'], lacks: ['staging'] });
expect('a role in more scopes than the role it implies', 'installations', instFiles(instYaml(), vocabYaml('      user: { scopes: [dev] }\n      admin: [user]\n')), 'fail', { has: ['exists in a scope that an implied role does not'] });
expect('an unknown key in a scope', 'installations', instFiles(instYaml(), vocabYaml(undefined, '  dev: { secret: true }\n')), 'fail', { has: ['scopes.dev.secret: unknown key'] });
expect('a scope name with a colon', 'installations', instFiles(instYaml(), vocabYaml(undefined, '  "dev:x": {}\n')), 'fail', { has: ['a scope name is outside the allowed set'], lacks: ['dev:x'] });
expect('a client requiring an undeclared grant', 'installations', instFiles(instYaml(undefined, '[dev:app:owner]'), vocabYaml()), 'fail', { has: ['requires[0] is not a grant the vocabulary declares'], lacks: ['owner'] });
expect('a policy file naming an undeclared grant', 'installations', instFiles(instYaml(), vocabYaml(), { 'tests/installations/x/policy/x.cedar': 'permit (principal, action, resource == Grant::"prod:app:root");\n' }), 'fail', { has: ['grant name number 1 is not a grant'], lacks: ['root'] });
expect('no installations', 'installations', { 'README.md': 'x\n' }, 'fail', { has: ['empty sweep'] });

// ---- C10 registries: the kind, key and actor registries of the repository, then one change each
const regFiles = Object.fromEntries(['kinds', 'keys', 'actors'].map((n) => [`docs/architecture/${n}.yaml`, real(`docs/architecture/${n}.yaml`)]));
const nKinds = parseYaml(regFiles['docs/architecture/kinds.yaml']).kinds.length;
const editReg = (path, from, to) => {
  if (!regFiles[path].includes(from)) throw new Error(`selftest fixture: ${path} lacks ${from}`);
  return { ...regFiles, [path]: regFiles[path].replace(from, to) };
};
// An edit inside the block of one kind.
const editKind = (kind, from, to) => {
  const path = 'docs/architecture/kinds.yaml';
  const text = regFiles[path];
  const start = text.indexOf(`  - name: ${kind}\n`);
  if (start < 0) throw new Error(`selftest fixture: no kind ${kind}`);
  const end = text.indexOf('\n  - name:', start + 1);
  const block = text.slice(start, end < 0 ? undefined : end);
  if (!block.includes(from)) throw new Error(`selftest fixture: kind ${kind} lacks ${from}`);
  return { ...regFiles, [path]: text.slice(0, start) + block.replace(from, to) + (end < 0 ? '' : text.slice(end)) };
};
const KY = 'docs/architecture/keys.yaml';
const AY = 'docs/architecture/actors.yaml';
expect('the registries as they are', 'registries', regFiles, 'pass', { has: [`${nKinds} kinds`] });
expect('a kind with two writers', 'registries', editKind('Person', 'writer: session', 'writer: [session, exchange]'), 'fail', { has: ['Person: writer must be one actor'] });
expect('a writer that is no actor', 'registries', editKind('Person', 'writer: session', 'writer: sessions'), 'fail', { has: ['writer sessions is not an actor'] });
expect('a reader that is no actor', 'registries', editKind('Person', 'readers: [session, exchange, signer]', 'readers: [session, exchanger, signer]'), 'fail', { has: ['reader exchanger is not an actor'] });
expect('a reader qualifier that names no contract', 'registries', editKind('MinterConnection', 'adapter-<vendor> (as credential minter)', 'adapter-<vendor> (as minter)'), 'fail', { has: ['(as minter) names no contract'] });
expect('a watcher that is not a reader', 'registries', editKind('Tenant', 'readers: [every actor]', 'readers: [every actor]\n    watched_by: [exporter@]'), 'fail', { has: ['watched_by exporter@ is not one of the readers'] });
expect('a durable kind written by IaC', 'registries', editKind('Person', 'writer: session', 'writer: IaC'), 'fail', { has: ['sluis writes durable and temp kinds'] });
expect('a self-scoped kind that is not declared', 'registries', editKind('Lease', '    self_scoped: true\n', ''), 'fail', { has: ['writer self needs self_scoped: true'] });
expect('a kind the console writes beyond its two', 'registries', editKind('Person', 'writer: session', 'writer: console'), 'fail', { has: ['the console writes only Switch and LogLevelOverride'] });
expect('a temp kind without a time to live', 'registries', editKind('AuthCode', '    ttl: {default: 60s, max: 10m}\n', ''), 'fail', { has: ['AuthCode: a temp kind has a time to live with a default and a max'] });
expect('a temp kind without a maximum', 'registries', editKind('AuthCode', 'ttl: {default: 60s, max: 10m}', 'ttl: {default: 60s}'), 'fail', { has: ['a default and a max'] });
expect('a config kind with a tenant scope', 'registries', editKind('Boundary', 'scope: boundary', 'scope: boundary+tenant'), 'fail', { has: ['Boundary: a config kind has no tenant scope'] });
expect('a personal kind that is plain', 'registries', editKind('Allowance', 'treatment: plain', 'treatment: plain\n    personal: true'), 'fail', { has: ['Allowance: a personal kind is never plain'] });
expect('a personal kind that is sealed', 'registries', editKind('TenantClient', 'treatment: sealed', 'treatment: sealed\n    personal: true'), 'pass');
expect('a personal flag that is not a boolean', 'registries', editKind('Person', 'personal: true', 'personal: yes please'), 'fail', { has: ['Person: personal must be true or false'] });
expect('a config kind marked personal', 'registries', editKind('FirstAdmin', 'treatment: plain', 'treatment: plain\n    personal: true'), 'fail', { has: ['FirstAdmin: a personal kind is never plain'] });
expect('a secret kind that is sealed', 'registries', editKind('UpstreamSecret', 'treatment: plain', 'treatment: sealed'), 'fail', { has: ['a secret kind is plain'] });
expect('a secret kind written by the pipeline', 'registries', editKind('UpstreamSecret', 'writer: IaC', 'writer: pipeline'), 'fail', { has: ['a secret kind is written by IaC'] });
expect('a temp kind that is backed up', 'registries', editKind('AuthCode', 'backed_up: no', 'backed_up: yes'), 'fail', { has: ['only a durable kind is backed up'] });
expect('an exportable kind the exporter does not read', 'registries', editKind('Crl', 'readers: [exporter@]', 'readers: [ca]'), 'fail', { has: ['an exportable kind is read by exporter@'] });
expect('a kind served by another family than its writer', 'registries', editKind('Person', 'serves: work', 'serves: keys'), 'fail', { has: ['serves keys, but its writer session is in the family work'] });
expect('a linked kind that does not exist', 'registries', editKind('Upstream', 'links: [UpstreamSecret]', 'links: [UpstreamSecrets]'), 'fail', { has: ['links UpstreamSecrets, which is not a kind'] });
expect('a sealed kind whose writer cannot seal', 'registries', editKind('Person', 'writer: session', 'writer: policy'), 'fail', { has: ['Person is sealed, but its writer policy has no data key seal'] });
expect('a sealed kind whose reader cannot open', 'registries', editKind('Person', 'readers: [session, exchange, signer]', 'readers: [session, exchange, signer, quota]'), 'fail', { has: ['its reader quota has no data key open'] });
expect('DataKeyWrap with other data key purposes than keys.yaml', 'registries', editKind('DataKeyWrap', 'per_tenant: [data, pseudonym, pairwise, evidence]', 'per_tenant: [data, evidence]'), 'fail', { has: ['DataKeyWrap.purposes must equal the data key purposes'] });
expect('a baseline that is not 1 symmetric and 5 P-384 keys', 'registries', editReg(KY, '  - name: ssh-host\n    kind: signing\n    algorithm: ES384\n    enabled: baseline\n    ops: [sign, public-key]\n    aws: { key_spec: ECC_NIST_P384', '  - name: ssh-host\n    kind: signing\n    algorithm: ES384\n    enabled: baseline\n    ops: [sign, public-key]\n    aws: { key_spec: ECC_NIST_P256'), 'fail', { has: ['the AWS baseline is 1 symmetric key and 5 P-384 keys'] });
expect('two purposes in one card slot', 'registries', editReg(KY, "board: { slot: '83' }", "board: { slot: '82' }"), 'fail', { has: ['slot 82 is also the slot of ssh-user'] });
expect('a slot that the plan gives to another purpose', 'registries', editReg(KY, "'83': ssh-host", "'83': ssh-user"), 'fail', { has: ['slot_plan.slots.83 is ssh-user'] });
expect('a signing key with two using actors', 'registries', editReg(KY, '    users: [signer]\n    notes: "Signs tokens.', '    users: [signer, ca]\n    notes: "Signs tokens.'), 'fail', { has: ['exactly one using actor'] });
expect('a key purpose with an algorithm that is not declared', 'registries', editReg(KY, 'algorithm: AES-256-GCM\n    enabled: baseline', 'algorithm: AES-512\n    enabled: baseline'), 'fail', { has: ['algorithm AES-512 is not declared'] });
expect('a user that is no actor', 'registries', editReg(KY, 'users: [ssh-ca]\n    notes: "The SSH user', 'users: [ssh-cas]\n    notes: "The SSH user'), 'fail', { has: ['user ssh-cas is not an actor'] });
expect('an actor using a purpose keys.yaml lacks', 'registries', editReg(AY, '- { purpose: grant, ops: [seal] }', '- { purpose: grnt, ops: [seal] }'), 'fail', { has: ['the key purpose grnt is not in docs/architecture/keys.yaml'] });
expect('an actor using an op the purpose does not allow', 'registries', editReg(AY, '- { purpose: x509-intermediate, ops: [sign, public-key] }', '- { purpose: x509-intermediate, ops: [sign, seal] }'), 'fail', { has: ['x509-intermediate does not allow the op seal'] });
expect('a user that does not list the purpose', 'registries', editReg(KY, '    cookie:\n      ops: [seal, open]\n      users: [session]', '    cookie:\n      ops: [seal, open]\n      users: [session, policy]'), 'fail', { has: ['policy is a user, but its key_purposes'] });
expect('an actor using a purpose it is no user of', 'registries', editReg(KY, 'users: [entry, session, ca, adapter-github]', 'users: [entry, session, ca]'), 'fail', { has: ['does not list adapter-github as a user of mac'] });
expect('a temp kind whose default is above its maximum', 'registries', editKind('AuthCode', 'ttl: {default: 60s, max: 10m}', 'ttl: {default: 11m, max: 10m}'), 'fail', { has: ['AuthCode: ttl.default 11m is above ttl.max 10m'] });
expect('a default above its maximum, in other units', 'registries', editKind('PendingEnrolment', 'ttl: {default: 7d, max: 30d}', 'ttl: {default: 721h, max: 30d}'), 'fail', { has: ['PendingEnrolment: ttl.default 721h is above ttl.max 30d'] });
expect('a temp kind whose maximum is 0s', 'registries', editKind('AuthCode', 'ttl: {default: 60s, max: 10m}', 'ttl: {default: 0s, max: 0s}'), 'fail', { has: ['AuthCode: ttl.max is 0s'] });
expect('a temp kind whose maximum is a bare 0', 'registries', editKind('Lease', 'ttl: {default: 30s, max: 10m}', 'ttl: {default: 30s, max: 0}'), 'fail', { has: ['Lease: ttl.max is 0'] });
expect('a maximum above the decided one', 'registries', editKind('AuthCode', 'ttl: {default: 60s, max: 10m}', 'ttl: {default: 60s, max: 11m}'), 'fail', { has: ['AuthCode: ttl.max 11m is above the decided maximum 10m'] });
expect('a directory fact kept longer than the decided maximum', 'registries', editKind('DirectoryUser', 'max: 7d', 'max: 8d'), 'fail', { has: ['DirectoryUser: ttl.max 8d is above the decided maximum 7d'] });
expect('a decided maximum that is not a duration', 'registries', editKind('Lease', 'ttl: {default: 30s, max: 10m}', 'ttl: {default: 30s, max: long}'), 'fail', { has: ['Lease: ttl.max must be a duration, at most the decided maximum 10m'] });
expect('a maximum below the decided one is fine', 'registries', editKind('AuthCode', 'ttl: {default: 60s, max: 10m}', 'ttl: {default: 60s, max: 5m}'), 'pass');
expect('a PIN release kept longer than the decided maximum', 'registries', editKind('PinRelease', 'max: 15m', 'max: 16m'), 'fail', { has: ['PinRelease: ttl.max 16m is above the decided maximum 15m'] });
expect('a sealed kind with no tenant, whose reader has no boundary data key', 'registries', editKind('EnrolmentToken', 'readers: [exchange]', 'readers: [exchange, session]'), 'fail', { has: ['EnrolmentToken is sealed and has no tenant', 'does not list session'] });
expect('a sealed kind made boundary-scoped by an edit', 'registries', editKind('Person', 'scope: boundary+tenant', 'scope: boundary'), 'fail', { has: ['Person is sealed and has no tenant', 'does not list session'] });
expect('DataKeyWrap with three boundary data keys', 'registries', editKind('DataKeyWrap', 'boundary: [grant, cookie, mac, data]', 'boundary: [grant, cookie, mac]'), 'fail', { has: ['DataKeyWrap.purposes must equal the data key purposes'] });
expect('a boundary data key that is missing from keys.yaml', 'registries', editReg(KY, '    data:\n      ops: [seal, open]\n      users: [exchange, console]\n      erased: never', '    datum:\n      ops: [seal, open]\n      users: [exchange, console]\n      erased: never'), 'fail', { has: ['data_keys.boundary must be exactly grant, cookie, mac, data'] });
expect('an actor using the archive key with an op it does not allow', 'registries', editReg(AY, '- { purpose: backup-archive, ops: [wrap] }', '- { purpose: backup-archive, ops: [wrap, seal] }'), 'fail', { has: ['backup-archive does not allow the op seal'] });
expect('a backed-up kind that does not list exporter@ is read by the backup job', 'registries', regFiles, 'pass', { has: ['40 backed up, read by exporter@\'s backup job as ciphertext'] });
expect('a backup job without the exporter actor', 'registries', editReg(AY, '  - name: exporter\n    family: data', '  - name: exporters\n    family: data'), 'fail', { has: ['the backup job\'s actor exporter is not an actor'] });
expect('a backup job whose actor is not a data actor', 'registries', editReg(AY, '  - name: exporter\n    family: data', '  - name: exporter\n    family: work'), 'fail', { has: ['the backup job\'s actor is in the data family (it is work)'] });
expect('a backup job without the data port', 'registries', editReg(AY, 'ports: [data, keys, audit-emit, destination]', 'ports: [keys, audit-emit, destination]'), 'fail', { has: ['exporter@ reads the backed-up kinds through the data port'] });
expect('no key registry', 'registries', { ...regFiles, [KY]: undefined }, 'fail', { has: ['keys.yaml is missing'] });
expect('an external caller that keys.yaml does not list', 'registries', editReg(KY, 'users: [every work actor, reader, product-emitter]', 'users: [every work actor, reader]'), 'fail', { has: ['does not list product-emitter as a user of pseudonym'] });
expect('a user that is neither an actor nor an external caller', 'registries', editReg(KY, 'users: [every work actor, reader, product-emitter]', 'users: [every work actor, reader, product-emitters]'), 'fail', { has: ['user product-emitters is not an actor'] });

// ---- C11 terms: the glossary's lint section, in warn mode and in error mode
const glossary = (extra = {}) => `schema: ${extra.schema ?? 1}
checked: "2026-11-03"
categories: {families: "Families"}
terms:
  - {term: family, definition: "One of four groups.", category: families}
retired:
  - {id: key-holder, term: key-holder, replacement: "key@", allowed_in: []}
  - {id: origin, term: origin, replacement: "storage class", allowed_in: []}${extra.retired ?? ''}
lint:
  scope: {include: ["docs/**/*.md", "docs/**/*.yaml"], exclude: ["docs/glossary.yaml", "docs/old/**"]}
  skip_records: [{files: "docs/requirements/*.yaml", where: {status: withdrawn}}]
  case_insensitive: true
  strip_before_match: ['\\]\\([^)]*\\)']
  rules:
    - {id: key-holder, pattern: '\\bkey[- ]holders?\\b'}
    - {id: origin, pattern: '\\borigins?\\b', context_allow: '(CORS|same-origin)'}${extra.rules ?? ''}
`;
const withGlossary = (docs, extra) => ({ 'docs/glossary.yaml': glossary(extra), ...docs });
const req = (status) => `requirements:\n  - id: REQ-X-001\n    status: ${status}\n    statement: "The key-holder MUST sign."\n  - id: REQ-X-002\n    status: planned\n    statement: "Fine."\n`;
expect('no hit', 'terms', withGlossary({ 'docs/a.md': 'The key service seals.\n' }), 'pass', { has: ['0 hits in 0 files', 'warn mode, exit 0'] });
expect('a hit in warn mode', 'terms', withGlossary({ 'docs/a.md': 'Ask the key-holder.\n' }), 'pass', { has: ['docs/a.md:1: retired term "key-holder" (key-holder): use key@', '1 hits in 1 files', 'warn mode'] });
expect('a hit in error mode', 'terms', withGlossary({ 'docs/a.md': 'Ask the key-holder.\n' }), 'fail', { args: ['--error'], has: ['docs/a.md:1: retired term', '1 retired terms'] });
expect('a hit with TERMS_MODE=error', 'terms', withGlossary({ 'docs/a.md': 'Ask the key holders.\n' }), 'fail', { env: { TERMS_MODE: 'error' }, has: ['docs/a.md:1'] });
expect('the match is case-insensitive and whole-word', 'terms', withGlossary({ 'docs/a.md': 'The KEY-HOLDER and a monkey-holder.\n' }), 'pass', { has: ['1 hits in 1 files'] });
expect('a link target is not prose', 'terms', withGlossary({ 'docs/a.md': 'See [the keys](/decisions/0006-key-holder-and-origins/) page.\n' }), 'pass', { has: ['0 hits'] });
expect('a hit that the rule\'s context_allow lets through', 'terms', withGlossary({ 'docs/a.md': 'The CORS origin header.\nThe origin of the data.\n' }), 'pass', { has: ['docs/a.md:2:', '1 hits in 1 files'], lacks: ['docs/a.md:1:'] });
expect('a terms-allow marker on the line before', 'terms', withGlossary({ 'docs/a.md': '<!-- terms-allow: key-holder -->\nThe key-holder stood in the road.\n' }), 'pass', { args: ['--error'], has: ['1 terms-allow marker', 'docs/a.md:1: terms-allow key-holder', 'no retired terms'] });
expect('a terms-allow marker for another term', 'terms', withGlossary({ 'docs/a.md': '<!-- terms-allow: origin -->\nThe key-holder.\n' }), 'fail', { args: ['--error'], has: ['docs/a.md:2:'] });
expect('a terms-allow marker with a comma list', 'terms', withGlossary({ 'docs/a.md': 'The key-holder at its origin. terms-allow: origin, key-holder\n' }), 'pass', { args: ['--error'] });
expect('a terms-allow marker with an unknown id', 'terms', withGlossary({ 'docs/a.md': '<!-- terms-allow: mediator -->\nText.\n' }), 'fail', { has: ['terms-allow names mediator'] });
expect('an excluded path', 'terms', withGlossary({ 'docs/old/a.md': 'The key-holder.\n', 'docs/b.md': 'Text.\n' }), 'pass', { args: ['--error'] });
expect('a withdrawn record is skipped, an active one is not', 'terms', withGlossary({ 'docs/requirements/x.yaml': req('withdrawn') + req('planned').replace('requirements:\n', '') }), 'pass', { has: ['x.yaml:10:', '1 hits'], lacks: ['x.yaml:4:'] });
expect('a file outside the include globs', 'terms', withGlossary({ 'docs/a.md': 'Text.\n', 'tools/a.mjs': '// the key-holder\n' }), 'pass', { args: ['--error'] });
expect('a rule for a term that is not retired', 'terms', withGlossary({ 'docs/a.md': 'Text.\n' }, { rules: "\n    - {id: mediator, pattern: '\\\\bmediator\\\\b'}" }), 'fail', { has: ['lint.rules[2] (mediator): id is not a retired id'] });
expect('a retired term without a rule', 'terms', withGlossary({ 'docs/a.md': 'Text.\n' }, { retired: '\n  - {id: pkl, term: Pkl, replacement: "Protobuf", allowed_in: []}' }), 'fail', { has: ['retired term pkl has no rule'] });
expect('a pattern that does not compile', 'terms', withGlossary({ 'docs/a.md': 'Text.\n' }, { rules: "\n    - {id: key-holder, pattern: '(open'}" }), 'fail', { has: ['pattern'] });
expect('a glossary of another schema', 'terms', withGlossary({ 'docs/a.md': 'Text.\n' }, { schema: 2 }), 'fail', { has: ['schema must be 1'] });
expect('no glossary', 'terms', { 'docs/a.md': 'Text.\n' }, 'fail', { has: ['docs/glossary.yaml is missing'] });
expect('nothing in the scope', 'terms', { 'docs/glossary.yaml': glossary(), 'README.txt': 'x\n' }, 'fail', { has: ['empty sweep'] });

// ---- C11 generated pages: the glossary, kind, rule and key pages of the repository, then one change each.
// The fixtures are the registries, the pages and the decision records the pages link.
const pageRecords = Object.fromEntries(readdirSync(join(repo, 'docs/decisions')).filter((f) => /^[0-9]{4}-.*\.md$/.test(f) && !f.startsWith('0000')).map((f) => [`docs/decisions/${f}`, real(`docs/decisions/${f}`)]));
const pageFiles = (names) => ({ ...Object.fromEntries(names.map((p) => [p, real(p)])), ...pageRecords });
const pageEdit = (files, path, from, to) => {
  if (!files[path].includes(from)) throw new Error(`selftest fixture: ${path} lacks ${from}`);
  return { ...files, [path]: files[path].replace(from, to) };
};
const GLOSSARY = 'docs/glossary.yaml';
const glossaryPage = pageFiles([GLOSSARY, 'docs/concepts/index.md']);
const nTerms = parseYaml(glossaryPage[GLOSSARY]).terms.length;
expect('the vocabulary page as it is', 'glossary-page', glossaryPage, 'pass', { has: [`${nTerms} terms, no errors`] });
expect('a definition changed, the page not rewritten', 'glossary-page', pageEdit(glossaryPage, GLOSSARY, 'A program with one responsibility', 'A program with a single job'), 'fail', { has: ['generated block is stale', 'just glossary-write'] });
expect('a retired term added, the page not rewritten', 'glossary-page', pageEdit(glossaryPage, GLOSSARY, '  - term: Pkl\n', '  - term: Pkl2\n'), 'fail', { has: ['generated block is stale'] });
expect('a term in a category that is not declared', 'glossary-page', pageEdit(glossaryPage, GLOSSARY, 'category: families\n    see: ["0002-families-of-actors"]', 'category: families2\n    see: ["0002-families-of-actors"]'), 'fail', { has: ['category families2 is not in categories'] });
expect('a term defined twice', 'glossary-page', pageEdit(glossaryPage, GLOSSARY, '  - term: work actor\n', '  - term: family\n'), 'fail', { has: ['the term is defined twice'] });
expect('a see that names a record that does not exist', 'glossary-page', pageEdit(glossaryPage, GLOSSARY, '"0002-families-of-actors#the-four-families", "/concepts/families/"', '"0099-gone#the-four-families", "/concepts/families/"'), 'fail', { has: ['there is no record 0099'] });
expect('a see that names a heading the record does not have', 'glossary-page', pageEdit(glossaryPage, GLOSSARY, '"0002-families-of-actors#the-four-families", "/concepts/families/"', '"0002-families-of-actors#nowhere", "/concepts/families/"'), 'fail', { has: ['has no heading #nowhere'] });
expect('a vocabulary page without its markers', 'glossary-page', { ...glossaryPage, 'docs/concepts/index.md': '---\ntitle: Concepts\n---\n\nText.\n' }, 'fail', { has: ['markers are missing'] });
expect('no vocabulary page', 'glossary-page', { ...glossaryPage, 'docs/concepts/index.md': undefined }, 'fail', { has: ['docs/concepts/index.md is missing'] });
expect('no glossary', 'glossary-page', { ...glossaryPage, [GLOSSARY]: undefined }, 'fail', { has: ['docs/glossary.yaml is missing'] });

const KINDS_YAML = 'docs/architecture/kinds.yaml';
const KEYS_YAML = 'docs/architecture/keys.yaml';
const ACTORS_YAML = 'docs/architecture/actors.yaml';
const kindsPage = pageFiles([KINDS_YAML, ACTORS_YAML, 'docs/reference/kinds.md']);
expect('the kinds page as it is', 'kinds-page', kindsPage, 'pass', { has: [`${nKinds} kinds, no errors`] });
expect('a kind that gains a reader, the page not rewritten', 'kinds-page', pageEdit(kindsPage, KINDS_YAML, 'readers: [session, exchange, signer]', 'readers: [session, exchange, signer, policy]'), 'fail', { has: ['generated block is stale', 'just kinds-write'] });
expect('a time to live changed, the page not rewritten', 'kinds-page', pageEdit(kindsPage, KINDS_YAML, 'ttl: {default: 60s, max: 10m}', 'ttl: {default: 30s, max: 10m}'), 'fail', { has: ['generated block is stale'] });
expect('a kind of an unknown class', 'kinds-page', pageEdit(kindsPage, KINDS_YAML, '    class: secret\n', '    class: vault\n'), 'fail', { has: ['class must be one of'] });
expect('a kind listed twice', 'kinds-page', pageEdit(kindsPage, KINDS_YAML, '  - name: TrustAnchors\n', '  - name: Boundary\n'), 'fail', { has: ['the kind is listed twice'] });
expect('a kinds page without its markers', 'kinds-page', { ...kindsPage, 'docs/reference/kinds.md': '---\ntitle: Kinds\n---\n\nText.\n' }, 'fail', { has: ['markers are missing'] });
expect('no kind registry', 'kinds-page', { ...kindsPage, [KINDS_YAML]: undefined }, 'fail', { has: ['kinds.yaml is missing'] });

const rulesPage = pageFiles([KINDS_YAML, ACTORS_YAML, 'docs/reference/rules.md']);
expect('the rules page as it is', 'rules-page', rulesPage, 'pass', { has: ['rules, no errors'] });
expect('a reader added, the page not rewritten', 'rules-page', pageEdit(rulesPage, KINDS_YAML, 'readers: [session, exchange, signer]', 'readers: [session, exchange, signer, policy]'), 'fail', { has: ['generated block is stale', 'just rules-write'] });
expect('a call added, the page not rewritten', 'rules-page', pageEdit(rulesPage, ACTORS_YAML, 'calls: [policy, signer, exchange, adapter-upstream-oidc]', 'calls: [policy, signer, exchange, ca, adapter-upstream-oidc]'), 'fail', { has: ['generated block is stale'] });
expect('a reader that is neither an actor nor a macro', 'rules-page', pageEdit(rulesPage, KINDS_YAML, 'readers: [session, exchange, signer]', 'readers: [session, exchanger, signer]'), 'fail', { has: ['exchanger is neither an actor nor a known macro'] });
expect('a rules page without its markers', 'rules-page', { ...rulesPage, 'docs/reference/rules.md': '---\ntitle: Rules\n---\n\nText.\n' }, 'fail', { has: ['markers are missing'] });
expect('no actor registry for the rules', 'rules-page', { ...rulesPage, [ACTORS_YAML]: undefined }, 'fail', { has: ['actors.yaml is missing'] });

const keysPage = pageFiles([KEYS_YAML, ACTORS_YAML, 'docs/reference/keys.md']);
expect('the keys page as it is', 'keys-page', keysPage, 'pass', { has: ['key purposes, no errors'] });
expect('a note changed, the page not rewritten', 'keys-page', pageEdit(keysPage, KEYS_YAML, 'The SSH user certificate authority.', 'The SSH user CA.'), 'fail', { has: ['generated block is stale', 'just keys-write'] });
expect('a slot changed, the page not rewritten', 'keys-page', pageEdit(keysPage, KEYS_YAML, "'83': ssh-host", "'93': ssh-host"), 'fail', { has: ['generated block is stale'] });
expect('a data key user added, the page not rewritten', 'keys-page', pageEdit(keysPage, KEYS_YAML, 'users: [session]\n      erased: never\n      notes: "Seals and opens the session cookie', 'users: [session, policy]\n      erased: never\n      notes: "Seals and opens the session cookie'), 'fail', { has: ['generated block is stale'] });
expect('a purpose with an algorithm that is not declared', 'keys-page', pageEdit(keysPage, KEYS_YAML, 'algorithm: AES-256-GCM\n    enabled: baseline', 'algorithm: AES-512\n    enabled: baseline'), 'fail', { has: ['algorithm AES-512 is not declared'] });
expect('a slot that names no purpose', 'keys-page', pageEdit(keysPage, KEYS_YAML, "'83': ssh-host", "'83': ssh-hosts"), 'fail', { has: ['ssh-hosts, which is not a purpose'] });
expect('a keys page without its markers', 'keys-page', { ...keysPage, 'docs/reference/keys.md': '---\ntitle: Keys\n---\n\nText.\n' }, 'fail', { has: ['markers are missing'] });
expect('no key registry', 'keys-page', { ...keysPage, [KEYS_YAML]: undefined }, 'fail', { has: ['keys.yaml is missing'] });

rmSync(scratch, { recursive: true, force: true });
if (failures) {
  console.error(`selftest: ${failures} of ${cases} cases failed`);
  process.exit(1);
}
console.log(`selftest: ${cases} cases, all as expected`);
