#!/usr/bin/env node
// The rules page, docs/reference/rules.md: the rules over kinds (actor x kind x verb) from the kind registry,
// docs/architecture/kinds.yaml, and the call graph from the actor registry, docs/architecture/actors.yaml.
// The block between the markers is generated; the check fails while it is stale (`--write` rewrites it).
//
// A kind row gives a write rule to its writer (create, update, delete), a read rule to each reader (get, list)
// and a watch rule to each watcher: the readers named in `watched_by` of a durable or temp kind, exporter@ for an
// exportable kind, and every reader of a config kind (it gets the changes with the snapshot). A reader written
// `adapter-<vendor> (as <contract>)` gives the rule to the adapters that implement the contract only. A reader or writer written as a macro (`every actor`, `self`, `adapter-<vendor>`, `the actor
// named in the id`) is expanded here; anything the registry does not allow is denied. The registries
// themselves are checked by tools/checks/registries.mjs and tools/checks/actors.mjs.
//
// usage: tools/checks/rules-page.mjs [--write] [repo-root]
import { code, generator, list, md, table } from './pages-lib.mjs';

const KINDS = 'docs/architecture/kinds.yaml';
const ACTORS = 'docs/architecture/actors.yaml';
const PAGE = 'docs/reference/rules.md';
const g = generator('check-rules-page', 'rules-page.mjs', { source: `${KINDS} and ${ACTORS}`, page: PAGE, recipe: 'rules-write' });
const { error, load, adr, adrHref, heading } = g;

const kreg = load(KINDS);
const areg = load(ACTORS);
const kinds = Array.isArray(kreg?.kinds) ? kreg.kinds : [];
const actors = Array.isArray(areg?.actors) ? areg.actors : [];
const platform = Array.isArray(areg?.platform) ? areg.platform : [];
const portDefs = areg?.ports ?? {};
const names = new Set(actors.map((a) => a.name));
const adapters = actors.filter((a) => /^adapter-/.test(a.name)).map((a) => a.name);
// `(as <contract>)` after a reader: the contract of actors.yaml that the adapter implements.
const AS_CONTRACT = { 'credential minter': 'CredentialMinter', provisioner: 'Provisioner', 'facts source': 'FactsSource', upstream: 'Upstream', notifier: 'Notifier' };
const implementing = (contract) => actors.filter((a) => /^adapter-/.test(a.name) && (a.contracts ?? []).includes(contract)).map((a) => a.name);
const CLASSES = ['config', 'secret', 'durable', 'temp'];
const OUTSIDE = new Set(['IaC', 'pipeline']);
const VERBS = { write: 'create, update, delete', read: 'get, list', watch: 'watch' };
const kindLink = (n) => `[${code(n)}](/reference/kinds/#${n.toLowerCase()})`;
const actorLink = (n) => `[${code(n)}](/reference/actors/#${n})`;

// One token of `writer` or `readers`: the actors it names and the macro it came from, if any.
function expand(tok) {
  const m = /^(.*?)\s*(?:\((.*)\))?$/.exec(tok.trim());
  const base = m[1];
  const qual = m[2] ?? '';
  const plain = base.replace(/@$/, '');
  if (names.has(plain)) return { actors: [plain], macro: null, qual };
  if (OUTSIDE.has(base)) return { actors: [], outside: base };
  if (base === 'every actor') return { actors: [...names], macro: 'every actor', qual: /own id/.test(qual) ? 'own id only' : qual };
  if (base === 'self') return { actors: [...names], macro: 'every actor', qual: 'ids under its own name' };
  if (base === 'adapter-<vendor>') {
    const c = /^as (.+)$/.exec(qual);
    if (c) {
      if (!(c[1] in AS_CONTRACT)) { error(`${KINDS}: ${tok}: (as ${c[1]}) names no contract`); return { actors: [], outside: tok }; }
      return { actors: implementing(AS_CONTRACT[c[1]]), macro: 'every adapter', qual: `implements ${AS_CONTRACT[c[1]]}` };
    }
    return { actors: adapters, macro: 'every adapter', qual: qual || 'ids under its own name' };
  }
  if (base === 'the actor named in the id') return { actors: /adapter/.test(qual) ? adapters : [...names], macro: /adapter/.test(qual) ? 'every adapter' : 'every actor', qual: 'the actor named in the id' };
  if (/^none yet/.test(base)) return { actors: [], outside: 'none yet' };
  error(`${KINDS}: ${tok} is neither an actor nor a known macro`);
  return { actors: [], outside: tok };
}

// the rules: {actor, verb, kind, macro, qual}
const rules = [];
const unwritten = new Map(); // outside writer -> kinds
for (const k of kinds) {
  const w = expand(k.writer);
  if (w.outside) unwritten.set(w.outside, [...(unwritten.get(w.outside) ?? []), k.name]);
  for (const a of w.actors) rules.push({ actor: a, verb: 'write', kind: k, macro: w.macro, qual: w.qual });
  for (const t of k.readers ?? []) {
    const r = expand(t);
    for (const a of r.actors) rules.push({ actor: a, verb: 'read', kind: k, macro: r.macro, qual: r.qual });
  }
  // the watch rules
  const watchers = k.class === 'config' ? (k.readers ?? []) : (k.watched_by ?? []);
  const seen = new Set();
  for (const t of [...watchers, ...(k.exportable === 'yes' ? ['exporter@'] : [])]) {
    const r = expand(t);
    for (const a of r.actors) if (!seen.has(`${a}|${r.macro}|${r.qual}`)) { seen.add(`${a}|${r.macro}|${r.qual}`); rules.push({ actor: a, verb: 'watch', kind: k, macro: r.macro, qual: r.qual }); }
  }
  // the backup job reads every backed-up kind as ciphertext, whatever `readers` lists
  if (k.backed_up === 'yes' && !rules.some((r) => r.actor === 'exporter' && r.verb === 'read' && r.kind === k)) {
    rules.push({ actor: 'exporter', verb: 'read', kind: k, macro: null, qual: 'backup job, as ciphertext' });
  }
}

function render() {
  const out = [];
  const nKinds = kinds.length;
  out.push(`${rules.length} rules over ${nKinds} kinds and ${actors.length} actors (kind registry checked ${kreg.checked}). Anything not listed is denied.`, '');
  out.push(heading(2, 'The verbs'), '',
    `A rule says that an actor may use a verb on a kind. The store checks it on every call and denies by default ([store rules](${adrHref('0005', 'rules')})). The two registries generate every layer that enforces it ([registries generate the enforcement](${adrHref('0002', 'registries-generate-the-enforcement')})).`, '');
  out.push(...table(['Verb', 'Given to', 'What it allows'], [
    ['create, update, delete', 'the kind\'s one writer', 'Changing the kind\'s items. The store also checks the schema, the version, the bounds and the links on a write.'],
    ['get, list', 'each reader', 'Reading items. A sealed value opens only at key@, with a grant sealed for its tenant.'],
    ['watch', 'each watcher: a reader that the kind names in `watched_by`, exporter@ for an exportable kind, and every reader of a config kind', 'A change feed from a resume point. A kind that nobody watches, such as an allowance or a rate window, has none.'],
  ]), '');
  out.push('A config or secret kind has no actor as its writer: infrastructure as code or the publishing pipeline writes it. The store reads the config bounds of a layered kind itself.', '');

  // macro rules
  out.push(heading(2, 'Rules every actor has'), '', 'A rule written for a whole set of actors, in the registry as a macro, is shown once here and not repeated in the sections below.', '');
  const groups = new Map();
  for (const r of rules.filter((x) => x.macro)) {
    const key = `${r.macro}|${r.verb}|${r.qual}`;
    if (!groups.has(key)) groups.set(key, { ...r, kinds: new Set() });
    groups.get(key).kinds.add(r.kind.name);
  }
  out.push(...table(['Actors', 'Verb', 'Condition', 'Kinds'], [...groups.values()].sort((a, b) => a.macro.localeCompare(b.macro) || a.verb.localeCompare(b.verb))
    .map((x) => [x.macro, VERBS[x.verb], md(x.qual || '—'), list([...x.kinds].map(kindLink))])), '');

  // matrix
  out.push(heading(2, 'Deny matrix'), '',
    'Per actor and class: how many kinds it may write (w) and read (r), macro rules included. Every other pair of actor and kind is denied, so the last column counts the kinds an actor cannot touch at all. The store reads the config bounds of a layered kind itself, which no rule lists.', '');
  const rows = actors.map((a) => {
    const mine = rules.filter((r) => r.actor === a.name);
    const cell = (c) => {
      const w = new Set(mine.filter((r) => r.verb === 'write' && r.kind.class === c).map((r) => r.kind.name)).size;
      const r = new Set(mine.filter((x) => x.verb === 'read' && x.kind.class === c).map((x) => x.kind.name)).size;
      return `${w} / ${r}`;
    };
    const touched = new Set(mine.map((r) => r.kind.name)).size;
    return [`[${code(a.name)}](#${a.name})`, a.family, ...CLASSES.map(cell), `${nKinds - touched}`];
  });
  out.push(...table(['Actor', 'Family', 'Config (w / r)', 'Secret (w / r)', 'Durable (w / r)', 'Temp (w / r)', 'Denied kinds'], rows), '');
  out.push(`The full deny matrix is generated from the same registries and tested: for every pair of actors, X is denied Y's kinds, keys and sockets ([registries generate the enforcement](${adrHref('0002', 'registries-generate-the-enforcement')})).`, '');

  // per actor
  out.push(heading(2, 'Rules per actor'), '', 'Each actor\'s own rules: the kinds it writes and the kinds it reads by name. The rules every actor has are above.', '');
  for (const a of actors) {
    const mine = rules.filter((r) => r.actor === a.name && !r.macro);
    const lines = (verb) => {
      const m = new Map();
      for (const r of mine.filter((x) => x.verb === verb)) m.set(r.kind.name, r.qual);
      return [...m].map(([n, q]) => `${kindLink(n)}${q ? ` (${md(q)})` : ''}`);
    };
    out.push(heading(3, code(a.name)), '', `${a.family} family. ${a.holder ? 'A credential holder.' : 'Holds no credential at rest.'}`, '');
    out.push(`- **Writes** (create, update, delete): ${list(lines('write'))}.`);
    out.push(`- **Reads** (get, list): ${list(lines('read'))}.`);
    out.push(`- **Watches** (change feed): ${list(lines('watch'))}.`, '');
  }

  out.push(heading(2, 'Kinds no actor writes'), '', 'The writer of these kinds is outside sluis, or the kind has no writer yet.', '');
  out.push(...table(['Writer', 'Kinds'], [...unwritten].map(([w, ks]) => [code(w), list(ks.map(kindLink))])), '');

  // call graph
  out.push(heading(2, 'Call graph'), '',
    `Which actor calls which, besides the data, keys and audit-emit ports. The graph is default deny: it is enforced by one interceptor in every process and again by each transport (${adr('0003', 'the-call-graph', 'the call graph')}). Calls to store and key go through the ports, so they are not listed.`, '');
  const all = [...actors, ...platform];
  const calledBy = new Map(all.map((a) => [a.name, []]));
  for (const a of all) for (const c of a.calls) {
    if (c === 'adapter-<vendor>') for (const ad of adapters) calledBy.get(ad)?.push(a.name);
    else calledBy.get(c)?.push(a.name);
  }
  const callTxt = (c) => (c === 'adapter-<vendor>' ? 'any adapter' : actorLink(c));
  out.push(...table(['Actor', 'Calls', 'Called by'], all.filter((a) => a.calls.length || calledBy.get(a.name).length).map((a) => [
    actorLink(a.name), list(a.calls.map(callTxt)), list(calledBy.get(a.name).map(actorLink)),
  ])), '');
  out.push(heading(3, 'Ports'), '', 'Every actor reaches the other families through ports, and a port that is not shared belongs to one family.', '');
  out.push(...table(['Port', 'Reaches', 'Actors that have it'], Object.entries(portDefs).map(([n, p]) => {
    const has = all.filter((a) => a.ports.includes(n));
    return [code(n), md(p.description), has.length === actors.length ? 'every actor' : list(has.map((a) => actorLink(a.name)))];
  })));
  return out;
}

g.sync(render, rules.length, 'rules');
