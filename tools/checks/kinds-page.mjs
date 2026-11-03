#!/usr/bin/env node
// The kinds page, docs/reference/kinds.md, against the kind registry, docs/architecture/kinds.yaml:
// every kind with its class, scope, treatment, profile, writer, readers, lifetime, whether it is exportable
// and backed up, then the layered groups and how their layers combine, the built-in values and what is
// not data. The block between the markers is generated; the check fails while it is stale (`--write`
// rewrites it).
//
// The registry itself is checked by tools/checks/registries.mjs; this reads it as it is.
//
// usage: tools/checks/kinds-page.mjs [--write] [repo-root]
import { anchor, code, generator, kebab, list, md, table } from './pages-lib.mjs';

const SOURCE = 'docs/architecture/kinds.yaml';
const ACTORS = 'docs/architecture/actors.yaml';
const PAGE = 'docs/reference/kinds.md';
const g = generator('check-kinds-page', 'kinds-page.mjs', { source: SOURCE, page: PAGE, recipe: 'kinds-write' });
const { error, load, adr, adrHref, claim, heading } = g;

const reg = load(SOURCE);
const actorReg = load(ACTORS);
const kinds = Array.isArray(reg?.kinds) ? reg.kinds : [];
const actorNames = new Set([...(actorReg?.actors ?? []), ...(actorReg?.platform ?? [])].map((a) => a.name));
const kindNames = new Set(kinds.map((k) => k.name));
const CLASSES = ['config', 'secret', 'durable', 'temp'];
const CLASS_TEXT = {
  config: 'Signed configuration, written by infrastructure as code or the publishing pipeline, never by an actor.',
  secret: 'Read-only secrets, held by the secret source and written by infrastructure as code.',
  durable: "Read-write state that must survive, behind the store's durable port; backed up when authoritative.",
  temp: 'State with a time to live, kept in the temp engine.',
};

// A writer or reader token as a link: `store@` and its kin name the actors store, key and exporter; a
// trailing parenthesis qualifies the name.
function who(tok) {
  const m = /^([a-z][a-z0-9-]*)(@)?(\s*\(.*\))?$/.exec(tok.trim());
  if (m && actorNames.has(m[1])) return `[${code(m[1] + (m[2] ?? ''))}](/reference/actors/#${m[1]})${m[3] ? md(m[3]) : ''}`;
  return /^(IaC|pipeline)$/.test(tok) ? code(tok) : md(tok);
}
const kindLink = (n) => (kindNames.has(n) ? `[${code(n)}](#${n.toLowerCase()})` : code(n));
const profile = (k) => (k.profile === '-' ? 'none' : k.profile);
const yn = (v) => (v === true || v === 'yes' ? 'yes' : 'no');
const ttlText = (k) => {
  if (!k.ttl) return null;
  const { field, default: d, max } = k.ttl;
  return [field ? `field ${code(field)}` : null, d ? `default ${md(d)}` : null, max ? `maximum ${md(max)}` : null].filter(Boolean).join('; ');
};

if (reg) {
  const seen = new Set();
  for (const [i, k] of kinds.entries()) {
    const at = `${SOURCE}: kinds[${i}]${k?.name ? ` (${k.name})` : ''}`;
    if (typeof k?.name !== 'string') { error(`${at}: needs a name`); continue; }
    if (seen.has(k.name)) error(`${at}: the kind is listed twice`);
    seen.add(k.name);
    for (const f of ['serves', 'scope', 'class', 'treatment', 'profile', 'writer', 'readers']) if (!(f in k)) error(`${at}: missing ${f}`);
    if (!CLASSES.includes(k.class)) error(`${at}: class must be one of ${CLASSES.join(', ')}`);
    if (!Array.isArray(k.readers)) error(`${at}: readers must be a list`);
  }
}

function kindSection(k) {
  const out = [heading(3, code(k.name)), ''];
  if (k.notes) out.push(md(k.notes), '');
  const moduleName = k.layer_module ?? 'core';
  out.push(`- **Class:** ${k.class}; scope ${k.scope}; ${k.treatment}; profile ${profile(k)}; module ${moduleName}; serves the ${k.serves} family.${k.personal ? ' Holds personal data.' : ''}${k.status ? ` Status: ${k.status}.` : ''}`);
  out.push(`- **Writer:** ${k.self_scoped ? 'every actor, under ids that start with its own name (self-scoped)' : who(k.writer)}.`);
  out.push(`- **Readers:** ${list(k.readers.map(who))}${k.backed_up === 'yes' ? '; plus the backup job of [`exporter@`](/reference/actors/#exporter), which reads the kind as ciphertext' : ''}.`);
  out.push(`- **Exportable:** ${yn(k.exportable)}; **backed up:** ${yn(k.backed_up)}.`);
  const ttl = ttlText(k);
  if (ttl) out.push(`- **Lifetime:** ${ttl}.`);
  if (k.layer) out.push(`- **Layer:** ${k.layer.layer} of the group [${k.layer.group}](#group-${k.layer.group.toLowerCase()}).`);
  if (k.links?.length) out.push(`- **Links:** ${list(k.links.map(kindLink))}.`);
  if (k.indexes?.length) out.push(`- **Indexes:** ${list(k.indexes.map(code))}, besides listing by tenant.`);
  if (k.purposes) out.push(`- **Data key purposes:** ${Object.entries(k.purposes).map(([s, p]) => `${s.replace('_', ' ')} ${list(p.map(code))}`).join('; ')}. See [the key registry](/reference/keys/#data-keys).`);
  out.push('');
  return out;
}

function render() {
  const out = [];
  const by = (f) => kinds.reduce((m, k) => m.set(f(k), (m.get(f(k)) ?? 0) + 1), new Map());
  const cls = by((k) => k.class);
  const mods = by((k) => k.layer_module ?? 'core');
  out.push(`${kinds.length} kinds (registry checked ${reg.checked}): ${CLASSES.map((c) => `${cls.get(c) ?? 0} ${c}`).join(', ')}. By module: ${[...mods].map(([m, n]) => `${n} ${m}`).join(', ')}. ${kinds.filter((k) => k.backed_up === 'yes').length} are backed up and ${kinds.filter((k) => k.exportable === 'yes').length} are exportable.`, '');
  out.push(heading(2, 'Kinds by class'), '');
  out.push(...table(['Class', 'What it is', 'Kinds'], CLASSES.map((c) => [code(c), CLASS_TEXT[c], `${cls.get(c) ?? 0}`])), '');
  out.push(`The classes, scopes, treatments and profiles are explained in ${adr('0004', 'storage-classes', 'ADR 0004')}; one writer per kind in ${adr('0004', 'one-writer-per-kind', 'one writer per kind')}.`, '');
  for (const c of CLASSES) {
    const inClass = kinds.filter((k) => k.class === c);
    if (!inClass.length) { error(`${SOURCE}: no kind of class ${c}`); continue; }
    out.push(heading(2, `${c[0].toUpperCase()}${c.slice(1)} kinds`), '', CLASS_TEXT[c], '');
    out.push(...table(['Kind', 'Scope', 'Treatment', 'Profile', 'Writer'], inClass.map((k) => {
      return [`[${code(k.name)}](#${k.name.toLowerCase()})`, k.scope, k.treatment, profile(k), k.self_scoped ? 'self' : who(k.writer)];
    })), '');
    for (const k of inClass) out.push(...kindSection(k));
  }

  out.push(heading(2, 'Layered groups'), '',
    `A layered group is a set of kinds that combine into one effective value, each layer by a rule: [layers and the direction rule](${adrHref('0004', 'layers-and-the-direction-rule')}), [layered and linked kinds](${adrHref('0004', 'layered-and-linked-kinds')}).`, '');
  out.push(...table(['Group', 'Profile', 'Combine', 'Layers', 'Notes'], Object.entries(reg.layered_groups ?? {}).map(([name, grp]) => {
    claim(`group-${name.toLowerCase()}`, `the group ${name}`);
    const layers = Object.entries(grp.layers ?? {}).map(([l, v]) => `**${l}:** ${Array.isArray(v) ? list(v.map(kindLink)) : md(v)}`);
    return [`${anchor(`group-${name.toLowerCase()}`)}${code(name)}`, grp.profile, code(grp.combine), layers.join('<br>'), md([grp.effective_read ? `Effective read: ${grp.effective_read}.` : '', grp.notes ?? ''].filter(Boolean).join(' '))];
  })), '');
  out.push(heading(2, 'Combine rules'), '');
  out.push(...table(['Rule', 'Meaning'], Object.entries(reg.combine_rules ?? {}).map(([n, t]) => [code(n), md(t)])), '');
  out.push(heading(2, 'Built-in values'), '', `Not kinds: part of the release, never read from the store ([built-in](${adrHref('0004', 'built-in')})).`, '');
  out.push(...(reg.built_in ?? []).map((t) => `- ${md(t)}`), '');
  out.push(heading(2, 'Writers outside sluis'), '', 'Config and secret kinds have a writer that is not an actor.', '');
  out.push(...table(['Writer', 'What it is'], Object.entries(reg.writers_outside_sluis ?? {}).map(([n, t]) => [code(n), md(t)])), '');
  out.push(heading(2, 'What is not data'), '', `Things sluis keeps or touches that are not kinds, and where they live ([what is not data](${adrHref('0004', 'what-is-not-data')})).`, '');
  out.push(...table(['Thing', 'Where it lives'], Object.entries(reg.not_kinds ?? {}).map(([n, t]) => [code(n), md(t)])));
  return out;
}

g.sync(render, kinds.length, 'kinds');
