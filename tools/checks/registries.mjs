#!/usr/bin/env node
// The kind registry, the key registry and the actor registry against each other:
//
//   docs/architecture/kinds.yaml   every kind of data: scope, class, treatment, profile, layer, writer, readers, lifetime
//   docs/architecture/keys.yaml    every key purpose: algorithm, AWS key spec, card slot, using actors
//   docs/architecture/actors.yaml  read here for the names of the actors and their key purposes
//                                  (its own shape is tools/checks/actors.mjs's)
//
//   - kinds: closed fields; a class, a scope, a treatment and a profile of the known values; ONE
//     writer per kind, except the declared self-scoped kinds (`writer: self` with `self_scoped: true`);
//     the writer and every reader an actor of actors.yaml (`store@`, `key@` and `exporter@` name the
//     actors store, key and exporter), a macro, or for a config or secret kind IaC or the pipeline; a
//     temp kind has a time to live with a default and a maximum (a default never above its maximum, a
//     maximum never 0s, and for the kinds whose maxima are decided never above that maximum); a config or secret kind has no tenant
//     scope, is plain, and has no expiry; a kind flagged `personal: true` is never plain; only the console's two kinds are written by the console; a
//     kind the exporter watches is readable by it; every `backed_up: yes` kind is read by exporter@'s
//     backup job as ciphertext (a read rule implied by the field, not listed in `readers`), so exporter@
//     must be a data-family actor with the data port; layered groups and the kinds in their layers agree;
//     linked kinds exist; DataKeyWrap lists the data key purposes of keys.yaml;
//   - keys: closed fields; every algorithm declared; the AWS baseline of one symmetric key and five P-384
//     keys; a signing or key-agreement key has exactly one using actor; the card slot plan has no
//     collision and covers every purpose that has a slot; the data key purposes are four per tenant
//     (data, pseudonym, pairwise, evidence) and four per boundary (grant, cookie, mac, data); a sealed kind
//     with no tenant is sealed under the boundary's `data` key, so its writer and readers use it;
//   - across the three: every user of a key purpose is an actor and lists that purpose in its
//     `key_purposes` with ops the purpose allows, and the reverse; every actor that writes a sealed
//     kind can seal with the `data` key and every actor that reads one can open with it.
//
// Needs the `yaml` package of site/ (`just site-install`).
//
// usage: tools/checks/registries.mjs [repo-root]
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { reporter, repoRoot } from './lib.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const { parse } = createRequire(join(here, '..', '..', 'site', 'package.json'))('yaml');

const root = repoRoot();
const { error, finish } = reporter('check-registries');

const KINDS = 'docs/architecture/kinds.yaml';
const KEYS = 'docs/architecture/keys.yaml';
const ACTORS = 'docs/architecture/actors.yaml';

const FAMILIES = ['work', 'data', 'keys', 'audit'];
const CLASSES = ['config', 'secret', 'durable', 'temp'];
const SCOPES = ['boundary', 'boundary+tenant'];
const TREATMENTS = ['hashed', 'sealed', 'plain'];
const PROFILES = ['Fixed', 'Operable', 'Tenant-adjustable', '-'];
const MODULES = ['core', 'CIAM module', 'quota module'];
const KIND_FIELDS = ['name', 'serves', 'scope', 'class', 'treatment', 'profile', 'layer', 'links', 'writer', 'readers', 'exportable', 'backed_up',
  'ttl', 'indexes', 'purposes', 'self_scoped', 'status', 'layer_module', 'watched_by', 'personal', 'notes'];
const KIND_REQUIRED = ['name', 'serves', 'scope', 'class', 'treatment', 'profile', 'writer', 'readers', 'exportable', 'backed_up'];
const KIND_TOP = ['schema', 'checked', 'writers_outside_sluis', 'combine_rules', 'layered_groups', 'built_in', 'not_kinds', 'kinds'];
const OUTSIDE = ['IaC', 'pipeline'];
// The contracts an adapter implements, as a reader's qualifier `(as <contract>)` names them. The qualifier limits
// the macro `adapter-<vendor>` to the adapters whose `contracts` list the contract (tools/checks/rules-page.mjs);
// any other trailing parenthesis is a label and is not read.
const AS_CONTRACT = { 'credential minter': 'CredentialMinter', provisioner: 'Provisioner', 'facts source': 'FactsSource', upstream: 'Upstream', notifier: 'Notifier' };
// The macros of a writer or a reader.
const MACROS = ['every actor', 'every work actor', 'self', 'the actor named in the id', 'adapter-<vendor>'];
const CONSOLE_KINDS = ['Switch', 'LogLevelOverride'];
// The backup job: exporter@ reads every `backed_up: yes` kind as ciphertext, whatever `readers` lists.
const BACKUP_READER = 'exporter';
// The decided maxima of temp kinds, in seconds. The tunables may shorten a lifetime, never lengthen it past these.
const SECONDS = { s: 1, m: 60, h: 3600, d: 86400 };
const TTL_CEILING = {
  AuthCode: '10m', DeviceCode: '15m', WebAuthnChallenge: '10m', Lease: '10m', SpentGrant: '5m',
  LogLevelOverride: '24h', PredefinedPolicyLinkTemporary: '24h', PendingEnrolment: '30d',
  UpstreamMetadata: '24h', VerifierKeyCache: '24h', DirectoryUser: '7d', DirectoryGroup: '7d',
  DirectoryMembership: '7d', GitHubManifestState: '1h', PinReleaseRequest: '15m', PinRelease: '15m',
};
// A duration written as a number and a unit (`90s`, `10m`, `24h`, `7d`), also at the start of a longer text
// (`90d (agent chain, built-in maximum)`); null for prose such as `the window`.
const seconds = (v) => {
  const m = /^(\d+)(?:\s*([smhd])(?![a-z]))?/i.exec(String(v ?? '').trim());
  if (!m) return null;
  if (!m[2]) return Number(m[1]) === 0 ? 0 : null; // a bare number is read only when it is 0
  return Number(m[1]) * SECONDS[m[2].toLowerCase()];
};

const OPS = ['seal', 'open', 'sign', 'mac', 'public-key', 'wrap', 'unwrap'];
const PURPOSE_KINDS = ['signing', 'key-agreement', 'wrapping'];
const ENABLED = ['baseline', 'on-use', 'named-exception'];
const KEY_TOP = ['schema', 'checked', 'algorithms', 'purposes', 'slot_plan', 'data_keys', 'wrapping'];
const PURPOSE_FIELDS = ['name', 'kind', 'algorithm', 'enabled', 'ops', 'aws', 'board', 'users', 'notes'];
const ALGO_FIELDS = ['family', 'curve', 'status', 'note'];
const PIV_SLOTS = new Set(['9a', '9c', '9d', '9e', ...Array.from({ length: 20 }, (_, i) => (0x82 + i).toString(16))]);
const TENANT_PURPOSES = ['data', 'pseudonym', 'pairwise', 'evidence'];
const BOUNDARY_PURPOSES = ['grant', 'cookie', 'mac', 'data'];
const ERASED = { tenant: ['tenant exit', 'end of the evidence retention'], boundary: ['never'] };

const load = (rel) => {
  if (!existsSync(join(root, rel))) { error(`${rel} is missing`); return null; }
  try { return parse(readFileSync(join(root, rel), 'utf8')); } catch (e) { error(`${rel}: not valid YAML: ${e.message}`); return null; }
};
const isStrList = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string');
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);

const kindsDoc = load(KINDS);
const keysDoc = load(KEYS);
const actorsDoc = load(ACTORS);
if (!kindsDoc || !keysDoc || !actorsDoc) finish(0, 'registries');

// ---- the actors, as far as this check needs them
const actors = new Map();
for (const a of [...(actorsDoc.actors ?? []), ...(actorsDoc.platform ?? [])]) {
  if (typeof a?.name === 'string') actors.set(a.name, { ...a, family: a.family ?? 'platform' });
}
const adapters = [...actors.values()].filter((a) => a.name.startsWith('adapter-'));
// Callers of key that are not actors (a product's emitter): known by name, with their own key_purposes.
const externals = new Map((actorsDoc.external_callers ?? []).filter((c) => typeof c?.name === 'string').map((c) => [c.name, { ...c, family: 'external' }]));

// A reference in a writer, a reader or a user list: what it names. `@` ends the name of a holder.
function ref(raw) {
  const s = String(raw).replace(/\s*\([^)]*\)\s*$/, '').trim();
  if (OUTSIDE.includes(s)) return { outside: s };
  if (s === 'none yet') return { none: true };
  if (MACROS.includes(s)) return { macro: s };
  const name = s.replace(/@$/, '');
  return { name, actor: actors.get(name) ?? externals.get(name) };
}

// ---- keys.yaml
const keys = keysDoc;
const purposes = new Map();
const dataKeys = new Map(); // purpose -> { scope, ... }
const algorithms = isObj(keys.algorithms) ? keys.algorithms : {};
if (keys.schema !== 1) error(`${KEYS}: schema must be 1`);
for (const k of Object.keys(keys)) if (!KEY_TOP.includes(k)) error(`${KEYS}: unknown top-level key ${k}`);
for (const k of KEY_TOP) if (!(k in keys)) error(`${KEYS}: missing top-level key ${k}`);
for (const [n, a] of Object.entries(algorithms)) {
  if (!isObj(a)) { error(`${KEYS}: algorithms.${n}: not an object`); continue; }
  for (const f of Object.keys(a)) if (!ALGO_FIELDS.includes(f)) error(`${KEYS}: algorithms.${n}: unknown field ${f}`);
  if (!['default', 'exception'].includes(a.status)) error(`${KEYS}: algorithms.${n}: status must be default or exception`);
  if (typeof a.family !== 'string' || typeof a.note !== 'string') error(`${KEYS}: algorithms.${n}: needs a family and a note`);
}
const usedSlots = new Map();
for (const [i, p] of (Array.isArray(keys.purposes) ? keys.purposes : []).entries()) {
  const at = `${KEYS}: purposes[${i}]${p?.name ? ` (${p.name})` : ''}`;
  if (!isObj(p) || typeof p.name !== 'string' || !/^[a-z][a-z0-9-]*$/.test(p.name)) { error(`${at}: name must be lower-case kebab-case`); continue; }
  if (purposes.has(p.name)) error(`${at}: the purpose is listed twice`);
  purposes.set(p.name, p);
  for (const f of Object.keys(p)) if (!PURPOSE_FIELDS.includes(f)) error(`${at}: unknown field ${f}`);
  for (const f of ['kind', 'algorithm', 'enabled', 'ops', 'aws', 'board', 'users', 'notes']) if (!(f in p)) error(`${at}: missing ${f}`);
  if (!PURPOSE_KINDS.includes(p.kind)) error(`${at}: kind must be one of ${PURPOSE_KINDS.join(', ')}`);
  if (!(p.algorithm in algorithms)) error(`${at}: algorithm ${p.algorithm} is not declared under algorithms`);
  if (!ENABLED.includes(p.enabled)) error(`${at}: enabled must be one of ${ENABLED.join(', ')}`);
  if (!isStrList(p.ops) || !p.ops.length || p.ops.some((o) => !OPS.includes(o))) error(`${at}: ops must list ${OPS.join(', ')}`);
  if (p.kind === 'signing' && !(p.ops ?? []).includes('sign')) error(`${at}: a signing key has the op sign`);
  if (!isObj(p.aws) || typeof p.aws.key_spec !== 'string' || !['boundary', 'trust domain', 'writer instance'].includes(p.aws.per) || typeof p.aws.baseline !== 'boolean') error(`${at}: aws needs key_spec, per (boundary | trust domain | writer instance) and baseline (true or false)`);
  else if (p.aws.baseline !== (p.enabled === 'baseline')) error(`${at}: aws.baseline must be ${p.enabled === 'baseline'} for an ${p.enabled} purpose`);
  if (!isObj(p.board) || typeof p.board.slot !== 'string') { error(`${at}: board.slot must be a string (a slot, spare or none)`); }
  else {
    if ('algorithm' in p.board && !(p.board.algorithm in algorithms)) error(`${at}: board.algorithm ${p.board.algorithm} is not declared under algorithms`);
    for (const f of Object.keys(p.board)) if (!['slot', 'algorithm', 'runtimes'].includes(f)) error(`${at}: unknown board field ${f}`);
    if (!['spare', 'none'].includes(p.board.slot)) {
      if (!PIV_SLOTS.has(p.board.slot)) error(`${at}: board.slot ${p.board.slot} is not a PIV slot (9a, 9c, 9d, 9e or 82 to 95)`);
      else if (usedSlots.has(p.board.slot)) error(`${at}: slot ${p.board.slot} is also the slot of ${usedSlots.get(p.board.slot)}`);
      else usedSlots.set(p.board.slot, p.name);
    }
  }
  if (!isStrList(p.users) || !p.users.length) error(`${at}: users must be a list of actors`);
  else {
    if (p.kind !== 'wrapping' && p.users.length !== 1) error(`${at}: a ${p.kind} key has exactly one using actor (its key policy names one), not ${p.users.length}`);
    for (const u of p.users) {
      const r = ref(u);
      if (r.name !== undefined && !r.actor) error(`${at}: user ${u} is not an actor of ${ACTORS}`);
      else if (r.outside || r.none || (r.macro && !['every work actor', 'adapter-<vendor>'].includes(r.macro))) error(`${at}: user ${u} is not an actor or the macro every work actor or adapter-<vendor>`);
    }
  }
}
// AWS baseline: one symmetric key and five P-384 keys.
{
  const base = [...purposes.values()].filter((p) => p.enabled === 'baseline');
  const sym = base.filter((p) => p.aws?.key_spec === 'SYMMETRIC_DEFAULT').length;
  const p384 = base.filter((p) => p.aws?.key_spec === 'ECC_NIST_P384').length;
  if (sym !== 1 || p384 !== 5 || base.length !== 6) error(`${KEYS}: the AWS baseline is 1 symmetric key and 5 P-384 keys, found ${sym} symmetric and ${p384} P-384 among ${base.length} baseline purposes`);
}
// The slot plan.
const plan = keys.slot_plan;
if (!isObj(plan)) error(`${KEYS}: slot_plan is missing`);
else {
  if (plan.version !== 1) error(`${KEYS}: slot_plan.version must be 1`);
  const slots = isObj(plan.slots) ? plan.slots : {};
  for (const [slot, name] of Object.entries(slots)) {
    if (!PIV_SLOTS.has(slot)) error(`${KEYS}: slot_plan.slots: ${slot} is not a PIV slot`);
    if (!purposes.has(name)) error(`${KEYS}: slot_plan.slots.${slot}: ${name} is not a purpose`);
    else if (purposes.get(name).board?.slot !== slot) error(`${KEYS}: slot_plan.slots.${slot} is ${name}, but the purpose says slot ${purposes.get(name).board?.slot}`);
  }
  for (const [slot, name] of usedSlots) if (slots[slot] !== name) error(`${KEYS}: purpose ${name} has slot ${slot}, which slot_plan.slots does not give to it`);
  const sp = plan.spare ?? {};
  const from = Number.parseInt(String(sp.from), 16);
  const to = Number.parseInt(String(sp.to), 16);
  if (!(from >= 0x82 && to <= 0x95 && to >= from) || sp.count !== to - from + 1) error(`${KEYS}: slot_plan.spare must be a range of retired slots (82 to 95) with count = to - from + 1`);
  else {
    for (const slot of [...Object.keys(slots), ...Object.keys(plan.unused ?? {})]) {
      const n = Number.parseInt(slot, 16);
      if (n >= from && n <= to) error(`${KEYS}: slot ${slot} lies in the spare range`);
    }
    const wantSpare = [...purposes.values()].filter((p) => p.board?.slot === 'spare').length;
    if (wantSpare > sp.count) error(`${KEYS}: ${wantSpare} purposes need a spare slot and the range holds ${sp.count}`);
  }
  for (const slot of Object.keys(plan.unused ?? {})) {
    if (!PIV_SLOTS.has(slot)) error(`${KEYS}: slot_plan.unused: ${slot} is not a PIV slot`);
    if (slots[slot]) error(`${KEYS}: slot ${slot} is both in use and unused`);
  }
}
// The data keys.
for (const scope of ['tenant', 'boundary']) {
  const group = keys.data_keys?.[scope];
  const want = scope === 'tenant' ? TENANT_PURPOSES : BOUNDARY_PURPOSES;
  if (!isObj(group)) { error(`${KEYS}: data_keys.${scope} is missing`); continue; }
  if (Object.keys(group).sort().join() !== [...want].sort().join()) error(`${KEYS}: data_keys.${scope} must be exactly ${want.join(', ')}`);
  for (const [n, d] of Object.entries(group)) {
    const at = `${KEYS}: data_keys.${scope}.${n}`;
    // `data` is the one name in both scopes: the tenant's key and the key of a sealed kind with no tenant. They
    // are two keys with two addresses (tenant or `-`) and one purpose name, so the uses below are merged.
    const earlier = dataKeys.get(n);
    if (purposes.has(n) || (earlier && !(earlier.scope === 'tenant' && scope === 'boundary' && n === 'data'))) error(`${at}: the name is also another key purpose`);
    if (earlier) dataKeys.set(n, { ...earlier, ops: [...new Set([...(earlier.ops ?? []), ...(d?.ops ?? [])])], users: [...new Set([...(earlier.users ?? []), ...(d?.users ?? [])])] });
    else dataKeys.set(n, { ...d, scope });
    if (!isStrList(d?.ops) || !d.ops.length || d.ops.some((o) => !['seal', 'open', 'mac'].includes(o))) error(`${at}: ops must list seal, open or mac`);
    if (!ERASED[scope].includes(d?.erased)) error(`${at}: erased must be one of ${ERASED[scope].join(', ')}`);
    if (!isStrList(d?.users) || !d.users.length) error(`${at}: users must be a list of actors`);
    else for (const u of d.users) {
      const r = ref(u);
      if (r.name !== undefined && !r.actor) error(`${at}: user ${u} is not an actor of ${ACTORS}`);
      else if (r.outside || r.none || (r.macro && !['every work actor', 'adapter-<vendor>'].includes(r.macro))) error(`${at}: user ${u} is not an actor or the macro every work actor or adapter-<vendor>`);
    }
    if (typeof d?.notes !== 'string') error(`${at}: notes is missing`);
  }
}

// ---- the uses, both ways
const all = new Map([...purposes, ...dataKeys]);
const usersOf = (p) => (p.users ?? []).flatMap((u) => {
  const r = ref(u);
  if (r.macro === 'every work actor') return [...actors.values()].filter((a) => a.family === 'work').map((a) => a.name);
  if (r.macro === 'adapter-<vendor>') return [];
  return r.name ? [r.name] : [];
});
for (const [name, a] of [...actors, ...externals]) {
  const seen = new Set();
  for (const [j, kp] of (Array.isArray(a.key_purposes) ? a.key_purposes : []).entries()) {
    const at = `${ACTORS}: ${name}: key_purposes[${j}]`;
    if (seen.has(kp?.purpose)) error(`${at}: ${kp.purpose} is listed twice`);
    seen.add(kp?.purpose);
    const p = all.get(kp?.purpose);
    if (!p) { error(`${at}: the key purpose ${kp?.purpose} is not in ${KEYS}`); continue; }
    for (const o of kp.ops ?? []) if (!(p.ops ?? []).includes(o)) error(`${at}: ${kp.purpose} does not allow the op ${o} (it allows ${p.ops.join(', ')})`);
    const users = (p.users ?? []).map(ref);
    const named = usersOf(p).includes(name) || (users.some((r) => r.macro === 'adapter-<vendor>') && name.startsWith('adapter-'));
    if (!named) error(`${at}: ${KEYS} does not list ${name} as a user of ${kp.purpose}`);
  }
}
for (const [purpose, p] of all) {
  for (const u of usersOf(p)) {
    const a = actors.get(u) ?? externals.get(u);
    if (a && !(a.key_purposes ?? []).some((kp) => kp.purpose === purpose)) error(`${KEYS}: ${purpose}: ${u} is a user, but its key_purposes in ${ACTORS} does not list ${purpose}`);
  }
}

// ---- kinds.yaml
const kd = kindsDoc;
if (kd.schema !== 1) error(`${KINDS}: schema must be 1`);
for (const k of Object.keys(kd)) if (!KIND_TOP.includes(k)) error(`${KINDS}: unknown top-level key ${k}`);
for (const k of KIND_TOP) if (!(k in kd)) error(`${KINDS}: missing top-level key ${k}`);
const kinds = new Map();
const list = Array.isArray(kd.kinds) ? kd.kinds : [];
for (const [i, k] of list.entries()) {
  const at = `${KINDS}: ${k?.name ?? `kinds[${i}]`}`;
  if (!isObj(k) || typeof k.name !== 'string' || !/^[A-Z][A-Za-z0-9]*$/.test(k.name)) { error(`${at}: name must be PascalCase`); continue; }
  if (kinds.has(k.name)) error(`${at}: the kind is listed twice`);
  kinds.set(k.name, k);
  for (const f of Object.keys(k)) if (!KIND_FIELDS.includes(f)) error(`${at}: unknown field ${f}`);
  for (const f of KIND_REQUIRED) if (!(f in k)) error(`${at}: missing ${f}`);
  if (!FAMILIES.includes(k.serves)) error(`${at}: serves must be one of ${FAMILIES.join(', ')}`);
  if (!SCOPES.includes(k.scope)) error(`${at}: scope must be one of ${SCOPES.join(', ')}`);
  if (!CLASSES.includes(k.class)) error(`${at}: class must be one of ${CLASSES.join(', ')}`);
  if (!TREATMENTS.includes(k.treatment)) error(`${at}: treatment must be one of ${TREATMENTS.join(', ')}`);
  if (!PROFILES.includes(k.profile)) error(`${at}: profile must be one of ${PROFILES.join(', ')}`);
  if (!['yes', 'no'].includes(k.exportable) || !['yes', 'no'].includes(k.backed_up)) error(`${at}: exportable and backed_up must be yes or no`);
  if ('layer_module' in k && !MODULES.includes(k.layer_module)) error(`${at}: layer_module must be one of ${MODULES.join(', ')}`);
  if ('links' in k && !isStrList(k.links)) error(`${at}: links must be a list of kinds`);
  if ('indexes' in k && !isStrList(k.indexes)) error(`${at}: indexes must be a list of strings`);
  if ('notes' in k && typeof k.notes !== 'string') error(`${at}: notes must be a string`);
  // `personal: true` is the reviewed flag of a kind that holds personal data (ADR 0004, "Treatment"): such a kind is
  // sealed, or hashed when it is compare-only, and never plain. A config or secret kind is plain and carries no flag.
  if ('personal' in k && typeof k.personal !== 'boolean') error(`${at}: personal must be true or false`);
  if (k.personal === true && k.treatment === 'plain') error(`${at}: a personal kind is never plain (treatment follows the data: sealed, or hashed when it is compare-only)`);
  const external = k.class === 'config' || k.class === 'secret';
  if (external) {
    if (k.scope !== 'boundary') error(`${at}: a ${k.class} kind has no tenant scope`);
    if (k.treatment !== 'plain') error(`${at}: a ${k.class} kind is plain (it is signed or held by the secret source)`);
    if ('ttl' in k) error(`${at}: a ${k.class} kind has no time to live`);
    if (k.backed_up !== 'no') error(`${at}: a ${k.class} kind is not backed up (IaC and the pipeline keep it)`);
  }
  if (k.backed_up === 'yes' && k.class !== 'durable') error(`${at}: only a durable kind is backed up`);
  if (k.class === 'temp') {
    if (!isObj(k.ttl) || !('default' in k.ttl) || !('max' in k.ttl)) error(`${at}: a temp kind has a time to live with a default and a max`);
    else {
      for (const f of Object.keys(k.ttl)) if (!['default', 'max'].includes(f)) error(`${at}: ttl.${f}: a temp kind's ttl has a default and a max only`);
      const def = seconds(k.ttl.default);
      const max = seconds(k.ttl.max);
      if (max === 0) error(`${at}: ttl.max is ${k.ttl.max}: a temp kind that may not live cannot be written`);
      if (def !== null && max !== null && def > max) error(`${at}: ttl.default ${k.ttl.default} is above ttl.max ${k.ttl.max}`);
      if (k.name in TTL_CEILING) {
        if (max === null) error(`${at}: ttl.max must be a duration, at most the decided maximum ${TTL_CEILING[k.name]}`);
        else if (max > seconds(TTL_CEILING[k.name])) error(`${at}: ttl.max ${k.ttl.max} is above the decided maximum ${TTL_CEILING[k.name]}`);
      }
    }
  }
  if (k.class === 'durable' && 'ttl' in k && (!isObj(k.ttl) || typeof k.ttl.field !== 'string')) error(`${at}: a durable kind's ttl names the expiry field`);
  // the writer: one
  const w = k.writer;
  if (typeof w !== 'string') error(`${at}: writer must be one actor (a kind has one writer)`);
  else {
    const r = ref(w);
    if (k.class === 'secret' && r.outside !== 'IaC') error(`${at}: a secret kind is written by IaC`);
    else if (k.class === 'config' && !r.outside) error(`${at}: a config kind is written by IaC or the pipeline`);
    else if (!external) {
      if (r.outside) error(`${at}: ${w} writes config and secret kinds only; sluis writes durable and temp kinds`);
      else if (r.none) { if (k.status !== 'planned') error(`${at}: a kind without a writer has status planned`); }
      else if (r.macro === 'self') { if (k.self_scoped !== true) error(`${at}: writer self needs self_scoped: true`); }
      else if (r.macro && r.macro !== 'adapter-<vendor>') error(`${at}: ${w} is not a writer`);
      else if (r.name !== undefined && !r.actor) error(`${at}: writer ${w} is not an actor of ${ACTORS}`);
      else if (r.actor && r.actor.family !== 'platform' && r.actor.family !== k.serves) error(`${at}: serves ${k.serves}, but its writer ${w} is in the family ${r.actor.family}`);
      if (r.macro === 'adapter-<vendor>' && k.serves !== 'work') error(`${at}: an adapter is a work actor, so serves must be work`);
    }
    if (k.status === 'planned' && !r.none) error(`${at}: status planned is for a kind without a writer`);
  }
  if (k.self_scoped === true && w !== 'self') error(`${at}: self_scoped is for writer self`);
  if (k.self_scoped !== undefined && k.self_scoped !== true) error(`${at}: self_scoped is true or absent`);
  if (!Array.isArray(k.readers) || !k.readers.length) error(`${at}: readers must be a non-empty list`);
  else for (const rd of k.readers) {
    const r = ref(rd);
    if (r.outside || r.none) error(`${at}: reader ${rd} is not an actor`);
    else if (r.name !== undefined && !r.actor) error(`${at}: reader ${rd} is not an actor of ${ACTORS}`);
    const q = /\(as ([^)]*)\)\s*$/.exec(String(rd));
    if (q && !(q[1] in AS_CONTRACT)) error(`${at}: reader ${rd}: (as ${q[1]}) names no contract; use one of ${Object.keys(AS_CONTRACT).map((c) => `(as ${c})`).join(', ')}`);
    else if (q && ref(rd).macro !== 'adapter-<vendor>') error(`${at}: reader ${rd}: (as ${q[1]}) limits the macro adapter-<vendor> only`);
  }
  // `watched_by` names the readers of a durable or temp kind that watch it; exporter@ watches an exportable kind
  // without being listed, and the readers of a config kind get its changes with the snapshot.
  if (k.watched_by !== undefined) {
    if (!isStrList(k.watched_by) || !k.watched_by.length) error(`${at}: watched_by must be a non-empty list of readers`);
    else if (k.class !== 'durable' && k.class !== 'temp') error(`${at}: watched_by is for a durable or temp kind; the readers of a config kind get its changes with the snapshot`);
    else for (const wb of k.watched_by) if (!(k.readers ?? []).includes(wb)) error(`${at}: watched_by ${wb} is not one of the readers`);
  }
  if (k.exportable === 'yes' && Array.isArray(k.readers) && !k.readers.some((rd) => ref(rd).name === 'exporter')) error(`${at}: an exportable kind is read by exporter@`);
  if (k.writer === 'console' && !CONSOLE_KINDS.includes(k.name)) error(`${at}: the console writes only ${CONSOLE_KINDS.join(' and ')}; route the write to the owning actor`);
}
// The read rules that the field `backed_up` implies: exporter@'s backup job reads every backed-up kind as
// ciphertext (it does not open a sealed value), whether or not `readers` lists exporter@.
const backedUp = [...kinds.values()].filter((k) => k.backed_up === 'yes');
if (backedUp.length) {
  const b = actors.get(BACKUP_READER);
  if (!b) error(`${KINDS}: ${backedUp.length} kinds are backed_up: yes, and the backup job's actor ${BACKUP_READER} is not an actor of ${ACTORS}`);
  else {
    if (b.family !== 'data') error(`${ACTORS}: ${BACKUP_READER}: the backup job's actor is in the data family (it is ${b.family})`);
    if (!(b.ports ?? []).includes('data')) error(`${ACTORS}: ${BACKUP_READER}: exporter@ reads the backed-up kinds through the data port, which its ports lack`);
  }
}
for (const n of CONSOLE_KINDS) if (kinds.has(n) && kinds.get(n).writer !== 'console') error(`${KINDS}: ${n}: the console writes it itself`);

// links, layers, groups
for (const [n, k] of kinds) {
  for (const l of k.links ?? []) if (!kinds.has(l)) error(`${KINDS}: ${n}: links ${l}, which is not a kind`);
  if (k.layer) {
    const g = kd.layered_groups?.[k.layer.group];
    if (!g) error(`${KINDS}: ${n}: layer group ${k.layer.group} is not under layered_groups`);
    else if (!(g.layers?.[k.layer.layer] ?? []).includes?.(n)) error(`${KINDS}: ${n}: layer ${k.layer.layer} of ${k.layer.group} does not list it`);
  }
}
for (const [gn, g] of Object.entries(isObj(kd.layered_groups) ? kd.layered_groups : {})) {
  if (!isObj(g) || !isObj(g.layers) || typeof g.combine !== 'string' || !(g.combine in (kd.combine_rules ?? {}))) { error(`${KINDS}: layered_groups.${gn}: needs layers and a combine rule of combine_rules`); continue; }
  if (!PROFILES.includes(g.profile)) error(`${KINDS}: layered_groups.${gn}: profile must be one of ${PROFILES.join(', ')}`);
  for (const [layer, members] of Object.entries(g.layers)) {
    if (!Array.isArray(members)) continue; // built-in is prose
    for (const m of members) {
      if (!kinds.has(m)) error(`${KINDS}: layered_groups.${gn}.${layer}: ${m} is not a kind`);
      else if (kinds.get(m).layer?.group !== gn || kinds.get(m).layer?.layer !== layer) error(`${KINDS}: ${m} is in ${gn}.${layer}, but its own layer says ${JSON.stringify(kinds.get(m).layer)}`);
    }
  }
}

// DataKeyWrap lists the data key purposes of keys.yaml
{
  const d = kinds.get('DataKeyWrap');
  if (!d) error(`${KINDS}: DataKeyWrap is missing`);
  else if (d.writer !== 'key@') error(`${KINDS}: DataKeyWrap: key@ is its one writer`);
  else {
    const same = (x, y) => Array.isArray(x) && [...x].sort().join() === Object.keys(y ?? {}).sort().join();
    if (!same(d.purposes?.per_tenant, keys.data_keys?.tenant) || !same(d.purposes?.boundary, keys.data_keys?.boundary)) error(`${KINDS}: DataKeyWrap.purposes must equal the data key purposes of ${KEYS} (${TENANT_PURPOSES.join(', ')} per tenant; ${BOUNDARY_PURPOSES.join(', ')} per boundary)`);
  }
}

// A sealed kind is sealed with the `data` key: its writer seals, its readers open.
const hasOp = (a, purpose, op) => (a.key_purposes ?? []).some((kp) => kp.purpose === purpose && (kp.ops ?? []).includes(op));
for (const [n, k] of kinds) {
  if (k.treatment !== 'sealed' || k.class === 'config' || k.class === 'secret') continue;
  const w = typeof k.writer === 'string' ? ref(k.writer) : {};
  if (w.actor && !hasOp(w.actor, 'data', 'seal')) error(`${KINDS}: ${n} is sealed, but its writer ${w.name} has no data key seal in key_purposes (${ACTORS})`);
  for (const rd of Array.isArray(k.readers) ? k.readers : []) {
    const r = ref(rd);
    if (r.actor && !hasOp(r.actor, 'data', 'open')) error(`${KINDS}: ${n} is sealed, but its reader ${r.name} has no data key open in key_purposes (${ACTORS})`);
  }
  // A sealed kind with no tenant in its address is sealed under the boundary's `data` key (tenant `-`).
  if (k.scope === 'boundary') {
    const bd = keys.data_keys?.boundary?.data;
    if (!bd) { error(`${KINDS}: ${n} is sealed and has no tenant, so ${KEYS} needs the boundary data key \`data\``); continue; }
    const allowed = new Set(usersOf(bd));
    const who = [w.name, ...(Array.isArray(k.readers) ? k.readers : []).map((rd) => ref(rd).name)].filter((x) => x !== undefined && actors.has(x));
    for (const x of new Set(who)) if (!allowed.has(x)) error(`${KINDS}: ${n} is sealed and has no tenant, so it is sealed under the boundary's data key, but ${KEYS} data_keys.boundary.data does not list ${x}`);
  }
}

finish(kinds.size, `kinds (${backedUp.length} backed up, read by ${BACKUP_READER}@'s backup job as ciphertext; with ${actors.size} actors and platform pieces, ${purposes.size} key purposes, ${dataKeys.size} data key purposes)`);
