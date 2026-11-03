#!/usr/bin/env node
// The keys page, docs/reference/keys.md, against the key registry, docs/architecture/keys.yaml, and the
// actor registry, docs/architecture/actors.yaml: the algorithms, the purposes per algorithm, the AWS
// baseline, the purposes enabled on use, the data keys per tenant and per boundary, the card slot plan,
// and which actor uses which purpose. The block between the markers is generated; the check fails while
// it is stale (`--write` rewrites it).
//
// The registries themselves are checked by tools/checks/registries.mjs; this reads them as they are.
//
// usage: tools/checks/keys-page.mjs [--write] [repo-root]
import { anchor, code, generator, list, md, table } from './pages-lib.mjs';

const KEYS = 'docs/architecture/keys.yaml';
const ACTORS = 'docs/architecture/actors.yaml';
const PAGE = 'docs/reference/keys.md';
const g = generator('check-keys-page', 'keys-page.mjs', { source: `${KEYS} and ${ACTORS}`, page: PAGE, recipe: 'keys-write' });
const { error, load, adrHref, claim, heading } = g;

const reg = load(KEYS);
const areg = load(ACTORS);
const purposes = Array.isArray(reg?.purposes) ? reg.purposes : [];
const algorithms = reg?.algorithms ?? {};
const everyone = [...(areg?.actors ?? []), ...(areg?.platform ?? [])];
const names = new Set(everyone.map((a) => a.name));

const user = (u) => (names.has(u) ? `[${code(u)}](/reference/actors/#${u})` : /^adapter-</.test(u) ? code(u) : md(u));
const users = (us) => list((us ?? []).map(user));
// An algorithm has a section only when some purpose uses it.
const algo = (a) => (purposes.some((p) => p.algorithm === a) ? `[${code(a)}](#${a.toLowerCase()})` : code(a));
const ops = (o) => list((o ?? []).map(code));
const awsText = (p) => (p.aws ? `${code(p.aws.key_spec)}, one per ${p.aws.per}` : '—');
const boardText = (p) => {
  const b = p.board ?? {};
  const bits = [b.slot === 'none' ? 'no slot' : b.slot === 'spare' ? 'a spare slot' : `slot ${code(b.slot)}`];
  if (b.algorithm) bits.push(`algorithm ${code(b.algorithm)}`);
  if (b.runtimes) bits.push(`on ${b.runtimes.join(', ')}`);
  return bits.join('; ');
};
const purposeRow = (p) => [`${code(p.name)}`, p.kind, ops(p.ops), awsText(p), boardText(p), users(p.users), md(p.notes)];
const PURPOSE_HEAD = ['Purpose', 'Kind', 'Ops', 'AWS key', 'Board', 'Used by', 'Notes'];

if (reg) {
  for (const [i, p] of purposes.entries()) {
    const at = `${KEYS}: purposes[${i}]${p?.name ? ` (${p.name})` : ''}`;
    if (typeof p?.name !== 'string' || typeof p?.algorithm !== 'string') error(`${at}: needs a name and an algorithm`);
    else if (!(p.algorithm in algorithms)) error(`${at}: algorithm ${p.algorithm} is not declared`);
  }
}

function render() {
  const out = [];
  const baseline = purposes.filter((p) => p.enabled === 'baseline');
  const sym = baseline.filter((p) => p.aws?.key_spec === 'SYMMETRIC_DEFAULT').length;
  const p384 = baseline.filter((p) => p.aws?.key_spec === 'ECC_NIST_P384').length;
  out.push(`${purposes.length} key purposes and ${Object.keys(algorithms).length} algorithms (key registry checked ${reg.checked}). The AWS baseline is ${sym} symmetric key and ${p384} P-384 keys.`, '');

  out.push(heading(2, 'Algorithms'), '', `The FIPS-approved set is the default; an exception says why ([algorithms](${adrHref('0006', 'algorithms')}), [named exceptions](${adrHref('0006', 'named-exceptions')})).`, '');
  out.push(...table(['Algorithm', 'Family', 'Curve', 'Status', 'Purposes', 'Note'], Object.entries(algorithms).map(([n, a]) => [
    algo(n), a.family, a.curve ?? '—', a.status, list(purposes.filter((p) => p.algorithm === n).map((p) => `[${code(p.name)}](#${p.name})`), '—'), md(a.note),
  ])), '');

  out.push(heading(2, 'Purposes per algorithm'), '', `One key per purpose and algorithm, never shared across purposes ([key purposes](${adrHref('0006', 'key-purposes')})).`, '');
  for (const [n, a] of Object.entries(algorithms)) {
    const ps = purposes.filter((p) => p.algorithm === n);
    if (!ps.length) continue;
    out.push(heading(3, n), '', md(a.note), '');
    out.push(...table(PURPOSE_HEAD, ps.map((p) => {
      claim(p.name, `the purpose ${p.name}`);
      const row = purposeRow(p);
      row[0] = `${anchor(p.name)}${row[0]}`;
      return row;
    })), '');
  }

  out.push(heading(2, 'AWS baseline'), '',
    `On AWS every boundary has ${sym} symmetric key and ${p384} P-384 keys, one per boundary, per trust domain or per writer instance as the table says ([keys per boundary on AWS](${adrHref('0006', 'keys-per-boundary-on-aws')})).`, '');
  out.push(...table(['Purpose', 'Algorithm', 'AWS key spec', 'One per', 'Used by'], baseline.map((p) => [`[${code(p.name)}](#${p.name})`, algo(p.algorithm), code(p.aws.key_spec), p.aws.per, users(p.users)])), '');

  out.push(heading(2, 'Enabled on use'), '', 'No key exists until an installation enables the purpose; then it gets a dedicated key.', '');
  const onUse = purposes.filter((p) => p.enabled === 'on-use');
  out.push(...table(['Purpose', 'Algorithm', 'AWS key', 'Board', 'Used by'], onUse.map((p) => [`[${code(p.name)}](#${p.name})`, algo(p.algorithm), awsText(p), boardText(p), users(p.users)])), '');
  out.push(heading(3, 'Named exceptions'), '', 'The algorithm is an exception to the FIPS-approved default; each purpose has a dedicated key.', '');
  const named = purposes.filter((p) => p.enabled === 'named-exception');
  out.push(...table(['Purpose', 'Algorithm', 'AWS key', 'Board', 'Used by'], named.map((p) => [`[${code(p.name)}](#${p.name})`, algo(p.algorithm), awsText(p), boardText(p), users(p.users)])), '');

  out.push(heading(2, 'Data keys'), '',
    `Data keys are software AES-256 keys that key generates and wraps; they are stored only as \`DataKeyWrap\` items ([data keys](${adrHref('0006', 'data-keys')}), [DataKeyWrap](${adrHref('0006', 'datakeywrap')})). Tenant keys are erased with the tenant or at the end of the evidence retention; boundary keys are never erased.`, '');
  for (const [scope, label] of [['tenant', 'Per tenant'], ['boundary', 'Per boundary']]) {
    const dk = reg.data_keys?.[scope] ?? {};
    out.push(heading(3, label), '');
    out.push(...table(['Data key', 'Ops', 'Used by', 'Erased', 'Notes'], Object.entries(dk).map(([n, d]) => {
      const id = `${scope}-data-key-${n}`;
      claim(id, `the ${scope} data key ${n}`);
      return [`${anchor(id)}${code(n)}`, ops(d.ops), users(d.users), md(d.erased), md(d.notes)];
    })), '');
  }
  out.push(heading(3, 'How a data key is wrapped'), '');
  out.push(...Object.entries(reg.wrapping ?? {}).map(([n, t]) => `- **${{ aws: 'AWS', board: 'Board', backup_archive: 'Backup archive' }[n] ?? n.replace(/_/g, ' ')}:** ${md(t)}`), '');

  out.push(heading(2, 'Board slot plan'), '',
    `The default card slot map, version ${reg.slot_plan?.version} ([keys per board](${adrHref('0006', 'keys-per-board')}), [the slot plan](${adrHref('0006', 'the-slot-plan')})). A purpose that an installation does not enable gets no slot and no key.`, '');
  const slots = Object.entries(reg.slot_plan?.slots ?? {});
  out.push(...table(['Slot', 'Purpose', 'Algorithm on the card', 'Runs on'], slots.map(([s, n]) => {
    const p = purposes.find((x) => x.name === n);
    if (!p) { error(`${KEYS}: slot ${s} names ${n}, which is not a purpose`); return [code(s), n, '—', '—']; }
    return [code(s), `[${code(n)}](#${n})`, algo(p.board?.algorithm ?? p.algorithm), p.board?.runtimes ? p.board.runtimes.join(', ') : 'every board'];
  })), '');
  const sp = reg.slot_plan?.spare;
  if (sp) out.push(`**Spare slots:** ${code(sp.from)} to ${code(sp.to)} (${sp.count}). ${md(sp.note)}`, '');
  for (const [s, t] of Object.entries(reg.slot_plan?.unused ?? {})) out.push(`**Unused:** slot ${code(s)}. ${md(t)}`, '');
  const spareUsers = purposes.filter((p) => p.board?.slot === 'spare').map((p) => p.name);
  if (spareUsers.length) out.push(`Purposes that take a spare slot when enabled: ${list(spareUsers.map((n) => `[${code(n)}](#${n})`))}.`, '');

  out.push(heading(2, 'Which actor uses which key'), '', 'From the actor registry; the key registry names the same pairs from the other side, and `just check-registries` makes them agree.', '');
  out.push(...table(['Actor', 'Key purposes (ops)'], everyone.filter((a) => a.key_purposes?.length).map((a) => [
    `[${code(a.name)}](/reference/actors/#${a.name})`, list(a.key_purposes.map((k) => `${code(k.purpose)} (${k.ops.join(', ')})`)),
  ])));
  return out;
}

g.sync(render, purposes.length, 'key purposes');
