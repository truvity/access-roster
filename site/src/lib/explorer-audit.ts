// Builds the audit explorer's model, per tested installation, from src/data/explorer/audit.yaml.
// Ports, drivers and runtimes come from architecture.yaml so the two explorers
// agree. Nothing here states a fact about audit. A "shape" in this file is a
// tested installation (local, boards, lambda, kubernetes) of a runtime; a "role" is an actor.
import { parse } from 'yaml';
import raw from '../data/explorer/audit.yaml?raw';
import { data as arch, statuses } from './explorer-arch';
import { assertStatuses, fill, place, routeEdges, size, label, type Detail, type MapModel, type MapNode, type Row } from './explorer-layout';

/* eslint-disable @typescript-eslint/no-explicit-any */
export const data: any = parse(raw);
assertStatuses(data, statuses, 'audit.yaml');
export { statuses };

export type AuditShape = MapModel & {
  shape: any;
  audit: any;
  transport: any;
  ack: string;
  wait: string;
  recv: string;
  drain: string;
  bound: string;
};

export function shapes(): AuditShape[] {
  return arch.shapes.map(build);
}

function build(sh: any): AuditShape {
  const rt = arch.runtimes[sh.runtime];
  const au = data.shapes[sh.id];
  const ok = data.transport_kinds[sh.ports.transport] ?? data.transport_kinds.spool;
  const cluster = sh.nodes === 'N' || sh.nodes > 1;
  const nodes: MapNode[] = [];
  const nameOf: Record<string, string> = {};
  const defs = data.nodes;

    for (const [id, n] of Object.entries<any>(defs)) {
    let l2 = n.l2 ?? '';
    let l3 = n.l3 ?? '';
    let shared = !!n.shared;
    let cls = n.cls as string;
    let rows: Row[] = [];
    let kind = '';
    let status: string | undefined;
    let issue: number | undefined;
    const notes: Detail['notes'] = [];

    if (n.role) {
      const rid = n.role;
      // `l2_<runtime>` and `l3_<runtime>` override a node's lines on that runtime template (lambda, kubernetes).
      if (n[`l2_${sh.runtime}`]) { l2 = n[`l2_${sh.runtime}`]; l3 = n[`l3_${sh.runtime}`]; }
      else if (n[`l3_${sh.runtime}`]) { l3 = n[`l3_${sh.runtime}`]; }
      else if (!n.l2 || n.role === 'entry') {
        if (n.role !== 'entry') { l2 = fill(rt.role.id_short, { id: rid }); l3 = fill(rt.role.sock_short, { id: rid }); }
      }
      kind = 'actor';
      status = 'decided';
      rows = [
        { k: 'Unit', v: fill(rt.role.unit, { id: rid }), code: true },
        { k: 'Identity', v: fill(rt.role.identity, { id: rid }), code: true },
        { k: 'Listens', v: arch.roles[rid]?.listen_by_runtime?.[sh.runtime] ?? fill(rt.role.listen, { id: rid }), code: true },
      ];
      if (rid === 'writer') rows.push({ k: 'Log key', v: au.log_key });
      if (rid === 'witness') rows.push({ k: 'Witness', v: au.witness });
    } else if (n.port && cls === 'driver') {
      const did = sh.ports[n.port];
      const d = arch.drivers[did];
      const perRole = d.instance === 'per-actor';
      shared = !perRole;
      cls = perRole ? 'driver-role' : 'driver-shared';
      const portTitle = label(n.port);
      l2 = `${d.title}, ${d.instance}`;
      l3 = `${portTitle} port`;
      kind = perRole ? 'driver service, per-actor' : `driver service, shared${d.shared_name ? ` (${d.shared_name})` : ''}`;
      status = d.status;
      issue = d.issue;
      rows = [
        { k: 'Driver', v: `${d.title}, instance: ${d.instance}` },
        { k: 'Backed by', v: d.backing },
      ];
      if (!perRole) {
        const tpl = rt.shared_driver;
        rows.push({ k: 'Unit', v: fill(tpl.unit, { driver: did, id: did }), code: true });
        rows.push({ k: 'Listens', v: fill(tpl.listen, { driver: did, id: did }), code: true });
      } else {
        rows.push({ k: 'Listens', v: `${fill(rt.role_driver.listen, { driver: String(d.binary).replace(/^drivers\//, ''), role: '<role>' })}, one per role that uses it`, code: true });
      }
      if (n.port === 'transport') {
        rows.push({ k: 'Durable means', v: ok.durable });
        rows.push({ k: 'Records wait', v: ok.wait + (cluster ? ok.cluster_wait ?? '' : '') });
        rows.push({ k: 'Who the record is from', v: ok.caller });
        rows.push({ k: 'Instance', v: ok.instance });
        rows.push({ k: 'Mode in this installation', v: ok.mode_label ?? ok.mode });
      }
      if (n.port === 'keys') rows.push({ k: 'Used here by', v: 'the writer (the log key) and the witness (its own key)' });
    } else if (n.port && cls === 'store') {
      const did = sh.ports[n.port];
      const d = arch.drivers[did];
      const bl = arch.backing_lines[`${n.port}.${did}`] ?? [d.backing, ''];
      l2 = bl[0];
      l3 = bl[1] || n.title;
      kind = 'backing store';
      status = n.port === 'index' ? d.status : 'decided';
      issue = n.port === 'index' ? d.issue : undefined;
      rows = [{ k: 'Backend', v: d.backing }];
      if (n.port === 'blob') {
        rows = [{ k: 'Backend', v: au.blob }, { k: 'Lock mode', v: au.lock }, ...data.blob_rows];
      }
      if (n.port === 'keys') rows.push({ k: 'Log key', v: au.log_key });
      if (n.port === 'index') {
        rows = [{ k: 'Backend', v: d.backing }, { k: 'Placement', v: au.index_placement }];
      }
    } else if (cls === 'external') {
      kind = 'outside sluis';
    } else if (id === 'producers') {
      kind = 'actors, producers';
      status = 'decided';
    } else if (id === 'recovery') {
      kind = 'break-glass tool';
      status = 'decided';
    } else if (id === 'rspool') {
      kind = 'local spool, break-glass';
      status = 'decided';
    }
    if (id === 'index' && !n.port) rows = [];
    // Optional per-node overrides from the YAML.
    if (n.kind) kind = n.kind;
    if (n.status) { status = n.status; issue = n.issue; }
    if (n.rows) rows = n.rows;
    if (n.extra_rows) rows = [...rows, ...n.extra_rows];

    const detail: Detail = {
      title: n.title,
      kind: kind || n.cls,
      cls: cls === 'driver' ? 'driver-shared' : cls,
      status, issue,
      does: n.does,
      rows: [...rows, ...(n.holds ? [{ k: 'Holds', v: n.holds }] : []), ...(n.never ? [{ k: 'Never holds', v: n.never }] : [])],
      lists: [],
      notes,
    };
    if (id === 'index') {
      // The index node is an index store, not a driver.
      const d = arch.drivers[sh.ports.index];
      const bl = arch.backing_lines[`index.${sh.ports.index}`];
      nodes.push(place({ id, lane: n.lane, row: n.row, cls: 'store', shared: false, title: 'search index', l2: bl[0], l3: bl[1], detail: { ...detail, kind: 'search index', cls: 'store', status: d.status, issue: d.issue, rows: [{ k: 'Backend', v: d.backing }, { k: 'Placement', v: au.index_placement }], notes: [] } }));
      nameOf[id] = 'search index';
      continue;
    }
    nodes.push(place({ id, lane: n.lane, row: n.row, cls: detail.cls, shared, title: n.title, l2, l3, detail }));
    nameOf[id] = n.title;
  }

  const ids = new Set(nodes.map((x) => x.id));
  const live = data.calls.filter((e: any) => ids.has(e.f) && ids.has(e.t));
  const edges = routeEdges(nodes, live.map((e: any) => ({ ...e })));
  const nm = (id: string) => nameOf[id] ?? id;
  for (const n of nodes) {
    if (n.cls === 'external') continue;
    const outs = edges.filter((e) => e.f === n.id && e.m);
    const ins = edges.filter((e) => e.t === n.id && e.m);
    if (outs.length) n.detail.lists.push({ title: 'Calls', items: outs.map((e) => `${nm(e.t)}: ${e.m}${e.d ? `. ${e.d}` : ''}`) });
    if (ins.length) n.detail.lists.push({ title: 'Called by', items: ins.map((e) => `${nm(e.f)}: ${e.m}`) });
  }

  const { width, height, lanes } = size(nodes, data.lanes);
  const shapeNotes: MapModel['notes'] = au.note ? [{ text: au.note, status: 'decided' }] : [];
  return {
    id: sh.id, name: sh.name, nodes, edges, width, height, lanes,
    intro: `Runtime: ${sh.environment}. Transport: ${ok.short}. Keys: ${sh.keys}. Blob: ${au.blob}, ${au.lock}.`,
    notes: shapeNotes,
    shape: sh, audit: au, transport: ok,
    ack: ok.durable,
    wait: ok.wait + (cluster ? ok.cluster_wait ?? '' : ''),
    recv: ok.recv + (cluster ? ok.cluster_recv ?? '' : ''),
    drain: ok.drain + (cluster ? ok.cluster_drain ?? '' : ''),
    bound: ok.bound,
  };
}
