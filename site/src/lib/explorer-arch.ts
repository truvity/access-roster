// Builds the identity explorer's model, per tested installation, from
// src/data/explorer/architecture.yaml. Nothing here states a fact about sluis:
// facts are in the YAML, and this file only expands them (names from the
// runtime templates, the call graph per preset, the layout of the map).
// Vocabulary: a "shape" in the code is a tested installation (local, boards,
// lambda, kubernetes) of a runtime (bare-metal, serverless, kubernetes); a "role" in the
// code is an actor. The identifiers keep their old names; the text shown to
// the reader uses the new.
import { parse } from 'yaml';
import raw from '../data/explorer/architecture.yaml?raw';

import { H, W, assertStatuses, place, size, routeEdges, fill, label, type Detail, type MapEdge, type MapModel, type MapNode, type Row } from './explorer-layout';

/* eslint-disable @typescript-eslint/no-explicit-any */
export const data: any = parse(raw);
export const statuses: Record<string, string> = data.statuses;
assertStatuses(data, statuses, 'architecture.yaml');
export { W, H };

export type ShapeModel = MapModel & {
  shape: any;
  runtime: any;
  processes: { id: string; title: string; kind: string; unit: string; identity: string; listen: string }[];
  ports: { port: string; driver: string; instance: string; backing: string }[];
};

const LANES = ['Edge and node', 'Actors', 'Drivers', 'Backing stores', 'Integrations', 'Outside'];

const ROLE_ORDER = ['session', 'exchange', 'console', 'policy', 'signer', 'ca', 'ssh-ca', 'quota', 'writer', 'witness', 'indexer', 'reader'];
const INT_ORDER = ['int-upstream', 'int-workload', 'int-facts', 'int-minter', 'int-provisioner', 'int-notifier'];
const PORT_ROW: Record<string, number> = { keys: 1.4, state: 3.8, blob: 6.2, transport: 8.4 };


export function shapes(): ShapeModel[] {
  return data.shapes.map(build);
}

function build(shape: any): ShapeModel {
  const rt = data.runtimes[shape.runtime];
  const edgeKind = data.edges_kinds[shape.edge];
  const nodes: MapNode[] = [];
  const nameOf: Record<string, string> = {};
  const add = (n: Omit<MapNode, 'x' | 'y'>) => {
    nodes.push(place(n));
    nameOf[n.id] = n.title;
  };
  const edgesAll = data.calls;

  // ---- lane 0
  add({
    id: 'client', lane: 0, row: 0, cls: 'external', shared: false,
    title: data.externals.client.title, l2: data.externals.client.sub, l3: 'outside sluis',
    detail: { title: 'client', kind: 'outside sluis', cls: 'external', does: data.externals.client.does, rows: [], lists: [], notes: [] },
  });
  add({
    id: 'edge', lane: 0, row: 1.2, cls: 'edge', shared: false,
    title: edgeKind.title, l2: edgeKind.line2, l3: edgeKind.line3,
    detail: {
      title: `Edge connector: ${edgeKind.sub}`, kind: 'edge connector', cls: 'edge', status: edgeKind.status, issue: edgeKind.issue,
      does: edgeKind.does,
      rows: [
        { k: 'Listens', v: edgeKind.listen },
        { k: 'Reaches entry by', v: edgeKind.transport },
      ],
      lists: [], notes: [],
    },
  });
  const entryRole = data.roles.entry;
  add({
    id: 'entry', lane: 0, row: 2.4, cls: 'role', shared: false,
    title: 'entry', l2: fill(rt.role.id_short, { id: 'entry' }), l3: entryRole.map_line_by_runtime?.[shape.runtime] ?? fill(rt.role.sock_short, { id: 'entry' }),
    detail: roleDetail('entry', entryRole),
  });
  if (shape.node_agent) {
    const na = data.node_agent;
    add({
      id: 'sluis-node', lane: 0, row: 4.4, cls: 'node', shared: false,
      title: na.title, l2: fill(rt.role.id_short, { id: 'node' }), l3: fill(rt.role.sock_short, { id: 'node' }),
      detail: {
        title: 'sluis-node', kind: 'node service, workload identity', cls: 'node', status: na.status, issue: na.issue,
        does: na.does,
        rows: [
          { k: 'Unit', v: fill(rt.role.unit, { id: 'node' }), code: true },
          { k: 'Identity', v: fill(rt.role.identity, { id: 'node' }), code: true },
          { k: 'Binary', v: `/usr/libexec/sluis/${na.binary}`, code: true },
          { k: 'Listens', v: fill(rt.role.listen, { id: 'node' }), code: true },
          { k: 'Holds', v: na.holds },
        ],
        lists: [{ title: 'Manifest summary (illustrative)', items: na.resources }],
        notes: [{ text: na.listener_note }],
      },
    });
  }

  // ---- lane 1: actors
  ROLE_ORDER.forEach((id, i) => {
    const r = data.roles[id];
    add({
      id, lane: 1, row: i, cls: 'role', shared: false,
      title: r.name, l2: fill(rt.role.id_short, { id }), l3: fill(rt.role.sock_short, { id }),
      detail: roleDetail(id, r),
    });
  });

  // ---- lanes 2 and 3: drivers and their backing stores
  for (const port of ['keys', 'state', 'blob', 'transport'] as const) {
    const driverId = shape.ports[port];
    const d = data.drivers[driverId];
    const p = data.ports[port];
    const perRole = d.instance === 'per-actor';
    const users: string[] = p.users;
    const tpl = perRole ? rt.role_driver : rt.shared_driver;
    // A driver that runs once for each actor is named by its binary (`drivers/aws`, `drivers/nats-jetstream`).
    const vars = { id: driverId, driver: perRole ? String(d.binary).replace(/^drivers\//, '') : driverId };
    const instances = perRole
      ? users.map((u) => `${fill(tpl.unit, { ...vars, role: u })}: ${fill(tpl.listen, { ...vars, role: u })}`)
      : [];
    const rows: Row[] = [
      { k: 'Instance', v: perRole ? `per-actor: one per actor that uses it (${users.length}), each running as that actor` : 'shared: one instance, which checks each caller by peer credentials against an access list generated from the manifest' },
    ];
    if (d.shared_name) rows.push({ k: 'Shared driver', v: `${d.shared_name}: audits every use` });
    if (!perRole) {
      rows.push({ k: 'Unit', v: fill(tpl.unit, vars), code: true });
      rows.push({ k: 'Identity', v: fill(tpl.identity, vars), code: true });
      rows.push({ k: 'Listens', v: fill(tpl.listen, vars), code: true });
    }
    rows.push({ k: 'Binary', v: `/usr/libexec/sluis/${d.binary}`, code: true });
    if (d.mode) rows.push({ k: 'Transport mode', v: d.mode });
    rows.push({ k: 'Backed by', v: d.backing });
    rows.push({ k: 'Holds', v: d.holds });
    if (d.slots) rows.push({ k: 'Slots', v: d.slots, href: '/concepts/keys/#the-card-slot-map' });
    if (d.peer_port) rows.push({ k: 'Peer traffic', v: "The driver's own TCP port, over mTLS (the port is set in configuration; 4002 is an example). It is the only TCP port between nodes." });
    const lists = [
      { title: 'Used by', items: users },
      ...(perRole ? [{ title: 'Instances (unit: socket)', items: instances }] : []),
    ];
    const notes: Detail['notes'] = [];
    if (port === 'transport' && driverId === 'spool') notes.push({ text: 'On a cluster each node has its own spool.' });
    add({
      id: p.node, lane: 2, row: PORT_ROW[port], cls: perRole ? 'driver-role' : 'driver-shared', shared: !perRole,
      title: `${port} · ${d.title}`,
      l2: perRole ? `per-actor x ${users.length}` : fill(tpl.id_short, vars),
      l3: perRole ? (rt.per_actor_line ?? 'uid of each actor') : fill(tpl.sock_short, vars),
      detail: {
        title: `${label(port)} driver: ${d.title}`,
        kind: perRole ? 'driver service, per-actor' : `driver service, shared${d.shared_name ? ` (${d.shared_name})` : ''}`,
        cls: perRole ? 'driver-role' : 'driver-shared',
        status: d.status, issue: d.issue, does: d.does, rows, lists, notes,
      },
    });
    const bl = data.backing_lines[`${port}.${driverId}`] ?? [d.backing, ''];
    add({
      id: p.store_node, lane: 3, row: PORT_ROW[port], cls: 'store', shared: false,
      title: bl[0], l2: bl[1], l3: p.store_title,
      detail: {
        title: `${label(p.store_title)}: ${d.backing}`, kind: 'backing store', cls: 'store', does: `The ${port} port's backing store in this installation: ${d.backing}.`,
        rows: [], lists: [], notes: port === 'keys' && shape.keys_note ? [{ text: shape.keys_note }] : [],
      },
    });
  }
  {
    const idxId = shape.ports.index;
    const d = data.drivers[idxId];
    const bl = data.backing_lines[`index.${idxId}`];
    add({
      id: 'store-index', lane: 3, row: 10.2, cls: 'store', shared: false,
      title: bl[0], l2: bl[1], l3: 'index',
      detail: {
        title: `Index: ${d.title}`, kind: 'backing store', cls: 'store', status: d.status, issue: d.issue,
        does: d.does, rows: d.binary ? [{ k: 'Binary', v: `/usr/libexec/sluis/${d.binary}`, code: true }] : [], lists: [],
        notes: [],
      },
    });
  }

  // ---- lane 4 and 5: integrations and the outside
  INT_ORDER.forEach((id, i) => {
    const it = data.integrations[id];
    const short = it.example.replace(/^int-/, '');
    add({
      id, lane: 4, row: i * 1.06, cls: 'integration', shared: false,
      title: `${it.kind}`, l2: fill(rt.role.id_short, { id: it.example }), l3: fill(rt.role.sock_short, { id: it.example }),
      detail: {
        title: `${it.kind} integration`, kind: 'integration', cls: 'integration', status: 'decided',
        does: it.does,
        rows: [
          { k: 'Example', v: `${it.example}, as the install names it (illustrative)` },
          { k: 'Unit', v: fill(rt.role.unit, { id: it.example }), code: true },
          { k: 'Identity', v: fill(rt.role.identity, { id: it.example }), code: true },
          { k: 'Binary', v: `/usr/libexec/sluis/integrations/${short}`, code: true },
          { k: 'Listens', v: fill(rt.role.listen, { id: it.example }), code: true },
          { k: 'Holds', v: it.holds },
          { k: 'Egress', v: it.egress },
        ],
        lists: [], notes: [{ text: 'An integration returns facts or carries out an effect core has already authorized. It never decides. Core calls it, never the reverse.' }],
      },
    });
  });
  (['upstream', 'vendor', 'downstream'] as const).forEach((id, i) => {
    const e = data.externals[id];
    add({
      id, lane: 5, row: 0.8 + i * 2.2, cls: 'external', shared: false,
      title: e.title, l2: e.sub, l3: 'outside sluis',
      detail: { title: e.title, kind: 'outside sluis', cls: 'external', does: e.does, rows: [], lists: [], notes: [] },
    });
  });

  // ---- edges
  const ids = new Set(nodes.map((n) => n.id));
  const okWhen = (w: any) => {
    if (!w) return true;
    if (w.runtime !== undefined && shape.runtime !== w.runtime) return false;
    if (w.node_agent !== undefined && !!shape.node_agent !== w.node_agent) return false;
    if (w.ports) for (const [p, v] of Object.entries(w.ports)) if (shape.ports[p] !== v) return false;
    return true;
  };
  const live = edgesAll.filter((e: any) => ids.has(e.f) && ids.has(e.t) && okWhen(e.when));

  const edges = routeEdges(nodes, live, (e) => (`${e.f}>${e.t}` === 'edge>entry' ? edgeKind.transport : e.m));

  // ---- derived call lists on each detail
  const nm = (id: string) => nameOf[id] ?? id;
  for (const n of nodes) {
    if (['external'].includes(n.cls) && n.id !== 'client') continue;
    const outs = edges.filter((e) => e.f === n.id && e.m);
    const ins = edges.filter((e) => e.t === n.id && e.m);
    if (outs.length) n.detail.lists.push({ title: 'Calls', items: outs.map((e) => `${nm(e.t)}: ${e.m}${e.d ? `. ${e.d}` : ''}`) });
    if (ins.length) n.detail.lists.push({ title: 'Called by', items: ins.map((e) => `${nm(e.f)}: ${e.m}`) });
    if (n.cls === 'role' || n.cls === 'integration') {
      if (shape.node_agent && data.roles[n.id]?.workload_jwt !== false) n.detail.lists.push({ title: 'Also', items: ['Asks sluis-node for its workload JWT at start and renewal (not drawn).'] });
    }
  }

  const { width, height, lanes } = size(nodes, LANES);

  const processes = nodes
    .filter((n) => !['external', 'store'].includes(n.cls) && n.id !== 'edge')
    .map((n) => {
      const d = n.detail;
      const get = (k: string) => d.rows.find((r) => r.k === k)?.v ?? '';
      return { id: n.id, title: n.title, kind: d.kind, unit: get('Unit'), identity: get('Identity'), listen: get('Listens') };
    });
  const ports = (['keys', 'state', 'blob', 'transport', 'index'] as const).map((p) => {
    const d = data.drivers[shape.ports[p]];
    return { port: p, driver: d.title, instance: d.instance, backing: d.backing };
  });

  return {
    id: shape.id, name: shape.name, shape, runtime: rt, nodes, edges, width, height, lanes, processes, ports,
    intro: `Runtime: ${shape.environment}. ${shape.hardware}. Keys: ${shape.keys}. State: ${shape.state}.`,
    notes: shape.notes ?? [],
  };

  function roleDetail(id: string, r: any): Detail {
    const listen = r.listen_by_runtime?.[shape.runtime] ?? fill(rt.role.listen, { id });
    const usedPorts = (r.uses ?? []).map((p: string) => {
      const d = data.drivers[shape.ports[p]];
      return `${p}: ${d.title} (${d.instance})`;
    });
    const rows: Row[] = [
      { k: 'Unit', v: fill(rt.role.unit, { id }), code: true },
      { k: 'Identity', v: fill(rt.role.identity, { id }), code: true },
      { k: 'Binary', v: `/usr/libexec/sluis/${r.binary}`, code: true },
      { k: 'Listens', v: listen, code: true },
      { k: 'Called over', v: id === 'entry' ? edgeKind.transport : rt.role_call },
      { k: 'Holds', v: r.holds },
    ];
    const notes: Detail['notes'] = [];
    if (r.listener_note) notes.push({ text: r.listener_note });
    return {
      title: r.name, kind: 'actor', cls: 'role', status: r.status, issue: r.issue, does: r.does, rows,
      lists: [
        { title: 'Drivers it uses in this installation', items: usedPorts },
        { title: 'Manifest summary (illustrative)', items: r.resources },
      ],
      notes,
    };
  }
}
