import { useState } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Checkbox from "@mui/material/Checkbox";
import FormControlLabel from "@mui/material/FormControlLabel";
import MenuItem from "@mui/material/MenuItem";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TextField from "@mui/material/TextField";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";

import { Backend, access, ago, at, backendName, personName, reason, settings, workspaces } from "./api";
import { useAsync, useWhile } from "./hooks";
import type { Workspace } from "./gen/directoryroster/v1/workspace_pb";
import { paths } from "./router";
import { Authority, Facet, Facets, Failure, Loading, Names, Nothing, Page, Ref, Rows, Section, State, authorityKind, stateLabel } from "./ui";

/** The identity-side container: every directory this hub reads. */
export function Directories({ operator, onDone }: { operator: boolean; onDone: (message: string) => void }) {
  const list = useAsync(() => workspaces.listWorkspaces({}), []);
  const [adding, setAdding] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const [provider, setProvider] = useState("");
  const [state, setState] = useState("");

  const all = list.value?.workspaces ?? [];

  // The states actually present, in the order the chips rank them, so the
  // facet never offers a button that returns nothing. A provider with one
  // contested domain gets that button; an installation with none never
  // sees the word.
  const order = ["authoritative", "provisional", "contested", "unserved", "unowned"];
  const present = order.filter((kind) => all.some((tenant) => tenant.domains.some((domain) => authorityKind(domain) === kind)));

  // Filtering is BY DOMAIN and the row is a domain, so a provider whose
  // domains all fall away falls away with them. A provider with no
  // domains at all survives only when no state is being asked for —
  // there is nothing about it that could match one.
  const rows = all
    .filter((tenant) => !provider || tenant.id === provider)
    .map((tenant) => ({ ...tenant, domains: state ? tenant.domains.filter((domain) => authorityKind(domain) === state) : tenant.domains }))
    .filter((tenant) => tenant.domains.length > 0 || !state);

  return (
    <Page
      title="Providers"
      lede="Every identity provider access-roster holds a credential for, one row per domain it serves. Domains are discovered, never typed, and the groups and accounts behind them are what memberships and people are made of."
      actions={
        <Button variant="contained" disabled={!operator || adding} onClick={() => setAdding(true)}>
          Add a provider
        </Button>
      }
    >
      {adding ? (
        <AddDirectory
          onCancel={() => setAdding(false)}
          onAdded={(message) => {
            setAdding(false);
            onDone(message);
            list.reload();
          }}
          onFailure={setFailure}
        />
      ) : null}

      <Loading busy={list.loading} />
      <Failure error={failure ?? list.error} />

      <Facets>
        <Facet
          value={provider}
          onChange={setProvider}
          all={{ value: "", label: "Every provider" }}
          options={all.map((tenant) => ({ value: tenant.id, label: tenant.id }))}
          mono
        />
        <Facet
          value={state}
          onChange={setState}
          all={{ value: "", label: "Any state" }}
          options={present.map((kind) => ({ value: kind, label: stateLabel(kind) }))}
        />
      </Facets>

      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Provider</TableCell>
              <TableCell>Backend</TableCell>
              <TableCell>Domain</TableCell>
              <TableCell>Health</TableCell>
              <TableCell>Snapshot</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.flatMap((tenant) =>
              // ONE ROW PER DOMAIN, repeating the provider. A stack of
              // domains inside one cell cannot be scanned down, and a
              // provider with seven of them towers over one with two.
              // The duplication is the price of the row being the unit a
              // reader compares.
              (tenant.domains.length ? tenant.domains : [undefined]).map((domain, index) => (
                <TableRow key={`${tenant.id}:${domain?.name ?? ""}`} hover>
                  <TableCell>
                    {index === 0 ? (
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                        <Ref to={paths.directory(tenant.id)} mono>
                          {tenant.id}
                        </Ref>
                        {tenant.declared ? <State kind="declared" /> : null}
                      </Stack>
                    ) : (
                      // Repeated, but quietly: the eye should land on the
                      // first of a run and read the rest as the same one.
                      <Ref to={paths.directory(tenant.id)} mono dim>
                        {tenant.id}
                      </Ref>
                    )}
                  </TableCell>
                  <TableCell>
                    {index === 0 ? (
                      <Typography variant="body2" color="text.secondary">
                        {backendName(tenant.backend)}
                      </Typography>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    {domain ? (
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                        <Typography variant="body2" color={domain.served ? undefined : "text.secondary"}>
                          {domain.name}
                        </Typography>
                        <Authority authoritative={domain.authoritative} conflict={domain.conflict} served={domain.served} owned={domain.owned} reason={domain.reason} />
                      </Stack>
                    ) : (
                      <Typography variant="body2" color="text.secondary">
                        no domain discovered yet
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    {index === 0 ? (
                      <State kind={tenant.health?.ok ? "healthy" : "failing"} title={tenant.health?.ok ? undefined : (tenant.health?.error ?? "not probed yet")} />
                    ) : null}
                  </TableCell>
                  <TableCell>{index === 0 ? ago(at(tenant.snapshotAt)) : null}</TableCell>
                </TableRow>
              )),
            )}
            {!list.loading && rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5}>
                  {/* An empty state that names an action offers it. This
                      page is reached with nothing on it twice: on day one,
                      and straight after disconnecting the last provider
                      — and on both the only way on is a control in the
                      header, which is where somebody reading a sentence
                      in the middle of the page is not looking. */}
                  <Stack direction="row" sx={{ alignItems: "center", flexWrap: "wrap", gap: 1, py: 1 }}>
                    <Typography variant="body2" color="text.secondary">
                      No providers yet. Add one to start serving its domains.
                    </Typography>
                    <Button size="small" disabled={!operator || adding} onClick={() => setAdding(true)}>
                      Add a provider
                    </Button>
                  </Stack>
                </TableCell>
              </TableRow>
            ) : null}
          </TableBody>
        </Table>
      </TableContainer>
    </Page>
  );
}

/** The two ways in, as one panel: admin consent through the directory's
 *  own screen, or a service-account key the operator already holds. Only
 *  the ways this deployment can actually take are offered, and when there
 *  are none the panel says why instead of showing a button that does
 *  nothing. */
function AddDirectory({
  onCancel,
  onAdded,
  onFailure,
}: {
  onCancel: () => void;
  onAdded: (message: string) => void;
  onFailure: (message: string) => void;
}) {
  const providers = useAsync(() => settings.getSettings({}), []);
  const connectors = providers.value?.connectors ?? [];
  const keyConnectors = providers.value?.keyConnectors ?? [];
  const [backend, setBackend] = useState<Backend | undefined>();
  const [admin, setAdmin] = useState("");
  const [key, setKey] = useState<{ name: string; bytes: Uint8Array } | undefined>();
  const [busy, setBusy] = useState(false);

  const chosenKeyBackend = backend ?? keyConnectors[0];

  const consent = async (which: Backend) => {
    setBusy(true);
    try {
      const started = await workspaces.beginConnect({ backend: which });
      window.location.href = started.consentUrl;
    } catch (error) {
      setBusy(false);
      onFailure(reason(error));
    }
  };

  const upload = async () => {
    if (!chosenKeyBackend || !key) return;
    setBusy(true);
    try {
      const done = await workspaces.uploadKey({ backend: chosenKeyBackend, key: key.bytes, admin: admin.trim() });
      onAdded(`${done.workspace?.id ?? "The provider"} added from ${key.name}.`);
    } catch (error) {
      onFailure(reason(error));
    } finally {
      setBusy(false);
    }
  };

  const pick = (file: File | undefined) => {
    if (!file) {
      setKey(undefined);
      return;
    }
    void file.arrayBuffer().then((buffer) => setKey({ name: file.name, bytes: new Uint8Array(buffer) }));
  };

  return (
    <Paper variant="outlined" sx={{ p: 2.5, mb: 3 }}>
      <Loading busy={providers.loading || busy} />
      <Failure error={providers.error} />
      {providers.value && connectors.length === 0 ? (
        <Stack spacing={1}>
          <Typography variant="body2">This deployment has no provider backend wired, so there is nothing to connect to yet.</Typography>
          <Typography variant="body2" color="text.secondary">
            Connecting a Google Workspace needs the Google connector and an OAuth client in <Ref to={paths.settings()}>Settings</Ref>; a deployment can
            also declare a provider in its values with a service-account key.
          </Typography>
        </Stack>
      ) : (
        <Stack spacing={3}>
          <Box>
            <Typography variant="subtitle2">Through admin consent</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.25 }}>
              The provider's own consent screen, signed in as its admin. Domains, accounts and groups are discovered from what it grants.
            </Typography>
            <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap", gap: 1 }}>
              {connectors.map((which) => (
                <Button key={which} variant="contained" disabled={busy} onClick={() => void consent(which)}>
                  Connect {backendName(which)}
                </Button>
              ))}
            </Stack>
          </Box>

          {keyConnectors.length ? (
            <Box>
              <Typography variant="subtitle2">With a service-account key</Typography>
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.25 }}>
                The key the provider issued, and the admin account it should act as. The key is stored in this service's namespace and never shown again.
              </Typography>
              <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start", flexWrap: "wrap", gap: 1 }}>
                {keyConnectors.length > 1 ? (
                  <TextField select label="Provider" value={chosenKeyBackend ?? ""} onChange={(e) => setBackend(Number(e.target.value) as Backend)} sx={{ minWidth: 200 }}>
                    {keyConnectors.map((which) => (
                      <MenuItem key={which} value={which}>
                        {backendName(which)}
                      </MenuItem>
                    ))}
                  </TextField>
                ) : null}
                <Button variant="outlined" component="label" disabled={busy}>
                  {key ? key.name : "Choose the key file"}
                  <input type="file" accept="application/json,.json" hidden onChange={(e) => pick(e.target.files?.[0])} />
                </Button>
                <TextField label="Admin to act as" placeholder="admin@example.com" value={admin} onChange={(e) => setAdmin(e.target.value)} sx={{ minWidth: 260 }} />
                <Button variant="contained" disabled={busy || !key || !admin.trim()} onClick={() => void upload()}>
                  Add
                </Button>
              </Stack>
            </Box>
          ) : null}
        </Stack>
      )}
      <Box sx={{ mt: 2 }}>
        <Button size="small" onClick={onCancel}>
          Cancel
        </Button>
      </Box>
    </Paper>
  );
}

/** One directory, read along the chain: its standing, the domains it
 *  serves, the groups it contributes and the accounts it holds. Every
 *  group and every account is a link, because a directory is the top of
 *  the identity side and everything below it is reachable from here. */
export function Directory({
  id,
  operator,
  onDone,
  choosing,
}: {
  id: string;
  operator: boolean;
  onDone: (message: string) => void;
  /** True when the consent that just connected this directory left the
   *  question of which domains to serve open. */
  choosing?: boolean;
}) {
  const list = useAsync(() => workspaces.listWorkspaces({}), []);
  const groups = useAsync(() => access.listDirectoryGroups({}), []);
  const policy = useAsync(() => access.getPolicy({}), []);
  const accounts = useAsync(() => access.searchPeople({ workspaceId: id, limit: 200 }), [id]);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();

  const tenant = (list.value?.workspaces ?? []).find((w) => w.id === id);
  const contributed = (groups.value?.groups ?? []).filter((g) => g.workspaceId === id);
  const feeds = new Map<string, string[]>();
  for (const group of policy.value?.groups ?? []) {
    for (const member of group.members) {
      feeds.set(member.address, [...(feeds.get(member.address) ?? []), group.name]);
    }
  }
  const people = accounts.value?.people ?? [];

  // A directory that has never been read. The first snapshot runs
  // detached — a connect must not hold a browser open for a whole tenant
  // — so this page opens on a workspace with nothing in it yet, and would
  // otherwise stay that way: it fetches once, and the read it is waiting
  // for lands seconds later behind it.
  const firstSnapshot = tenant !== undefined && at(tenant.snapshotAt) === undefined;
  useWhile(firstSnapshot, 2000, () => {
    list.reload();
    groups.reload();
    accounts.reload();
  });

  const act = async (run: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setFailure(undefined);
    try {
      await run();
      onDone(done);
      list.reload();
      groups.reload();
      accounts.reload();
    } catch (error) {
      setFailure(reason(error));
    } finally {
      setBusy(false);
    }
  };

  if (!tenant) {
    return (
      <Box>
        <Loading busy={list.loading} />
        <Failure error={list.error} />
        {!list.loading ? <Nothing>No provider with that id. It may have been disconnected.</Nothing> : null}
      </Box>
    );
  }

  return (
    <Page
      title={tenant.id}
      mono
      lede={
        firstSnapshot
          ? `A ${backendName(tenant.backend)} provider. Its first snapshot is running; this page fills in by itself when it lands.`
          : `A ${backendName(tenant.backend)} provider holding ${accounts.value?.total ?? people.length} accounts and ${contributed.length} groups.`
      }
      facts={[
        { label: "Acting as", value: tenant.admin || "—" },
        { label: "Connected by", value: tenant.connectedBy || undefined },
        { label: "Health", value: <State kind={tenant.health?.ok ? "healthy" : "failing"} title={tenant.health?.ok ? undefined : (tenant.health?.error ?? "not probed yet")} /> },
        { label: "Snapshot", value: ago(at(tenant.snapshotAt)) },
        { label: "Origin", value: tenant.declared ? <State kind="declared" /> : "connected here" },
      ]}
      aside={
        <>
      <Domains
        tenant={tenant}
        operator={operator}
        busy={busy}
        choosing={choosing}
        onSave={(domains) => {
          void act(
            () => workspaces.setServedDomains({ workspaceId: tenant.id, domains }),
            domains.length === 0 ? "Serving every domain this provider owns." : `Serving ${domains.length} of its domains.`,
          );
        }}
      />
      <SyncedGroups
        tenant={tenant}
        operator={operator}
        busy={busy}
        onSave={(groups) => {
          void act(
            () => workspaces.setSyncedGroups({ workspaceId: tenant.id, groups }),
            groups.length === 0 ? "Keeping every group in the served domains." : `Keeping ${groups.length} of its groups.`,
          );
        }}
      />
        </>
      }
      actions={
        <>
          <Button size="small" disabled={!operator || busy} onClick={() => void act(() => workspaces.probe({ workspaceId: tenant.id }), "Probed.")}>
            Probe
          </Button>
          <Button size="small" disabled={!operator || busy} onClick={() => void act(() => workspaces.refresh({ workspaceId: tenant.id }), "New snapshot taken.")}>
            Refresh
          </Button>
          <Button
            size="small"
            disabled={!operator || tenant.declared}
            onClick={async () => {
              try {
                const started = await workspaces.reconnect({ workspaceId: tenant.id });
                window.location.href = started.consentUrl;
              } catch (error) {
                setFailure(reason(error));
              }
            }}
          >
            Reconnect
          </Button>
          <Tooltip title={tenant.declared ? "Declared by the deployment: remove it from the values instead." : "Revoke the credential and forget this provider."}>
            <span>
              <Button
                size="small"
                color="warning"
                disabled={!operator || tenant.declared || busy}
                onClick={() => void act(() => workspaces.disconnect({ workspaceId: tenant.id }), `${tenant.id} disconnected.`)}
              >
                Disconnect
              </Button>
            </span>
          </Tooltip>
        </>
      }
    >
      <Loading busy={busy || firstSnapshot || list.loading || groups.loading || accounts.loading} />
      <Failure error={failure ?? groups.error ?? accounts.error} />

      <Section title="Groups it contributes" hint="what a membership can attach to an internal group">
        <Rows
          items={contributed}
          keyOf={(g) => g.email}
          primary={(g) => (
            <Ref to={paths.directoryGroup(g.email)} mono>
              {g.email}
            </Ref>
          )}
          secondary={(g) => (
            <>
              {g.members} members · feeds <Names items={(feeds.get(g.email) ?? []).map((name) => ({ label: name, to: paths.group(name), mono: true }))} empty="nothing" muted />
            </>
          )}
          empty={firstSnapshot ? "Reading them now — the first snapshot is still running." : "No groups snapshotted from this provider yet."}
        />
      </Section>

      <Section title="Accounts it holds" hint={accounts.value?.truncated ? `the first ${people.length}; the People page filters the rest` : "as the last snapshot has them"}>
        <Rows
          items={people}
          keyOf={(p) => p.email}
          primary={(p) => <Ref to={paths.person(p.email)}>{personName(p.givenName, p.familyName, p.email)}</Ref>}
          secondary={(p) => p.email}
          right={(p) => <State kind={p.live ? "live" : "suspended"} />}
          empty={firstSnapshot ? "Reading them now — the first snapshot is still running." : "No accounts snapshotted from this provider yet."}
        />
      </Section>
    </Page>
  );
}

/** The domains of one directory: what it owns, and which of them this hub
 *  answers for.
 *
 *  Discovery and service are two different facts about a domain and the
 *  section shows both, because the difference is invisible otherwise: a
 *  domain missing from a list looks the same whether the directory never
 *  had it or an operator decided not to read it. Narrowing is offered
 *  only where it is the operator's to make — a declared directory says so
 *  in the deployment's values — and only ever picks from what the
 *  directory itself reports, so nothing here can claim a domain the
 *  company does not own.
 *
 *  Ticking every box means "all of them", not "these ones", so a domain
 *  the company adds later is served without anyone remembering to come
 *  back here.
 *
 *  A connect opens this straight away. The tenant it was built against
 *  owned seven domains, most of them not domains anybody works at, and a
 *  connect that quietly served all seven read every one before the
 *  operator had done anything. So the question is asked once, at the
 *  moment somebody is standing in front of the answer, with the domain
 *  they consented from already ticked. */
function Domains({
  tenant,
  operator,
  busy,
  choosing,
  onSave,
}: {
  tenant: Workspace;
  operator: boolean;
  busy: boolean;
  choosing?: boolean;
  onSave: (domains: string[]) => void;
}) {
  const owned = tenant.domains.filter((d) => d.owned).map((d) => d.name);
  const served = tenant.domains.filter((d) => d.served).map((d) => d.name);
  const mayChoose = operator && !tenant.declared && tenant.domains.length > 1;
  const [choice, setChoice] = useState<string[] | undefined>(choosing && mayChoose ? served : undefined);
  const editing = choice !== undefined;
  const narrowed = tenant.domains.some((d) => !d.served);

  const toggle = (name: string) =>
    setChoice((current) => {
      const now = current ?? [];
      return now.includes(name) ? now.filter((d) => d !== name) : [...now, name];
    });

  return (
    <Section
      title="Domains"
      hint={
        editing
          ? "tick the ones access-roster should answer for. The rest stays discovered and visible, but nothing routes to it and its accounts are never read"
          : narrowed
            ? "discovered from the provider; only the served ones are routed and kept"
            : "discovered from the provider and re-read on every probe"
      }
    >
      {editing ? (
        <Stack spacing={0.5}>
          {tenant.domains.map((domain) => (
            <FormControlLabel
              key={domain.name}
              control={<Checkbox size="small" checked={choice.includes(domain.name)} disabled={!domain.owned} onChange={() => toggle(domain.name)} />}
              label={
                <Typography variant="body2" color={domain.owned ? undefined : "text.secondary"}>
                  {domain.name}
                  {domain.owned ? null : " — no longer owned"}
                </Typography>
              }
            />
          ))}
          <Stack direction="row" spacing={1} sx={{ pt: 0.5 }}>
            <Button
              size="small"
              variant="contained"
              disabled={busy || choice.length === 0}
              onClick={() => {
                onSave(choice.length === owned.length ? [] : choice);
                setChoice(undefined);
              }}
            >
              Save
            </Button>
            <Tooltip title="Including domains the company adds later, without anyone coming back here.">
              <span>
                <Button
                  size="small"
                  disabled={busy}
                  onClick={() => {
                    onSave([]);
                    setChoice(undefined);
                  }}
                >
                  Serve all of them
                </Button>
              </span>
            </Tooltip>
            <Button size="small" disabled={busy} onClick={() => setChoice(undefined)}>
              Cancel
            </Button>
          </Stack>
          {choice.length === 0 ? (
            <Typography variant="caption" color="text.secondary">
              A provider that serves nothing answers for nobody. Disconnect it instead.
            </Typography>
          ) : null}
        </Stack>
      ) : (
        <>
          <Rows
            items={tenant.domains}
            keyOf={(d) => d.name}
            primary={(d) => d.name}
            right={(d) => <Authority authoritative={d.authoritative} conflict={d.conflict} served={d.served} owned={d.owned} reason={d.reason} />}
            empty="None discovered yet. Probe once the credential works."
          />
          {mayChoose ? (
            <Button size="small" sx={{ ml: -1, mt: 0.5 }} onClick={() => setChoice(served)}>
              Choose which to serve
            </Button>
          ) : null}
          {tenant.declared && narrowed ? (
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
              The deployment states which domains this provider serves.
            </Typography>
          ) : null}
        </>
      )}
    </Section>
  );
}

/** Which of a directory's groups this hub keeps.
 *
 *  A company's directory holds every mailing list it has ever made, and
 *  an installation's policy speaks about a handful of them. Keeping the
 *  rest costs a cache, a picker full of noise, and a page of groups that
 *  attach to nothing — so an operator may name the ones that matter.
 *
 *  The list to pick from is what the last read of the directory HELD,
 *  not what is currently kept: a chooser that could only offer what was
 *  already chosen could never widen the choice again. It is why the
 *  snapshot carries the discovered names even for groups it drops.
 *
 *  Narrowing here is not a saving in the directory's quota. The hub
 *  still reads the tenant's groups — that list is what this picker is —
 *  and the saving is in what is stored, answered and shown. */
function SyncedGroups({
  tenant,
  operator,
  busy,
  onSave,
}: {
  tenant: Workspace;
  operator: boolean;
  busy: boolean;
  onSave: (groups: string[]) => void;
}) {
  const discovered = tenant.discoveredGroups;
  const [choice, setChoice] = useState<string[] | undefined>();
  const editing = choice !== undefined;
  const narrowed = tenant.syncGroups.length > 0;
  const mayChoose = operator && !tenant.declared && discovered.length > 0;

  if (discovered.length === 0 && !narrowed) return null;

  const toggle = (name: string) =>
    setChoice((current) => {
      const now = current ?? [];
      return now.includes(name) ? now.filter((g) => g !== name) : [...now, name];
    });

  return (
    <Section
      title="Groups it syncs"
      hint={
        editing
          ? "tick the groups access-roster should keep. The rest stays in the provider and is simply not read back"
          : narrowed
            ? `${tenant.syncGroups.length} of ${discovered.length} groups this provider holds`
            : "every group in the served domains"
      }
    >
      {editing ? (
        <Stack spacing={0.5}>
          {discovered.map((group) => (
            <FormControlLabel
              key={group}
              control={<Checkbox size="small" checked={choice.includes(group)} onChange={() => toggle(group)} />}
              label={<Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.85em" }}>{group}</Typography>}
            />
          ))}
          <Stack direction="row" spacing={1} sx={{ pt: 0.5 }}>
            <Button
              size="small"
              variant="contained"
              disabled={busy || choice.length === 0}
              onClick={() => {
                onSave(choice.length === discovered.length ? [] : choice);
                setChoice(undefined);
              }}
            >
              Save
            </Button>
            <Tooltip title="Including groups the company makes later, without anyone coming back here.">
              <span>
                <Button
                  size="small"
                  disabled={busy}
                  onClick={() => {
                    onSave([]);
                    setChoice(undefined);
                  }}
                >
                  Keep all of them
                </Button>
              </span>
            </Tooltip>
            <Button size="small" disabled={busy} onClick={() => setChoice(undefined)}>
              Cancel
            </Button>
          </Stack>
        </Stack>
      ) : (
        <>
          {narrowed ? (
            <Rows
              items={tenant.syncGroups}
              keyOf={(g) => g}
              primary={(g) => (
                <Ref to={paths.directoryGroup(g)} mono>
                  {g}
                </Ref>
              )}
              empty="None."
            />
          ) : (
            <Typography variant="body2" color="text.secondary">
              Every group in the served domains is kept.
            </Typography>
          )}
          {mayChoose ? (
            <Button size="small" sx={{ ml: -1, mt: 0.5 }} onClick={() => setChoice(tenant.syncGroups.length ? [...tenant.syncGroups] : [...discovered])}>
              Choose which to sync
            </Button>
          ) : null}
          {tenant.declared && narrowed ? (
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
              The deployment states which groups this provider syncs.
            </Typography>
          ) : null}
        </>
      )}
    </Section>
  );
}
