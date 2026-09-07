import { useState } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
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
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Authority, Failure, Loading, Names, Nothing, Page, Ref, Rows, Section, State } from "./ui";

/** The identity-side container: every directory this hub reads. */
export function Directories({ operator, onDone }: { operator: boolean; onDone: (message: string) => void }) {
  const list = useAsync(() => workspaces.listWorkspaces({}), []);
  const [adding, setAdding] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();

  const rows = list.value?.workspaces ?? [];

  return (
    <Page
      title="Directories"
      lede="Every directory this hub holds a credential for. Its domains are discovered, never typed, and its groups and accounts are what memberships and people are made of."
      actions={
        <Button variant="contained" disabled={!operator || adding} onClick={() => setAdding(true)}>
          Add a directory
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

      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Directory</TableCell>
              <TableCell>Backend</TableCell>
              <TableCell>Domains</TableCell>
              <TableCell>Health</TableCell>
              <TableCell>Snapshot</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((tenant) => (
              <TableRow key={tenant.id} hover>
                <TableCell>
                  <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                    <Ref to={paths.directory(tenant.id)} mono>
                      {tenant.id}
                    </Ref>
                    {tenant.declared ? <State kind="declared" /> : null}
                  </Stack>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {backendName(tenant.backend)}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Stack spacing={0.5}>
                    {tenant.domains.map((domain) => (
                      <Stack key={domain.name} direction="row" spacing={1} sx={{ alignItems: "center" }}>
                        <Typography variant="body2">{domain.name}</Typography>
                        <Authority authoritative={domain.authoritative} conflict={domain.conflict} />
                      </Stack>
                    ))}
                  </Stack>
                </TableCell>
                <TableCell>
                  <State kind={tenant.health?.ok ? "healthy" : "failing"} title={tenant.health?.ok ? undefined : (tenant.health?.error ?? "not probed yet")} />
                </TableCell>
                <TableCell>{ago(at(tenant.snapshotAt))}</TableCell>
              </TableRow>
            ))}
            {!list.loading && rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                    No directories yet. Add one to start serving its domains.
                  </Typography>
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
      onAdded(`${done.workspace?.id ?? "The directory"} added from ${key.name}.`);
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
          <Typography variant="body2">This deployment has no directory backend wired, so there is nothing to connect to yet.</Typography>
          <Typography variant="body2" color="text.secondary">
            Connecting a Google Workspace needs the Google connector and an OAuth client in <Ref to={paths.settings()}>Settings</Ref>; a deployment can
            also declare a directory in its values with a service-account key.
          </Typography>
        </Stack>
      ) : (
        <Stack spacing={3}>
          <Box>
            <Typography variant="subtitle2">Through admin consent</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.25 }}>
              The directory's own consent screen, signed in as its admin. Domains, accounts and groups are discovered from what it grants.
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
                The key the directory issued, and the admin account it should act as. The key is stored in the hub's namespace and never shown again.
              </Typography>
              <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start", flexWrap: "wrap", gap: 1 }}>
                {keyConnectors.length > 1 ? (
                  <TextField select label="Directory" value={chosenKeyBackend ?? ""} onChange={(e) => setBackend(Number(e.target.value) as Backend)} sx={{ minWidth: 200 }}>
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
export function Directory({ id, operator, onDone }: { id: string; operator: boolean; onDone: (message: string) => void }) {
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
        {!list.loading ? <Nothing>No directory with that id. It may have been disconnected.</Nothing> : null}
      </Box>
    );
  }

  return (
    <Page
      title={tenant.id}
      mono
      lede={`A ${backendName(tenant.backend)} directory holding ${accounts.value?.total ?? people.length} accounts and ${contributed.length} groups.`}
      facts={[
        { label: "Acting as", value: tenant.admin || "—" },
        { label: "Connected by", value: tenant.connectedBy || undefined },
        { label: "Health", value: <State kind={tenant.health?.ok ? "healthy" : "failing"} title={tenant.health?.ok ? undefined : (tenant.health?.error ?? "not probed yet")} /> },
        { label: "Snapshot", value: ago(at(tenant.snapshotAt)) },
        { label: "Origin", value: tenant.declared ? <State kind="declared" /> : "connected here" },
      ]}
      aside={
        <>
      <Section title="Domains" hint="discovered from the directory and re-read on every probe">
        <Rows
          items={tenant.domains}
          keyOf={(d) => d.name}
          primary={(d) => d.name}
          right={(d) => <Authority authoritative={d.authoritative} conflict={d.conflict} />}
          empty="None discovered yet. Probe once the credential works."
        />
      </Section>
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
          <Tooltip title={tenant.declared ? "Declared by the deployment: remove it from the values instead." : "Revoke the credential and forget this directory."}>
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
      <Loading busy={busy || list.loading || groups.loading || accounts.loading} />
      <Failure error={failure ?? groups.error ?? accounts.error} />

      <Section title="Directory groups it contributes" hint="what a membership can attach to an internal group">
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
          empty="No groups snapshotted from this directory yet."
        />
      </Section>

      <Section title="Accounts it holds" hint={accounts.value?.truncated ? `the first ${people.length}; the People page filters the rest` : "as the last snapshot has them"}>
        <Rows
          items={people}
          keyOf={(p) => p.email}
          primary={(p) => <Ref to={paths.person(p.email)}>{personName(p.givenName, p.familyName, p.email)}</Ref>}
          secondary={(p) => p.email}
          right={(p) => <State kind={p.live ? "live" : "suspended"} />}
          empty="No accounts snapshotted from this directory yet."
        />
      </Section>
    </Page>
  );
}
