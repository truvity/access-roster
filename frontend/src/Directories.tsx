import { useState } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Chip from "@mui/material/Chip";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";

import { Backend, access, ago, at, backendName, reason, settings, workspaces } from "./api";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Authority, Failure, Loading, Nothing, Ref, Section, Summary } from "./ui";

/** The tenants this hub holds a credential for. */
export function Directories({ operator }: { operator: boolean; onDone: (message: string) => void }) {
  const list = useAsync(() => workspaces.listWorkspaces({}), []);
  const providers = useAsync(() => settings.getSettings({}), []);
  const [failure, setFailure] = useState<string | undefined>();

  const connect = async (backend: Backend) => {
    setFailure(undefined);
    try {
      const started = await workspaces.beginConnect({ backend });
      window.location.href = started.consentUrl;
    } catch (error) {
      setFailure(reason(error));
    }
  };

  const rows = list.value?.workspaces ?? [];
  const connectors = providers.value?.connectors ?? [];

  return (
    <Box>
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", mb: 1 }}>
        <Box>
          <Typography variant="h6">Directories</Typography>
          <Typography variant="body2" color="text.secondary">
            Every tenant this hub holds a credential for. Domains are discovered, never typed.
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          {connectors.map((backend) => (
            <Button key={backend} variant="contained" disabled={!operator} onClick={() => void connect(backend)}>
              Connect {backendName(backend)}
            </Button>
          ))}
          {providers.value && connectors.length === 0 ? (
            <Tooltip title="No backend is configured to connect with. Set the OAuth client in Settings first.">
              <span>
                <Button variant="contained" disabled>
                  Connect a tenant
                </Button>
              </span>
            </Tooltip>
          ) : null}
        </Stack>
      </Stack>

      <Loading busy={list.loading || providers.loading} />
      <Failure error={failure ?? list.error} />

      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Tenant</TableCell>
              <TableCell>Domains</TableCell>
              <TableCell>Health</TableCell>
              <TableCell>Snapshot</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((tenant) => (
              <TableRow key={tenant.id} hover>
                <TableCell>
                  <Ref to={paths.directory(tenant.id)} mono>
                    {tenant.id}
                  </Ref>
                  <Stack direction="row" spacing={0.5} sx={{ mt: 0.5 }}>
                    <Chip size="small" variant="outlined" label={backendName(tenant.backend)} />
                    {tenant.declared ? <Chip size="small" variant="outlined" color="secondary" label="declared" /> : null}
                  </Stack>
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
                  {tenant.health?.ok ? (
                    <Chip size="small" color="success" variant="outlined" label="ok" />
                  ) : (
                    <Tooltip title={tenant.health?.error ?? "not probed yet"}>
                      <Chip size="small" color="warning" label="failing" />
                    </Tooltip>
                  )}
                </TableCell>
                <TableCell>
                  <Typography variant="body2">{ago(at(tenant.snapshotAt))}</Typography>
                </TableCell>
              </TableRow>
            ))}
            {!list.loading && rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                    No tenants yet. Connect one to start serving its domains.
                  </Typography>
                </TableCell>
              </TableRow>
            ) : null}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

/** One tenant: its domains, its health, and what it contributes. */
export function Directory({
  id,
  operator,
  onDone,
}: {
  id: string;
  operator: boolean;
  onDone: (message: string) => void;
}) {
  const list = useAsync(() => workspaces.listWorkspaces({}), []);
  const groups = useAsync(() => access.listDirectoryGroups({}), []);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();

  const tenant = (list.value?.workspaces ?? []).find((w) => w.id === id);
  const contributed = (groups.value?.groups ?? []).filter((g) => g.workspaceId === id);

  const act = async (what: string, run: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setFailure(undefined);
    try {
      await run();
      onDone(done);
      list.reload();
      groups.reload();
    } catch (error) {
      setFailure(reason(error));
    } finally {
      setBusy(false);
    }
    void what;
  };

  if (!tenant) {
    return (
      <Box>
        <Loading busy={list.loading} />
        <Failure error={list.error} />
        {!list.loading ? <Nothing>No tenant with that id. It may have been disconnected.</Nothing> : null}
      </Box>
    );
  }

  return (
    <Box>
      <Summary
        title={<span style={{ fontFamily: "monospace" }}>{tenant.id}</span>}
        subtitle={`${backendName(tenant.backend)} · acting as ${tenant.admin || "—"}${
          tenant.connectedBy ? ` · connected by ${tenant.connectedBy}` : ""
        }`}
        chips={
          <>
            {tenant.declared ? (
              <Tooltip title="The deployment declared this tenant: it is read-only here and wins a contested domain.">
                <Chip size="small" variant="outlined" color="secondary" label="declared" />
              </Tooltip>
            ) : null}
            {tenant.health?.ok ? (
              <Chip size="small" color="success" variant="outlined" label="healthy" />
            ) : (
              <Tooltip title={tenant.health?.error ?? "not probed yet"}>
                <Chip size="small" color="warning" label="failing" />
              </Tooltip>
            )}
            <Chip size="small" variant="outlined" label={`snapshot ${ago(at(tenant.snapshotAt))}`} />
          </>
        }
        right={
          <Stack direction="row" spacing={1}>
            <Button size="small" disabled={!operator || busy} onClick={() => void act("probe", () => workspaces.probe({ workspaceId: tenant.id }), "Probed.")}>
              Probe
            </Button>
            <Button size="small" disabled={!operator || busy} onClick={() => void act("refresh", () => workspaces.refresh({ workspaceId: tenant.id }), "New snapshot taken.")}>
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
            <Tooltip
              title={
                tenant.declared
                  ? "Declared by the deployment: remove it from the values instead."
                  : "Revoke the credential and forget this tenant."
              }
            >
              <span>
                <Button
                  size="small"
                  color="warning"
                  disabled={!operator || tenant.declared || busy}
                  onClick={() =>
                    void act("disconnect", () => workspaces.disconnect({ workspaceId: tenant.id }), `${tenant.id} disconnected.`)
                  }
                >
                  Disconnect
                </Button>
              </span>
            </Tooltip>
          </Stack>
        }
      />

      <Loading busy={busy || list.loading} />
      <Failure error={failure} />

      <Section title="Domains" hint="discovered from the tenant and re-read on every probe">
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableBody>
              {tenant.domains.map((domain) => (
                <TableRow key={domain.name}>
                  <TableCell>{domain.name}</TableCell>
                  <TableCell align="right">
                    <Authority authoritative={domain.authoritative} conflict={domain.conflict} />
                  </TableCell>
                </TableRow>
              ))}
              {tenant.domains.length === 0 ? (
                <TableRow>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      None discovered yet. Probe once the credential works.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>
        </TableContainer>
      </Section>

      <Section title="Groups it contributes" hint="what a membership can be attached to">
        {contributed.length === 0 ? (
          <Nothing>No groups snapshotted from this tenant yet.</Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Directory group</TableCell>
                  <TableCell align="right">Members</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {contributed.map((group) => (
                  <TableRow key={group.email} hover>
                    <TableCell>{group.email}</TableCell>
                    <TableCell align="right">{group.members}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Section>
    </Box>
  );
}
