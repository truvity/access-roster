import { useState } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Chip from "@mui/material/Chip";
import Menu from "@mui/material/Menu";
import MenuItem from "@mui/material/MenuItem";
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

import { Backend, ago, at, backendName, reason, workspaces } from "./api";
import { useAsync } from "./hooks";
import { Authority, Failure, Loading } from "./ui";

export function Workspaces({ operator, onDone }: { operator: boolean; onDone: (message: string) => void }) {
  const list = useAsync(() => workspaces.listWorkspaces({}), []);
  const [busy, setBusy] = useState<string | undefined>();
  const [failure, setFailure] = useState<string | undefined>();
  const [connectMenu, setConnectMenu] = useState<HTMLElement | null>(null);

  const act = async (what: string, run: () => Promise<unknown>, done: string) => {
    setBusy(what);
    setFailure(undefined);
    try {
      await run();
      onDone(done);
      list.reload();
    } catch (error) {
      setFailure(reason(error));
    } finally {
      setBusy(undefined);
    }
  };

  const connect = async (backend: Backend) => {
    setConnectMenu(null);
    setFailure(undefined);
    try {
      const started = await workspaces.beginConnect({ backend });
      window.location.href = started.consentUrl;
    } catch (error) {
      setFailure(reason(error));
    }
  };

  const rows = list.value?.workspaces ?? [];

  return (
    <Box>
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", mb: 1 }}>
        <Box>
          <Typography variant="h6">Workspaces</Typography>
          <Typography variant="body2" color="text.secondary">
            Every directory this hub holds a credential for. Domains are discovered, never typed.
          </Typography>
        </Box>
        <Button variant="contained" disabled={!operator} onClick={(e) => setConnectMenu(e.currentTarget)}>
          Connect a workspace
        </Button>
        <Menu anchorEl={connectMenu} open={Boolean(connectMenu)} onClose={() => setConnectMenu(null)}>
          <MenuItem onClick={() => void connect(Backend.GOOGLE)}>Google Workspace</MenuItem>
          <MenuItem onClick={() => void connect(Backend.DEMO)}>Demonstration tenant</MenuItem>
        </Menu>
      </Stack>

      <Loading busy={list.loading || Boolean(busy)} />
      <Failure error={failure ?? list.error} />

      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Workspace</TableCell>
              <TableCell>Domains</TableCell>
              <TableCell>Acting as</TableCell>
              <TableCell>Health</TableCell>
              <TableCell>Snapshot</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((workspace) => {
              const health = workspace.health;
              return (
                <TableRow key={workspace.id} hover>
                  <TableCell>
                    <Stack spacing={0.5}>
                      <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                        {workspace.id}
                      </Typography>
                      <Stack direction="row" spacing={0.5}>
                        <Chip size="small" variant="outlined" label={backendName(workspace.backend)} />
                        {workspace.declared ? (
                          <Tooltip title="The deployment declared this workspace: it is read-only here and wins a contested domain.">
                            <Chip size="small" variant="outlined" color="secondary" label="declared" />
                          </Tooltip>
                        ) : null}
                      </Stack>
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Stack spacing={0.5}>
                      {workspace.domains.map((domain) => (
                        <Stack key={domain.name} direction="row" spacing={1} sx={{ alignItems: "center" }}>
                          <Typography variant="body2">{domain.name}</Typography>
                          <Authority authoritative={domain.authoritative} conflict={domain.conflict} />
                        </Stack>
                      ))}
                      {workspace.domains.length === 0 ? (
                        <Typography variant="body2" color="text.secondary">
                          none discovered yet
                        </Typography>
                      ) : null}
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">{workspace.admin || "—"}</Typography>
                    {workspace.connectedBy ? (
                      <Typography variant="caption" color="text.secondary">
                        connected by {workspace.connectedBy}
                      </Typography>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    {health?.ok ? (
                      <Chip size="small" color="success" variant="outlined" label="ok" />
                    ) : (
                      <Tooltip title={health?.error ?? "not probed yet"}>
                        <Chip size="small" color="warning" label="failing" />
                      </Tooltip>
                    )}
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                      {ago(at(health?.probedAt))}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">{ago(at(workspace.snapshotAt))}</Typography>
                  </TableCell>
                  <TableCell align="right">
                    <Stack direction="row" spacing={1} sx={{ justifyContent: "flex-end" }}>
                      <Button
                        size="small"
                        disabled={!operator || Boolean(busy)}
                        onClick={() =>
                          void act("probe", () => workspaces.probe({ workspaceId: workspace.id }), "Probed.")
                        }
                      >
                        Probe
                      </Button>
                      <Button
                        size="small"
                        disabled={!operator || Boolean(busy)}
                        onClick={() =>
                          void act(
                            "refresh",
                            () => workspaces.refresh({ workspaceId: workspace.id }),
                            "New snapshot taken.",
                          )
                        }
                      >
                        Refresh
                      </Button>
                      <Button
                        size="small"
                        disabled={!operator || workspace.declared}
                        onClick={async () => {
                          try {
                            const started = await workspaces.reconnect({ workspaceId: workspace.id });
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
                          workspace.declared
                            ? "Declared by the deployment: remove it from the values instead."
                            : "Revoke the credential and forget this workspace."
                        }
                      >
                        <span>
                          <Button
                            size="small"
                            color="warning"
                            disabled={!operator || workspace.declared || Boolean(busy)}
                            onClick={() =>
                              void act(
                                "disconnect",
                                () => workspaces.disconnect({ workspaceId: workspace.id }),
                                `${workspace.id} disconnected.`,
                              )
                            }
                          >
                            Disconnect
                          </Button>
                        </span>
                      </Tooltip>
                    </Stack>
                  </TableCell>
                </TableRow>
              );
            })}
            {!list.loading && rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                    No workspaces yet. Connect one to start serving its domains.
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
