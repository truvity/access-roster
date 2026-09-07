import { useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Chip from "@mui/material/Chip";
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

import { access, forHowLong, reason } from "./api";
import type { PolicyGroup } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { Failure, Loading } from "./ui";

/** The policy as an operator works with it: the declared vocabulary,
 *  read-only, and the one table that is editable — who is in each group. */
export function AccessView({ operator, onDone }: { operator: boolean; onDone: (message: string) => void }) {
  const policy = useAsync(() => access.getPolicy({}), []);
  const [failure, setFailure] = useState<string | undefined>();
  const [adding, setAdding] = useState<string | undefined>();

  const groups = policy.value?.groups ?? [];

  const detach = async (group: string, address: string) => {
    setFailure(undefined);
    try {
      await access.removeMembership({ group, directoryGroup: address });
      onDone(`${address} removed from ${group}.`);
      policy.reload();
    } catch (error) {
      setFailure(reason(error));
    }
  };

  return (
    <Box>
      <Typography variant="h6">Access</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        The internal groups this deployment declared, and who is in them. Group names, what each adds to a
        token and how long a token lives are deployment configuration; membership is the one thing changed
        here.
      </Typography>

      {policy.value?.adminEnabled ? (
        <Alert severity="warning" sx={{ mb: 2 }}>
          The break-glass admin account is enabled. Turn it off in the deployment once a group below grants
          operator to a real identity.
        </Alert>
      ) : null}

      <Loading busy={policy.loading} />
      <Failure error={failure ?? policy.error} />

      <Stack spacing={2}>
        {groups.map((group) => (
          <GroupCard
            key={group.name}
            group={group}
            operator={operator}
            adding={adding === group.name}
            onAdd={() => setAdding(group.name)}
            onCancel={() => setAdding(undefined)}
            onAdded={(address) => {
              setAdding(undefined);
              onDone(`${address} added to ${group.name}.`);
              policy.reload();
            }}
            onDetach={(address) => void detach(group.name, address)}
            onFailure={setFailure}
          />
        ))}
      </Stack>

      <Typography variant="subtitle1" sx={{ mt: 4, mb: 1 }}>
        Clients
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        What the groups above buy: a client's id is the audience of the tokens issued for it, and its
        requirements are who may be issued one. Clients are declared by the deployment or registered by the
        workload itself, never created here.
      </Typography>
      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Client</TableCell>
              <TableCell>Kind</TableCell>
              <TableCell>Requires any of</TableCell>
              <TableCell>Token cap</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(policy.value?.clients ?? []).map((client) => (
              <TableRow key={client.id} hover>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                    {client.id}
                  </Typography>
                  {client.redirects.length ? (
                    <Typography variant="caption" color="text.secondary">
                      {client.redirects.join(", ")}
                    </Typography>
                  ) : null}
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {client.kind}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                    {client.requires.map((group) => (
                      <Chip key={group} size="small" variant="outlined" label={group} />
                    ))}
                  </Stack>
                </TableCell>
                <TableCell>
                  <Typography variant="body2">{client.ttlCap ? forHowLong(client.ttlCap) : "—"}</Typography>
                </TableCell>
              </TableRow>
            ))}
            {(policy.value?.clients ?? []).length === 0 ? (
              <TableRow>
                <TableCell colSpan={4}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                    No clients are declared. The hub itself needs none; they arrive with the issuer.
                  </Typography>
                </TableCell>
              </TableRow>
            ) : null}
          </TableBody>
        </Table>
      </TableContainer>

      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 2 }}>
        Sign-in sources in this deployment: {(policy.value?.loginSources ?? ["none"]).join(", ")}
      </Typography>
    </Box>
  );
}

function GroupCard({
  group,
  operator,
  adding,
  onAdd,
  onCancel,
  onAdded,
  onDetach,
  onFailure,
}: {
  group: PolicyGroup;
  operator: boolean;
  adding: boolean;
  onAdd: () => void;
  onCancel: () => void;
  onAdded: (address: string) => void;
  onDetach: (address: string) => void;
  onFailure: (message: string) => void;
}) {
  const claims = group.claims ? JSON.stringify(group.claims) : "";

  return (
    <Paper variant="outlined">
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", p: 2, pb: 1 }}>
        <Box>
          <Typography variant="subtitle1" sx={{ fontFamily: "monospace" }}>
            {group.name}
          </Typography>
          <Stack direction="row" spacing={1} sx={{ mt: 0.5, flexWrap: "wrap", gap: 0.5 }}>
            <Tooltip title="What this group adds to a token, deep-merged with every other group the person is in.">
              <Chip size="small" variant="outlined" label={claims ? `adds ${claims}` : "adds only its own name"} />
            </Tooltip>
            <Chip size="small" variant="outlined" label={`token ${forHowLong(group.lifetime)}`} />
            {group.matchers.map((matcher) => (
              <Chip key={matcher} size="small" variant="outlined" color="secondary" label={matcher} />
            ))}
          </Stack>
        </Box>
        <Button size="small" variant="contained" disabled={!operator || adding} onClick={onAdd}>
          Add a directory group
        </Button>
      </Stack>

      {adding ? (
        <AddMembership group={group.name} onCancel={onCancel} onAdded={onAdded} onFailure={onFailure} />
      ) : null}

      <TableContainer sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Directory group</TableCell>
              <TableCell>From</TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {group.members.map((member) => (
              <TableRow key={member.address} hover>
                <TableCell>
                  <Typography variant="body2">{member.address}</Typography>
                </TableCell>
                <TableCell>
                  <Tooltip
                    title={
                      member.layer === "declared"
                        ? "Declared by the deployment: change it in the values."
                        : "Added in this console."
                    }
                  >
                    <Chip
                      size="small"
                      variant="outlined"
                      color={member.layer === "declared" ? "secondary" : "default"}
                      label={member.layer}
                    />
                  </Tooltip>
                </TableCell>
                <TableCell align="right">
                  <span>
                    <Button
                      size="small"
                      color="warning"
                      disabled={!operator || member.layer === "declared"}
                      onClick={() => onDetach(member.address)}
                    >
                      Remove
                    </Button>
                  </span>
                </TableCell>
              </TableRow>
            ))}
            {group.members.length === 0 ? (
              <TableRow>
                <TableCell colSpan={3}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 1.5 }}>
                    Nobody is in this group{group.matchers.length ? " by membership" : ""}, so it grants
                    nothing yet.
                  </Typography>
                </TableCell>
              </TableRow>
            ) : null}
          </TableBody>
        </Table>
      </TableContainer>
    </Paper>
  );
}

/** The inline row: a picker over the groups the hub has already
 *  snapshotted, so there is nothing to mistype and nothing to cover the
 *  table behind a dialog. */
function AddMembership({
  group,
  onCancel,
  onAdded,
  onFailure,
}: {
  group: string;
  onCancel: () => void;
  onAdded: (address: string) => void;
  onFailure: (message: string) => void;
}) {
  const [chosen, setChosen] = useState("");
  const available = useAsync(() => access.listDirectoryGroups({}), []);

  const submit = async () => {
    try {
      await access.addMembership({ group, directoryGroup: chosen });
      onAdded(chosen);
    } catch (error) {
      onFailure(reason(error));
    }
  };

  return (
    <Stack direction="row" spacing={1} sx={{ px: 2, pb: 2, alignItems: "flex-start" }}>
      <TextField
        select
        size="small"
        label="Directory group"
        value={chosen}
        onChange={(e) => setChosen(e.target.value)}
        sx={{ minWidth: 360 }}
        helperText={
          available.value?.groups.length
            ? "From the hub's own snapshots."
            : "No groups snapshotted yet: connect a workspace first."
        }
      >
        {(available.value?.groups ?? []).map((g) => (
          <MenuItem key={g.email} value={g.email}>
            {g.email} · {g.members} members
          </MenuItem>
        ))}
      </TextField>
      <Button variant="contained" disabled={!chosen} onClick={() => void submit()} sx={{ mt: 0.25 }}>
        Add
      </Button>
      <Button onClick={onCancel} sx={{ mt: 0.25 }}>
        Cancel
      </Button>
    </Stack>
  );
}
