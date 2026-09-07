import { useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Card from "@mui/material/Card";
import CardContent from "@mui/material/CardContent";
import Chip from "@mui/material/Chip";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";
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

import { Role, access, reason, roleName, whoami } from "./api";
import type { AccessRule } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { Failure, Loading } from "./ui";

export function AccessView({ operator, onDone }: { operator: boolean; onDone: (message: string) => void }) {
  const policy = useAsync(() => access.getAccessPolicy({}), []);
  const me = useAsync(whoami, []);
  const [failure, setFailure] = useState<string | undefined>();
  const [adding, setAdding] = useState(false);

  const rules = policy.value?.rules ?? [];

  const remove = async (id: string) => {
    setFailure(undefined);
    try {
      await access.removeRule({ id });
      onDone(`Rule ${id} removed.`);
      policy.reload();
    } catch (error) {
      setFailure(reason(error));
    }
  };

  return (
    <Box>
      <Typography variant="h6">Access</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Who may use this console. Rules are evaluated in order and nothing is granted by default.
      </Typography>

      {policy.value?.adminEnabled ? (
        <Alert severity="warning" sx={{ mb: 2 }}>
          The break-glass admin account is enabled. Turn it off in the deployment once a rule below grants
          operator to a real identity.
        </Alert>
      ) : null}

      <Card variant="outlined" sx={{ mb: 2 }}>
        <CardContent>
          <Typography variant="subtitle2" gutterBottom>
            You
          </Typography>
          {me.value?.status === "signed-in" ? (
            <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
              <Typography variant="body2">{me.value.email}</Typography>
              <Chip size="small" label={`via ${me.value.source}`} variant="outlined" />
              {(me.value.roles ?? []).map((role) => (
                <Chip key={role} size="small" color="primary" label={role} />
              ))}
              {(me.value.matchedRules ?? []).map((rule) => (
                <Chip key={rule} size="small" variant="outlined" label={`granted by ${rule}`} />
              ))}
              {me.value.roles?.length === 0 ? <Chip size="small" color="warning" label="no access" /> : null}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">
              Not signed in.
            </Typography>
          )}
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
            Sign-in sources in this deployment: {(policy.value?.loginSources ?? ["none"]).join(", ")}
          </Typography>
        </CardContent>
      </Card>

      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", mb: 1 }}>
        <Typography variant="subtitle1">Rules</Typography>
        <Button variant="contained" size="small" disabled={!operator} onClick={() => setAdding(true)}>
          Add a rule
        </Button>
      </Stack>

      <Loading busy={policy.loading} />
      <Failure error={failure ?? policy.error} />

      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Rule</TableCell>
              <TableCell>Matches</TableCell>
              <TableCell>Grants</TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {rules.map((rule) => (
              <TableRow key={rule.id} hover>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                    {rule.id}
                  </Typography>
                  {rule.declared ? (
                    <Chip size="small" variant="outlined" color="secondary" label="declared" sx={{ mt: 0.5 }} />
                  ) : null}
                </TableCell>
                <TableCell>
                  <Typography variant="body2">{subjectOf(rule)}</Typography>
                </TableCell>
                <TableCell>
                  <Chip size="small" label={roleName(rule.role)} color={rule.role === Role.OPERATOR ? "primary" : "default"} />
                </TableCell>
                <TableCell align="right">
                  <Tooltip
                    title={rule.declared ? "Declared by the deployment: change the values instead." : "Remove this rule."}
                  >
                    <span>
                      <Button size="small" color="warning" disabled={!operator || rule.declared} onClick={() => void remove(rule.id)}>
                        Remove
                      </Button>
                    </span>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {!policy.loading && rules.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                    No rules yet, so nobody but the break-glass admin can act. Add one that grants operator to
                    a group from a connected directory.
                  </Typography>
                </TableCell>
              </TableRow>
            ) : null}
          </TableBody>
        </Table>
      </TableContainer>

      <AddRule
        open={adding}
        onClose={() => setAdding(false)}
        onAdded={(id) => {
          setAdding(false);
          onDone(`Rule ${id} added.`);
          policy.reload();
        }}
      />
    </Box>
  );
}

/** How a rule reads in one line. */
function subjectOf(rule: AccessRule): string {
  switch (rule.subject.case) {
    case "directoryGroup":
      return `members of ${rule.subject.value.group}`;
    case "claim":
      return `${rule.subject.value.claim} = ${rule.subject.value.value} from ${rule.subject.value.issuer}`;
    case "email":
      return rule.subject.value;
    case "emailDomain":
      return `anyone at ${rule.subject.value}`;
    default:
      return "—";
  }
}

type Kind = "directoryGroup" | "emailDomain" | "email";

function AddRule({
  open,
  onClose,
  onAdded,
}: {
  open: boolean;
  onClose: () => void;
  onAdded: (id: string) => void;
}) {
  const [kind, setKind] = useState<Kind>("directoryGroup");
  const [group, setGroup] = useState("");
  const [value, setValue] = useState("");
  const [role, setRole] = useState<Role>(Role.OPERATOR);
  const [id, setId] = useState("");
  const [failure, setFailure] = useState<string | undefined>();

  const groups = useAsync(() => access.listDirectoryGroups({}), [open]);

  const submit = async () => {
    setFailure(undefined);
    const subject =
      kind === "directoryGroup"
        ? ({ case: "directoryGroup" as const, value: { group } })
        : kind === "emailDomain"
          ? ({ case: "emailDomain" as const, value })
          : ({ case: "email" as const, value });
    try {
      await access.addRule({ rule: { id, role, subject } });
      onAdded(id);
    } catch (error) {
      setFailure(reason(error));
    }
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Add a rule</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Failure error={failure} />
          <TextField
            label="Rule id"
            helperText="Stable, and shown wherever this rule grants someone access."
            value={id}
            onChange={(e) => setId(e.target.value)}
            size="small"
            fullWidth
          />
          <TextField select label="Matches" value={kind} onChange={(e) => setKind(e.target.value as Kind)} size="small">
            <MenuItem value="directoryGroup">Members of a directory group</MenuItem>
            <MenuItem value="emailDomain">Anyone at an email domain</MenuItem>
            <MenuItem value="email">One address</MenuItem>
          </TextField>

          {kind === "directoryGroup" ? (
            <TextField
              select
              label="Group"
              value={group}
              onChange={(e) => setGroup(e.target.value)}
              size="small"
              helperText={
                groups.value?.groups.length
                  ? "From the hub's own snapshots, so there is nothing to mistype."
                  : "No groups snapshotted yet: connect a workspace first."
              }
            >
              {(groups.value?.groups ?? []).map((g) => (
                <MenuItem key={g.email} value={g.email}>
                  {g.email} · {g.members} members
                </MenuItem>
              ))}
            </TextField>
          ) : (
            <TextField
              label={kind === "emailDomain" ? "Domain" : "Address"}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              size="small"
            />
          )}

          <TextField select label="Grants" value={role} onChange={(e) => setRole(Number(e.target.value) as Role)} size="small">
            <MenuItem value={Role.OPERATOR}>operator — may connect, probe and change access</MenuItem>
            <MenuItem value={Role.VIEWER}>viewer — may read</MenuItem>
          </TextField>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={() => void submit()} disabled={!id || (kind === "directoryGroup" ? !group : !value)}>
          Add
        </Button>
      </DialogActions>
    </Dialog>
  );
}
