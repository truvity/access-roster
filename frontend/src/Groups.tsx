import { useState } from "react";
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

import { access, adds, forHowLong, people as peopleCount, personName, reason } from "./api";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Failure, Loading, Nothing, Ref, Section, Summary } from "./ui";

/** The vocabulary of access, as a list to browse and audit. */
export function Groups() {
  const policy = useAsync(() => access.getPolicy({}), []);
  const groups = policy.value?.groups ?? [];
  const clients = policy.value?.clients ?? [];

  return (
    <Box>
      <Typography variant="h6">Internal groups</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        The vocabulary of access. A person or a machine is in one by membership or by a matcher, and
        everything downstream speaks these names.
      </Typography>

      <Loading busy={policy.loading} />
      <Failure error={policy.error} />

      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Group</TableCell>
              <TableCell>In it by</TableCell>
              <TableCell>Adds</TableCell>
              <TableCell>Token</TableCell>
              <TableCell>Opens</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {groups.map((group) => {
              const opens = clients.filter((client) => client.requires.includes(group.name));
              return (
                <TableRow key={group.name} hover>
                  <TableCell>
                    <Ref to={paths.group(group.name)} mono>
                      {group.name}
                    </Ref>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary">
                      {group.members.length ? `${group.members.length} directory groups` : ""}
                      {group.members.length && group.matchers.length ? ", " : ""}
                      {group.matchers.length ? `${group.matchers.length} matchers` : ""}
                      {!group.members.length && !group.matchers.length ? "nobody yet" : ""}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary" noWrap sx={{ maxWidth: 300 }}>
                      {adds(group.claims as Record<string, unknown> | undefined).replace(/^adds /, "")}
                    </Typography>
                  </TableCell>
                  <TableCell>{forHowLong(group.lifetime)}</TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                      {opens.map((client) => (
                        <Ref key={client.id} to={paths.client(client.id)}>
                          <Chip size="small" variant="outlined" label={client.id} clickable />
                        </Ref>
                      ))}
                      {opens.length === 0 ? (
                        <Typography variant="body2" color="text.secondary">
                          no client
                        </Typography>
                      ) : null}
                    </Stack>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

/** One internal group: who is in it, what it adds, and what it opens.
 *  The pivot of the whole model, so both directions are on the page. */
export function Group({
  name,
  operator,
  onDone,
}: {
  name: string;
  operator: boolean;
  onDone: (message: string) => void;
}) {
  const policy = useAsync(() => access.getPolicy({}), []);
  const holders = useAsync(() => access.listHolders({ group: name }), [name]);
  const [adding, setAdding] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();

  const group = (policy.value?.groups ?? []).find((g) => g.name === name);
  const opens = (policy.value?.clients ?? []).filter((client) => client.requires.includes(name));

  const detach = async (address: string) => {
    setFailure(undefined);
    try {
      await access.removeMembership({ group: name, directoryGroup: address });
      onDone(`${address} removed from ${name}.`);
      policy.reload();
      holders.reload();
    } catch (error) {
      setFailure(reason(error));
    }
  };

  if (!group) {
    return (
      <Box>
        <Loading busy={policy.loading} />
        <Failure error={policy.error} />
        {!policy.loading ? <Nothing>No internal group with that name is declared.</Nothing> : null}
      </Box>
    );
  }

  const people = holders.value?.holders ?? [];

  return (
    <Box>
      <Summary
        title={<span style={{ fontFamily: "monospace" }}>{group.name}</span>}
        subtitle={`It ${adds(group.claims as Record<string, unknown> | undefined)}.`}
        chips={
          <>
            <Chip size="small" variant="outlined" label={`token ${forHowLong(group.lifetime)}`} />
            <Chip size="small" variant="outlined" label={peopleCount(people.length)} />
            {group.matchers.map((matcher) => (
              <Chip key={matcher} size="small" variant="outlined" color="secondary" label={matcher} />
            ))}
          </>
        }
      />

      <Loading busy={policy.loading || holders.loading} />
      <Failure error={failure ?? policy.error ?? holders.error} />

      <Section title="What it adds to a token" hint="merged with every other group the person is in">
        <Paper variant="outlined" sx={{ p: 2 }}>
          {group.claims ? (
            <Stack spacing={1}>
              {Array.isArray((group.claims as Record<string, unknown>).groups) ? (
                <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5, alignItems: "center" }}>
                  <Typography variant="body2" color="text.secondary" sx={{ mr: 1 }}>
                    groups claim
                  </Typography>
                  {((group.claims as Record<string, unknown>).groups as string[]).map((value) => (
                    <Chip key={value} size="small" variant="outlined" label={value} />
                  ))}
                </Stack>
              ) : null}
              {Object.keys(group.claims as Record<string, unknown>).some((key) => key !== "groups") ? (
                <Box component="pre" sx={{ m: 0, fontSize: 13, fontFamily: "monospace" }}>
                  {JSON.stringify(
                    Object.fromEntries(
                      Object.entries(group.claims as Record<string, unknown>).filter(([key]) => key !== "groups"),
                    ),
                    null,
                    2,
                  )}
                </Box>
              ) : null}
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">
              Only its own name, which relying parties read from the groups claim.
            </Typography>
          )}
        </Paper>
      </Section>

      <Section
        title="Directory groups in it"
        hint="the one thing this console changes"
        action={
          <Button size="small" variant="contained" disabled={!operator || adding} onClick={() => setAdding(true)}>
            Attach a directory group
          </Button>
        }
      >
        {adding ? (
          <Attach
            group={group.name}
            onCancel={() => setAdding(false)}
            onAdded={(address) => {
              setAdding(false);
              onDone(`${address} added to ${group.name}.`);
              policy.reload();
              holders.reload();
            }}
            onFailure={setFailure}
          />
        ) : null}
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableBody>
              {group.members.map((member) => (
                <TableRow key={member.address} hover>
                  <TableCell>{member.address}</TableCell>
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
                        onClick={() => void detach(member.address)}
                      >
                        Remove
                      </Button>
                    </span>
                  </TableCell>
                </TableRow>
              ))}
              {group.members.length === 0 ? (
                <TableRow>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                      No directory group is attached
                      {group.matchers.length ? ", so only the matchers above put anyone in it." : " yet."}
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>
        </TableContainer>
      </Section>

      <Section title="Clients it opens" hint="what being in this group buys">
        {opens.length === 0 ? (
          <Nothing>No client requires this group, so it only adds claims to a token.</Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableBody>
                {opens.map((client) => (
                  <TableRow key={client.id} hover>
                    <TableCell>
                      <Ref to={paths.client(client.id)} mono>
                        {client.id}
                      </Ref>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {client.kind}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">{client.ttlCap ? forHowLong(client.ttlCap) : "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Section>

      <Section
        title="Who is in it now"
        hint={`resolved against ${holders.value?.examined ?? 0} accounts in the snapshots`}
      >
        {people.length === 0 ? (
          <Nothing>Nobody. Attaching a directory group above is what changes that.</Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Person</TableCell>
                  <TableCell>Because of</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {people.map((holder) => (
                  <TableRow key={holder.email} hover>
                    <TableCell>
                      <Ref to={paths.person(holder.email)}>
                        {personName(holder.givenName, holder.familyName, holder.email)}
                      </Ref>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                        {holder.email}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                        {holder.via.map((why) => (
                          <Chip key={why} size="small" variant="outlined" label={why} />
                        ))}
                        {!holder.live ? <Chip size="small" color="warning" label="suspended" /> : null}
                        {!holder.authoritative ? <Chip size="small" color="warning" variant="outlined" label="hold" /> : null}
                      </Stack>
                    </TableCell>
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

/** The inline row: a picker over the groups the hub has already
 *  snapshotted, so there is nothing to mistype. */
function Attach({
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
  const picked = (available.value?.groups ?? []).find((g) => g.email === chosen);

  const submit = async () => {
    try {
      await access.addMembership({ group, directoryGroup: chosen });
      onAdded(chosen);
    } catch (error) {
      onFailure(reason(error));
    }
  };

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 1 }}>
      <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start", flexWrap: "wrap", gap: 1 }}>
        <TextField
          select
          size="small"
          label="Directory group"
          value={chosen}
          onChange={(e) => setChosen(e.target.value)}
          sx={{ minWidth: 360 }}
          helperText={
            picked
              ? `Adds ${picked.members} people to ${group}.`
              : available.value?.groups.length
                ? "From the hub's own snapshots."
                : "No groups snapshotted yet: connect a tenant first."
          }
        >
          {(available.value?.groups ?? []).map((g) => (
            <MenuItem key={g.email} value={g.email}>
              {g.email} · {g.members} members
            </MenuItem>
          ))}
        </TextField>
        <Button variant="contained" disabled={!chosen} onClick={() => void submit()} sx={{ mt: 0.25 }}>
          Attach
        </Button>
        <Button onClick={onCancel} sx={{ mt: 0.25 }}>
          Cancel
        </Button>
      </Stack>
    </Paper>
  );
}
