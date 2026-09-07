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

import { access, adds, forHowLong, people as peopleCount, personName, reason } from "./api";
import { Attach } from "./attach";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Failure, Loading, Nothing, Ref, Section, Summary } from "./ui";

/** The access-side groups: the vocabulary everything downstream speaks. */
export function Groups() {
  const policy = useAsync(() => access.getPolicy({}), []);
  const groups = policy.value?.groups ?? [];
  const clients = policy.value?.clients ?? [];

  return (
    <Box>
      <Typography variant="h6">Internal groups</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        The vocabulary of access. A person is in one through a directory group, a machine through a
        matcher, and every client and every claim speaks these names. They are declared by the deployment;
        who is in them is what this console edits.
      </Typography>

      <Loading busy={policy.loading} />
      <Failure error={policy.error} />

      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Internal group</TableCell>
              <TableCell>Fed by</TableCell>
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
                    <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                      {group.members.map((member) => (
                        <Ref key={member.address} to={paths.directoryGroup(member.address)}>
                          <Chip size="small" variant="outlined" label={member.address} clickable />
                        </Ref>
                      ))}
                      {group.matchers.map((matcher) => (
                        <Chip key={matcher} size="small" variant="outlined" color="secondary" label={matcher} />
                      ))}
                      {!group.members.length && !group.matchers.length ? (
                        <Typography variant="body2" color="text.secondary">
                          nobody yet
                        </Typography>
                      ) : null}
                    </Stack>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary" noWrap sx={{ maxWidth: 260 }}>
                      {adds(group.claims as Record<string, unknown> | undefined).replace(/^adds /, "")}
                    </Typography>
                  </TableCell>
                  <TableCell>{forHowLong(group.lifetime)}</TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                      {opens.map((client) => (
                        <Ref key={client.id} to={paths.client(client.id)}>
                          <Chip size="small" variant="outlined" color="primary" label={client.id} clickable />
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

/** One internal group, read along the chain: the directory groups that
 *  feed it, the people that puts in it right now, what it adds to a
 *  token, and the clients it opens. The mirror of a directory group's
 *  page. */
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
  const claims = group.claims as Record<string, unknown> | undefined;

  return (
    <Box>
      <Summary
        title={<span style={{ fontFamily: "monospace" }}>{group.name}</span>}
        subtitle={`${peopleCount(people.length)} in it · fed by ${group.members.length} directory ${group.members.length === 1 ? "group" : "groups"}${group.matchers.length ? ` and ${group.matchers.length} ${group.matchers.length === 1 ? "matcher" : "matchers"}` : ""} · opens ${opens.length} ${opens.length === 1 ? "client" : "clients"}`}
        chips={
          <>
            <Chip size="small" variant="outlined" label={`token ${forHowLong(group.lifetime)}`} />
            <Chip size="small" variant="outlined" label={adds(claims)} />
          </>
        }
      />

      <Loading busy={policy.loading || holders.loading} />
      <Failure error={failure ?? policy.error ?? holders.error} />

      <Section
        title="Directory groups that feed it"
        hint="the memberships table: the one thing this console changes"
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
            onAdded={(_, address) => {
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
                  <TableCell>
                    <Ref to={paths.directoryGroup(member.address)} mono>
                      {member.address}
                    </Ref>
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
                        onClick={() => void detach(member.address)}
                      >
                        Remove
                      </Button>
                    </span>
                  </TableCell>
                </TableRow>
              ))}
              {group.matchers.map((matcher) => (
                <TableRow key={matcher} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                      {matcher}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Tooltip title="A matcher admits a proof by its shape rather than by a directory: a CI job, a workload, or a verified sign-in. Declared only.">
                      <Chip size="small" variant="outlined" color="secondary" label="matcher" />
                    </Tooltip>
                  </TableCell>
                  <TableCell />
                </TableRow>
              ))}
              {group.members.length === 0 && group.matchers.length === 0 ? (
                <TableRow>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                      Nothing feeds it yet, so nobody is in it.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>
        </TableContainer>
      </Section>

      <Section
        title="People in it now"
        hint={`the directory groups above, resolved against ${holders.value?.examined ?? 0} accounts in the snapshots`}
      >
        {people.length === 0 ? (
          <Nothing>
            Nobody.{" "}
            {group.matchers.length
              ? "Only machines can be in it, through the matchers above."
              : "Attaching a directory group above is what changes that."}
          </Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Person</TableCell>
                  <TableCell>Through</TableCell>
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
                          <Ref key={why} to={paths.directoryGroup(why)}>
                            <Chip size="small" variant="outlined" label={why} clickable />
                          </Ref>
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

      <Section title="What it adds to a token" hint="merged with every other group the identity is in; the shortest lifetime wins">
        <Paper variant="outlined" sx={{ p: 2 }}>
          {claims ? (
            <Stack spacing={1}>
              {Array.isArray(claims.groups) ? (
                <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5, alignItems: "center" }}>
                  <Typography variant="body2" color="text.secondary" sx={{ mr: 1 }}>
                    groups claim
                  </Typography>
                  {(claims.groups as string[]).map((value) => (
                    <Chip key={value} size="small" variant="outlined" label={value} />
                  ))}
                </Stack>
              ) : null}
              {Object.keys(claims).some((key) => key !== "groups") ? (
                <Box component="pre" sx={{ m: 0, fontSize: 13, fontFamily: "monospace" }}>
                  {JSON.stringify(
                    Object.fromEntries(Object.entries(claims).filter(([key]) => key !== "groups")),
                    null,
                    2,
                  )}
                </Box>
              ) : null}
              <Typography variant="body2" color="text.secondary">
                Tokens live {forHowLong(group.lifetime)} through this group, unless another group or the client
                says shorter.
              </Typography>
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">
              Only its own name, which relying parties read from the groups claim. Tokens live{" "}
              {forHowLong(group.lifetime)} through it.
            </Typography>
          )}
        </Paper>
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
                    <TableCell align="right">{client.ttlCap ? `capped at ${forHowLong(client.ttlCap)}` : ""}</TableCell>
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
