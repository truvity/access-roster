import { useState } from "react";
import Alert from "@mui/material/Alert";
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

import { access, ago, at, forHowLong, people as peopleCount, personName, reason } from "./api";
import { Attach } from "./attach";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Authority, Failure, Loading, Nothing, Ref, Section, Summary } from "./ui";

/** The identity-side groups: what the directories say exists. The list
 *  answers which of them the policy uses at all, which is the first thing
 *  a reviewer wants to know. */
export function DirectoryGroups() {
  const groups = useAsync(() => access.listDirectoryGroups({}), []);
  const policy = useAsync(() => access.getPolicy({}), []);

  const feeds = new Map<string, string[]>();
  for (const group of policy.value?.groups ?? []) {
    for (const member of group.members) {
      feeds.set(member.address, [...(feeds.get(member.address) ?? []), group.name]);
    }
  }
  const rows = groups.value?.groups ?? [];

  return (
    <Box>
      <Typography variant="h6">Directory groups</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Every group in every connected directory, as the last snapshot has it. A directory group grants
        nothing by itself: it does so by being attached to an internal group, and that attachment is the
        one thing this console edits.
      </Typography>

      <Loading busy={groups.loading || policy.loading} />
      <Failure error={groups.error ?? policy.error} />

      {!groups.loading && rows.length === 0 ? (
        <Nothing>No directory groups snapshotted yet: add a directory first.</Nothing>
      ) : (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Directory group</TableCell>
                <TableCell>Directory</TableCell>
                <TableCell align="right">Members</TableCell>
                <TableCell>Feeds</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((group) => {
                const into = feeds.get(group.email) ?? [];
                return (
                  <TableRow key={group.email} hover>
                    <TableCell>
                      <Ref to={paths.directoryGroup(group.email)} mono>
                        {group.email}
                      </Ref>
                    </TableCell>
                    <TableCell>
                      <Ref to={paths.directory(group.workspaceId)} mono>
                        {group.workspaceId}
                      </Ref>
                    </TableCell>
                    <TableCell align="right">{group.members}</TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                        {into.map((name) => (
                          <Ref key={name} to={paths.group(name)}>
                            <Chip size="small" variant="outlined" color="primary" label={name} clickable />
                          </Ref>
                        ))}
                        {into.length === 0 ? (
                          <Typography variant="body2" color="text.secondary">
                            nothing
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
      )}
    </Box>
  );
}

/** One directory group, read along the chain: who the directory says is
 *  in it, the internal groups it feeds, and the clients that therefore
 *  open. It is the mirror of an internal group's page, and the attach
 *  action lives on both, because the membership joins the two. */
export function DirectoryGroup({
  email,
  operator,
  onDone,
}: {
  email: string;
  operator: boolean;
  onDone: (message: string) => void;
}) {
  const group = useAsync(() => access.getDirectoryGroup({ email }), [email]);
  const policy = useAsync(() => access.getPolicy({}), []);
  const [adding, setAdding] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();

  const value = group.value;
  const feeds = value?.feeds ?? [];
  const clients = (policy.value?.clients ?? []).filter((client) =>
    client.requires.some((name) => feeds.some((feed) => feed.group === name)),
  );

  const detach = async (name: string) => {
    setFailure(undefined);
    try {
      await access.removeMembership({ group: name, directoryGroup: email });
      onDone(`${email} removed from ${name}.`);
      group.reload();
    } catch (error) {
      setFailure(reason(error));
    }
  };

  if (!value) {
    return (
      <Box>
        <Loading busy={group.loading} />
        <Failure error={group.error} />
      </Box>
    );
  }

  const served = Boolean(value.workspaceId);
  const members = value.members;
  const live = members.filter((m) => m.known && m.live).length;

  return (
    <Box>
      <Summary
        title={<span style={{ fontFamily: "monospace" }}>{value.email}</span>}
        subtitle={
          served
            ? `${peopleCount(members.length)} in it · feeds ${feeds.length} internal ${feeds.length === 1 ? "group" : "groups"} · opens ${clients.length} ${clients.length === 1 ? "client" : "clients"}`
            : "No connected directory serves this domain, so the hub has no opinion about it."
        }
        chips={
          served ? (
            <>
              <Ref to={paths.directory(value.workspaceId)}>
                <Chip size="small" variant="outlined" label={`from ${value.workspaceId}`} clickable />
              </Ref>
              <Authority authoritative={value.authoritative} />
              <Chip size="small" variant="outlined" label={`snapshot ${ago(at(value.snapshotAt))}`} />
            </>
          ) : null
        }
      />

      <Loading busy={group.loading || policy.loading} />
      <Failure error={failure ?? policy.error} />

      {served && !value.found ? (
        <Alert severity="warning" sx={{ mb: 2 }}>
          The directory does not have a group by this address. If the policy names it, the membership grants
          nothing until the group exists.
        </Alert>
      ) : null}

      <Section
        title="Members, as the directory reports them"
        hint={`what the directory says, before the policy: ${live} of ${members.length} live`}
      >
        {members.length === 0 ? (
          <Nothing>The directory reports nobody in it.</Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableBody>
                {members.map((member) => (
                  <TableRow key={member.email} hover>
                    <TableCell>
                      {member.known ? (
                        <Ref to={paths.person(member.email)}>
                          {personName(member.givenName, member.familyName, member.email)}
                        </Ref>
                      ) : (
                        <Typography variant="body2">{member.email}</Typography>
                      )}
                      {member.known ? (
                        <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                          {member.email}
                        </Typography>
                      ) : null}
                    </TableCell>
                    <TableCell align="right">
                      {!member.known ? (
                        <Tooltip title="No connected directory has this account, so the hub cannot say whether it is live.">
                          <Chip size="small" variant="outlined" label="not read by the hub" />
                        </Tooltip>
                      ) : member.live ? (
                        <Chip size="small" color="success" variant="outlined" label="live" />
                      ) : (
                        <Chip size="small" color="warning" label="suspended" />
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Section>

      <Section
        title="Internal groups it feeds"
        hint="the memberships table, read backwards"
        action={
          <Button size="small" variant="contained" disabled={!operator || adding} onClick={() => setAdding(true)}>
            Attach to an internal group
          </Button>
        }
      >
        {adding ? (
          <Attach
            directoryGroup={value.email}
            onCancel={() => setAdding(false)}
            onAdded={(name) => {
              setAdding(false);
              onDone(`${value.email} added to ${name}.`);
              group.reload();
            }}
            onFailure={setFailure}
          />
        ) : null}
        {feeds.length === 0 ? (
          <Nothing>None. Attaching it to an internal group is what makes its members reach anything.</Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableBody>
                {feeds.map((feed) => (
                  <TableRow key={feed.group} hover>
                    <TableCell>
                      <Ref to={paths.group(feed.group)} mono>
                        {feed.group}
                      </Ref>
                    </TableCell>
                    <TableCell>
                      <Tooltip
                        title={
                          feed.layer === "declared"
                            ? "Declared by the deployment: change it in the values."
                            : "Added in this console."
                        }
                      >
                        <Chip
                          size="small"
                          variant="outlined"
                          color={feed.layer === "declared" ? "secondary" : "default"}
                          label={feed.layer}
                        />
                      </Tooltip>
                    </TableCell>
                    <TableCell align="right">
                      <span>
                        <Button
                          size="small"
                          color="warning"
                          disabled={!operator || feed.layer === "declared"}
                          onClick={() => void detach(feed.group)}
                        >
                          Remove
                        </Button>
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Section>

      <Section title="Clients that open through it" hint="what its members can be issued a token for">
        {clients.length === 0 ? (
          <Nothing>None yet: none of the internal groups above is required by a client.</Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableBody>
                {clients.map((client) => (
                  <TableRow key={client.id} hover>
                    <TableCell>
                      <Ref to={paths.client(client.id)} mono>
                        {client.id}
                      </Ref>
                    </TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                        {client.requires
                          .filter((name) => feeds.some((feed) => feed.group === name))
                          .map((name) => (
                            <Ref key={name} to={paths.group(name)}>
                              <Chip size="small" variant="outlined" color="primary" label={name} clickable />
                            </Ref>
                          ))}
                      </Stack>
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
