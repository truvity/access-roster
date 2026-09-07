import { useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";

import { access, ago, at, forHowLong, people as peopleCount, personName, reason } from "./api";
import { Attach } from "./attach";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Authority, Failure, Loading, Mono, Names, Nothing, Page, Ref, Rows, Section, State } from "./ui";

/** The identity-side groups: what the directories say exists, and which
 *  of it the policy uses. */
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
    <Page
      title="Directory groups"
      lede="Every group in every connected directory, as the last snapshot has it. A directory group grants nothing by itself: it does so by being attached to an internal group, and that attachment is the one thing this console edits."
    >
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
              {rows.map((group) => (
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
                    <Names items={(feeds.get(group.email) ?? []).map((name) => ({ label: name, to: paths.group(name), mono: true }))} empty="nothing" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Page>
  );
}

/** One directory group, read along the chain: who the directory says is
 *  in it, the internal groups it feeds, and the clients that therefore
 *  open. The mirror of an internal group's page. */
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
  const clients = (policy.value?.clients ?? []).filter((client) => client.requires.some((name) => feeds.some((feed) => feed.group === name)));

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
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

  return (
    <Page
      title={value.email}
      mono
      lede={
        served
          ? `${peopleCount(members.length)} in it, feeding ${plural(feeds.length, "internal group", "internal groups")} and opening ${plural(clients.length, "client", "clients")}.`
          : "No connected directory serves this domain, so the hub has no opinion about it."
      }
      facts={
        served
          ? [
              {
                label: "Directory",
                value: (
                  <Ref to={paths.directory(value.workspaceId)} mono>
                    {value.workspaceId}
                  </Ref>
                ),
              },
              { label: "Answer", value: <Authority authoritative={value.authoritative} /> },
              { label: "Snapshot", value: ago(at(value.snapshotAt)) },
            ]
          : []
      }
    >
      <Loading busy={group.loading || policy.loading} />
      <Failure error={failure ?? policy.error} />

      {served && !value.found ? (
        <Alert severity="warning" sx={{ mb: 3 }}>
          The directory does not have a group by this address. If the policy names it, the membership grants nothing until the group exists.
        </Alert>
      ) : null}

      <Section title="Members" hint={`as the directory reports them, before the policy: ${live} of ${members.length} live`}>
        <Rows
          items={members}
          keyOf={(m) => m.email}
          primary={(m) =>
            m.known ? (
              <Ref to={paths.person(m.email)}>{personName(m.givenName, m.familyName, m.email)}</Ref>
            ) : (
              <Mono>{m.email}</Mono>
            )
          }
          secondary={(m) => (m.known ? m.email : undefined)}
          right={(m) => <State kind={!m.known ? "unknown" : m.live ? "live" : "suspended"} />}
          empty="The directory reports nobody in it."
        />
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
        <Rows
          items={feeds}
          keyOf={(feed) => feed.group}
          primary={(feed) => (
            <Ref to={paths.group(feed.group)} mono>
              {feed.group}
            </Ref>
          )}
          right={(feed) => (
            <>
              <State kind={feed.layer === "declared" ? "declared" : "console"} />
              <Button size="small" color="warning" disabled={!operator || feed.layer === "declared"} onClick={() => void detach(feed.group)}>
                Remove
              </Button>
            </>
          )}
          empty="None. Attaching it to an internal group is what makes its members reach anything."
        />
      </Section>

      <Section title="Clients that open through it" hint="what its members can be issued a token for">
        <Rows
          items={clients}
          keyOf={(client) => client.id}
          primary={(client) => (
            <Ref to={paths.client(client.id)} mono>
              {client.id}
            </Ref>
          )}
          secondary={(client) => (
            <>
              through{" "}
              <Names
                items={client.requires.filter((name) => feeds.some((feed) => feed.group === name)).map((name) => ({ label: name, to: paths.group(name), mono: true }))}
                muted
              />
            </>
          )}
          right={(client) => (client.ttlCap ? <span>capped at {forHowLong(client.ttlCap)}</span> : null)}
          empty="None yet: none of the internal groups above is required by a client."
        />
      </Section>
    </Page>
  );
}
