import { useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import ToggleButton from "@mui/material/ToggleButton";
import ToggleButtonGroup from "@mui/material/ToggleButtonGroup";

import { access, ago, at, forHowLong, people as peopleCount, personName } from "./api";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Authority, Failure, Loading, Mono, Names, Nothing, Page, Ref, Rows, Section, State } from "./ui";

/** The identity-side groups: what the providers say exists, and which
 *  of it the policy uses. */
export function DirectoryGroups() {
  const groups = useAsync(() => access.listDirectoryGroups({}), []);
  const policy = useAsync(() => access.getPolicy({}), []);
  const [provider, setProvider] = useState("");
  const [domain, setDomain] = useState("");

  const feeds = new Map<string, string[]>();
  for (const group of policy.value?.groups ?? []) {
    for (const member of group.members) {
      feeds.set(member.address, [...(feeds.get(member.address) ?? []), group.name]);
    }
  }
  const all = groups.value?.groups ?? [];
  // This list is not truncated, so unlike the people page it can filter
  // where it stands.
  const rows = all.filter((group) => (!provider || group.workspaceId === provider) && (!domain || group.domain === domain));
  const providers = [...new Set(all.map((group) => group.workspaceId))].sort();
  const domains = [...new Set(all.map((group) => group.domain))].filter(Boolean).sort();

  return (
    <Page
      title="Groups"
      lede="Every group in every connected provider, as the last snapshot has it. A group here grants nothing by itself: it does so by being attached to an internal group, and that attachment is the one thing this console edits."
    >
      <Stack direction="row" spacing={2} sx={{ alignItems: "center", flexWrap: "wrap", gap: 1.5, mb: 1.5 }}>
        {providers.length > 1 ? (
          <ToggleButtonGroup size="small" exclusive value={provider} onChange={(_, next: string | null) => next !== null && setProvider(next)}>
            <ToggleButton value="">Every provider</ToggleButton>
            {providers.map((id) => (
              <ToggleButton key={id} value={id} sx={{ fontFamily: "monospace", textTransform: "none" }}>
                {id}
              </ToggleButton>
            ))}
          </ToggleButtonGroup>
        ) : null}
        {domains.length > 1 ? (
          <ToggleButtonGroup size="small" exclusive value={domain} onChange={(_, next: string | null) => next !== null && setDomain(next)}>
            <ToggleButton value="">Every domain</ToggleButton>
            {domains.map((name) => (
              <ToggleButton key={name} value={name} sx={{ fontFamily: "monospace", textTransform: "none" }}>
                {name}
              </ToggleButton>
            ))}
          </ToggleButtonGroup>
        ) : null}
      </Stack>

      <Loading busy={groups.loading || policy.loading} />
      <Failure error={groups.error ?? policy.error} />

      {!groups.loading && rows.length === 0 ? (
        <Nothing>{all.length === 0 ? "No groups snapshotted yet: add a provider first." : "No group matches the filter."}</Nothing>
      ) : (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Group</TableCell>
                <TableCell>Provider</TableCell>
                <TableCell>Domain</TableCell>
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
                  <TableCell>
                    <Mono>{group.domain}</Mono>
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

/** One provider group, read along the chain: who the provider says is in
 *  it, the internal groups it feeds, and the clients that therefore
 *  open. The mirror of an internal group's page. */
export function DirectoryGroup({ email }: { email: string }) {
  const group = useAsync(() => access.getDirectoryGroup({ email }), [email]);
  const policy = useAsync(() => access.getPolicy({}), []);

  const value = group.value;
  const feeds = value?.feeds ?? [];
  const clients = (policy.value?.clients ?? []).filter((client) => client.requires.some((name) => feeds.some((feed) => feed.group === name)));

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
          : "No connected provider serves this domain, so the hub has no opinion about it."
      }
      facts={
        served
          ? [
              {
                label: "Provider",
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
      aside={null}
    >
      <Loading busy={group.loading || policy.loading} />
      <Failure error={policy.error} />

      {served && !value.found ? (
        <Alert severity="warning" sx={{ mb: 3 }}>
          The provider does not have a group by this address. If the policy names it, the membership grants nothing until the group exists.
        </Alert>
      ) : null}

      <Section title="Members" hint={`as the provider reports them, before the policy: ${live} of ${members.length} live`}>
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
          empty="The provider reports nobody in it."
        />
      </Section>

      <Section title="Internal groups it feeds" hint="the policy, read backwards">
        <Rows
          items={feeds}
          keyOf={(feed) => feed.group}
          primary={(feed) => (
            <Ref to={paths.group(feed.group)} mono>
              {feed.group}
            </Ref>
          )}
          right={() => <State kind="declared" />}
          empty="None. Naming it in an internal group, in the policy, is what makes its members reach anything."
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
