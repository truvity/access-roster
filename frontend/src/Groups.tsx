import { useState } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Typography from "@mui/material/Typography";

import { access, adds, forHowLong, matcherKind, people as peopleCount, personName, reason } from "./api";
import { Attach } from "./attach";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Failure, Loading, Mono, Names, Nothing, Page, Ref, Rows, Section, State } from "./ui";

/** The access-side groups: the vocabulary everything downstream speaks. */
export function Groups() {
  const policy = useAsync(() => access.getPolicy({}), []);
  const groups = policy.value?.groups ?? [];
  const clients = policy.value?.clients ?? [];

  return (
    <Page
      title="Groups"
      lede="The vocabulary of access. A person is in one through a group in a provider, a machine through a matcher, and every client and every claim speaks these names. They are declared by the deployment; who is in them is what this console edits."
    >
      <Loading busy={policy.loading} />
      <Failure error={policy.error} />

      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Group</TableCell>
              <TableCell>Fed by</TableCell>
              <TableCell>Adds</TableCell>
              <TableCell>Token</TableCell>
              <TableCell>Opens</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {groups.map((group) => {
              const opens = clients.filter((client) => client.requires.includes(group.name));
              const fedBy = [
                ...group.members.map((member) => ({ label: member.address, to: paths.directoryGroup(member.address), mono: true })),
                ...group.rules.map((rule) => ({ label: `${matcherKind(rule.kind)} ${rule.rule}`, mono: true })),
              ];
              return (
                <TableRow key={group.name} hover>
                  <TableCell>
                    <Ref to={paths.group(group.name)} mono>
                      {group.name}
                    </Ref>
                  </TableCell>
                  <TableCell>
                    <Names items={fedBy} empty="nobody yet" />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary" noWrap sx={{ maxWidth: 240 }}>
                      {adds(group.claims as Record<string, unknown> | undefined).replace(/^adds /, "")}
                    </Typography>
                  </TableCell>
                  <TableCell>{forHowLong(group.lifetime)}</TableCell>
                  <TableCell>
                    <Names items={opens.map((client) => ({ label: client.id, to: paths.client(client.id), mono: true }))} empty="no client" />
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
    </Page>
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
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
  type Feeder = { key: string; address?: string; matcher?: string; layer?: string };
  const feeders: Feeder[] = [
    ...group.members.map((m) => ({ key: m.address, address: m.address, layer: m.layer })),
    ...group.rules.map((r) => ({ key: `${r.kind}:${r.rule}`, matcher: `${matcherKind(r.kind)} ${r.rule}` })),
  ];

  return (
    <Page
      title={group.name}
      mono
      lede={`${peopleCount(people.length)} in it, fed by ${plural(group.members.length, "provider group", "provider groups")}${
        group.rules.length ? ` and ${plural(group.rules.length, "matcher", "matchers")}` : ""
      }, opening ${plural(opens.length, "client", "clients")}.`}
      facts={[{ label: "Token lifetime", value: forHowLong(group.lifetime) }]}
      aside={
        <>
      <Section title="What it adds to a token" hint="merged with every other group the identity is in; the shortest lifetime wins">
        <Paper variant="outlined" sx={{ p: 2 }}>
          {claims ? (
            <Stack spacing={1.5}>
              {Array.isArray(claims.groups) ? (
                <Box>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.25 }}>
                    groups claim
                  </Typography>
                  <Names items={(claims.groups as string[]).map((value) => ({ label: value, mono: true }))} />
                </Box>
              ) : null}
              {Object.keys(claims).some((key) => key !== "groups") ? (
                <Typography component="pre" variant="body2" sx={{ m: 0, fontFamily: "monospace" }}>
                  {JSON.stringify(Object.fromEntries(Object.entries(claims).filter(([key]) => key !== "groups")), null, 2)}
                </Typography>
              ) : null}
              <Typography variant="body2" color="text.secondary">
                Tokens live {forHowLong(group.lifetime)} through this group, unless another group or the client says shorter.
              </Typography>
            </Stack>
          ) : (
            <Typography variant="body2" color="text.secondary">
              Only its own name, which relying parties read from the groups claim. Tokens live {forHowLong(group.lifetime)} through it.
            </Typography>
          )}
        </Paper>
      </Section>
        </>
      }
    >
      <Loading busy={policy.loading || holders.loading} />
      <Failure error={failure ?? policy.error ?? holders.error} />

      <Section
        title="Fed by"
        hint="the memberships table: the one thing this console changes"
        action={
          <Button size="small" variant="contained" disabled={!operator || adding} onClick={() => setAdding(true)}>
            Attach a provider group
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
        <Rows
          items={feeders}
          keyOf={(f) => f.key}
          primary={(f) =>
            f.address ? (
              <Ref to={paths.directoryGroup(f.address)} mono>
                {f.address}
              </Ref>
            ) : (
              <Mono>{f.matcher}</Mono>
            )
          }
          right={(f) =>
            f.address ? (
              <>
                <State kind={f.layer === "declared" ? "declared" : "console"} />
                <Button size="small" color="warning" disabled={!operator || f.layer === "declared"} onClick={() => void detach(f.address!)}>
                  Remove
                </Button>
              </>
            ) : (
              <State kind="matcher" />
            )
          }
          empty="Nothing feeds it yet, so nobody is in it."
        />
      </Section>

      <Section title="People in it now" hint={`the provider groups above, resolved against ${holders.value?.examined ?? 0} accounts in the snapshots`}>
        <Rows
          items={people}
          keyOf={(h) => h.email}
          primary={(h) => <Ref to={paths.person(h.email)}>{personName(h.givenName, h.familyName, h.email)}</Ref>}
          secondary={(h) => (
            <>
              {h.email} · through <Names items={h.via.map((why) => ({ label: why, to: paths.directoryGroup(why), mono: true }))} muted />
            </>
          )}
          right={(h) => (
            <>
              {!h.live ? <State kind="suspended" /> : null}
              {!h.authoritative ? <State kind="provisional" /> : null}
            </>
          )}
          empty={
            group.rules.length ? "Nobody by membership. Only what the matchers above admit is in it." : "Nobody. Attaching a provider group above is what changes that."
          }
        />
      </Section>

      <Section title="Clients it opens" hint="what being in this group buys">
        <Rows
          items={opens}
          keyOf={(client) => client.id}
          primary={(client) => (
            <Ref to={paths.client(client.id)} mono>
              {client.id}
            </Ref>
          )}
          secondary={(client) => client.kind}
          right={(client) => (client.ttlCap ? <span>capped at {forHowLong(client.ttlCap)}</span> : null)}
          empty="No client requires this group, so it only adds claims to a token."
        />
      </Section>
    </Page>
  );
}
