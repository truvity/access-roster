import Box from "@mui/material/Box";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Typography from "@mui/material/Typography";

import { access, forHowLong, matcherKind, people as peopleCount, personName } from "./api";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Failure, Loading, Mono, Names, Nothing, Page, Ref, Rows, Section, State } from "./ui";

/** What the internal groups buy: the relying parties a token can be
 *  issued for. */
export function Clients() {
  const policy = useAsync(() => access.getPolicy({}), []);
  const clients = policy.value?.clients ?? [];

  return (
    <Page
      title="Clients"
      lede="A client's id is the audience of the tokens issued for it, and its requirements are who may be issued one. Clients are declared by the deployment or registered by the workload itself, never created here."
    >
      <Loading busy={policy.loading} />
      <Failure error={policy.error} />

      {clients.length === 0 ? (
        <Nothing>No clients are declared. The hub itself needs none; they arrive with the issuer.</Nothing>
      ) : (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Client</TableCell>
                <TableCell>Kind</TableCell>
                <TableCell>Opened by any of</TableCell>
                <TableCell>Token cap</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {clients.map((client) => (
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
                  <TableCell>
                    <Names items={client.requires.map((group) => ({ label: group, to: paths.group(group), mono: true }))} empty="nobody" />
                  </TableCell>
                  <TableCell>{client.ttlCap ? forHowLong(client.ttlCap) : "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Page>
  );
}

/** One client: who may reach it, and who does — people through their
 *  directory groups, machines through the rules that admit them. */
export function Client({ id }: { id: string }) {
  const policy = useAsync(() => access.getPolicy({}), []);
  const holders = useAsync(() => access.listHolders({ client: id }), [id]);

  const client = (policy.value?.clients ?? []).find((c) => c.id === id);
  const people = holders.value?.holders ?? [];
  const machines = (policy.value?.groups ?? [])
    .filter((g) => client?.requires.includes(g.name))
    .flatMap((g) => g.rules.map((rule) => ({ key: `${g.name}:${rule.rule}`, kind: rule.kind, rule: rule.rule, group: g.name })));

  if (!client) {
    return (
      <Box>
        <Loading busy={policy.loading} />
        <Failure error={policy.error} />
        {!policy.loading ? <Nothing>No client with that id is declared.</Nothing> : null}
      </Box>
    );
  }

  const rules = `${machines.length} ${machines.length === 1 ? "rule" : "rules"}`;

  return (
    <Page
      title={client.id}
      mono
      lede={`Opened by ${client.requires.length} internal ${client.requires.length === 1 ? "group" : "groups"}; reached right now by ${peopleCount(people.length)} and ${rules}.`}
      facts={[
        { label: "Kind", value: client.kind },
        { label: "Token cap", value: client.ttlCap ? forHowLong(client.ttlCap) : "none" },
        { label: "Secret, as a Kubernetes Secret name", value: client.secret ? <Mono>{client.secret}</Mono> : undefined },
      ]}
      aside={
        <>
      {client.redirects.length ? (
        <Section title="Redirects">
          <Rows items={client.redirects} keyOf={(uri) => uri} primary={(uri) => <Box sx={{ wordBreak: "break-all" }}><Mono>{uri}</Mono></Box>} empty="" />
        </Section>
      ) : null}
        </>
      }
    >
      <Loading busy={policy.loading || holders.loading} />
      <Failure error={policy.error ?? holders.error} />

      <Section title="Internal groups that open it" hint="being in any one of them is enough">
        <Rows
          items={client.requires}
          keyOf={(group) => group}
          primary={(group) => (
            <Ref to={paths.group(group)} mono>
              {group}
            </Ref>
          )}
          empty="It requires no group, so nobody is admitted."
        />
      </Section>

      <Section title="People who reach it now" hint={`resolved against ${holders.value?.examined ?? 0} accounts in the snapshots`}>
        <Rows
          items={people}
          keyOf={(h) => h.email}
          primary={(h) => <Ref to={paths.person(h.email)}>{personName(h.givenName, h.familyName, h.email)}</Ref>}
          secondary={(h) => (
            <>
              {h.email} · through <Names items={h.via.map((group) => ({ label: group, to: paths.group(group), mono: true }))} muted />
            </>
          )}
          right={(h) => (
            <>
              {!h.live ? <State kind="suspended" /> : null}
              <span>token {forHowLong(h.lifetime)}</span>
            </>
          )}
          empty="Nobody. Attach a directory group to one of the internal groups above, and the people in it reach this client."
        />
      </Section>

      <Section title="Machines that reach it" hint="the rules that admit a proof into one of the groups above">
        <Rows
          items={machines}
          keyOf={(m) => m.key}
          primary={(m) => (
            <>
              {matcherKind(m.kind)} <Mono>{m.rule}</Mono>
            </>
          )}
          secondary={(m) => (
            <>
              through{" "}
              <Ref to={paths.group(m.group)} mono>
                {m.group}
              </Ref>
            </>
          )}
          right={() => <State kind="declared" />}
          empty="No rule admits a machine into any of the groups above."
        />
      </Section>
    </Page>
  );
}
