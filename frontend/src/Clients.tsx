import Box from "@mui/material/Box";
import Chip from "@mui/material/Chip";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Typography from "@mui/material/Typography";

import { access, forHowLong, people as peopleCount, personName } from "./api";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Failure, Loading, Nothing, Ref, Section, Summary } from "./ui";

/** What the groups buy: the relying parties a token can be issued for. */
export function Clients() {
  const policy = useAsync(() => access.getPolicy({}), []);
  const clients = policy.value?.clients ?? [];

  return (
    <Box>
      <Typography variant="h6">Clients</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        A client's id is the audience of the tokens issued for it, and its requirements are who may be issued
        one. Clients are declared by the deployment or registered by the workload itself, never created here.
      </Typography>

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
                <TableCell>Requires any of</TableCell>
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
                    <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                      {client.requires.map((group) => (
                        <Ref key={group} to={paths.group(group)}>
                          <Chip size="small" variant="outlined" label={group} clickable />
                        </Ref>
                      ))}
                    </Stack>
                  </TableCell>
                  <TableCell>{client.ttlCap ? forHowLong(client.ttlCap) : "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}

/** One client: who may reach it, and who does. */
export function Client({ id }: { id: string }) {
  const policy = useAsync(() => access.getPolicy({}), []);
  const holders = useAsync(() => access.listHolders({ client: id }), [id]);

  const client = (policy.value?.clients ?? []).find((c) => c.id === id);
  const people = holders.value?.holders ?? [];

  if (!client) {
    return (
      <Box>
        <Loading busy={policy.loading} />
        <Failure error={policy.error} />
        {!policy.loading ? <Nothing>No client with that id is declared.</Nothing> : null}
      </Box>
    );
  }

  return (
    <Box>
      <Summary
        title={<span style={{ fontFamily: "monospace" }}>{client.id}</span>}
        subtitle={`A ${client.kind} client. Tokens issued for it carry this id as their audience.`}
        chips={
          <>
            {client.ttlCap ? <Chip size="small" variant="outlined" label={`caps tokens at ${forHowLong(client.ttlCap)}`} /> : null}
            {client.secret ? <Chip size="small" variant="outlined" label={`secret in ${client.secret}`} /> : null}
            <Chip size="small" variant="outlined" label={`${peopleCount(people.length)} reach it`} />
          </>
        }
      />

      <Loading busy={policy.loading || holders.loading} />
      <Failure error={policy.error ?? holders.error} />

      <Section title="Groups that open it" hint="being in any one of them is enough">
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableBody>
              {client.requires.map((group) => (
                <TableRow key={group} hover>
                  <TableCell>
                    <Ref to={paths.group(group)} mono>
                      {group}
                    </Ref>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Section>

      {client.redirects.length ? (
        <Section title="Redirects" hint="where a login may return to">
          <Paper variant="outlined" sx={{ p: 2 }}>
            {client.redirects.map((uri) => (
              <Typography key={uri} variant="body2" sx={{ fontFamily: "monospace" }}>
                {uri}
              </Typography>
            ))}
          </Paper>
        </Section>
      ) : null}

      <Section
        title="Who reaches it now"
        hint={`resolved against ${holders.value?.examined ?? 0} accounts in the snapshots`}
      >
        {people.length === 0 ? (
          <Nothing>
            Nobody. Attach a directory group to one of the groups above, and the people in it reach this
            client.
          </Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Person</TableCell>
                  <TableCell>Through</TableCell>
                  <TableCell>Token</TableCell>
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
                        {holder.via.map((group) => (
                          <Ref key={group} to={paths.group(group)}>
                            <Chip size="small" variant="outlined" label={group} clickable />
                          </Ref>
                        ))}
                        {!holder.live ? <Chip size="small" color="warning" label="suspended" /> : null}
                      </Stack>
                    </TableCell>
                    <TableCell>{forHowLong(holder.lifetime)}</TableCell>
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
