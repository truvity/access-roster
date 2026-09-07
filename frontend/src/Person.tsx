import { useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Chip from "@mui/material/Chip";
import Collapse from "@mui/material/Collapse";
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

import { access, forHowLong, personName, roleName } from "./api";
import type { ExplainRequest, ExplainResponse } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Failure, Loading, Nothing, Ref, Section, Summary } from "./ui";

/** One person: everything they reach, and what put it there. The most
 *  used page in the console, because the most frequent question is "why
 *  can't this person do that". */
export function Person({ email }: { email: string }) {
  const explained = useAsync(() => access.explain({ email } as ExplainRequest), [email]);

  if (!email) {
    return <Nothing>Search for a person to see what they reach.</Nothing>;
  }
  return (
    <Box>
      <Loading busy={explained.loading} />
      <Failure error={explained.error} />
      {explained.value ? <Explanation value={explained.value} /> : null}
    </Box>
  );
}

/** The shared body of a person page and of an explained machine proof:
 *  the same question, so the same answer. */
export function Explanation({ value }: { value: ExplainResponse }) {
  const [showClaims, setShowClaims] = useState(false);
  const identity = value.identity;
  const isPerson = Boolean(identity?.email);
  const admitted = value.clients.filter((client) => client.admitted);
  const name = personName(identity?.givenName, identity?.familyName, identity?.email);

  return (
    <Box>
      <Summary
        title={name || "a machine identity"}
        subtitle={
          isPerson
            ? `${roleName(identity?.role ?? 0)} in this console · in ${value.held.length} internal groups · reaches ${admitted.length} of ${value.clients.length} clients`
            : `in ${value.held.length} internal groups · reaches ${admitted.length} of ${value.clients.length} clients`
        }
        chips={
          <>
            {value.suspended ? (
              <Tooltip title="The directory says this account is not live. A consumer acts on that only because the answer is authoritative.">
                <Chip size="small" color="warning" label="suspended" />
              </Tooltip>
            ) : null}
            {isPerson && !value.inDomain ? (
              <Tooltip title="No connected tenant serves this address's domain, so the hub has no opinion about it.">
                <Chip size="small" variant="outlined" label="no opinion" />
              </Tooltip>
            ) : null}
            {value.inDomain && !value.authoritative ? (
              <Tooltip title="The directory cannot be vouched for right now, so this is a hold rather than a fact.">
                <Chip size="small" color="warning" variant="outlined" label="hold" />
              </Tooltip>
            ) : null}
          </>
        }
        right={
          <Typography variant="body2" color="text.secondary">
            token lifetime {forHowLong(value.lifetime)}
          </Typography>
        }
      />

      {isPerson && value.inDomain && !value.found ? (
        <Alert severity="warning" sx={{ mb: 2 }}>
          The directory does not know this address.
        </Alert>
      ) : null}

      <Section title="What it reaches" hint="a client's id is the audience its tokens carry">
        {value.clients.length === 0 ? (
          <Nothing>No clients are declared yet, so there is nothing to be issued a token for.</Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Client</TableCell>
                  <TableCell>Through</TableCell>
                  <TableCell>Token</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {value.clients.map((client) => (
                  <TableRow key={client.id} hover sx={{ opacity: client.admitted ? 1 : 0.45 }}>
                    <TableCell>
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                        <Ref to={paths.client(client.id)} mono>
                          {client.id}
                        </Ref>
                        {client.admitted ? null : <Chip size="small" variant="outlined" label="refused" />}
                      </Stack>
                    </TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                        {client.requires
                          .filter((group) => !client.admitted || value.held.some((held) => held.group === group))
                          .map((group) => (
                            <Ref key={group} to={paths.group(group)}>
                              <Chip
                                size="small"
                                variant="outlined"
                                color={client.admitted ? "primary" : "default"}
                                label={group}
                                clickable
                              />
                            </Ref>
                          ))}
                      </Stack>
                    </TableCell>
                    <TableCell>{client.admitted ? forHowLong(client.lifetime) : "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Section>

      <Section title="Internal groups, and what put it in them">
        {value.held.length === 0 ? (
          <Nothing>
            In no internal group, so nothing is granted. Attaching a directory group to one is what changes
            that.
          </Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableBody>
                {value.held.map((held) => (
                  <TableRow key={held.group} hover>
                    <TableCell>
                      <Ref to={paths.group(held.group)} mono>
                        {held.group}
                      </Ref>
                    </TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                        {held.via.map((why) => (
                          <Chip key={why} size="small" variant="outlined" label={why} />
                        ))}
                      </Stack>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Section>

      {value.directoryGroups.length ? (
        <Section title="Directory groups the hub reports" hint="the raw membership behind the rows above">
          <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
            {value.directoryGroups.map((group) => (
              <Chip key={group} size="small" variant="outlined" label={group} />
            ))}
          </Stack>
        </Section>
      ) : null}

      <Box>
        <Button size="small" onClick={() => setShowClaims(!showClaims)}>
          {showClaims ? "Hide" : "Show"} the claims a token would carry
        </Button>
        <Collapse in={showClaims}>
          <Paper variant="outlined" sx={{ p: 2, mt: 1, overflowX: "auto" }}>
            <Box component="pre" sx={{ m: 0, fontSize: 13, fontFamily: "monospace" }}>
              {JSON.stringify(value.claims ?? {}, null, 2)}
            </Box>
          </Paper>
        </Collapse>
      </Box>
    </Box>
  );
}
