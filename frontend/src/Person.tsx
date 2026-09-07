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

/** One person: the place where the two sides meet. Their identity facts
 *  come from the directory, and from there the chain runs one row per
 *  hop to the clients they reach. The most used page in the console,
 *  because the most frequent question is "why can't this person do
 *  that". */
export function Person({ email }: { email: string }) {
  const explained = useAsync(() => access.explain({ email } as ExplainRequest), [email]);
  const found = useAsync(() => access.searchPeople({ query: email, limit: 5 }), [email]);
  const account = (found.value?.people ?? []).find((p) => p.email.toLowerCase() === email.toLowerCase());

  if (!email) {
    return <Nothing>Search for a person to see what they reach.</Nothing>;
  }
  return (
    <Box>
      <Loading busy={explained.loading} />
      <Failure error={explained.error} />
      {explained.value ? <Explanation value={explained.value} directory={account?.workspaceId} /> : null}
    </Box>
  );
}

/** The shared body of a person's page and of a machine's: the same
 *  question, so the same answer. Reads along the chain — where the
 *  identity comes from, then one row per internal group held with the
 *  directory group or matcher that put it there and the clients that
 *  opened, then what did not open and why, then the raw claims. */
export function Explanation({ value, directory }: { value: ExplainResponse; directory?: string }) {
  const [showClaims, setShowClaims] = useState(false);
  const identity = value.identity;
  const isPerson = Boolean(identity?.email);
  const admitted = value.clients.filter((client) => client.admitted);
  const refused = value.clients.filter((client) => !client.admitted);
  const name = personName(identity?.givenName, identity?.familyName, identity?.email);
  const heldNames = new Set(value.held.map((held) => held.group));

  return (
    <Box>
      <Summary
        title={name || "a machine identity"}
        subtitle={
          isPerson
            ? `${roleName(identity?.role ?? 0)} in this console · in ${value.held.length} internal ${value.held.length === 1 ? "group" : "groups"} · reaches ${admitted.length} of ${value.clients.length} clients`
            : `in ${value.held.length} internal ${value.held.length === 1 ? "group" : "groups"} · reaches ${admitted.length} of ${value.clients.length} clients`
        }
        chips={
          <>
            {isPerson && identity?.email && identity.email !== name ? (
              <Chip size="small" variant="outlined" label={identity.email} sx={{ fontFamily: "monospace" }} />
            ) : null}
            {directory ? (
              <Ref to={paths.directory(directory)}>
                <Chip size="small" variant="outlined" label={`from ${directory}`} clickable />
              </Ref>
            ) : null}
            {value.suspended ? (
              <Tooltip title="The directory says this account is not live. A consumer acts on that only because the answer is authoritative.">
                <Chip size="small" color="warning" label="suspended" />
              </Tooltip>
            ) : isPerson && value.inDomain && value.found ? (
              <Chip size="small" color="success" variant="outlined" label="live" />
            ) : null}
            {isPerson && !value.inDomain ? (
              <Tooltip title="No connected directory serves this address's domain, so the hub has no opinion about it.">
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

      {isPerson ? (
        <Section title="Directory groups" hint="what the directory says, before the policy">
          {value.directoryGroups.length === 0 ? (
            <Nothing>
              {value.inDomain
                ? "In no directory group, so no membership can put them anywhere."
                : "Nothing: no connected directory reads this address."}
            </Nothing>
          ) : (
            <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
              {value.directoryGroups.map((group) => (
                <Ref key={group} to={paths.directoryGroup(group)}>
                  <Chip
                    size="small"
                    variant="outlined"
                    label={group}
                    clickable
                    color={value.held.some((held) => held.via.includes(group)) ? "primary" : "default"}
                  />
                </Ref>
              ))}
            </Stack>
          )}
        </Section>
      ) : null}

      <Section
        title="The chain"
        hint="one row per internal group held: what put them in it, and what it opens"
      >
        {value.held.length === 0 ? (
          <Nothing>
            In no internal group, so nothing opens.{" "}
            {isPerson
              ? "Attaching one of the directory groups above to an internal group is what changes that."
              : "No matcher admits this proof."}
          </Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>{isPerson ? "Directory group" : "Matcher"}</TableCell>
                  <TableCell>Internal group</TableCell>
                  <TableCell>Opens</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {value.held.map((held) => {
                  const opens = admitted.filter((client) => client.requires.includes(held.group));
                  return (
                    <TableRow key={held.group} hover>
                      <TableCell>
                        <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                          {held.via.map((why) =>
                            why.includes("@") ? (
                              <Ref key={why} to={paths.directoryGroup(why)}>
                                <Chip size="small" variant="outlined" label={why} clickable />
                              </Ref>
                            ) : (
                              <Chip key={why} size="small" variant="outlined" color="secondary" label={why} />
                            ),
                          )}
                        </Stack>
                      </TableCell>
                      <TableCell>
                        <Ref to={paths.group(held.group)} mono>
                          {held.group}
                        </Ref>
                      </TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                          {opens.map((client) => (
                            <Ref key={client.id} to={paths.client(client.id)}>
                              <Chip
                                size="small"
                                variant="outlined"
                                color="primary"
                                label={`${client.id} · ${forHowLong(client.lifetime)}`}
                                clickable
                              />
                            </Ref>
                          ))}
                          {opens.length === 0 ? (
                            <Typography variant="body2" color="text.secondary">
                              only claims
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
      </Section>

      {refused.length ? (
        <Section title="Not reached" hint="and the internal group that would open each">
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableBody>
                {refused.map((client) => (
                  <TableRow key={client.id} hover sx={{ opacity: 0.7 }}>
                    <TableCell>
                      <Ref to={paths.client(client.id)} mono>
                        {client.id}
                      </Ref>
                    </TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5, alignItems: "center" }}>
                        <Typography variant="body2" color="text.secondary">
                          needs any of
                        </Typography>
                        {client.requires.map((group) => (
                          <Ref key={group} to={paths.group(group)}>
                            <Chip
                              size="small"
                              variant="outlined"
                              label={group}
                              clickable
                              color={heldNames.has(group) ? "primary" : "default"}
                            />
                          </Ref>
                        ))}
                        {client.requires.length === 0 ? (
                          <Typography variant="body2" color="text.secondary">
                            nobody: it requires no group
                          </Typography>
                        ) : null}
                      </Stack>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
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
