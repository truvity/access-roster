import { useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Collapse from "@mui/material/Collapse";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Typography from "@mui/material/Typography";

import { access, forHowLong, personName, roleName } from "./api";
import type { ExplainRequest, ExplainResponse } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Failure, Loading, Mono, Names, Nothing, Page, Ref, Rows, Section, State, type Fact } from "./ui";

/** One person: the place where the two sides meet. Their identity facts
 *  come from the directory, and from there the chain runs one row per
 *  hop to the clients they reach. */
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

/** The shared body of a person's page and of a machine's. Reads along
 *  the chain: where the identity comes from, one row per internal group
 *  held with what put it there and what opened, what did not open and
 *  why, then the raw claims. */
export function Explanation({ value, directory }: { value: ExplainResponse; directory?: string }) {
  const [showClaims, setShowClaims] = useState(false);
  const identity = value.identity;
  const isPerson = Boolean(identity?.email);
  const admitted = value.clients.filter((client) => client.admitted);
  const refused = value.clients.filter((client) => !client.admitted);
  const name = personName(identity?.givenName, identity?.familyName, identity?.email);
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

  const facts: Fact[] = isPerson
    ? [
        { label: "Address", value: <Mono>{identity?.email}</Mono> },
        {
          label: "Directory",
          value: directory ? (
            <Ref to={paths.directory(directory)} mono>
              {directory}
            </Ref>
          ) : value.inDomain ? undefined : "none serves this domain",
        },
        {
          label: "Account",
          value: value.suspended ? <State kind="suspended" /> : value.inDomain && value.found ? <State kind="live" /> : undefined,
        },
        {
          label: "Answer",
          value: !value.inDomain ? undefined : value.authoritative ? <State kind="authoritative" /> : <State kind="hold" />,
        },
        { label: "In this console", value: roleName(identity?.role ?? 0) },
        { label: "Token lifetime", value: forHowLong(value.lifetime) },
      ]
    : [{ label: "Token lifetime", value: forHowLong(value.lifetime) }];

  return (
    <Page
      title={name || "A machine identity"}
      lede={`In ${plural(value.held.length, "internal group", "internal groups")}, reaching ${admitted.length} of ${plural(value.clients.length, "client", "clients")}.`}
      facts={facts}
    >
      {isPerson && value.inDomain && !value.found ? (
        <Alert severity="warning" sx={{ mb: 3 }}>
          The directory does not know this address.
        </Alert>
      ) : null}

      {isPerson ? (
        <Section title="Directory groups" hint="what the directory says, before the policy">
          <Names
            items={value.directoryGroups.map((group) => ({ label: group, to: paths.directoryGroup(group), mono: true }))}
            empty={
              value.inDomain
                ? "In no directory group, so no membership can put them anywhere."
                : "Nothing: no connected directory reads this address."
            }
          />
        </Section>
      ) : null}

      <Section title="The chain" hint="one row per internal group held: what put them in it, and what it opens">
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
                  <TableCell sx={{ width: "34%" }}>{isPerson ? "Directory group" : "Matcher"}</TableCell>
                  <TableCell sx={{ width: "22%" }}>Internal group</TableCell>
                  <TableCell>Opens</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {value.held.map((held) => {
                  const opens = admitted.filter((client) => client.requires.includes(held.group));
                  return (
                    <TableRow key={held.group}>
                      <TableCell>
                        <Names items={held.via.map((why) => (why.includes("@") ? { label: why, to: paths.directoryGroup(why), mono: true } : { label: why, mono: true }))} />
                      </TableCell>
                      <TableCell>
                        <Ref to={paths.group(held.group)} mono>
                          {held.group}
                        </Ref>
                      </TableCell>
                      <TableCell>
                        <Names
                          items={opens.map((client) => ({ label: client.id, to: paths.client(client.id), mono: true, note: forHowLong(client.lifetime) }))}
                          empty="only claims"
                        />
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
          <Rows
            items={refused}
            keyOf={(client) => client.id}
            primary={(client) => (
              <Ref to={paths.client(client.id)} mono>
                {client.id}
              </Ref>
            )}
            secondary={(client) =>
              client.requires.length ? (
                <>
                  needs any of{" "}
                  <Names items={client.requires.map((group) => ({ label: group, to: paths.group(group), mono: true }))} muted />
                </>
              ) : (
                "requires no group: nobody is admitted"
              )
            }
            empty=""
          />
        </Section>
      ) : null}

      <Box>
        <Button size="small" onClick={() => setShowClaims(!showClaims)}>
          {showClaims ? "Hide" : "Show"} the claims a token would carry
        </Button>
        <Collapse in={showClaims}>
          <Paper variant="outlined" sx={{ p: 2, mt: 1, overflowX: "auto" }}>
            <Typography component="pre" variant="body2" sx={{ m: 0, fontFamily: "monospace" }}>
              {JSON.stringify(value.claims ?? {}, null, 2)}
            </Typography>
          </Paper>
        </Collapse>
      </Box>
    </Page>
  );
}
