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

import { access, forHowLong, personName, roleName, sourceName, type Me } from "./api";
import type { ExplainRequest, ExplainResponse } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Failure, Loading, Mono, Names, Nothing, Page, Ref, Section, State, type Fact } from "./ui";

/** One person: the place where the two sides meet. Their identity facts
 *  come from the directory, and from there the chain runs one row per
 *  hop to the clients they reach. Your own page is the same page, with
 *  one more fact: how you signed in. */
export function Person({ email, me }: { email: string; me?: Me }) {
  const explained = useAsync(() => access.explain({ email } as ExplainRequest), [email]);
  const self = me?.status === "signed-in" && me.email?.toLowerCase() === email.toLowerCase();

  if (!email) {
    return <Nothing>Search for a person to see what they reach.</Nothing>;
  }
  return (
    <Box>
      <Loading busy={explained.loading} />
      <Failure error={explained.error} />
      {explained.value ? (
        <Explanation value={explained.value} directory={explained.value.workspaceId || undefined} signedInVia={self ? sourceName(me?.source) : undefined} />
      ) : null}
    </Box>
  );
}

/** The shared body of a person's page and of a machine's. The main
 *  column is the chain; the aside is who this is, what the directory
 *  says, and the claims. */
export function Explanation({ value, directory, signedInVia }: { value: ExplainResponse; directory?: string; signedInVia?: string }) {
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
        { label: "Signed in", value: signedInVia },
        { label: "Token lifetime", value: forHowLong(value.lifetime) },
      ]
    : [{ label: "Token lifetime", value: forHowLong(value.lifetime) }];

  const aside = (
    <>
      {isPerson ? (
        <Section title="Directory groups" hint="before the policy">
          <Names
            items={value.directoryGroups.map((group) => ({ label: group, to: paths.directoryGroup(group), mono: true }))}
            empty={value.inDomain ? "In no directory group, so no membership can put them anywhere." : "No connected directory reads this address."}
          />
        </Section>
      ) : null}
      <Box>
        <Button size="small" onClick={() => setShowClaims(!showClaims)} sx={{ ml: -1 }}>
          {showClaims ? "Hide" : "Show"} the claims a token would carry
        </Button>
        <Collapse in={showClaims}>
          <Paper variant="outlined" sx={{ p: 1.5, mt: 1, maxHeight: 360, overflow: "auto" }}>
            <Typography component="pre" variant="caption" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.75rem" }}>
              {JSON.stringify(value.claims ?? {}, null, 2)}
            </Typography>
          </Paper>
        </Collapse>
      </Box>
    </>
  );

  return (
    <Page
      title={name || "A machine identity"}
      lede={`In ${plural(value.held.length, "internal group", "internal groups")}, reaching ${admitted.length} of ${plural(value.clients.length, "client", "clients")}.`}
      facts={facts}
      aside={aside}
    >
      {isPerson && value.inDomain && !value.found ? (
        <Alert severity="warning" sx={{ mb: 3 }}>
          The directory does not know this address.
        </Alert>
      ) : null}

      <Section title="The chain" hint="one row per internal group held: what put them in it, and what it opens">
        {value.held.length === 0 ? (
          <Nothing>
            In no internal group, so nothing opens.{" "}
            {isPerson ? "Attaching one of their directory groups to an internal group is what changes that." : "No matcher admits this proof."}
          </Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ width: "36%" }}>{isPerson ? "Directory group" : "Matcher"}</TableCell>
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
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ width: "36%" }}>Client</TableCell>
                  <TableCell>Needs any of</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {refused.map((client) => (
                  <TableRow key={client.id}>
                    <TableCell>
                      <Ref to={paths.client(client.id)} mono>
                        {client.id}
                      </Ref>
                    </TableCell>
                    <TableCell>
                      <Names
                        items={client.requires.map((group) => ({ label: group, to: paths.group(group), mono: true }))}
                        empty="nobody: it requires no group"
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Section>
      ) : null}
    </Page>
  );
}
