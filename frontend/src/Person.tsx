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

import { access, forHowLong, issuerIsSameOrigin, personName, reason, roleName, sessions, sourceName, type Me } from "./api";
import type { ExplainRequest, ExplainResponse } from "./gen/directoryroster/v1/access_pb";
import type { Session } from "./gen/accessissuer/v1/session_pb";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Failure, Loading, Mono, Names, Nothing, Page, Ref, Section, State, type Fact } from "./ui";
import { SessionsPanel } from "./Sessions";

/** One person: the place where the two sides meet. Their identity facts
 *  come from the directory, and from there the chain runs one row per
 *  hop to the clients they reach. Your own page is the same page, with
 *  one more fact: how you signed in. */
export function Person({
  email,
  me,
  operator,
  onDone,
}: {
  email: string;
  me?: Me;
  operator?: boolean;
  onDone?: (message: string) => void;
}) {
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
        <Explanation
          value={explained.value}
          directory={explained.value.workspaceId || undefined}
          signedInVia={self ? sourceName(me?.source) : undefined}
          sessionsOf={issuerIsSameOrigin(me?.issuerUrl) && (self || operator) ? email : undefined}
          signOutURL={self ? (me?.signOutUrl ?? "/logout") : undefined}
          onDone={onDone}
        />
      ) : null}
    </Box>
  );
}

/** The shared body of a person's page and of a machine's. The main
 *  column reads top to bottom: what they reach, what they do not, the
 *  directory groups behind it, their active sessions once an issuer
 *  shares this console's origin, and the claims a token would carry. The
 *  aside carries only the identity facts — short lines that stay in
 *  view while the column is read.
 *
 *  sessionsOf is the identity to show sessions for -- set only once an
 *  issuer is configured AND the viewer may see them (themselves, or an
 *  operator on anybody's page); Matchers' simulator passes none of this,
 *  so a machine's explanation renders no sessions section at all. */
export function Explanation({
  value,
  directory,
  signedInVia,
  sessionsOf,
  signOutURL,
  onDone,
}: {
  value: ExplainResponse;
  directory?: string;
  signedInVia?: string;
  sessionsOf?: string;
  /** Where to go when the sessions just ended were the reader's OWN.
   *  Undefined on somebody else's page. */
  signOutURL?: string;
  onDone?: (message: string) => void;
}) {
  const [showClaims, setShowClaims] = useState(true);
  const [busy, setBusy] = useState<string | undefined>();
  const [sessionFailure, setSessionFailure] = useState<string | undefined>();
  const identity = value.identity;
  const isPerson = Boolean(identity?.email);
  const found = useAsync(
    () => (sessionsOf ? sessions.listSessions({ identity: sessionsOf }) : Promise.resolve(undefined)),
    [sessionsOf],
  );

  const revoke = async (session: Session) => {
    setBusy(session.id);
    setSessionFailure(undefined);
    try {
      await sessions.revokeSessions({ identity: session.identity, sessionId: session.id });
      onDone?.(`Ended the session on ${session.clientId}.`);
      found.reload();
    } catch (error) {
      setSessionFailure(reason(error));
    } finally {
      setBusy(undefined);
    }
  };

  const signOutEverywhere = async () => {
    if (!sessionsOf) return;
    setBusy("*");
    setSessionFailure(undefined);
    try {
      await sessions.revokeSessions({ identity: sessionsOf });

      // "Everywhere" includes HERE. Naming no client ends the sign-in as
      // well as the sessions, so on your own page this page's own
      // session is one of the ones that just ended — and staying put
      // left it acting signed in until the next call failed with a
      // sentence about tokens. Follow through instead.
      if (signOutURL) {
        window.location.href = signOutURL;
        return;
      }

      onDone?.(`${sessionsOf} is signed out everywhere.`);
      found.reload();
    } catch (error) {
      setSessionFailure(reason(error));
    } finally {
      setBusy(undefined);
    }
  };
  const admitted = value.clients.filter((client) => client.admitted);
  const refused = value.clients.filter((client) => !client.admitted);
  const name = personName(identity?.givenName, identity?.familyName, identity?.email);
  const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

  const facts: Fact[] = isPerson
    ? [
        { label: "Address", value: <Mono>{identity?.email}</Mono> },
        {
          label: "Provider",
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
          value: !value.inDomain ? undefined : value.authoritative ? <State kind="authoritative" /> : <State kind="provisional" />,
        },
        { label: "In this console", value: roleName(identity?.role ?? 0) },
        { label: "Signed in", value: signedInVia },
        { label: "Token lifetime", value: forHowLong(value.lifetime) },
      ]
    : [{ label: "Token lifetime", value: forHowLong(value.lifetime) }];

  return (
    <Page
      title={name || "A machine identity"}
      lede={`In ${plural(value.held.length, "internal group", "internal groups")}, reaching ${admitted.length} of ${plural(value.clients.length, "client", "clients")}.`}
      facts={facts}
      aside={null}
    >
      {isPerson && value.inDomain && !value.found ? (
        <Alert severity="warning" sx={{ mb: 3 }}>
          The provider does not know this address.
        </Alert>
      ) : null}

      <Section title="The chain" hint="one row per internal group held: what put them in it, and what it opens">
        {value.held.length === 0 ? (
          <Nothing>
            In no internal group, so nothing opens.{" "}
            {isPerson ? "Attaching one of their provider groups to an internal group is what changes that." : "No matcher admits this proof."}
          </Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ width: "36%" }}>{isPerson ? "Provider group" : "Matcher"}</TableCell>
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

      {isPerson ? (
        <Section title="Provider groups" hint="every group the provider puts them in, before the policy looks at any of it">
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Names
              items={value.directoryGroups.map((group) => ({ label: group, to: paths.directoryGroup(group), mono: true }))}
              empty={value.inDomain ? "In no provider group, so no membership can put them anywhere." : "No connected provider reads this address."}
            />
          </Paper>
        </Section>
      ) : null}

      {sessionsOf ? (
        <Section
          title="Active sessions"
          hint="one row per application, grouped under the browser session that opened them"
          action={
            <Button size="small" color="warning" disabled={busy === "*"} onClick={signOutEverywhere}>
              Sign out everywhere
            </Button>
          }
        >
          <Loading busy={found.loading} />
          <Failure error={found.error ?? sessionFailure} />
          <SessionsPanel
            sessions={found.value?.sessions ?? []}
            showClient
            onRevoke={revoke}
            revoking={busy}
            empty="No open session."
          />
        </Section>
      ) : null}

      <Section
        title="The claims a token would carry"
        hint="what a client would read out of a token minted for this identity right now"
        action={
          <Button size="small" onClick={() => setShowClaims(!showClaims)}>
            {showClaims ? "Hide" : "Show"}
          </Button>
        }
      >
        <Collapse in={showClaims}>
          <Paper variant="outlined" sx={{ p: 2, overflowX: "auto" }}>
            <Typography component="pre" variant="body2" sx={{ m: 0, fontFamily: "monospace" }}>
              {JSON.stringify(value.claims ?? {}, null, 2)}
            </Typography>
          </Paper>
        </Collapse>
      </Section>
    </Page>
  );
}
