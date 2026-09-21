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

import { access, forHowLong, github, issuerIsSameOrigin, personName, reason, roleName, secretStores, sessions, sourceName, type Me } from "./api";
import type { ExplainRequest, ExplainResponse } from "./gen/directoryroster/v1/access_pb";
import type { Session } from "./gen/accessissuer/v1/session_pb";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { labelOf, linkPage, rowsOf, sentence, tooltipOf } from "./githubModel";
import { byNamespace, opens, prefixes } from "./secretStoresModel";
import { loginCell, OwnerRule, sourceName as linkSourceName } from "./GitHub";
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
      {explained.value ? <GitHubSection email={email} self={self} /> : null}
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

      {isPerson && identity?.email ? <SecretReach email={identity.email} /> : null}

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

/** A person on GitHub: the account linked to their address, the teams the
 *  policy puts them in and where each stands. Read from the GitHub page's
 *  one call, which needs the viewer role; without it only the person's own
 *  way to link is shown. */
function GitHubSection({ email, self }: { email: string; self: boolean }) {
  const status = useAsync(() => github.getGitHubStatus({}), []);
  const address = email.toLowerCase();
  const rows = (status.value?.organisations ?? []).flatMap((org) =>
    rowsOf(org)
      .filter((row) => row.member.email.toLowerCase() === address)
      .map((row) => ({ ...row, acting: org.enabled })),
  );
  const links = (status.value?.links ?? []).filter((l) => l.emails.some((e) => e.toLowerCase() === address));
  const active = links.find((l) => l.state === "linked");
  if (!self && rows.length === 0 && links.length === 0) return null;

  return (
    <Box sx={{ mb: 3 }}>
      <Section
        title="GitHub"
        hint={active ? `@${active.login}, ${linkSourceName(active.source)}` : rows.length ? "not linked" : undefined}
        action={
          self ? (
            <Button size="small" variant={active ? "text" : "contained"} href={linkPage(status.value?.linkUrl)} target="_blank" rel="noreferrer">
              {active ? "Link again" : "Link your GitHub account"}
            </Button>
          ) : null
        }
      >
        {rows.length ? (
          <>
          <OwnerRule rows={rows} />
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Where</TableCell>
                  <TableCell>GitHub</TableCell>
                  <TableCell>Role</TableCell>
                  <TableCell>State</TableCell>
                  <TableCell>Next</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.map((row) => (
                  <TableRow key={`${row.org}/${row.team}/${row.member.action}`}>
                    <TableCell>
                      {row.team ? (
                        <Ref to={paths.githubTeam(row.org, row.team)} mono>
                          {`${row.org} / ${row.team}`}
                        </Ref>
                      ) : (
                        <Ref to={paths.githubOrganisation(row.org)} mono>
                          {row.org}
                        </Ref>
                      )}
                    </TableCell>
                    <TableCell>{loginCell(row.member.login)}</TableCell>
                    <TableCell>{row.member.state === "reported" ? "owner" : row.member.role}</TableCell>
                    <TableCell>
                      <State kind={labelOf(row.member.state)} title={tooltipOf(row.member)} />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{sentence(row.member, row.acting)}</Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          </>
        ) : (
          <Typography variant="body2" color="text.secondary">
            {self
              ? "No GitHub team is bound to a group you are in. Linking your account now means you are added the day one is."
              : "No GitHub team is bound to a group this person is in."}
          </Typography>
        )}
      </Section>
    </Box>
  );
}

/** What this person's groups open in the declared secret stores, read
 *  from the policy each STORE holds rather than from what this side
 *  declares — the gap between the two is what somebody looking here is
 *  trying to find.
 *
 *  Empty is the ordinary answer and draws nothing: most people are in no
 *  group any store admits, and an empty section on every page would be a
 *  question mark where there is no question. */
function SecretReach({ email }: { email: string }) {
  const answer = useAsync(() => secretStores.listSecretManagerReach({ email }), [email]);
  const reach = answer.value?.reach ?? [];
  if (answer.loading || reach.length === 0) return null;

  return (
    <Section
      title="Secret stores they can reach"
      hint={`${prefixes(reach).length} path${prefixes(reach).length === 1 ? "" : "s"}, through ${reach.length} group${reach.length === 1 ? "" : "s"} — what the store's own policy grants, not what this side declares`}
    >
      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Store</TableCell>
              <TableCell>Namespace</TableCell>
              <TableCell>Through</TableCell>
              <TableCell>Opens</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {byNamespace(reach).flatMap((group) =>
              group.reach.map((one) => (
                <TableRow key={`${one.manager}/${one.namespace}/${one.group}`} hover>
                  <TableCell>
                    <Ref to={paths.secretStores()} mono>
                      {one.manager}
                    </Ref>
                  </TableCell>
                  <TableCell>
                    <Ref to={paths.secretNamespace(one.manager, one.namespace)} mono>
                      {one.namespace}
                    </Ref>
                  </TableCell>
                  <TableCell>
                    <Ref to={paths.group(one.group)} mono>
                      {one.group}
                    </Ref>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color={one.writes ? "warning.main" : "text.secondary"} sx={{ fontFamily: "monospace" }}>
                      {one.unreadable ? "could not be read" : opens(one.rules) || "nothing"}
                    </Typography>
                  </TableCell>
                </TableRow>
              )),
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Section>
  );
}
