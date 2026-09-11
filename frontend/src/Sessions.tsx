import { useCallback, useEffect, useState } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Divider from "@mui/material/Divider";
import List from "@mui/material/List";
import ListItem from "@mui/material/ListItem";
import ListItemText from "@mui/material/ListItemText";
import ListSubheader from "@mui/material/ListSubheader";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TextField from "@mui/material/TextField";
import ToggleButton from "@mui/material/ToggleButton";
import ToggleButtonGroup from "@mui/material/ToggleButtonGroup";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";

import { ago, at, howName, reason, sessions as sessionsClient, until } from "./api";
import type { Session } from "./gen/accessissuer/v1/session_pb";
import { paths } from "./router";
import { Failure, Loading, Nothing, Page, Ref } from "./ui";

/** Sessions live in the issuer (docs/design/access-issuer.md, "Where
 *  session management lives"): one refresh token, described, per
 *  identity and per client. This is the one file that renders them,
 *  because a person's page, a client's page and the installation-wide
 *  listing all show the same row with different columns hidden. */

/** One row's worth of a session, plus the button that ends it. Shown
 *  wherever sessions show: a person's page (client only), a client's
 *  page (identity only), and the Sessions rail page (both). Sessions
 *  that share a browser (SSO) session are grouped under one heading so
 *  "this laptop" reads as one thing (docs/design/hub.md, "The
 *  console"). */
export function SessionsPanel({
  sessions,
  showIdentity,
  showClient,
  onRevoke,
  revoking,
  empty,
}: {
  sessions: Session[];
  showIdentity?: boolean;
  showClient?: boolean;
  onRevoke: (session: Session) => void;
  revoking?: string;
  empty: React.ReactNode;
}) {
  if (sessions.length === 0) return <Nothing>{empty}</Nothing>;

  // Group consecutive sessions that share a non-empty `sso`. The list
  // itself already arrives newest-first, so a session with no browser
  // parent (a device sign-in, a token exchange) is a group of one.
  const groups: { sso: string; items: Session[] }[] = [];
  for (const session of sessions) {
    const last = groups[groups.length - 1];
    if (session.sso && last?.sso === session.sso) {
      last.items.push(session);
    } else {
      groups.push({ sso: session.sso, items: [session] });
    }
  }

  return (
    <Paper variant="outlined">
      <List disablePadding>
        {groups.map((group, gi) => (
          <Box key={group.sso || group.items[0].id}>
            {gi > 0 ? <Divider component="li" /> : null}
            {group.sso ? (
              <ListSubheader disableSticky sx={{ bgcolor: "transparent", lineHeight: 2.5, fontSize: "0.7rem" }}>
                same browser
              </ListSubheader>
            ) : null}
            {group.items.map((session, ii) => (
              <Box key={session.id}>
                {ii > 0 ? <Divider component="li" sx={{ ml: group.sso ? 3 : 0 }} /> : null}
                <ListItem sx={{ py: 0.75, pl: group.sso ? 3.5 : 1.5, pr: 1.5, gap: 2 }}>
                  <ListItemText
                    primary={
                      <>
                        {showIdentity ? (
                          <Ref to={paths.person(session.identity)}>{session.identity}</Ref>
                        ) : null}
                        {showIdentity && showClient ? " · " : null}
                        {showClient ? (
                          <Ref to={paths.client(session.clientId)} mono>
                            {session.clientId}
                          </Ref>
                        ) : null}
                      </>
                    }
                    secondary={
                      <>
                        {howName(session.how)} · opened {ago(at(session.issuedAt))} · last used{" "}
                        {session.lastRefreshed ? ago(at(session.lastRefreshed)) : "never"} · expires{" "}
                        {until(at(session.expiresAt))}
                      </>
                    }
                    slotProps={{ primary: { component: "div", variant: "body2" }, secondary: { component: "div", variant: "caption" } }}
                    sx={{ my: 0 }}
                  />
                  <Button size="small" color="warning" disabled={revoking === session.id} onClick={() => onRevoke(session)}>
                    Revoke
                  </Button>
                </ListItem>
              </Box>
            ))}
          </Box>
        ))}
      </List>
    </Paper>
  );
}

/** The installation-wide listing, as a TABLE.
 *
 *  The grouped list above is right in a narrow column on a person's page,
 *  where there are three sessions and the browser grouping is the point.
 *  It is wrong here: four facts per session were stacked into one caption
 *  line, so a page that can hold a hundred rows used a third of its width
 *  and none of its columns lined up. A reader scanning for "whose session
 *  expires soonest" had to read every line.
 *
 *  The browser grouping survives as a COLUMN rather than a heading. Two
 *  rows with the same mark came from the same browser; a blank means the
 *  session has no browser behind it at all, which is what a token
 *  exchange is. A column can be compared down the page, which is the one
 *  thing a run of subheadings cannot.
 */
function SessionsTable({
  sessions,
  onRevoke,
  revoking,
}: {
  sessions: Session[];
  onRevoke: (session: Session) => void;
  revoking?: string;
}) {
  if (sessions.length === 0) return <Nothing>No open session matches the filter.</Nothing>;

  // A short, stable mark per browser session, numbered in the order they
  // appear. The `sso` itself is an opaque id: printing it would be noise
  // nobody can act on, where "A" beside "A" is the whole message.
  const marks = new Map<string, string>();
  for (const session of sessions) {
    if (session.sso && !marks.has(session.sso)) {
      marks.set(session.sso, String.fromCharCode(65 + (marks.size % 26)));
    }
  }
  // A browser with only one session here needs no mark: the column exists
  // to say "these two are the same one".
  const counts = new Map<string, number>();
  for (const session of sessions) {
    if (session.sso) counts.set(session.sso, (counts.get(session.sso) ?? 0) + 1);
  }

  return (
    <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Person</TableCell>
            <TableCell>Client</TableCell>
            <TableCell>Way in</TableCell>
            <TableCell>
              <Tooltip title="Sessions with the same mark came from one browser. Blank is a session with no browser behind it.">
                <span>Browser</span>
              </Tooltip>
            </TableCell>
            <TableCell>Opened</TableCell>
            <TableCell>Last used</TableCell>
            <TableCell>Expires</TableCell>
            <TableCell align="right" />
          </TableRow>
        </TableHead>
        <TableBody>
          {sessions.map((session) => (
            <TableRow key={session.id} hover>
              <TableCell>
                <Ref to={paths.person(session.identity)}>{session.identity}</Ref>
              </TableCell>
              <TableCell>
                <Ref to={paths.client(session.clientId)} mono>
                  {session.clientId}
                </Ref>
              </TableCell>
              <TableCell>
                <Typography variant="body2" color="text.secondary">
                  {howName(session.how)}
                </Typography>
              </TableCell>
              <TableCell>
                {session.sso && (counts.get(session.sso) ?? 0) > 1 ? (
                  <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                    {marks.get(session.sso)}
                  </Typography>
                ) : null}
              </TableCell>
              <TableCell>{ago(at(session.issuedAt))}</TableCell>
              <TableCell>
                <Typography variant="body2" color={session.lastRefreshed ? undefined : "text.secondary"}>
                  {session.lastRefreshed ? ago(at(session.lastRefreshed)) : "never"}
                </Typography>
              </TableCell>
              <TableCell>{until(at(session.expiresAt))}</TableCell>
              <TableCell align="right">
                <Button size="small" color="warning" disabled={revoking === session.id} onClick={() => onRevoke(session)}>
                  Revoke
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

/** Every open session in the installation, newest first (INF-682). It
 *  exists for the incident where you do not know WHOSE session to look
 *  for, which is also why it is operator-only and every read of it is
 *  audited on the issuer's side. The rail hides the entry for anyone
 *  else; this still refuses to render the list for one, in case the
 *  page is reached another way. */
export function SessionsPage({ operator }: { operator: boolean }) {
  const [identity, setIdentity] = useState("");
  const [clientId, setClientId] = useState("");
  const [how, setHow] = useState("");
  const [items, setItems] = useState<Session[]>([]);
  const [nextToken, setNextToken] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [busy, setBusy] = useState<string | undefined>();
  const [failure, setFailure] = useState<string | undefined>();

  const load = useCallback(() => {
    setLoading(true);
    setFailure(undefined);
    sessionsClient
      .listSessions({ identity, clientId, pageSize: 100 })
      .then((response) => {
        setItems(response.sessions);
        setNextToken(response.nextPageToken);
      })
      .catch((error: unknown) => setFailure(reason(error)))
      .finally(() => setLoading(false));
  }, [identity, clientId]);

  useEffect(() => {
    if (operator) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load, operator]);

  const loadMore = async () => {
    setLoadingMore(true);
    try {
      const response = await sessionsClient.listSessions({ identity, clientId, pageSize: 100, pageToken: nextToken });
      setItems((prev) => [...prev, ...response.sessions]);
      setNextToken(response.nextPageToken);
    } catch (error) {
      setFailure(reason(error));
    } finally {
      setLoadingMore(false);
    }
  };

  const revoke = async (session: Session) => {
    setBusy(session.id);
    setFailure(undefined);
    try {
      await sessionsClient.revokeSessions({ identity: session.identity, sessionId: session.id });
      load();
    } catch (error) {
      setFailure(reason(error));
    } finally {
      setBusy(undefined);
    }
  };

  if (!operator) {
    return <Nothing>Listing every session in the installation is an operator's.</Nothing>;
  }

  // Person and client are filtered by the ISSUER, because they page; the
  // way in is filtered here, because it is a closed set the rows carry.
  // Only the ways actually present are offered, so the facet never shows
  // a button that returns nothing.
  const ways = [...new Set(items.map((session) => session.how))].sort();
  const shown = how ? items.filter((session) => String(session.how) === how) : items;

  return (
    <Page title="Sessions" lede="Every session open right now, across every person and client. Every listing here is audited.">
      <Stack direction="row" spacing={2} sx={{ mb: 2, alignItems: "center", flexWrap: "wrap", gap: 1.5 }}>
        <TextField
          size="small"
          label="Person"
          placeholder="ada@example.com"
          value={identity}
          onChange={(e) => setIdentity(e.target.value.trim())}
        />
        <TextField
          size="small"
          label="Client"
          placeholder="argocd"
          value={clientId}
          onChange={(e) => setClientId(e.target.value.trim())}
        />
        {ways.length > 1 ? (
          <ToggleButtonGroup size="small" exclusive value={how} onChange={(_, next: string | null) => next !== null && setHow(next)}>
            <ToggleButton value="">Any way in</ToggleButton>
            {ways.map((kind) => (
              <ToggleButton key={kind} value={String(kind)} sx={{ textTransform: "none" }}>
                {howName(kind)}
              </ToggleButton>
            ))}
          </ToggleButtonGroup>
        ) : null}
      </Stack>

      <Loading busy={loading} />
      <Failure error={failure} />

      <SessionsTable sessions={shown} onRevoke={revoke} revoking={busy} />

      {nextToken ? (
        <Box sx={{ mt: 2 }}>
          <Button size="small" onClick={loadMore} disabled={loadingMore}>
            Load more
          </Button>
        </Box>
      ) : null}
    </Page>
  );
}
