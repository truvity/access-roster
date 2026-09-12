import { useEffect, useState } from "react";
import Button from "@mui/material/Button";
import MenuItem from "@mui/material/MenuItem";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TextField from "@mui/material/TextField";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";

import { ago, at, audit, reason } from "./api";
import type { AuditEvent } from "./gen/directoryroster/v1/audit_pb";
import { Failure, Loading, Mono, Nothing, Page, State } from "./ui";

type Filters = { source: string; kind: string; subject: string; target: string };

const empty: Filters = { source: "", kind: "", subject: "", target: "" };

/** What happened lately, in the whole installation.
 *
 *  One stream: the issuer's sign-ins, refusals, exchanges and revokes;
 *  the console's connects and disconnects; and what a reporting component
 *  says it did, beside the identity it proved. Operator-only, because it
 *  names every sign-in. Capped — the log holds every event for good. */
export function AuditPage() {
  const [draft, setDraft] = useState<Filters>(empty);
  const [filters, setFilters] = useState<Filters>(empty);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [cursor, setCursor] = useState("");
  const [loading, setLoading] = useState(true);
  const [failure, setFailure] = useState<string | undefined>();

  const load = async (from: string, replace: boolean) => {
    setLoading(true);
    setFailure(undefined);
    try {
      const page = await audit.listAuditEvents({ ...filters, cursor: from, limit: 100 });
      setEvents((previous) => (replace ? page.events : [...previous, ...page.events]));
      setCursor(page.cursor);
    } catch (error) {
      setFailure(reason(error));
    } finally {
      setLoading(false);
    }
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => void load("", true), [filters]);

  return (
    <Page
      title="Audit"
      lede="What happened lately: sign-ins and refusals, token exchanges, revokes, connects and disconnects, and what a reporting component such as the GitHub controller did. Newest first. The stream is capped by count and age; every event is also a log line, and the log is the copy that lasts."
    >
      <Stack
        component="form"
        direction="row"
        sx={{ flexWrap: "wrap", gap: 1.5, alignItems: "center", mb: 2 }}
        onSubmit={(e) => {
          e.preventDefault();
          setFilters(draft);
        }}
      >
        <TextField select size="small" label="Source" value={draft.source} onChange={(e) => setDraft({ ...draft, source: e.target.value })} sx={{ minWidth: 160 }}>
          <MenuItem value="">Any</MenuItem>
          <MenuItem value="issuer">issuer</MenuItem>
          <MenuItem value="directory">directory</MenuItem>
          <MenuItem value="console">console</MenuItem>
          <MenuItem value="github-roster">github-roster</MenuItem>
        </TextField>
        <TextField size="small" label="Kind" placeholder="sign-in" value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value })} />
        <TextField size="small" label="Concerning" placeholder="an address" value={draft.subject} onChange={(e) => setDraft({ ...draft, subject: e.target.value })} />
        <TextField size="small" label="Where" placeholder="a client, workspace or organisation" value={draft.target} onChange={(e) => setDraft({ ...draft, target: e.target.value })} />
        <Button type="submit" variant="outlined" size="small">
          Show
        </Button>
      </Stack>

      <Loading busy={loading} />
      <Failure error={failure} />

      {!loading && events.length === 0 && !failure ? (
        <Nothing>Nothing recorded matches. The stream holds only the last while; older events are in the log.</Nothing>
      ) : null}

      {events.length > 0 ? (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>When</TableCell>
                <TableCell>What</TableCell>
                <TableCell>By</TableCell>
                <TableCell>Concerning</TableCell>
                <TableCell>Where</TableCell>
                <TableCell>Outcome</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {events.map((event) => (
                <TableRow key={event.id} hover>
                  <TableCell sx={{ whiteSpace: "nowrap" }}>
                    <Tooltip title={at(event.at)?.toISOString() ?? ""}>
                      <span>{ago(at(event.at))}</span>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <Mono>{event.kind}</Mono>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                      {event.source}
                      {attributes(event)}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Mono>{event.actor || "—"}</Mono>
                    {event.reporter ? (
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                        reported by <Mono>{event.reporter}</Mono>
                      </Typography>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <Mono>{event.subject || "—"}</Mono>
                  </TableCell>
                  <TableCell>
                    <Mono>{event.target || "—"}</Mono>
                  </TableCell>
                  <TableCell>
                    {outcome(event)}
                    {event.reason ? (
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                        {event.reason}
                      </Typography>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ) : null}

      {cursor ? (
        <Button sx={{ mt: 2 }} disabled={loading} onClick={() => void load(cursor, false)}>
          Older
        </Button>
      ) : null}
    </Page>
  );
}

function outcome(event: AuditEvent) {
  switch (event.outcome) {
    case "refused":
      return <State kind="refused" />;
    case "failed":
      return <State kind="failed" />;
    case "held":
      return <State kind="held" />;
    default:
      return <Typography variant="body2">ok</Typography>;
  }
}

/** The attributes worth a glance, inline after the source. */
function attributes(event: AuditEvent): string {
  const entries = Object.entries(event.attributes ?? {});
  return entries.length ? ` · ${entries.map(([key, value]) => `${key} ${value}`).join(" · ")}` : "";
}
