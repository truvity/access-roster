import { useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Card from "@mui/material/Card";
import CardContent from "@mui/material/CardContent";
import Chip from "@mui/material/Chip";
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

import { access, forHowLong, roleName } from "./api";
import type { ExplainResponse } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { Failure, Loading } from "./ui";

/** Effective access: what an identity actually gets, and which membership
 *  put it there. Operators may look at anyone; everyone sees themselves. */
export function MeView({ operator }: { operator: boolean }) {
  const [lookup, setLookup] = useState("");
  const [asked, setAsked] = useState("");
  const explained = useAsync(() => access.explain({ email: asked }), [asked]);

  return (
    <Box>
      <Typography variant="h6">Effective access</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        What an identity is entitled to right now, and what put it there. Nothing here is granted directly:
        a role is held by being in an internal group the deployment declared.
      </Typography>

      {operator ? (
        <Stack direction="row" spacing={1} sx={{ mb: 2, alignItems: "flex-start" }}>
          <TextField
            size="small"
            label="Look up someone"
            placeholder="person@example.com"
            value={lookup}
            onChange={(e) => setLookup(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") setAsked(lookup.trim());
            }}
            sx={{ minWidth: 320 }}
          />
          <Button variant="contained" onClick={() => setAsked(lookup.trim())} sx={{ mt: 0.25 }}>
            Explain
          </Button>
          {asked ? (
            <Button
              sx={{ mt: 0.25 }}
              onClick={() => {
                setAsked("");
                setLookup("");
              }}
            >
              Back to me
            </Button>
          ) : null}
        </Stack>
      ) : null}

      <Loading busy={explained.loading} />
      <Failure error={explained.error} />
      {explained.value ? <Explanation value={explained.value} /> : null}
    </Box>
  );
}

function Explanation({ value }: { value: ExplainResponse }) {
  const identity = value.identity;
  const name = [identity?.givenName, identity?.familyName].filter(Boolean).join(" ");

  return (
    <Stack spacing={2}>
      <Card variant="outlined">
        <CardContent>
          <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
            <Typography variant="subtitle1">{name || identity?.email || "the break-glass admin"}</Typography>
            {identity?.email ? (
              <Typography variant="body2" color="text.secondary">
                {identity.email}
              </Typography>
            ) : null}
            <Chip size="small" color="primary" label={roleName(identity?.role ?? 0)} />
            {value.suspended ? <Chip size="small" color="warning" label="suspended" /> : null}
            {!value.inDomain && identity?.email ? (
              <Tooltip title="No connected workspace serves this address's domain, so the hub has no opinion about it.">
                <Chip size="small" variant="outlined" label="no opinion" />
              </Tooltip>
            ) : null}
            {value.inDomain && !value.authoritative ? (
              <Tooltip title="The directory cannot be vouched for right now, so this is a hold rather than a fact.">
                <Chip size="small" color="warning" variant="outlined" label="hold" />
              </Tooltip>
            ) : null}
            <Box sx={{ flexGrow: 1 }} />
            <Typography variant="body2" color="text.secondary">
              token lifetime {forHowLong(value.lifetime)}
            </Typography>
          </Stack>
          {!value.found && value.inDomain ? (
            <Alert severity="warning" sx={{ mt: 2 }}>
              The directory does not know this address.
            </Alert>
          ) : null}
        </CardContent>
      </Card>

      <Box>
        <Typography variant="subtitle2" gutterBottom>
          Internal groups, and what put you in them
        </Typography>
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Group</TableCell>
                <TableCell>Because of</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {value.held.map((held) => (
                <TableRow key={held.group} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                      {held.group}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap" }}>
                      {held.via.map((why) => (
                        <Chip key={why} size="small" variant="outlined" label={why} />
                      ))}
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
              {value.held.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={2}>
                    <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                      In no internal group, so nothing is granted. An operator can attach a directory group
                      to one on the Access tab.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>
        </TableContainer>
      </Box>

      <Box>
        <Typography variant="subtitle2" gutterBottom>
          Claims a token would carry
        </Typography>
        <Paper variant="outlined" sx={{ p: 2, overflowX: "auto" }}>
          <Box component="pre" sx={{ m: 0, fontSize: 13, fontFamily: "monospace" }}>
            {JSON.stringify(value.claims ?? {}, null, 2)}
          </Box>
        </Paper>
      </Box>

      {value.directoryGroups.length ? (
        <Box>
          <Typography variant="subtitle2" gutterBottom>
            Directory groups the hub reports
          </Typography>
          <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
            {value.directoryGroups.map((group) => (
              <Chip key={group} size="small" variant="outlined" label={group} />
            ))}
          </Stack>
        </Box>
      ) : null}
    </Stack>
  );
}
