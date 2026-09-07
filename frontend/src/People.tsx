import { useState } from "react";
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
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";

import { access, personName } from "./api";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Failure, Loading, Nothing, Ref } from "./ui";

/** The identity-side leaf: every account the hub has snapshotted. Search
 *  is the usual way to a person; this list is for the reviewer who wants
 *  to scan rather than to ask. */
export function People() {
  const [query, setQuery] = useState("");
  const found = useAsync(() => access.searchPeople({ query, limit: 200 }), [query]);
  const people = found.value?.people ?? [];

  return (
    <Box>
      <Stack direction="row" sx={{ alignItems: "flex-start", justifyContent: "space-between", mb: 1, gap: 2 }}>
        <Box>
          <Typography variant="h6">People</Typography>
          <Typography variant="body2" color="text.secondary">
            Every account in every connected directory, as the last snapshot has it. A person's page shows
            the chain from their directory groups to the clients they reach.
          </Typography>
        </Box>
        <TextField
          size="small"
          label="Filter by name or address"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          sx={{ minWidth: 280 }}
        />
      </Stack>

      <Loading busy={found.loading} />
      <Failure error={found.error} />

      {!found.loading && people.length === 0 ? (
        <Nothing>
          {query ? "Nobody matches. The filter looks at the address and the name." : "No accounts snapshotted yet: add a directory first."}
        </Nothing>
      ) : (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Person</TableCell>
                <TableCell>Address</TableCell>
                <TableCell>Directory</TableCell>
                <TableCell>Status</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {people.map((person) => (
                <TableRow key={person.email} hover>
                  <TableCell>
                    <Ref to={paths.person(person.email)}>
                      {personName(person.givenName, person.familyName, person.email)}
                    </Ref>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: "monospace" }}>
                      {person.email}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Ref to={paths.directory(person.workspaceId)} mono>
                      {person.workspaceId}
                    </Ref>
                  </TableCell>
                  <TableCell>
                    {person.live ? (
                      <Chip size="small" color="success" variant="outlined" label="live" />
                    ) : (
                      <Chip size="small" color="warning" label="suspended" />
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      {found.value?.truncated ? (
        <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
          Showing the first {people.length}. Narrow the filter to see the rest.
        </Typography>
      ) : null}
    </Box>
  );
}
