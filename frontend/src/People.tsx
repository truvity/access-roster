import { useState } from "react";
import Paper from "@mui/material/Paper";
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
import { Failure, Loading, Mono, Nothing, Page, Ref, State } from "./ui";

/** The identity-side leaf: every account the hub has snapshotted. Search
 *  is the usual way to a person; this list is for the reviewer who wants
 *  to scan rather than to ask. */
export function People() {
  const [query, setQuery] = useState("");
  const found = useAsync(() => access.searchPeople({ query, limit: 200 }), [query]);
  const people = found.value?.people ?? [];

  return (
    <Page
      title="People"
      lede="Every account in every connected directory, as the last snapshot has it. A person's page shows the chain from their directory groups to the clients they reach."
      actions={<TextField label="Filter by name or address" value={query} onChange={(e) => setQuery(e.target.value)} sx={{ minWidth: 280 }} />}
    >
      <Loading busy={found.loading} />
      <Failure error={found.error} />

      {!found.loading && people.length === 0 ? (
        <Nothing>{query ? "Nobody matches. The filter looks at the address and the name." : "No accounts snapshotted yet: add a directory first."}</Nothing>
      ) : (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Person</TableCell>
                <TableCell>Address</TableCell>
                <TableCell>Directory</TableCell>
                <TableCell>Account</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {people.map((person) => (
                <TableRow key={person.email} hover>
                  <TableCell>
                    <Ref to={paths.person(person.email)}>{personName(person.givenName, person.familyName, person.email)}</Ref>
                  </TableCell>
                  <TableCell>
                    <Mono>{person.email}</Mono>
                  </TableCell>
                  <TableCell>
                    <Ref to={paths.directory(person.workspaceId)} mono>
                      {person.workspaceId}
                    </Ref>
                  </TableCell>
                  <TableCell>
                    <State kind={person.live ? "live" : "suspended"} />
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
    </Page>
  );
}
