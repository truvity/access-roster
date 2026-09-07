import { useState } from "react";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import ToggleButton from "@mui/material/ToggleButton";
import ToggleButtonGroup from "@mui/material/ToggleButtonGroup";
import Typography from "@mui/material/Typography";

import { access, personName, workspaces } from "./api";
import { AccountFilter } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Failure, Loading, Mono, Nothing, Page, Ref, State } from "./ui";

/** The identity-side leaf: every account the hub has snapshotted. The
 *  header search is how you reach one person; this list is for the
 *  reviewer who scans, so it filters by the two things a reviewer scans
 *  for — which directory, and whether the account is live. */
export function People() {
  const [directory, setDirectory] = useState("");
  const [account, setAccount] = useState<AccountFilter>(AccountFilter.UNSPECIFIED);
  const tenants = useAsync(() => workspaces.listWorkspaces({}), []);
  const found = useAsync(() => access.searchPeople({ workspaceId: directory, account, limit: 200 }), [directory, account]);
  const people = found.value?.people ?? [];
  const list = tenants.value?.workspaces ?? [];

  return (
    <Page
      title="People"
      lede="Every account in every connected directory, as the last snapshot has it. A person's page shows the chain from their directory groups to the clients they reach."
    >
      <Stack direction="row" spacing={2} sx={{ alignItems: "center", flexWrap: "wrap", gap: 1.5, mb: 1.5 }}>
        {list.length > 1 ? (
          <ToggleButtonGroup size="small" exclusive value={directory} onChange={(_, next: string | null) => next !== null && setDirectory(next)}>
            <ToggleButton value="">Every directory</ToggleButton>
            {list.map((tenant) => (
              <ToggleButton key={tenant.id} value={tenant.id} sx={{ fontFamily: "monospace", textTransform: "none" }}>
                {tenant.id}
              </ToggleButton>
            ))}
          </ToggleButtonGroup>
        ) : null}
        <ToggleButtonGroup size="small" exclusive value={account} onChange={(_, next: AccountFilter | null) => next !== null && setAccount(next)}>
          <ToggleButton value={AccountFilter.UNSPECIFIED}>Any account</ToggleButton>
          <ToggleButton value={AccountFilter.LIVE}>Live</ToggleButton>
          <ToggleButton value={AccountFilter.SUSPENDED}>Suspended</ToggleButton>
        </ToggleButtonGroup>
      </Stack>

      <Loading busy={found.loading} />
      <Failure error={found.error} />

      {!found.loading && people.length === 0 ? (
        <Nothing>
          {directory || account !== AccountFilter.UNSPECIFIED ? "Nobody matches the filter." : "No accounts snapshotted yet: add a directory first."}
        </Nothing>
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
          Showing the first {people.length}. Narrow the filter, or search by name in the header, to reach the rest.
        </Typography>
      ) : null}
    </Page>
  );
}
