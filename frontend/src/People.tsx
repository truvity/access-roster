import { useState } from "react";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Typography from "@mui/material/Typography";

import { access, github, personName, workspaces } from "./api";
import { AccountFilter } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Facet, Facets, Failure, Loading, Mono, Nothing, Page, Ref, State } from "./ui";

/** The identity-side leaf: every account the hub has snapshotted. The
 *  header search is how you reach one person; this list is for the
 *  reviewer who scans, so it filters by the three things a reviewer
 *  scans for — which provider, which domain, and whether the account is
 *  live. */
export function People({ github: initialGitHub = "" }: { github?: string }) {
  const [provider, setProvider] = useState("");
  const [domain, setDomain] = useState("");
  const [account, setAccount] = useState<AccountFilter>(AccountFilter.UNSPECIFIED);
  const [linked, setLinked] = useState<GitHubFilter>(initialGitHub === "linked" || initialGitHub === "not-linked" ? initialGitHub : "");
  const tenants = useAsync(() => workspaces.listWorkspaces({}), []);
  // Whether a person linked a GitHub account is not on the people the hub
  // returns, so it is read from the GitHub status — only once somebody
  // asks, because that call reads every organisation's report — and
  // applied to the page in hand.
  const links = useAsync(() => (linked ? github.getGitHubStatus({}) : Promise.resolve(undefined)), [linked]);
  const linkedAddresses = new Set(
    (links.value?.links ?? []).filter((l) => l.state === "linked").flatMap((l) => l.emails.map((email) => email.toLowerCase())),
  );
  // The domain filter is applied by the hub, not here: this page shows
  // the first 200 of a match, and narrowing that page in the browser
  // would answer "nobody" while the snapshot holds hundreds.
  const found = useAsync(
    () => access.searchPeople({ workspaceId: provider, domain, account, limit: 200 }),
    [provider, domain, account],
  );
  const all = found.value?.people ?? [];
  const people = !linked || !links.value ? all : all.filter((p) => linkedAddresses.has(p.email.toLowerCase()) === (linked === "linked"));
  const list = tenants.value?.workspaces ?? [];
  // Every domain any provider SERVES, deduplicated: a domain belongs to
  // one provider, so choosing a domain while a different provider is
  // selected is the one combination that can hold nobody.
  //
  // Unserved domains are left out rather than shown empty. A provider
  // discovers every domain its tenant owns — eleven of them here, most
  // of them parked — and only the served ones can hold an account this
  // page will ever list. Offering the rest makes the filter mostly a row
  // of buttons that return nothing, and hides the two or three that
  // work among them.
  const domains = [
    ...new Set(list.flatMap((tenant) => tenant.domains.filter((each) => each.served).map((each) => each.name))),
  ].sort();

  return (
    <Page
      title="People"
      lede="Every account in every connected provider, as the last snapshot has it. A person's page shows the chain from their provider groups to the clients they reach."
    >
      <Facets>
        <Facet
          value={provider}
          onChange={setProvider}
          all={{ value: "", label: "Every provider" }}
          options={list.map((tenant) => ({ value: tenant.id, label: tenant.id }))}
          mono
        />
        <Facet
          value={domain}
          onChange={setDomain}
          all={{ value: "", label: "Every domain" }}
          options={domains.map((name) => ({ value: name, label: name }))}
          mono
        />
        <Facet
          value={account}
          onChange={setAccount}
          all={{ value: AccountFilter.UNSPECIFIED, label: "Any account" }}
          options={[
            { value: AccountFilter.LIVE, label: "Live" },
            { value: AccountFilter.SUSPENDED, label: "Suspended" },
          ]}
        />
        <Facet
          value={linked}
          onChange={setLinked}
          all={{ value: "", label: "Any GitHub" }}
          options={[
            { value: "linked", label: "GitHub: linked" },
            { value: "not-linked", label: "GitHub: not linked" },
          ]}
        />
      </Facets>

      <Loading busy={found.loading || links.loading} />
      <Failure error={found.error ?? (links.error ? `Whether people linked a GitHub account could not be read: ${links.error}` : undefined)} />

      {!found.loading && !links.loading && people.length === 0 ? (
        <Nothing>
          {provider || domain || linked || account !== AccountFilter.UNSPECIFIED ? "Nobody matches the filter." : "No accounts snapshotted yet: add a provider first."}
        </Nothing>
      ) : (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Person</TableCell>
                <TableCell>Address</TableCell>
                <TableCell>Provider</TableCell>
                <TableCell>Domain</TableCell>
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
                    <Mono>{domainOf(person.email)}</Mono>
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
          {linked
            ? `Showing those among the first ${all.length} accounts. Narrow the other filters, or search by name in the header, to reach the rest.`
            : `Showing the first ${people.length}. Narrow the filter, or search by name in the header, to reach the rest.`}
        </Typography>
      ) : null}
    </Page>
  );
}

/** Whether to narrow the list to people who linked a GitHub account. */
type GitHubFilter = "" | "linked" | "not-linked";

/** The domain half of an address. It is the column and the filter both,
 *  and it is read here rather than carried in the response because the
 *  address already is the answer. */
function domainOf(email: string): string {
  const at = email.lastIndexOf("@");
  return at < 0 ? "" : email.slice(at + 1);
}
