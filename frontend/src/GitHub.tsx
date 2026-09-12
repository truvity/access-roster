import { useState } from "react";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";

import { ago, at, github } from "./api";
import type { GitHubMember, GitHubOrganisation } from "./gen/directoryroster/v1/github_pb";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Facet, Facts, Failure, Loading, Mono, Names, Nothing, Page, Section, State, type StateKind } from "./ui";

/** GitHub organisations: what the policy says each team should contain,
 *  beside what the controller last found and did.
 *
 *  Read-only, like the rest of the console. The controller acts; this
 *  page is where an operator reads what it did and, while an organisation
 *  is disabled, what it would do — which is how an organisation is
 *  enabled knowingly rather than hopefully. */
export function GitHubPage() {
  const status = useAsync(() => github.getGitHubStatus({}), []);
  const organisations = status.value?.organisations ?? [];

  return (
    <Page
      title="GitHub"
      lede="Each GitHub team is fed by internal groups, exactly as a client is opened by them: the holders of those groups are the people the team should contain. The controller makes each organisation match and reports here what it found. Nothing on this page writes to GitHub."
    >
      <Loading busy={status.loading} />
      <Failure error={status.error} />

      {status.value && !status.value.reportsAvailable ? (
        <Nothing>This deployment keeps no state in Kubernetes, so a controller has nowhere to report: only the bindings are shown.</Nothing>
      ) : null}

      {!status.loading && organisations.length === 0 ? (
        <Nothing>No GitHub organisation is bound. A team is bound in the policy's github table, beside the groups that feed it.</Nothing>
      ) : null}

      {organisations.map((org) => (
        <Organisation key={org.org} org={org} />
      ))}
    </Page>
  );
}

type Filter = "all" | "attention" | "synced";

/** One person on one team, flattened so a single table can answer "what
 *  will the controller do in this organisation". */
type Row = { key: string; team: string; member: GitHubMember };

function Organisation({ org }: { org: GitHubOrganisation }) {
  const [filter, setFilter] = useState<Filter>("attention");

  const rows: Row[] = [
    ...org.members.map((member) => ({ key: `org:${member.email}:${member.login}`, team: "", member })),
    ...org.teams.flatMap((team) =>
      team.members.map((member) => ({ key: `${team.team}:${member.email}:${member.login}`, team: team.team, member })),
    ),
  ];
  const attention = rows.filter((row) => row.member.state !== "synced");
  const synced = rows.filter((row) => row.member.state === "synced");
  const shown = { all: rows, attention, synced }[filter];

  return (
    <Section title={org.org} hint={summary(org)}>
      <Stack sx={{ gap: 2 }}>
        <Facts
          items={[
            { label: "Controller", value: outcome(org) },
            { label: "Acts on it", value: org.reported ? (org.enabled ? "yes" : "no — disabled, derived only") : undefined },
            { label: "Last pass", value: at(org.tick?.at) ? ago(at(org.tick?.at)) : undefined },
            { label: "Changes", value: org.tick ? String(org.tick.changes) : undefined },
            { label: "Held", value: org.tick ? String(org.tick.held) : undefined },
            {
              label: "In the organisation itself",
              value: org.memberGroups.length ? <Names items={org.memberGroups.map((group) => ({ label: group, to: paths.group(group), mono: true }))} /> : undefined,
            },
          ]}
        />
        {org.reportError ? <Failure error={`The last report could not be read: ${org.reportError}`} /> : null}
        {org.tick?.error ? <Failure error={`The last pass failed: ${org.tick.error}`} /> : null}
        {!org.bound ? (
          <Nothing>The policy no longer binds this organisation. What follows is the controller's last report on it.</Nothing>
        ) : null}

        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Team</TableCell>
                <TableCell>Members from</TableCell>
                <TableCell>Maintainers from</TableCell>
                <TableCell align="right">Synced</TableCell>
                <TableCell align="right">Not yet</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {org.teams.map((team) => (
                <TableRow key={team.team} hover>
                  <TableCell>
                    <Mono>{team.team}</Mono>
                    {!team.bound ? (
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                        no longer bound
                      </Typography>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <Names items={team.memberGroups.map((group) => ({ label: group, to: paths.group(group), mono: true }))} empty="—" />
                  </TableCell>
                  <TableCell>
                    <Names items={team.maintainerGroups.map((group) => ({ label: group, to: paths.group(group), mono: true }))} empty="—" />
                  </TableCell>
                  <TableCell align="right">{team.members.filter((m) => m.state === "synced").length}</TableCell>
                  <TableCell align="right">{team.members.filter((m) => m.state !== "synced").length}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {rows.length > 0 ? (
          <>
            <Facet
              value={filter}
              onChange={setFilter}
              all={{ value: "all", label: `Everyone (${rows.length})` }}
              options={[
                { value: "attention", label: `Not synced (${attention.length})` },
                { value: "synced", label: `Synced (${synced.length})` },
              ]}
            />
            {shown.length === 0 ? (
              <Nothing>{filter === "synced" ? "Nobody is synced yet." : "Everyone is synced."}</Nothing>
            ) : (
              <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Person</TableCell>
                      <TableCell>GitHub</TableCell>
                      <TableCell>Where</TableCell>
                      <TableCell>Role</TableCell>
                      <TableCell>State</TableCell>
                      <TableCell>Next</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {shown.map((row) => (
                      <TableRow key={row.key} hover>
                        <TableCell>
                          <Mono>{row.member.email || "—"}</Mono>
                        </TableCell>
                        <TableCell>{row.member.login ? <Mono>{row.member.login}</Mono> : <Typography variant="body2" color="text.secondary">not linked</Typography>}</TableCell>
                        <TableCell>{row.team ? <Mono>{row.team}</Mono> : <Typography variant="body2">the organisation</Typography>}</TableCell>
                        <TableCell>{row.member.role}</TableCell>
                        <TableCell>
                          <State kind={stateKind(row.member.state)} />
                        </TableCell>
                        <TableCell>{next(row.member)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </>
        ) : null}

        {org.unlinked.length > 0 ? (
          <Section title="Not linked" hint="members of the organisation whose login no bound holder's address matched — listed, never touched">
            <Names items={org.unlinked.map((account) => ({ label: account.login, mono: true, note: account.reason }))} />
          </Section>
        ) : null}
      </Stack>
    </Section>
  );
}

/** The organisation's one line: how many teams, and whether anything is
 *  waiting. */
function summary(org: GitHubOrganisation): string {
  const teams = `${org.teams.length} ${org.teams.length === 1 ? "team" : "teams"}`;
  if (!org.reported) return `${teams} bound, not reported yet`;
  const waiting = [...org.members, ...org.teams.flatMap((t) => t.members)].filter((m) => m.state !== "synced").length;
  return waiting ? `${teams}, ${waiting} not synced` : `${teams}, everyone synced`;
}

function outcome(org: GitHubOrganisation) {
  if (!org.reported) return <State kind="unreported" />;
  const kind = org.tick?.outcome as StateKind | undefined;
  return kind ? <State kind={kind} /> : <State kind="unreported" />;
}

function stateKind(state: string): StateKind {
  switch (state) {
    case "synced":
    case "pending":
    case "invited":
    case "leaving":
    case "held":
      return state;
    default:
      return "unknown";
  }
}

/** What the controller does next, and — for a held action — why it is
 *  not doing it. The reason is the point of the column: a held member
 *  with no reason reads as a stuck controller. */
function next(member: GitHubMember) {
  if (!member.action) return null;
  const words: Record<string, string> = { invite: "invite", add: "add to team", "set-role": "change role", remove: "remove" };
  const label = words[member.action] ?? member.action;
  if (!member.reason) return <Typography variant="body2">{label}</Typography>;
  return (
    <Tooltip title={member.reason}>
      <Typography variant="body2" component="span" sx={{ borderBottom: "1px dotted", cursor: "help" }}>
        {label} — {member.reason}
      </Typography>
    </Tooltip>
  );
}
