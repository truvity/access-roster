import { useState, type ReactNode } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Collapse from "@mui/material/Collapse";
import IconButton from "@mui/material/IconButton";
import MenuItem from "@mui/material/MenuItem";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Tab from "@mui/material/Tab";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Tabs from "@mui/material/Tabs";
import TextField from "@mui/material/TextField";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";

import { ago, at, github, reason } from "./api";
import type { GetGitHubStatusResponse, GitHubCatalogueApp, GitHubOrganisation, GitHubRunnerApp } from "./gen/directoryroster/v1/github_pb";
import { countLabels, labelOf, linkPage, organisationNeeds, peopleOf, rowsOf, sentence, tooltipOf, type Row } from "./githubModel";
import { useAsync } from "./hooks";
import { go, paths } from "./router";
import { Facts, Failure, Loading, Mono, Names, Nothing, Page, Ref, Section, State, type StateKind } from "./ui";

type Props = { operator: boolean; onDone: (message: string) => void };

/** GitHub, as tabs: what needs attention across every organisation, each
 *  organisation and its teams, and the Apps behind it all. One call feeds
 *  every tab, so moving between them never waits. */
export function GitHubPage({ section, rest, operator, onDone }: Props & { section?: string; rest: string[] }) {
  const status = useAsync(() => github.getGitHubStatus({}), []);
  const tab = section === "organisations" ? "organisations" : section === "apps" ? "apps" : "overview";
  const value = status.value;

  let body: ReactNode = null;
  if (value) {
    if (tab === "organisations" && rest[0]) {
      const org = value.organisations.find((o) => o.org === rest[0]);
      body = !org ? (
        <Nothing>No organisation {rest[0]} is bound or reported.</Nothing>
      ) : rest[1] === "teams" && rest[2] ? (
        <TeamPage org={org} team={rest[2]} />
      ) : (
        <OrganisationPage org={org} operator={operator} onDone={onDone} reload={status.reload} />
      );
    } else if (tab === "organisations") {
      body = <OrganisationsList status={value} />;
    } else if (tab === "apps" && rest[0] === "catalogue" && rest[1]) {
      const app = value.catalogueApps.find((a) => a.id === rest[1]);
      body = app ? (
        <CatalogueAppPage app={app} operator={operator} onDone={onDone} reload={status.reload} />
      ) : (
        <Nothing>The catalogue declares no App {rest[1]}, and none was created from it.</Nothing>
      );
    } else if (tab === "apps" && rest[0] === "catalogue") {
      body = <CataloguePage status={value} />;
    } else if (tab === "apps") {
      body = <AppsPage status={value} operator={operator} onDone={onDone} reload={status.reload} />;
    } else {
      body = <Overview status={value} />;
    }
  }

  return (
    <Box>
      <Tabs
        value={tab}
        onChange={(_, next: string) => go(next === "overview" ? paths.github() : next === "apps" ? paths.githubApps() : paths.githubOrganisations())}
        sx={{ mb: 3 }}
      >
        <Tab value="overview" label="Overview" />
        <Tab value="organisations" label="Organisations" />
        <Tab value="apps" label="Apps" />
      </Tabs>
      <Loading busy={status.loading} />
      <Failure error={status.error} />
      {value && !value.reportsAvailable ? (
        <Nothing>This deployment keeps no state in Kubernetes, so a controller has nowhere to report: only the bindings are shown.</Nothing>
      ) : null}
      {body}
    </Box>
  );
}

// ---------------------------------------------------------------- overview

function Overview({ status }: { status: GetGitHubStatusResponse }) {
  const people = peopleOf(status.organisations);
  const waiting = people.filter((p) => p.label === "their-move");
  const needs = status.organisations.flatMap((org) => [
    ...organisationNeeds(org).map((what) => ({ org: org.org, what })),
    ...rowsOf(org)
      .filter((row) => labelOf(row.member.state) === "needs-you")
      .map((row) => ({ org: org.org, what: `${row.member.email || row.member.login}: ${row.member.reason}` })),
  ]);
  const dryRun = status.organisations.filter((org) => org.bound && org.connection?.installed && !org.enabled);

  let next: ReactNode;
  if (!status.linkApp || status.organisations.some((org) => org.bound && !org.connection?.installed)) {
    next = (
      <>
        Create the GitHub Apps on the <Ref to={paths.githubApps()}>Apps</Ref> tab.
      </>
    );
  } else if (needs.length) {
    next = `${needs.length} ${needs.length === 1 ? "thing needs" : "things need"} you — the organisations below say what.`;
  } else if (waiting.length) {
    next = `${waiting.length} ${waiting.length === 1 ? "person has" : "people have"} not linked or accepted yet: send them the link page below.`;
  } else if (dryRun.length) {
    next = `Read ${dryRun.map((org) => org.org).join(" and ")}'s dry run, then add ${dryRun.length === 1 ? "it" : "them"} to githubRoster.actsIn.`;
  } else {
    next = "Nothing to do: every organisation matches the policy.";
  }

  return (
    <Page title="GitHub" lede="Who belongs in which GitHub team is the policy's; the controller makes every organisation match. This is what needs attention.">
      <Alert severity={needs.length ? "warning" : "info"} sx={{ mb: 3 }}>
        <strong>Next:</strong> {next}
      </Alert>

      <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" }, gap: 2, mb: 4 }}>
        {status.organisations.map((org) => (
          <OrganisationCard key={org.org} org={org} />
        ))}
      </Box>

      {waiting.length ? (
        <Section title="Waiting for them" hint={`${waiting.length} not linked, or invited and not accepted`}>
          <Stack sx={{ gap: 1.5 }}>
            <Stack direction="row" sx={{ gap: 1, alignItems: "center", flexWrap: "wrap" }}>
              <CopyButton value={waiting.map((p) => p.email).join(", ")} label="Copy their addresses" />
              <Typography variant="body2" color="text.secondary">
                and send them
              </Typography>
              <CopyLine value={linkPage(status.linkUrl)} />
            </Stack>
            <Names items={waiting.map((p) => ({ label: p.email, to: paths.person(p.email), mono: true }))} />
          </Stack>
        </Section>
      ) : null}
    </Page>
  );
}

function OrganisationCard({ org }: { org: GitHubOrganisation }) {
  const counts = countLabels(rowsOf(org).map((row) => row.member));
  const needs = organisationNeeds(org);
  return (
    <Paper variant="outlined" sx={{ p: 2, minWidth: 0 }}>
      <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "center", gap: 1, mb: 1 }}>
        <Ref to={paths.githubOrganisation(org.org)} mono>
          {org.org}
        </Ref>
        {outcome(org)}
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
        {!org.connection?.installed ? "App not installed" : org.enabled ? "the controller acts" : "dry run"}
        {at(org.tick?.at) ? ` · last pass ${ago(at(org.tick?.at))}` : ""}
        {org.seats?.known ? ` · ${org.seats.free} ${org.seats.free === 1 ? "seat" : "seats"} free` : ""}
      </Typography>
      <Stack direction="row" sx={{ gap: 3, flexWrap: "wrap" }}>
        <Count label="OK" value={counts.ok} />
        <Count label="Waiting for them" value={counts["their-move"]} />
        <Count label="Needs you" value={counts["needs-you"] + needs.length} strong />
      </Stack>
      {needs.length ? (
        <Typography variant="body2" sx={{ mt: 1.5 }}>
          {needs.join(" · ")}
        </Typography>
      ) : null}
    </Paper>
  );
}

function Count({ label, value, strong }: { label: string; value: number; strong?: boolean }) {
  return (
    <Box>
      <Typography variant="h6" color={strong && value ? "warning.main" : undefined} sx={{ lineHeight: 1.2 }}>
        {value}
      </Typography>
      <Typography variant="caption" color="text.secondary">
        {label}
      </Typography>
    </Box>
  );
}

// ----------------------------------------------------------- organisations

function OrganisationsList({ status }: { status: GetGitHubStatusResponse }) {
  return (
    <Page title="Organisations" lede="Every GitHub organisation the policy binds or the controller reports on.">
      {status.organisations.length === 0 ? (
        <Nothing>No GitHub organisation is bound. A team is bound in the policy&apos;s github table.</Nothing>
      ) : (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Organisation</TableCell>
                <TableCell>Controller</TableCell>
                <TableCell>Teams</TableCell>
                <TableCell align="right">OK</TableCell>
                <TableCell align="right">Waiting for them</TableCell>
                <TableCell align="right">Needs you</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {status.organisations.map((org) => {
                const counts = countLabels(rowsOf(org).map((row) => row.member));
                return (
                  <TableRow key={org.org} hover>
                    <TableCell>
                      <Ref to={paths.githubOrganisation(org.org)} mono>
                        {org.org}
                      </Ref>
                    </TableCell>
                    <TableCell>{outcome(org)}</TableCell>
                    <TableCell>{org.teams.length}</TableCell>
                    <TableCell align="right">{counts.ok}</TableCell>
                    <TableCell align="right">{counts["their-move"]}</TableCell>
                    <TableCell align="right">{counts["needs-you"] + organisationNeeds(org).length}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Page>
  );
}

function OrganisationPage({ org, operator, onDone, reload }: Props & { org: GitHubOrganisation; reload: () => void }) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const [others, setOthers] = useState(false);
  const rows = rowsOf(org);
  const acting = org.enabled;
  const changes = rows.filter((row) => row.member.action);
  const removals = changes.filter((row) => row.member.action === "remove");
  const rest = rows.filter(
    (row) => row.member.action !== "remove" && (Boolean(row.member.action) || ["held", "retrying", "reported", "ignored", "not-linked", "invited"].includes(row.member.state)),
  );
  // People, not rows: an invitation shows on the organisation's row and on
  // every team row for the same person, and is one invitation.
  const count = (action: string) =>
    new Set(changes.filter((row) => row.member.action === action).map((row) => (action === "invite" ? row.member.email : `${row.team}|${row.member.login}`))).size;
  const breaker = org.breaker;
  const seats = org.seats;

  const confirm = async () => {
    if (!breaker) return;
    setBusy(true);
    setFailure(undefined);
    try {
      await github.confirmGitHubRemovals({ org: org.org, fingerprint: breaker.fingerprint });
      onDone(`Confirmed: the ${breaker.affected} removals in ${org.org} go ahead on the next pass.`);
      reload();
    } catch (error) {
      setFailure(reason(error));
    } finally {
      setBusy(false);
    }
  };

  const plan = [
    count("invite") && `invite ${count("invite")}`,
    count("add") && `add ${count("add")} to teams`,
    count("set-role") && `change ${count("set-role")} ${count("set-role") === 1 ? "role" : "roles"}`,
    count("remove") && `remove ${count("remove")}`,
  ].filter(Boolean);

  return (
    <Page
      title={org.org}
      mono
      lede={
        !org.reported
          ? "The controller has not reported on this organisation yet."
          : plan.length
            ? `${acting ? "This pass will" : "If enabled now, the controller would"} ${plan.join(", ")}.`
            : "Nothing to change."
      }
      facts={[
        { label: "Controller", value: outcome(org) },
        { label: "Acts on it", value: org.reported ? (acting ? "yes" : "no — dry run") : undefined },
        { label: "Last pass", value: at(org.tick?.at) ? ago(at(org.tick?.at)) : undefined },
        { label: "Seats", value: seats?.known ? `${seats.free} free of ${seats.total}` : undefined },
      ]}
    >
      <Stack sx={{ gap: 2, mb: 4 }}>
        <Failure error={failure} />
        {org.reportError ? <Failure error={`The last report could not be read: ${org.reportError}`} /> : null}
        {org.tick?.error ? <Failure error={`The last pass failed: ${org.tick.error}`} /> : null}
        {seats && !seats.known ? (
          <Alert severity="warning">
            <strong>Nobody is invited: the seats cannot be counted.</strong> Approve organisation administration (read) for this
            organisation&apos;s App on GitHub; invitations go out on the next pass.
          </Alert>
        ) : null}
        {seats?.known && seats.short > 0 ? (
          <Alert severity="warning">
            <strong>
              Not enough seats: {seats.short} {seats.short === 1 ? "person waits" : "people wait"} for a seat.
            </strong>{" "}
            Buy {seats.short} in {org.org}&apos;s billing on GitHub ({seats.filled} of {seats.total} taken, {seats.pending} invitations pending).
          </Alert>
        ) : null}
        {breaker && !breaker.confirmed ? (
          <Alert
            severity="error"
            action={
              operator ? (
                <Button color="inherit" size="small" disabled={busy || org.removalConfirmation?.fingerprint === breaker.fingerprint} onClick={() => void confirm()}>
                  {org.removalConfirmation?.fingerprint === breaker.fingerprint ? "Confirmed" : "Confirm"}
                </Button>
              ) : null
            }
          >
            <strong>
              Removals held: {breaker.affected} of {breaker.members} members would leave at once.
            </strong>{" "}
            That is more often a policy mistake than people leaving. Read the removals below; confirming lets exactly this set go ahead.
          </Alert>
        ) : null}
      </Stack>

      {removals.length ? (
        <Section title={acting ? "Removals" : "Removals it would make"} hint="the part worth reading before anything else">
          <RowsTable rows={removals} acting={acting} hideState />
        </Section>
      ) : null}

      {rest.length ? (
        <Section
          title={acting ? "Everything else" : "Everything else it would do"}
          hint={`${rest.length} rows — invitations, team changes, and who it is waiting on`}
          action={
            <Button size="small" onClick={() => setOthers(!others)}>
              {others ? "Hide" : "Show"}
            </Button>
          }
        >
          <Collapse in={others}>
            <RowsTable rows={rest} acting={acting} />
          </Collapse>
        </Section>
      ) : null}

      <Section title="Teams" hint="each fed by internal groups; open one for its members">
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Team</TableCell>
                <TableCell>Fed by</TableCell>
                <TableCell align="right">OK</TableCell>
                <TableCell align="right">Waiting for them</TableCell>
                <TableCell align="right">Needs you</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {org.teams.map((team) => {
                const counts = countLabels(team.members);
                return (
                  <TableRow key={team.team} hover>
                    <TableCell>
                      <Ref to={paths.githubTeam(org.org, team.team)} mono>
                        {team.team}
                      </Ref>
                      {!team.bound ? (
                        <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                          no longer bound
                        </Typography>
                      ) : null}
                    </TableCell>
                    <TableCell>
                      <Names items={[...team.memberGroups, ...team.maintainerGroups].map((group) => ({ label: group, to: paths.group(group), mono: true }))} empty="—" />
                    </TableCell>
                    <TableCell align="right">{counts.ok}</TableCell>
                    <TableCell align="right">{counts["their-move"]}</TableCell>
                    <TableCell align="right">{counts["needs-you"]}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
        {org.memberGroups.length ? (
          <Typography variant="body2" color="text.secondary" component="div" sx={{ mt: 1 }}>
            In the organisation itself, without a team: <Names items={org.memberGroups.map((group) => ({ label: group, to: paths.group(group), mono: true }))} />
          </Typography>
        ) : null}
      </Section>

      {org.ignored.length ? (
        <Section title="Ignored" hint="left alone here, whatever the groups say — declared in the policy, in git">
          <Names items={org.ignored.map((entry) => (entry.includes("@") ? { label: entry, to: paths.person(entry), mono: true } : { label: entry, mono: true }))} />
        </Section>
      ) : null}

      {org.outsideCollaborators.length ? (
        <Section title="Outside collaborators" hint="access to repositories without membership: reported, never managed">
          <Names items={org.outsideCollaborators.map((account) => ({ label: account.login, mono: true }))} />
        </Section>
      ) : null}

      {org.unlinked.length ? (
        <Section title="Members nobody linked" hint="in the organisation, and nobody can say who they are: never touched">
          <Names items={org.unlinked.map((account) => ({ label: account.login, mono: true }))} />
        </Section>
      ) : null}
    </Page>
  );
}

function TeamPage({ org, team: slug }: { org: GitHubOrganisation; team: string }) {
  const team = org.teams.find((t) => t.team === slug);
  if (!team) return <Nothing>{org.org} has no bound or reported team {slug}.</Nothing>;
  const counts = countLabels(team.members);
  const rows: Row[] = team.members.map((member) => ({ org: org.org, team: team.team, member }));
  return (
    <Page
      title={team.team}
      mono
      lede={
        <>
          A team in{" "}
          <Ref to={paths.githubOrganisation(org.org)} mono>
            {org.org}
          </Ref>
          : {counts.ok} OK, {counts["their-move"]} waiting for them, {counts["needs-you"]} needing you.
        </>
      }
    >
      <Section title="Fed by" hint="the internal groups whose holders belong in it; change it in the policy, in git">
        <Facts
          items={[
            { label: "Members", value: <Names items={team.memberGroups.map((group) => ({ label: group, to: paths.group(group), mono: true }))} empty="—" /> },
            { label: "Maintainers", value: <Names items={team.maintainerGroups.map((group) => ({ label: group, to: paths.group(group), mono: true }))} empty="—" /> },
          ]}
        />
      </Section>
      <Section title="Members" hint="as the controller found them">
        {rows.length ? <RowsTable rows={rows} acting={org.enabled} hideWhere /> : <Nothing>Nobody is wanted in this team.</Nothing>}
      </Section>
    </Page>
  );
}

function RowsTable({ rows, acting, hideWhere, hideState }: { rows: Row[]; acting: boolean; hideWhere?: boolean; hideState?: boolean }) {
  return (
    <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Person</TableCell>
            <TableCell>GitHub</TableCell>
            {hideWhere ? null : <TableCell>Where</TableCell>}
            <TableCell>Role</TableCell>
            {hideState ? null : <TableCell>State</TableCell>}
            <TableCell>Next</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={`${row.team}:${row.member.email}:${row.member.login}:${row.member.action}:${row.member.state}`} hover>
              <TableCell>
                {row.member.email ? (
                  <Ref to={paths.person(row.member.email)} mono>
                    {row.member.email}
                  </Ref>
                ) : (
                  "—"
                )}
              </TableCell>
              <TableCell>{loginCell(row.member.login)}</TableCell>
              {hideWhere ? null : (
                <TableCell>
                  {row.team ? (
                    <Ref to={paths.githubTeam(row.org, row.team)} mono>
                      {row.team}
                    </Ref>
                  ) : (
                    <Typography variant="body2">the organisation</Typography>
                  )}
                </TableCell>
              )}
              <TableCell>{row.member.role}</TableCell>
              {hideState ? null : (
                <TableCell>
                  <State kind={labelOf(row.member.state) as StateKind} title={tooltipOf(row.member)} />
                </TableCell>
              )}
              <TableCell>
                <Typography variant="body2">{sentence(row.member, acting)}</Typography>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

// -------------------------------------------------------------------- apps

function AppsPage({ status, operator, onDone, reload }: Props & { status: GetGitHubStatusResponse; reload: () => void }) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const bound = status.organisations.filter((org) => org.bound);
  const [owner, setOwner] = useState(bound[0]?.org ?? "");
  const app = status.linkApp;

  const leave = async (start: () => Promise<{ url: string; manifest: string }>) => {
    setBusy(true);
    setFailure(undefined);
    try {
      const started = await start();
      if (started.manifest) postManifest(started.url, started.manifest);
      else window.location.href = started.url;
    } catch (error) {
      setFailure(reason(error));
      setBusy(false);
    }
  };
  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setFailure(undefined);
    try {
      await work();
    } catch (error) {
      setFailure(reason(error));
    } finally {
      setBusy(false);
    }
  };
  const settingsNote = (url: string) => (url ? ` Its owner can delete the App on GitHub: ${url}` : "");
  const links = status.links;
  const linked = links.filter((l) => l.state === "linked").length;
  const attention = links.length - linked;

  const disconnectLinkApp = () =>
    run(async () => {
      const gone = await github.disconnectGitHubLinkApp({});
      onDone(`The link App is disconnected; ${gone.invalidated} links wait for their people to link again.${settingsNote(gone.appSettingsUrl)}`);
      reload();
    });
  const disconnectRunnerApp = (org: string, tier: string) =>
    run(async () => {
      const gone = await github.disconnectGitHubRunnerApp({ org, tier });
      onDone(
        `${org}'s ${tier} runner App is disconnected${gone.uninstalled ? " and uninstalled" : `. ${gone.detail}`}.${settingsNote(gone.appSettingsUrl)}`,
      );
      reload();
    });
  const runnerRows = runnerAppRows(status);
  const disconnectOrganisation = (org: string) =>
    run(async () => {
      const gone = await github.disconnectGitHubOrganisation({ org });
      onDone(`${org} is disconnected${gone.uninstalled ? " and its App uninstalled" : `. ${gone.detail}`}.${settingsNote(gone.appSettingsUrl)}`);
      reload();
    });

  return (
    <Page
      title="Apps"
      lede="One link App people authorize, for every organisation, one App per organisation the controller acts through, and — where the deployment declares runner tiers — one runner App per organisation per tier."
    >
      <Failure error={failure} />
      <Section
        title="Link App"
        hint="for every organisation"
        action={
          !operator || !status.linkingAvailable ? null : app ? (
            <Tooltip title="Forget the link App. Every link it made becomes unverifiable: nobody is added or removed on its account until the person links again.">
              <span>
                <Button size="small" color="warning" disabled={busy} onClick={() => void disconnectLinkApp()}>
                  Disconnect
                </Button>
              </span>
            </Tooltip>
          ) : (
            <Stack direction="row" sx={{ gap: 1, alignItems: "center" }}>
              <TextField select size="small" label="Under" value={owner} onChange={(event) => setOwner(event.target.value)} disabled={busy} sx={{ minWidth: 140 }}>
                {bound.map((org) => (
                  <MenuItem key={org.org} value={org.org}>
                    {org.org}
                  </MenuItem>
                ))}
              </TextField>
              <Button size="small" variant="outlined" disabled={busy || !owner} onClick={() => void leave(() => github.beginGitHubLinkAppConnect({ owner }))}>
                Create
              </Button>
            </Stack>
          )
        }
      >
        {!status.linkingAvailable ? (
          <Nothing>This deployment keeps no state in Kubernetes, so a link would not survive a restart.</Nothing>
        ) : (
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Facts
              items={[
                { label: "App", value: app ? appLink(app.appSlug, app.htmlUrl) : "not created" },
                { label: "Created under", value: app?.owner },
                { label: "Connected", value: app ? since(app.connectedAt, app.connectedBy) : undefined },
                { label: "Linked", value: app ? String(linked) : undefined },
                { label: "Not counting", value: app && attention ? String(attention) : undefined },
                { label: "Send people to", value: app ? <CopyLine value={linkPage(status.linkUrl)} /> : undefined },
              ]}
            />
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1.5 }}>
              Public, reads a person&apos;s own email addresses and nothing else, installed nowhere. The organisation it is created under only
              hosts it.
            </Typography>
          </Paper>
        )}
      </Section>

      <Section title="Organisation Apps" hint="one per organisation, installed on it">
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Organisation</TableCell>
                <TableCell>Team App</TableCell>
                <TableCell>State</TableCell>
                <TableCell>Connected</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {status.organisations.map((org) => {
                const c = org.connection;
                return (
                  <TableRow key={org.org} hover>
                    <TableCell>
                      <Ref to={paths.githubOrganisation(org.org)} mono>
                        {org.org}
                      </Ref>
                    </TableCell>
                    <TableCell>{c ? appLink(c.appSlug, c.htmlUrl) : "—"}</TableCell>
                    <TableCell>
                      <Typography variant="body2">{!c ? "not created" : c.installed ? "installed" : "created, not installed"}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {c ? since(c.connectedAt, c.connectedBy) : "—"}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">
                      {!operator ? null : !c ? (
                        <Tooltip title={!org.bound ? "Bind the organisation's teams in the policy first." : "Two clicks by the organisation's owner: create, then install."}>
                          <span>
                            <Button
                              size="small"
                              variant="outlined"
                              disabled={busy || !org.bound || !status.connectingAvailable}
                              onClick={() => void leave(() => github.beginGitHubConnect({ org: org.org }))}
                            >
                              Create
                            </Button>
                          </span>
                        </Tooltip>
                      ) : (
                        <Stack direction="row" sx={{ gap: 1, justifyContent: "flex-end" }}>
                          {!c.installed ? (
                            <Button size="small" variant="outlined" disabled={busy} onClick={() => void leave(() => github.beginGitHubConnect({ org: org.org }))}>
                              Finish installing
                            </Button>
                          ) : null}
                          <Tooltip title="Uninstall the App and forget the organisation. Its teams stop being managed; nobody is removed.">
                            <span>
                              <Button size="small" color="warning" disabled={busy} onClick={() => void disconnectOrganisation(org.org)}>
                                Disconnect
                              </Button>
                            </span>
                          </Tooltip>
                        </Stack>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      </Section>

      {runnerRows.length ? (
        <Section title="Runner Apps" hint="one per organisation per tier, for its self-hosted runners">
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Organisation</TableCell>
                  <TableCell>Tier</TableCell>
                  <TableCell>Runner App</TableCell>
                  <TableCell>State</TableCell>
                  <TableCell>Connected</TableCell>
                  <TableCell />
                </TableRow>
              </TableHead>
              <TableBody>
                {runnerRows.map(({ org, tier, app: r, declared, bound: isBound }) => (
                  <TableRow key={`${org}/${tier}`} hover>
                    <TableCell>
                      <Ref to={paths.githubOrganisation(org)} mono>
                        {org}
                      </Ref>
                    </TableCell>
                    <TableCell>
                      <Mono>{tier}</Mono>
                    </TableCell>
                    <TableCell>{r ? appLink(r.appSlug, r.htmlUrl) : "—"}</TableCell>
                    <TableCell>
                      <Typography variant="body2">{!r ? "not created" : r.installed ? "installed" : "created, not installed"}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {r ? since(r.connectedAt, r.connectedBy) : "—"}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">
                      {!operator ? null : !r ? (
                        <Tooltip title={!isBound ? "Bind the organisation's teams in the policy first." : "Two clicks by the organisation's owner: create, then install."}>
                          <span>
                            <Button
                              size="small"
                              variant="outlined"
                              disabled={busy || !isBound || !declared}
                              onClick={() => void leave(() => github.beginGitHubRunnerAppConnect({ org, tier }))}
                            >
                              Create
                            </Button>
                          </span>
                        </Tooltip>
                      ) : (
                        <Stack direction="row" sx={{ gap: 1, justifyContent: "flex-end" }}>
                          {!r.installed && declared ? (
                            <Button size="small" variant="outlined" disabled={busy} onClick={() => void leave(() => github.beginGitHubRunnerAppConnect({ org, tier }))}>
                              Finish installing
                            </Button>
                          ) : null}
                          <Tooltip title="Uninstall the App and forget its key. Runners registered with it stop getting jobs.">
                            <span>
                              <Button size="small" color="warning" disabled={busy} onClick={() => void disconnectRunnerApp(org, tier)}>
                                Disconnect
                              </Button>
                            </span>
                          </Tooltip>
                        </Stack>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Section>
      ) : null}

      {status.catalogueAvailable && status.catalogueApps.length ? (
        <Section title="Catalogue" hint="Apps the deployment declares as data, each created and installed from its own page">
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Stack direction="row" sx={{ gap: 3, flexWrap: "wrap", alignItems: "center" }}>
              <Count label="Declared" value={status.catalogueApps.filter((a) => a.declared).length} />
              <Count label="Installed" value={status.catalogueApps.filter((a) => a.state === "installed").length} />
              <Count label="Differ on GitHub" value={status.catalogueApps.filter((a) => a.state === "drifted").length} strong />
              <Box sx={{ flexGrow: 1 }} />
              <Ref to={paths.githubCatalogue()}>Open the catalogue</Ref>
            </Stack>
          </Paper>
        </Section>
      ) : null}

      {links.length ? (
        <Section title="Linked accounts" hint={`${linked} linked${attention ? `, ${attention} not counting` : ""}`}>
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>GitHub</TableCell>
                  <TableCell>Work addresses</TableCell>
                  <TableCell>How</TableCell>
                  <TableCell>State</TableCell>
                  <TableCell>Checked</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {links.map((l) => (
                  <TableRow key={String(l.accountId)} hover>
                    <TableCell>{loginCell(l.login)}</TableCell>
                    <TableCell>
                      <Names items={l.emails.map((email) => ({ label: email, to: paths.person(email), mono: true }))} empty="—" />
                    </TableCell>
                    <TableCell>
                      <Tooltip title={l.note || "They authorized the link App; checked on GitHub every pass."}>
                        <Typography variant="body2" component="span">
                          {sourceName(l.source)}
                        </Typography>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <State kind={linkKind(l.state)} title={l.reason || undefined} />
                    </TableCell>
                    <TableCell>{at(l.checkedAt) ? ago(at(l.checkedAt)) : "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Section>
      ) : null}
    </Page>
  );
}

// --------------------------------------------------------------- catalogue

/** Every App the catalogue declares, one row each: what it is and where it
 *  stands. Its permissions, grants and actions are on its own page, so a
 *  long catalogue stays a list. */
function CataloguePage({ status }: { status: GetGitHubStatusResponse }) {
  const apps = status.catalogueApps;
  return (
    <Page
      title="Catalogue"
      lede={
        <>
          GitHub Apps declared in the deployment&apos;s values (<Mono>githubApps.catalogue</Mono>). Each is created and installed by an owner of its
          organisation in two clicks, and this service keeps its key. Back to <Ref to={paths.githubApps()}>Apps</Ref>.
        </>
      }
    >
      {!status.catalogueAvailable ? (
        <Nothing>This deployment keeps no state in Kubernetes, so an App&apos;s key would not survive a restart.</Nothing>
      ) : apps.length === 0 ? (
        <Nothing>The catalogue declares no App. Declare one in githubApps.catalogue and roll the service out.</Nothing>
      ) : (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>App</TableCell>
                <TableCell>Organisation</TableCell>
                <TableCell>State</TableCell>
                <TableCell>Installed on</TableCell>
                <TableCell align="right">Permissions</TableCell>
                <TableCell align="right">Grants</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {apps.map((app) => (
                <TableRow key={app.id} hover>
                  <TableCell>
                    <Ref to={paths.githubCatalogueApp(app.id)} mono>
                      {app.id}
                    </Ref>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                      {app.declared ? app.description || app.name : "no longer declared"}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Mono>{app.org}</Mono>
                  </TableCell>
                  <TableCell>
                    <State kind={catalogueKind(app.state)} title={app.reason || undefined} />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">{scopeName(app.repositorySelection || app.installation)}</Typography>
                  </TableCell>
                  <TableCell align="right">{app.permissions.filter((p) => p.declared).length}</TableCell>
                  <TableCell align="right">{app.grants.length}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Page>
  );
}

/** One catalogue App: what it may do beside what GitHub holds, who may ask
 *  for its tokens, and the two clicks that create and install it. */
function CatalogueAppPage({ app, operator, onDone, reload }: Props & { app: GitHubCatalogueApp; reload: () => void }) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const [checked, setChecked] = useState<GitHubCatalogueApp | undefined>();
  const shown = checked && checked.id === app.id ? checked : app;
  const settings = settingsURL(shown);
  const drifted = shown.state === "drifted";

  const act = async (work: () => Promise<void>) => {
    setBusy(true);
    setFailure(undefined);
    try {
      await work();
    } catch (error) {
      setFailure(reason(error));
    } finally {
      setBusy(false);
    }
  };
  const begin = () =>
    act(async () => {
      const started = await github.beginGitHubCatalogueAppConnect({ id: app.id });
      if (started.manifest) postManifest(started.url, started.manifest);
      else window.location.href = started.url;
    });
  const recheck = () =>
    act(async () => {
      const answer = await github.checkGitHubCatalogueApp({ id: app.id });
      setChecked(answer.app);
    });
  const disconnect = () =>
    act(async () => {
      const gone = await github.disconnectGitHubCatalogueApp({ id: app.id });
      onDone(
        `${app.id} is disconnected${gone.uninstalled ? " and uninstalled" : `. ${gone.detail}`}. The App itself stays on GitHub${
          gone.appSettingsUrl ? `; its owner deletes it at ${gone.appSettingsUrl}` : ""
        }.`,
      );
      setChecked(undefined);
      reload();
    });

  const actions = !operator ? null : (
    <>
      {shown.state === "not_created" && shown.declared ? (
        <Tooltip title={`Two clicks by an owner of ${shown.org}: create, then install.`}>
          <span>
            <Button size="small" variant="outlined" disabled={busy} onClick={() => void begin()}>
              Create
            </Button>
          </span>
        </Tooltip>
      ) : null}
      {shown.state === "created" && shown.declared ? (
        <Button size="small" variant="outlined" disabled={busy} onClick={() => void begin()}>
          Install
        </Button>
      ) : null}
      {shown.state !== "not_created" && shown.declared ? (
        <Tooltip title="Ask GitHub again now, rather than show what it said in the last minute.">
          <span>
            <Button size="small" disabled={busy} onClick={() => void recheck()}>
              Re-check
            </Button>
          </span>
        </Tooltip>
      ) : null}
      {shown.state !== "not_created" ? (
        <Tooltip title="Uninstall the App and forget its key here. The App stays on GitHub for its owner to delete; nothing minted from it works once uninstalled.">
          <span>
            <Button size="small" color="warning" disabled={busy} onClick={() => void disconnect()}>
              Disconnect
            </Button>
          </span>
        </Tooltip>
      ) : null}
    </>
  );

  return (
    <Page
      title={shown.id}
      mono
      lede={shown.description || `A GitHub App in ${shown.org}, declared in the catalogue.`}
      actions={actions}
      facts={[
        { label: "State", value: <State kind={catalogueKind(shown.state)} /> },
        { label: "Organisation", value: <Mono>{shown.org}</Mono> },
        { label: "Name on GitHub", value: shown.appSlug ? appLink(shown.appSlug, shown.htmlUrl) : <Mono>{shown.name}</Mono> },
        { label: "Visibility", value: shown.declared ? (shown.public ? "public: any account may install it" : "private: installs only on its organisation") : undefined },
        {
          label: "Installed on",
          value: shown.declared ? `${scopeName(shown.installation)} declared${shown.repositorySelection ? `, ${scopeName(shown.repositorySelection)} on GitHub` : ""}` : undefined,
        },
        { label: "Created", value: shown.appSlug ? since(shown.connectedAt, shown.connectedBy) : undefined },
        { label: "Checked", value: at(shown.checkedAt) ? ago(at(shown.checkedAt)) : undefined },
      ]}
    >
      <Stack sx={{ gap: 2, mb: 4 }}>
        <Failure error={failure} />
        {shown.reason ? <Alert severity="warning">{shown.reason}</Alert> : null}
        {drifted ? (
          <Alert severity="warning">
            <strong>GitHub differs from the catalogue.</strong> GitHub has no API to change an App&apos;s permissions or events, so an owner of{" "}
            {shown.org} edits them{" "}
            {settings ? (
              <a href={settings} target="_blank" rel="noreferrer">
                in the App&apos;s settings
              </a>
            ) : (
              "in the App's settings"
            )}{" "}
            — or the catalogue changes to match — and then Re-check.
            <Box component="ul" sx={{ mt: 1, mb: 0, pl: 3 }}>
              {shown.drift.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </Box>
          </Alert>
        ) : null}
      </Stack>

      <Section title="Permissions" hint={shown.state === "not_created" ? "what the App will ask for" : "declared, beside what the App and its installation hold on GitHub"}>
        {shown.permissions.length === 0 ? (
          <Nothing>No permission is declared or held.</Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Permission</TableCell>
                  <TableCell>Declared</TableCell>
                  {shown.state !== "not_created" ? <TableCell>App</TableCell> : null}
                  {shown.installationId ? <TableCell>Installation</TableCell> : null}
                </TableRow>
              </TableHead>
              <TableBody>
                {shown.permissions.map((p) => {
                  const differs = shown.state !== "not_created" && p.app !== p.declared && !(p.name === "metadata" && !p.declared && p.app === "read");
                  return (
                    <TableRow key={p.name} hover>
                      <TableCell>
                        <Mono>{p.name}</Mono>
                      </TableCell>
                      <TableCell>{p.declared || "—"}</TableCell>
                      {shown.state !== "not_created" ? (
                        <TableCell>
                          <Typography variant="body2" color={differs ? "warning.main" : undefined} sx={{ fontWeight: differs ? 600 : undefined }}>
                            {p.app || "—"}
                          </Typography>
                        </TableCell>
                      ) : null}
                      {shown.installationId ? (
                        <TableCell>
                          <Typography variant="body2" color={p.installation !== p.app ? "warning.main" : undefined}>
                            {p.installation || "—"}
                          </Typography>
                        </TableCell>
                      ) : null}
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        )}
        {shown.events.length ? (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Events: <Mono>{shown.events.join(", ")}</Mono> — the webhook stays inactive.
          </Typography>
        ) : null}
      </Section>

      {shown.declared ? (
        <Section title="Grants" hint="who may ask for a token of this App, for which repositories, and at most with what">
          {shown.grants.length === 0 ? (
            <Nothing>No group may ask for a token of this App.</Nothing>
          ) : (
            <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Group</TableCell>
                    <TableCell>Repositories</TableCell>
                    <TableCell>At most</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {shown.grants.map((grant, i) => (
                    <TableRow key={`${grant.group}:${i}`} hover>
                      <TableCell>
                        <Ref to={paths.group(grant.group)} mono>
                          {grant.group}
                        </Ref>
                        {!grant.groupDeclared ? (
                          <Typography variant="caption" color="warning.main" sx={{ display: "block" }}>
                            the policy declares no such group
                          </Typography>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <Mono>{grant.repositories.map((r) => (r === "*" ? `every repository in ${shown.org}` : r)).join(", ")}</Mono>
                      </TableCell>
                      <TableCell>
                        <Mono>
                          {Object.entries(grant.permissions)
                            .sort(([a], [b]) => a.localeCompare(b))
                            .map(([name, level]) => `${name}: ${level}`)
                            .join(", ")}
                        </Mono>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Section>
      ) : null}

      {shown.installationId ? (
        <Section title="Where the key is" hint="for a deployment copying it, for example with an External Secrets PushSecret">
          <Facts
            items={[
              { label: "Secret", value: <Mono>{"<release>-github-catalogue-apps"}</Mono> },
              {
                label: "Keys",
                value: <Mono>{["github_app_id", "github_app_installation_id", "github_app_private_key", "record.json"].map((k) => `${shown.id}.${k}`).join(", ")}</Mono>,
              },
              { label: "App id", value: String(shown.appId) },
              { label: "Installation id", value: String(shown.installationId) },
            ]}
          />
        </Section>
      ) : null}
    </Page>
  );
}

function catalogueKind(state: string): StateKind {
  switch (state) {
    case "installed":
      return "installed";
    case "created":
      return "created";
    case "drifted":
      return "drifted";
    default:
      return "not-created";
  }
}

function scopeName(scope: string): string {
  return ({ all: "all repositories", selected: "selected repositories" } as Record<string, string>)[scope] ?? scope;
}

/** Where an owner edits the App: the organisation's settings page for it,
 *  which is also where it is deleted. */
function settingsURL(app: GitHubCatalogueApp): string {
  return app.appSlug ? `https://github.com/organizations/${encodeURIComponent(app.org)}/settings/apps/${encodeURIComponent(app.appSlug)}` : "";
}

// ----------------------------------------------------------------- helpers

/** One row per bound organisation per declared tier, plus any App created
 * for a tier or an organisation no longer declared or bound, so it can
 * still be disconnected. */
function runnerAppRows(status: GetGitHubStatusResponse) {
  const rows = new Map<string, { org: string; tier: string; app?: GitHubRunnerApp; declared: boolean; bound: boolean }>();
  const bound = new Set(status.organisations.filter((org) => org.bound).map((org) => org.org));
  for (const org of [...bound].sort()) {
    for (const tier of status.runnerTiers) rows.set(`${org}/${tier}`, { org, tier, declared: true, bound: true });
  }
  for (const app of status.runnerApps) {
    const key = `${app.org}/${app.tier}`;
    const row = rows.get(key) ?? { org: app.org, tier: app.tier, declared: status.runnerTiers.includes(app.tier), bound: bound.has(app.org) };
    rows.set(key, { ...row, app });
  }
  return [...rows.values()].sort((a, b) => a.org.localeCompare(b.org) || a.tier.localeCompare(b.tier));
}

export function sourceName(source: string): string {
  return ({ self: "linked by them", profile: "public profile", imported: "imported" } as Record<string, string>)[source] ?? source;
}

export function linkKind(state: string): StateKind {
  switch (state) {
    case "linked":
      return "ok";
    case "unverifiable":
      return "their-move";
    case "lost":
      return "lost";
    default:
      return "unknown";
  }
}

function outcome(org: GitHubOrganisation) {
  if (!org.reported) return <State kind="unreported" />;
  const kind = org.tick?.outcome as StateKind | undefined;
  return kind ? <State kind={kind} /> : <State kind="unreported" />;
}

function appLink(slug: string, url: string) {
  return url ? (
    <a href={url} target="_blank" rel="noreferrer">
      <Mono>{slug}</Mono>
    </a>
  ) : (
    <Mono>{slug}</Mono>
  );
}

export function loginCell(login: string) {
  return login ? (
    <a href={`https://github.com/${login}`} target="_blank" rel="noreferrer">
      <Mono>{login}</Mono>
    </a>
  ) : (
    <Typography variant="body2" color="text.secondary">
      not linked
    </Typography>
  );
}

function since(connectedAt: Parameters<typeof at>[0], by: string): string {
  const when = at(connectedAt);
  return [when ? ago(when) : "", by ? `by ${by}` : ""].filter(Boolean).join(" ");
}

export function CopyLine({ value }: { value: string }) {
  return (
    <Stack direction="row" sx={{ alignItems: "center", gap: 0.5, minWidth: 0 }}>
      <Box component="a" href={value} target="_blank" rel="noreferrer" sx={{ minWidth: 0, overflowWrap: "anywhere" }}>
        <Mono>{value}</Mono>
      </Box>
      <CopyIcon value={value} />
    </Stack>
  );
}

function CopyIcon({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Tooltip title={copied ? "Copied" : "Copy"}>
      <IconButton size="small" aria-label="copy" onClick={() => void navigator.clipboard.writeText(value).then(() => setCopied(true))}>
        <ContentCopyIcon fontSize="inherit" />
      </IconButton>
    </Tooltip>
  );
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button size="small" variant="outlined" startIcon={<ContentCopyIcon fontSize="inherit" />} onClick={() => void navigator.clipboard.writeText(value).then(() => setCopied(true))}>
      {copied ? "Copied" : label}
    </Button>
  );
}

/** GitHub creates an App only from a manifest POSTed by the browser, so
 *  this is a form, submitted once, rather than a link. */
function postManifest(action: string, manifest: string) {
  const form = document.createElement("form");
  form.method = "post";
  form.action = action;
  const field = document.createElement("input");
  field.type = "hidden";
  field.name = "manifest";
  field.value = manifest;
  form.appendChild(field);
  document.body.appendChild(form);
  form.submit();
}
