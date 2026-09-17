import { useState, type ReactNode } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Collapse from "@mui/material/Collapse";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogContentText from "@mui/material/DialogContentText";
import DialogTitle from "@mui/material/DialogTitle";
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
import type { GetGitHubStatusResponse, GitHubAppGrant, GitHubOrganisation, ListGitHubAppsResponse } from "./gen/directoryroster/v1/github_pb";
import {
  appsNeedingYou,
  appView,
  atMost,
  countLabels,
  feedsOnlyItself,
  fixSentence,
  groupApps,
  labelOf,
  linkPage,
  organisationNeeds,
  ownerRule,
  peopleOf,
  permissionDiffers,
  purposeWords,
  recentTokensEmpty,
  recentTokensKept,
  recentTokensProblem,
  repositoryWords,
  rowsOf,
  sentence,
  summaryOf,
  tooltipOf,
  type GitHubAppView,
  type Row,
} from "./githubModel";
import { useAsync } from "./hooks";
import { go, paths } from "./router";
import { Facts, Failure, Loading, Mono, Names, Nothing, Page, Ref, Rows, Section, ShortNames, State, type StateKind } from "./ui";

type Props = { operator: boolean; onDone: (message: string) => void };

/** GitHub, as tabs: what needs attention across every organisation, each
 *  organisation and its teams, and the Apps behind it all.
 *
 *  Two calls feed every tab — the organisations and their reports, and the
 *  Apps — so moving between them never waits, and neither answer is
 *  derived from the other. */
export function GitHubPage({ section, rest, operator, onDone }: Props & { section?: string; rest: string[] }) {
  const status = useAsync(() => github.getGitHubStatus({}), []);
  const listed = useAsync(() => github.listGitHubApps({}), []);
  const tab = section === "organisations" ? "organisations" : section === "apps" ? "apps" : "overview";
  const value = status.value;
  const catalogue = listed.value;
  const apps = (catalogue?.apps ?? []).map(appView);
  const reload = () => {
    status.reload();
    listed.reload();
  };

  let body: ReactNode = null;
  if (value && catalogue) {
    if (tab === "organisations" && rest[0]) {
      const org = value.organisations.find((o) => o.org === rest[0]);
      body = !org ? (
        <Nothing>No organisation {rest[0]} is bound or reported.</Nothing>
      ) : rest[1] === "teams" && rest[2] ? (
        <TeamPage org={org} team={rest[2]} />
      ) : (
        <OrganisationPage org={org} apps={apps} operator={operator} onDone={onDone} reload={reload} />
      );
    } else if (tab === "organisations") {
      body = <OrganisationsList status={value} apps={apps} />;
    } else if (tab === "apps" && rest[0]) {
      const app = apps.find((a) => a.id === rest[0]);
      body = app ? (
        <AppPage key={app.id} app={app} listed={catalogue} status={value} operator={operator} onDone={onDone} reload={reload} />
      ) : (
        <Nothing>
          No App {rest[0]} is declared or created here. Every App is on the <Ref to={paths.githubApps()}>Apps</Ref> tab.
        </Nothing>
      );
    } else if (tab === "apps") {
      body = <AppsList listed={catalogue} apps={apps} />;
    } else {
      body = <Overview status={value} apps={apps} />;
    }
  }

  return (
    <Box>
      <Tabs
        value={tab}
        onChange={(_, next: string) => go(next === "overview" ? paths.github() : next === "apps" ? paths.githubApps() : paths.githubOrganisations())}
        variant="scrollable"
        allowScrollButtonsMobile
        sx={{ mb: 3 }}
      >
        <Tab value="overview" label="Overview" />
        <Tab value="organisations" label="Organisations" />
        <Tab value="apps" label="Apps" />
      </Tabs>
      <Loading busy={status.loading || listed.loading} />
      <Failure error={status.error ?? listed.error} />
      {value && !value.reportsAvailable ? (
        <Nothing>This deployment keeps no state in Kubernetes, so a controller has nowhere to report: only the bindings are shown.</Nothing>
      ) : null}
      {body}
    </Box>
  );
}

// ---------------------------------------------------------------- overview

/** What the Apps that need you are waiting for, counted by the fix. */
function appNeedsWords(apps: GitHubAppView[]): string {
  const count = (fix: GitHubAppView["fix"]) => apps.filter((app) => app.fix === fix).length;
  return [
    count("create") && `${count("create")} not created`,
    count("install") && `${count("install")} not installed`,
    count("recheck") && `${count("recheck")} differing on GitHub`,
    count("disconnect") && `${count("disconnect")} no longer declared`,
  ]
    .filter(Boolean)
    .join(", ");
}

function Overview({ status, apps }: { status: GetGitHubStatusResponse; apps: GitHubAppView[] }) {
  const people = peopleOf(status.organisations);
  const waiting = people.filter((p) => p.label === "their-move");
  const needs = status.organisations.flatMap((org) => [
    ...organisationNeeds(org).map((what) => ({ org: org.org, what })),
    ...rowsOf(org)
      .filter((row) => labelOf(row.member.state) === "needs-you")
      .map((row) => ({ org: org.org, what: `${row.member.email || row.member.login}: ${row.member.reason}` })),
  ]);
  const appsNeeding = apps.filter((app) => app.label === "needs-you");
  const dryRun = status.organisations.filter((org) => org.bound && org.connection?.installed && !org.enabled);

  let next: ReactNode;
  if (appsNeeding.length) {
    next = (
      <>
        {appsNeeding.length} {appsNeeding.length === 1 ? "App needs" : "Apps need"} you ({appNeedsWords(appsNeeding)}): open{" "}
        {appsNeeding.length === 1 ? <Ref to={paths.githubApp(appsNeeding[0].id)}>it</Ref> : <Ref to={paths.githubApps()}>the Apps tab</Ref>}.
      </>
    );
  } else if (needs.length) {
    next = `${needs.length} ${needs.length === 1 ? "thing needs" : "things need"} you — the organisations below say what.`;
  } else if (waiting.length) {
    next = `${waiting.length} ${waiting.length === 1 ? "person has" : "people have"} not linked or accepted yet: send them the link page below.`;
  } else if (dryRun.length) {
    next = `Read ${dryRun.map((org) => org.org).join(" and ")}'s dry run, then add ${dryRun.length === 1 ? "it" : "them"} to githubRoster.actsIn.`;
  } else {
    next = "Nothing to do: every organisation matches the policy, and every App is installed as declared.";
  }

  return (
    <Page title="GitHub" lede="Who belongs in which GitHub team is the policy's; the controller makes every organisation match. This is what needs attention.">
      <Alert severity={needs.length || appsNeeding.length ? "warning" : "info"} sx={{ mb: 3 }}>
        <strong>Next:</strong> {next}
      </Alert>

      <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" }, gap: 2, mb: 4 }}>
        {status.organisations.map((org) => (
          <OrganisationCard key={org.org} org={org} apps={apps} />
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

function OrganisationCard({ org, apps }: { org: GitHubOrganisation; apps: GitHubAppView[] }) {
  const counts = countLabels(rowsOf(org).map((row) => row.member));
  const needs = organisationNeeds(org, apps);
  const own = organisationNeeds(org).length + appsNeedingYou(apps, org.org);
  return (
    <Paper variant="outlined" sx={{ p: 2, minWidth: 0 }}>
      <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "center", gap: 1, mb: 1 }}>
        <Ref to={paths.githubOrganisation(org.org)} mono>
          {org.org}
        </Ref>
        {outcome(org)}
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
        {!org.connection?.installed ? "controller App not installed" : org.enabled ? "the controller acts" : "dry run"}
        {at(org.tick?.at) ? ` · last pass ${ago(at(org.tick?.at))}` : ""}
        {org.seats?.known ? ` · ${org.seats.free} ${org.seats.free === 1 ? "seat" : "seats"} free` : ""}
      </Typography>
      <Stack direction="row" sx={{ gap: 3, flexWrap: "wrap" }}>
        <Count label="OK" value={counts.ok} />
        <Count label="Waiting for them" value={counts["their-move"]} />
        <Count label="Needs you" value={counts["needs-you"] + own} strong />
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

function OrganisationsList({ status, apps }: { status: GetGitHubStatusResponse; apps: GitHubAppView[] }) {
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
                    <TableCell align="right">{counts["needs-you"] + organisationNeeds(org).length + appsNeedingYou(apps, org.org)}</TableCell>
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

function OrganisationPage({ org, apps, operator, onDone, reload }: Props & { org: GitHubOrganisation; apps: GitHubAppView[]; reload: () => void }) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const rows = rowsOf(org);
  const acting = org.enabled;
  const changes = rows.filter((row) => row.member.action);
  const removals = changes.filter((row) => row.member.action === "remove");
  const others = rows.filter((row) => row.member.action && row.member.action !== "remove");
  const retrying = rows.filter((row) => !row.member.action && row.member.state === "retrying");
  // People, not rows: an invitation shows on the organisation's row and on
  // every team row for the same person, and is one invitation.
  const people = (state: string) => [...new Set(rows.filter((row) => row.member.state === state && row.member.email).map((row) => row.member.email))];
  const notLinked = people("not-linked");
  const invited = people("invited");
  const lapsed = people("ignored");
  const count = (action: string) =>
    new Set(changes.filter((row) => row.member.action === action).map((row) => (action === "invite" ? row.member.email : `${row.team}|${row.member.login}`))).size;
  const breaker = org.breaker;
  const seats = org.seats;
  const own = apps.filter((app) => app.org === org.org && app.purpose !== "link");

  // What the controller leaves alone here, whatever the groups say.
  const owners = [
    ...new Map(rows.filter((row) => row.member.state === "reported").map((row) => [row.member.email || row.member.login, row.member])).values(),
  ];
  const leftAlone = [
    {
      key: "owners",
      what: "Owners",
      why: ownerRule,
      items: owners.map((m) => (m.email ? { label: m.email, to: paths.person(m.email), mono: true } : { label: m.login, mono: true })),
    },
    {
      key: "ignored",
      what: "Ignored",
      why: "left alone here, whatever the groups say — declared in the policy, in git",
      items: org.ignored.map((entry) => (entry.includes("@") ? { label: entry, to: paths.person(entry), mono: true } : { label: entry, mono: true })),
    },
    {
      key: "outside",
      what: "Outside collaborators",
      why: "access to repositories without membership: reported, never managed",
      items: org.outsideCollaborators.map((account) => ({ label: account.login, mono: true })),
    },
    {
      key: "unlinked",
      what: "Members nobody linked",
      why: "in the organisation, and nobody can say who they are: never touched",
      items: org.unlinked.map((account) => ({ label: account.login, mono: true })),
    },
  ].filter((group) => group.items.length);
  const leftAloneCount = leftAlone.reduce((n, group) => n + group.items.length, 0);

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
  const waitingOn = new Set([...notLinked, ...invited, ...lapsed]).size;

  const hideFedBy = org.teams.length > 0 && org.teams.every(feedsOnlyItself);

  return (
    <Page
      title={org.org}
      mono
      lede={
        !org.reported
          ? "The controller has not reported on this organisation yet."
          : plan.length
            ? `${acting ? "This pass will" : "If enabled now, the controller would"} ${plan.join(", ")}${waitingOn ? `, and waits on ${waitingOn} ${waitingOn === 1 ? "person" : "people"}` : ""}.`
            : waitingOn
              ? `Nothing to change until ${waitingOn} ${waitingOn === 1 ? "person links or accepts" : "people link or accept"}.`
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

      {others.length || retrying.length ? (
        <Section title={acting ? "Other changes" : "Other changes it would make"} hint="invitations, team changes and roles, with anything held for you">
          <RowsTable rows={[...others, ...retrying]} acting={acting} />
        </Section>
      ) : null}

      {waitingOn ? (
        <Section title="Waiting for them" hint="only they can move these forward; send them the link page">
          <Rows
            items={[
              { key: "not-linked", what: "have not linked a GitHub account", who: notLinked },
              { key: "invited", what: "invited, and not accepted yet", who: invited },
              { key: "ignored", what: "let two invitations expire; invited again once they link again", who: lapsed },
            ].filter((group) => group.who.length)}
            keyOf={(group) => group.key}
            primary={(group) => <ShortNames items={group.who.map((email) => ({ label: email, to: paths.person(email), mono: true }))} noun={["person", "people"]} />}
            secondary={(group) => group.what}
            empty=""
          />
        </Section>
      ) : null}

      <Section title="Teams" hint={hideFedBy ? "each fed by the internal group of the same name; open one for its members" : "each fed by internal groups; open one for its members"}>
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Team</TableCell>
                {hideFedBy ? null : <TableCell>Fed by</TableCell>}
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
                    {hideFedBy ? null : (
                      <TableCell>
                        <Names items={[...team.memberGroups, ...team.maintainerGroups].map((group) => ({ label: group, to: paths.group(group), mono: true }))} empty="—" />
                      </TableCell>
                    )}
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

      <Section title="Apps" hint="installed here, or declared for it; the link App serves every organisation">
        <Rows
          items={own}
          keyOf={(app) => app.id}
          primary={(app) => (
            <Ref to={paths.githubApp(app.id)} mono>
              {app.name}
            </Ref>
          )}
          secondary={(app) => purposeWords(app)}
          right={(app) => <AppState app={app} />}
          empty="No App is installed or declared for this organisation."
        />
      </Section>

      {leftAloneCount ? (
        <Disclosure title="Left alone" hint={`${leftAloneCount} ${leftAloneCount === 1 ? "account" : "accounts"} the controller reports and never changes`}>
          <Rows
            items={leftAlone}
            keyOf={(group) => group.key}
            primary={(group) => (
              <>
                <Typography component="span" variant="body2" sx={{ fontWeight: 500 }}>
                  {group.what}:{" "}
                </Typography>
                <ShortNames items={group.items} noun={["account", "accounts"]} />
              </>
            )}
            secondary={(group) => group.why}
            empty=""
          />
        </Disclosure>
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
        {rows.length ? (
          <>
            <OwnerRule rows={rows} />
            <RowsTable rows={rows} acting={org.enabled} hideWhere />
          </>
        ) : (
          <Nothing>Nobody is wanted in this team.</Nothing>
        )}
      </Section>
    </Page>
  );
}

/** The owner rule, once, above a table that has an owner in it. */
export function OwnerRule({ rows }: { rows: Row[] }) {
  if (!rows.some((row) => row.member.state === "reported")) return null;
  return (
    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
      {ownerRule}
    </Typography>
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
              <TableCell>{row.member.state === "reported" ? "owner" : row.member.role}</TableCell>
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

/** A block of reference material, closed until asked for. */
function Disclosure({ title, hint, children }: { title: string; hint?: ReactNode; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <Section
      title={title}
      hint={hint}
      action={
        <Button size="small" onClick={() => setOpen(!open)} aria-expanded={open}>
          {open ? "Hide" : "Show"}
        </Button>
      }
    >
      <Collapse in={open} unmountOnExit>
        {children}
      </Collapse>
    </Section>
  );
}

function AppState({ app }: { app: GitHubAppView }) {
  return <State kind={app.label} title={app.exact} />;
}

/** The groups that may mint an App's tokens: names up to three, a count
 *  beyond. */
function Minters({ app }: { app: GitHubAppView }) {
  if (app.purpose !== "tokens") return <Typography variant="body2" color="text.secondary">—</Typography>;
  const groups = [...new Set(app.grants.map((grant) => grant.group))];
  if (groups.length > 3) {
    return (
      <Ref to={paths.githubApp(app.id)}>
        {groups.length} groups
      </Ref>
    );
  }
  return <Names items={groups.map((group) => ({ label: group, to: paths.group(group), mono: true }))} empty="nobody" />;
}

/** Every App in one list: the link App, then each organisation's Apps,
 *  those that need you first. What each is for is a word; what it holds
 *  and the buttons that change it are on its own page. */
function AppsList({ listed, apps }: { listed: ListGitHubAppsResponse; apps: GitHubAppView[] }) {
  const groups = groupApps(apps);
  return (
    <Page
      title="Apps"
      lede="Every GitHub App this service keeps a key for, or is declared to: the link App people authorize, one App per organisation the controller manages teams through, one per organisation per runner tier, and the Apps declared in the catalogue that mint tokens for internal groups. Open one to create, install, re-check or disconnect it."
    >
      {groups.length === 0 ? (
        <Nothing>No App is declared or created. Bind an organisation in the policy, or declare an App in githubApps.catalogue.</Nothing>
      ) : (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small" sx={{ minWidth: 640 }}>
            <TableHead>
              <TableRow>
                <TableCell>App</TableCell>
                <TableCell>Purpose</TableCell>
                <TableCell>State</TableCell>
                <TableCell>Repositories</TableCell>
                <TableCell>Who may mint</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {groups.map((group) => [
                <TableRow key={`org:${group.org}`}>
                  <TableCell colSpan={5} sx={{ bgcolor: "action.hover", py: 0.75 }}>
                    {group.org ? (
                      <Ref to={paths.githubOrganisation(group.org)} mono>
                        {group.org}
                      </Ref>
                    ) : (
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>
                        Every organisation
                      </Typography>
                    )}
                  </TableCell>
                </TableRow>,
                ...group.apps.map((app) => (
                  <TableRow key={app.id} hover>
                    <TableCell>
                      <Ref to={paths.githubApp(app.id)} mono>
                        {app.name}
                      </Ref>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{purposeWords(app)}</Typography>
                    </TableCell>
                    <TableCell>
                      <AppState app={app} />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{app.repositories}</Typography>
                    </TableCell>
                    <TableCell>
                      <Minters app={app} />
                    </TableCell>
                  </TableRow>
                )),
              ])}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      {!listed.catalogueAvailable ? (
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
          This deployment keeps no state in Kubernetes, so it keeps no catalogue Apps: their keys would not survive a restart.
        </Typography>
      ) : null}
    </Page>
  );
}

/** What disconnecting an App does, said before it is done. */
function consequence(app: GitHubAppView): string {
  const stays = "The App itself stays on GitHub, for an owner to delete in its settings.";
  switch (app.purpose) {
    case "link":
      return `Forgets the link App. Every link made through it becomes unverifiable: nobody is added or removed on its account until they link again. ${stays}`;
    case "controller":
      return `Uninstalls it from ${app.org} and forgets its key. The organisation's teams stop being managed; nobody is removed. ${stays}`;
    case "runners":
      return `Uninstalls it from ${app.org} and forgets its key. The ${app.tier} runners registered with it stop getting jobs. ${stays}`;
    default:
      return `Uninstalls it from ${app.org} and forgets its key here: no token can be minted from it any more. ${stays}`;
  }
}

/** One App, whatever made it: what it is for, where it stands, the one fix
 *  it needs, and the buttons that act on it. */
function AppPage({
  app,
  listed,
  status,
  operator,
  onDone,
  reload,
}: Props & { app: GitHubAppView; listed: ListGitHubAppsResponse; status: GetGitHubStatusResponse; reload: () => void }) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const [checked, setChecked] = useState<GitHubAppView | undefined>();
  const [asking, setAsking] = useState(false);
  const bound = listed.boundOrganisations;
  const [owner, setOwner] = useState(bound[0] ?? "");
  const shown = checked ?? app;
  const org = status.organisations.find((o) => o.org === shown.org);

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

  // One call for each of the three, whichever kind of App this is: the
  // server knows from the id which flow it is, and starts the same one
  // the per-kind call always did.
  const begin = () =>
    act(async () => {
      const started = await github.beginGitHubAppConnect({ id: shown.id, owner });
      if (started.manifest) postManifest(started.url, started.manifest);
      else window.location.href = started.url;
    });

  const recheck = () =>
    act(async () => {
      const answer = await github.checkGitHubApp({ id: shown.id });
      if (answer.app) setChecked(appView(answer.app));
    });

  const disconnect = () =>
    act(async () => {
      setAsking(false);
      const settings = (url: string) => (url ? ` An owner deletes the App itself at ${url}.` : "");
      const gone = await github.disconnectGitHubApp({ id: shown.id });
      if (shown.purpose === "link") {
        onDone(`The link App is disconnected; ${gone.invalidated} links wait for their people to link again.${settings(gone.appSettingsUrl)}`);
      } else {
        onDone(`${shown.name} is disconnected${gone.uninstalled ? " and uninstalled" : `. ${gone.detail}`}.${settings(gone.appSettingsUrl)}`);
      }
      setChecked(undefined);
      reload();
    });

  const canCreate =
    shown.purpose === "link"
      ? listed.linkingAvailable && bound.length > 0
      : shown.purpose === "controller"
        ? listed.connectingAvailable && shown.declared
        : shown.declared;

  const actions = !operator ? null : (
    <>
      {shown.fix === "create" && shown.purpose === "link" && canCreate ? (
        <TextField select size="small" label="Under" value={owner} onChange={(event) => setOwner(event.target.value)} disabled={busy} sx={{ minWidth: 140 }}>
          {bound.map((o) => (
            <MenuItem key={o} value={o}>
              {o}
            </MenuItem>
          ))}
        </TextField>
      ) : null}
      {shown.fix === "create" ? (
        <Tooltip
          title={
            canCreate
              ? shown.purpose === "link"
                ? "One click by an owner of the organisation it is created under; it is installed nowhere."
                : `Two clicks by an owner of ${shown.org}: create, then install.`
              : shown.declared
                ? "This deployment keeps no state in Kubernetes, so the App's key would not survive a restart."
                : "The deployment no longer declares it."
          }
        >
          <span>
            <Button size="small" variant="contained" disabled={busy || !canCreate || (shown.purpose === "link" && !owner)} onClick={() => void begin()}>
              Create
            </Button>
          </span>
        </Tooltip>
      ) : null}
      {shown.fix === "install" ? (
        <Button size="small" variant="contained" disabled={busy} onClick={() => void begin()}>
          Install
        </Button>
      ) : null}
      {shown.purpose !== "link" && shown.stage !== "not-created" && shown.declared ? (
        <Tooltip title="Ask GitHub again now, rather than show what it said in the last minute.">
          <span>
            <Button size="small" variant={shown.fix === "recheck" ? "contained" : "text"} disabled={busy} onClick={() => void recheck()}>
              Re-check
            </Button>
          </span>
        </Tooltip>
      ) : null}
      {shown.stage !== "not-created" ? (
        <Button size="small" color="warning" disabled={busy} onClick={() => setAsking(true)}>
          Disconnect
        </Button>
      ) : null}
    </>
  );

  const needsYou = shown.label === "needs-you";
  const permissions = shown.permissions;
  const drifted = permissions.some(permissionDiffers);

  return (
    <Page
      title={shown.name}
      mono={shown.stage !== "not-created"}
      lede={summaryOf(shown)}
      actions={actions}
      facts={[
        { label: "State", value: <AppState app={shown} /> },
        {
          label: shown.purpose === "link" ? "Created under" : "Organisation",
          value: shown.org ? (
            <Ref to={paths.githubOrganisation(shown.org)} mono>
              {shown.org}
            </Ref>
          ) : undefined,
        },
        { label: "Purpose", value: purposeWords(shown) },
        { label: "Repositories", value: shown.repositories },
        { label: "On GitHub", value: shown.slug ? appLink(shown.slug, shown.htmlUrl) : undefined },
        { label: "Created", value: shown.slug ? since(shown.connectedAt, shown.connectedBy) : undefined },
        { label: "Checked", value: at(shown.checkedAt) ? ago(at(shown.checkedAt)) : undefined },
      ]}
    >
      <Stack sx={{ gap: 2, mb: 4 }}>
        <Failure error={failure} />
        {needsYou ? (
          <Alert severity="warning">
            <strong>Needs you.</strong> {fixSentence(shown)}{" "}
            {shown.fix === "recheck" && shown.settingsUrl ? (
              <a href={shown.settingsUrl} target="_blank" rel="noreferrer">
                Open its settings on GitHub.
              </a>
            ) : null}
            {!operator && shown.fix !== "none" ? " An operator does this." : null}
            {shown.drift.length ? (
              <Box component="ul" sx={{ mt: 1, mb: 0, pl: 3 }}>
                {shown.drift.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </Box>
            ) : null}
          </Alert>
        ) : null}
        {shown.label === "waiting-person" || shown.label === "waiting-controller" ? <Alert severity="info">Nothing to do here: {shown.exact}.</Alert> : null}
        {shown.reason ? <Alert severity="warning">{shown.reason}</Alert> : null}
      </Stack>

      {shown.purpose === "tokens" ? (
        <Section title="Who may mint tokens" hint="each internal group, the repositories it may ask for, and the most a token may carry">
          <Rows
            items={shown.grants.map((grant, i) => ({ grant, i }))}
            keyOf={({ grant, i }) => `${grant.group}:${i}`}
            primary={({ grant }) => (
              <>
                <Ref to={paths.group(grant.group)} mono>
                  {grant.group}
                </Ref>
                {!grant.groupDeclared ? (
                  <Typography component="span" variant="caption" color="warning.main">
                    {" "}
                    the policy declares no such group
                  </Typography>
                ) : null}
              </>
            )}
            secondary={({ grant }) => <GrantLine grant={grant} org={shown.org} />}
            empty="No internal group may mint tokens of this App."
          />
        </Section>
      ) : null}

      {shown.purpose === "tokens" && operator && shown.installationId ? <RecentTokens id={shown.id} /> : null}

      {shown.purpose === "controller" ? (
        <Section title="Acts on" hint="the organisation whose members and teams the controller manages through it">
          <Rows
            items={org ? [org] : []}
            keyOf={(o) => o.org}
            primary={(o) => (
              <Ref to={paths.githubOrganisation(o.org)} mono>
                {o.org}
              </Ref>
            )}
            secondary={(o) => `${o.teams.length} ${o.teams.length === 1 ? "team" : "teams"}${at(o.tick?.at) ? ` · last pass ${ago(at(o.tick?.at))}` : ""}`}
            right={(o) => outcome(o)}
            empty={`${shown.org} is not bound or reported.`}
          />
        </Section>
      ) : null}

      {shown.purpose === "runners" ? (
        <Section title="Registers runners for" hint="one App per organisation per tier, so a compromised runner plane stays in its tier">
          <Rows
            items={[shown]}
            keyOf={(a) => a.id}
            primary={(a) => (
              <Ref to={paths.githubOrganisation(a.org)} mono>
                {a.org}
              </Ref>
            )}
            secondary={(a) => `the ${a.tier} tier's runner scale sets`}
            empty=""
          />
        </Section>
      ) : null}

      {shown.purpose === "link" ? (
        <Section title="Linked accounts" hint="the accounts people linked through it; every organisation reads them">
          <Rows
            items={[
              {
                key: "linked",
                label: `${shown.linked} ${shown.linked === 1 ? "account" : "accounts"} linked`,
                to: paths.peopleGitHub(true),
                note: "open People, narrowed to those who linked",
              },
              { key: "not-linked", label: "People who have not linked", to: paths.peopleGitHub(false), note: "send them the link page below" },
            ]}
            keyOf={(item) => item.key}
            primary={(item) => <Ref to={item.to}>{item.label}</Ref>}
            secondary={(item) => item.note}
            empty=""
          />
          {shown.stage !== "not-created" ? (
            <Box sx={{ mt: 1.5 }}>
              <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                Send people to
              </Typography>
              <CopyLine value={linkPage(listed.linkUrl)} />
            </Box>
          ) : null}
        </Section>
      ) : null}

      {permissions.length ? (
        <Disclosure
          title="Permissions"
          hint={drifted ? "declared, beside what the App and its installation hold on GitHub" : shown.stage === "not-created" ? "what the App will ask for" : "declared, and held as declared"}
        >
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Permission</TableCell>
                  {drifted ? (
                    <>
                      <TableCell>Declared</TableCell>
                      <TableCell>App</TableCell>
                      {shown.installationId ? <TableCell>Installation</TableCell> : null}
                    </>
                  ) : (
                    <TableCell>Level</TableCell>
                  )}
                </TableRow>
              </TableHead>
              <TableBody>
                {permissions.map((p) => {
                  const differs = permissionDiffers(p);
                  return (
                    <TableRow key={p.name} hover>
                      <TableCell>
                        <Mono>{p.name}</Mono>
                      </TableCell>
                      {drifted ? (
                        <>
                          <TableCell>{p.declared || "—"}</TableCell>
                          <TableCell>
                            <Typography variant="body2" color={differs ? "warning.main" : undefined} sx={{ fontWeight: differs ? 600 : undefined }}>
                              {p.app || "—"}
                            </Typography>
                          </TableCell>
                          {shown.installationId ? <TableCell>{p.installation || "—"}</TableCell> : null}
                        </>
                      ) : (
                        <TableCell>{p.declared || p.app || "—"}</TableCell>
                      )}
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        </Disclosure>
      ) : null}

      {shown.events.length ? (
        <Disclosure title="Events" hint="the webhook events declared; the webhook itself stays inactive">
          <Names items={shown.events.map((event) => ({ label: event, mono: true }))} />
        </Disclosure>
      ) : null}

      <Disclosure title="Where it is kept" hint="the Kubernetes Secret its key is in, and its ids on GitHub">
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Facts
            items={[
              {
                label: "Kubernetes Secret",
                value: shown.secret ? <Mono>{shown.secret}</Mono> : "none: this deployment keeps no state in Kubernetes",
              },
              { label: "Keys in the Secret", value: shown.secretKeys.length ? <Mono>{shown.secretKeys.join(", ")}</Mono> : undefined },
              { label: "App id", value: shown.appId ? String(shown.appId) : undefined },
              { label: "Installation id", value: shown.installationId ? String(shown.installationId) : undefined },
              { label: "Declared in", value: shown.origin === "catalogue" ? (shown.declared ? "catalogue" : "catalogue, no longer") : "built in" },
            ]}
          />
        </Paper>
      </Disclosure>

      <Dialog open={asking} onClose={() => setAsking(false)}>
        <DialogTitle>Disconnect {shown.name}?</DialogTitle>
        <DialogContent>
          <DialogContentText>{consequence(shown)}</DialogContentText>
          {shown.settingsUrl ? (
            <DialogContentText sx={{ mt: 1.5 }}>
              <a href={shown.settingsUrl} target="_blank" rel="noreferrer">
                Its settings on GitHub
              </a>
            </DialogContentText>
          ) : null}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAsking(false)}>Keep it</Button>
          <Button color="warning" variant="contained" disabled={busy} onClick={() => void disconnect()}>
            Disconnect
          </Button>
        </DialogActions>
      </Dialog>
    </Page>
  );
}

/** One grant's reach, short, with every permission a click away. */
function GrantLine({ grant, org }: { grant: GitHubAppGrant; org: string }) {
  const [open, setOpen] = useState(false);
  const all = Object.entries(grant.permissions)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, level]) => `${name}: ${level}`);
  return (
    <>
      {repositoryWords(grant.repositories, org)} · at most {atMost(grant.permissions)}
      {all.length > 2 ? (
        <>
          {" "}
          <Button size="small" variant="text" onClick={() => setOpen(!open)} sx={{ textTransform: "none", p: 0, minWidth: 0, verticalAlign: "baseline", fontSize: "inherit" }}>
            {open ? "hide" : "show all"}
          </Button>
          {open ? (
            <Box sx={{ mt: 0.5 }}>
              <Mono>{all.join(", ")}</Mono>
            </Box>
          ) : null}
        </>
      ) : null}
    </>
  );
}

/** When this service started keeping the recent tokens, in words, or
 *  empty where it does not say: `ago` answers "never" for nothing, which
 *  is not what a missing answer means. */
function sinceWords(keptSince?: { seconds: bigint; nanos: number }): string {
  const when = at(keptSince);
  return when ? ago(when) : "";
}

/** The last installation tokens asked of an App, minted or refused: who
 *  asked, under which grant, for what, and what was decided. Never the
 *  token, which nothing keeps.
 *
 *  From the service's own memory of them rather than from the audit
 *  trail. The trail holds every one of them for as long as the bucket
 *  does, but narrowing it to one App scans object after object of hour
 *  after hour: this section used to ask it, wait fifteen seconds and
 *  apologise. The trail is one link away, narrowed to this App. */
function RecentTokens({ id }: { id: string }) {
  const recent = useAsync(() => github.listGitHubAppTokens({ id }), [id]);
  const tokens = recent.value?.tokens ?? [];
  const trail = (
    <Ref to={paths.audit({ kind: "github.token.minted", target: `github-app:${id}` })}>Audit</Ref>
  );
  return (
    <Section title="Recent tokens" hint="the last ten asked for, minted or refused; tokens themselves are never kept">
      <Loading busy={recent.loading} />
      {recent.error ? (
        <Nothing>
          {recentTokensProblem(recent.error)} The {trail} page holds every token asked for.
        </Nothing>
      ) : null}
      {!recent.loading && !recent.error && tokens.length === 0 ? (
        <Nothing>
          {recentTokensEmpty(sinceWords(recent.value?.keptSince))} The {trail} page holds every token asked for, however long ago.
        </Nothing>
      ) : null}
      {tokens.length > 0 ? (
        <>
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>When</TableCell>
                  <TableCell>By</TableCell>
                  <TableCell>Repositories</TableCell>
                  <TableCell>Permissions</TableCell>
                  <TableCell>Outcome</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {tokens.map((token, i) => (
                  <TableRow key={`${at(token.at)?.toISOString() ?? i}-${i}`} hover>
                    <TableCell sx={{ whiteSpace: "nowrap" }}>
                      <Tooltip title={at(token.at)?.toISOString() ?? ""}>
                        <span>{ago(at(token.at))}</span>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Mono>{token.subject || "—"}</Mono>
                      {token.grant ? (
                        <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                          through{" "}
                          <Ref to={paths.group(token.grant)} mono>
                            {token.grant}
                          </Ref>
                        </Typography>
                      ) : null}
                    </TableCell>
                    <TableCell>
                      <Mono>{token.repositories.length ? token.repositories.join(" ") : "every repository"}</Mono>
                    </TableCell>
                    <TableCell>
                      <Mono>{token.permissions || "—"}</Mono>
                    </TableCell>
                    <TableCell>
                      {token.outcome === "ok" ? "minted" : <State kind={token.outcome === "failed" ? "failed" : "refused"} title={token.reason || undefined} />}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
            {recentTokensKept(sinceWords(recent.value?.keptSince))} The {trail} page holds every token asked for, however long ago.
          </Typography>
        </>
      ) : null}
    </Section>
  );
}

// ----------------------------------------------------------------- helpers

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
