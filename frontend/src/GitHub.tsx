import { useState, type ReactNode } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import IconButton from "@mui/material/IconButton";
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
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";

import { ago, at, github, reason } from "./api";
import type { GetGitHubStatusResponse, GitHubMember, GitHubOrganisation } from "./gen/directoryroster/v1/github_pb";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Facet, Facts, Failure, Loading, Mono, Names, Nothing, Page, Ref, Section, State, type StateKind } from "./ui";

/** GitHub: who belongs in which team, whether they have linked the account
 *  they use, and what the controller would change.
 *
 *  Read top to bottom it is the order the work happens in: set the Apps
 *  up, get people linked, read what each organisation is waiting on. The
 *  one thing an operator does here is create and remove Apps; the
 *  controller acts, and the page says what it found. */
export function GitHubPage({ operator, onDone }: { operator: boolean; onDone: (message: string) => void }) {
  const status = useAsync(() => github.getGitHubStatus({}), []);
  const value = status.value;

  return (
    <Page
      title="GitHub"
      lede="The policy decides who belongs in which GitHub team. Each person links the GitHub account they use, once; the controller then makes every organisation match, and this page shows what it would change."
    >
      <Loading busy={status.loading} />
      <Failure error={status.error} />

      {value && !value.reportsAvailable ? (
        <Nothing>This deployment keeps no state in Kubernetes, so a controller has nowhere to report: only the bindings are shown.</Nothing>
      ) : null}
      {value && value.organisations.length === 0 ? (
        <Nothing>No GitHub organisation is bound. A team is bound in the policy&apos;s github table, beside the groups that feed it.</Nothing>
      ) : null}

      {value && value.organisations.length > 0 ? (
        <>
          <SetUp status={value} operator={operator} onDone={onDone} reload={status.reload} />
          <People status={value} />
          {value.organisations.map((org) => (
            <Organisation key={org.org} org={org} />
          ))}
          <LinkedAccounts status={value} />
        </>
      ) : null}
    </Page>
  );
}

// ---------------------------------------------------------------- set up

/** Three steps, each ticked when done. Every App is in the first, in one
 *  table, because an App has nowhere else to live on the page. */
function SetUp({
  status,
  operator,
  onDone,
  reload,
}: {
  status: GetGitHubStatusResponse;
  operator: boolean;
  onDone: (message: string) => void;
  reload: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const bound = status.organisations.filter((org) => org.bound);
  const [owner, setOwner] = useState(bound[0]?.org ?? "");

  const people = collectPeople(status.organisations);
  const linkedPeople = people.filter((person) => person.state !== "not-linked").length;
  const connected = bound.filter((org) => org.connection?.installed).length;
  const acting = bound.filter((org) => org.enabled).length;

  // Creating an App leaves the page for GitHub, so busy stays set.
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
  const disconnectOrganisation = (org: string) =>
    run(async () => {
      const gone = await github.disconnectGitHubOrganisation({ org });
      onDone(`${org} is disconnected${gone.uninstalled ? " and its App uninstalled" : `. ${gone.detail}`}.${settingsNote(gone.appSettingsUrl)}`);
      reload();
    });
  const disconnectLinkApp = () =>
    run(async () => {
      const gone = await github.disconnectGitHubLinkApp({});
      onDone(`The link App is disconnected; ${gone.invalidated} links wait for their people to link again.${settingsNote(gone.appSettingsUrl)}`);
      reload();
    });

  const app = status.linkApp;
  const linkAction = !operator ? null : app ? (
    <Tooltip title="Forget the link App. Every link becomes unverifiable: nobody is added or removed on its account until the person links again.">
      <span>
        <Button size="small" color="warning" disabled={busy} onClick={() => void disconnectLinkApp()}>
          Disconnect
        </Button>
      </span>
    </Tooltip>
  ) : !status.linkingAvailable ? null : (
    <Stack direction="row" sx={{ gap: 1, justifyContent: "flex-end", alignItems: "center" }}>
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
  );
  const organisationAction = (org: GitHubOrganisation) => {
    const c = org.connection;
    if (!operator) return null;
    if (!c) {
      return (
        <Tooltip title={!org.bound ? "Bind the organisation's teams in the policy first." : "Two clicks by the organisation's owner: create, then install."}>
          <span>
            <Button size="small" variant="outlined" disabled={busy || !org.bound || !status.connectingAvailable} onClick={() => void leave(() => github.beginGitHubConnect({ org: org.org }))}>
              Create
            </Button>
          </span>
        </Tooltip>
      );
    }
    return (
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
    );
  };

  const steps: { done: boolean; title: string; body: ReactNode }[] = [
    {
      done: bound.length > 0 && connected === bound.length && Boolean(app),
      title: "Create the GitHub Apps",
      body: (
        <AppTable>
          <AppRow
            name={app ? appLink(app.appSlug, app.htmlUrl) : <Typography variant="body2">link App</Typography>}
            scope={<Typography variant="body2">every organisation</Typography>}
            purpose={
              <>
                People authorize it to show which work addresses their GitHub account has.
                <Typography component="span" variant="caption" color="text.secondary" sx={{ display: "block" }}>
                  One for all organisations: public, reads a person&apos;s own email addresses, installed nowhere.
                </Typography>
              </>
            }
            state={!status.linkingAvailable ? "not available here" : app ? `created under ${app.owner}` : "not created"}
            since={app ? since(app.connectedAt, app.connectedBy) : ""}
            action={linkAction}
          />
          {status.organisations.map((org) => {
            const c = org.connection;
            return (
              <AppRow
                key={org.org}
                name={c ? appLink(c.appSlug, c.htmlUrl) : <Typography variant="body2">team App</Typography>}
                scope={<Mono>{org.org}</Mono>}
                purpose={
                  <>
                    The controller manages {org.org}&apos;s members and teams through it.
                    <Typography component="span" variant="caption" color="text.secondary" sx={{ display: "block" }}>
                      Private, members: write, installed on {org.org}.{org.bound ? "" : " The policy no longer binds it."}
                    </Typography>
                  </>
                }
                state={!c ? "not created" : c.installed ? "installed" : "created, not installed"}
                since={c ? since(c.connectedAt, c.connectedBy) : ""}
                action={organisationAction(org)}
              />
            );
          })}
        </AppTable>
      ),
    },
    {
      done: people.length > 0 && linkedPeople === people.length,
      title: `People link their GitHub account — ${linkedPeople} of ${people.length}`,
      body: app ? (
        <Stack sx={{ gap: 1 }}>
          <Typography variant="body2" color="text.secondary">
            Send everybody below who is <em>not linked</em> this page. They sign in to GitHub, authorize, and are invited or added within a
            few minutes. A personal address counts for nothing: they need their work address verified on the account.
          </Typography>
          <CopyLine value={status.linkUrl} />
        </Stack>
      ) : (
        <Typography variant="body2" color="text.secondary">
          Create the link App first.
        </Typography>
      ),
    },
    {
      done: bound.length > 0 && acting === bound.length,
      title: "Let the controller act",
      body: (
        <Typography variant="body2" color="text.secondary">
          Every organisation starts as a dry run. When its section below reads right, add it to <Mono>githubRoster.actsIn</Mono> in the
          deployment. Acting now: {acting ? bound.filter((org) => org.enabled).map((org) => org.org).join(", ") : "none"}.
        </Typography>
      ),
    },
  ];
  const done = steps.filter((step) => step.done).length;

  return (
    <Section title="Set up" hint={`${done} of ${steps.length} done`}>
      <Failure error={failure} />
      <Paper variant="outlined">
        {steps.map((step, index) => (
          <Stack key={step.title} direction="row" sx={{ gap: 1.5, p: 2, borderTop: index ? 1 : 0, borderColor: "divider" }}>
            {step.done ? <CheckCircleIcon color="success" fontSize="small" sx={{ mt: 0.25 }} /> : <RadioButtonUncheckedIcon color="disabled" fontSize="small" sx={{ mt: 0.25 }} />}
            <Stack sx={{ gap: 1, minWidth: 0, flex: 1 }}>
              <Typography variant="subtitle2">
                {index + 1}. {step.title}
              </Typography>
              {step.body}
            </Stack>
          </Stack>
        ))}
      </Paper>
    </Section>
  );
}

function AppTable({ children }: { children: ReactNode }) {
  return (
    <TableContainer sx={{ overflowX: "auto" }}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>App</TableCell>
            <TableCell>Organisation</TableCell>
            <TableCell>What it does</TableCell>
            <TableCell>State</TableCell>
            <TableCell>Connected</TableCell>
            <TableCell />
          </TableRow>
        </TableHead>
        <TableBody>{children}</TableBody>
      </Table>
    </TableContainer>
  );
}

function AppRow({
  name,
  scope,
  purpose,
  state,
  since,
  action,
}: {
  name: ReactNode;
  scope: ReactNode;
  purpose: ReactNode;
  state: string;
  since: string;
  action: ReactNode;
}) {
  return (
    <TableRow>
      <TableCell>{name}</TableCell>
      <TableCell>{scope}</TableCell>
      <TableCell>
        <Typography variant="body2">{purpose}</Typography>
      </TableCell>
      <TableCell>
        <Typography variant="body2">{state}</Typography>
      </TableCell>
      <TableCell>
        <Typography variant="body2" color="text.secondary">
          {since || "—"}
        </Typography>
      </TableCell>
      <TableCell align="right">{action}</TableCell>
    </TableRow>
  );
}

function CopyLine({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Stack direction="row" sx={{ alignItems: "center", gap: 0.5, minWidth: 0 }}>
      <Box component="a" href={value} target="_blank" rel="noreferrer" sx={{ minWidth: 0, overflowWrap: "anywhere" }}>
        <Mono>{value}</Mono>
      </Box>
      <Tooltip title={copied ? "Copied" : "Copy"}>
        <IconButton
          size="small"
          aria-label="copy"
          onClick={() => {
            void navigator.clipboard.writeText(value).then(() => setCopied(true));
          }}
        >
          <ContentCopyIcon fontSize="inherit" />
        </IconButton>
      </Tooltip>
    </Stack>
  );
}

// ---------------------------------------------------------------- people

/** One person across every organisation and team the policy wants them in. */
type Person = {
  email: string;
  login: string;
  places: string[];
  /** The state that matters most across their rows. */
  state: string;
  next: GitHubMember | undefined;
};

/** Worst first: what an operator should look at before anything else. */
const priority = ["held", "leaving", "pending", "invited", "not-linked", "synced"];

function collectPeople(organisations: GitHubOrganisation[]): Person[] {
  const byEmail = new Map<string, Person>();
  const add = (place: string, member: GitHubMember) => {
    if (!member.email) return;
    const person = byEmail.get(member.email) ?? { email: member.email, login: "", places: [], state: "synced", next: undefined };
    if (member.login && !person.login) person.login = member.login;
    person.places.push(place);
    if (rank(member.state) < rank(person.state)) {
      person.state = member.state;
      person.next = member;
    }
    byEmail.set(member.email, person);
  };
  for (const org of organisations) {
    for (const member of org.members) add(org.org, member);
    for (const team of org.teams) for (const member of team.members) add(`${org.org} / ${team.team}`, member);
  }
  return [...byEmail.values()].sort((a, b) => rank(a.state) - rank(b.state) || a.email.localeCompare(b.email));
}

function rank(state: string): number {
  const at = priority.indexOf(state);
  return at < 0 ? priority.length : at;
}

type PeopleFilter = "all" | "action" | "waiting" | "synced";

function People({ status }: { status: GetGitHubStatusResponse }) {
  const people = collectPeople(status.organisations);
  const action = people.filter((p) => ["held", "leaving", "pending"].includes(p.state));
  const waiting = people.filter((p) => ["not-linked", "invited"].includes(p.state));
  const synced = people.filter((p) => p.state === "synced");
  const [filter, setFilter] = useState<PeopleFilter>(action.length ? "action" : waiting.length ? "waiting" : "all");
  if (people.length === 0) return null;
  const shown = { all: people, action, waiting, synced }[filter];

  return (
    <Section title="People" hint={`${people.length} the policy wants in GitHub, ${synced.length} synced`}>
      <Stack sx={{ gap: 1.5 }}>
        <Facet
          value={filter}
          onChange={setFilter}
          all={{ value: "all", label: `Everyone (${people.length})` }}
          options={[
            { value: "action", label: `To change (${action.length})` },
            { value: "waiting", label: `Waiting on them (${waiting.length})` },
            { value: "synced", label: `Synced (${synced.length})` },
          ]}
        />
        {shown.length === 0 ? (
          <Nothing>{filter === "action" ? "Nothing to change." : filter === "waiting" ? "Nobody is waiting." : "Nobody here."}</Nothing>
        ) : (
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Person</TableCell>
                  <TableCell>GitHub</TableCell>
                  <TableCell>Where</TableCell>
                  <TableCell>State</TableCell>
                  <TableCell>Next</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {shown.map((person) => (
                  <TableRow key={person.email} hover>
                    <TableCell>
                      <Ref to={paths.person(person.email)} mono>
                        {person.email}
                      </Ref>
                    </TableCell>
                    <TableCell>{loginCell(person.login)}</TableCell>
                    <TableCell>
                      <Typography variant="body2">{person.places.join(", ")}</Typography>
                    </TableCell>
                    <TableCell>
                      <State kind={stateKind(person.state)} />
                    </TableCell>
                    <TableCell>{person.next ? next(person.next) : null}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Stack>
    </Section>
  );
}

// ---------------------------------------------------------- organisations

/** One organisation: how the controller's last pass went, its teams, and
 *  the changes it would make. People waiting to link are in People above,
 *  once, rather than here once per team. */
function Organisation({ org }: { org: GitHubOrganisation }) {
  const rows = [
    ...org.members.map((member) => ({ team: "", member })),
    ...org.teams.flatMap((team) => team.members.map((member) => ({ team: team.team, member }))),
  ];
  const changes = rows.filter((row) => row.member.action || row.member.state === "held");

  return (
    <Section title={org.org} hint={summary(org)}>
      <Stack sx={{ gap: 2 }}>
        <Facts
          items={[
            { label: "Controller", value: outcome(org) },
            { label: "Acts on it", value: org.reported ? (org.enabled ? "yes" : "no — dry run") : undefined },
            { label: "Last pass", value: at(org.tick?.at) ? ago(at(org.tick?.at)) : undefined },
            { label: "To change", value: org.tick ? String(org.tick.changes) : undefined },
            { label: "Held", value: org.tick ? String(org.tick.held) : undefined },
            { label: "Not linked", value: org.tick ? String(org.tick.waiting) : undefined },
            {
              label: "In the organisation itself",
              value: org.memberGroups.length ? <Names items={org.memberGroups.map((group) => ({ label: group, to: paths.group(group), mono: true }))} /> : undefined,
            },
          ]}
        />
        {org.reportError ? <Failure error={`The last report could not be read: ${org.reportError}`} /> : null}
        {org.tick?.error ? <Failure error={`The last pass failed: ${org.tick.error}`} /> : null}
        {!org.bound ? <Nothing>The policy no longer binds this organisation. What follows is the controller&apos;s last report on it.</Nothing> : null}

        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Team</TableCell>
                <TableCell>Members from</TableCell>
                <TableCell>Maintainers from</TableCell>
                <TableCell align="right">Synced</TableCell>
                <TableCell align="right">To change</TableCell>
                <TableCell align="right">Not linked</TableCell>
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
                  <TableCell align="right">{count(team.members, (m) => m.state === "synced")}</TableCell>
                  <TableCell align="right">{count(team.members, (m) => Boolean(m.action) || m.state === "held")}</TableCell>
                  <TableCell align="right">{count(team.members, (m) => m.state === "not-linked")}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {changes.length > 0 ? (
          <Box>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              {org.enabled ? "Changes" : "Changes it would make"}
            </Typography>
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
                  {changes.map((row) => (
                    <TableRow key={`${row.team}:${row.member.email}:${row.member.login}:${row.member.action}`} hover>
                      <TableCell>{row.member.email ? <Mono>{row.member.email}</Mono> : "—"}</TableCell>
                      <TableCell>{loginCell(row.member.login)}</TableCell>
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
          </Box>
        ) : null}

        {org.unlinked.length > 0 ? (
          <Box>
            <Typography variant="subtitle2">Members nobody linked ({org.unlinked.length})</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>
              In {org.org} on GitHub, and nobody has linked the account to a work address — so nobody can say who they are. Never touched.
            </Typography>
            <Names items={org.unlinked.map((account) => ({ label: account.login, mono: true }))} />
          </Box>
        ) : null}
      </Stack>
    </Section>
  );
}

// ---------------------------------------------------------- linked accounts

/** Every account linked so far. Last on the page: it is the evidence
 *  behind People, and matters most when a link went wrong. */
function LinkedAccounts({ status }: { status: GetGitHubStatusResponse }) {
  if (!status.linkingAvailable || status.links.length === 0) return null;
  const linked = status.links.filter((l) => l.state === "linked").length;
  return (
    <Section title="Linked GitHub accounts" hint={`${linked} linked, ${status.links.length - linked} not counting`}>
      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>GitHub</TableCell>
              <TableCell>Work addresses</TableCell>
              <TableCell>State</TableCell>
              <TableCell>Checked</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {status.links.map((l) => {
              const checked = at(l.checkedAt);
              return (
                <TableRow key={String(l.accountId)} hover>
                  <TableCell>{loginCell(l.login)}</TableCell>
                  <TableCell>
                    <Names items={l.emails.map((email) => ({ label: email, to: paths.person(email), mono: true }))} empty="—" />
                  </TableCell>
                  <TableCell>
                    <State kind={linkKind(l.state)} />
                    {l.reason ? (
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                        {l.reason}
                      </Typography>
                    ) : null}
                  </TableCell>
                  <TableCell>{checked ? ago(checked) : "—"}</TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
    </Section>
  );
}

// ---------------------------------------------------------------- helpers

function appLink(slug: string, url: string) {
  return url ? (
    <a href={url} target="_blank" rel="noreferrer">
      <Mono>{slug}</Mono>
    </a>
  ) : (
    <Mono>{slug}</Mono>
  );
}

function loginCell(login: string) {
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

function count<T>(items: T[], test: (item: T) => boolean): number {
  return items.filter(test).length;
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

/** The organisation's one line. */
function summary(org: GitHubOrganisation): string {
  const teams = `${org.teams.length} ${org.teams.length === 1 ? "team" : "teams"}`;
  if (!org.reported) return `${teams}, not reported yet`;
  const tick = org.tick;
  const parts = [teams];
  if (tick?.changes) parts.push(`${tick.changes} to change`);
  if (tick?.held) parts.push(`${tick.held} held`);
  if (tick?.waiting) parts.push(`${tick.waiting} not linked`);
  if (parts.length === 1) parts.push("everyone synced");
  return parts.join(", ");
}

function outcome(org: GitHubOrganisation) {
  if (!org.reported) return <State kind="unreported" />;
  const kind = org.tick?.outcome as StateKind | undefined;
  return kind ? <State kind={kind} /> : <State kind="unreported" />;
}

function stateKind(state: string): StateKind {
  switch (state) {
    case "not-linked":
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

function linkKind(state: string): StateKind {
  switch (state) {
    case "linked":
    case "lost":
    case "unverifiable":
      return state;
    default:
      return "unknown";
  }
}

/** What happens next for one row, and why when it is held. A not-linked
 *  row has no next step of the controller's: the chip says it all. */
function next(member: GitHubMember) {
  if (member.state === "not-linked") return null;
  const words: Record<string, string> = { invite: "invite", add: "add to team", "set-role": "change role", remove: "remove" };
  const label = member.action ? (words[member.action] ?? member.action) : "";
  if (!member.reason) return label ? <Typography variant="body2">{label}</Typography> : null;
  return (
    <Typography variant="body2">
      {label ? `${label} — ` : ""}
      <Typography component="span" variant="body2" color="text.secondary">
        {member.reason}
      </Typography>
    </Typography>
  );
}
