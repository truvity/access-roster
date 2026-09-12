import { useState } from "react";
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
import ToggleButton from "@mui/material/ToggleButton";
import ToggleButtonGroup from "@mui/material/ToggleButtonGroup";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";

import { access, matcherKind } from "./api";
import type { ExplainRequest, PolicyGroup } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { Explanation } from "./Person";
import { paths } from "./router";
import { Facet, Failure, Loading, Mono, Names, Nothing, Page, Ref, Section, State } from "./ui";

/** The kind of rule, which is also the tab. `directory` is the one this
 *  page used to omit, and it is the majority of the estate. */
type Kind = "all" | "directory" | "ci" | "workload" | "sign-in" | "github-team" | "github-org";

/** What a rule needs besides itself to grant anything.
 *
 *  This is the one thing worth keeping from the split this page used to
 *  make — as information, rather than as a page boundary an operator had
 *  to know about before they could find an answer. A membership rule
 *  needs the directory to vouch, so it degrades to the hold window when
 *  the hub cannot read one; a matcher needs only the proof presented and
 *  does not. That is why recovery is a workload rule: it has to work on
 *  the day the directory is what is broken. */
const dependsOn = {
  directory: {
    label: "the provider",
    why: "The hub confirms the account really is in this provider group before granting anything. While it cannot read the provider, the last snapshot stands until the hold window runs out, and then this rule grants nothing.",
  },
  proof: {
    label: "the proof alone",
    why: "Nothing outside the proof presented has to be reachable for this rule to grant. It still holds on the day the provider is what is broken, which is why the way back in is a rule of this kind.",
  },
} as const;

type Row = {
  key: string;
  kind: Kind;
  rule: string;
  group: string;
  needs: keyof typeof dependsOn;
  declared: boolean;
  // A GitHub binding feeds a team or an organisation rather than an
  // internal group, so what it feeds has no group page to link to and
  // opens no client.
  team?: boolean;
  // A GitHub binding's RULE is an internal group, so the group filter
  // has to match the rule rather than what it feeds.
  filterGroup?: string;
  // `member` or `maintainer`, GitHub's two team roles.
  role?: string;
};

/** One row of a GitHub binding: an internal group, what it feeds, and
 *  the role it feeds it as. */
function githubRow(kind: Kind, group: string, feeds: string, role: string, groups: PolicyGroup[]): Row {
  return {
    key: `${feeds}:${role}:${group}`,
    kind,
    rule: group,
    group: feeds,
    filterGroup: group,
    needs: needsOf(groups, group),
    declared: true,
    team: true,
    role,
  };
}

/** What a GitHub binding depends on: whatever the internal group it
 *  names depends on. A group the provider vouches for degrades to the
 *  hold window when the provider cannot be read; one admitted by a proof
 *  alone does not. */
function needsOf(groups: PolicyGroup[], name: string): keyof typeof dependsOn {
  const group = groups.find((g) => g.name === name);
  if (!group) return "directory";
  return group.members.length ? "directory" : "proof";
}

/** Every rule that puts an identity into an internal group.
 *
 *  It used to be Matchers, and showed only the rules that admit a proof
 *  by its shape — which is a distinction between how a rule is
 *  evaluated, not between what an operator is asking. Filtering it by a
 *  group fed by a directory returned nothing, and nothing reads as
 *  missing data rather than as the wrong page.
 *
 *  The complete set was already in the console one group at a time. This
 *  is the across-all-groups view that stopped dropping half of it. */
export function Rules() {
  const policy = useAsync(() => access.getPolicy({}), []);
  const [kind, setKind] = useState<Kind>("all");
  const [group, setGroup] = useState("");

  const groups = policy.value?.groups ?? [];
  const clients = policy.value?.clients ?? [];

  // A GitHub binding feeds a TEAM or an ORGANISATION rather than an
  // internal group, so it grants nothing in a token and opens no client.
  // It belongs here anyway: the question this page answers is "how does
  // somebody come to be in this, and why", and a GitHub team is a
  // consumer of an internal group exactly as a client is.
  const githubRows: Row[] = [
    ...(policy.value?.teams ?? []).flatMap((t) => [
      ...t.members.map((g) => githubRow("github-team", g, `${t.org}/${t.team}`, "member", groups)),
      ...t.maintainers.map((g) => githubRow("github-team", g, `${t.org}/${t.team}`, "maintainer", groups)),
    ]),
    ...(policy.value?.orgs ?? []).flatMap((o) => o.members.map((g) => githubRow("github-org", g, o.org, "member", groups))),
  ];

  const rows: Row[] = groups.flatMap((g) => [
    // Membership: the majority of the estate, and what this page used to
    // leave out.
    ...g.members.map((m) => ({
      key: `${g.name}:directory:${m.address}`,
      kind: "directory" as Kind,
      rule: m.address,
      group: g.name,
      needs: "directory" as const,
      declared: true,
    })),
    ...g.rules.map((rule) => ({
      key: `${g.name}:${rule.kind}:${rule.rule}`,
      kind: rule.kind as Kind,
      rule: rule.rule,
      group: g.name,
      needs: "proof" as const,
      declared: true,
    })),
  ]);

  const opens = (name: string) => clients.filter((client) => client.requires.includes(name));
  const all = [...rows, ...githubRows];
  const shown = all.filter((row) => (kind === "all" || row.kind === kind) && (!group || (row.filterGroup ?? row.group) === group));
  // Every group any rule feeds — which is now all of them, rather than
  // the third that had a matcher — plus any a GitHub binding names, so
  // that filtering by one never returns the rows it feeds and nothing
  // else.
  const bound = new Set(githubRows.map((row) => row.filterGroup));
  const fed = groups.filter((g) => g.members.length || g.rules.length || bound.has(g.name));

  return (
    <Page
      title="Rules"
      lede="Every rule that puts an identity somewhere: a provider group somebody is a member of, a verified sign-in, a workload, a CI job, and the internal groups that feed a GitHub team. Together they are the whole answer to who is in what and why. Declared by the deployment, never written here."
    >
      <Loading busy={policy.loading} />
      <Failure error={policy.error} />

      <Stack direction="row" sx={{ alignItems: "center", flexWrap: "wrap", gap: 1.5, mb: 1.5 }}>
        <Facet
          value={kind}
          onChange={(next) => setKind(next as Kind)}
          all={{ value: "all", label: "All" }}
          options={[
            { value: "directory", label: "Provider groups" },
            { value: "sign-in", label: "Sign-ins" },
            { value: "workload", label: "Workloads" },
            { value: "ci", label: "CI jobs" },
            ...(githubRows.some((row) => row.kind === "github-team") ? [{ value: "github-team", label: "GitHub teams" }] : []),
            ...(githubRows.some((row) => row.kind === "github-org") ? [{ value: "github-org", label: "GitHub orgs" }] : []),
          ]}
        />
        <TextField select label="Internal group" value={group} onChange={(e) => setGroup(e.target.value)} sx={{ minWidth: 220 }}>
          <MenuItem value="">Any</MenuItem>
          {fed.map((g) => (
            <MenuItem key={g.name} value={g.name}>
              {g.name}
            </MenuItem>
          ))}
        </TextField>
      </Stack>

      {!policy.loading && shown.length === 0 ? (
        <Nothing>{emptiness(kind, group, all.length)}</Nothing>
      ) : (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto", mb: 4 }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Kind</TableCell>
                <TableCell>Rule</TableCell>
                <TableCell>Feeds</TableCell>
                <TableCell>Opens</TableCell>
                <TableCell>Depends on</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {shown.map((row) => (
                <TableRow key={row.key} hover>
                  <TableCell>{ruleKind(row.kind)}</TableCell>
                  <TableCell>{rule(row)}</TableCell>
                  <TableCell>
                    {row.team ? (
                      <>
                        <Mono>{row.group}</Mono>
                        {row.role === "maintainer" ? (
                          <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                            as maintainer
                          </Typography>
                        ) : null}
                      </>
                    ) : (
                      <Ref to={paths.group(row.group)} mono>
                        {row.group}
                      </Ref>
                    )}
                  </TableCell>
                  <TableCell>
                    {row.team ? (
                      <Typography variant="body2" color="text.secondary">
                        nothing here
                      </Typography>
                    ) : (
                      <Names items={opens(row.group).map((client) => ({ label: client.id, to: paths.client(client.id), mono: true }))} empty="only claims" />
                    )}
                  </TableCell>
                  <TableCell>
                    <Tooltip title={dependsOn[row.needs].why}>
                      <Typography variant="body2" component="span" sx={{ borderBottom: "1px dotted", cursor: "help" }}>
                        {dependsOn[row.needs].label}
                      </Typography>
                    </Tooltip>
                  </TableCell>
                  <TableCell align="right">
                    <State kind={row.declared ? "declared" : "console"} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Section title="Test a proof" hint="type what a real job or workload would present, and see which rules it falls into and what that opens">
        <Simulator />
      </Section>
    </Page>
  );
}

/** The kind, in an operator's words. `directory group` is not a matcher
 *  kind and never reaches matcherKind, which is why this wraps it. */
function ruleKind(kind: Kind): string {
  switch (kind) {
    case "directory":
      return "provider group";
    case "github-team":
      return "GitHub team";
    case "github-org":
      return "GitHub org";
    default:
      return matcherKind(kind);
  }
}

/** The rule itself, linked to whatever page explains it: a provider
 *  group's page for a membership, the internal group's page for a GitHub
 *  binding, and nothing for a matcher, which is the rule in full. */
function rule(row: Row) {
  if (row.kind === "directory") {
    return (
      <Ref to={paths.directoryGroup(row.rule)} mono>
        {row.rule}
      </Ref>
    );
  }
  if (row.team) {
    return (
      <Ref to={paths.group(row.rule)} mono>
        {row.rule}
      </Ref>
    );
  }
  return <Mono>{row.rule}</Mono>;
}

/** What an empty table means, which is not one thing.
 *
 *  On a page claiming to be every rule, an empty CI jobs tab reads as
 *  "not yet" rather than as broken — and that is the truth: no CI rule
 *  exists until CI is rewired. Saying so is the whole benefit of the tab
 *  being here at all. */
function emptiness(kind: Kind, group: string, total: number): string {
  if (total === 0) return "No rule is declared: nothing puts anybody into an internal group.";
  if (group) return "No rule of this kind feeds that group.";
  switch (kind) {
    case "ci":
      return "No CI job rule is declared yet.";
    case "workload":
      return "No workload rule is declared.";
    case "sign-in":
      return "No sign-in rule is declared: everybody arrives through a provider group.";
    case "github-team":
      return "No GitHub team is bound to an internal group.";
    case "github-org":
      return "No GitHub organisation binds members of its own: everybody in one is there through a team.";
    case "directory":
      return "No provider group feeds anything: only the rules above admit anyone.";
    default:
      return "No rule matches the filter.";
  }
}

type ProofKind = "ci" | "workload";

function Simulator() {
  const [kind, setKind] = useState<ProofKind>("ci");
  const [repository, setRepository] = useState("example-org/gitops");
  const [ref, setRef] = useState("refs/heads/master");
  const [namespace, setNamespace] = useState("identity-system");
  const [name, setName] = useState("authorization-webhook");
  const [asked, setAsked] = useState<ExplainRequest | undefined>();

  const explained = useAsync(() => (asked ? access.explain(asked) : Promise.resolve(undefined)), [asked]);

  const ask = () => {
    if (kind === "ci") setAsked({ github: { repository: repository.trim(), ref: ref.trim() } } as ExplainRequest);
    else setAsked({ serviceAccount: { namespace: namespace.trim(), name: name.trim() } } as ExplainRequest);
  };

  return (
    <>
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack spacing={2}>
          <ToggleButtonGroup size="small" exclusive value={kind} onChange={(_, next: ProofKind | null) => next && setKind(next)} sx={{ flexWrap: "wrap" }}>
            <ToggleButton value="ci">A CI job</ToggleButton>
            <ToggleButton value="workload">A workload</ToggleButton>
          </ToggleButtonGroup>
          <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start", flexWrap: "wrap", gap: 1 }}>
            {kind === "ci" ? (
              <>
                <TextField label="Repository" value={repository} onChange={(e) => setRepository(e.target.value)} sx={{ minWidth: 260 }} />
                <TextField label="Ref" value={ref} onChange={(e) => setRef(e.target.value)} sx={{ minWidth: 240 }} />
              </>
            ) : (
              <>
                <TextField label="Namespace" value={namespace} onChange={(e) => setNamespace(e.target.value)} sx={{ minWidth: 220 }} />
                <TextField label="ServiceAccount" value={name} onChange={(e) => setName(e.target.value)} sx={{ minWidth: 260 }} />
              </>
            )}
            <Button variant="contained" onClick={ask} sx={{ mt: 0.25 }}>
              Show the chain
            </Button>
          </Stack>
          {!asked ? (
            <Typography variant="caption" color="text.secondary">
              A proof can fall into several rules at once; it then holds every group they feed, with the shortest lifetime. A person's own chain is on their page — this is for the proofs nothing can list, because a CI run exists only while it runs.
            </Typography>
          ) : null}
        </Stack>
      </Paper>
      <Loading busy={explained.loading} />
      <Failure error={explained.error} />
      {explained.value ? <Explanation value={explained.value} /> : null}
    </>
  );
}
