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
import type { ExplainRequest } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { Explanation } from "./Person";
import { paths } from "./router";
import { Facet, Failure, Loading, Mono, Names, Nothing, Page, Ref, Section, State } from "./ui";

/** The kind of rule, which is also the tab. `directory` is the one this
 *  page used to omit, and it is the majority of the estate. */
type Kind = "all" | "directory" | "ci" | "workload" | "sign-in" | "github-team";

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
  // A GitHub team binding feeds a team rather than an internal group, so
  // there is no group page to link to and no client it opens.
  team?: boolean;
};

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

  // A GitHub team binding feeds a TEAM rather than an internal group, so
  // it grants nothing in a token and opens no client. It belongs here
  // anyway: the question this page answers is "how does somebody come to
  // be in this, and why", and for a GitHub team the answer is a
  // directory group exactly as it is for an internal one.
  const teamRows: Row[] = (policy.value?.teams ?? []).flatMap((t) =>
    t.members.map((address) => ({
      key: `${t.org}/${t.team}:${address}`,
      kind: "github-team" as Kind,
      rule: address,
      group: `${t.org}/${t.team}`,
      needs: "directory" as const,
      declared: true,
      team: true,
    })),
  );

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
  const all = [...rows, ...teamRows];
  const shown = all.filter((row) => (kind === "all" || row.kind === kind) && (!group || row.group === group));
  // Every group any rule feeds — which is now all of them, rather than
  // the third that had a matcher.
  const fed = groups.filter((g) => g.members.length || g.rules.length);

  return (
    <Page
      title="Rules"
      lede="Every rule that puts an identity somewhere: a provider group somebody is a member of, a verified sign-in, a workload, a CI job, and the provider groups that feed a GitHub team. Together they are the whole answer to who is in what and why. Declared by the deployment, never written here."
    >
      <Loading busy={policy.loading} />
      <Failure error={policy.error} />

      <Stack direction="row" spacing={2} sx={{ alignItems: "center", flexWrap: "wrap", gap: 1.5, mb: 1.5 }}>
        <Facet
          value={kind}
          onChange={(next) => setKind(next as Kind)}
          all={{ value: "all", label: "All" }}
          options={[
            { value: "directory", label: "Provider groups" },
            { value: "sign-in", label: "Sign-ins" },
            { value: "workload", label: "Workloads" },
            { value: "ci", label: "CI jobs" },
            ...(teamRows.length ? [{ value: "github-team", label: "GitHub teams" }] : []),
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
                  <TableCell>
                    {row.kind === "directory" ? (
                      <Ref to={paths.directoryGroup(row.rule)} mono>
                        {row.rule}
                      </Ref>
                    ) : (
                      <Mono>{row.rule}</Mono>
                    )}
                  </TableCell>
                  <TableCell>
                    {row.team ? (
                      <Mono>{row.group}</Mono>
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
    default:
      return matcherKind(kind);
  }
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
