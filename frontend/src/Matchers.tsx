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
import Typography from "@mui/material/Typography";

import { access, matcherKind } from "./api";
import type { ExplainRequest } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { Explanation } from "./Person";
import { paths } from "./router";
import { Failure, Loading, Mono, Names, Nothing, Page, Ref, Section, State } from "./ui";

type Kind = "all" | "ci" | "workload" | "sign-in";

/** The identity side's second way in. A directory group feeds an
 *  internal group by membership; a matcher feeds one by shape. This is
 *  the list of every rule in force, and the simulator below it is how a
 *  concrete proof is checked against them, because a CI run exists only
 *  while it runs and cannot be listed. */
export function Matchers() {
  const policy = useAsync(() => access.getPolicy({}), []);
  const [kind, setKind] = useState<Kind>("all");
  const [group, setGroup] = useState("");

  const groups = policy.value?.groups ?? [];
  const clients = policy.value?.clients ?? [];
  const rows = groups.flatMap((g) =>
    g.rules.map((rule) => ({
      key: `${g.name}:${rule.kind}:${rule.rule}`,
      kind: rule.kind,
      rule: rule.rule,
      group: g.name,
      opens: clients.filter((client) => client.requires.includes(g.name)),
    })),
  );
  const shown = rows.filter((row) => (kind === "all" || row.kind === kind) && (!group || row.group === group));
  const withRules = groups.filter((g) => g.rules.length);

  return (
    <Page
      title="Matchers"
      lede="Every rule that admits a proof by its shape rather than through a directory: a CI job, a workload, or a verified sign-in. A directory group feeds an internal group by membership; a matcher feeds one by pattern. Declared by the deployment, never written here."
    >
      <Loading busy={policy.loading} />
      <Failure error={policy.error} />

      <Stack direction="row" spacing={2} sx={{ alignItems: "center", flexWrap: "wrap", gap: 1.5, mb: 1.5 }}>
        <ToggleButtonGroup size="small" exclusive value={kind} onChange={(_, next: Kind | null) => next && setKind(next)}>
          <ToggleButton value="all">All</ToggleButton>
          <ToggleButton value="ci">CI jobs</ToggleButton>
          <ToggleButton value="workload">Workloads</ToggleButton>
          <ToggleButton value="sign-in">Sign-ins</ToggleButton>
        </ToggleButtonGroup>
        <TextField select label="Internal group" value={group} onChange={(e) => setGroup(e.target.value)} sx={{ minWidth: 220 }}>
          <MenuItem value="">Any</MenuItem>
          {withRules.map((g) => (
            <MenuItem key={g.name} value={g.name}>
              {g.name}
            </MenuItem>
          ))}
        </TextField>
      </Stack>

      {!policy.loading && shown.length === 0 ? (
        <Nothing>{rows.length ? "No rule matches the filter." : "No matcher is declared: only directory groups put anyone anywhere."}</Nothing>
      ) : (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto", mb: 4 }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Kind</TableCell>
                <TableCell>Rule</TableCell>
                <TableCell>Feeds</TableCell>
                <TableCell>Opens</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {shown.map((row) => (
                <TableRow key={row.key} hover>
                  <TableCell>{matcherKind(row.kind)}</TableCell>
                  <TableCell>
                    <Mono>{row.rule}</Mono>
                  </TableCell>
                  <TableCell>
                    <Ref to={paths.group(row.group)} mono>
                      {row.group}
                    </Ref>
                  </TableCell>
                  <TableCell>
                    <Names items={row.opens.map((client) => ({ label: client.id, to: paths.client(client.id), mono: true }))} empty="only claims" />
                  </TableCell>
                  <TableCell align="right">
                    <State kind="declared" />
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
          <ToggleButtonGroup size="small" exclusive value={kind} onChange={(_, next: ProofKind | null) => next && setKind(next)}>
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
              A proof can fall into several rules at once; it then holds every group they feed, with the shortest lifetime.
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
