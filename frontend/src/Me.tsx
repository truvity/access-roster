import { useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Card from "@mui/material/Card";
import CardContent from "@mui/material/CardContent";
import Chip from "@mui/material/Chip";
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

import { access, forHowLong, roleName } from "./api";
import type { ExplainRequest, ExplainResponse } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { Failure, Loading } from "./ui";

type Kind = "person" | "ci" | "workload";

/** Effective access: what a proof is entitled to, and what put it there.
 *  A person, a CI job and a workload are the same question, so they are
 *  the same page — which is also the only place the whole model is
 *  visible at once. */
export function MeView({ operator }: { operator: boolean }) {
  const [kind, setKind] = useState<Kind>("person");
  const [email, setEmail] = useState("");
  const [repository, setRepository] = useState("example-org/gitops");
  const [ref, setRef] = useState("refs/heads/master");
  const [namespace, setNamespace] = useState("identity-system");
  const [name, setName] = useState("authorization-webhook");
  const [asked, setAsked] = useState<ExplainRequest | undefined>();

  const explained = useAsync(() => access.explain(asked ?? {}), [asked]);

  const ask = () => {
    if (kind === "person") setAsked({ email: email.trim() } as ExplainRequest);
    if (kind === "ci") setAsked({ github: { repository: repository.trim(), ref: ref.trim() } } as ExplainRequest);
    if (kind === "workload")
      setAsked({ serviceAccount: { namespace: namespace.trim(), name: name.trim() } } as ExplainRequest);
  };

  return (
    <Box>
      <Typography variant="h6">Effective access</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        What a proof is entitled to right now, and what put it there. Nothing is granted directly: a role, a
        claim and a client are all reached by being in an internal group.
      </Typography>

      {operator ? (
        <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
          <Stack spacing={2}>
            <ToggleButtonGroup
              size="small"
              exclusive
              value={kind}
              onChange={(_, next: Kind | null) => next && setKind(next)}
            >
              <ToggleButton value="person">A person</ToggleButton>
              <ToggleButton value="ci">A CI job</ToggleButton>
              <ToggleButton value="workload">A workload</ToggleButton>
            </ToggleButtonGroup>

            <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start", flexWrap: "wrap", gap: 1 }}>
              {kind === "person" ? (
                <TextField
                  size="small"
                  label="Address"
                  placeholder="leave empty for yourself"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && ask()}
                  sx={{ minWidth: 320 }}
                />
              ) : null}
              {kind === "ci" ? (
                <>
                  <TextField
                    size="small"
                    label="Repository"
                    value={repository}
                    onChange={(e) => setRepository(e.target.value)}
                    sx={{ minWidth: 260 }}
                  />
                  <TextField
                    size="small"
                    label="Ref"
                    value={ref}
                    onChange={(e) => setRef(e.target.value)}
                    sx={{ minWidth: 220 }}
                  />
                </>
              ) : null}
              {kind === "workload" ? (
                <>
                  <TextField
                    size="small"
                    label="Namespace"
                    value={namespace}
                    onChange={(e) => setNamespace(e.target.value)}
                    sx={{ minWidth: 220 }}
                  />
                  <TextField
                    size="small"
                    label="ServiceAccount"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    sx={{ minWidth: 260 }}
                  />
                </>
              ) : null}
              <Button variant="contained" onClick={ask} sx={{ mt: 0.25 }}>
                Explain
              </Button>
              {asked ? (
                <Button sx={{ mt: 0.25 }} onClick={() => { setAsked(undefined); setEmail(""); setKind("person"); }}>
                  Back to me
                </Button>
              ) : null}
            </Stack>
          </Stack>
        </Paper>
      ) : null}

      <Loading busy={explained.loading} />
      <Failure error={explained.error} />
      {explained.value ? <Explanation value={explained.value} /> : null}
    </Box>
  );
}

function Explanation({ value }: { value: ExplainResponse }) {
  const identity = value.identity;
  const person = Boolean(identity?.email);
  const name = [identity?.givenName, identity?.familyName].filter(Boolean).join(" ");

  return (
    <Stack spacing={2}>
      <Card variant="outlined">
        <CardContent>
          <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap", gap: 1 }}>
            <Typography variant="subtitle1">
              {name || identity?.email || "a machine identity"}
            </Typography>
            {name && identity?.email ? (
              <Typography variant="body2" color="text.secondary">
                {identity.email}
              </Typography>
            ) : null}
            <Chip size="small" color="primary" label={roleName(identity?.role ?? 0)} />
            {value.suspended ? (
              <Tooltip title="The directory says this account is not live. A consumer acts on that only because the answer is authoritative.">
                <Chip size="small" color="warning" label="suspended" />
              </Tooltip>
            ) : null}
            {person && !value.inDomain ? (
              <Tooltip title="No connected workspace serves this address's domain, so the hub has no opinion about it.">
                <Chip size="small" variant="outlined" label="no opinion" />
              </Tooltip>
            ) : null}
            {value.inDomain && !value.authoritative ? (
              <Tooltip title="The directory cannot be vouched for right now, so this is a hold rather than a fact.">
                <Chip size="small" color="warning" variant="outlined" label="hold" />
              </Tooltip>
            ) : null}
            <Box sx={{ flexGrow: 1 }} />
            <Typography variant="body2" color="text.secondary">
              token lifetime {forHowLong(value.lifetime)}
            </Typography>
          </Stack>
          {person && value.inDomain && !value.found ? (
            <Alert severity="warning" sx={{ mt: 2 }}>
              The directory does not know this address.
            </Alert>
          ) : null}
        </CardContent>
      </Card>

      <Section title="Internal groups, and what put it in them">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Group</TableCell>
              <TableCell>Because of</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {value.held.map((held) => (
              <TableRow key={held.group} hover>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                    {held.group}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                    {held.via.map((why) => (
                      <Chip key={why} size="small" variant="outlined" label={why} />
                    ))}
                  </Stack>
                </TableCell>
              </TableRow>
            ))}
            {value.held.length === 0 ? (
              <Empty columns={2}>
                In no internal group, so nothing is granted. An operator can attach a directory group to one
                on the Access tab.
              </Empty>
            ) : null}
          </TableBody>
        </Table>
      </Section>

      <Section title="Clients it would be issued a token for">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Client</TableCell>
              <TableCell>Kind</TableCell>
              <TableCell>Requires</TableCell>
              <TableCell>Token</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {value.clients.map((client) => (
              <TableRow key={client.id} hover sx={{ opacity: client.admitted ? 1 : 0.5 }}>
                <TableCell>
                  <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                    <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                      {client.id}
                    </Typography>
                    {client.admitted ? (
                      <Tooltip title="The token's audience would be this client's id.">
                        <Chip size="small" color="success" variant="outlined" label="admitted" />
                      </Tooltip>
                    ) : (
                      <Chip size="small" variant="outlined" label="refused" />
                    )}
                  </Stack>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {client.kind}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
                    {client.requires.map((group) => (
                      <Chip key={group} size="small" variant="outlined" label={group} />
                    ))}
                  </Stack>
                </TableCell>
                <TableCell>
                  <Typography variant="body2">{client.admitted ? forHowLong(client.lifetime) : "—"}</Typography>
                </TableCell>
              </TableRow>
            ))}
            {value.clients.length === 0 ? (
              <Empty columns={4}>No clients are declared, so there is nothing to be issued a token for.</Empty>
            ) : null}
          </TableBody>
        </Table>
      </Section>

      <Box>
        <Typography variant="subtitle2" gutterBottom>
          Claims a token would carry
        </Typography>
        <Paper variant="outlined" sx={{ p: 2, overflowX: "auto" }}>
          <Box component="pre" sx={{ m: 0, fontSize: 13, fontFamily: "monospace" }}>
            {JSON.stringify(value.claims ?? {}, null, 2)}
          </Box>
        </Paper>
      </Box>

      {value.directoryGroups.length ? (
        <Box>
          <Typography variant="subtitle2" gutterBottom>
            Directory groups the hub reports
          </Typography>
          <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
            {value.directoryGroups.map((group) => (
              <Chip key={group} size="small" variant="outlined" label={group} />
            ))}
          </Stack>
        </Box>
      ) : null}
    </Stack>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Box>
      <Typography variant="subtitle2" gutterBottom>
        {title}
      </Typography>
      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        {children}
      </TableContainer>
    </Box>
  );
}

function Empty({ columns, children }: { columns: number; children: React.ReactNode }) {
  return (
    <TableRow>
      <TableCell colSpan={columns}>
        <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
          {children}
        </Typography>
      </TableCell>
    </TableRow>
  );
}
