import Box from "@mui/material/Box";
import Chip from "@mui/material/Chip";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";

import { access, ago, at, workspaces, type Me } from "./api";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { Failure, Loading, Nothing, Ref, Section } from "./ui";

/** The first question anyone has is whether something is broken. This
 *  page answers it, and every count is a link to the thing it counts. */
export function Overview({ me }: { me?: Me }) {
  const tenants = useAsync(() => workspaces.listWorkspaces({}), []);
  const policy = useAsync(() => access.getPolicy({}), []);

  const list = tenants.value?.workspaces ?? [];
  const groups = policy.value?.groups ?? [];
  const clients = policy.value?.clients ?? [];

  const failing = list.filter((w) => !w.health?.ok);
  const domains = list.flatMap((w) => w.domains.map((d) => ({ ...d, workspace: w.id })));
  const contested = domains.filter((d) => d.conflict);
  const held = domains.filter((d) => !d.authoritative && !d.conflict);
  const emptyGroups = groups.filter((g) => g.members.length === 0 && g.matchers.length === 0);
  const openTo = new Set(clients.flatMap((c) => c.requires));
  const unusedGroups = groups.filter((g) => !openTo.has(g.name) && !g.name.startsWith("hub-"));
  const staleSnapshot = list
    .map((w) => at(w.snapshotAt))
    .filter(Boolean)
    .sort((a, b) => (a && b ? a.getTime() - b.getTime() : 0))[0];

  const problems =
    failing.length + contested.length + held.length === 0 && list.length > 0;

  return (
    <Box>
      <Loading busy={tenants.loading || policy.loading} />
      <Failure error={tenants.error ?? policy.error} />

      <Stack direction="row" spacing={2} sx={{ flexWrap: "wrap", gap: 2, mb: 3 }}>
        <Tile
          label="Directories"
          value={`${list.length - failing.length}/${list.length}`}
          hint={failing.length ? `${failing.length} failing` : "all healthy"}
          bad={failing.length > 0}
          to={paths.directories()}
        />
        <Tile
          label="Domains served"
          value={`${domains.length - contested.length - held.length}/${domains.length}`}
          hint={contested.length ? `${contested.length} contested` : held.length ? `${held.length} on hold` : "all authoritative"}
          bad={contested.length + held.length > 0}
          to={paths.directories()}
        />
        <Tile label="Internal groups" value={String(groups.length)} hint={`${emptyGroups.length} with nobody in them`} to={paths.groups()} />
        <Tile label="Clients" value={String(clients.length)} hint="what the groups buy" to={paths.clients()} />
        <Tile label="Last snapshot" value={ago(staleSnapshot)} hint="oldest across tenants" to={paths.directories()} />
      </Stack>

      <Section title="Needs attention" hint="everything else is working">
        {problems && emptyGroups.length === 0 && unusedGroups.length === 0 && !policy.value?.adminEnabled ? (
          <Nothing>Nothing. Every domain is authoritative and every group leads somewhere.</Nothing>
        ) : (
          <Stack spacing={1}>
            {policy.value?.adminEnabled ? (
              <Row severity="warning" title="The break-glass admin account is enabled">
                Turn it off in the deployment once a group grants operator to a real identity.
              </Row>
            ) : null}
            {failing.map((w) => (
              <Row key={w.id} severity="error" title={`${w.id} is not answering`}>
                {w.health?.error || "the last probe failed"}. Its domains are a hold until it recovers.{" "}
                <Ref to={paths.directory(w.id)}>Open it</Ref>.
              </Row>
            ))}
            {contested.map((d) => (
              <Row key={d.name} severity="warning" title={`${d.name} is claimed twice`}>
                Authoritative for neither tenant until one of them drops it.{" "}
                <Ref to={paths.directory(d.workspace)}>Open {d.workspace}</Ref>.
              </Row>
            ))}
            {held.map((d) => (
              <Row key={d.name} severity="warning" title={`${d.name} is on hold`}>
                Its snapshot is stale or its probe failed. Consumers add but never remove.{" "}
                <Ref to={paths.directory(d.workspace)}>Open {d.workspace}</Ref>.
              </Row>
            ))}
            {emptyGroups.map((g) => (
              <Row key={g.name} severity="info" title={`${g.name} has nobody in it`}>
                Declared but empty, so it grants nothing. <Ref to={paths.group(g.name)}>Attach a directory group</Ref>.
              </Row>
            ))}
            {unusedGroups.map((g) => (
              <Row key={g.name} severity="info" title={`${g.name} opens no client`}>
                No client requires it, so it only adds claims. <Ref to={paths.group(g.name)}>Open it</Ref>.
              </Row>
            ))}
          </Stack>
        )}
      </Section>

      {me?.email ? (
        <Section title="You" hint="what this account is entitled to">
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap", gap: 1 }}>
              <Typography variant="body2">{me.name || me.email}</Typography>
              {(me.groups ?? []).map((group) => (
                <Chip key={group} size="small" variant="outlined" label={group} />
              ))}
              <Box sx={{ flexGrow: 1 }} />
              <Ref to={paths.person(me.email)}>See everything you reach</Ref>
            </Stack>
          </Paper>
        </Section>
      ) : null}
    </Box>
  );
}

function Tile({
  label,
  value,
  hint,
  bad,
  to,
}: {
  label: string;
  value: string;
  hint: string;
  bad?: boolean;
  to: string;
}) {
  return (
    <Paper variant="outlined" sx={{ p: 2, minWidth: 170, flexGrow: 1 }}>
      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
        {label}
      </Typography>
      <Typography variant="h5" sx={{ fontFamily: "monospace" }} color={bad ? "warning.main" : "text.primary"}>
        {value}
      </Typography>
      <Ref to={to}>
        <Typography variant="caption">{hint}</Typography>
      </Ref>
    </Paper>
  );
}

function Row({
  severity,
  title,
  children,
}: {
  severity: "error" | "warning" | "info";
  title: string;
  children: React.ReactNode;
}) {
  const color = severity === "error" ? "warning.main" : severity === "warning" ? "warning.main" : "text.secondary";
  return (
    <Paper variant="outlined" sx={{ p: 1.5, borderLeft: 3, borderLeftColor: color }}>
      <Typography variant="body2" sx={{ fontWeight: 600 }}>
        {title}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {children}
      </Typography>
    </Paper>
  );
}
