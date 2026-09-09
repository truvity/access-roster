import Box from "@mui/material/Box";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";

import { access, ago, at, settings, workspaces, type Me } from "./api";
import { useAsync, useWhile } from "./hooks";
import { paths } from "./router";
import { incomplete, Setup, type Progress } from "./Setup";
import { DomainReason } from "./gen/directoryroster/v1/workspace_pb";
import { domainReason, Failure, Loading, Names, Nothing, Page, Ref, Section } from "./ui";

/** The first question anyone has is whether something is broken. This
 *  page answers it, and every count is a link to the thing it counts. */
export function Overview({ me, operator }: { me?: Me; operator: boolean }) {
  const tenants = useAsync(() => workspaces.listWorkspaces({}), []);
  const policy = useAsync(() => access.getPolicy({}), []);
  const directoryGroups = useAsync(() => access.listDirectoryGroups({}), []);
  const current = useAsync(() => settings.getSettings({}), []);

  const list = tenants.value?.workspaces ?? [];
  const groups = policy.value?.groups ?? [];
  const clients = policy.value?.clients ?? [];

  const failing = list.filter((w) => !w.health?.ok);
  // Only a SERVED domain has a standing. One this hub was told not to
  // read is not a degraded answer, it is no answer — and counting those
  // as problems is what put "0/7 served, 7 on hold" on this page while
  // the directory's own page correctly said six of them were simply not
  // served.
  const domains = list.flatMap((w) => w.domains.filter((d) => d.served).map((d) => ({ ...d, workspace: w.id })));
  const unserved = list.reduce((n, w) => n + w.domains.filter((d) => !d.served).length, 0);
  const contested = domains.filter((d) => d.conflict);
  const provisional = domains.filter((d) => !d.authoritative && !d.conflict);
  const emptyGroups = groups.filter((g) => g.members.length === 0 && g.rules.length === 0);
  const attached = new Set(groups.flatMap((g) => g.members.map((m) => m.address)));
  const allDirectoryGroups = directoryGroups.value?.groups ?? [];
  const usedDirectoryGroups = allDirectoryGroups.filter((g) => attached.has(g.email));
  const openTo = new Set(clients.flatMap((c) => c.requires));
  const unusedGroups = groups.filter((g) => !openTo.has(g.name) && !g.name.startsWith("hub-"));
  const staleSnapshot = list
    .map((w) => at(w.snapshotAt))
    .filter(Boolean)
    .sort((a, b) => (a && b ? a.getTime() - b.getTime() : 0))[0];

  const clean = failing.length + contested.length + provisional.length === 0 && list.length > 0;

  // A directory connected moments ago has no snapshot yet, and its first
  // read lands seconds later. Without this the counts on the page that
  // exists to say whether anything is broken are a photograph of the
  // moment before anything had been read. It stops when the snapshot
  // lands: nothing here polls a steady state.
  const firstSnapshot = list.some((w) => at(w.snapshotAt) === undefined);
  useWhile(firstSnapshot, 2000, () => {
    tenants.reload();
    directoryGroups.reload();
  });

  // An installation that is not finished is not "broken", and the counts
  // below cannot say anything useful about it yet. What it needs is the
  // next step, so that is what the page leads with until there is none.
  const operators = groups.find((g) => g.name === "all:access-roster:operator");
  const progress: Progress | undefined = policy.value && current.value
    ? {
        clientConfigured: Boolean(current.value.oauthClient?.configured),
        directories: list.length,
        operators: (operators?.members.length ?? 0) + (operators?.rules.length ?? 0),
        standingPassword: policy.value.recoveryKind === "password",
        setup: current.value.setup,
        operatorGroup: operators?.name ?? "all:access-roster:operator",
      }
    : undefined;
  const settingUp = progress !== undefined && incomplete(progress);
  const standingPassword = policy.value?.recoveryKind === "password";

  return (
    <Page title="Overview" lede="Whether anything is broken, and the counts behind it. Every number is a link to the thing it counts.">
      <Loading busy={firstSnapshot || tenants.loading || policy.loading || current.loading} />
      <Failure error={tenants.error ?? policy.error} />

      {settingUp && progress ? <Setup progress={progress} operator={operator} /> : null}

      <Box sx={{ display: "grid", gridTemplateColumns: { xs: "repeat(2, 1fr)", sm: "repeat(3, 1fr)", lg: "repeat(6, 1fr)" }, gap: 1.5, mb: 4 }}>
        <Tile label="Directories" value={`${list.length - failing.length}/${list.length}`} hint={failing.length ? `${failing.length} failing` : "all healthy"} bad={failing.length > 0} to={paths.directories()} />
        <Tile
          label="Domains served"
          value={`${domains.length - contested.length - provisional.length}/${domains.length}`}
          hint={
            contested.length
              ? `${contested.length} contested`
              : provisional.length
                ? `${provisional.length} provisional`
                : unserved
                  ? `all authoritative, ${unserved} not served`
                  : "all authoritative"
          }
          bad={contested.length + provisional.length > 0}
          to={paths.directories()}
        />
        <Tile label="Directory groups" value={`${usedDirectoryGroups.length}/${allDirectoryGroups.length}`} hint="attached to an internal group" to={paths.directoryGroups()} />
        <Tile label="Internal groups" value={String(groups.length)} hint={`${emptyGroups.length} with nobody in them`} to={paths.groups()} />
        <Tile label="Clients" value={String(clients.length)} hint="what the internal groups buy" to={paths.clients()} />
        <Tile label="Last snapshot" value={ago(staleSnapshot)} hint="oldest across directories" to={paths.directories()} />
      </Box>

      <Section title="Needs attention" hint="everything else is working">
        {clean && emptyGroups.length === 0 && unusedGroups.length === 0 && !standingPassword ? (
          <Nothing>Nothing. Every served domain is authoritative and every group leads somewhere.</Nothing>
        ) : (
          <Stack spacing={1}>
            {standingPassword && !settingUp ? (
              <Row severity="warning" title="A recovery password is kept on this installation">
                It is a standing credential. In a cluster, recovery proves access to the API server instead and
                keeps nothing; otherwise turn it off once a group grants operator to a real identity.
              </Row>
            ) : null}
            {failing.map((w) => (
              <Row key={w.id} severity="error" title={`${w.id} is not answering`}>
                {w.health?.error || "the last probe failed"}. Its domains are provisional until it recovers. <Ref to={paths.directory(w.id)}>Open it</Ref>.
              </Row>
            ))}
            {contested.map((d) => (
              <Row key={d.name} severity="warning" title={`${d.name} is served by two directories`}>
                Authoritative for neither until one of them stops serving it. <Ref to={paths.directory(d.workspace)}>Open {d.workspace}</Ref>.
              </Row>
            ))}
            {provisional.map((d) => (
              <Row
                key={d.name}
                severity={d.reason === DomainReason.FIRST_SNAPSHOT_PENDING ? "info" : "warning"}
                title={`${d.name} is provisional${domainReason[d.reason] ? ` — ${domainReason[d.reason].short}` : ""}`}
              >
                {domainReason[d.reason]?.why ?? "Its answers may not be acted on for removals."} Consumers add but never remove.{" "}
                <Ref to={paths.directory(d.workspace)}>Open {d.workspace}</Ref>.
              </Row>
            ))}
            {emptyGroups.map((g) => (
              <Row key={g.name} severity="info" title={`${g.name} has nobody in it`}>
                Declared, but no directory group feeds it, so it grants nothing. <Ref to={paths.group(g.name)}>Attach one</Ref>.
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
          <Paper variant="outlined" sx={{ px: 1.5, py: 1 }}>
            <Stack direction="row" sx={{ alignItems: "center", flexWrap: "wrap", gap: 1 }}>
              <Typography variant="body2" sx={{ fontWeight: 600 }}>
                {me.name || me.email}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                in
              </Typography>
              <Names items={(me.groups ?? []).map((group) => ({ label: group, to: paths.group(group), mono: true }))} empty="no internal group" />
              <Box sx={{ flexGrow: 1 }} />
              <Ref to={paths.person(me.email)}>See your chain</Ref>
            </Stack>
          </Paper>
        </Section>
      ) : null}
    </Page>
  );
}

function Tile({ label, value, hint, bad, to }: { label: string; value: string; hint: string; bad?: boolean; to: string }) {
  return (
    <Paper variant="outlined" sx={{ px: 1.75, py: 1.5, minWidth: 0 }}>
      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
        {label}
      </Typography>
      <Typography variant="h5" sx={{ fontFamily: "monospace", my: 0.25 }} color={bad ? "warning.main" : "text.primary"}>
        {value}
      </Typography>
      <Ref to={to}>
        <Typography variant="caption">{hint}</Typography>
      </Ref>
    </Paper>
  );
}

function Row({ severity, title, children }: { severity: "error" | "warning" | "info"; title: string; children: React.ReactNode }) {
  const color = severity === "info" ? "divider" : "warning.main";
  return (
    <Paper variant="outlined" sx={{ px: 1.5, py: 1, borderLeft: 3, borderLeftColor: color }}>
      <Typography variant="body2" sx={{ fontWeight: 600 }}>
        {title}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {children}
      </Typography>
    </Paper>
  );
}
