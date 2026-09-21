import Alert from "@mui/material/Alert";
import Paper from "@mui/material/Paper";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Typography from "@mui/material/Typography";

import { secretStores } from "./api";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { byState, opens, stateOf, summary } from "./secretStoresModel";
import { Failure, Loading, Mono, Names, Nothing, Page, Ref, Section, State } from "./ui";

/** The lede every page here repeats in one form or another: this console
 *  READS the store. Saying it once per page is deliberate — the rest of
 *  the console has buttons, and a reader who assumes this page does too
 *  will look for one when they find drift. */
const readOnly =
  "Read-only. The store's desired state is written in your own repository and applied by whatever applies it; this console shows what it found beside what this deployment declares. Nothing here writes to a store, and the reader cannot read a secret's value at all.";

/** Every declared store, with a line per namespace. */
export function SecretStores() {
  const stores = useAsync(() => secretStores.listSecretManagers({}), []);
  const managers = stores.value?.managers ?? [];

  return (
    <Page
      title="Secret stores"
      lede={`The stores this deployment declares, and what each namespace holds. A namespace is an environment, and its groups are this roster's own. ${readOnly}`}
    >
      <Loading busy={stores.loading} />
      <Failure error={stores.error} />

      {managers.length === 0 ? (
        <Nothing>No secret store is declared. Declare one in the deployment&apos;s values to show it here.</Nothing>
      ) : (
        managers.map((manager) => (
          <Section
            key={manager.name}
            title={manager.name}
            hint={`${manager.address} · logs in on ${manager.mount} as ${manager.role}`}
          >
            <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Namespace</TableCell>
                    <TableCell>Environment</TableCell>
                    <TableCell>Groups</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {manager.namespaces.map((namespace) => (
                    <TableRow key={namespace.name} hover>
                      <TableCell>
                        <Ref to={paths.secretNamespace(manager.name, namespace.name)} mono>
                          {namespace.name}
                        </Ref>
                      </TableCell>
                      <TableCell>
                        <Mono>{namespace.environment}</Mono>
                      </TableCell>
                      <TableCell>
                        {namespace.unreadable ? (
                          <State kind="unreadable" title={namespace.reason} />
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            {summary(namespace.counts, false)}
                          </Typography>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Section>
        ))
      )}
    </Page>
  );
}

/** One namespace: every group, in the four states, with what each one
 *  opens. */
export function SecretNamespace({ manager, namespace }: { manager: string; namespace: string }) {
  const answer = useAsync(() => secretStores.getSecretManagerNamespace({ manager, namespace }), [manager, namespace]);
  const found = answer.value;
  const groups = [...(found?.groups ?? [])].sort(byState);
  const unreadable = found?.namespace?.unreadable ?? false;

  return (
    <Page
      title={`${manager} · ${namespace}`}
      lede={`The groups of the ${found?.namespace?.environment ?? namespace} environment, as this store holds them. ${readOnly}`}
      facts={[
        { label: "Store", value: <Ref to={paths.secretStores()}>{manager}</Ref> },
        { label: "Environment", value: <Mono>{found?.namespace?.environment ?? namespace}</Mono> },
        { label: "Groups", value: summary(found?.namespace?.counts, unreadable) },
      ]}
    >
      <Loading busy={answer.loading} />
      <Failure error={answer.error} />

      {found?.namespace?.reason ? (
        <Alert severity={unreadable ? "warning" : "info"} sx={{ mb: 2 }}>
          {found.namespace.reason}
          {unreadable
            ? " — this is what the reader was told, not what the store holds. A namespace nobody may read and an empty one look the same from here."
            : ""}
        </Alert>
      ) : null}

      {groups.length === 0 ? (
        <Nothing>
          {unreadable
            ? "Nothing could be read here, so nothing is shown. This is not the same as an empty namespace."
            : "No group is declared for this environment and the store holds none."}
        </Nothing>
      ) : (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Group</TableCell>
                <TableCell>State</TableCell>
                <TableCell>Opens</TableCell>
                <TableCell>Doors</TableCell>
                <TableCell>Entities</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {groups.map((group) => (
                <TableRow key={group.name} hover>
                  <TableCell>
                    {group.declared ? (
                      // A declared group is this roster's own: its page
                      // says who is in it, which is the question the
                      // store cannot answer.
                      <Ref to={paths.group(group.name)} mono>
                        {group.name}
                      </Ref>
                    ) : (
                      <Mono>{group.name}</Mono>
                    )}
                  </TableCell>
                  <TableCell>
                    <State
                      kind={stateOf(group.state)}
                      title={
                        group.state && !group.hasPolicy && stateOf(group.state) === "bound"
                          ? "The group is there and no policy of its name is: it grants nothing, and the store reports neither half as a fault."
                          : undefined
                      }
                      label={stateOf(group.state) === "bound" && !group.hasPolicy ? "no policy" : undefined}
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: "monospace" }}>
                      {opens(group.rules) || "—"}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Names items={group.doors.map((door) => ({ label: door, mono: true }))} empty="none" />
                  </TableCell>
                  <TableCell>{group.members || "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {found?.policies?.length ? (
        <Section
          title="Policies"
          hint="Every ACL policy this namespace holds, including the ones no group above carries. A policy nothing is bound to grants nobody anything — and is also how a group that was removed leaves its permissions behind."
        >
          <Names items={found.policies.map((name) => ({ label: name, mono: true }))} empty="none" />
        </Section>
      ) : null}

      {found?.doors?.length ? (
        <Section title="Doors" hint="The namespace's auth mounts. A group bound at one and not the other is admitted for the CLI and refused in the web console, or the other way round.">
          <Names items={found.doors.map((door) => ({ label: `${door.path} (${door.type})`, mono: true }))} empty="none" />
        </Section>
      ) : null}
    </Page>
  );
}
