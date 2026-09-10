import Alert from "@mui/material/Alert";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";

import { every, settings } from "./api";
import { useAsync } from "./hooks";
import { Facts, Failure, Loading, Page, Section, State } from "./ui";

export function SettingsView() {
  const current = useAsync(() => settings.getSettings({}), []);

  const client = current.value?.oauthClient;

  return (
    <Page
      title="Settings"
      lede="Deployment configuration, shown so that you can see what this installation is running with. Nothing here is editable: the policy is a file in git, and every credential is a Secret."
    >
      <Loading busy={current.loading} />
      <Failure error={current.error} />

      <Section
        title="OAuth client"
        hint="registered once with the provider backend; it drives admin consent and sign-in, and the secret is never shown"
        action={
          <Stack direction="row" spacing={1}>
            <State kind={client?.configured ? "configured" : "unconfigured"} />
          </Stack>
        }
      >
        <Alert severity="info">
          {client?.configured
            ? `The deployment provides this client (${client?.clientId}). Change it where the Secret is delivered.`
            : "No OAuth client is configured, so nobody can sign in and this installation issues tokens to machines only. It is delivered as a Secret, named in the values."}
        </Alert>
      </Section>

      <Section title="Freshness" hint="how often the hub reads, and how old a reading may be before it stops vouching">
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Facts
            items={[
              { label: "Snapshot refresh", value: every(current.value?.refreshInterval) },
              { label: "Freshness window", value: every(current.value?.freshnessWindow) },
              { label: "Probe", value: every(current.value?.probeInterval) },
              { label: "Snapshot store", value: current.value?.cacheBackend ?? "—" },
            ]}
          />
        </Paper>
      </Section>
    </Page>
  );
}
