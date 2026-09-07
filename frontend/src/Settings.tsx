import { useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";

import { access, every, reason, settings } from "./api";
import { ClientSource } from "./gen/directoryroster/v1/settings_pb";
import { useAsync } from "./hooks";
import { Facts, Failure, Loading, Page, Section, State } from "./ui";

export function SettingsView({ operator, onDone }: { operator: boolean; onDone: (message: string) => void }) {
  const current = useAsync(() => settings.getSettings({}), []);
  const policy = useAsync(() => access.getPolicy({}), []);
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [failure, setFailure] = useState<string | undefined>();

  const client = current.value?.oauthClient;
  const declared = client?.source === ClientSource.DECLARED;

  const save = async () => {
    setFailure(undefined);
    try {
      await settings.setOAuthClient({ clientId, clientSecret });
      setClientSecret("");
      onDone("OAuth client stored.");
      current.reload();
    } catch (error) {
      setFailure(reason(error));
    }
  };

  return (
    <Page title="Settings" lede="One thing is writable here. Everything else is deployment configuration, shown so that you can see what the hub is running with.">
      <Loading busy={current.loading} />
      <Failure error={failure ?? current.error} />

      <Section
        title="OAuth client"
        hint="registered once with the directory backend; it drives admin consent and sign-in, and the secret is never shown"
        action={
          <Stack direction="row" spacing={1}>
            <State kind={client?.configured ? "configured" : "unconfigured"} />
            {declared ? <State kind="declared" /> : null}
          </Stack>
        }
      >
        {declared ? (
          <Alert severity="info">The deployment declared this client ({client?.clientId}). Change it in the values.</Alert>
        ) : (
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Stack spacing={2} sx={{ maxWidth: 520 }}>
              <TextField label="Client id" value={clientId || client?.clientId || ""} onChange={(e) => setClientId(e.target.value)} disabled={!operator} fullWidth />
              <TextField label="Client secret" type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} disabled={!operator} fullWidth />
              <Box>
                <Button variant="contained" disabled={!operator || !clientId || !clientSecret} onClick={() => void save()}>
                  Save
                </Button>
              </Box>
            </Stack>
          </Paper>
        )}
      </Section>

      <Section
        title="Policy layers"
        hint="the declared layer comes from the deployment and is read-only here; the console layer is what was attached in this console, as the same YAML, so a standalone start moves into git by pasting"
      >
        {policy.value?.consoleLayer ? (
          <Paper variant="outlined" sx={{ p: 2, overflowX: "auto" }}>
            <Typography component="pre" variant="body2" sx={{ m: 0, fontFamily: "monospace" }}>
              {policy.value.consoleLayer}
            </Typography>
          </Paper>
        ) : (
          <Typography variant="body2" color="text.secondary">
            The console layer is empty: every membership in force was declared by the deployment.
          </Typography>
        )}
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
