import { useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Card from "@mui/material/Card";
import CardContent from "@mui/material/CardContent";
import Chip from "@mui/material/Chip";
import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";

import { access, every, reason, settings } from "./api";
import { ClientSource } from "./gen/directoryroster/v1/settings_pb";
import { useAsync } from "./hooks";
import { Failure, Loading } from "./ui";

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
    <Box>
      <Typography variant="h6">Settings</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        One thing is writable here. Everything else is deployment configuration, shown so that you can see
        what the hub is running with.
      </Typography>

      <Loading busy={current.loading} />
      <Failure error={failure ?? current.error} />

      <Card variant="outlined" sx={{ mb: 2 }}>
        <CardContent>
          <Stack direction="row" spacing={1} sx={{ alignItems: "center", mb: 1 }}>
            <Typography variant="subtitle2">OAuth client</Typography>
            {client?.configured ? (
              <Chip size="small" color="success" variant="outlined" label="configured" />
            ) : (
              <Chip size="small" color="warning" label="not configured" />
            )}
            {declared ? <Chip size="small" variant="outlined" color="secondary" label="declared" /> : null}
          </Stack>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Registered once with the directory backend. It drives both admin consent, when an operator
            connects a workspace, and sign-in, where the hub runs its own login. The secret is never shown.
          </Typography>

          {declared ? (
            <Alert severity="info">
              The deployment declared this client ({client?.clientId}). Change it in the values.
            </Alert>
          ) : (
            <Stack spacing={2} sx={{ maxWidth: 520 }}>
              <TextField
                label="Client id"
                size="small"
                value={clientId || client?.clientId || ""}
                onChange={(e) => setClientId(e.target.value)}
                disabled={!operator}
                fullWidth
              />
              <TextField
                label="Client secret"
                size="small"
                type="password"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
                disabled={!operator}
                fullWidth
              />
              <Box>
                <Button
                  variant="contained"
                  disabled={!operator || !clientId || !clientSecret}
                  onClick={() => void save()}
                >
                  Save
                </Button>
              </Box>
            </Stack>
          )}
        </CardContent>
      </Card>

      <Card variant="outlined" sx={{ mb: 2 }}>
        <CardContent>
          <Typography variant="subtitle2" gutterBottom>
            Policy layers
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            The declared layer comes from the deployment and is read-only here. The console layer is what was
            added on the Access tab; it is the same YAML, so an installation that started standalone moves its
            edits into git by pasting.
          </Typography>
          {policy.value?.consoleLayer ? (
            <Box
              component="pre"
              sx={{ m: 0, p: 2, fontSize: 13, fontFamily: "monospace", bgcolor: "action.hover", borderRadius: 1, overflowX: "auto" }}
            >
              {policy.value.consoleLayer}
            </Box>
          ) : (
            <Typography variant="body2" color="text.secondary">
              The console layer is empty: every membership in force was declared by the deployment.
            </Typography>
          )}
        </CardContent>
      </Card>

      <Card variant="outlined">
        <CardContent>
          <Typography variant="subtitle2" gutterBottom>
            Freshness
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            <Knob label="Snapshot refresh" value={every(current.value?.refreshInterval)} hint="how often a new snapshot is taken" />
            <Knob label="Freshness window" value={every(current.value?.freshnessWindow)} hint="how old a snapshot may be before its domains stop being authoritative" />
            <Knob label="Probe" value={every(current.value?.probeInterval)} hint="how often a credential is checked and domains re-read" />
            <Knob label="Snapshot store" value={current.value?.cacheBackend ?? "—"} hint="where snapshots live" />
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}

function Knob({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <Box sx={{ minWidth: 160 }}>
      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
        {label}
      </Typography>
      <Typography variant="h6" sx={{ fontFamily: "monospace" }}>
        {value}
      </Typography>
      <Typography variant="caption" color="text.secondary">
        {hint}
      </Typography>
    </Box>
  );
}
