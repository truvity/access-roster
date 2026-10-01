import { useState, type ReactNode } from "react";
import Alert from "@mui/material/Alert";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogContentText from "@mui/material/DialogContentText";
import DialogTitle from "@mui/material/DialogTitle";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";

import { at, ago, reason, slackApps } from "./api";
import type { SlackApp } from "./gen/directoryroster/v1/slack_apps_pb";
import { useAsync } from "./hooks";
import { configurationTokenUrl, looksLikeConfigurationToken, nextStep, offersReinstall, stateView, summaryOf } from "./slackAppsModel";
import { Failure, Loading, Mono, Nothing, Page, State } from "./ui";

type Props = { onDone: (message: string) => void };

/** What a dialog is asking for: a configuration token to create an App,
 *  or, optionally, to update one before it is reinstalled. */
type Asking = { app: SlackApp; purpose: "create" | "reinstall" };

/** The Slack Apps the deployment declares: where each stands, and the
 *  steps an operator of its workspace takes — create, install, reinstall.
 *
 *  Whether the caller may take a step is the server's per-App answer
 *  (`canOperate`), never the caller's installation-wide role: an operator
 *  of one company's directory operates that company's workspaces only. */
export function SlackAppsPage({ onDone }: Props) {
  const listed = useAsync(() => slackApps.listSlackApps({}), []);
  const apps = listed.value?.apps ?? [];
  const [asking, setAsking] = useState<Asking | undefined>();
  const [busy, setBusy] = useState<string | undefined>();
  const [failure, setFailure] = useState<string | undefined>();

  // Install is a navigation to Slack: Slack's own page, then back to the
  // console's callback, which finishes it.
  const install = async (app: SlackApp, configurationToken = "") => {
    setBusy(app.id);
    setFailure(undefined);
    try {
      const started = await slackApps.installSlackApp({ id: app.id, configurationToken });
      window.location.href = started.url;
    } catch (error) {
      setFailure(reason(error));
      setBusy(undefined);
    }
  };

  const created = (app: SlackApp) => {
    setAsking(undefined);
    onDone(`${app.name} is created in Slack. Install it next: an owner of ${app.workspace} approves it there.`);
    listed.reload();
  };

  return (
    <Page
      title="Slack Apps"
      lede="The Slack Apps this deployment declares in slackApps. Creating one takes a throwaway app configuration token, used once and never kept; installing it is approved in Slack by an owner of the workspace; the bot token that comes back is kept in a Secret, and only for the workspace the policy names."
    >
      <Loading busy={listed.loading} />
      <Failure error={listed.error ?? failure} />
      {listed.value && !listed.value.available ? (
        <Alert severity="info" sx={{ mb: 2 }}>
          This deployment keeps no state in Kubernetes, so it keeps no Slack Apps: a bot token would not survive a restart.
        </Alert>
      ) : null}
      {listed.value && apps.length === 0 ? (
        <Nothing>No Slack App is declared for a workspace you may see. Declare one in slackApps, for a workspace of the policy.</Nothing>
      ) : null}
      {apps.length > 0 ? (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small" sx={{ minWidth: 720 }}>
            <TableHead>
              <TableRow>
                <TableCell>App</TableCell>
                <TableCell>Workspace</TableCell>
                <TableCell>State</TableCell>
                <TableCell>Scopes</TableCell>
                <TableCell align="right" />
              </TableRow>
            </TableHead>
            <TableBody>
              {apps.map((app) => (
                <AppRow
                  key={app.id}
                  app={app}
                  busy={busy === app.id}
                  onCreate={() => setAsking({ app, purpose: "create" })}
                  onInstall={() => void install(app)}
                  onReinstall={() => setAsking({ app, purpose: "reinstall" })}
                />
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ) : null}
      {asking ? (
        <TokenDialog
          key={`${asking.purpose}:${asking.app.id}`}
          asking={asking}
          onCancel={() => setAsking(undefined)}
          onCreated={() => created(asking.app)}
          onReinstall={(token) => {
            setAsking(undefined);
            void install(asking.app, token);
          }}
        />
      ) : null}
    </Page>
  );
}

function AppRow({
  app,
  busy,
  onCreate,
  onInstall,
  onReinstall,
}: {
  app: SlackApp;
  busy: boolean;
  onCreate: () => void;
  onInstall: () => void;
  onReinstall: () => void;
}) {
  const view = stateView(app);
  const step = nextStep(app);
  const buttons: ReactNode[] = [];
  if (app.canOperate) {
    if (step === "create") {
      buttons.push(
        <Button key="create" size="small" variant="contained" disabled={busy} onClick={onCreate}>
          Create
        </Button>,
      );
    }
    if (step === "install") {
      buttons.push(
        <Button key="install" size="small" variant="contained" disabled={busy} onClick={onInstall}>
          Install
        </Button>,
      );
    }
    if (offersReinstall(app)) {
      buttons.push(
        <Button key="reinstall" size="small" variant={step === "reinstall" ? "contained" : "text"} disabled={busy} onClick={onReinstall}>
          Reinstall
        </Button>,
      );
    }
  }
  return (
    <TableRow hover>
      <TableCell>
        <Mono>{app.name || app.id}</Mono>
        <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
          {summaryOf(app)}
        </Typography>
        {app.appSettingsUrl ? (
          <Typography variant="caption" sx={{ display: "block" }}>
            <a href={app.appSettingsUrl} target="_blank" rel="noreferrer">
              {app.appId} in Slack
            </a>
            {at(app.installedAt) ? <> · installed {ago(at(app.installedAt))}</> : null}
          </Typography>
        ) : null}
      </TableCell>
      <TableCell>
        <Mono>{app.workspace}</Mono>
        <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
          {app.teamId || "workspace not connected yet"}
        </Typography>
      </TableCell>
      <TableCell>
        <State kind={view.kind} label={view.label} title={view.title} />
      </TableCell>
      <TableCell>
        <Typography variant="body2" sx={{ wordBreak: "break-word" }}>
          {app.botScopes.join(", ")}
        </Typography>
        {app.missingScopes.length > 0 ? (
          <Typography variant="caption" color="warning.main" sx={{ display: "block" }}>
            not granted: {app.missingScopes.join(", ")}
          </Typography>
        ) : null}
      </TableCell>
      <TableCell align="right">
        <Stack direction="row" sx={{ gap: 1, justifyContent: "flex-end" }}>
          {buttons}
        </Stack>
      </TableCell>
    </TableRow>
  );
}

/** Asks for the configuration token, and holds it only while the dialog
 *  is open: the field is cleared the moment it is submitted, before the
 *  call, so neither a failure nor a re-render keeps it. */
function TokenDialog({
  asking,
  onCancel,
  onCreated,
  onReinstall,
}: {
  asking: Asking;
  onCancel: () => void;
  onCreated: () => void;
  onReinstall: (token: string) => void;
}) {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const { app, purpose } = asking;
  const required = purpose === "create" || app.needsConfigurationToken;
  const valid = token === "" ? !required : looksLikeConfigurationToken(token);

  const submit = async () => {
    const submitted = token.trim();
    setToken("");
    if (purpose === "reinstall") {
      onReinstall(submitted);
      return;
    }
    setBusy(true);
    setFailure(undefined);
    try {
      await slackApps.createSlackApp({ id: app.id, configurationToken: submitted });
      onCreated();
    } catch (error) {
      setFailure(reason(error));
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onCancel} fullWidth maxWidth="sm">
      <DialogTitle>{purpose === "create" ? `Create ${app.name}` : `Reinstall ${app.name}`}</DialogTitle>
      <DialogContent>
        <DialogContentText sx={{ mb: 2 }}>
          {purpose === "create" ? (
            <>
              Slack creates an App only for someone holding an <strong>app configuration token</strong>. Generate one at{" "}
              <a href={configurationTokenUrl} target="_blank" rel="noreferrer">
                api.slack.com/apps
              </a>{" "}
              under &ldquo;Your App Configuration Tokens&rdquo;, for the workspace that will own the App, and paste it here. It expires in twelve hours, is used
              once, and is never stored or logged. Installing it is the next step.
            </>
          ) : app.needsConfigurationToken ? (
            <>
              The entry declares scopes the App was created without, and Slack changes an App&rsquo;s scopes only for a configuration token. Generate one at{" "}
              <a href={configurationTokenUrl} target="_blank" rel="noreferrer">
                api.slack.com/apps
              </a>{" "}
              and paste it: it updates the App once, is never stored, and then an owner approves the new scopes in Slack.
            </>
          ) : (
            <>An owner of {app.workspace} approves the App in Slack again. No token is needed: the App already carries every declared scope.</>
          )}
        </DialogContentText>
        {required ? (
          <TextField
            label="App configuration token"
            type="password"
            autoComplete="off"
            autoFocus
            fullWidth
            value={token}
            onChange={(event) => setToken(event.target.value)}
            disabled={busy}
            slotProps={{ htmlInput: { spellCheck: false, autoCapitalize: "off", "data-lpignore": "true" } }}
          />
        ) : null}
        <Failure error={failure} />
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        <Button variant="contained" disabled={busy || !valid} onClick={() => void submit()}>
          {purpose === "create" ? "Create" : "Reinstall"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
