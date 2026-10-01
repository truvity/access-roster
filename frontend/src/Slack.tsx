import { useState, type ReactNode } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
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
import TableRow from "@mui/material/TableRow";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";

import { at, ago, reason, slack } from "./api";
import type { SlackBreaker, SlackRemovalConfirmation, SlackWorkspaceStatus } from "./gen/directoryroster/v1/slack_pb";
import { useAsync } from "./hooks";
import { paths } from "./router";
import { ChangeOwnerDialog, OwnerField } from "./Owner";
import { initialOwner, ownerSentence, ownerValid, type OwnerOffer } from "./ownerModel";
import { configurationTokenUrl, looksLikeConfigurationToken } from "./slackAppsModel";
import {
  breakerSentence,
  connectionView,
  isConfirmed,
  needsToken,
  nextStep,
  offersDisconnect,
  offersReconnect,
  offersRefresh,
  passRequested,
  summaryOf,
  tickNotice,
  type Step,
} from "./slackModel";
import { Failure, Loading, Mono, Nothing, Page, Ref, Section, State, type StateKind } from "./ui";

type Props = { onDone: (message: string) => void };

/** What a dialog is asking for: a configuration token to connect a
 *  workspace or to update its App, or confirmation of a disconnect. */
type Asking =
  | { ws: SlackWorkspaceStatus; purpose: "connect" | "reconnect" }
  | { ws: SlackWorkspaceStatus; purpose: "disconnect" }
  | { ws: SlackWorkspaceStatus; purpose: "owner" };

/** The Slack workspaces the policy declares: whether each is connected,
 *  what the controller last did there, and the things an operator of its
 *  owner does about it — connect, install, reconnect, disconnect, and
 *  confirm a removal set the controller held back.
 *
 *  Whether the caller may take a step is the server's per-workspace answer
 *  (`canOperate`), never the caller's installation-wide role. */
export function SlackPage({ onDone }: Props) {
  const loaded = useAsync(() => slack.getSlackStatus({}), []);
  const workspaces = loaded.value?.workspaces ?? [];
  // What the caller may name as an owner, which the server decides.
  const offer: OwnerOffer = { choices: loaded.value?.ownerChoices ?? [], mayBeNone: loaded.value?.mayConnectWithoutOwner ?? false };
  const [asking, setAsking] = useState<Asking | undefined>();
  const [busy, setBusy] = useState<string | undefined>();
  const [failure, setFailure] = useState<string | undefined>();

  // Install is a navigation to Slack: Slack's own page, then back to the
  // console's callback, which finishes it.
  const begin = async (ws: SlackWorkspaceStatus, configurationToken = "", owner = "") => {
    setBusy(ws.workspace);
    setFailure(undefined);
    try {
      const started = await slack.beginSlackWorkspaceConnect({ workspace: ws.workspace, configurationToken, owner });
      window.location.href = started.url;
    } catch (error) {
      setFailure(reason(error));
      setBusy(undefined);
      loaded.reload();
    }
  };

  return (
    <Page
      title="Workspaces"
      lede="The Slack workspaces the policy declares by key. Connecting one creates the roster's own Slack App in it from a manifest, with a throwaway app configuration token that is used once and never kept; an owner of the workspace installs it; the controller then keeps its channels in step with the directory. The owning directory's operators operate the workspace, and its served domains are how people are found in it."
    >
      <Loading busy={loaded.loading} />
      <Failure error={loaded.error ?? failure} />
      {loaded.value && !loaded.value.connectingAvailable ? (
        <Alert severity="info" sx={{ mb: 2 }}>
          This deployment keeps no state in Kubernetes, so it cannot connect a workspace: a bot token would not survive a restart.
        </Alert>
      ) : null}
      {loaded.value && !loaded.value.reportsAvailable ? (
        <Alert severity="info" sx={{ mb: 2 }}>
          This deployment keeps no report from the Slack controller, so only connections are shown.
        </Alert>
      ) : null}
      {loaded.value && workspaces.length === 0 ? (
        <Nothing>No Slack workspace is declared for a directory you may see. Declare one in the policy&apos;s slack.workspaces by its key, then connect it here.</Nothing>
      ) : null}
      <Stack sx={{ gap: 3 }}>
        {workspaces.map((ws) => (
          <WorkspaceCard
            key={ws.workspace}
            ws={ws}
            busy={busy === ws.workspace}
            connecting={loaded.value?.connectingAvailable ?? false}
            onStep={(step) => (step === "install" ? void begin(ws) : setAsking({ ws, purpose: step === "connect" ? "connect" : "reconnect" }))}
            onReconnect={() => setAsking({ ws, purpose: "reconnect" })}
            onDisconnect={() => setAsking({ ws, purpose: "disconnect" })}
            onChangeOwner={() => setAsking({ ws, purpose: "owner" })}
            onDone={onDone}
            reload={loaded.reload}
          />
        ))}
      </Stack>
      {asking && (asking.purpose === "connect" || asking.purpose === "reconnect") ? (
        <TokenDialog
          key={`${asking.purpose}:${asking.ws.workspace}`}
          ws={asking.ws}
          purpose={asking.purpose}
          offer={offer}
          onCancel={() => setAsking(undefined)}
          onSubmit={(token, owner) => {
            setAsking(undefined);
            void begin(asking.ws, token, owner);
          }}
        />
      ) : null}
      {asking && asking.purpose === "owner" ? (
        <ChangeOwnerDialog
          key={`owner:${asking.ws.workspace}`}
          title={`Change the owner of ${asking.ws.workspace}`}
          current={asking.ws.owner}
          offer={offer}
          noun="Slack workspace"
          save={async (owner) => {
            await slack.changeSlackWorkspaceOwner({ workspace: asking.ws.workspace, owner });
          }}
          onCancel={() => setAsking(undefined)}
          onDone={() => {
            const ws = asking.ws.workspace;
            setAsking(undefined);
            onDone(`The owner of ${ws} is changed.`);
            loaded.reload();
          }}
        />
      ) : null}
      {asking && asking.purpose === "disconnect" ? (
        <DisconnectDialog
          key={`disconnect:${asking.ws.workspace}`}
          ws={asking.ws}
          onCancel={() => setAsking(undefined)}
          onDone={(message) => {
            setAsking(undefined);
            onDone(message);
            loaded.reload();
          }}
        />
      ) : null}
    </Page>
  );
}

function WorkspaceCard({
  ws,
  busy,
  connecting,
  onStep,
  onReconnect,
  onDisconnect,
  onChangeOwner,
  onDone,
  reload,
}: {
  ws: SlackWorkspaceStatus;
  busy: boolean;
  connecting: boolean;
  onStep: (step: Step) => void;
  onReconnect: () => void;
  onDisconnect: () => void;
  onChangeOwner: () => void;
  onDone: (message: string) => void;
  reload: () => void;
}) {
  const [failure, setFailure] = useState<string | undefined>();
  const [confirming, setConfirming] = useState<string | undefined>();
  const [refreshing, setRefreshing] = useState(false);
  // Refresh asks the controller for a pass over this workspace now, instead
  // of at its next interval; it notices within a minute.
  const refresh = async () => {
    setRefreshing(true);
    setFailure(undefined);
    try {
      await slack.requestSlackPass({ workspace: ws.workspace });
      onDone(`A pass over ${ws.workspace} is requested. The controller notices within a minute.`);
      reload();
    } catch (error) {
      setFailure(reason(error));
    } finally {
      setRefreshing(false);
    }
  };
  const view = connectionView(ws);
  const step = nextStep(ws);
  const buttons: ReactNode[] = [];
  if (ws.canOperate && connecting && offersRefresh(ws)) {
    buttons.push(
      <Button key="refresh" size="small" variant="text" disabled={busy || refreshing || passRequested(ws)} onClick={() => void refresh()}>
        Refresh
      </Button>,
    );
  }
  if (ws.canOperate && connecting) {
    if (step === "connect" || step === "install") {
      buttons.push(
        <Button key="step" size="small" variant="contained" disabled={busy} onClick={() => onStep(step)}>
          {step === "connect" ? "Connect" : "Install"}
        </Button>,
      );
    }
    if (offersReconnect(ws)) {
      buttons.push(
        <Button key="reconnect" size="small" variant={step === "reconnect" ? "contained" : "text"} disabled={busy} onClick={onReconnect}>
          Reconnect
        </Button>,
      );
    }
    if (ws.canChangeOwner) {
      buttons.push(
        <Button key="owner" size="small" variant="text" disabled={busy} onClick={onChangeOwner}>
          Change owner
        </Button>,
      );
    }
    if (offersDisconnect(ws)) {
      buttons.push(
        <Button key="disconnect" size="small" color="error" variant="text" disabled={busy} onClick={onDisconnect}>
          Disconnect
        </Button>,
      );
    }
  }
  const confirm = async (channel: string, breaker: SlackBreaker) => {
    setConfirming(channel);
    setFailure(undefined);
    try {
      await slack.confirmSlackRemovals({ workspace: ws.workspace, channel, fingerprint: breaker.fingerprint });
      onDone(`Confirmed: the ${breaker.affected} removals in ${channel ? `${ws.workspace}/${channel}` : ws.workspace} go ahead on the next pass.`);
      reload();
    } catch (error) {
      setFailure(reason(error));
    } finally {
      setConfirming(undefined);
    }
  };

  const held = ws.channels.filter((channel) => channel.breaker && !channel.breaker.confirmed).length;
  const tick = ws.tick;
  const notice = tickNotice(ws);
  const when = at(tick?.at);
  return (
    <Paper variant="outlined" sx={{ p: 2 }}>
      <Stack direction="row" sx={{ alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap", gap: 2 }}>
        <Box sx={{ minWidth: 0 }}>
          <Stack direction="row" sx={{ alignItems: "center", flexWrap: "wrap", gap: 1 }}>
            <Typography variant="h6" sx={{ fontFamily: "monospace" }}>
              {ws.workspace}
            </Typography>
            <State kind={view.kind} label={view.label} title={view.title} />
            {ws.connectionState === "installed" || ws.connectionState === "scopes_missing" ? <ActingChip ws={ws} /> : null}
          </Stack>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            {summaryOf(ws)}
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
            {!ws.declared ? "no longer declared in the policy" : ws.teamId ? <Mono>{ws.teamId}</Mono> : "team recorded at the first install"}
            {ws.connectionState !== "not_connected" ? (
              <> · {ownerSentence(ws.owner, ws.ownerDomain, "only the installation-wide role operates it, and its people are held until an owner is set")}</>
            ) : null}
            {ws.connection?.appSettingsUrl ? (
              <>
                {" · "}
                <a href={ws.connection.appSettingsUrl} target="_blank" rel="noreferrer">
                  {ws.connection.appId} in Slack
                </a>
              </>
            ) : null}
            {ws.connection && at(ws.connection.connectedAt) && ws.connectionState !== "created" ? (
              <> · connected {ago(at(ws.connection.connectedAt))}{ws.connection.connectedBy ? ` by ${ws.connection.connectedBy}` : ""}</>
            ) : null}
            {when ? <> · last pass {ago(when)}</> : null}
          </Typography>
        </Box>
        <Stack direction="row" sx={{ gap: 1, flexShrink: 0, flexWrap: "wrap" }}>
          {buttons}
        </Stack>
      </Stack>

      <Stack sx={{ gap: 1.5, mt: notice || failure || ws.breaker ? 2 : 0 }}>
        <Failure error={failure} />
        {notice ? <Alert severity={notice.severity}>{notice.text}</Alert> : null}
        {ws.breaker && !ws.breaker.confirmed ? (
          <BreakerAlert
            sentence={breakerSentence("workspace", ws.breaker.affected, ws.breaker.total)}
            breaker={ws.breaker}
            confirmation={ws.removalConfirmation}
            canOperate={ws.canOperate}
            busy={confirming === ""}
            onConfirm={() => void confirm("", ws.breaker!)}
          />
        ) : null}
      </Stack>

      {ws.channels.length > 0 ? (
        <Typography variant="body2" sx={{ mt: 2 }}>
          <Ref to={paths.slackChannels({ workspace: ws.workspace })}>
            {ws.channels.length} {ws.channels.length === 1 ? "channel" : "channels"}
          </Ref>
          <Typography component="span" variant="body2" color="text.secondary">
            {" "}
            managed here, and whether each person is where they should be
            {held > 0 ? ` · ${held} ${held === 1 ? "channel holds" : "channels hold"} removals for you to confirm` : ""}
          </Typography>
        </Typography>
      ) : null}

      {ws.leavers.length > 0 ? (
        <Box sx={{ mt: 2 }}>
          <Section title="Leavers" hint="no longer in the directory and still active in a managed channel: reported, never acted on here">
            <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
              <Table size="small">
                <TableBody>
                  {ws.leavers.map((leaver) => (
                    <TableRow key={`${leaver.email}|${leaver.userId}`}>
                      <TableCell>
                        <Mono>{leaver.email || leaver.userId}</Mono>
                        {leaver.reason ? (
                          <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                            {leaver.reason}
                          </Typography>
                        ) : null}
                      </TableCell>
                      <TableCell>{leaver.channels.map((name) => `#${name}`).join(", ")}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Section>
        </Box>
      ) : null}
    </Paper>
  );
}

function ActingChip({ ws }: { ws: SlackWorkspaceStatus }) {
  if (!ws.reported) return <State kind="unreported" />;
  const outcome = ws.tick?.outcome ?? "";
  const known: Record<string, StateKind> = {
    "in-sync": "in-sync",
    applied: "applied",
    "dry-run": "dry-run",
    held: "held",
    retrying: "retrying",
    waiting: "waiting",
    failed: "failed",
  };
  return <State kind={known[outcome] ?? (ws.acting ? "applied" : "dry-run")} />;
}

/** The held removals of a workspace or a channel, and the confirmation that lets exactly that set go ahead. */
export function BreakerAlert({
  sentence,
  breaker,
  confirmation,
  canOperate,
  busy,
  onConfirm,
}: {
  sentence: string;
  breaker: SlackBreaker;
  confirmation?: SlackRemovalConfirmation;
  canOperate: boolean;
  busy: boolean;
  onConfirm: () => void;
}) {
  const confirmed = isConfirmed(breaker, confirmation);
  return (
    <Alert
      severity="error"
      action={
        canOperate ? (
          <Button color="inherit" size="small" disabled={busy || confirmed} onClick={onConfirm}>
            {confirmed ? "Confirmed" : "Confirm"}
          </Button>
        ) : null
      }
    >
      <strong>{sentence}</strong> That is more often a policy mistake than people leaving. Read the removals below; confirming lets exactly this set go ahead,
      and lapses after a day.
      {confirmed && confirmation ? (
        <> Confirmed by {confirmation.confirmedBy} {ago(at(confirmation.confirmedAt))}.</>
      ) : null}
    </Alert>
  );
}

/** Asks for the configuration token, and holds it only while the dialog
 *  is open: the field is cleared the moment it is submitted, before the
 *  call, so neither a failure nor a re-render keeps it. */
function TokenDialog({
  ws,
  purpose,
  offer,
  onCancel,
  onSubmit,
}: {
  ws: SlackWorkspaceStatus;
  purpose: "connect" | "reconnect";
  offer: OwnerOffer;
  onCancel: () => void;
  onSubmit: (token: string, owner: string) => void;
}) {
  const [token, setToken] = useState("");
  const [owner, setOwner] = useState(() => initialOwner(offer));
  const required = needsToken(ws, purpose);
  // The owner is chosen once, when the workspace is first connected.
  const choosesOwner = purpose === "connect";
  const valid = (token === "" ? !required : looksLikeConfigurationToken(token)) && (!choosesOwner || ownerValid(offer, owner));
  const submit = () => {
    const submitted = token.trim();
    setToken("");
    onSubmit(submitted, choosesOwner ? owner : "");
  };
  return (
    <Dialog open onClose={onCancel} fullWidth maxWidth="sm">
      <DialogTitle>{purpose === "connect" ? `Connect ${ws.workspace}` : `Reconnect ${ws.workspace}`}</DialogTitle>
      <DialogContent>
        <DialogContentText sx={{ mb: 2 }}>
          {purpose === "connect" ? (
            <>
              Slack creates an App only for someone holding an <strong>app configuration token</strong>. Generate one at{" "}
              <a href={configurationTokenUrl} target="_blank" rel="noreferrer">
                api.slack.com/apps
              </a>{" "}
              under &ldquo;Your App Configuration Tokens&rdquo;, for the workspace that will own the App, and paste it here. It expires in twelve hours, is used
              once, and is never stored or logged. You are then sent to Slack, where an owner of {ws.workspace} approves the App.
            </>
          ) : ws.needsConfigurationToken ? (
            <>
              The roster now asks for scopes the App was created without, and Slack changes an App&rsquo;s scopes only for a configuration token. Generate one at{" "}
              <a href={configurationTokenUrl} target="_blank" rel="noreferrer">
                api.slack.com/apps
              </a>{" "}
              and paste it: it updates the App once and is never stored. An owner then approves the new scopes in Slack.
            </>
          ) : (
            <>An owner of {ws.workspace} approves the App in Slack again. No token is needed: the App already carries every scope the roster asks for.</>
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
            slotProps={{ htmlInput: { spellCheck: false, autoCapitalize: "off", "data-lpignore": "true" } }}
          />
        ) : null}
        {choosesOwner ? <OwnerField offer={offer} noun="Slack workspace" value={owner} onChange={setOwner} /> : null}
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel}>Cancel</Button>
        <Button variant="contained" disabled={!valid} onClick={submit}>
          {purpose === "connect" ? "Connect" : "Reconnect"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** Disconnecting revokes the bot token and forgets the connection. When
 *  Slack will not revoke it the connection is kept, and the dialog offers
 *  to forget it anyway, saying what that leaves behind. */
function DisconnectDialog({ ws, onCancel, onDone }: { ws: SlackWorkspaceStatus; onCancel: () => void; onDone: (message: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const go = async (forgetAnyway: boolean) => {
    setBusy(true);
    setFailure(undefined);
    try {
      const done = await slack.disconnectSlackWorkspace({ workspace: ws.workspace, forgetAnyway });
      onDone(
        done.revoked
          ? `${ws.workspace} is disconnected and its bot token is revoked. Delete the App in Slack when you no longer need it.`
          : `${ws.workspace} is disconnected. The bot token was not revoked: remove the App in Slack.`,
      );
    } catch (error) {
      setFailure(reason(error));
      setBusy(false);
    }
  };
  return (
    <Dialog open onClose={busy ? undefined : onCancel} fullWidth maxWidth="sm">
      <DialogTitle>Disconnect {ws.workspace}?</DialogTitle>
      <DialogContent>
        <DialogContentText>
          The controller stops acting in {ws.workspace}: no channel is created, nobody is invited or removed. The bot token is revoked in Slack and forgotten
          here. The App itself stays in Slack until it is deleted there; connecting again creates a new one.
        </DialogContentText>
        <Failure error={failure} />
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        {failure ? (
          <Button color="error" disabled={busy} onClick={() => void go(true)}>
            Forget anyway
          </Button>
        ) : null}
        <Button color="error" variant="contained" disabled={busy} onClick={() => void go(false)}>
          Disconnect
        </Button>
      </DialogActions>
    </Dialog>
  );
}
