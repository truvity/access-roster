import { useState } from "react";
import Alert from "@mui/material/Alert";
import Autocomplete from "@mui/material/Autocomplete";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogContentText from "@mui/material/DialogContentText";
import DialogTitle from "@mui/material/DialogTitle";
import FormControlLabel from "@mui/material/FormControlLabel";
import MenuItem from "@mui/material/MenuItem";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Switch from "@mui/material/Switch";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";

import { reason, slackConnect } from "./api";
import type { ListSlackSharedChannelsResponse, SlackDiscoveredChannel, SlackSharedChannel } from "./gen/directoryroster/v1/slack_connect_pb";
import { useAsync } from "./hooks";
import {
  definitionOf,
  discoveredForm,
  discoveredStatus,
  emptyForm,
  formOf,
  guestChoices,
  hostChoices,
  manageBlocked,
  unplacedSides,
  privacyLabel,
  problems,
  sideLabel,
  stateView,
  withSidePrivate,
  withGuests,
  withHost,
  withPerSide,
  type Form,
} from "./slackConnectModel";
import { directoryLabel } from "./ownerModel";
import { landings, landingSentence, sourceOptions, unreachedWarning } from "./slackSourcesModel";
import { SourcePicker } from "./SourcePicker";
import { Failure, Loading, Mono, Nothing, Page, State } from "./ui";

type Props = { onDone: (message: string) => void };

/** What a dialog is doing: writing a new channel, editing one, or
 *  confirming a delete. */
type Dialogue = { kind: "create" } | { kind: "manage"; row: SlackDiscoveredChannel } | { kind: "edit"; channel: SlackSharedChannel } | { kind: "delete"; channel: SlackSharedChannel };

/** The Slack Connect channels between this installation's own
 *  workspaces, created and edited here.
 *
 *  Whether the caller may change a row is the server's per-record answer
 *  (`canOperate`): the operator of the HOST workspace's owner, or of the
 *  installation. A guest workspace's operator sees the channel and
 *  cannot change it. */
export function SlackConnectPage({ onDone }: Props) {
  const listed = useAsync(() => slackConnect.listSlackSharedChannels({}), []);
  const channels = listed.value?.channels ?? [];
  const [dialogue, setDialogue] = useState<Dialogue | undefined>();
  const canCreate = hostChoices(listed.value?.workspaces ?? []).length > 0 && listed.value?.available === true;

  const done = (message: string) => {
    setDialogue(undefined);
    onDone(message);
    listed.reload();
  };

  return (
    <Page
      title="Slack Connect"
      lede="Shared channels between this installation's own Slack workspaces. The host workspace creates and owns a channel and invites the others' bots; each side then manages its own people, who come only from the directory groups named here. Changes are recorded in the audit trail."
      actions={
        canCreate ? (
          <Button variant="contained" onClick={() => setDialogue({ kind: "create" })}>
            New channel
          </Button>
        ) : undefined
      }
    >
      <Loading busy={listed.loading} />
      <Failure error={listed.error} />
      {listed.value && !listed.value.available ? (
        <Alert severity="info" sx={{ mb: 2 }}>
          This deployment keeps no state in Kubernetes, so it keeps no shared channel records.
        </Alert>
      ) : null}
      {listed.value && listed.value.available && channels.length === 0 ? <Nothing>No shared channel is defined for a workspace you may see.</Nothing> : null}
      {channels.length > 0 ? (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small" sx={{ minWidth: 720 }}>
            <TableHead>
              <TableRow>
                <TableCell>Channel</TableCell>
                <TableCell>Host</TableCell>
                <TableCell>Shared with</TableCell>
                <TableCell>Directory groups</TableCell>
                <TableCell>Visibility</TableCell>
                <TableCell>State</TableCell>
                <TableCell align="right" />
              </TableRow>
            </TableHead>
            <TableBody>
              {channels.map((channel) => (
                <ChannelRow
                  key={channel.channel?.name}
                  channel={channel}
                  onEdit={() => setDialogue({ kind: "edit", channel })}
                  onDelete={() => setDialogue({ kind: "delete", channel })}
                />
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ) : null}
      <DiscoveredSection rows={listed.value?.discovered ?? []} available={listed.value?.available === true} onManage={(row) => setDialogue({ kind: "manage", row })} />
      {dialogue?.kind === "delete" ? <DeleteDialog channel={dialogue.channel} onCancel={() => setDialogue(undefined)} onDone={done} /> : null}
      {dialogue && dialogue.kind !== "delete" && listed.value ? (
        <EditDialog
          key={dialogue.kind === "edit" ? dialogue.channel.channel?.name : dialogue.kind === "manage" ? dialogue.row.channelId : "new"}
          options={listed.value}
          editing={dialogue.kind === "edit" ? dialogue.channel : undefined}
          discovered={dialogue.kind === "manage" ? dialogue.row : undefined}
          onCancel={() => setDialogue(undefined)}
          onDone={done}
        />
      ) : null}
    </Page>
  );
}

function ChannelRow({ channel, onEdit, onDelete }: { channel: SlackSharedChannel; onEdit: () => void; onDelete: () => void }) {
  const def = channel.channel;
  const view = stateView(channel);
  if (!def) return null;
  return (
    <TableRow hover>
      <TableCell>
        <Mono>#{def.name}</Mono>
      </TableCell>
      <TableCell>
        <Mono>{def.host || "—"}</Mono>
      </TableCell>
      <TableCell>{def.with.join(", ")}</TableCell>
      <TableCell>
        <Typography variant="body2" sx={{ wordBreak: "break-word" }}>
          {def.from.join(", ")}
        </Typography>
      </TableCell>
      <TableCell>{def.host ? privacyLabel(def) : ""}</TableCell>
      <TableCell>
        <State kind={view.kind} label={view.label} title={view.title} />
        {channel.reason && (channel.state === "invalid" || channel.state === "held") ? (
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", maxWidth: 320 }}>
            {channel.reason}
          </Typography>
        ) : null}
      </TableCell>
      <TableCell align="right">
        {channel.canOperate ? (
          <Stack direction="row" sx={{ gap: 1, justifyContent: "flex-end" }}>
            {def.host ? (
              <Button size="small" onClick={onEdit}>
                Edit
              </Button>
            ) : null}
            <Button size="small" color="error" onClick={onDelete}>
              Delete
            </Button>
          </Stack>
        ) : null}
      </TableCell>
    </TableRow>
  );
}

/** The channels the workspaces' bots can see in Slack, one row each,
 *  whether or not a record manages them. Managing one opens the create
 *  form prefilled from what was seen. */
function DiscoveredSection({ rows, available, onManage }: { rows: SlackDiscoveredChannel[]; available: boolean; onManage: (row: SlackDiscoveredChannel) => void }) {
  if (rows.length === 0) return null;
  return (
    <>
      <Typography variant="h6" sx={{ mt: 4, mb: 1 }}>
        Discovered
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        Slack Connect channels that already exist and that a connected workspace's bot can see. Every connected workspace is a side. One nothing places the channel
        in is unknown, not absent: its bot lists a private channel only once it is in it, and a public one it has not joined may not be listed at all, so add it
        by hand if the channel is shared there. Taking a channel under management never removes anybody from it.
      </Typography>
      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small" sx={{ minWidth: 720 }}>
          <TableHead>
            <TableRow>
              <TableCell>Channel</TableCell>
              <TableCell>Host</TableCell>
              <TableCell>Sides</TableCell>
              <TableCell>Managed</TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((row) => {
              const blocked = manageBlocked(row);
              return (
                <TableRow hover key={row.channelId}>
                  <TableCell>
                    <Mono>{row.sides.find((s) => s.workspace === row.hostWorkspace)?.name || row.channelId}</Mono>
                  </TableCell>
                  <TableCell>{row.hostWorkspace ? <Mono>{row.hostWorkspace}</Mono> : "external"}</TableCell>
                  <TableCell>
                    {row.sides.map((side) => (
                      <Typography key={side.workspace} variant="body2" sx={{ wordBreak: "break-word" }}>
                        <strong>{side.workspace}</strong>: {sideLabel(side)}
                        {side.seen ? `, ${side.members} members` : ""}
                      </Typography>
                    ))}
                    {row.externalTeams > 0 ? (
                      <Typography variant="caption" color="text.secondary">
                        and {row.externalTeams} {row.externalTeams === 1 ? "team" : "teams"} that {row.externalTeams === 1 ? "is" : "are"} not connected here
                      </Typography>
                    ) : null}
                    {unplacedSides(row).length > 0 ? (
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                        Not prefilled: {unplacedSides(row).join(", ")}
                      </Typography>
                    ) : null}
                  </TableCell>
                  <TableCell>{discoveredStatus(row)}</TableCell>
                  <TableCell align="right">
                    {!row.managed && available ? (
                      <span title={blocked}>
                        <Button size="small" disabled={!row.canManage} onClick={() => onManage(row)}>
                          Manage
                        </Button>
                      </span>
                    ) : null}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
    </>
  );
}

function EditDialog({
  options,
  editing,
  discovered,
  onCancel,
  onDone,
}: {
  options: ListSlackSharedChannelsResponse;
  editing?: SlackSharedChannel;
  discovered?: SlackDiscoveredChannel;
  onCancel: () => void;
  onDone: (message: string) => void;
}) {
  const [form, setForm] = useState<Form>(editing?.channel ? formOf(editing.channel) : discovered ? discoveredForm(discovered) : emptyForm);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const hosts = hostChoices(options.workspaces);
  const guests = guestChoices(options.workspaces, form.host);
  const wrong = problems(form);
  // Where the chosen groups land: each side takes the groups of the
  // directory that owns it.
  const picker = sourceOptions(options.sourceDirectories);
  const ownerOfSide = (workspace: string) => options.workspaces.find((w) => w.key === workspace)?.owner ?? "";
  const placed = landings(
    [form.host, ...form.with].map((workspace) => ({ workspace, owner: ownerOfSide(workspace) })),
    form.from,
    picker,
  );
  const ownerName = (owner: string) => {
    const dir = options.sourceDirectories.find((d) => d.workspaceId === owner);
    return dir ? directoryLabel(dir.workspaceId, dir.domains) : owner;
  };
  const warning = unreachedWarning(placed.unreached);

  const submit = async () => {
    setBusy(true);
    setFailure(undefined);
    try {
      const channel = definitionOf(form);
      if (editing) {
        await slackConnect.updateSlackSharedChannel({ channel });
        onDone(`#${channel.name} is updated. The controller applies it on its next pass.`);
      } else {
        await slackConnect.createSlackSharedChannel({ channel });
        if (discovered) {
          onDone(`#${channel.name} is under management. The controller takes over the existing channel on its next pass; nobody is removed from it.`);
          return;
        }
        onDone(`#${channel.name} is defined. ${channel.host} creates it and invites ${channel.with.join(", ")} on the controller's next pass.`);
      }
    } catch (error) {
      setFailure(reason(error));
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onCancel} fullWidth maxWidth="sm">
      <DialogTitle>{editing ? `Edit #${form.name}` : discovered ? "Manage an existing channel" : "New Slack Connect channel"}</DialogTitle>
      <DialogContent>
        <Stack sx={{ gap: 2, pt: 1 }}>
          <TextField
            label="Channel name"
            value={form.name}
            onChange={(event) => setForm({ ...form, name: event.target.value })}
            disabled={busy || !!editing}
            helperText={editing ? "A name cannot change: create a new channel to use another." : "Lowercase letters, digits, '-' and '_'."}
            slotProps={{ htmlInput: { spellCheck: false, autoCapitalize: "off" } }}
            autoFocus={!editing}
          />
          <TextField
            select
            label="Host workspace"
            value={form.host}
            onChange={(event) => setForm(withHost(form, event.target.value))}
            disabled={busy || !!editing || !!discovered}
            helperText={
              editing
                ? "The host cannot change: it owns the channel in Slack. Create a new channel to host from another workspace."
                : discovered
                  ? "The workspace that hosts the channel in Slack."
                  : "The workspace that creates and owns the channel. Only workspaces you operate are offered."
            }
          >
            {(editing ? [form.host] : hosts).map((key) => (
              <MenuItem key={key} value={key}>
                {key}
              </MenuItem>
            ))}
          </TextField>
          <Autocomplete
            multiple
            options={guests}
            value={form.with}
            onChange={(_, value) => setForm(withGuests(form, value))}
            disabled={busy}
            renderInput={(params) => <TextField {...params} label="Shared with" helperText="The other workspaces. Each accepts the invitation in Slack." />}
          />
          <SourcePicker
            options={picker}
            value={form.from}
            onChange={(value) => setForm({ ...form, from: value })}
            disabled={busy}
            helperText="Groups of any connected directory. Members come only from these groups, never from individuals."
          />
          {form.host && form.from.length > 0 ? (
            <Stack sx={{ gap: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                A person joins on the side whose workspace&apos;s owning directory serves their address, so the chosen groups land like this:
              </Typography>
              {placed.perSide.map((landing) => (
                <Typography key={landing.workspace} variant="caption" color="text.secondary" sx={{ pl: 1 }}>
                  {landingSentence(landing, ownerName(landing.owner))}
                </Typography>
              ))}
              {warning ? <Alert severity="warning">{warning}</Alert> : null}
            </Stack>
          ) : null}
          <FormControlLabel
            control={<Switch checked={form.private} onChange={(event) => setForm({ ...form, private: event.target.checked, perSide: undefined })} disabled={busy || !!form.perSide} />}
            label={form.perSide ? "Visibility set per side" : form.private ? "Private on every side" : "Public on every side"}
          />
          <FormControlLabel
            control={<Switch checked={!!form.perSide} onChange={(event) => setForm(withPerSide(form, event.target.checked))} disabled={busy || !form.host || form.with.length === 0} />}
            label="Choose visibility per side"
          />
          {form.perSide
            ? Object.keys(form.perSide).map((side) => (
                <FormControlLabel
                  key={side}
                  sx={{ ml: 2 }}
                  control={<Switch checked={form.perSide?.[side] ?? false} onChange={(event) => setForm(withSidePrivate(form, side, event.target.checked))} disabled={busy} />}
                  label={`${side}: ${form.unknownSides.includes(side) ? "choose, the bot cannot see this side" : form.perSide?.[side] ? "private" : "public"}`}
                />
              ))
            : null}
          {discovered ? (
            <Typography variant="caption" color="text.secondary">
              The existing channel {discovered.channelId} is taken over as it is: the bot joins a public side, a private side needs the bot invited, and nobody is
              removed. Its members come only from the directory groups chosen here.
            </Typography>
          ) : null}
          {wrong.length > 0 && (form.name !== "" || form.host !== "") ? (
            <Typography variant="caption" color="text.secondary">
              {wrong.join(" ")}
            </Typography>
          ) : null}
          <Failure error={failure} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        <Button variant="contained" disabled={busy || wrong.length > 0} onClick={() => void submit()}>
          {editing ? "Save" : "Create"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function DeleteDialog({ channel, onCancel, onDone }: { channel: SlackSharedChannel; onCancel: () => void; onDone: (message: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const name = channel.channel?.name ?? "";

  const submit = async () => {
    setBusy(true);
    setFailure(undefined);
    try {
      const deleted = await slackConnect.deleteSlackSharedChannel({ name });
      onDone(deleted.note);
    } catch (error) {
      setFailure(reason(error));
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onCancel} fullWidth maxWidth="sm">
      <DialogTitle>Delete the record of #{name}?</DialogTitle>
      <DialogContent>
        <DialogContentText>
          This deletes the record only. <strong>The channel stays in Slack</strong>, in every workspace that has it, and is not archived. The reconciler stops
          managing it: people who were added stay until someone removes them in Slack, and nobody is added or removed any more.
        </DialogContentText>
        <Failure error={failure} />
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        <Button color="error" variant="contained" disabled={busy} onClick={() => void submit()}>
          Delete the record
        </Button>
      </DialogActions>
    </Dialog>
  );
}
