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

import { reason, slackChannels } from "./api";
import type { ListSlackChannelsResponse, SlackChannelRecord, SlackDiscoveredOrdinary } from "./gen/directoryroster/v1/slack_channels_pb";
import { useAsync } from "./hooks";
import {
  channelDefinitionOf,
  channelProblems,
  discoveredSentence,
  emptyChannelForm,
  formOfDiscovered,
  formOfRecord,
  manageableWorkspaces,
  manageHint,
  modeLabel,
  ownerOf,
  type ChannelForm,
} from "./slackChannelsModel";
import { stateView } from "./slackConnectModel";
import { sourceOptions } from "./slackSourcesModel";
import { SourcePicker } from "./SourcePicker";
import { Failure, Loading, Mono, Nothing, State } from "./ui";

type Dialogue =
  | { kind: "create" }
  | { kind: "manage"; row: SlackDiscoveredOrdinary }
  | { kind: "edit"; record: SlackChannelRecord }
  | { kind: "delete"; record: SlackChannelRecord };

/** The ordinary channels managed from the console: members come from
 *  DIRECTORY groups of the directory that owns the workspace, never from
 *  internal groups. Channels the policy binds stay in git and are shown on
 *  each workspace's card above. Below the list are the channels the bots can
 *  see that nothing manages; Manage takes one under management, prefilled
 *  from what was seen.
 *
 *  Whether the caller may change a row is the server's per-record answer. */
export function SlackChannelsSection({ onDone }: { onDone: (message: string) => void }) {
  const listed = useAsync(() => slackChannels.listSlackChannels({}), []);
  const records = listed.value?.channels ?? [];
  const [dialogue, setDialogue] = useState<Dialogue | undefined>();
  const canCreate = manageableWorkspaces(listed.value?.workspaces ?? []).length > 0 && listed.value?.available === true;

  const done = (message: string) => {
    setDialogue(undefined);
    onDone(message);
    listed.reload();
  };

  return (
    <>
      <Stack direction="row" sx={{ alignItems: "flex-end", justifyContent: "space-between", gap: 2, mt: 4, mb: 1 }}>
        <Typography variant="h6">Console channels</Typography>
        {canCreate ? (
          <Button variant="contained" onClick={() => setDialogue({ kind: "create" })}>
            New channel
          </Button>
        ) : null}
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        Ordinary channels managed here rather than in git. Their members come only from directory groups of the directory that owns the workspace, never from
        internal groups; the controller reconciles them with the same rules as the policy&apos;s channels. Slack Connect channels are on their own page.
        Changes are recorded in the audit trail.
      </Typography>
      <Loading busy={listed.loading} />
      <Failure error={listed.error} />
      {listed.value && !listed.value.available ? (
        <Alert severity="info" sx={{ mb: 2 }}>
          This deployment keeps no state in Kubernetes, so it keeps no console channel records.
        </Alert>
      ) : null}
      {listed.value && listed.value.available && records.length === 0 ? <Nothing>No console channel is defined for a workspace you may see.</Nothing> : null}
      {records.length > 0 ? (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small" sx={{ minWidth: 720 }}>
            <TableHead>
              <TableRow>
                <TableCell>Channel</TableCell>
                <TableCell>Workspace</TableCell>
                <TableCell>Directory groups</TableCell>
                <TableCell>Mode</TableCell>
                <TableCell>State</TableCell>
                <TableCell align="right" />
              </TableRow>
            </TableHead>
            <TableBody>
              {records.map((record) => (
                <RecordRow
                  key={`${record.channel?.workspace}/${record.channel?.name}`}
                  record={record}
                  onEdit={() => setDialogue({ kind: "edit", record })}
                  onDelete={() => setDialogue({ kind: "delete", record })}
                />
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ) : null}
      <DiscoveredSection
        rows={listed.value?.discovered ?? []}
        more={(listed.value?.workspaces ?? []).reduce((n, w) => n + w.discoveredMore, 0)}
        available={listed.value?.available === true}
        onManage={(row) => setDialogue({ kind: "manage", row })}
      />
      {dialogue?.kind === "delete" ? <DeleteDialog record={dialogue.record} onCancel={() => setDialogue(undefined)} onDone={done} /> : null}
      {dialogue && dialogue.kind !== "delete" && listed.value ? (
        <EditDialog
          key={dialogue.kind === "edit" ? `${dialogue.record.channel?.workspace}/${dialogue.record.channel?.name}` : dialogue.kind === "manage" ? dialogue.row.channelId : "new"}
          options={listed.value}
          editing={dialogue.kind === "edit" ? dialogue.record : undefined}
          discovered={dialogue.kind === "manage" ? dialogue.row : undefined}
          onCancel={() => setDialogue(undefined)}
          onDone={done}
        />
      ) : null}
    </>
  );
}

function RecordRow({ record, onEdit, onDelete }: { record: SlackChannelRecord; onEdit: () => void; onDelete: () => void }) {
  const def = record.channel;
  const view = stateView(record);
  if (!def) return null;
  return (
    <TableRow hover>
      <TableCell>
        <Mono>#{def.name}</Mono>
        {def.workspace ? (
          <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
            {def.private ? "private" : "public"}
          </Typography>
        ) : null}
      </TableCell>
      <TableCell>
        <Mono>{def.workspace || "—"}</Mono>
      </TableCell>
      <TableCell>
        <Typography variant="body2" sx={{ wordBreak: "break-word" }}>
          {def.sources.join(", ")}
        </Typography>
      </TableCell>
      <TableCell>{def.workspace ? def.mode || "extend" : ""}</TableCell>
      <TableCell>
        <State kind={view.kind} label={view.label} title={view.title} />
        {record.reason && (record.state === "invalid" || record.state === "held") ? (
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", maxWidth: 320 }}>
            {record.reason}
          </Typography>
        ) : null}
      </TableCell>
      <TableCell align="right">
        {record.canOperate ? (
          <Stack direction="row" sx={{ gap: 1, justifyContent: "flex-end" }}>
            {def.workspace ? (
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

function DiscoveredSection({ rows, more, available, onManage }: { rows: SlackDiscoveredOrdinary[]; more: number; available: boolean; onManage: (row: SlackDiscoveredOrdinary) => void }) {
  if (rows.length === 0) return null;
  return (
    <>
      <Typography variant="h6" sx={{ mt: 4, mb: 1 }}>
        Discovered channels
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        Channels a workspace&apos;s bot can see that neither the policy nor a record manages: public channels, and private ones the bot is in. Taking one under
        management never removes anybody from it unless you choose strict, and then only people the directory vouches have left.
        {more > 0 ? ` ${more} more are not listed: the report holds the first of each workspace's channels by name.` : ""}
      </Typography>
      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small" sx={{ minWidth: 560 }}>
          <TableHead>
            <TableRow>
              <TableCell>Channel</TableCell>
              <TableCell>Workspace</TableCell>
              <TableCell>As seen</TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((row) => (
              <TableRow hover key={`${row.workspace}/${row.channelId}`}>
                <TableCell>
                  <Mono>#{row.name}</Mono>
                </TableCell>
                <TableCell>
                  <Mono>{row.workspace}</Mono>
                </TableCell>
                <TableCell>{discoveredSentence(row)}</TableCell>
                <TableCell align="right">
                  {available ? (
                    <span title={manageHint(row)}>
                      <Button size="small" disabled={!row.canManage} onClick={() => onManage(row)}>
                        Manage
                      </Button>
                    </span>
                  ) : null}
                </TableCell>
              </TableRow>
            ))}
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
  options: ListSlackChannelsResponse;
  editing?: SlackChannelRecord;
  discovered?: SlackDiscoveredOrdinary;
  onCancel: () => void;
  onDone: (message: string) => void;
}) {
  const [form, setForm] = useState<ChannelForm>(editing ? formOfRecord(editing) : discovered ? formOfDiscovered(discovered) : emptyChannelForm);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const owner = ownerOf(options.workspaces, form.workspace);
  // An ordinary channel takes its own directory's groups only.
  const picker = sourceOptions(options.sourceDirectories.filter((dir) => dir.workspaceId === owner));
  const wrong = channelProblems(form, owner);
  const fixed = !!editing || !!discovered;

  const submit = async () => {
    setBusy(true);
    setFailure(undefined);
    try {
      const channel = channelDefinitionOf(form);
      if (editing) {
        await slackChannels.updateSlackChannel({ channel });
        onDone(`#${channel.name} is updated. The controller applies it on its next pass.`);
      } else {
        await slackChannels.createSlackChannel({ channel });
        onDone(
          discovered
            ? `#${channel.name} is under management. The controller takes over the existing channel on its next pass.`
            : `#${channel.name} is defined. The controller takes it over by name, or creates it, on its next pass.`,
        );
      }
    } catch (error) {
      setFailure(reason(error));
      setBusy(false);
    }
  };

  return (
    <Dialog open onClose={busy ? undefined : onCancel} fullWidth maxWidth="sm">
      <DialogTitle>{editing ? `Edit #${form.name}` : discovered ? "Manage an existing channel" : "New console channel"}</DialogTitle>
      <DialogContent>
        <Stack sx={{ gap: 2, pt: 1 }}>
          <TextField
            select
            label="Workspace"
            value={form.workspace}
            onChange={(event) => setForm({ ...form, workspace: event.target.value, sources: [] })}
            disabled={busy || fixed}
            helperText={fixed ? "A channel's workspace cannot change." : "Only workspaces you operate are offered."}
          >
            {(fixed ? [form.workspace] : manageableWorkspaces(options.workspaces)).map((key) => (
              <MenuItem key={key} value={key}>
                {key}
              </MenuItem>
            ))}
          </TextField>
          <TextField
            label="Channel name"
            value={form.name}
            onChange={(event) => setForm({ ...form, name: event.target.value })}
            disabled={busy || fixed}
            helperText={fixed ? "A name cannot change: create a new record to use another." : "Lowercase letters, digits, '-' and '_'. A channel of that name is taken over; none, created."}
            slotProps={{ htmlInput: { spellCheck: false, autoCapitalize: "off" } }}
            autoFocus={!fixed}
          />
          <FormControlLabel
            control={<Switch checked={form.private} onChange={(event) => setForm({ ...form, private: event.target.checked, mode: event.target.checked ? form.mode : "extend", ignore: event.target.checked ? form.ignore : [] })} disabled={busy || fixed} />}
            label={form.private ? "Private" : "Public"}
          />
          <TextField
            select
            label="Mode"
            value={form.mode}
            onChange={(event) => setForm({ ...form, mode: event.target.value === "strict" ? "strict" : "extend", ignore: event.target.value === "strict" ? form.ignore : [] })}
            disabled={busy}
            helperText={`${modeLabel(form.mode)}. Strict is for private channels: the controller removes people only after the directory vouches they no longer belong, and never past its breaker.`}
          >
            <MenuItem value="extend">{modeLabel("extend")}</MenuItem>
            <MenuItem value="strict" disabled={!form.private}>
              {modeLabel("strict")}
            </MenuItem>
          </TextField>
          {form.mode === "strict" ? (
            <Autocomplete
              multiple
              freeSolo
              options={[]}
              value={form.ignore}
              onChange={(_, value) => setForm({ ...form, ignore: value })}
              disabled={busy}
              renderInput={(params) => <TextField {...params} label="Never remove" helperText="Addresses, or Slack user ids, a strict channel keeps. Press Enter after each." />}
            />
          ) : null}
          <SourcePicker
            options={picker}
            value={form.sources}
            onChange={(sources) => setForm({ ...form, sources })}
            disabled={busy || owner === ""}
            helperText={owner === "" ? "Pick a workspace with an owning directory." : "Members come only from these groups of the workspace's own directory, never from individuals."}
          />
          {discovered ? (
            <Typography variant="caption" color="text.secondary">
              The existing channel {discovered.channelId} is taken over as it is: the bot joins a public channel, and a private one needs the bot in it already. Its
              visibility is not changed.
            </Typography>
          ) : null}
          {wrong.length > 0 && (form.name !== "" || form.workspace !== "") ? (
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

function DeleteDialog({ record, onCancel, onDone }: { record: SlackChannelRecord; onCancel: () => void; onDone: (message: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const workspace = record.channel?.workspace ?? "";
  const name = record.channel?.name ?? "";

  const submit = async () => {
    setBusy(true);
    setFailure(undefined);
    try {
      const deleted = await slackChannels.deleteSlackChannel({ workspace, name });
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
          This deletes the record only. <strong>The channel stays in Slack</strong> and is not archived. The reconciler stops managing it: people who were added stay
          until someone removes them in Slack, and nobody is added or removed any more.
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
