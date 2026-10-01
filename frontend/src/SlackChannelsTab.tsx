import { useMemo, useState } from "react";
import Alert from "@mui/material/Alert";
import Button from "@mui/material/Button";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Typography from "@mui/material/Typography";

import { slack, slackChannels, slackConnect } from "./api";
import type { ListSlackChannelsResponse, SlackChannelRecord, SlackDiscoveredOrdinary } from "./gen/directoryroster/v1/slack_channels_pb";
import type { ListSlackSharedChannelsResponse, SlackDiscoveredChannel, SlackSharedChannel } from "./gen/directoryroster/v1/slack_connect_pb";
import type { GetSlackStatusResponse } from "./gen/directoryroster/v1/slack_pb";
import { useAsync, type Async } from "./hooks";
import { go, paths, replace } from "./router";
import { ChannelDeleteDialog, ChannelEditDialog, DiscoveredOrdinary } from "./SlackChannels";
import { ConnectDeleteDialog, ConnectEditDialog, DiscoveredConnect } from "./SlackConnect";
import { modeLabel, manageableWorkspaces } from "./slackChannelsModel";
import { hostChoices, privacyLabel, visibilityMismatchHint } from "./slackConnectModel";
import {
  connectFilterOf,
  connectStateLabel,
  connectStates,
  connectWorkspaces,
  discoveredFilterOf,
  discoveredItems,
  discoveredKinds,
  discoveredVisibilities,
  filterConnect,
  filterDiscovered,
  shownSentence,
} from "./slackFilters";
import { buildRows, filterRows, kindLabel, kindSentence, rowPath, visibilityMismatch, type ChannelKind, type ChannelRow } from "./slackIndex";
import { Facet, Facets, Failure, Loading, Mono, Names, Nothing, Page, Ref, SearchField, State } from "./ui";

/** Everything the channel tabs and a channel's page read, loaded once for
 *  the Slack page: the controller's report of every workspace (with the
 *  policy's own channels), the console's records of ordinary channels, and
 *  its records of Slack Connect channels. Joined in [buildRows]. */
export type SlackIndex = {
  status: Async<GetSlackStatusResponse>;
  ordinary: Async<ListSlackChannelsResponse>;
  shared: Async<ListSlackSharedChannelsResponse>;
  rows: ChannelRow[];
  loading: boolean;
  error?: string;
  reload: () => void;
};

export function useSlackIndex(): SlackIndex {
  const status = useAsync(() => slack.getSlackStatus({}), []);
  const ordinary = useAsync(() => slackChannels.listSlackChannels({}), []);
  const shared = useAsync(() => slackConnect.listSlackSharedChannels({}), []);
  const rows = useMemo(() => buildRows(status.value, ordinary.value, shared.value), [status.value, ordinary.value, shared.value]);
  return {
    status,
    ordinary,
    shared,
    rows,
    loading: status.loading || ordinary.loading || shared.loading,
    error: status.error ?? ordinary.error ?? shared.error,
    reload: () => {
      status.reload();
      ordinary.reload();
      shared.reload();
    },
  };
}

type Dialogue =
  | { kind: "edit" | "delete"; row: ChannelRow }
  | { kind: "create-console" }
  | { kind: "create-connect" }
  | { kind: "manage-console"; row: SlackDiscoveredOrdinary }
  | { kind: "manage-connect"; row: SlackDiscoveredChannel };

/** The dialogs of the channel tabs and the channel page, in one place so
 *  that a change made anywhere closes the same way: the dialogue closes, the
 *  banner says what happened, and the index reloads. */
export function ChannelDialogues({ dialogue, index, close, onDone }: { dialogue?: Dialogue; index: SlackIndex; close: () => void; onDone: (message: string) => void }) {
  if (!dialogue) return null;
  const done = (message: string) => {
    close();
    onDone(message);
    index.reload();
  };
  const ordinary = index.ordinary.value;
  const shared = index.shared.value;
  const inGit = index.rows.filter((row) => row.kind === "policy").map((row) => ({ workspace: row.workspace, name: row.name, id: row.id }));
  switch (dialogue.kind) {
    case "delete":
      return dialogue.row.kind === "console" ? (
        <ChannelDeleteDialog record={dialogue.row.record as SlackChannelRecord} onCancel={close} onDone={done} />
      ) : dialogue.row.kind === "connect" ? (
        <ConnectDeleteDialog channel={dialogue.row.record as SlackSharedChannel} onCancel={close} onDone={done} />
      ) : null;
    case "edit":
      return dialogue.row.kind === "console" && ordinary ? (
        <ChannelEditDialog key={dialogue.row.name} options={ordinary} editing={dialogue.row.record as SlackChannelRecord} inGit={inGit} onCancel={close} onDone={done} />
      ) : dialogue.row.kind === "connect" && shared ? (
        <ConnectEditDialog key={dialogue.row.name} options={shared} editing={dialogue.row.record as SlackSharedChannel} onCancel={close} onDone={done} />
      ) : null;
    case "create-console":
      return ordinary ? <ChannelEditDialog key="new-console" options={ordinary} inGit={inGit} onCancel={close} onDone={done} /> : null;
    case "create-connect":
      return shared ? <ConnectEditDialog key="new-connect" options={shared} onCancel={close} onDone={done} /> : null;
    case "manage-console":
      return ordinary ? <ChannelEditDialog key={dialogue.row.channelId} options={ordinary} discovered={dialogue.row} inGit={inGit} onCancel={close} onDone={done} /> : null;
    case "manage-connect":
      return shared ? <ConnectEditDialog key={dialogue.row.channelId} options={shared} discovered={dialogue.row} onCancel={close} onDone={done} /> : null;
  }
}

/** Edit and Delete for a channel the console keeps a record of, which is
 *  where an action on a channel belongs: on the channel. A policy channel
 *  has neither, and the caller who may not operate it sees neither. */
export function RowActions({ row, onEdit, onDelete }: { row: ChannelRow; onEdit: () => void; onDelete: () => void }) {
  if (!row.canOperate || !row.record) return null;
  return (
    <Stack direction="row" sx={{ gap: 1, justifyContent: "flex-end" }}>
      <Button size="small" onClick={onEdit}>
        Edit
      </Button>
      <Button size="small" color="error" onClick={onDelete}>
        Delete
      </Button>
    </Stack>
  );
}

/** Where the channel's people come from, as links. */
export function SourceNames({ row }: { row: ChannelRow }) {
  return (
    <Names
      items={row.sources.map((s) => ({ label: s.address, to: s.internal ? paths.group(s.address) : paths.directoryGroup(s.address), mono: true }))}
      empty="none"
      muted
    />
  );
}

function kindCaption(row: ChannelRow): string {
  return row.kind === "policy" ? "policy · defined in git" : kindLabel[row.kind];
}

/** Every managed channel across the workspaces, in one table, however it is
 *  managed. A policy channel is read-only here, with the internal groups
 *  that feed it; a console channel is edited where it is listed; a Slack
 *  Connect channel names its host and sides. Each name is the channel's
 *  own page. */
export function ChannelsTab({ index, query, onDone }: { index: SlackIndex; query: URLSearchParams; onDone: (message: string) => void }) {
  const workspace = query.get("workspace") ?? "";
  const kind = query.get("kind") ?? "";
  const [dialogue, setDialogue] = useState<Dialogue | undefined>();
  const rows = filterRows(index.rows, { workspace, kind });
  const keys = (index.status.value?.workspaces ?? []).map((w) => w.workspace);
  const canCreate = manageableWorkspaces(index.ordinary.value?.workspaces ?? []).length > 0 && index.ordinary.value?.available === true;
  const narrow = (next: { workspace?: string; kind?: string }) => go(paths.slackChannels({ workspace, kind, ...next }));

  const kinds: ChannelKind[] = ["policy", "console", "connect"];
  return (
    <Page
      title="Channels"
      lede={`${index.rows.length === 0 ? "No managed channel yet" : `${index.rows.length} managed ${index.rows.length === 1 ? "channel" : "channels"}`}, across every workspace: the policy's, the console's and the Slack Connect ones. Open one for who is in it and why.`}
      actions={
        canCreate ? (
          <Button variant="contained" onClick={() => setDialogue({ kind: "create-console" })}>
            New channel
          </Button>
        ) : undefined
      }
    >
      <Loading busy={index.loading} />
      <Failure error={index.error} />
      <Facets>
        <Facet value={workspace} onChange={(next) => narrow({ workspace: next })} options={keys.map((key) => ({ value: key, label: key }))} all={{ value: "", label: "Every workspace" }} mono />
        <Facet value={kind} onChange={(next) => narrow({ kind: next })} options={kinds.map((k) => ({ value: k as string, label: kindLabel[k] }))} all={{ value: "", label: "Every kind" }} />
      </Facets>
      {index.ordinary.value && !index.ordinary.value.available ? (
        <Alert severity="info" sx={{ mb: 2 }}>
          This deployment keeps no state in Kubernetes, so it keeps no console channel records.
        </Alert>
      ) : null}
      {!index.loading && rows.length === 0 ? (
        <Nothing>{index.rows.length === 0 ? "No channel is managed for a workspace you may see. The policy binds some in slack.workspaces, and New channel defines one here." : "No channel matches that filter."}</Nothing>
      ) : null}
      {rows.length > 0 ? (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small" sx={{ minWidth: 820 }}>
            <TableHead>
              <TableRow>
                <TableCell>Channel</TableCell>
                <TableCell>Workspace</TableCell>
                <TableCell>Fed by</TableCell>
                <TableCell>Mode</TableCell>
                <TableCell>State</TableCell>
                <TableCell align="right" />
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((row) => (
                <TableRow hover key={`${row.kind}|${row.workspace}|${row.name}`}>
                  <TableCell>
                    <Ref to={rowPath(row)} mono>
                      #{row.name}
                    </Ref>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block" }} title={kindSentence[row.kind]}>
                      {kindCaption(row)} · {row.kind === "connect" ? privacySummary(row) : row.private ? "private" : "public"}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Mono>{row.workspace}</Mono>
                    {row.kind === "connect" && row.sides.length > 1 ? (
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                        with {row.sides.slice(1).map((s) => s.workspace).join(", ")}
                      </Typography>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <SourceNames row={row} />
                  </TableCell>
                  <TableCell>{row.kind === "connect" ? "" : modeLabel(row.mode).split(":")[0]}</TableCell>
                  <TableCell>
                    <State kind={row.state.kind} label={row.state.label} title={row.state.title} />
                  </TableCell>
                  <TableCell align="right">
                    <RowActions row={row} onEdit={() => setDialogue({ kind: "edit", row })} onDelete={() => setDialogue({ kind: "delete", row })} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ) : null}
      <ChannelDialogues dialogue={dialogue} index={index} close={() => setDialogue(undefined)} onDone={onDone} />
    </Page>
  );
}

/** The visibility of a Slack Connect channel, whichever record says it. */
export function privacySummary(row: ChannelRow): string {
  const record = row.record as SlackSharedChannel | undefined;
  return record?.channel ? privacyLabel(record.channel) : row.private ? "private" : "public";
}

/** The Slack Connect channels the console keeps records of: host, sides,
 *  and where each side stands. Creating and editing are here and on the
 *  channel's page. */
export function ConnectTab({ index, query, onDone }: { index: SlackIndex; query: URLSearchParams; onDone: (message: string) => void }) {
  const [dialogue, setDialogue] = useState<Dialogue | undefined>();
  const all = index.rows.filter((row) => row.kind === "connect");
  const filter = connectFilterOf(query);
  const rows = filterConnect(all, filter);
  const { hosts, sides } = connectWorkspaces(all);
  const narrow = (next: Partial<typeof filter>) => go(paths.slackConnect({ ...filter, ...next }));
  const canCreate = hostChoices(index.shared.value?.workspaces ?? []).length > 0 && index.shared.value?.available === true;
  return (
    <Page
      title="Slack Connect"
      lede="Shared channels between this installation's own Slack workspaces: the host creates and owns each one and invites the others' bots, and every side manages its own people from the directory groups named here."
      actions={
        canCreate ? (
          <Button variant="contained" onClick={() => setDialogue({ kind: "create-connect" })}>
            New channel
          </Button>
        ) : undefined
      }
    >
      <Loading busy={index.loading} />
      <Failure error={index.error} />
      {all.length > 0 ? (
        <Facets>
          <Facet value={filter.host} onChange={(next) => narrow({ host: next })} options={hosts.map((key) => ({ value: key, label: key }))} all={{ value: "", label: "Every host" }} mono />
          <Facet value={filter.side} onChange={(next) => narrow({ side: next })} options={sides.map((key) => ({ value: key, label: key }))} all={{ value: "", label: "Any side" }} mono />
          <Facet
            value={filter.state}
            onChange={(next) => narrow({ state: next as typeof filter.state })}
            options={connectStates.map((st) => ({ value: st as string, label: connectStateLabel[st] }))}
            all={{ value: "", label: "Every state" }}
          />
          <SearchField label="Channel name" value={filter.q} onChange={(q) => replace(paths.slackConnect({ ...filter, q }))} />
          {rows.length !== all.length ? (
            <Typography variant="caption" color="text.secondary">
              {rows.length} of {all.length} shown
            </Typography>
          ) : null}
        </Facets>
      ) : null}
      {index.shared.value && !index.shared.value.available ? (
        <Alert severity="info" sx={{ mb: 2 }}>
          This deployment keeps no state in Kubernetes, so it keeps no shared channel records.
        </Alert>
      ) : null}
      {!index.loading && rows.length === 0 ? <Nothing>{all.length === 0 ? "No shared channel is defined for a workspace you may see." : "No shared channel matches that filter."}</Nothing> : null}
      {rows.length > 0 ? (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small" sx={{ minWidth: 760 }}>
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
              {rows.map((row) => (
                <TableRow hover key={`${row.workspace}|${row.name}`}>
                  <TableCell>
                    <Ref to={rowPath(row)} mono>
                      #{row.name}
                    </Ref>
                  </TableCell>
                  <TableCell>
                    <Mono>{row.workspace}</Mono>
                  </TableCell>
                  <TableCell>{row.sides.slice(1).map((s) => s.workspace).join(", ")}</TableCell>
                  <TableCell>
                    <SourceNames row={row} />
                  </TableCell>
                  <TableCell>{privacySummary(row)}</TableCell>
                  <TableCell>
                    <State kind={row.state.kind} label={row.state.label} title={row.state.title} />
                    {row.reason && (row.state.kind === "refused" || row.state.kind === "needs-you") ? (
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", maxWidth: 320 }}>
                        {row.reason}
                      </Typography>
                    ) : null}
                    {visibilityMismatch(row) ? (
                      <Typography variant="caption" color="warning.main" sx={{ display: "block", maxWidth: 320 }}>
                        Visibility mismatch. {row.canOperate ? "Edit: " : ""}
                        {visibilityMismatchHint}
                      </Typography>
                    ) : null}
                  </TableCell>
                  <TableCell align="right">
                    <RowActions row={row} onEdit={() => setDialogue({ kind: "edit", row })} onDelete={() => setDialogue({ kind: "delete", row })} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ) : null}
      <ChannelDialogues dialogue={dialogue} index={index} close={() => setDialogue(undefined)} onDone={onDone} />
    </Page>
  );
}

/** Every channel a bot can see that nothing manages, ordinary and shared,
 *  each with the Manage that takes it under management. */
export function DiscoveredTab({ index, query, onDone }: { index: SlackIndex; query: URLSearchParams; onDone: (message: string) => void }) {
  const [dialogue, setDialogue] = useState<Dialogue | undefined>();
  const ordinary = index.ordinary.value;
  const shared = index.shared.value;
  const unmanagedShared = (shared?.discovered ?? []).filter((row) => !row.managed);
  const items = discoveredItems(ordinary?.discovered ?? [], unmanagedShared);
  const filter = discoveredFilterOf(query);
  const kept = filterDiscovered(items, filter);
  const ordinaryRows = kept.flatMap((item) => (item.ordinary ? [item.ordinary] : []));
  const sharedRows = kept.flatMap((item) => (item.shared ? [item.shared] : []));
  const keys = (index.status.value?.workspaces ?? []).map((w) => w.workspace);
  const nothing = !index.loading && items.length === 0;
  const narrow = (next: Partial<typeof filter>) => go(paths.slackDiscovered({ ...filter, ...next }));
  return (
    <Page
      title="Discovered"
      lede={
        nothing
          ? "Nothing is visible that is not already managed."
          : `${shownSentence(kept.length, items.length)} visible to a workspace's bot and managed by nothing. Manage takes one over without removing anybody from it.`
      }
    >
      <Loading busy={index.loading} />
      <Failure error={index.error} />
      {items.length > 0 ? (
        <Facets>
          <Facet value={filter.workspace} onChange={(next) => narrow({ workspace: next })} options={keys.map((key) => ({ value: key, label: key }))} all={{ value: "", label: "Every workspace" }} mono />
          <Facet
            value={filter.kind}
            onChange={(next) => narrow({ kind: next as typeof filter.kind })}
            options={discoveredKinds.map((k) => ({ value: k as string, label: k === "shared" ? "Slack Connect" : "ordinary" }))}
            all={{ value: "", label: "Every kind" }}
          />
          <Facet
            value={filter.visibility}
            onChange={(next) => narrow({ visibility: next as typeof filter.visibility })}
            options={discoveredVisibilities.map((v) => ({ value: v as string, label: v }))}
            all={{ value: "", label: "Every visibility" }}
          />
          <Facet
            value={filter.sort}
            onChange={(next) => narrow({ sort: next as typeof filter.sort })}
            options={[{ value: "members", label: "Most members" }]}
            all={{ value: "", label: "By workspace, name" }}
          />
          <SearchField label="Channel name" value={filter.q} onChange={(q) => replace(paths.slackDiscovered({ ...filter, q }))} />
        </Facets>
      ) : null}
      {nothing ? <Nothing>Every channel the bots can see is already a policy, console or Slack Connect channel.</Nothing> : null}
      {!nothing && kept.length === 0 ? <Nothing>No channel matches that filter.</Nothing> : null}
      {ordinaryRows.length > 0 ? (
        <Typography variant="subtitle1" sx={{ mt: 2 }}>
          Ordinary channels
        </Typography>
      ) : null}
      <DiscoveredOrdinary rows={ordinaryRows} more={(ordinary?.workspaces ?? []).reduce((n, w) => n + w.discoveredMore, 0)} available={ordinary?.available === true} onManage={(row) => setDialogue({ kind: "manage-console", row })} />
      {sharedRows.length > 0 ? (
        <Typography variant="subtitle1" sx={{ mt: 2 }}>
          Slack Connect channels
        </Typography>
      ) : null}
      <DiscoveredConnect rows={sharedRows} available={shared?.available === true} onManage={(row) => setDialogue({ kind: "manage-connect", row })} />
      <ChannelDialogues dialogue={dialogue} index={index} close={() => setDialogue(undefined)} onDone={onDone} />
    </Page>
  );
}

export type { Dialogue };
