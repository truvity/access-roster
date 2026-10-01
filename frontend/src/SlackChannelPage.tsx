import { useState } from "react";
import { AuditProvider, AuditView } from "@truvity/audit/react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Collapse from "@mui/material/Collapse";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Typography from "@mui/material/Typography";

import { audit, reason, slack } from "./api";
import { roster } from "./auditSentences";
import type { SlackBreaker, SlackChannelStatus } from "./gen/directoryroster/v1/slack_pb";
import { paths } from "./router";
import { BreakerAlert } from "./Slack";
import { modeLabel } from "./slackChannelsModel";
import { findRow, kindLabel, kindSentence, peopleSentence, summaryLine, type ChannelRow, type Side } from "./slackIndex";
import { breakerSentence, channelKind, memberKind, noAccountReason, split } from "./slackModel";
import { ChannelDialogues, privacySummary, RowActions, type Dialogue, type SlackIndex } from "./SlackChannelsTab";
import { Failure, Loading, Mono, Nothing, Page, Ref, Rows, Section, State } from "./ui";

/** The audit trail's own qualifier for everything that happened to a
 *  channel: the controller's creates, adoptions, invitations and removals,
 *  and every change made on the console. */
export function auditNarrowing(row: Pick<ChannelRow, "workspace" | "name">): string {
  return `target:slack_channel:${row.workspace}/${row.name}`;
}

/** One channel, whichever way it is managed: what it is in a sentence, who
 *  feeds it, the state of every person in it and why, and everything that
 *  happened to it. The edges come first and the raw trail sits behind a
 *  disclosure. Actions on the channel — edit, forget — are here.
 *
 *  `nameOrId` is the name in the workspace or the Slack id, so a link from
 *  somewhere that knows only the id still lands. */
export function SlackChannelPage({
  workspace,
  nameOrId,
  index,
  auditConnected,
  onDone,
}: {
  workspace: string;
  nameOrId: string;
  index: SlackIndex;
  auditConnected: boolean;
  onDone: (message: string) => void;
}) {
  const [dialogue, setDialogue] = useState<Dialogue | undefined>();
  const row = findRow(index.rows, workspace, nameOrId);

  if (!row) {
    return (
      <Box>
        <Loading busy={index.loading} />
        <Failure error={index.error} />
        {!index.loading ? (
          <Nothing>
            No managed channel {nameOrId} in {workspace}. Every managed channel is on the <Ref to={paths.slackChannels()}>Channels</Ref> tab; one nothing manages is on{" "}
            <Ref to={paths.slackDiscovered()}>Discovered</Ref>.
          </Nothing>
        ) : null}
      </Box>
    );
  }

  const definedBy =
    row.kind === "console" && row.record && "createdBy" in row.record && row.record.createdBy ? `defined by ${row.record.createdBy}` : "";
  return (
    <Page
      title={`#${row.name}`}
      mono
      lede={summaryLine(row)}
      facts={[
        {
          label: "Kind",
          value: (
            <span title={kindSentence[row.kind]}>
              {kindLabel[row.kind]}
              {row.kind === "policy" ? " · defined in git" : ""}
            </span>
          ),
        },
        { label: row.kind === "connect" ? "Host" : "Workspace", value: <Ref to={paths.slack()} mono>{row.workspace}</Ref> },
        { label: "Visibility", value: row.kind === "connect" ? privacySummary(row) : row.private ? "private" : "public" },
        { label: "Mode", value: row.kind === "connect" ? "" : modeLabel(row.mode) },
        { label: "Slack id", value: row.id ? <Mono>{row.id}</Mono> : "" },
        { label: "State", value: <State kind={row.state.kind} label={row.state.label} title={row.state.title} /> },
        { label: "Record", value: definedBy },
      ]}
      actions={<RowActions row={row} onEdit={() => setDialogue({ kind: "edit", row })} onDelete={() => setDialogue({ kind: "delete", row })} />}
    >
      <Loading busy={index.loading} />
      <Failure error={index.error} />
      {row.reason && (row.state.kind === "refused" || row.state.kind === "needs-you") ? (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {row.reason}
        </Typography>
      ) : null}

      <Section
        title="Fed by"
        hint={
          row.kind === "policy"
            ? "internal groups, named in the policy: change them there, in git"
            : "directory groups, whose members belong whichever side they are on"
        }
      >
        <Rows
          items={row.sources}
          keyOf={(s) => s.address}
          primary={(s) => (
            <Ref to={s.internal ? paths.group(s.address) : paths.directoryGroup(s.address)} mono>
              {s.address}
            </Ref>
          )}
          secondary={(s) => (s.internal ? "internal group" : "directory group")}
          empty="Nothing feeds it: a channel is fed by at least one group, so this record is refused or not reported."
        />
      </Section>

      {row.kind === "connect" ? (
        <Section title="Sides" hint="every workspace the channel reaches, and where each stands">
          <Rows
            items={row.sides}
            keyOf={(side) => side.workspace}
            primary={(side) => (
              <>
                <Ref to={paths.slack()} mono>
                  {side.workspace}
                </Ref>{" "}
                {side.workspace === row.workspace ? <Typography component="span" variant="caption" color="text.secondary">host</Typography> : null}
              </>
            )}
            secondary={(side) => `#${side.name} · ${sideVisibility(row, side)}${side.status ? "" : " · not reported yet"}`}
            right={(side) => (side.status ? <State kind={channelKind(side.status)} title={side.status.reason} /> : <State kind="unreported" />)}
            empty="No side is named."
          />
        </Section>
      ) : null}

      <Section title="People" hint={peopleSentence(row.sides.flatMap((s) => s.status?.members ?? [])) || "who is in it, once the controller has reported"}>
        <Stack sx={{ gap: 2 }}>
          {row.sides.map((side) => (
            <SidePeople key={side.workspace} side={side} showHeading={row.sides.length > 1} onDone={onDone} reload={index.reload} />
          ))}
        </Stack>
      </Section>

      <History row={row} connected={auditConnected} />
      <ChannelDialogues dialogue={dialogue} index={index} close={() => setDialogue(undefined)} onDone={onDone} />
    </Page>
  );
}

function sideVisibility(row: ChannelRow, side: Side): string {
  const per = row.privatePerSide[side.workspace];
  return (per ?? row.private) ? "private" : "public";
}

/** One side's people: what needs reading first, the rest behind a count. */
function SidePeople({ side, showHeading, onDone, reload }: { side: Side; showHeading: boolean; onDone: (message: string) => void; reload: () => void }) {
  const channel = side.status;
  const [showSettled, setShowSettled] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  if (!channel) {
    return (
      <Box>
        {showHeading ? <SideHeading side={side} /> : null}
        <Nothing>No people reported yet: the controller has not reported this channel{showHeading ? ` in ${side.workspace}` : ""}.</Nothing>
      </Box>
    );
  }
  const { settled, open } = split(channel.members);
  const shown = showSettled ? [...open, ...settled] : open;
  const confirm = async (breaker: SlackBreaker) => {
    setConfirming(true);
    setFailure(undefined);
    try {
      await slack.confirmSlackRemovals({ workspace: side.workspace, channel: channel.name, fingerprint: breaker.fingerprint });
      onDone(`Confirmed: the ${breaker.affected} removals in ${side.workspace}/${channel.name} go ahead on the next pass.`);
      reload();
    } catch (error) {
      setFailure(reason(error));
    } finally {
      setConfirming(false);
    }
  };
  return (
    <Box>
      {showHeading ? <SideHeading side={side} /> : null}
      <Failure error={failure} />
      {channel.breaker && !channel.breaker.confirmed ? (
        <Box sx={{ mb: 1 }}>
          <BreakerAlert
            sentence={breakerSentence(`#${channel.name}`, channel.breaker.affected, channel.breaker.total)}
            breaker={channel.breaker}
            confirmation={channel.removalConfirmation}
            canOperate={side.canOperate}
            busy={confirming}
            onConfirm={() => void confirm(channel.breaker!)}
          />
        </Box>
      ) : null}
      <Members channel={channel} rows={shown} />
      {settled.length > 0 ? (
        <Button size="small" variant="text" onClick={() => setShowSettled((v) => !v)} sx={{ textTransform: "none", p: 0, minWidth: 0, mt: 0.5 }}>
          {showSettled ? "Hide" : "Show"} {settled.length} in step
        </Button>
      ) : open.length === 0 && channel.members.length === 0 ? (
        <Typography variant="caption" color="text.secondary">
          No people reported yet.
        </Typography>
      ) : null}
    </Box>
  );
}

function SideHeading({ side }: { side: Side }) {
  return (
    <Typography variant="subtitle2" sx={{ mb: 0.5 }}>
      <Mono>#{side.name}</Mono> in{" "}
      <Ref to={paths.slack()} mono>
        {side.workspace}
      </Ref>
    </Typography>
  );
}

function Members({ channel, rows }: { channel: SlackChannelStatus; rows: SlackChannelStatus["members"] }) {
  if (rows.length === 0) return null;
  return (
    <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
      <Table size="small" sx={{ minWidth: 520 }}>
        <TableHead>
          <TableRow>
            <TableCell>Person</TableCell>
            <TableCell>State</TableCell>
            <TableCell>Why</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map((member) => (
            <TableRow key={`${channel.name}|${member.person}|${member.email}|${member.userId}`} hover>
              <TableCell>
                {member.person ? (
                  <Ref to={paths.person(member.email || member.person)} mono>
                    {member.email || member.person}
                  </Ref>
                ) : (
                  <Mono>{member.email || member.userId}</Mono>
                )}
              </TableCell>
              <TableCell>
                <State kind={memberKind(member)} title={member.reason === noAccountReason ? "Only the person can move this forward: they need a Slack account under this address." : undefined} />
              </TableCell>
              <TableCell>
                <Typography variant="body2" color="text.secondary">
                  {member.reason}
                </Typography>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

/** Everything that happened to the channel, as the audit trail keeps it:
 *  the existing audit view, narrowed to the channel's target. Behind a
 *  disclosure, because it is the raw record and the page above is what it
 *  adds up to. */
function History({ row, connected }: { row: ChannelRow; connected: boolean }) {
  const [open, setOpen] = useState(false);
  const narrowing = auditNarrowing(row);
  return (
    <Section
      title="History"
      hint="every create, invitation, removal and change, from the audit trail"
      action={
        connected ? (
          <Stack direction="row" sx={{ gap: 1 }}>
            <Button size="small" href={`#${paths.audit(narrowing)}`}>
              Open in Audit
            </Button>
            <Button size="small" onClick={() => setOpen(!open)}>
              {open ? "Hide" : "Show"}
            </Button>
          </Stack>
        ) : undefined
      }
    >
      {!connected ? (
        <Nothing>No audit installation is connected to this console, so nothing is kept beyond the service&apos;s log.</Nothing>
      ) : (
        <Collapse in={open} unmountOnExit>
          <AuditProvider client={audit} sentences={[roster]}>
            <AuditView query={narrowing} permalink={(profile, id) => `#${paths.audit(`id:${id}`, profile)}`} />
          </AuditProvider>
        </Collapse>
      )}
    </Section>
  );
}
