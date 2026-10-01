import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";

import { paths } from "./router";
import { useSlackIndex } from "./SlackChannelsTab";
import {
  byWorkspace,
  groupPeople,
  kindLabel,
  memberSentence,
  peopleSentence,
  placesOfPerson,
  reachOfDirectoryGroup,
  reachOfInternalGroup,
  rowPath,
  type Place,
  type Reach,
} from "./slackIndex";
import { memberKind } from "./slackModel";
import { Mono, Ref, Rows, Section, State } from "./ui";

/** The Slack channels a group feeds, per workspace, and what its people are
 *  doing in each. The reverse of a channel's "Fed by": drawn from the same
 *  reports and records, so it costs the Slack service nothing.
 *
 *  A directory group reaches channels two ways, directly (a console or
 *  Slack Connect channel names it) and through an internal group it feeds
 *  (a policy channel names that). An internal group reaches the policy
 *  channels that name it.
 *
 *  Nothing is drawn for a caller who may see no workspace, or when Slack is
 *  not set up at all: a section that says "none" about a system the
 *  deployment does not use is noise. */
export function SlackChannelsFed({ group, internal, feeds, emails }: { group: string; internal?: boolean; feeds?: string[]; emails: string[] }) {
  const index = useSlackIndex();
  const reach: Reach[] = internal ? reachOfInternalGroup(index.rows, group) : reachOfDirectoryGroup(index.rows, group, feeds ?? []);
  const configured = (index.status.value?.workspaces.length ?? 0) > 0;
  if (reach.length === 0 && !configured) return null;
  return (
    <Section title="Slack channels it feeds" hint="its people belong in these channels; each row says where they stand">
      {reach.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          None. Naming it as a source of a channel, on the Channels tab of Slack, is what puts its people in one.
        </Typography>
      ) : (
        byWorkspace(reach).map(({ workspace, items }) => (
          <Box key={workspace} sx={{ mb: 1.5 }}>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>
              <Ref to={paths.slack()} mono>
                {workspace}
              </Ref>
            </Typography>
            <Rows
              items={items}
              keyOf={({ row }) => `${row.kind}|${row.workspace}|${row.name}`}
              primary={({ row }) => (
                <Ref to={rowPath(row)} mono>
                  #{row.name}
                </Ref>
              )}
              secondary={({ row, via }) => {
                const { present, unreported } = groupPeople(row, emails);
                const said = peopleSentence(present);
                return `${kindLabel[row.kind]}${via ? ` · through ${via}` : ""}${said ? ` · ${said}` : ""}${unreported > 0 && present.length + unreported > 0 ? ` · ${unreported} not reported` : ""}`;
              }}
              right={({ row }) => <State kind={row.state.kind} label={row.state.label} title={row.state.title} />}
              empty=""
            />
          </Box>
        ))
      )}
    </Section>
  );
}

/** A person's Slack: every channel they have a row in, per workspace, with
 *  where they stand and why. A person with no Slack account yet reads as
 *  waiting for them, with that as the reason, so an operator is not asked to
 *  fix what only the person can. Nothing is drawn for a person in no
 *  channel, or for a caller the reports are hidden from. */
export function PersonSlack({ email }: { email: string }) {
  const index = useSlackIndex();
  const places = placesOfPerson(index.status.value, index.rows, email);
  if (places.length === 0) return null;
  return (
    <Box sx={{ mb: 3 }}>
      <Section title="Slack" hint="every channel they belong in, by workspace, and where they stand">
        {Object.entries(groupByWorkspace(places)).map(([workspace, here]) => (
          <Box key={workspace} sx={{ mb: 1.5 }}>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>
              <Ref to={paths.slack()} mono>
                {workspace}
              </Ref>
            </Typography>
            <Rows
              items={here}
              keyOf={(place) => `${place.workspace}|${place.channel.name}`}
              primary={(place) => (
                <Ref to={paths.slackChannel(place.workspace, place.channel.name)} mono>
                  #{place.channel.name}
                </Ref>
              )}
              secondary={(place) => (
                <>
                  {kindLabel[place.channel.kind]} · {memberSentence(place.member)}
                  {place.member.userId ? (
                    <>
                      {" · "}
                      <Mono>{place.member.userId}</Mono>
                    </>
                  ) : null}
                </>
              )}
              right={(place) => <State kind={memberKind(place.member)} />}
              empty=""
            />
          </Box>
        ))}
      </Section>
    </Box>
  );
}

function groupByWorkspace(places: Place[]): Record<string, Place[]> {
  const out: Record<string, Place[]> = {};
  for (const place of places) (out[place.workspace] ??= []).push(place);
  return out;
}
