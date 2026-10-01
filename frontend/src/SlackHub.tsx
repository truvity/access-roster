import Box from "@mui/material/Box";
import Tab from "@mui/material/Tab";
import Tabs from "@mui/material/Tabs";

import { go, paths } from "./router";
import { slackTabOf, slackTabs } from "./slackTabsModel";
import { SlackAppsPage } from "./SlackApps";
import { SlackChannelPage } from "./SlackChannelPage";
import { ChannelsTab, ConnectTab, DiscoveredTab, useSlackIndex } from "./SlackChannelsTab";
import { SlackPage } from "./Slack";

/** Slack, as tabs. The channel tabs and a channel's page share one load
 *  (the reports, and the console's two kinds of record), so a channel's
 *  page opens without waiting and a change made on one reloads them all. */
export function SlackHub({
  section,
  rest,
  query,
  auditConnected,
  onDone,
}: {
  section?: string;
  rest: string[];
  query: URLSearchParams;
  auditConnected: boolean;
  onDone: (message: string) => void;
}) {
  const tab = slackTabOf(section);
  return (
    <Box>
      <Tabs
        value={tab}
        onChange={(_, next: string) => go(slackTabs.find((t) => t.value === next)?.to ?? paths.slack())}
        variant="scrollable"
        allowScrollButtonsMobile
        sx={{ mb: 3 }}
      >
        {slackTabs.map((t) => (
          <Tab key={t.value} value={t.value} label={t.label} />
        ))}
      </Tabs>
      {tab === "workspaces" ? <SlackPage onDone={onDone} /> : null}
      {tab === "apps" ? <SlackAppsPage onDone={onDone} /> : null}
      {tab === "channels" || tab === "connect" || tab === "discovered" ? (
        <IndexTabs tab={tab} rest={rest} query={query} auditConnected={auditConnected} onDone={onDone} />
      ) : null}
    </Box>
  );
}

function IndexTabs({ tab, rest, query, auditConnected, onDone }: { tab: "channels" | "connect" | "discovered"; rest: string[]; query: URLSearchParams; auditConnected: boolean; onDone: (message: string) => void }) {
  const index = useSlackIndex();
  if (tab === "connect") return <ConnectTab index={index} onDone={onDone} />;
  if (tab === "discovered") return <DiscoveredTab index={index} onDone={onDone} />;
  if (rest[0] && rest[1]) return <SlackChannelPage workspace={rest[0]} nameOrId={rest[1]} index={index} auditConnected={auditConnected} onDone={onDone} />;
  return <ChannelsTab index={index} query={query} onDone={onDone} />;
}
