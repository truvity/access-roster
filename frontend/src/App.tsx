import { useState } from "react";
import Alert from "@mui/material/Alert";
import AppBar from "@mui/material/AppBar";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Chip from "@mui/material/Chip";
import Container from "@mui/material/Container";
import Stack from "@mui/material/Stack";
import Tab from "@mui/material/Tab";
import Tabs from "@mui/material/Tabs";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";

import { whoami, type Me } from "./api";
import { useAsync } from "./hooks";
import { paths, useRoute } from "./router";
import { Search } from "./Search";
import { Overview } from "./Overview";
import { Directories, Directory } from "./Directories";
import { DirectoryGroups, DirectoryGroup } from "./DirectoryGroups";
import { People } from "./People";
import { Person } from "./Person";
import { Machines } from "./Machines";
import { Groups, Group } from "./Groups";
import { Clients, Client } from "./Clients";
import { SettingsView } from "./Settings";

type Tab = { value: string; label: string; to: string };

/** The navigation is the model: two sides, one adjective each, joined by
 *  the membership. Clustering the tabs is what makes the symmetry
 *  visible, and naming both sides in full is what keeps "group" from
 *  meaning two things. */
const clusters: { label?: string; tabs: Tab[] }[] = [
  { tabs: [{ value: "overview", label: "Overview", to: paths.overview() }] },
  {
    label: "Identity — where people come from",
    tabs: [
      { value: "directories", label: "Directories", to: paths.directories() },
      { value: "directory-groups", label: "Directory groups", to: paths.directoryGroups() },
      { value: "people", label: "People", to: paths.people() },
      { value: "machines", label: "Machines", to: paths.machines() },
    ],
  },
  {
    label: "Access — what they get",
    tabs: [
      { value: "groups", label: "Internal groups", to: paths.groups() },
      { value: "clients", label: "Clients", to: paths.clients() },
    ],
  },
  { tabs: [{ value: "settings", label: "Settings", to: paths.settings() }] },
];

export function App() {
  const route = useRoute();
  const me = useAsync<Me>(whoami, []);
  const [banner, setBanner] = useState<string | undefined>();

  const identity = me.value;
  const roles = identity?.roles ?? [];
  const operator = roles.includes("operator");

  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "background.default" }}>
      <AppBar position="static" color="default" elevation={0} sx={{ borderBottom: 1, borderColor: "divider" }}>
        <Toolbar sx={{ gap: 2 }}>
          <Stack direction="row" spacing={1} sx={{ alignItems: "baseline" }}>
            <Typography variant="h6" sx={{ whiteSpace: "nowrap" }}>
              directory-roster
            </Typography>
            {identity?.version ? (
              <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
                {identity.version}
              </Typography>
            ) : null}
          </Stack>
          <Search />
          <Box sx={{ flexGrow: 1 }} />
          <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
            {identity?.status === "signed-in" ? (
              <>
                <Box sx={{ textAlign: "right", lineHeight: 1.2 }}>
                  <Typography variant="body2">{identity.name || identity.email}</Typography>
                  {identity.name && identity.name !== identity.email ? (
                    <Typography variant="caption" color="text.secondary">
                      {identity.email}
                    </Typography>
                  ) : null}
                </Box>
                {roles.length ? (
                  <Chip size="small" label={roles[0]} color={operator ? "primary" : "default"} />
                ) : (
                  <Chip size="small" label="no access" color="warning" variant="outlined" />
                )}
                <Button size="small" href={identity.signOutUrl ?? "/logout"} onClick={signOut}>
                  Sign out
                </Button>
              </>
            ) : (
              <Button size="small" variant="contained" href="/login">
                Sign in
              </Button>
            )}
          </Stack>
        </Toolbar>

        <Stack direction="row" sx={{ px: 2, alignItems: "flex-end", flexWrap: "wrap", columnGap: 3 }}>
          {clusters.map((cluster, index) => {
            const current = cluster.tabs.some((tab) => tab.value === route.view) ? route.view : false;
            return (
              <Box key={index} sx={{ pt: cluster.label ? 0 : 2.25 }}>
                {cluster.label ? (
                  <Typography
                    variant="overline"
                    color="text.secondary"
                    sx={{ display: "block", lineHeight: 1.6, px: 2, fontSize: 10 }}
                  >
                    {cluster.label}
                  </Typography>
                ) : null}
                <Tabs value={current} sx={{ minHeight: 40 }}>
                  {cluster.tabs.map((tab) => (
                    <Tab
                      key={tab.value}
                      value={tab.value}
                      label={tab.label}
                      href={`#${tab.to}`}
                      component="a"
                      sx={{ minHeight: 40, py: 0.5 }}
                    />
                  ))}
                </Tabs>
              </Box>
            );
          })}
        </Stack>
      </AppBar>

      <Container maxWidth="lg" sx={{ py: 3 }}>
        {identity?.status === "signed-in" && roles.length === 0 ? (
          <Alert severity="warning" sx={{ mb: 2 }}>
            You are signed in as {identity.email}, and no internal group grants you access. An operator can
            attach a directory group to one on either group's page; on a fresh installation, sign in with
            the break-glass admin account first.
          </Alert>
        ) : null}
        {banner ? (
          <Alert severity="success" sx={{ mb: 2 }} onClose={() => setBanner(undefined)}>
            {banner}
          </Alert>
        ) : null}

        <Page view={route.view} id={route.id} operator={operator} onDone={setBanner} me={identity} />
      </Container>
    </Box>
  );
}

function Page({
  view,
  id,
  operator,
  onDone,
  me,
}: {
  view: string;
  id?: string;
  operator: boolean;
  onDone: (message: string) => void;
  me?: Me;
}) {
  switch (view) {
    case "directories":
      return id ? (
        <Directory id={id} operator={operator} onDone={onDone} />
      ) : (
        <Directories operator={operator} onDone={onDone} />
      );
    case "directory-groups":
      return id ? <DirectoryGroup email={id} operator={operator} onDone={onDone} /> : <DirectoryGroups />;
    case "people":
      return id ? <Person email={id} /> : <People />;
    case "machines":
      return <Machines />;
    case "groups":
      return id ? <Group name={id} operator={operator} onDone={onDone} /> : <Groups />;
    case "clients":
      return id ? <Client id={id} /> : <Clients />;
    case "settings":
      return <SettingsView operator={operator} onDone={onDone} />;
    default:
      return <Overview me={me} />;
  }
}

/** Sign-out is a POST: a link that logs you out would be a link anyone
 *  could put in a page. */
function signOut(event: React.MouseEvent<HTMLAnchorElement>) {
  event.preventDefault();
  const url = event.currentTarget.getAttribute("href") ?? "/logout";
  void fetch(url, { method: "POST" }).then(() => {
    window.location.href = "/login";
  });
}
