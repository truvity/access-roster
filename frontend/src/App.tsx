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
import { Groups, Group } from "./Groups";
import { Clients, Client } from "./Clients";
import { Person } from "./Person";
import { Explain } from "./Explain";
import { SettingsView } from "./Settings";

const tabs = [
  { value: "overview", label: "Overview", to: paths.overview() },
  { value: "directories", label: "Directories", to: paths.directories() },
  { value: "groups", label: "Groups", to: paths.groups() },
  { value: "clients", label: "Clients", to: paths.clients() },
  { value: "explain", label: "Explain", to: paths.explain() },
  { value: "settings", label: "Settings", to: paths.settings() },
];

export function App() {
  const route = useRoute();
  const me = useAsync<Me>(whoami, []);
  const [banner, setBanner] = useState<string | undefined>();

  const identity = me.value;
  const roles = identity?.roles ?? [];
  const operator = roles.includes("operator");
  const current = tabs.some((tab) => tab.value === route.view) ? route.view : "";

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
        <Tabs value={current || false} sx={{ px: 2 }}>
          {tabs.map((tab) => (
            <Tab key={tab.value} value={tab.value} label={tab.label} href={`#${tab.to}`} component="a" />
          ))}
        </Tabs>
      </AppBar>

      <Container maxWidth="lg" sx={{ py: 3 }}>
        {identity?.status === "signed-in" && roles.length === 0 ? (
          <Alert severity="warning" sx={{ mb: 2 }}>
            You are signed in as {identity.email}, and no group grants you access. An operator can attach a
            directory group to one on a group's page; on a fresh installation, sign in with the break-glass
            admin account first.
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
      return id ? <Directory id={id} operator={operator} onDone={onDone} /> : <Directories operator={operator} onDone={onDone} />;
    case "groups":
      return id ? <Group name={id} operator={operator} onDone={onDone} /> : <Groups />;
    case "clients":
      return id ? <Client id={id} /> : <Clients />;
    case "people":
      return <Person email={id ?? me?.email ?? ""} />;
    case "explain":
      return <Explain />;
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
