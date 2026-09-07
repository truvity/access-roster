import { useState } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Container from "@mui/material/Container";
import Divider from "@mui/material/Divider";
import Drawer from "@mui/material/Drawer";
import IconButton from "@mui/material/IconButton";
import List from "@mui/material/List";
import ListItemButton from "@mui/material/ListItemButton";
import ListItemIcon from "@mui/material/ListItemIcon";
import ListItemText from "@mui/material/ListItemText";
import ListSubheader from "@mui/material/ListSubheader";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";
import useMediaQuery from "@mui/material/useMediaQuery";
import { useTheme } from "@mui/material/styles";
import AppsIcon from "@mui/icons-material/Apps";
import DashboardIcon from "@mui/icons-material/Dashboard";
import DomainIcon from "@mui/icons-material/Domain";
import GroupsIcon from "@mui/icons-material/Groups";
import MenuIcon from "@mui/icons-material/Menu";
import PeopleIcon from "@mui/icons-material/People";
import SettingsIcon from "@mui/icons-material/Settings";
import ShieldIcon from "@mui/icons-material/Shield";
import RuleIcon from "@mui/icons-material/Rule";

import { whoami, type Me } from "./api";
import { useAsync } from "./hooks";
import { paths, useRoute } from "./router";
import { Search } from "./Search";
import { Overview } from "./Overview";
import { Directories, Directory } from "./Directories";
import { DirectoryGroups, DirectoryGroup } from "./DirectoryGroups";
import { People } from "./People";
import { Person } from "./Person";
import { Matchers } from "./Matchers";
import { Groups, Group } from "./Groups";
import { Clients, Client } from "./Clients";
import { SettingsView } from "./Settings";

const drawerWidth = 236;

type Item = { value: string; label: string; to: string; icon: React.ReactNode };

/** The navigation is the model: two sides, one adjective each, joined by
 *  the membership. A rail with grouped destinations is what Material
 *  recommends for this many, and it keeps the header for the two things
 *  that belong there — search and who you are. */
const identity: Item[] = [
  { value: "directories", label: "Directories", to: paths.directories(), icon: <DomainIcon fontSize="small" /> },
  { value: "directory-groups", label: "Directory groups", to: paths.directoryGroups(), icon: <GroupsIcon fontSize="small" /> },
  { value: "people", label: "People", to: paths.people(), icon: <PeopleIcon fontSize="small" /> },
  { value: "matchers", label: "Matchers", to: paths.matchers(), icon: <RuleIcon fontSize="small" /> },
];
const accessSide: Item[] = [
  { value: "groups", label: "Internal groups", to: paths.groups(), icon: <ShieldIcon fontSize="small" /> },
  { value: "clients", label: "Clients", to: paths.clients(), icon: <AppsIcon fontSize="small" /> },
];

export function App() {
  const route = useRoute();
  const me = useAsync<Me>(whoami, []);
  const [banner, setBanner] = useState<string | undefined>();
  const [open, setOpen] = useState(false);
  const theme = useTheme();
  const wide = useMediaQuery(theme.breakpoints.up("md"));

  const identityInfo = me.value;
  const roles = identityInfo?.roles ?? [];
  const operator = roles.includes("operator");

  const nav = (
    <Box sx={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <Box sx={{ px: 2.5, pt: 2.25, pb: 1.5 }}>
        <Typography variant="subtitle1" sx={{ lineHeight: 1.2 }}>
          directory-roster
        </Typography>
        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
          {identityInfo?.version ?? ""}
        </Typography>
      </Box>
      <List dense disablePadding sx={{ pb: 1 }}>
        <NavItem item={{ value: "overview", label: "Overview", to: paths.overview(), icon: <DashboardIcon fontSize="small" /> }} current={route.view} onPick={() => setOpen(false)} />
        <ListSubheader disableSticky sx={{ mt: 1.5 }} title="Where people come from">
          Identity
        </ListSubheader>
        {identity.map((item) => (
          <NavItem key={item.value} item={item} current={route.view} onPick={() => setOpen(false)} />
        ))}
        <ListSubheader disableSticky sx={{ mt: 1.5 }} title="What they get">
          Access
        </ListSubheader>
        {accessSide.map((item) => (
          <NavItem key={item.value} item={item} current={route.view} onPick={() => setOpen(false)} />
        ))}
      </List>
      <Box sx={{ flexGrow: 1 }} />
      <Divider />
      <List dense disablePadding sx={{ py: 1 }}>
        <NavItem item={{ value: "settings", label: "Settings", to: paths.settings(), icon: <SettingsIcon fontSize="small" /> }} current={route.view} onPick={() => setOpen(false)} />
      </List>
    </Box>
  );

  return (
    <Box sx={{ display: "flex", minHeight: "100vh", bgcolor: "background.default" }}>
      <Drawer
        variant={wide ? "permanent" : "temporary"}
        open={wide ? true : open}
        onClose={() => setOpen(false)}
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          [`& .MuiDrawer-paper`]: { width: drawerWidth, boxSizing: "border-box", borderRight: 1, borderColor: "divider", bgcolor: "background.paper" },
        }}
      >
        {nav}
      </Drawer>

      <Box component="main" sx={{ flexGrow: 1, minWidth: 0 }}>
        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            gap: 2,
            px: { xs: 2, md: 4 },
            height: 56,
            borderBottom: 1,
            borderColor: "divider",
            bgcolor: "background.paper",
            position: "sticky",
            top: 0,
            zIndex: (t) => t.zIndex.appBar,
          }}
        >
          {!wide ? (
            <IconButton edge="start" onClick={() => setOpen(true)} aria-label="open navigation">
              <MenuIcon />
            </IconButton>
          ) : null}
          <Search />
          <Box sx={{ flexGrow: 1 }} />
          {identityInfo?.status === "signed-in" ? (
            <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }}>
              <Box sx={{ textAlign: "right", lineHeight: 1.15 }}>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  {identityInfo.name || identityInfo.email}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {roles.length ? roles[0] : "no access"}
                  {identityInfo.name && identityInfo.name !== identityInfo.email ? ` · ${identityInfo.email}` : ""}
                </Typography>
              </Box>
              <Button size="small" href={identityInfo.signOutUrl ?? "/logout"} onClick={signOut}>
                Sign out
              </Button>
            </Stack>
          ) : (
            <Button size="small" variant="contained" href="/login">
              Sign in
            </Button>
          )}
        </Box>

        <Container maxWidth="lg" sx={{ py: 3.5, px: { xs: 2, md: 4 } }}>
          {identityInfo?.status === "signed-in" && roles.length === 0 ? (
            <Alert severity="warning" sx={{ mb: 2 }}>
              You are signed in as {identityInfo.email}, and no internal group grants you access. An operator
              can attach a directory group to one on either group's page; on a fresh installation, sign in with
              the break-glass admin account first.
            </Alert>
          ) : null}
          {banner ? (
            <Alert severity="success" sx={{ mb: 2 }} onClose={() => setBanner(undefined)}>
              {banner}
            </Alert>
          ) : null}

          <PageFor view={route.view} id={route.id} operator={operator} onDone={setBanner} me={identityInfo} />
        </Container>
      </Box>
    </Box>
  );
}

function NavItem({ item, current, onPick }: { item: Item; current: string; onPick: () => void }) {
  const selected = item.value === current;
  return (
    <ListItemButton component="a" href={`#${item.to}`} selected={selected} onClick={onPick} sx={{ "&.Mui-selected": { bgcolor: "action.selected" } }}>
      <ListItemIcon sx={{ color: selected ? "primary.main" : "text.secondary" }}>{item.icon}</ListItemIcon>
      <ListItemText primary={item.label} slotProps={{ primary: { variant: "body2", sx: { fontWeight: selected ? 600 : 500 } } }} />
    </ListItemButton>
  );
}

function PageFor({
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
    case "directory-groups":
      return id ? <DirectoryGroup email={id} operator={operator} onDone={onDone} /> : <DirectoryGroups />;
    case "people":
      return id ? <Person email={id} /> : <People />;
    case "matchers":
      return <Matchers />;
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

