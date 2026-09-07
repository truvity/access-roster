import { useEffect, useMemo, useState } from "react";
import Box from "@mui/material/Box";
import Chip from "@mui/material/Chip";
import InputBase from "@mui/material/InputBase";
import ListItemButton from "@mui/material/ListItemButton";
import Paper from "@mui/material/Paper";
import Popper from "@mui/material/Popper";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";

import { access, personName, workspaces } from "./api";
import { useAsync } from "./hooks";
import { go, paths } from "./router";

type Hit = { kind: string; label: string; detail?: string; to: string };

/** Almost every task starts with a name: a person, a group on either
 *  side, a client, a directory. One field that resolves any of them removes the first click
 *  from nearly every journey, which is why it sits on every page rather
 *  than on one. */
export function Search() {
  const [query, setQuery] = useState("");
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);

  // The small, stable lists are loaded once and matched here; only people
  // need the server, because nothing else can enumerate a directory.
  const policy = useAsync(() => access.getPolicy({}), []);
  const directoryGroups = useAsync(() => access.listDirectoryGroups({}), []);
  const tenants = useAsync(() => workspaces.listWorkspaces({}), []);
  const [people, setPeople] = useState<Hit[]>([]);

  useEffect(() => {
    const term = query.trim();
    if (term.length < 2) {
      setPeople([]);
      return;
    }
    let live = true;
    const timer = setTimeout(() => {
      access
        .searchPeople({ query: term, limit: 6 })
        .then((found) => {
          if (!live) return;
          setPeople(
            found.people.map((person) => ({
              kind: "person",
              label: personName(person.givenName, person.familyName, person.email),
              detail: person.email + (person.live ? "" : " · suspended"),
              to: paths.person(person.email),
            })),
          );
        })
        .catch(() => setPeople([]));
    }, 150);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [query]);

  const hits = useMemo<Hit[]>(() => {
    const term = query.trim().toLowerCase();
    if (term.length < 2) return [];
    const matches = (value: string) => value.toLowerCase().includes(term);
    const out: Hit[] = [...people];

    for (const group of policy.value?.groups ?? []) {
      if (matches(group.name)) {
        out.push({
          kind: "internal group",
          label: group.name,
          detail: `fed by ${group.members.length} directory groups`,
          to: paths.group(group.name),
        });
      }
    }
    for (const client of policy.value?.clients ?? []) {
      if (matches(client.id)) {
        out.push({ kind: "client", label: client.id, detail: client.kind, to: paths.client(client.id) });
      }
    }
    for (const group of directoryGroups.value?.groups ?? []) {
      if (matches(group.email)) {
        out.push({
          kind: "directory group",
          label: group.email,
          detail: `${group.members} members · from ${group.workspaceId}`,
          to: paths.directoryGroup(group.email),
        });
      }
    }
    for (const tenant of tenants.value?.workspaces ?? []) {
      const domains = tenant.domains.map((d) => d.name).join(", ");
      if (matches(tenant.id) || matches(domains)) {
        out.push({ kind: "directory", label: tenant.id, detail: domains, to: paths.directory(tenant.id) });
      }
    }
    // An address nobody knows is still worth looking up: the answer "no
    // workspace serves that domain" is the answer.
    if (term.includes("@") && !out.some((hit) => hit.label.toLowerCase() === term)) {
      out.push({ kind: "person", label: query.trim(), detail: "look it up", to: paths.person(query.trim()) });
    }
    return out.slice(0, 12);
  }, [query, people, policy.value, directoryGroups.value, tenants.value]);

  const open = Boolean(anchor) && hits.length > 0;

  const choose = (to: string) => {
    setQuery("");
    setAnchor(null);
    go(to);
  };

  return (
    <Box sx={{ position: "relative", minWidth: { xs: 200, sm: 380 } }}>
      <Paper
        variant="outlined"
        sx={{ px: 1.5, py: 0.5, display: "flex", alignItems: "center", gap: 1 }}
        ref={setAnchor}
      >
        <InputBase
          fullWidth
          placeholder="Search a person, group or client"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && hits.length) choose(hits[0].to);
            if (e.key === "Escape") setQuery("");
          }}
          sx={{ fontSize: 14 }}
        />
      </Paper>

      <Popper open={open} anchorEl={anchor} placement="bottom-start" style={{ zIndex: 1300 }}>
        <Paper variant="outlined" sx={{ mt: 0.5, width: anchor?.clientWidth, maxHeight: 420, overflowY: "auto" }}>
          {hits.map((hit) => (
            <ListItemButton key={hit.kind + hit.label} onClick={() => choose(hit.to)} dense>
              <Stack direction="row" spacing={1} sx={{ alignItems: "center", width: "100%" }}>
                <Box sx={{ minWidth: 0, flexGrow: 1 }}>
                  <Typography variant="body2" noWrap>
                    {hit.label}
                  </Typography>
                  {hit.detail ? (
                    <Typography variant="caption" color="text.secondary" noWrap sx={{ display: "block" }}>
                      {hit.detail}
                    </Typography>
                  ) : null}
                </Box>
                <Chip size="small" variant="outlined" label={hit.kind} />
              </Stack>
            </ListItemButton>
          ))}
        </Paper>
      </Popper>
    </Box>
  );
}
