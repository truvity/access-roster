import { useState } from "react";
import Button from "@mui/material/Button";
import MenuItem from "@mui/material/MenuItem";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";

import { access, reason } from "./api";
import { useAsync } from "./hooks";

/** The one write this console has, offered from both ends of the join.
 *  On an internal group's page the group is fixed and a directory group
 *  is picked; on a directory group's page it is the other way round. The
 *  picker lists only what already exists, so there is nothing to
 *  mistype. */
export function Attach({
  group,
  directoryGroup,
  onCancel,
  onAdded,
  onFailure,
}: {
  group?: string;
  directoryGroup?: string;
  onCancel: () => void;
  onAdded: (group: string, directoryGroup: string) => void;
  onFailure: (message: string) => void;
}) {
  const [chosen, setChosen] = useState("");
  const pickDirectoryGroup = Boolean(group);
  const directoryGroups = useAsync(
    () => (pickDirectoryGroup ? access.listDirectoryGroups({}) : Promise.resolve(undefined)),
    [pickDirectoryGroup],
  );
  const policy = useAsync(() => (pickDirectoryGroup ? Promise.resolve(undefined) : access.getPolicy({})), [
    pickDirectoryGroup,
  ]);

  const options = pickDirectoryGroup
    ? (directoryGroups.value?.groups ?? []).map((g) => ({
        value: g.email,
        label: `${g.email} · ${g.members} members`,
        helper: `Adds ${g.members} people to ${group}.`,
      }))
    : (policy.value?.groups ?? [])
        .filter((g) => !g.members.some((m) => m.address === directoryGroup))
        .map((g) => ({
          value: g.name,
          label: g.name,
          helper: `Everyone in ${directoryGroup} lands in ${g.name}.`,
        }));
  const picked = options.find((option) => option.value === chosen);
  const loading = directoryGroups.loading || policy.loading;

  const submit = async () => {
    const target = { group: group ?? chosen, directoryGroup: directoryGroup ?? chosen };
    try {
      await access.addMembership(target);
      onAdded(target.group, target.directoryGroup);
    } catch (error) {
      onFailure(reason(error));
    }
  };

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 1 }}>
      <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start", flexWrap: "wrap", gap: 1 }}>
        <TextField
          select
          size="small"
          label={pickDirectoryGroup ? "Provider group" : "Internal group"}
          value={chosen}
          onChange={(e) => setChosen(e.target.value)}
          sx={{ minWidth: 360 }}
          helperText={
            picked
              ? picked.helper
              : options.length
                ? pickDirectoryGroup
                  ? "From the hub's own snapshots."
                  : "The internal groups the deployment declared."
                : loading
                  ? "Loading."
                  : pickDirectoryGroup
                    ? "No provider groups snapshotted yet: add a provider first."
                    : "Every declared internal group already has this provider group."
          }
        >
          {options.map((option) => (
            <MenuItem key={option.value} value={option.value}>
              {option.label}
            </MenuItem>
          ))}
        </TextField>
        <Button variant="contained" disabled={!chosen} onClick={() => void submit()} sx={{ mt: 0.25 }}>
          Attach
        </Button>
        <Button onClick={onCancel} sx={{ mt: 0.25 }}>
          Cancel
        </Button>
      </Stack>
    </Paper>
  );
}
