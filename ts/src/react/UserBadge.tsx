import { Box, Button, Chip, Stack, Typography } from "@mui/material";

import type { Identity } from "../identity.js";

export interface UserBadgeProps {
  /** The caller, from useIdentity(). */
  identity: Identity;
  /** Roles shown in the accent colour; every other role is neutral. */
  emphasize?: string[];
  /** Where "Sign in" goes when nobody is signed in. */
  signInHref?: string;
}

/** The header block every console in this family shows: who you are, what
 * that gets you, and the way out.
 *
 * It renders all four states, including the one consoles usually skip.
 * "Unknown" means the application could not be asked — showing a sign-in
 * button there would send a signed-in person to authenticate again for
 * nothing, and showing nothing would leave them wondering. */
export function UserBadge({ identity, emphasize = ["operator"], signInHref = "/login" }: UserBadgeProps) {
  if (identity.status === "loading") return null;

  if (identity.status === "unknown") {
    return (
      <Typography variant="body2" color="text.secondary" title={identity.error}>
        Signed in, but this page could not confirm who with.
      </Typography>
    );
  }

  if (identity.status === "signed-out") {
    return (
      <Button href={signInHref} size="small" variant="outlined">
        Sign in
      </Button>
    );
  }

  const name = identity.name || identity.email || "signed in";
  return (
    <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }}>
      <Box sx={{ textAlign: "right", lineHeight: 1.15, minWidth: 0 }}>
        <Typography variant="body2" noWrap>
          {name}
        </Typography>
        {identity.name && identity.email && (
          <Typography variant="caption" color="text.secondary" noWrap>
            {identity.email}
          </Typography>
        )}
      </Box>
      {(identity.roles ?? []).map((role) => (
        <Chip
          key={role}
          label={role}
          size="small"
          variant="outlined"
          color={emphasize.includes(role) ? "success" : "default"}
        />
      ))}
      {identity.signOutUrl && (
        <Button href={identity.signOutUrl} size="small" variant="outlined" title="End this session">
          Sign out
        </Button>
      )}
    </Stack>
  );
}
