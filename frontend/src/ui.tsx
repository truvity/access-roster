import type { ReactNode } from "react";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Chip from "@mui/material/Chip";
import LinearProgress from "@mui/material/LinearProgress";
import Link from "@mui/material/Link";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";

/** Whether a domain's answers may be acted on — the flag the whole design
 *  turns on, so it gets a shape of its own rather than a word in a cell. */
export function Authority({ authoritative, conflict }: { authoritative: boolean; conflict?: boolean }) {
  if (conflict) {
    return (
      <Tooltip title="Another workspace claims this domain too. It is authoritative for neither until one of them drops it.">
        <Chip size="small" color="warning" variant="filled" label="conflict" />
      </Tooltip>
    );
  }
  if (authoritative) {
    return (
      <Tooltip title="The last probe succeeded, the snapshot is fresh and no one else claims this domain. Consumers may act on removals.">
        <Chip size="small" color="success" variant="outlined" label="authoritative" />
      </Tooltip>
    );
  }
  return (
    <Tooltip title="Answers about this domain are a hold, not a fact: consumers add but never remove.">
      <Chip size="small" color="warning" variant="outlined" label="hold" />
    </Tooltip>
  );
}

export function Loading({ busy }: { busy: boolean }) {
  return <Box sx={{ height: 4 }}>{busy ? <LinearProgress /> : null}</Box>;
}

export function Failure({ error }: { error?: string }) {
  if (!error) return null;
  return (
    <Alert severity="error" sx={{ my: 2 }}>
      {error}
    </Alert>
  );
}

/** Every name in the console is a link to the page about that thing: it
 *  is what makes the chain from a directory group to an audience
 *  walkable in both directions. */
export function Ref({ to, children, mono }: { to: string; children: ReactNode; mono?: boolean }) {
  return (
    <Link
      href={`#${to}`}
      underline="hover"
      sx={{ fontFamily: mono ? "monospace" : undefined, cursor: "pointer" }}
    >
      {children}
    </Link>
  );
}

/** The one line at the top of every detail page: what this is, in plain
 *  language, before any table. */
export function Summary({
  title,
  subtitle,
  chips,
  right,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  chips?: ReactNode;
  right?: ReactNode;
}) {
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
      <Stack direction="row" spacing={2} sx={{ alignItems: "center", flexWrap: "wrap", gap: 1 }}>
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="h6" sx={{ lineHeight: 1.2 }}>
            {title}
          </Typography>
          {subtitle ? (
            <Typography variant="body2" color="text.secondary">
              {subtitle}
            </Typography>
          ) : null}
        </Box>
        {chips ? (
          <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", gap: 0.5 }}>
            {chips}
          </Stack>
        ) : null}
        <Box sx={{ flexGrow: 1 }} />
        {right}
      </Stack>
    </Paper>
  );
}

/** A titled block. Detail pages are a stack of these: edges first, raw
 *  detail last. */
export function Section({
  title,
  hint,
  action,
  children,
}: {
  title: string;
  hint?: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <Box sx={{ mb: 3 }}>
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", mb: 0.5 }}>
        <Box>
          <Typography variant="subtitle2">{title}</Typography>
          {hint ? (
            <Typography variant="caption" color="text.secondary">
              {hint}
            </Typography>
          ) : null}
        </Box>
        {action}
      </Stack>
      {children}
    </Box>
  );
}

/** An empty state says what to do next, never "no data". */
export function Nothing({ children }: { children: ReactNode }) {
  return (
    <Paper variant="outlined" sx={{ p: 2 }}>
      <Typography variant="body2" color="text.secondary">
        {children}
      </Typography>
    </Paper>
  );
}
