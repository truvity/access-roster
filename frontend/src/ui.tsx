import type { ReactNode } from "react";

import { DomainReason } from "./gen/directoryroster/v1/workspace_pb";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Chip from "@mui/material/Chip";
import Divider from "@mui/material/Divider";
import LinearProgress from "@mui/material/LinearProgress";
import Link from "@mui/material/Link";
import List from "@mui/material/List";
import ListItem from "@mui/material/ListItem";
import ListItemText from "@mui/material/ListItemText";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";

/* The console's visual vocabulary. One meaning per form:
 *   a name is a Link (monospace when it is an identifier),
 *   a state is a Chip and nothing else is,
 *   facts are a label/value grid,
 *   two-column data is a list, tabular data is a table. */

/** Every name in the console is a link to the page about that thing. */
export function Ref({ to, children, mono, dim }: { to: string; children: ReactNode; mono?: boolean; dim?: boolean }) {
  return (
    <Link
      href={`#${to}`}
      underline="hover"
      sx={{
        fontFamily: mono ? "monospace" : undefined,
        fontSize: mono ? "0.85em" : undefined,
        // `dim` is for a name repeated down a run of rows: still the same
        // link, but the eye should land on the first of the run and read
        // the rest as continuation rather than as new information.
        opacity: dim ? 0.55 : undefined,
      }}
    >
      {children}
    </Link>
  );
}

/** Several names in a sentence, separated rather than boxed. */
export function Names({
  items,
  empty,
  muted,
}: {
  items: { label: string; to?: string; mono?: boolean; note?: string }[];
  empty?: string;
  muted?: boolean;
}) {
  if (items.length === 0) {
    return empty ? (
      <Typography component="span" variant="body2" color="text.secondary">
        {empty}
      </Typography>
    ) : null;
  }
  return (
    <Typography component="span" variant="body2" color={muted ? "text.secondary" : "text.primary"} sx={{ lineHeight: 1.8 }}>
      {items.map((item, index) => (
        <span key={item.label + index}>
          {index > 0 ? <span style={{ opacity: 0.5 }}>, </span> : null}
          {item.to ? (
            <Ref to={item.to} mono={item.mono}>
              {item.label}
            </Ref>
          ) : (
            <span style={{ fontFamily: item.mono ? "monospace" : undefined, fontSize: item.mono ? "0.85em" : undefined }}>{item.label}</span>
          )}
          {item.note ? (
            <Typography component="span" variant="caption" color="text.secondary">
              {" "}
              {item.note}
            </Typography>
          ) : null}
        </span>
      ))}
    </Typography>
  );
}

export type StateKind =
  | "live"
  | "suspended"
  | "authoritative"
  | "provisional"
  | "contested"
  | "declared"
  | "console"
  | "matcher"
  | "unknown"
  | "healthy"
  | "failing"
  | "configured"
  | "unconfigured"
  | "unserved"
  | "unowned";

const states: Record<StateKind, { label: string; color: "success" | "warning" | "secondary" | "default"; filled?: boolean; title: string }> = {
  live: { label: "live", color: "success", title: "The provider reports this account as active." },
  suspended: { label: "suspended", color: "warning", filled: true, title: "The provider says this account is not live. A consumer acts on that only when the answer is authoritative." },
  authoritative: { label: "authoritative", color: "success", title: "The last probe succeeded, the snapshot is fresh and no one else claims this domain. Consumers may act on removals." },
  provisional: { label: "provisional", color: "warning", title: "Answers about this may not be acted on for removals: consumers add but never remove." },
  contested: { label: "contested", color: "warning", filled: true, title: "Another directory serves this domain too. It is authoritative for neither until one of them stops." },
  declared: { label: "declared", color: "secondary", title: "Declared by the deployment: change it in the values." },
  console: { label: "console", color: "default", title: "Added in this console." },
  matcher: { label: "matcher", color: "secondary", title: "Admits a proof by its shape rather than through a directory: a CI job, a workload, a verified sign-in. Declared only." },
  unknown: { label: "not read", color: "default", title: "No connected directory has this account, so access-roster cannot say whether it is live." },
  healthy: { label: "healthy", color: "success", title: "The last probe succeeded." },
  failing: { label: "failing", color: "warning", filled: true, title: "The last probe failed." },
  configured: { label: "configured", color: "success", title: "" },
  unconfigured: { label: "not configured", color: "warning", filled: true, title: "" },
  unserved: {
    label: "not served",
    color: "default",
    title: "This directory owns the domain and access-roster has been told not to read it: nothing routes to it and its accounts are not kept.",
  },
  unowned: {
    label: "no longer owned",
    color: "warning",
    title: "This hub is set to serve the domain, but the directory no longer lists it — it has moved elsewhere. It routes nothing; drop it from the served list.",
  },
};

/** The one thing a chip means here: a state. A state that has a reason
 *  carries it in the label — "provisional" on its own is the answer that
 *  sent an operator looking for a fault that was not there. */
/** The word a state is shown as, for a filter that has to say the same
 *  thing the chip says. One table, read twice. */
export function stateLabel(kind: string): string {
  return states[kind as StateKind]?.label ?? kind;
}

export function State({ kind, title, label }: { kind: StateKind; title?: string; label?: string }) {
  const s = states[kind];
  const chip = <Chip label={label ? `${s.label} · ${label}` : s.label} color={s.color} variant={s.filled ? "filled" : "outlined"} />;
  const tip = title ?? s.title;
  return tip ? <Tooltip title={tip}>{chip}</Tooltip> : chip;
}

/** Why a domain is provisional, in the operator's words. The wire says
 *  only "not authoritative", which covers a directory connected ten
 *  seconds ago and one whose credential was revoked last week — and
 *  showing the wrong one of those reads as an alarm on a directory that
 *  is perfectly fine. */
export const domainReason: Record<number, { short: string; why: string }> = {
  [DomainReason.FIRST_SNAPSHOT_PENDING]: {
    short: "first snapshot",
    why: "This directory has not been read yet. The first snapshot is running; it clears by itself.",
  },
  [DomainReason.SNAPSHOT_STALE]: {
    short: "stale",
    why: "The last snapshot is older than the freshness window, so its answers are no longer current enough to act on.",
  },
  [DomainReason.PROBE_FAILED]: {
    short: "probe failed",
    why: "The credential did not work at the last probe. Reconnect, or upload a new key.",
  },
};

/** Whether a domain's answers may be acted on — or, before that question
 *  arises, whether the hub answers for it at all. A domain left out of the
 *  served list has no authority to report and is never provisional: it is
 *  not a degraded answer, it is no answer. */
export type AuthorityFacts = {
  authoritative: boolean;
  conflict?: boolean;
  served?: boolean;
  owned?: boolean;
  reason?: DomainReason;
};

/** Which one state a domain is in.
 *
 *  Exported because a FILTER has to agree with the chip, and the only way
 *  to guarantee that is for both to ask the same function. The order is
 *  the point and is not alphabetical: a domain the tenant does not own is
 *  not merely unserved, and a contested one is not merely provisional, so
 *  the first match wins and the rest are never reached. */
export function authorityKind(domain: AuthorityFacts): StateKind {
  if (domain.owned === false) return "unowned";
  if (domain.served === false) return "unserved";
  if (domain.conflict) return "contested";
  if (domain.authoritative) return "authoritative";
  return "provisional";
}

export function Authority({ authoritative, conflict, served, owned, reason }: AuthorityFacts) {
  const kind = authorityKind({ authoritative, conflict, served, owned, reason });
  if (kind !== "provisional") return <State kind={kind} />;
  const explained = reason !== undefined ? domainReason[reason] : undefined;
  return <State kind="provisional" label={explained?.short} title={explained?.why} />;
}

export type Fact = { label: string; value: ReactNode };

/** Label over value, in a row — or stacked, in an aside. Metadata reads
 *  as metadata. */
export function Facts({ items, stacked }: { items: Fact[]; stacked?: boolean }) {
  const shown = items.filter((item) => item.value !== undefined && item.value !== null && item.value !== "");
  if (shown.length === 0) return null;
  return (
    <Stack direction={stacked ? "column" : "row"} sx={{ flexWrap: "wrap", columnGap: 4, rowGap: stacked ? 1.75 : 1.5 }}>
      {shown.map((item) => (
        <Box key={item.label} sx={{ minWidth: 0 }}>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.25 }}>
            {item.label}
          </Typography>
          <Typography component="div" variant="body2" sx={{ display: "flex", alignItems: "center", gap: 0.75, minHeight: 22 }}>
            {item.value}
          </Typography>
        </Box>
      ))}
    </Stack>
  );
}

/** The top of every page: what this is, in one line and one sentence,
 *  then its facts, then the actions that belong to it.
 *
 *  A detail page splits on a wide window: the main column carries the
 *  edges, the aside carries the facts and the reference material that
 *  would otherwise push the edges down. On a narrow window the aside
 *  follows the main column. */
export function Page({
  title,
  mono,
  lede,
  facts,
  actions,
  aside,
  children,
}: {
  title: ReactNode;
  mono?: boolean;
  lede?: ReactNode;
  facts?: Fact[];
  actions?: ReactNode;
  aside?: ReactNode;
  children?: ReactNode;
}) {
  if (aside !== undefined) {
    return (
      <Box>
        <Stack direction="row" sx={{ alignItems: "flex-start", justifyContent: "space-between", gap: 2, mb: 3 }}>
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="h5" sx={{ fontFamily: mono ? "monospace" : undefined, wordBreak: "break-word" }}>
              {title}
            </Typography>
            {lede ? (
              <Typography variant="body1" color="text.secondary" sx={{ mt: 0.5, maxWidth: 760 }}>
                {lede}
              </Typography>
            ) : null}
          </Box>
          {actions ? (
            <Stack direction="row" spacing={1} sx={{ flexShrink: 0, alignItems: "center" }}>
              {actions}
            </Stack>
          ) : null}
        </Stack>
        <Box sx={{ display: { xs: "block", lg: "grid" }, gridTemplateColumns: "minmax(0, 1fr) 300px", columnGap: 5, alignItems: "start" }}>
          <Box sx={{ minWidth: 0 }}>{children}</Box>
          <Box sx={{ position: { lg: "sticky" }, top: 76, pl: { lg: 4 }, borderLeft: { lg: 1 }, borderColor: { lg: "divider" } }}>
            {facts?.length ? (
              <Box sx={{ mb: 3 }}>
                <Facts items={facts} stacked />
              </Box>
            ) : null}
            {aside}
          </Box>
        </Box>
      </Box>
    );
  }
  return (
    <Box>
      <Stack direction="row" sx={{ alignItems: "flex-start", justifyContent: "space-between", gap: 2, mb: facts?.length ? 2 : 3 }}>
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="h5" sx={{ fontFamily: mono ? "monospace" : undefined, wordBreak: "break-word" }}>
            {title}
          </Typography>
          {lede ? (
            <Typography variant="body1" color="text.secondary" sx={{ mt: 0.5, maxWidth: 760 }}>
              {lede}
            </Typography>
          ) : null}
        </Box>
        {actions ? (
          <Stack direction="row" spacing={1} sx={{ flexShrink: 0, alignItems: "center" }}>
            {actions}
          </Stack>
        ) : null}
      </Stack>
      {facts?.length ? (
        <Box sx={{ mb: 3 }}>
          <Facts items={facts} />
        </Box>
      ) : null}
      {children}
    </Box>
  );
}

/** A titled block. Pages are a stack of these, separated by type and
 *  space rather than by a border each. */
export function Section({
  title,
  hint,
  action,
  children,
}: {
  title: string;
  hint?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <Box sx={{ mb: 4 }}>
      <Stack direction="row" sx={{ alignItems: "flex-end", justifyContent: "space-between", gap: 2, mb: 1 }}>
        <Box>
          <Typography variant="subtitle1">{title}</Typography>
          {hint ? (
            <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
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

/** Two-column data: a primary line, a secondary line, something on the
 *  right. A list, because a table with an empty half is not a table. */
export function Rows<T>({
  items,
  keyOf,
  primary,
  secondary,
  right,
  empty,
}: {
  items: T[];
  keyOf: (item: T) => string;
  primary: (item: T) => ReactNode;
  secondary?: (item: T) => ReactNode;
  right?: (item: T) => ReactNode;
  empty: ReactNode;
}) {
  if (items.length === 0) return <Nothing>{empty}</Nothing>;
  return (
    <Paper variant="outlined">
      <List disablePadding>
        {items.map((item, index) => (
          <Box key={keyOf(item)}>
            {index > 0 ? <Divider component="li" /> : null}
            <ListItem sx={{ py: 0.75, px: 1.5, gap: 2 }}>
              <ListItemText
                primary={primary(item)}
                secondary={secondary ? secondary(item) : undefined}
                slotProps={{ primary: { component: "div", variant: "body2" }, secondary: { component: "div", variant: "caption" } }}
                sx={{ my: 0 }}
              />
              {right ? (
                <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexShrink: 0, justifyContent: "flex-end", flexWrap: "wrap", rowGap: 0.5 }}>
                  {right(item)}
                </Stack>
              ) : null}
            </ListItem>
          </Box>
        ))}
      </List>
    </Paper>
  );
}

export function Loading({ busy }: { busy: boolean }) {
  return <Box sx={{ height: 3, mb: 1 }}>{busy ? <LinearProgress sx={{ height: 3 }} /> : null}</Box>;
}

export function Failure({ error }: { error?: string }) {
  if (!error) return null;
  return (
    <Alert severity="error" sx={{ my: 2 }}>
      {error}
    </Alert>
  );
}

/** An empty state says what to do next, never "no data". */
export function Nothing({ children }: { children: ReactNode }) {
  return (
    <Box sx={{ px: 1.5, py: 1.25, borderRadius: 1, bgcolor: "action.hover" }}>
      <Typography variant="body2" color="text.secondary">
        {children}
      </Typography>
    </Box>
  );
}

/** Monospace inline, for an identifier that is not a link. */
export function Mono({ children }: { children: ReactNode }) {
  return (
    <Box component="span" sx={{ fontFamily: "monospace", fontSize: "0.85em" }}>
      {children}
    </Box>
  );
}
