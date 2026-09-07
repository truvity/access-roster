import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Chip from "@mui/material/Chip";
import LinearProgress from "@mui/material/LinearProgress";
import Tooltip from "@mui/material/Tooltip";

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
