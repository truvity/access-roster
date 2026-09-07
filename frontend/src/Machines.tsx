import { useState } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";
import ToggleButton from "@mui/material/ToggleButton";
import ToggleButtonGroup from "@mui/material/ToggleButtonGroup";
import Typography from "@mui/material/Typography";

import { access } from "./api";
import type { ExplainRequest } from "./gen/directoryroster/v1/access_pb";
import { useAsync } from "./hooks";
import { Explanation } from "./Person";
import { Failure, Loading } from "./ui";

type Kind = "ci" | "workload";

/** The identity-side leaf for proofs that have no directory. A CI job and
 *  a workload resolve to internal groups exactly as a person does, so
 *  they get the same page; they just cannot be searched for, because they
 *  do not exist until one runs, so the proof is typed here instead. */
export function Machines() {
  const [kind, setKind] = useState<Kind>("ci");
  const [repository, setRepository] = useState("example-org/gitops");
  const [ref, setRef] = useState("refs/heads/master");
  const [namespace, setNamespace] = useState("identity-system");
  const [name, setName] = useState("authorization-webhook");
  const [asked, setAsked] = useState<ExplainRequest | undefined>();

  const explained = useAsync(
    () => (asked ? access.explain(asked) : Promise.resolve(undefined)),
    [asked],
  );

  const ask = () => {
    if (kind === "ci") setAsked({ github: { repository: repository.trim(), ref: ref.trim() } } as ExplainRequest);
    else setAsked({ serviceAccount: { namespace: namespace.trim(), name: name.trim() } } as ExplainRequest);
  };

  return (
    <Box>
      <Typography variant="h6">Machines</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        A CI job or a workload is in an internal group by a matcher rather than by a directory group, and
        from there the chain is the same as a person's. Type the proof a real one would present.
      </Typography>

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack spacing={2}>
          <ToggleButtonGroup size="small" exclusive value={kind} onChange={(_, next: Kind | null) => next && setKind(next)}>
            <ToggleButton value="ci">A CI job</ToggleButton>
            <ToggleButton value="workload">A workload</ToggleButton>
          </ToggleButtonGroup>

          <Stack direction="row" spacing={1} sx={{ alignItems: "flex-start", flexWrap: "wrap", gap: 1 }}>
            {kind === "ci" ? (
              <>
                <TextField size="small" label="Repository" value={repository} onChange={(e) => setRepository(e.target.value)} sx={{ minWidth: 260 }} />
                <TextField size="small" label="Ref" value={ref} onChange={(e) => setRef(e.target.value)} sx={{ minWidth: 240 }} />
              </>
            ) : (
              <>
                <TextField size="small" label="Namespace" value={namespace} onChange={(e) => setNamespace(e.target.value)} sx={{ minWidth: 220 }} />
                <TextField size="small" label="ServiceAccount" value={name} onChange={(e) => setName(e.target.value)} sx={{ minWidth: 260 }} />
              </>
            )}
            <Button variant="contained" onClick={ask} sx={{ mt: 0.25 }}>
              Show the chain
            </Button>
          </Stack>
        </Stack>
      </Paper>

      <Loading busy={explained.loading} />
      <Failure error={explained.error} />
      {explained.value ? <Explanation value={explained.value} /> : null}
    </Box>
  );
}
