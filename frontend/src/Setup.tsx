import { useState } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Collapse from "@mui/material/Collapse";
import IconButton from "@mui/material/IconButton";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import RadioButtonUncheckedIcon from "@mui/icons-material/RadioButtonUnchecked";

import { backendName } from "./api";
import type { ConnectorSetup } from "./gen/directoryroster/v1/settings_pb";
import { paths } from "./router";
import { Mono, Ref, Section } from "./ui";

/** What a fresh installation still has to do, in order, with this
 *  installation's own values rather than a document's placeholders.
 *
 *  The redirect URI is the reason this exists at all. It is the hub's own
 *  hostname plus a fixed path, so a runbook can only describe it and an
 *  operator has to retype a hostname into a cloud console. That is where
 *  a day-one setup goes wrong, and it fails much later, at the first
 *  probe, with an error about a mismatched redirect. The hub knows the
 *  value exactly; showing it is strictly better than describing it. */
export type Progress = {
  clientConfigured: boolean;
  directories: number;
  operators: number;
  /** A recovery sign-in exists AND it is a stored password — the only
   *  shape that is a standing credential. Recovery by cluster access
   *  stores nothing, so there is nothing to turn off. */
  standingPassword: boolean;
  setup: ConnectorSetup[];
  operatorGroup: string;
};

/** Whether anything is left to do. A finished installation shows nothing:
 *  a checklist of ticks is a to-do list that has stopped being one. */
export function incomplete(p: Progress): boolean {
  return !p.clientConfigured || p.directories === 0 || p.operators === 0 || p.standingPassword;
}

export function Setup({ progress, operator }: { progress: Progress; operator: boolean }) {
  const steps = [
    {
      done: progress.clientConfigured,
      title: "Register an OAuth client with your provider",
      body: <Register setup={progress.setup} />,
    },
    {
      done: progress.clientConfigured,
      title: "Give the client to this hub",
      body: (
        <Typography variant="body2" color="text.secondary">
          Paste the id and secret in <Ref to={paths.settings()}>Settings</Ref>, or declare them in the
          deployment and the field goes read-only.
        </Typography>
      ),
    },
    {
      done: progress.directories > 0,
      title: "Connect the first provider",
      body: (
        <Typography variant="body2" color="text.secondary">
          One click, on <Ref to={paths.directories()}>Directories</Ref>, signed in as that tenant's admin
          role account. Its domains and groups are discovered; nothing is typed.
        </Typography>
      ),
    },
    {
      done: progress.operators > 0,
      title: "Say who operates this hub",
      body: (
        <Typography variant="body2" color="text.secondary">
          Attach a provider group to{" "}
          <Ref to={paths.group(progress.operatorGroup)} mono>
            {progress.operatorGroup}
          </Ref>
          . Everyone in it can then sign in here as an operator, and you stop being the only way in.
        </Typography>
      ),
    },
  ];
  // Only an installation that keeps a generated password has anything to
  // turn off. In a cluster, recovery is proving access to the API server
  // and stores nothing, so this step never appears.
  if (progress.standingPassword) {
    steps.push({
      done: false,
      title: "Turn off the recovery password",
      body: (
        <Typography variant="body2" color="text.secondary">
          Set <Mono>access.recovery.enabled: false</Mono>, or run this hub in a cluster, where recovery is a
          short-lived token proving access to the API server and no password is kept at all.
        </Typography>
      ),
    });
  }
  const done = steps.filter((step) => step.done).length;

  return (
    <Section
      title="Finish setting this up"
      hint={`${done} of ${steps.length} done. Each step disappears as it completes, and so does this.`}
    >
      <Paper variant="outlined">
        <Stack divider={<Box sx={{ borderBottom: 1, borderColor: "divider" }} />}>
          {steps.map((step, index) => (
            <Stack key={step.title} direction="row" spacing={1.5} sx={{ p: 1.75, alignItems: "flex-start" }}>
              <Box sx={{ pt: 0.25, color: step.done ? "success.main" : "text.disabled" }}>
                {step.done ? <CheckCircleIcon fontSize="small" /> : <RadioButtonUncheckedIcon fontSize="small" />}
              </Box>
              <Box sx={{ minWidth: 0, flexGrow: 1 }}>
                <Typography variant="body2" sx={{ fontWeight: 600, color: step.done ? "text.secondary" : "text.primary" }}>
                  {index + 1}. {step.title}
                </Typography>
                {step.done ? null : <Box sx={{ mt: 0.5 }}>{step.body}</Box>}
              </Box>
            </Stack>
          ))}
        </Stack>
      </Paper>
      {!operator ? (
        <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
          These steps need an operator. You are signed in as a viewer.
        </Typography>
      ) : null}
    </Section>
  );
}

/** The values to paste into the backend's cloud console. */
function Register({ setup }: { setup: ConnectorSetup[] }) {
  const [shown, setShown] = useState<string | undefined>(setup[0] ? String(setup[0].backend) : undefined);

  if (setup.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        This build knows no backend to guide you through.
      </Typography>
    );
  }
  return (
    <Stack spacing={1}>
      <Typography variant="body2" color="text.secondary">
        Once per installation, never per company: one project holding one OAuth client, its consent screen
        external and in production, these scopes, and both redirects — one for an administrator granting
        access to a company, one for a person signing in, and a client missing either works until somebody
        tries that flow. The connect runbook has the full walk-through.
      </Typography>
      {setup.map((entry) => {
        const key = String(entry.backend);
        const open = shown === key;
        return (
          <Box key={key}>
            <Button size="small" onClick={() => setShown(open ? undefined : key)} sx={{ ml: -1 }}>
              {open ? "Hide" : "Show"} what to register with {backendName(entry.backend)}
            </Button>
            <Collapse in={open}>
              <Stack spacing={1.5} sx={{ mt: 1 }}>
                <Field label="Authorised redirect URIs, both of them" values={entry.redirectUris} />
                <Field label="Scopes, all read-only" values={entry.scopes} />
              </Stack>
            </Collapse>
          </Box>
        );
      })}
    </Stack>
  );
}

function Field({ label, values }: { label: string; values: string[] }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    void navigator.clipboard?.writeText(values.join("\n")).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      },
      () => setCopied(false),
    );
  };
  return (
    <Box>
      <Stack direction="row" spacing={0.5} sx={{ alignItems: "center" }}>
        <Typography variant="caption" color="text.secondary">
          {label}
        </Typography>
        <Tooltip title={copied ? "Copied" : "Copy"}>
          <IconButton size="small" onClick={copy} aria-label={`copy ${label}`}>
            <ContentCopyIcon sx={{ fontSize: 14 }} />
          </IconButton>
        </Tooltip>
      </Stack>
      <Paper variant="outlined" sx={{ px: 1.25, py: 0.75, bgcolor: "background.default" }}>
        {values.map((value) => (
          <Typography key={value} variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.78rem", wordBreak: "break-all" }}>
            {value}
          </Typography>
        ))}
      </Paper>
    </Box>
  );
}
