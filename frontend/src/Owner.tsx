import { useState } from "react";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogContentText from "@mui/material/DialogContentText";
import DialogTitle from "@mui/material/DialogTitle";
import MenuItem from "@mui/material/MenuItem";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";

import { reason } from "./api";
import { Failure } from "./ui";
import { offersChoice, ownerName, ownerValid, type OwnerOffer } from "./ownerModel";

/** The owning directory a connect form asks for, where the caller has a
 *  choice, and a sentence saying which directory will own it where it has
 *  none. The server decides who may choose what: this only shows it. */
export function OwnerField({
  offer,
  noun,
  value,
  onChange,
}: {
  offer: OwnerOffer;
  noun: string;
  value: string;
  onChange: (owner: string) => void;
}) {
  if (!offersChoice(offer)) {
    const only = offer.choices[0];
    return (
      <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
        {only
          ? `The ${ownerName(only)} directory will own this ${noun}: its operators may operate it, alongside the installation-wide operator.`
          : `No directory will own this ${noun}: only the installation-wide role operates it, and nobody it names is looked up until an owner is set.`}
      </Typography>
    );
  }
  return (
    <TextField
      select
      fullWidth
      label="Owning directory"
      value={value}
      onChange={(event) => onChange(event.target.value)}
      helperText={`The connected directory this ${noun} belongs to. Its operators may operate it, alongside the installation-wide operator. Only the installation-wide operator changes it later.`}
      sx={{ mt: 2 }}
    >
      {offer.mayBeNone ? <MenuItem value="">None: the installation-wide role only</MenuItem> : null}
      {offer.choices.map((choice) => (
        <MenuItem key={choice.workspaceId} value={choice.workspaceId}>
          {ownerName(choice)}
        </MenuItem>
      ))}
    </TextField>
  );
}

/** Changing a connected thing's owner: the installation-wide operator's
 *  alone, to any connected directory or to none. */
export function ChangeOwnerDialog({
  title,
  current,
  offer,
  noun,
  save,
  onCancel,
  onDone,
}: {
  title: string;
  current: string;
  offer: OwnerOffer;
  noun: string;
  save: (owner: string) => Promise<void>;
  onCancel: () => void;
  onDone: (owner: string) => void;
}) {
  const [owner, setOwner] = useState(current);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | undefined>();
  const go = async () => {
    setBusy(true);
    setFailure(undefined);
    try {
      await save(owner);
      onDone(owner);
    } catch (error) {
      setFailure(reason(error));
      setBusy(false);
    }
  };
  return (
    <Dialog open onClose={busy ? undefined : onCancel} fullWidth maxWidth="sm">
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <DialogContentText>
          The owning directory&rsquo;s operators operate this {noun} beside the installation-wide operator, and its people are looked up by that directory&rsquo;s
          domains. Changing it takes effect at once; it is recorded in the audit trail.
        </DialogContentText>
        <OwnerField offer={{ ...offer, mayBeNone: true }} noun={noun} value={owner} onChange={setOwner} />
        <Failure error={failure} />
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
        <Button variant="contained" disabled={busy || owner === current || !ownerValid({ ...offer, mayBeNone: true }, owner)} onClick={() => void go()}>
          Change owner
        </Button>
      </DialogActions>
    </Dialog>
  );
}
