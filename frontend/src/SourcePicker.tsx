import Autocomplete from "@mui/material/Autocomplete";
import TextField from "@mui/material/TextField";

import { matchingOptions, optionOf, type SourceOption } from "./slackSourcesModel";

/** Picks directory groups for a channel: every group the server offers,
 *  listed under the directory it belongs to, and searchable by address or by
 *  directory. A group a record names that is no longer offered stays chosen,
 *  under "not in a connected directory", so it can be seen and removed. */
export function SourcePicker({
  options,
  value,
  onChange,
  disabled,
  helperText,
  label = "Directory groups",
}: {
  options: SourceOption[];
  value: string[];
  onChange: (sources: string[]) => void;
  disabled?: boolean;
  helperText?: string;
  label?: string;
}) {
  const chosen = value.map((email) => optionOf(options, email));
  const offered = [...options, ...chosen.filter((c) => c.directory === "")];
  return (
    <Autocomplete
      multiple
      disableCloseOnSelect
      options={offered}
      value={chosen}
      groupBy={(option) => option.label}
      getOptionLabel={(option) => option.email}
      isOptionEqualToValue={(a, b) => a.email === b.email}
      filterOptions={(all, state) => matchingOptions(all, state.inputValue)}
      onChange={(_, next) => onChange(next.map((option) => option.email))}
      disabled={disabled}
      noOptionsText="No directory group matches. Only groups of a connected directory can be chosen."
      renderInput={(params) => <TextField {...params} label={label} helperText={helperText} />}
    />
  );
}
