import Autocomplete from "@mui/material/Autocomplete";
import Chip from "@mui/material/Chip";
import TextField from "@mui/material/TextField";

import { withAddresses } from "./slackMembersModel";

/** Lists individual addresses for a channel, beside its directory groups.
 *  Type or paste one or several (blanks, commas and semicolons separate them)
 *  and press Enter, or leave the field. An address that cannot be used is
 *  drawn as an error chip and said in the helper text; Save stays off until
 *  none is left. */
export function MemberPicker({
  value,
  bad,
  problems,
  onChange,
  disabled,
  helperText,
  label = "Individual addresses",
}: {
  value: string[];
  /** The addresses to draw as errors. */
  bad: ReadonlySet<string>;
  /** What is wrong, one sentence each; shown instead of the helper text. */
  problems: readonly string[];
  onChange: (members: string[]) => void;
  disabled?: boolean;
  helperText?: string;
  label?: string;
}) {
  return (
    <Autocomplete
      multiple
      freeSolo
      autoSelect
      options={[]}
      value={value}
      onChange={(_, next) => onChange(withAddresses([], next.join(" ")))}
      disabled={disabled}
      renderValue={(items, getItemProps) =>
        items.map((item, index) => {
          const { key, ...props } = getItemProps({ index });
          return <Chip key={key} {...props} size="small" label={item} color={bad.has(item) ? "error" : "default"} variant={bad.has(item) ? "filled" : "outlined"} />;
        })
      }
      renderInput={(params) => (
        <TextField
          {...params}
          label={label}
          error={problems.length > 0}
          helperText={problems.length > 0 ? problems.join(". ") : helperText}
          slotProps={{ htmlInput: { ...params.slotProps.htmlInput, spellCheck: false, autoCapitalize: "off" } }}
        />
      )}
    />
  );
}
