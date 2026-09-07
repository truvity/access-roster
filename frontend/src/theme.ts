import { createTheme } from "@mui/material/styles";

// Teal for the hub, a muted slate ground, and semantic colours kept
// separate from the accent so that "not authoritative" reads as a state
// rather than as decoration.
export const theme = createTheme({
  palette: {
    primary: { main: "#0e7c7b" },
    secondary: { main: "#4a4fb5" },
    success: { main: "#2f7a4f" },
    warning: { main: "#a8433f" },
    background: { default: "#f3f5f8" },
  },
  typography: {
    fontFamily: `system-ui, -apple-system, "Segoe UI", sans-serif`,
    h6: { fontWeight: 600 },
  },
  shape: { borderRadius: 6 },
});
