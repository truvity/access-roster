import { createTheme } from "@mui/material/styles";

// A data console, not a touch app: tighter, quieter, lowercase. Teal is
// the accent; semantic colours stay separate from it so that a state
// reads as a state rather than as decoration. Borders are reserved for
// tables and forms — sections are separated by whitespace and type.
export const theme = createTheme({
  palette: {
    primary: { main: "#0e7c7b" },
    secondary: { main: "#4a4fb5" },
    success: { main: "#2f7a4f" },
    warning: { main: "#a8433f" },
    background: { default: "#f6f7f9", paper: "#ffffff" },
    divider: "#e2e6ec",
    text: { primary: "#1c2430", secondary: "#5b6675" },
  },
  typography: {
    fontFamily: `system-ui, -apple-system, "Segoe UI", sans-serif`,
    h5: { fontWeight: 650, fontSize: "1.35rem", letterSpacing: "-0.01em", lineHeight: 1.25 },
    h6: { fontWeight: 600, fontSize: "1.05rem" },
    subtitle1: { fontWeight: 600, fontSize: "0.95rem", lineHeight: 1.4 },
    subtitle2: { fontWeight: 600, fontSize: "0.85rem" },
    body1: { fontSize: "0.925rem" },
    body2: { fontSize: "0.85rem" },
    caption: { fontSize: "0.75rem", lineHeight: 1.4 },
    overline: { fontSize: "0.68rem", letterSpacing: "0.08em", fontWeight: 600 },
    button: { textTransform: "none", fontWeight: 600 },
  },
  shape: { borderRadius: 6 },
  components: {
    MuiButton: { defaultProps: { disableElevation: true } },
    MuiTab: { styleOverrides: { root: { textTransform: "none", minHeight: 40 } } },
    MuiChip: {
      defaultProps: { size: "small" },
      styleOverrides: { root: { fontSize: "0.72rem", height: 22 }, label: { paddingLeft: 8, paddingRight: 8 } },
    },
    MuiPaper: { styleOverrides: { outlined: { borderColor: "#e2e6ec" } } },
    MuiTableCell: {
      styleOverrides: {
        root: { padding: "7px 12px", borderBottomColor: "#eceff3" },
        head: { fontSize: "0.72rem", fontWeight: 600, color: "#5b6675", textTransform: "uppercase", letterSpacing: "0.04em" },
      },
    },
    MuiListSubheader: {
      styleOverrides: {
        root: { fontSize: "0.68rem", letterSpacing: "0.08em", fontWeight: 600, textTransform: "uppercase", lineHeight: "32px", backgroundColor: "transparent" },
      },
    },
    MuiListItemButton: { styleOverrides: { root: { borderRadius: 6, marginInline: 8, paddingBlock: 6 } } },
    MuiListItemIcon: { styleOverrides: { root: { minWidth: 34 } } },
    MuiTooltip: { defaultProps: { arrow: true } },
    MuiTextField: { defaultProps: { size: "small" } },
  },
});
