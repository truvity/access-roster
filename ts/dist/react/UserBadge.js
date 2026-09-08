import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Box, Button, Chip, Stack, Typography } from "@mui/material";
/** The header block every console in this family shows: who you are, what
 * that gets you, and the way out.
 *
 * It renders all four states, including the one consoles usually skip.
 * "Unknown" means the application could not be asked — showing a sign-in
 * button there would send a signed-in person to authenticate again for
 * nothing, and showing nothing would leave them wondering. */
export function UserBadge({ identity, emphasize = ["operator"], signInHref = "/login" }) {
    if (identity.status === "loading")
        return null;
    if (identity.status === "unknown") {
        return (_jsx(Typography, { variant: "body2", color: "text.secondary", title: identity.error, children: "Signed in, but this page could not confirm who with." }));
    }
    if (identity.status === "signed-out") {
        return (_jsx(Button, { href: signInHref, size: "small", variant: "outlined", children: "Sign in" }));
    }
    const name = identity.name || identity.email || "signed in";
    return (_jsxs(Stack, { direction: "row", spacing: 1.5, sx: { alignItems: "center" }, children: [_jsxs(Box, { sx: { textAlign: "right", lineHeight: 1.15, minWidth: 0 }, children: [_jsx(Typography, { variant: "body2", noWrap: true, children: name }), identity.name && identity.email && (_jsx(Typography, { variant: "caption", color: "text.secondary", noWrap: true, children: identity.email }))] }), (identity.roles ?? []).map((role) => (_jsx(Chip, { label: role, size: "small", variant: "outlined", color: emphasize.includes(role) ? "success" : "default" }, role))), identity.signOutUrl && (_jsx(Button, { href: identity.signOutUrl, size: "small", variant: "outlined", title: "End this session", children: "Sign out" }))] }));
}
//# sourceMappingURL=UserBadge.js.map