/** The React half. Peer dependencies: react and @mui/material, both
 * optional at the package level so an application with neither does not
 * pay for them. */
export { useIdentity } from "./useIdentity.js";
export { UserBadge, type UserBadgeProps } from "./UserBadge.js";
export { fetchIdentity, whoamiPath, type FetchOptions, type Identity, type Status } from "../identity.js";
