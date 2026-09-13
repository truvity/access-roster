/** access-roster — what a console needs from the identity it is behind.
 *
 * Install from GitHub Packages, with the @truvity scope pointed at
 * https://npm.pkg.github.com (docs/reference/typescript.md):
 *
 *     yarn add @truvity/access-roster
 *
 * The React half is under the "/react" subpath, so an application with no
 * React does not pay for it. The server half — verifying the token the
 * gateway forwards, and answering whoami — is under "/server", for a Node
 * service, so a browser bundle never pulls in a key set or `node:http`.
 */
export {
  fetchIdentity,
  whoamiPath,
  type FetchOptions,
  type Identity,
  type Status,
} from "./identity.js";
