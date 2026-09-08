/** access-roster — what a console needs from the identity it is behind.
 *
 * Install from git at a tag:
 *
 *     npm install github:truvity/access-roster#v0.2.0
 *
 * The React half is under the "/react" subpath, so an application with no
 * React does not pay for it.
 */
export {
  fetchIdentity,
  whoamiPath,
  type FetchOptions,
  type Identity,
  type Status,
} from "./identity.js";
