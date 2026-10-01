import type { DirectoryRef } from "./gen/directoryroster/v1/workspace_pb";

/** The owner of a Slack workspace or a GitHub organisation is the connected
 *  directory it belongs to. It is chosen when the thing is connected, and
 *  only the installation-wide operator changes it afterwards. The server
 *  decides every one of these answers (`ownerChoices`,
 *  `mayConnectWithoutOwner`): this file only words them, so that the console
 *  does not carry the rule a second time. */

/** What a connect form is offered: the directories the caller may name, and
 *  whether it may name none. */
export type OwnerOffer = { choices: DirectoryRef[]; mayBeNone: boolean };

/** Whether the form shows a choice at all. A caller who operates exactly one
 *  directory has nothing to choose: that directory owns what it connects. */
export function offersChoice(offer: OwnerOffer): boolean {
  return offer.mayBeNone ? offer.choices.length > 0 : offer.choices.length > 1;
}

/** The owner a form starts on: none for the installation-wide operator, the
 *  one directory for a caller with one, and unchosen for a caller with
 *  several. */
export function initialOwner(offer: OwnerOffer): string {
  if (offer.mayBeNone) return "";
  return offer.choices.length === 1 ? offer.choices[0]!.workspaceId : "";
}

/** Whether the form may be submitted with this owner. */
export function ownerValid(offer: OwnerOffer, owner: string): boolean {
  if (owner === "") return offer.mayBeNone || offer.choices.length === 1;
  return offer.choices.some((choice) => choice.workspaceId === owner);
}

/** What a directory is called wherever it is named as an owner: its
 *  workspace id and every domain it is authoritative for, sorted, so an
 *  operator looking for any one of its domains finds it:
 *  `C0north — alpha.example, globex.example`. `domains` is the list, or
 *  the server's already-joined text; a directory with none is its id. */
export function directoryLabel(workspaceId: string, domains: readonly string[] | string): string {
  const list = typeof domains === "string" ? domains : [...domains].sort().join(", ");
  return list ? `${workspaceId} \u2014 ${list}` : workspaceId;
}

/** What an owner choice is called: see [directoryLabel]. */
export function ownerName(choice: Pick<DirectoryRef, "workspaceId" | "domains">): string {
  return directoryLabel(choice.workspaceId, choice.domains);
}

/** The phrase for a connected thing's owner: the directory by its label, or
 *  the plain statement that nobody owns it. `domains` is empty when the
 *  owner serves nothing authoritatively or is no longer connected; the id
 *  alone then says which it was. */
export function ownerSentence(owner: string, domains: string, consequence: string): string {
  if (owner === "") return `no owning directory: ${consequence}`;
  return `owned by the ${directoryLabel(owner, domains)} directory`;
}
