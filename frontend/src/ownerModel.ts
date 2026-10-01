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

/** What an owner is called: the domain people know the directory by. */
export function ownerName(choice: Pick<DirectoryRef, "workspaceId" | "primaryDomain">): string {
  return choice.primaryDomain || choice.workspaceId;
}

/** The phrase for a connected thing's owner: the directory by its primary
 *  domain, or the plain statement that nobody owns it. `domain` is empty
 *  when the owner is no longer connected, and the id says which it was. */
export function ownerSentence(owner: string, domain: string, consequence: string): string {
  if (owner === "") return `no owning directory: ${consequence}`;
  return `owned by the ${domain || owner} directory${domain ? "" : " (no longer connected)"}`;
}
