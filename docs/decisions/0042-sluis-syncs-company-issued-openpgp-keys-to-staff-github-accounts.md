# 0042 — sluis syncs company-issued OpenPGP keys to staff GitHub accounts

**Status:** Proposed
**Date:** 2026-11-06

Proposal: [issue #874](https://github.com/truvity/sluis/issues/874). The sync has no issue of its own yet; this link is the OpenPGP foundation it grows from.

## Context

The company issues each staff member an OpenPGP signing key whose subkeys are born on the person's card. [ritueel](https://ritueel.id) makes the keys and builds the **staff keyring**, a package of one public certificate for every active person, in the layout of its release keyring. GitHub marks a commit Verified only when the signing key is on the author's account, and its copy of a key changes only when the key is uploaded again (to be measured, see Follow-ups): a subkey binding lasts about 13 months ([0024](/decisions/0024-root-custody-and-the-signing-api/#lifetimes-and-the-warning)), so a key uploaded by hand goes stale every year without anyone noticing, and a leaver's key stays on the account until someone remembers it.

On 2026-11-06 the maintainer decided, in these words and answers:

| Label | Decision |
|---|---|
| (the request) | "GPG and GitHub - it should be part of sluis to export GPG keyring (updated) to GitHub account (maybe using github app created by sluis)". |
| GH1 A | "the App manages only the keys the company issued. It adds and removes those fingerprints and leaves personal keys alone." |
| GH2 A | "personal GitHub accounts plus the App. Enterprise Managed Users is a possible later step." |
| GH3 A | "sluis owns the App. ritueel produces the keyring; sluis syncs it." |
| G1 A | "OpenPGP keys born on cards, with no SSH-signing fallback." |
| G3 C | "no GitHub enforcement yet. A later CI check compares each commit's signing key against the staff keyring." |
| G5 A | "for a leaver, the App removes the company key from their account and the certification lapses. Old commits stay Verified." |

This record turns those answers into a design. The other decisions of the day (G8 A, C2 A and C3 A) concern release signing and are in [Release signing](/distribution/release-signing/#how-a-release-is-verified); their requirements are named under Consequences.

Facts about GitHub, read from its documentation on 2026-11-06:

- A GitHub App can act as a user. The user authorises it, and the token it gets "only has permissions that both the user and the app have" ([user access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app)). The web application flow supports PKCE with `S256` only.
- The user token "expires after eight hours". The refresh token "expires after six months". A refresh returns a new user token and a new refresh token, and "once you use a refresh token, that refresh token and the old user access token will no longer work" ([refreshing user access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens)). A refresh token that has expired means the person goes through the flow again.
- The account permission "GPG keys" covers four calls on the authenticated user: `GET /user/gpg_keys` and `GET /user/gpg_keys/{id}` need read, `POST /user/gpg_keys` and `DELETE /user/gpg_keys/{id}` need write ([permissions required for GitHub Apps](https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps)). There is no call that changes a key in place ([GPG keys](https://docs.github.com/en/rest/users/gpg-keys)).
- When a user revokes the authorisation, GitHub sends the `github_app_authorization` event to the App by default, with no way to unsubscribe. Revoking does not uninstall the App, and a call with the revoked token gets `401` ([webhook events](https://docs.github.com/en/webhooks/webhook-events-and-payloads#github_app_authorization)).
- Vigilant mode is a setting on the person's own account ("Flag unsigned commits as unverified", under SSH and GPG keys). The page mentions no API and no organisation-level setting ([verification statuses](https://docs.github.com/en/authentication/managing-commit-signature-verification/displaying-verification-statuses-for-all-of-your-commits)).
- GitHub checks a signature at push time and keeps the result, so a later removal, expiry or revocation of a key does not change an old commit ([persistent verification](https://github.blog/changelog/2024-12-10-persistent-commit-signature-verification-is-generally-available/), 2024-12-10).

## Decision

### The App

- **One App does one job: it syncs company-issued OpenPGP keys.** It is the **key App**, a second public App beside the link App, and a `GitHubApp` of the operator's own tenant ([GitHub](/integrations/github/#what-sluis-asks-the-vendor-for)). It is public for the reason the link App is: staff accounts are personal, and a private App can be authorised only by members of its owner. Anyone may authorise it, and it does nothing for a person whom the directory does not know ([Joining](/decisions/0042-sluis-syncs-company-issued-openpgp-keys-to-staff-github-accounts/#joining)).
- **Its only permission is the account permission "GPG keys: read and write".** It has no repository, organisation or other account permission, is installed nowhere, and keeps GitHub's expiring user tokens on. It asks for no SSH-key permission, because there is no SSH-signing fallback (G1 A).
- **sluis makes it with the manifest flow** of [Connecting](/integrations/connecting/#github-app-manifest-flow), as for every App. The manifest names the callback URL of `adapter-github` and an active webhook for one event, `github_app_authorization`. The name of the permission in the manifest is confirmed when the manifest is written.
- **`adapter-github` is the only holder.** It opens the App's client secret from its `GitHubApp` per call, as it does for the other Apps ([0025](/decisions/0025-integrations/#adapters-and-connections)), and calls `api.github.com` and nothing else for this job.

### Joining

- **Each person authorises the App once, as part of joining.** The console shows the joining steps. After the person has signed in and the directory has them as live, the step "authorise the key App" starts the web application flow: a state bound to the person's session, an S256 PKCE challenge, and a redirect to GitHub. The state lives as long as the other manifest and OAuth states (a temp kind, at most one hour).
- **The first account is pinned.** `adapter-github` exchanges the code, reads the authenticated user and stores the GitHub user id. A later authorisation from another account is refused until an operator releases the pin, so a person cannot move their company keys to an account of a colleague or of a stranger.
- **The person verifies their company address on the account.** GitHub shows a signature as Verified only when the commit address is a user ID of the key and a verified address of the account. The page tells the person this; sluis cannot do it for them.

### Storing and refreshing the user token

- **The tokens are one durable item per person, sealed, personal and written by `adapter-github`,** the kind `GitHubKeyAuthorization`, added to the registry with the first build ([#874](https://github.com/truvity/sluis/issues/874)). It holds the GitHub user id, the user token and its expiry, the refresh token and its expiry, the state (`active`, `revoked`, `lapsed`, `left`) and the ids of the GitHub key records that sluis made. It is sealed under the tenant's `data` key, like every credential an adapter uses, and is erased with the person ([0004](/decisions/0004-the-data-model/)).
- **The adapter opens the item per call and keeps nothing,** as in [0025](/decisions/0025-integrations/#adapters-and-connections). The tokens are never in an audit record, a log line, a span or a console page ([0025](/decisions/0025-integrations/#how-core-authorises-an-effect)).
- **A refresh is made under the person's lease and written before it is used.** A refresh token works once, so two processes refreshing at the same time would burn the pair. The adapter takes a lease named for the person ([0026](/decisions/0026-reconcilers/#scope)), refreshes only when the user token has less than 5 minutes left, and writes the returned pair with a conditional write before the first call that uses it. If the write fails, the pair is lost and the person authorises again.
- **A pass refreshes often enough that the six months never run out.** Every full pass lists the account's keys, so a pass refreshes at least once a day and each refresh starts a new six-month refresh token. The refresh token lapses only when sluis has made no pass for six months, and then the state is `lapsed`, and the person is asked to authorise again.

### The sync loop

- **The source of truth is the staff keyring that ritueel builds.** It is an input of the adapter, like the root list ([0024](/decisions/0024-root-custody-and-the-signing-api/#root-pins-and-the-root-list)): the operator's pipeline signs the package, the operator pins the publisher's key in config, and `adapter-github` verifies the signature before it uses a certificate. A package with a lower sequence than the one held is refused. ritueel does not sign or publish the package, and sluis does not build it.
- **The desired state of a person is their company keys.** They are the certificates of the verified keyring whose user ID address is a verified address of that person in the directory. The adapter reads the directory facts through its data port and asks core nothing, so it only executes what the signed keyring says; who may hold a key is ritueel's and the operator's decision, not the adapter's ([0025](/decisions/0025-integrations/#the-rule)). When sluis certifies staff primaries ([0024](/decisions/0024-root-custody-and-the-signing-api/#company-openpgp-certification)), the adapter adds only a primary that carries sluis's own certification.
- **Three actions, for company fingerprints only.**

  | Action | When | How |
  |---|---|---|
  | Add | The desired certificate is not on the account | `POST /user/gpg_keys` with the armoured certificate and a name that holds the fingerprint |
  | Update | The account holds the primary, and the keyring has a binding, subkey or expiry that GitHub's copy lacks | GitHub cannot change a key in place, so add the new copy, then delete the old record |
  | Remove | The keyring no longer holds the key, or the person has left | `DELETE /user/gpg_keys/{id}` |

  Whether GitHub accepts a second upload of a primary it already holds is measured before the build ([#874](https://github.com/truvity/sluis/issues/874)). If it does not, an update is delete then add in one pass, and a commit pushed in the gap is permanently Unverified, because GitHub never re-checks.
- **A company key is a fingerprint that sluis can show it issued.** It is a primary in the current verified keyring, a primary whose GitHub record sluis made (the ids in the item), or a primary on the keyring's list of withdrawn keys. Every other key on the account is personal and is never read for any purpose but listing, never changed and never removed, even when its user ID carries a company address (GH1 A).
- **The pass is a reconciler's pass without being a reconciler.** [0026](/decisions/0026-reconcilers/#scope) limits a reconciler to membership, and this job manages keys, so it is a job of `adapter-github` of its own. It keeps the rules of 0026 that apply: one pass per person under a lease, level-triggered and idempotent, a dry run until the operator enables it, and a breaker that holds a pass which would remove more than half of a person's company keys, or of all people's. It runs when the keyring changes, when the directory changes the person, when the webhook arrives, and in a full pass at least once a day.
- **An unreadable keyring never removes anything.** A package that is missing, whose signature does not verify, or that is older than its time to live is unreadable, not empty. The pass adds nothing from it, removes nothing because of it, and reports it ([0026](/decisions/0026-reconcilers/#the-desired-state)).

### Audit

Each adapter audits what it does ([0025](/decisions/0025-integrations/#splitting-by-credential)); the action names live in code ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-action-table-is-code-and-the-release-identifies-it)). Records of this job:

- **A pass:** the person's pseudonym, the digest and sequence of the keyring, counts, and the mode (dry run or apply).
- **Each add, update and remove:** the fingerprint, the GitHub key id, and the outcome (`done`, `held`, `refused` or `failed`) with a reason from the closed list of [0025](/decisions/0025-integrations/#what-an-integration-may-return). A fingerprint is public and may be written.
- **The life of the authorisation:** granted, pinned, refreshed, lapsed, revoked, deleted, and a keyring that was refused and why.
- **Never recorded:** a token, a client secret, or the armoured key text.

### Revoked authorisation and leavers

- **Revocation is detected two ways.** The `github_app_authorization` event reaches `entry`, which routes it to `adapter-github` ([0025](/decisions/0025-integrations/#push-then-pull)). A pass that gets `401` or a refused refresh finds it too, which is the backstop when the event is lost. Either marks the item `revoked`, deletes both tokens, writes an audit record, raises a notice on the person's console page ("authorise the key App again") and an alert to the operator.
- **A revoked authorisation leaves the keys where they are.** sluis can no longer reach the account, so nothing is removed and nothing is added. The operator is told which fingerprints are on an account that sluis cannot manage.
- **A leaver's keys are removed while the authorisation lasts.** When the keyring no longer holds a person (ritueel drops the key at leaving) or the directory marks the person `left`, the next pass removes the person's company keys, then audits the outcome, then revokes the grant at GitHub (`DELETE /applications/{client_id}/grant`) and deletes the tokens. The item is not erased with the person until that outcome is audited or erasure reaches it.
- **A leaver whose authorisation is gone is covered by the rest of G5 A.** The operator removes the person from the organisation, ritueel drops the key from the staff keyring, sluis stops certifying and the certification lapses. The CI check below is what then refuses a commit signed with the dropped key.
- **Nothing is revoked at GitHub for a leaver, and old commits stay Verified.** A key is revoked only on a compromise, in ritueel, and then it leaves the keyring and this job removes it.

### Why Verified is not company enforcement

GitHub's Verified badge says that a signature verifies against some key on the author's account and that the address is verified. It says nothing about who issued the key, whether it lives on a card, or whether the person still works here. Anyone can add any key to their own account, and GH1 A leaves personal keys in place on purpose, so a personal key still produces Verified commits. GitHub also keeps the result for ever. Syncing company keys makes the company's keys reliable; it does not stop other keys.

Enforcement is the later check of G3 C. A required status check reads the signing key of each commit in a pull request and compares its fingerprint with the verified staff keyring: a commit signed by a key outside the keyring fails the check. It reads the same signed keyring that this job reads, and it has to allow the keys GitHub itself uses to sign merges. It is not built or specified here. Until it exists, "cards only" is written policy, and no ruleset requires signed commits for this reason.

### Vigilant mode

Vigilant mode is a per-user setting that marks unsigned commits Unverified. Only the person can switch it on, and sluis can neither set it nor read it. It is a step of joining that the person confirms, with the settings path in the instructions. Nothing in the sync depends on it.

## Consequences

- A staff member's signing key arrives on their account without a manual upload, follows each yearly renewal, and leaves with them. The most common failure, a key that went stale unnoticed, becomes an alert.
- sluis holds, for each person, a credential that reaches a personal account. It is sealed, opened per call and limited to GPG keys, but the write permission is the sharp part: whoever held a person's tokens could add a key of their own and sign commits as that person. The adapter therefore uploads only a certificate from a verified, current keyring, with a code path that takes no other input, calls only `api.github.com`, and audits every add. The later CI check is the control that catches what is left.
- The App is public, so anyone can authorise it. It holds nothing for a person the directory does not know, and an authorisation from an unknown account is deleted.
- A person who revokes the authorisation, or whose account sluis cannot reach, is not managed. The cost is an alert and a manual step, not a hidden gap.
- The sync depends on ritueel's staff keyring and on its format. That contract is ritueel's to write, and the sluis side passes its test vectors when they exist.
- Requirements: [REQ-OPS-099](/requirements/ops/#REQ-OPS-099) to [REQ-OPS-107](/requirements/ops/#REQ-OPS-107) for the sync, [REQ-SUPPLY-040](/requirements/supply/#REQ-SUPPLY-040) for the two-part verification of a release (G8 A) and [REQ-SUPPLY-041](/requirements/supply/#REQ-SUPPLY-041) for the workflow lint (C3 A). Pages: [GitHub](/integrations/github/) and [Release signing](/distribution/release-signing/), changed with this record.
- Not decided here and tracked as follow-ups: the form of the staff keyring document, the CI check, the measurements below, and an App for Enterprise Managed Users.

## Roads not taken

- **The account holds exactly the company keys (GH1 B).** It would delete a person's personal signing keys from their personal account, which is not the company's to do, and would break their personal projects.
- **No App; people upload by hand (GH1 C).** It is the state today: keys go stale at every renewal and a leaver's key stays until someone remembers it.
- **Enterprise Managed Users now (GH2 B).** It changes the ownership of every staff account and its reach on other repositories, which is a larger move than this sync and can come later without changing this design.
- **ritueel owns the App (GH3 B).** ritueel is a command-line tool that runs when a person is present and holds nothing online ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/)), while the sync needs a service that refreshes tokens and reacts to events.
- **A personal access token that the person gives sluis.** It is long-lived, not bound to one permission of this App, and expires when the person forgets it; the App's token is narrow and expires in eight hours.
- **Ask the person to authorise again every eight hours.** It removes the stored refresh token and also the automation.
- **A GitHub organisation call that adds a key to a member's account.** The key calls I read act on the authenticated user only, so no organisation-level path exists to use.
- **Sync from a list kept in sluis.** It would copy ritueel's keyring and drift from it; ritueel owns the keys, and sluis reads its signed package.
- **Make the sync a reconciler of 0026.** A reconciler manages membership only, and widening it for keys would blur the one rule that makes its safety rules simple.

## Follow-ups

- Build the key App, the kind `GitHubKeyAuthorization`, the sync and the audit records: [REQ-OPS-099](/requirements/ops/#REQ-OPS-099) to [REQ-OPS-107](/requirements/ops/#REQ-OPS-107) ([#874](https://github.com/truvity/sluis/issues/874)).
- Measure against GitHub before the build, dated: whether a second upload of a held primary is accepted; what a key with an address the account has not verified shows; the answer of a revoked token, of a refresh with a revoked grant, and of the refresh token on its sixth month; the name of the permission in the manifest; rate limits for a full pass of the staff ([#874](https://github.com/truvity/sluis/issues/874)).
- Write the format of the signed staff keyring and its list of withdrawn keys as an addition to ritueel's hand-off contract, with test vectors. This is a ritueel issue to be opened by the maintainer.
- The CI check of G3 C: a required status check of commit signers against the staff keyring. Its home and its design are a record of their own when it is built; this one only names it.
- Enterprise Managed Users as a later step of GH2 A: a record of its own when the company moves its accounts.
