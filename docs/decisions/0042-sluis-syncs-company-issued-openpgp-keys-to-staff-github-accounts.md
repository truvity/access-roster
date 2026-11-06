# 0042 — sluis syncs company-issued OpenPGP keys to staff GitHub accounts

**Status:** Accepted
**Date:** 2026-11-06

Proposal: [issue #1488](https://github.com/truvity/sluis/issues/1488).

## Context

The company issues each staff member an OpenPGP signing key whose subkeys are born on the person's card. Each staff key is a **key binding** inside sluis, and sluis produces the **staff keyring** from its bindings: one public certificate for every person with an active binding (the bindings are decided in the staff key bindings record, which is being written (tracked in [#1488](https://github.com/truvity/sluis/issues/1488))). GitHub marks a commit Verified only when the signing key is on the author's account, and its copy of a key changes only when the key is uploaded again (to be measured, see Follow-ups): a subkey binding lasts about 13 months ([0024](/decisions/0024-root-custody-and-the-signing-api/#lifetimes-and-the-warning)), so a key uploaded by hand goes stale every year without anyone noticing, and a leaver's key stays on the account until someone remembers it.

On 2026-11-06 the maintainer decided, in these words and answers:

| Label | Decision |
|---|---|
| (the request) | "GPG and GitHub - it should be part of sluis to export GPG keyring (updated) to GitHub account (maybe using github app created by sluis)". |
| GH1 A | "the App manages only the keys the company issued. It adds and removes those fingerprints and leaves personal keys alone." |
| GH2 A | "personal GitHub accounts plus the App. Enterprise Managed Users is a possible later step." |
| GH3 A | "sluis owns the App. ritueel produces the keyring; sluis syncs it." Changed on 2026-11-06 by the decision SK1 E, "staff keys are key bindings inside sluis, and sluis itself produces the staff keyring from its bindings": **sluis owns the App, produces the keyring and syncs it.** |
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
- GitHub checks a signature at push time and keeps the result, so a later removal or revocation of a key does not change an old commit (whether expiry behaves the same was not confirmed in that source) ([persistent verification](https://github.blog/changelog/2024-12-10-persistent-commit-signature-verification-is-generally-available/), 2024-12-10).

## Decision

### The App

- **One App does one job: it syncs company-issued OpenPGP keys.** It is the **key App**, a second public App beside the link App, and a `GitHubApp` of the operator's own tenant ([GitHub](/integrations/github/#what-sluis-asks-the-vendor-for)). It is public for the reason the link App is: staff accounts are personal, and a private App can be authorised only by members of its owner. Anyone may authorise it, and it does nothing for a person whom the directory does not know ([Joining](/decisions/0042-sluis-syncs-company-issued-openpgp-keys-to-staff-github-accounts/#joining)).
- **Its only permission is the account permission "GPG keys: read and write".** It has no repository, organisation or other account permission, is installed nowhere, and keeps GitHub's expiring user tokens on. It asks for no SSH-key permission, because there is no SSH-signing fallback (G1 A).
- **sluis makes it with the manifest flow** of [Connecting](/integrations/connecting/#github-app-manifest-flow), as for every App. The manifest names the callback URL of `adapter-github` and an active webhook for one event, `github_app_authorization`, with a webhook secret that stays sealed in the `GitHubApp`. The name of the permission in the manifest is confirmed when the manifest is written.
- **`adapter-github` is the only holder.** It opens the App's client secret from its `GitHubApp` per call, as it does for the other Apps ([0025](/decisions/0025-integrations/#adapters-and-connections)), and calls `api.github.com` and nothing else for this job.

### Joining

- **Each person authorises the App once, as part of joining.** The console shows the joining steps. After the person has signed in and the directory has them as live, the step "authorise the key App" starts the web application flow: a state bound to the person's session, an S256 PKCE challenge, and a redirect to GitHub. The state lives as long as the other manifest and OAuth states (a temp kind, at most one hour).
- **The first account is pinned.** `adapter-github` exchanges the code, reads the authenticated user and stores the GitHub user id. A later authorisation from another account is refused until an operator releases the pin, so a person cannot move their company keys to an account of a colleague or of a stranger ([REQ-OPS-119](/requirements/ops/#REQ-OPS-119)).
- **The person verifies their company address on the account.** GitHub shows a signature as Verified only when the commit address is a user ID of the key and a verified address of the account. The page tells the person this; sluis cannot do it for them.

### Storing and refreshing the user token

- **The tokens are one durable item per person, sealed, personal and written by `adapter-github`,** the kind `GitHubKeyAuthorization`, added to the registry with the first build ([#1214](https://github.com/truvity/sluis/issues/1214)). It holds a version, the GitHub user id, the user token and its expiry, the refresh token and its expiry, the state (`active`, `refresh-lost`, `revoked`, `lapsed`, `left`) and the ids of the GitHub key records that sluis made. Every write to it is conditional on the version that the writer read. It is sealed under the tenant's `data` key, like every credential an adapter uses, and is erased with the person ([0004](/decisions/0004-the-data-model/)).
- **The adapter opens the item per call and keeps nothing,** as in [0025](/decisions/0025-integrations/#adapters-and-connections). The tokens are never in an audit record, a log line, a span or a console page ([0025](/decisions/0025-integrations/#how-core-authorises-an-effect)).
- **A refresh is made under the person's lease and written before it is used.** A refresh token works once, so two processes refreshing at the same time would burn the pair. The adapter takes a lease named for the person ([0026](/decisions/0026-reconcilers/#scope)), refreshes only when the user token has less than 5 minutes left, and writes the returned pair with a conditional write before the first call that uses it ([REQ-OPS-106](/requirements/ops/#REQ-OPS-106)). If the write fails, the pair is lost, because GitHub has already made the old pair useless.
- **A lost pair is a state of its own, `refresh-lost`, and a routine one.** A process that crashes, or loses its lease, between GitHub's answer to a refresh and the write loses the pair. A refresh is due about every 8 hours for each person, so this will happen. It is not a revocation: the person did nothing, and the alert says so. The adapter marks the item `refresh-lost` when a refresh was begun and its answer was never written, or when a refresh is refused after one was begun, and it raises an operator task "ask the person to authorise again" with the person's console page showing the same step ([REQ-OPS-108](/requirements/ops/#REQ-OPS-108)). Until the person does, nothing is added or removed for them.
- **A leaver in `refresh-lost` has no removal path through sluis.** The pass cannot remove their keys without a token. The operator's step is then to remove the person from the organisation, and to ask the person to remove the key or to authorise again so that the next pass can remove it. The company key stays on the account until one of the two happens. Old commits stay Verified in any case, and the later CI check refuses a new commit signed by the key, because the binding has ended and the key is no longer in the staff keyring.
- **A pass refreshes often enough that the six months never run out.** Every full pass lists the account's keys, so a pass refreshes at least once a day and each refresh starts a new six-month refresh token. The refresh token lapses only when sluis has made no pass for six months, and then the state is `lapsed`, and the person is asked to authorise again.

### The sync loop

- **The source of truth is sluis's own binding records.** A binding ties one person, one certificate and its subkeys, and it is active or ended; how a binding is made, renewed and ended is decided in the staff key bindings record, which is being written (tracked in [#1488](https://github.com/truvity/sluis/issues/1488)). The staff keyring is what `adapter-github` derives from the active bindings of the tenant, read through its data port. No keyring file is read from outside sluis, so there is nothing to sign, pin or fetch, and no format to agree with another product.
- **The desired state of a person is the certificates of their active bindings.** The binding step proved the link between the person and the certificate (the verified directory address is a user ID of the certificate, and the card attestation was checked), and the adapter relies on that proof and does not repeat it. The adapter asks core nothing, so it only executes what the binding records say; who may hold a binding is decided where bindings are made, not in the adapter ([0025](/decisions/0025-integrations/#the-rule)).
- **Two controls stand between a binding record and an account.**
  1. **The person-to-certificate link.** The adapter adds a certificate only to the pinned GitHub account of the person whose active binding holds that certificate ([REQ-OPS-113](/requirements/ops/#REQ-OPS-113)). A wrong or tampered binding of one person cannot put its certificate on the account of another.
  2. **Only active bindings, with the certification of 0024.** A certificate is added only while its binding is active, and a binding that has ended or lapsed adds nothing. When sluis certifies staff primaries ([0024](/decisions/0024-root-custody-and-the-signing-api/#company-openpgp-certification)), the adapter adds only a primary that carries that certification.

  A compromised or wrong binding record can still name a certificate for its own person. The limit is stated, and the later CI check, which reads the same bindings, does not catch it. The limits below bound the damage: at most a few keys per person, of a bounded size, a bounded number of changes in a pass, and a breaker ([REQ-OPS-114](/requirements/ops/#REQ-OPS-114)).
- **Three actions, for company fingerprints only.**

  | Action | When | How |
  |---|---|---|
  | Add | The desired certificate is not on the account | `POST /user/gpg_keys` with the armoured certificate and a name that holds the fingerprint |
  | Update | The account holds the primary, and the binding has a subkey, binding signature or expiry that GitHub's copy lacks | GitHub cannot change a key in place, so add the new copy, then delete the old record, only if its id differs from the id that the add returned |
  | Remove | The binding has ended, or the person has left | `DELETE /user/gpg_keys/{id}` |

  Whether GitHub accepts a second upload of a primary it already holds, and what it answers, is measured before the build. If it answers with the existing record, the delete would remove the only copy, so the rule is: **delete the old record only when its id differs from the id that the add returned, and list the account again afterwards** and check that the fingerprint is still there ([REQ-OPS-116](/requirements/ops/#REQ-OPS-116)). If GitHub refuses a second upload, an update is delete then add in one pass, and a commit pushed in the gap is permanently Unverified, because GitHub never re-checks.
- **A key is identified by its full fingerprint, computed from the key itself.** GitHub's key object has no fingerprint field. The adapter takes the armoured public key that GitHub returns (`raw_key`), parses it, and computes the full version 4 fingerprint of the primary. It never matches on `key_id`, on the name, or on an email of the key object, because a short key id can collide and a name is chosen by whoever uploaded the key ([REQ-OPS-115](/requirements/ops/#REQ-OPS-115)). A key that cannot be parsed is personal and is left alone.
- **A company key is a certificate that sluis added.** It is a primary whose GitHub record sluis made (the ids in the item), or a primary whose binding sluis held and has ended. Removal covers only these: a binding record that names a fingerprint sluis never added cannot make the adapter delete it, so a wrong binding cannot delete a personal key ([REQ-OPS-112](/requirements/ops/#REQ-OPS-112)). Every other key on the account is personal and is never read for any purpose but listing, never changed and never removed, even when its user ID carries a company address (GH1 A).
- **The pass is a reconciler's pass without being a reconciler.** [0026](/decisions/0026-reconcilers/#scope) limits a reconciler to membership, and this job manages keys, so it is a job of `adapter-github` of its own. It keeps the rules of 0026 that apply: one pass per person under a lease, level-triggered and idempotent, a dry run until the operator enables it ([REQ-OPS-120](/requirements/ops/#REQ-OPS-120)), and a breaker.
- **The breaker is for mass removals and never holds a leaver.** It holds a pass that would remove more than half of the company keys of all people, and a pass that would remove more than half of one person's keys when the cause is not explicit ([REQ-OPS-110](/requirements/ops/#REQ-OPS-110)). A removal for a person the directory marks `left`, and a removal of a withdrawn fingerprint under the rule above, are exempt: a leaver with one key loses that key at once, which G5 A needs ([REQ-OPS-111](/requirements/ops/#REQ-OPS-111)).
- **Limits bound one pass.** A person holds at most 4 company keys on GitHub, a certificate is at most 16 KiB, and a pass makes at most 8 changes to one account; the figures are starting values, not measurements, and are tunables of the target ([REQ-OPS-114](/requirements/ops/#REQ-OPS-114)).
- **The pass runs** when a binding changes, when the directory changes the person, when the webhook arrives, and in a full pass at least once a day.
- **An unreadable binding store never removes anything.** A binding record that cannot be read, or whose read is older than its time to live, is unreadable, not empty. The pass adds nothing from it, removes nothing because of it, and reports it ([0026](/decisions/0026-reconcilers/#the-desired-state)).

### Audit

Each adapter audits what it does ([0025](/decisions/0025-integrations/#splitting-by-credential)); the action names live in code ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-action-table-is-code-and-the-release-identifies-it)). Records of this job:

- **A pass:** the person's pseudonym, the digest of the bindings it read, counts, and the mode (dry run or apply).
- **Each add, update and remove:** the fingerprint, the GitHub key id, and the outcome (`done`, `held`, `refused` or `failed`) with a reason from the closed list of [0025](/decisions/0025-integrations/#what-an-integration-may-return). A fingerprint is public and may be written.
- **The life of the authorisation:** granted, pinned, refreshed, lost (`refresh-lost`), lapsed, revoked, left, deleted, an event that was dropped and why, and a binding that was refused and why.
- **Never recorded:** a token, a client secret, or the armoured key text.

### Revoked authorisation and leavers

- **An event is a hint, and a call confirms it.** The `github_app_authorization` event reaches `entry`, which routes it to `adapter-github` ([0025](/decisions/0025-integrations/#push-then-pull)). The adapter checks the `X-Hub-Signature-256` header against the App's webhook secret and drops a request that fails. It maps the event's `sender` to the pinned GitHub user id, and drops an event for any other account. GitHub's page lists no `action` field for this event, so the adapter does not read one ([REQ-OPS-117](/requirements/ops/#REQ-OPS-117)).
- **`revoked` is set only after a confirmation, by a conditional write.** On the event, or on a `401` or a refused refresh in a pass, the adapter takes the person's lease, reads the item, probes GitHub with the current token (after a refresh if one is due), and only if the probe fails marks the item `revoked`. The write is conditional on the version that was read. On a conflict it reads again and decides again, because another process may have written a newer pair. A process that holds an older pair never deletes the newer one: process A with a pair P1, a lapsed lease and a `401` finds P2 on its re-read and does nothing ([REQ-OPS-109](/requirements/ops/#REQ-OPS-109)). A `revoked` item has both tokens deleted, an audit record, a notice on the person's console page ("authorise the key App again") and an alert to the operator.
- **A revoked authorisation leaves the keys where they are.** sluis can no longer reach the account, so nothing is removed and nothing is added. The operator is told which fingerprints are on an account that sluis cannot manage.
- **A leaver's keys are removed while the authorisation lasts.** When the person's binding has ended or the directory marks the person `left`, the next pass removes the person's company keys, then audits the outcome, then revokes the grant at GitHub (`DELETE /applications/{client_id}/grant`) and deletes the tokens. The item moves to `left`. The event that follows from the adapter's own revocation of the grant does not make the item `revoked` and raises no alert, because the item is already `left` and the sender's grant is the one the adapter ended ([REQ-OPS-118](/requirements/ops/#REQ-OPS-118)). The item is not erased with the person until the outcome is audited or erasure reaches it.
- **A leaver whose authorisation is gone is covered by the rest of G5 A.** The operator removes the person from the organisation, the binding ends, sluis stops certifying and the certification lapses. The CI check below is what then refuses a commit signed with the ended key. A leaver whose pair was lost is the case under [Storing and refreshing](/decisions/0042-sluis-syncs-company-issued-openpgp-keys-to-staff-github-accounts/#storing-and-refreshing-the-user-token).
- **No key is revoked at GitHub for a leaver, and old commits stay Verified.** The adapter revokes the App's grant, not a key. A key is revoked only on a compromise, by the way the binding record decides, and then its binding ends and this job removes it.

### Why Verified is not company enforcement

GitHub's Verified badge says that a signature verifies against some key on the author's account and that the address is verified. It says nothing about who issued the key, whether it lives on a card, or whether the person still works here. Anyone can add any key to their own account, and GH1 A leaves personal keys in place on purpose, so a personal key still produces Verified commits. GitHub also keeps the result for ever. Syncing company keys makes the company's keys reliable; it does not stop other keys.

Enforcement is the later check of G3 C. A required status check reads the signing key of each commit in a pull request and compares its fingerprint with the staff keyring that sluis produces from its bindings: a commit signed by a key outside the keyring fails the check. It reads the same bindings that this job reads, and it has to allow the keys GitHub itself uses to sign merges. It is not built or specified here. Until it exists, "cards only" is written policy, and no ruleset requires signed commits for this reason.

### Vigilant mode

Vigilant mode is a per-user setting that marks unsigned commits Unverified. Only the person can switch it on, and sluis can neither set it nor read it. It is a step of joining that the person confirms, with the settings path in the instructions. Nothing in the sync depends on it.

## Consequences

- A staff member's signing key arrives on their account without a manual upload, follows each yearly renewal, and leaves with them. The most common failure, a key that went stale unnoticed, becomes an alert.
- sluis holds, for each person, a credential that reaches a personal account. It is sealed, opened per call and limited to GPG keys, but the write permission is the sharp part: whoever held a person's tokens could add a key of their own and sign commits as that person. The adapter therefore uploads only the certificate of an active binding of that person, with a code path that takes no other input, calls only `api.github.com`, and audits every add. The person-to-certificate link and the active-binding rule bound a wrong or compromised binding record; the later CI check reads the same bindings and does not catch it.
- The App is public, so anyone can authorise it. It holds nothing for a person the directory does not know, and an authorisation from an unknown account is deleted.
- A person who revokes the authorisation, whose pair was lost, or whose account sluis cannot reach, is not managed. The cost is an alert and a manual step, not a hidden gap. A lost pair is routine and its alert says so.
- The build does not start until the measurements under Follow-ups are done and dated; this record states the design, and a measurement that contradicts it changes the design.
- The sync depends on sluis's binding records, which are decided in the staff key bindings record, which is being written (tracked in [#1488](https://github.com/truvity/sluis/issues/1488)). The sync needs from them a person, a certificate, an active or ended state and the time of each change, and nothing else. No format is agreed with another product.
- Requirements: [REQ-OPS-099](/requirements/ops/#REQ-OPS-099) to [REQ-OPS-126](/requirements/ops/#REQ-OPS-126) for the sync, [REQ-SUPPLY-043](/requirements/supply/#REQ-SUPPLY-043) for the two-part verification of a release (G8 A) and [REQ-SUPPLY-044](/requirements/supply/#REQ-SUPPLY-044) for the workflow lint (C3 A). Pages: [GitHub](/integrations/github/) and [Release signing](/distribution/release-signing/), changed with this record.
- Later work, tracked under Follow-ups: the CI check of G3 C, the measurements before the build, and an App for Enterprise Managed Users.

## Roads not taken

- **The account holds exactly the company keys (GH1 B).** It would delete a person's personal signing keys from their personal account, which is not the company's to do, and would break their personal projects.
- **No App; people upload by hand (GH1 C).** It is the state today: keys go stale at every renewal and a leaver's key stays until someone remembers it.
- **Enterprise Managed Users now (GH2 B).** It changes the ownership of every staff account and its reach on other repositories, which is a larger move than this sync and can come later without changing this design.
- **ritueel owns the App (GH3 B).** ritueel is a command-line tool that runs when a person is present and holds nothing online ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/)), while the sync needs a service that refreshes tokens and reacts to events.
- **A personal access token that the person gives sluis.** It is long-lived, not bound to one permission of this App, and expires when the person forgets it; the App's token is narrow and expires in eight hours.
- **Ask the person to authorise again every eight hours.** It removes the stored refresh token and also the automation.
- **A GitHub organisation call that adds a key to a member's account.** The key calls I read act on the authenticated user only, so no organisation-level path exists to use.
- **Sync from a keyring file that ritueel builds and signs (GH3 A as first decided).** It adds a format, a signature, a publisher pin and a transport between two products, and a source that sluis does not hold; the owner decided on 2026-11-06 (SK1 E) that sluis produces the keyring from its own bindings, so there is nothing external to compromise.
- **Make the sync a reconciler of 0026.** A reconciler manages membership only, and widening it for keys would blur the one rule that makes its safety rules simple.

## Follow-ups

- Build the key App, the kind `GitHubKeyAuthorization`, the sync and the audit records: [REQ-OPS-099](/requirements/ops/#REQ-OPS-099) to [REQ-OPS-126](/requirements/ops/#REQ-OPS-126) ([#1214](https://github.com/truvity/sluis/issues/1214)), gated on the next item.
- Measure against GitHub before the build, dated, and gate the build on it: whether a second upload of a held primary is accepted and what it answers; the fields of the key object (`raw_key`, and that it has no fingerprint); what a key with an address the account has not verified shows; the answer of a revoked token, of a refresh with a revoked grant, and of the refresh token on its sixth month; the fields of the `github_app_authorization` event; whether expiry changes a stored verification; the name of the permission in the manifest; rate limits for a full pass of the staff ([#1214](https://github.com/truvity/sluis/issues/1214)).
- Decide the staff key bindings that this sync reads: the staff key bindings record, which is being written (tracked in [#1488](https://github.com/truvity/sluis/issues/1488)).
- The CI check of G3 C: a required status check of commit signers against the staff keyring. It is built later and is designed in its own record then; this one only names it ([#1488](https://github.com/truvity/sluis/issues/1488)).
- Enterprise Managed Users as a later step of GH2 A: designed in its own record when the company moves its accounts ([#1488](https://github.com/truvity/sluis/issues/1488)).
