# 0049 — Credential minters mint only for declared targets whose entitlement sluis governs, and never where the vendor can trust sluis directly

**Status:** Superseded by 0025
**Date:** 2026-11-03

Proposal: [issue #1011](https://github.com/truvity/sluis/issues/1011).

## Context

A `CredentialMinter` returns a short-lived downstream credential for a scope that core authorised ([0025](/decisions/0025-integrations/#how-core-authorises-an-effect)): a GitHub installation token, a Cloudflare API token or R2 access key. The contract, the sealed grant and the closed list of refusal reasons are decided there. The question this record answers is for which targets a minter may exist at all. v1 minted for each vendor it integrated (parity rows [#811](https://github.com/truvity/sluis/issues/811), [#816](https://github.com/truvity/sluis/issues/816), [#817](https://github.com/truvity/sluis/issues/817) and [#819](https://github.com/truvity/sluis/issues/819)), and every minter's own credential is the sharpest one in its integration ([Cloudflare](/integrations/cloudflare/)).

The forces are that a minter is a place where sluis holds standing power at a vendor, so each one needs a reason (principle 8); that the only entitlement sluis can state with confidence is one it derives from its own groups and proofs (principle 4); and that a vendor that can trust sluis as an identity provider needs no minter at all.

## Decision

- **A minter serves a declared target.** A target is one vendor tenant that the install file declares, with its own integration process (`<vendor>-<capability>@<tenant>`, [0025](/decisions/0025-integrations/#splitting-by-credential)) and a reviewed catalogue of what may be minted: an App, a prototype token, a role. A request for a target or a catalogue entry that is not declared is refused with `NOT_FOUND`.
- **Sluis governs the membership that entitles a caller to mint.** Who may obtain a credential for a target is decided only by `policy`, from the internal groups it derives from directory facts and verified proofs ([0019](/decisions/0019-person-and-upstream-link/), [0020](/decisions/0020-grant-vocabulary-and-token-claims/)). The grant `policy` seals names the group, the catalogue entry and the scope, and the minter opens only that. A target whose entitlement is held outside sluis, such as a personal token that a person supplies or a credential sluis would have to read from a caller, is not a target: the request is refused with `UNSUPPORTED`.
- **A minter never passes on, stores or widens another party's credential.** It mints from its own catalogue entry; what it returns is never wider than the one grant, never longer than the least of the grant, the policy cap and the vendor's maximum, and never recorded ([0025](/decisions/0025-integrations/#how-core-authorises-an-effect)). It stores a minted credential only in a declared `stored` mode, sealed, with a rotation, a sweep of expired ones and a drift report against the vendor's own list.
- **No minter where the vendor can federate.** AWS roles and Kubernetes API servers trust sluis as an OpenID Connect issuer and take its tokens ([0017](/decisions/0017-identity-and-sign-in/)); sluis does not mint an AWS key or a service-account token for them. A minter exists only for a vendor that cannot accept an external issuer for the purpose.
- **The minting credential has a floor in code.** Each minter refuses a catalogue entry that grants administration of tokens, billing, account settings, memberships or identity providers at its vendor. Configuration can add names to the refusal list and cannot remove any. The per-vendor lists are on the integration pages and are not repeated here.
- **Per-vendor behaviour stays on the integration pages.** What a vendor needs, what its limits are and how a mint is requested are described there and tested against a fake vendor; this record fixes only when a minter may exist and what it may return.

## Consequences

- A minter is added with a reason that can be read off the install file: a declared target, a catalogue, a group that policy binds. Reviewers see in one place what the credential can do.
- A user who wants a token for something sluis does not govern gets a refusal, not a surprise. The cost is that a vendor with no federation and no declarable catalogue cannot be served until it has both.
- The AWS and Kubernetes rows of the parity list are relying-party recipes, not minters, and are tested as such.
- Requirements: REQ-EXCH-013 to REQ-EXCH-015 are added.

## Roads not taken

- **Mint for any target a caller names.** It makes sluis a proxy for credentials it cannot govern, and an undeclared target has no catalogue to bound the grant.
- **Accept a caller's own credential and exchange it.** sluis would hold or forward someone else's standing power, which is the secrets-engine role it has declined ([0009](/decisions/0009-export/)).
- **A minter for AWS and Kubernetes as well, for uniformity.** Both accept sluis as an issuer, so a minter would add a standing credential for nothing.
- **Leave the floor to configuration.** The sharpest credential in the integration would then depend on the care of each installation.
- **Mint without a catalogue, from the minter's own full rights.** The grant could then not be narrower than the vendor account itself.

## Follow-ups

- The first minters: GitHub installation tokens [#811](https://github.com/truvity/sluis/issues/811), Cloudflare API tokens [#816](https://github.com/truvity/sluis/issues/816) and R2 credentials [#817](https://github.com/truvity/sluis/issues/817).
