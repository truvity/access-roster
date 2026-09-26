# 0004 — SSH: opkssh for people, the secret store's SSH CA for hosts

**Status:** Accepted; partly superseded by [0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md)
**Date:** 2026-09-25

## Context

`accessctl credential ssh` already gets a person a short-lived
certificate from a secret store's SSH CA — a key made on the caller's
machine, signed once, handed to the agent
([design/accessctl.md#credential-the-broker-for-what-openbao-mints](../design/accessctl.md#credential-the-broker-for-what-openbao-mints),
[connect/openbao.md](../connect/openbao.md)). That is a courier in front
of a certificate authority: correct under
[0002](0002-mission-boundary-tokens-and-memberships.md), but a detour
through this repository's own binary for something OpenPubkey SSH
(**opkssh**) does directly — an OpenID Connect ID token, verified
against an issuer's key set, admitted straight into `sshd` with no
certificate authority and no broker in between.

Host identity is a different question from user identity: an SSH server
needs a key nobody rotates by hand and a client that trusts it without
asking on every connection, which is exactly what a certificate authority
is for. The two problems should not share one answer.

## Decision

**People authenticate with opkssh.** access-roster is opkssh's OIDC
issuer: a public client row declaring opkssh's loopback redirects
(`http://localhost:{3000,10001,11110}/login-callback`), and server-side
policy written as `oidc:groups:<internal group>` — the same `groups`
claim every other relying party reads, bound directly rather than through
a certificate. A server needs the `opkssh` binary installed and wired
into `sshd` via `AuthorizedKeysCommand` (with the matching
`AuthorizedKeysCommandUser`), network reach to the issuer's JWKS
endpoint, and its own expiration policy set to `24h` to match this
issuer's session bound rather than opkssh's own default; nothing else.
Session lifetime otherwise follows
[0001](0001-sessions-and-an-absolute-limit.md)'s 24-hour absolute limit,
the same as anywhere else a person's sign-in is the credential.

**Hosts keep their key signed by the secret store's SSH CA**, exactly as
[connect/openbao.md](../connect/openbao.md)'s host side already describes
— a certificate authority is still the right tool for a key that must
never be a person's problem to rotate, and clients trust it with
`@cert-authority` the way they always have.

`accessctl credential ssh` is removed once opkssh is adopted, per
[0007](0007-breaking-changes-inside-1x.md): a courier in front of a
certificate authority stops earning its keep once the direct path exists.

## The blocker, stated plainly

**opkssh cannot be adopted yet.** It verifies only RS256, PS256, ES256
and EdDSA ID tokens today, and access-issuer signs **ES384** by default
([0005](0005-es384-signing-algorithm.md)) — the one algorithm outside
that list. Adoption waits on upstream OpenPubkey support for ES384, or on
whichever alternative arrives first; `accessctl credential ssh` is not
removed, and stays the supported path for people, until one of those
lands. An installation could work around the gap today by setting
`signingKey.certificate: {algorithm: RSA, size: 2048, encoding: PKCS1}`
([reference/configuration.md](../reference/configuration.md)), but that
is a key-rotation decision made for one relying party's benefit, not a
default this repository asks for.

## Consequences

Until the blocker clears, `accessctl credential ssh` and opkssh are not
both maintained in parallel as competing paths — the certificate broker
stays the one documented way in for people, and this record is the
tracked reason the direct path is not there yet. When ES384 support
lands, the migration is: declare opkssh's client, write the
`oidc:groups:` policy on each server, cut over, then remove the broker
subcommand and its documentation, following the removal shape in
[design/access-roster.md#appendix-what-was-removed-and-why](../design/access-roster.md#appendix-what-was-removed-and-why).

## Alternatives considered

**Teleport** (or a similar access-plane product) for SSH. Rejected: it is
a second identity plane end to end — its own agents, its own certificate
authority, its own notion of a session — where opkssh needs only an
issuer this repository already runs and a claim it already mints.

**Keep the secret store's SSH CA for people too, indefinitely**, i.e. the
current state, permanently rather than as an interim. Rejected as the
long-term answer: it is one more hop (exchange, login, sign) for
something a verified ID token can do directly, and it is why this record
exists rather than leaving the courier undocumented as though it were the
destination.

**Tailscale SSH.** Gives host reachability and identity together on a
tailnet an installation already runs, but ties SSH authorization to
tailnet membership rather than to this repository's own `groups`
vocabulary — a second policy surface for the same decision opkssh makes
from the token this issuer already mints. Worth revisiting for an
installation whose hosts already live on a tailnet, but not the default
here.
