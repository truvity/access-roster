# 0011 — SSH: people on opkssh, machines and hosts on the secret store's OpenBAO

**Status:** Accepted
**Date:** 2026-09-26

## Context

[0004](0004-ssh-opkssh-and-the-secret-stores-ca.md) decided people would
move to opkssh — an OpenID Connect ID token verified straight into
`sshd`, no broker in between — once opkssh could verify this
installation's tokens, and that `accessctl credential ssh` would be
**removed** "once opkssh is adopted", because a courier in front of a
certificate authority stops earning its keep once the direct path
exists. The blocker it recorded was concrete: opkssh's verifier accepts
RS256, PS256, ES256 and EdDSA ID tokens and refuses ES384, this
installation's default; the only way around it under 0004 was to move
the *whole* installation's default key off ES384, which 0004 declined to
ask of every other relying party for one relying party's benefit.

[0009](0009-a-default-signing-algorithm-and-per-audience-exceptions.md)
(shipped v1.31.0) removes exactly that constraint: the issuer now signs
several algorithms at once, one key ring per algorithm, chosen per token
by the audience it is minted for. A client row can pin `signing_alg:
RS256` or `ES256` while every other audience keeps signing ES384. opkssh
can be adopted for people now, without moving the installation's default.

What 0004 did not separate is **who** was moving to opkssh. It says
"people authenticate with opkssh" in its Decision, but writes the removal
of `accessctl credential ssh` as though nothing else used it. Something
else does: `accessctl credential ssh` is also how a CI job or a
controller — a machine, holding a GitHub Actions OIDC token or a
Kubernetes ServiceAccount token, never a person at a browser — gets a
short-lived certificate today
([connect/openbao.md](../connect/openbao.md)). opkssh's login is shaped
for an interactive OIDC sign-in, or, as of a recent opkssh release, for
GitHub Actions' own OIDC token specifically (`opkssh login github`). It
has no equivalent of a Kubernetes ServiceAccount token, or of this
issuer's `service_account` policy matchers more generally — the shape a
controller running in-cluster already authenticates with everywhere else
in this estate. Removing the broker on the schedule 0004 wrote would take
that population's only path away, not replace it with a direct one.

## Decision

**People authenticate with opkssh, exactly as 0004 decided**, now that
the ES384 blocker is resolved: declare opkssh's client row with
`signing_alg: RS256` or `ES256` (never this installation's ES384
default, which opkssh cannot verify at all), write `oidc:groups:<internal
group>` policy on each server, and cut over. The mechanism is unchanged
from 0004's Decision; only the blocker under it is different.

**`accessctl credential ssh` stays — not as a courier for people, but as
the supported path for machines.** A CI job or a controller exchanges its
own identity at this issuer, logs in to OpenBAO's JWT mount with the
result, and gets a short-lived signed SSH user certificate — the same
broker [connect/openbao.md](../connect/openbao.md) already documents for
database and client certificates, with SSH as one more kind it signs.
This reverses 0004's plan to remove the subcommand "once opkssh was
adopted": opkssh's adoption for **people** does not extend to
**machines**, because opkssh's provider model has no equivalent of a
Kubernetes ServiceAccount token or of an issuer that already knows how to
turn one into internal groups by `service_account` matcher. Removing the
broker would leave that population with no path rather than a more direct
one.

**Hosts are unaffected** and continue exactly as 0004 and
[connect/openbao.md](../connect/openbao.md) already describe: a host
proves itself to OpenBAO (the AWS auth method for a cloud VM; cert auth
or AppRole for bare metal) and is issued a host certificate from the SSH
CA, renewed by an OpenBAO Agent or a timer; clients trust the CA with one
`@cert-authority` line. Nothing here changes that.

The full shape for all three — the policy rows, the file formats, the
commands — is [connect/ssh.md](../connect/ssh.md), written alongside this
record.

## Consequences

**`accessctl credential ssh`'s documentation stays live and is no longer
a stopgap.** 0004 described it as the interim path for people; it is now
the permanent, documented path for machines, and
[connect/ssh.md](../connect/ssh.md) is where that is written down rather
than left to be inferred from 0004 having not yet been acted on.

**opkssh's client row needs `signing_alg` pinned, and an installation
that forgets it is not gently caught.** A row left at the installation
default signs ES384, which opkssh cannot verify at all; the failure
surfaces as an opkssh error on the server (`unsupported signature
algorithm`), not as anything this issuer refuses at sign-in — worth
saying plainly rather than discovering at the first person's login.

**Machines keep one more hop than people**: exchange, then an OpenBAO
login, then a sign — versus opkssh's ID token verified directly. That
extra hop is not new cost introduced by this decision: a job already
takes it for a database or client certificate today, and this is the
same shape applied to one more kind, not a second design.

**A future opkssh release that added Kubernetes ServiceAccount tokens
(or an equivalent workload-identity provider) as a supported provider
would reopen this question** — this record is the reasoning to revisit,
not a permanent wall. Nothing here forecloses moving machines to opkssh
later if that gap closes; it says why it has not moved them now.

## Alternatives considered

**opkssh for machines too**, matching people exactly. Rejected for now:
GitHub Actions jobs are covered (`opkssh login github`, a provider opkssh
ships support for), but an in-cluster controller carrying a Kubernetes
ServiceAccount token is not — opkssh's policy language matches an issuer,
a subject and a claim, with no equivalent of this issuer's
`service_account` matchers (namespace, name, and which cluster's key set
signed it). Standardising every machine on opkssh today would mean either
leaving in-cluster callers with nothing, or maintaining a second,
narrower authorization surface for them on every host — the reason this
decision keeps one broker for every machine kind rather than splitting
machines further by how each happens to authenticate.

**Teleport** (or a similar access-plane product), as 0004 already
weighed and this decision does not revisit differently: a second
identity plane end to end — its own agents, its own certificate
authority, its own session model — where the machine path here needs
only the issuer and the secret store this estate already runs.

**Tailscale SSH**, likewise unchanged from 0004's answer: it ties SSH
authorization to tailnet membership, a second policy surface for the
same decision this issuer's `groups` already makes, and remains worth
revisiting only for an installation whose hosts already live on a
tailnet.
