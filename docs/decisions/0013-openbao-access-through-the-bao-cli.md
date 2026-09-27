# 0013 — OpenBAO access through the `bao` CLI

**Status:** Accepted; refines [0002](0002-mission-boundary-tokens-and-memberships.md), amends [0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md)
**Date:** 2026-09-27

## Context

`accessctl credential ssh|db|client` each reimplement one slice of what
the `bao` CLI already does: log in, then make the one call a role
allows. That slice grows every time OpenBAO grows — a new secrets
engine, a flag `sign` learns, a bug fixed upstream that this repository
would otherwise have to notice and port. [0002](0002-mission-boundary-tokens-and-memberships.md)
already drew this line for reading a secret store's own data (`accessctl
secrets`, removed in v1.30.0: "a courier command for it here duplicated a
client the store itself should ship"); it did not yet draw it for
*minting* a credential, and `accessctl credential` is exactly that
courier, kept a second time.

A second pressure points the same way. `docs/connect/postgresql.md` and
`docs/connect/ssh.md` each carry their own copy of the login-then-sign
sentence, because each courier repeats it. A caller who wants something
`bao` already supports — `bao ssh -mode=ca` for the interactive session
`ssh` itself drives, `bao kv get -field=...` for a single value, an
engine this repository has never heard of — has no path through this
tool at all today.

**One gap upstream, not a design gap here:** `-format=env` does not exist
on `bao kv get`. Every consumer of a secret as a set of environment
variables — Docker Compose's `env_file`, `just`'s `dotenv-load`, a
Node process reading `.env` — wants exactly that shape, and today
getting it means a caller's own `jq` pipeline reimplementing dotenv
quoting, once per repository, less carefully each time.

## Decision

**`accessctl bao <args…>` authenticates, then runs the real `bao`
binary with the arguments unchanged.** It logs in to OpenBAO's JWT mount
exactly as `accessctl credential` and `accessctl token --audience
openbao` already do — the sign-in (or the job's own token) exchanged for
`openbao`, then `auth/jwt-roster/login` — and hands the resulting token
to `bao` as `BAO_TOKEN`, in the child process's environment alone.
Everything after `accessctl bao` is OpenBAO's own syntax: its
subcommands, its flags, its bugs and its fixes stay upstream, and a
release of this tool never has to catch up with a release of that one.

The login targets the **namespace the caller is about to operate in**,
never a fixed one. OpenBAO's own contract
([truvity/openbao's `docs/integrations/access-roster.md`](https://github.com/truvity/openbao/blob/master/docs/integrations/access-roster.md),
"Root and every environment namespace get the same two auth mounts... the
namespace a person logs in to is the environment's name") gives every
namespace its own `jwt-roster` door, and a token minted in one namespace
is only good in that namespace and its children — never a sibling. So
`accessctl bao` reads `bao`'s own `-namespace` flag — or its documented
shortcut `-ns` (`bao kv get -h`: "`-ns` can be used as shortcut"), or
`BAO_NAMESPACE`, then `VAULT_NAMESPACE` — out of what it is about to
run, in that order, and logs in there. Both spellings of the flag are
ONE setting: whichever was typed last wins, regardless of which of the
two it was, the same as `bao` itself applies. **`bao`'s own flags,
including `-namespace`/`-ns`, go *after* the subcommand**
(`bao kv get -ns=dev secret/foo`, which `bao` accepts as readily as
before it) — `accessctl`'s own flags (`--address`, `--ca-cert`,
`--issuer`, `--client`, `--audience`, `--mount`, `--login-role`) go
*before* the subcommand, and the first argument that is not one of
those ends accessctl's own parsing. That is the whole separation rule:
nothing here parses `bao`'s syntax beyond finding that one flag under
its two spellings.

**The token is cached**, under this tool's own config directory, `0600`,
one file per OpenBAO address, namespace and subject — never
`~/.vault-token` and never `bao`'s own token-helper file, so a login
minted for one exchanged identity is never picked up by `bao`'s own
tooling running as somebody else. `accessctl bao --forget` revokes it and
removes the cache entry.

**`-format=env` on `kv get` is the one exception**, and it is a stop-gap:
`accessctl bao kv get ... -format=env` runs the real `bao` in JSON, and
renders the dotenv itself, ONLY when the installed `bao` does not
already answer `-format=env` on its own — checked once, cheaply, against
that binary's own `-format` help. The day an installed `bao` supports it
natively, this stops intercepting, because a wrapper that keeps
"fixing" a gap upstream has already closed is a second, competing
answer to the same question. This repository proposes the feature
upstream under the same rule 0002 already states for everything else:
OpenBAO's data plane is OpenBAO's to own.

**SSH**, unchanged in shape from what
[0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md) already
decided for machines, now runs through the passthrough rather than a
dedicated subcommand: `accessctl bao ssh -mode=ca …` for the interactive
session `ssh` itself drives (agent handling, host key checking and all,
exactly as `ssh` behaves when pointed at any other CA-issued
certificate), or `accessctl bao write -field=signed_key
<mount>/sign/<role> public_key=@key.pub > key-cert.pub` for scp, git, CI
and Ansible, which want the certificate as a file rather than a live
session. OpenBAO's host certificates, and people on opkssh, are
unaffected; opkssh remains the long-term target for people, still
blocked on ES384 verification support upstream.

**Postgres** moves to `accessctl psql` / `accessctl pg --` (a second PR,
following this one): the same authentication, then a Postgres client
certificate, handed to `psql` or an arbitrary command through libpq's own
environment variables rather than a `pg_service` entry this tool used to
write.

**Removed within 1.x** ([0007](0007-breaking-changes-inside-1x.md)):
`accessctl credential ssh|db|client`. Each becomes a refusal naming its
replacement, the same shape [0002](0002-mission-boundary-tokens-and-memberships.md)
already used for `accessctl secrets`.

## Consequences

**accessctl stops growing with OpenBAO.** A new secrets engine, a new
flag on `sign`, a fix to how `kv get` renders a value: all of it is
`bao`'s to ship, and a caller has it the day they upgrade `bao`, not the
day this repository catches up.

**One dependency this tool now has an opinion about: `bao` must be on
`PATH`.** Where `accessctl credential` needed nothing but this binary,
`accessctl bao` needs the real one installed beside it, and says so
plainly when it is missing.

**The interception is temporary by design, and says so.** An
installation that pins an old `bao` keeps the stop-gap for as long as it
runs that version; the day it upgrades past upstream support, the
behaviour is identical from the caller's side and the code path is
simply not exercised any more.

**A caller who wants `bao`'s own global flags must place them after the
subcommand.** This is not new: `bao` has always accepted them there. What
changes is that placing one *before* the subcommand no longer works
through `accessctl bao`, because that position is reserved for
accessctl's own flags. `docs/connect/openbao.md` says so where a caller
would look.

## Alternatives considered

**Keep growing `accessctl credential` per kind**, adding `accessctl
credential kv` or similar as new needs arrive. Rejected: this is the
exact shape [0002](0002-mission-boundary-tokens-and-memberships.md)
already rejected for reading data, now arriving again for everything
else `bao` can do. Every new kind is this repository re-implementing a
client for somebody else's data plane.

**Parse and forward every `bao` flag explicitly**, so `accessctl bao`'s
own `--help` could describe the whole surface. Rejected: that is
reimplementing `bao`'s CLI grammar one flag at a time, which is
precisely the maintenance burden this decision exists to end. Finding
one flag (`-namespace`, under either of its two spellings) to route the
login correctly is a narrow, justified exception; parsing all of them
is the feature this ADR refuses to grow back.

**Ship the dotenv conversion as a permanent feature**, since some
installations will run an old `bao` for a long time. Rejected: permanent
scope creep for a gap that is upstream's to close, and the detection
already makes an old `bao` cost nothing extra to a caller who stays
current — the stop-gap is free to keep and costs this repository nothing
once it stops being exercised.
