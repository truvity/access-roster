# 0016 — A managed known_hosts file for SSH host CAs, distinct from `accessctl bao`

**Status:** Accepted; refines [0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md), distinguishes from [0013](0013-openbao-access-through-the-bao-cli.md)
**Date:** 2026-09-28

## Context

[0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md) put host
certificates on the secret store's own SSH CA, and
[docs/connect/ssh.md](../connect/ssh.md#hosts-host-certificates-from-openbaos-ssh-ca)
already documents the manual side of trusting it: fetch the CA's public
key (`bao read ssh/config/ca`, or read it off any certificate with
`ssh-keygen -L`), then add one `@cert-authority <pattern> <key>` line to
`known_hosts`, by hand, once per environment, on every laptop. That chore
repeats on every laptop an operator uses, and again on every CA rotation,
and gets no easier for being small: forgetting it is not a failure, it is
`ssh`'s ordinary unknown-host prompt, which reads as "nothing is
configured" rather than "one line was never added."

[0013](0013-openbao-access-through-the-bao-cli.md) drew a hard line
against growing `accessctl` with OpenBAO's own data plane: every new
secrets engine, every new flag on `sign`, is `bao`'s own surface to keep
current, not a courier this repository re-implements one call at a time.
A command that trusts an SSH CA looks, at a glance, like exactly that
kind of courier — it is one more thing OpenBAO's SSH secrets engine
answers.

## Decision

**`accessctl ssh known-hosts` is a laptop-configuration command, not an
OpenBAO client**, and that is why it does not fall under 0013's line.
0013 refuses to reimplement OpenBAO's *growing* data plane — `kv`,
`sign`, `write`, and whatever engine comes next — one recipe at a time.
This command touches none of that surface: it reads exactly one
permanently-unauthenticated, permanently-unchanging endpoint (an SSH
secrets engine's `public_key`, the same one `bao read ssh/config/ca`
already reads) that carries no secret and decides no authorization, and
OpenBAO is only one of two sources it accepts — a plain `url:` does the
identical job for an installation that fronts its CA another way. What
this command grows with is nothing upstream; what it owns is a file on
this laptop, the same category of thing `kubeconfig` and `aws-config`
(`cmd/accessctl/config_writers.go`) already own.

**Input is entirely a config list this binary never gives a name to.**
An entry pairs one or more `ssh_config`-style host patterns with a CA
source — `url:` or `openbao: {namespace, mount}`, read the same way
`accessctl bao` already resolves its own address ([0013](0013-openbao-access-through-the-bao-cli.md)):
`--address`, then `$BAO_ADDR`, then `$VAULT_ADDR`. The list lives in
`config.yaml`'s own `sshKnownHosts:` section, or
`$ACCESSCTL_SSH_KNOWN_HOSTS` when the file names none — the same
"file, then one environment variable" shape every other setting in this
tool already uses for a single value, applied here to a list. No estate
name, domain or namespace is ever declared in this binary.

**It owns exactly one file, and only that one**:
`~/.ssh/known_hosts.d/accessctl` by default (`--file` names another),
fully rewritten on every run — never `~/.ssh/known_hosts`, and never
`~/.ssh/config`. It checks whether `~/.ssh/config` already points a
`UserKnownHostsFile` line at that file (a plain substring check, tilde
form or absolute, whichever a person wrote) and prints the one line to
add when it does not; it never edits that file itself, for the same
reason `kubeconfig` writes through `kubectl config` rather than
rewriting a kubeconfig wholesale — it is the person's own file, with
entries this tool knows nothing about.

**A fetch failure for one entry never drops that entry's trust, and
never fails the whole run.** The previous run's line for that exact set
of patterns is kept, with a warning, when there is one to keep; the
entry is skipped, with a warning, when there is not. One environment's
CA being briefly unreachable must not blank out every other environment
already trusted, and must not be indistinguishable from "this CA is no
longer trusted" — silently dropping a line would be exactly that.

**Only `ssh-ed25519` CA keys are ever written.** OpenBAO's own SSH
secrets engine defaults new CAs to `ssh-ed25519`, every host certificate
this design targets is signed by one, and refusing anything else by name
is what keeps a misconfigured entry (the wrong mount, a stray answer from
a different service entirely) from writing a `@cert-authority` line for
a key type nothing here can reason about.

**`accessctl login` refreshes this file automatically** when
`sshKnownHosts` (file or environment) names at least one entry — the
same shape `setup` already gives `kubeconfig` and `aws-config`, run once
by hand after signing in. Its failure is a warning, never a login
failure: a stale, or still-absent, trust file is nothing like a failed
sign-in, and most installations name nothing here at all.

## Consequences

**A laptop trusts a fleet's SSH host CAs the moment it signs in, with no
separate step to remember**, and stays current on every later `login`
without anyone re-running a fetch-and-paste by hand.

**Nothing here grows with OpenBAO.** The `openbao:` source is one fixed
call this design does not expect to ever need a second flag for; a
`url:` entry needs no OpenBAO awareness in the caller's own installation
at all.

**The honest boundary:** this command decides nothing about
*authorization* — it fetches a public key that, by construction, proves
nothing on its own; the CA's own signing role, and who may ask it to
sign a host certificate, stay exactly where
[docs/connect/ssh.md](../connect/ssh.md#hosts-host-certificates-from-openbaos-ssh-ca)
already puts them, with the secret store's own owners. A `url:` entry
handed something other than an OpenSSH public key, or a key whose own
integrity depends on the URL's own TLS trust, gets exactly the trust that
connection deserves — the same as the manual `curl` recipe it replaces,
no more and no less.

## Alternatives considered

**A docs recipe only** (the manual `bao read` / `ssh-keygen -L` steps
[docs/connect/ssh.md](../connect/ssh.md) already has), matching 0013's
general preference for documentation over a new command. Rejected:
unlike a single `bao kv get`, trusting a CA safely needs a FILE this
tool owns outright (never a blind append to `known_hosts` itself, which
is the person's own), a fallback rule so one flaky environment does not
erase every other, and a hook into `login` so it is current the moment
someone signs in. That is exactly what already turned `kubeconfig` and
`aws-config` from a recipe into a first-class command, and a shell
one-liner does not keep that behaviour without reimplementing it worse,
by hand, on every laptop.

**Grow `accessctl bao` itself**, e.g. `accessctl bao ssh -mode=trust`,
reusing the passthrough 0013 already built. Rejected: the whole point of
that passthrough is that everything after `accessctl bao` is `bao`'s own
syntax, unchanged; teaching it to also rewrite a `known_hosts` file
conflates *authenticate, then run `bao`* with *laptop configuration*, and
would only ever work for an `openbao:` source, never a plain `url:` one.
