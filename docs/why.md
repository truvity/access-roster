# Why access-roster exists

## The problem

An installation with more than one corporate directory — two companies,
each with its own Google Workspace, Entra next — needs to answer the same
questions everywhere its people and its machines reach infrastructure:

- **Is this account still live?** A leaver must lose access without
  anyone remembering to click.
- **Which groups is this person in?** Roles on clusters, in the CD
  system, on the code host and in cloud accounts all derive from them.
- **What may this machine do?** A CI job must get exactly the cloud role
  or cluster it is entitled to, from a signed proof and no stored secret.

And it needs to answer them **without running a user store**: the people
already exist in the corporate directories, and their passwords, MFA and
device policy already live there.

## What people build instead

The usual answer is an identity provider run only for infrastructure: it
federates to the corporate IdPs and issues tokens the infrastructure
trusts. It works, and it drags three prosthetics behind it:

1. **a directory reader per tenant**, because the provider federates
   sign-in but does not read groups — one process per Workspace, a
   service-account key in each;
2. **a login hook**, because roles must be computed from those groups at
   login and written into the token;
3. **a machine-token broker**, because the provider cannot consume a CI
   platform's identity token.

Plus a database, an operator, a login UI whose upgrades break, and a user
model nobody uses because the users are minted as code. Eighty percent of
an IdP's weight for twenty percent of its function.

## The shape here

Two services and their batteries, under one rule: **nothing here
authenticates anyone.** Sign-in is always the corporate identity
provider's. These services verify the result, know the directory, and
apply rules.

- **directory-roster** holds every directory credential so that nobody
  else does, keeps a fresh snapshot of every tenant, and answers the two
  questions with an **authoritative** flag that says when an answer may be
  acted on. Consumers remove access only on authoritative answers;
  everything that can go wrong degrades to "hold", never to "gone".
- **access-issuer** verifies proofs — a corporate sign-in, a CI job's
  token, a workload's ServiceAccount — asks the hub, applies **one rules
  file**, and issues the tokens clusters, cloud accounts and consoles
  trust. No users, no passwords, no database.
- Around them, the parts every installation otherwise hand-rolls: the
  proxy in front of a console, the libraries an application uses to know
  who is calling, the CLI a person uses for cloud credentials, the action
  a workflow uses for the same, and the guides for wiring each kind of
  relying party.

## Principles

- **Verify, never authenticate.** The day a requirement needs a password,
  a user record, MFA or a consent screen, the answer is an identity
  provider, not a feature here.
- **Authoritative or hold.** A failed probe, a stale snapshot, a domain
  claimed twice, an unreachable cache: all read as "not authoritative",
  and a consumer that removes access waits.
- **Sync where you can, claim where you must.** GitHub teams are
  synchronised from groups; clusters and cloud accounts need the decision
  in the token. Both draw from the same hub and the same rules.
- **One rules file.** Who gets which groups and which audiences is
  written once, versioned, tested. No role is minted anywhere else.
- **Conventions over registration.** A console registers itself, an
  exposure derives its client from its hostname, a cluster's audience
  follows its name. Adding a relying party is one edit, in one place.
- **Generic in the repository, specific in the deployment.** Nothing here
  names a company. The installation's tenants, hosts and accounts live in
  its own configuration.

## What it is not

Not a customer-facing identity provider: a product that lets its
customers' employees sign in with their own IdP needs an IdP with
per-organisation federation, and this repository's Connect package is only
the directory half of that experience. Not a service mesh: workloads keep
their platform identities. Not a secrets manager: it holds the few
credentials it must, in Kubernetes Secrets, and nothing else.
