# Why access-roster exists

The [README](../README.md) says what it is and where it sits among the
alternatives. This page is the longer argument: the situation it starts
from, the problems it solves, and the principles that decide every
design question after that.

## The situation it starts from

An installation already has, or can have for free:

- **corporate directories** — Google Workspace for each company, Entra
  next — where every employee already exists, with a password, MFA and
  device policy;
- **a CI platform** — GitHub Actions — that gives every job a signed,
  short-lived identity token;
- **clusters** whose API servers give every ServiceAccount the same
  kind of token, and publish the key set that verifies it;
- **infrastructure that speaks OIDC** — Kubernetes, AWS, ArgoCD, Kargo,
  any console behind a gateway.

What it does not have is the connective tissue: something that turns
"Alice is in group platform-admins in the truvity.com Workspace" into
"Alice may assume role power in account 1111, is cluster-admin on kernel,
and is an operator in the directory console", and turns "this is job
4711 of example-org/gitops on master" into "this job may deploy to
devel" — with one place to read the policy and no stored secret
anywhere.

## The problems, concretely

1. **Groups are not in anyone's token.** Google's ID token carries no
   groups. Entra's does, with an overage limit, and only for Entra.
   Every relying party that authorizes by group needs someone to read
   the directory.
2. **Leavers must lose access without a click.** A suspended account
   keeps any session it already has unless something notices. That
   something must know whether its answer can be trusted, or it will
   remove access on a hiccup.
3. **Several directories, one policy.** Two companies, two Workspaces,
   later a third tenant; the mapping to infrastructure roles must live
   in one file, not in each Workspace's admin console and each cluster's
   RBAC.
4. **AWS without Identity Center.** A trust policy for a custom issuer
   can see only `sub`, `aud`, `amr` and `email`. Group-based cloud roles
   need an issuer that gates *audiences* by policy. No corporate IdP
   does that.
5. **One issuer per cluster.** An EKS cluster trusts one external OIDC
   issuer. People and CI jobs must both arrive through it, so a GitHub
   token has to be exchanged somewhere.
6. **Machines with no secrets.** CI and workloads must obtain cloud and
   cluster credentials from the token their platform already gave them,
   under a policy that is the same file as the human one.
7. **Consoles without login code.** Every internal UI needs login,
   session, sign-out and a bearer to read. None of them should implement
   any of it.

## Why not just…

| Tool | What it gives | Where it stops |
|---|---|---|
| **Google Workspace as the issuer** | one issuer for both Workspaces, sign-in, MFA | no groups in the token; no audience gating for AWS; cannot exchange a CI token; no second directory behind the same issuer |
| **dex** | a stateless federating issuer, Kubernetes-friendly, a ConfigMap | no hook to look up groups, so Google users have none; fixed claims; no policy; no audience gating; token exchange without rules. The right shape, one step short |
| **Zitadel, Keycloak, Authentik** | federation, a login hook, machine users | a database, an operator and a login UI to run; a directory reader per tenant, a login hook to compute roles, a broker for CI tokens to write. The eighty percent of an IdP that costs and the twenty percent that is used |
| **Okta, Auth0, Entra ID** | everything, rented | policy lives in their UI and their API, not in git; machine identities are secrets to rotate; the infrastructure's identity depends on a vendor's uptime and pricing |
| **AWS IAM Identity Center** | AWS roles by group, SCIM from the directory | answers only AWS, not clusters, consoles or CI |
| **GitHub → AWS direct federation** | zero code for CI to AWS | policy sprawls into every account's trust policies keyed on subject patterns; nothing for clusters, because a cluster trusts one issuer |
| **Teleport, Boundary, an access mesh** | a full access plane with agents | its own agent model and identity store; SSO connectors are enterprise features; it replaces the gateway rather than sitting behind it |

None of these is wrong. Each solves two or three of the seven problems.
access-roster is the smallest set of parts that solves all seven with
the things the installation already has.

## Principles

These decide every design question, and when two of them conflict the
earlier one wins.

1. **Verify, never authenticate.** A password, a user record, MFA or a
   consent screen is an identity provider's job, not a feature here.
   There are no users in this system, only sessions.
2. **Configuration is chart values.** No database, no operator, no
   admin UI that writes. The policy is a file in git; the console reads
   it and never edits it. `git log` is the complete history of access.
3. **Almost nothing is a secret.** One signing key. The OAuth client
   credentials the corporate IdP issued. The refresh token a directory
   admin's consent produced. Nothing else — machines prove themselves
   with tokens their own platform issued, and the issuer holds no
   credential to verify them, only a public key set.
4. **Strict where implemented, and not one grant more.** Six grants
   cover a browser, a CLI with a browser to confirm in, and a machine
   that already holds a token. Each one that is served passes the
   conformance suite; each one that is not needed is not served, because
   every served endpoint is surface to keep truthful.
5. **One issuer, one policy, one vocabulary.** However many clusters,
   accounts and corporate directories, there is one `iss`, one file, and
   one flat `groups` claim that nothing downstream re-maps.
6. **Authoritative or hold.** A failed probe, a stale snapshot, a domain
   claimed twice: all read as "not authoritative", and nothing removes
   access on that answer.
7. **The lightest footprint for the relying party too.** ArgoCD, Kargo
   and a cluster each get a client id and an issuer URL and nothing else
   to configure. A console with no OpenID of its own gets a chart.

## What it is not

Not a customer-facing identity provider: a product whose customers sign
in with their own IdP needs per-organisation federation, and only the
directory connector here is reusable for that. Not a service mesh:
workloads keep their platform identities. Not a secrets manager. Not a
replacement for the corporate directory: it reads one, and if the
directory is wrong, so is every token.
