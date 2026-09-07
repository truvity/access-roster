# Why access-roster exists

## The situation it starts from

An installation already has, or can have for free:

- **corporate directories** — Google Workspace for each company, Entra
  next — where every employee already exists, with a password, MFA and
  device policy;
- **a CI platform** — GitHub Actions — that gives every job a signed,
  short-lived identity token;
- **infrastructure that speaks OIDC** — Kubernetes API servers, AWS
  accounts, ArgoCD, Kargo, any console behind a gateway;
- **a gateway** — Envoy Gateway — and a **sync loop** for GitHub teams.

What it does not have is the connective tissue: something that turns
"Alice is in group platform-admins in the truvity.com Workspace" into
"Alice may assume role power in account 1111, is cluster-admin on kernel,
and is an operator in the roster console", and turns "this is job 4711 of
example-org/gitops on master" into "this job may deploy to devel", with
one place to read the policy and no stored secret anywhere.

## The problems, concretely

1. **Groups are not in anyone's token.** Google's ID token carries no
   groups. Entra's does, with an overage limit, and only for Entra. Every
   relying party that authorizes by group needs someone to read the
   directory.
2. **Leavers must lose access without a click.** A suspended account keeps
   any session and any team membership it already has unless something
   notices. That something must know whether its answer can be trusted,
   or it will remove access on a hiccup.
3. **Several directories, one policy.** Two companies, two Workspaces,
   later a third tenant; the mapping to infrastructure roles must live in
   one file, not in each Workspace's admin console and each cluster's
   RBAC.
4. **AWS without Identity Center.** A trust policy for a custom issuer
   can see only `sub`, `aud`, `amr` and `email`. Group-based cloud roles
   across several organisations need an issuer that gates *audiences* by
   policy. No corporate IdP does that.
5. **One issuer per cluster.** An EKS cluster trusts one external OIDC
   issuer. People and CI jobs must both arrive through it, so a GitHub
   token has to be exchanged somewhere.
6. **Machines with no secrets.** CI must obtain cloud and cluster
   credentials from its platform's token alone, under policy, and that
   policy should be the same file as the human one.
7. **Consoles without login code.** Every internal UI needs login,
   session, sign-out and a bearer to read. None of them should implement
   any of it.

## Why not just…

| Tool | What it gives | Where it stops |
|---|---|---|
| **Google Workspace as the issuer** | one issuer for both Workspaces, sign-in, MFA | no groups in the token; no audience gating for AWS; cannot exchange a CI token; no second backend (Entra) behind the same issuer; nothing reads the directory for leavers |
| **Dex** | a stateless federating issuer, device flow, Kubernetes-friendly | no hook to look up groups, fixed claims, opaque subject, ungated audiences, token exchange without policy. Every gap above stays open, and the directory reads still need a separate service |
| **Zitadel or Keycloak run for infrastructure** | federation, a login hook, machine users | needs a directory reader per tenant, a login hook to compute roles, a broker for CI tokens, a database, an operator and a login UI — the eighty percent of an IdP that costs and the twenty percent that is used |
| **AWS IAM Identity Center** | AWS roles by group, SCIM from the directory | excluded by design here; and it answers only AWS, not clusters, consoles or CI |
| **GitHub → AWS direct federation** | zero code for CI to AWS | policy sprawls into every account's trust policies keyed on subject patterns; nothing for clusters, because a cluster trusts one issuer |
| **Teleport, Boundary, an access mesh** | a full access plane with agents | its own agent model and its own identity store; SSO connectors are enterprise features; it replaces the gateway rather than sitting behind it |
| **A group-sync into every relying party** | no issuer at all | works for GitHub teams (that is github-roster), fails for AWS trust policies and for consoles with sessions |

None of these is wrong. Each solves two or three of the seven problems.
Access-roster is the smallest set of parts that solves all seven with the
things the installation already has, under one rule.

## The shape

Two services and their batteries. **Nothing here authenticates anyone**:
sign-in stays with the corporate IdPs and the CI platform; these services
verify the result, know the directory, and apply the policy.

- **directory-roster** solves 1, 2 and 3 on the directory side: it holds
  every directory credential so nobody else does, snapshots every tenant,
  and answers *live?* and *in which groups?* with an **authoritative**
  flag. A consumer removes access only on an authoritative answer.
- **access-issuer** solves 3, 4, 5 and 6: it verifies proofs — a corporate
  sign-in, a CI token, a workload token — asks the hub, applies **one
  policy**, and issues tokens whose `groups` name the roles relying
  parties already read and whose **audiences** carry the decisions a
  cloud trust policy can see.
- **access-proxy**, the **libraries**, **accessctl** and the **action**
  solve 7 and the last mile: a console gets login and session from a
  chart, an application gets the caller's identity from a middleware, a
  person gets cloud credentials from a CLI, a job from a shell action.

The full map of who talks to whom is [integrations.md](integrations.md).

## Principles

- **Verify, never authenticate.** A password, a user record, MFA or a
  consent screen is an identity provider's job, not a feature here.
- **Authoritative or hold.** A failed probe, a stale snapshot, a domain
  claimed twice, an unreachable cache: all read as "not authoritative",
  and a consumer that removes access waits.
- **Sync where you can, claim where you must.** GitHub teams are
  synchronised from groups; clusters and cloud accounts need the decision
  in the token. Both draw from the same hub and the same policy.
- **One policy.** Who is in which internal group, what each adds and which clients it may use is
  written once, versioned, tested. No role is minted anywhere else.
- **Conventions over registration.** A console registers itself, an
  exposure derives its client from its hostname, a cluster's audience
  follows its name.
- **Generic in the repository, specific in the deployment.**

## What it is not

Not a customer-facing identity provider: a product whose customers sign
in with their own IdP needs per-organisation federation, and only the
Connect package here is reusable for that. Not a service mesh: workloads
keep their platform identities. Not a secrets manager.
