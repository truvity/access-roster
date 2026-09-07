# The token service — identity for infrastructure

**Status:** designed 2026-09-07; **built after the hub**, as the second
component of access-roster. Working component name `token-service`, to be
confirmed. Nothing in the hub depends on it.

## Purpose

One issuer that every cluster, cloud account and console of an
installation trusts, fed by the corporate identity providers the
installation already has and by the workload identities its CI already
carries, with the mapping from directory groups to entitlements written
in one file. It exists so that an installation does not have to run a
full identity provider — a user store, a login UI, a database — only to
get the twenty percent of one it uses: federation with claim shaping and
workload-token exchange.

It is a **security token service**, not an identity provider. The line:

- it never proves who anyone is; it verifies proofs produced elsewhere;
- it holds no passwords, no user records, no MFA, no consent screens, no
  self-registration, no second way in;
- break-glass lives outside it, in the cloud account and the cluster's own
  access mechanisms;
- its one operator page is read-only; policy changes are commits.

The day a requirement needs one of the things on that list is the day to
stop and reconsider, not to extend.

## What it verifies

| Proof | From | How |
|---|---|---|
| a corporate sign-in | Google Workspace, Microsoft Entra | an OIDC authorization-code flow the service starts and finishes, routed by email domain; the token's address is then resolved through the hub |
| a workload token | GitHub Actions, per organisation | RFC 8693 token exchange; verified against the issuer's keys, the organisation checked against an allow-list, claims such as repository and ref fed to the rules |
| a cluster workload | a Kubernetes ServiceAccount | token exchange with TokenReview, for in-cluster services that need a token another system trusts |

Every human login and refresh asks the hub `ResolveUser`: is the account
live, which groups, and is that answer authoritative. A suspended
account gets no token even though its identity provider would still sign
it in.

## Rules

The same engine the hub's console uses, with more outputs. Subjects: a
directory group (through the hub), a claim on a named issuer (a GitHub
repository, a ref, a workflow), an email, an email domain. Grants: a
`groups` claim — the role names relying parties already read — and a set
of **audiences**, each naming one relying party and one entitlement.

```yaml
issuers:
  corporate:
    - backend: google
  github:
    - organisation: example-org

rules:
  - when: { directory_group: platform-admins@example.com }
    grant:
      groups: [cluster-kernel:admin, cluster-prod:admin]
      audiences: [k8s:kernel, k8s:prod, aws:111122223333:power]
  - when: { github: { repository: example-org/gitops, ref: refs/heads/master } }
    grant:
      audiences: [aws:111122223333:gitops-deployer]

defaults:
  unmatched: deny
  hold_window: 4h
```

Declared in the deployment, rendered into a ConfigMap, tested like code.

## What it issues, and who trusts it

Standard OpenID Provider surface, from a library rather than written:
discovery, JWKS with key rotation, authorization code with PKCE, refresh,
device authorization, client credentials, JWT profile, token exchange.
Clients are static configuration from the deployment.

| Relying party | Trusts on | Reads |
|---|---|---|
| a Kubernetes API server | issuer, a client id per cluster | the `groups` claim into RBAC |
| a cloud account | an IAM OIDC provider per account; a trust policy per role that requires `aud` to equal that role's audience | nothing else: for a custom issuer, trust policies can see only `sub`, `aud`, `amr` and `email` |
| a console behind an authenticating proxy | client id and secret | `groups` |
| kubelogin and any standard OIDC client | discovery | works unchanged |

**Why audiences carry the cloud decision.** A rule-gated audience is
minted only for identities the rules allow, and a role's trust policy
names only that audience. One trust policy per role, no per-user
policies, several organisations behind one issuer. The `amr` claim would
be a cleaner carrier for groups if the cloud passes a custom issuer's
values through; that is a spike item, not an assumption.

## The CLI

Kubernetes needs no custom client: kubelogin does the device or code flow
and caches refresh tokens. The CLI's one job is the exchange for a cloud
role — present the login token, request `aws:<account>:<role>`, turn the
result into temporary credentials — plus the same for a CI job's exchanged
token. It ships from this repository.

## State

No database. Signing keys in Secrets, rotated. Authorization codes,
refresh tokens, device codes and the last-known groups per identity in
Valkey, external to the chart like the hub's. Rules and clients from the
deployment.

## Failure semantics

| Situation | Effect |
|---|---|
| the hub answers non-authoritative | existing identities keep their last-known groups for the hold window; new identities get nothing |
| the hub is down | same, then no new human logins after the window; workload exchange unaffected |
| the token service is down | no new logins anywhere; existing sessions and tokens live to expiry; break-glass is outside it |
| a workload token fails verification | `invalid_grant`, never a partial token |
| an audience is not granted | `invalid_target`, the exchange is refused |

## What it replaces, generically

An identity provider run only for infrastructure access, plus the two
things such a setup needs when the provider cannot look up directory
groups or consume workload tokens: a login hook that computes roles, and
a broker that mints machine tokens. The policy those carried is not
discarded; it becomes the rules file.

## Before building: the spike

1. Rule-gated audiences accepted by trust policies across two cloud
   accounts.
2. Whether the cloud passes a custom issuer's `amr` values through.
3. The device flow through kubelogin against a cluster, and one console
   login through its proxy.
4. One CI exchange from a real workflow, on a fork branch too.
5. The hold window when the hub answers non-authoritative.

Each with a number attached. The migration that follows is consumer by
consumer, the previous issuer running as fallback until it has no relying
party left.
