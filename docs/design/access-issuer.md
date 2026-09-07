# access-issuer — the token service

**Status:** designed 2026-09-07; **built after the hub**, as the second
service of access-roster. Nothing in the hub depends on it.

## Purpose

One issuer that every cluster, cloud account, CD system and console of an
installation trusts, fed by the corporate identity providers the
installation already has and by the identity tokens its CI platform
already mints, with the mapping from directory groups to entitlements
written in one file. It exists so that an installation does not run a
full identity provider — a user store, a login UI, a database — only to
get the part of one it uses: federation with claim shaping and
workload-token exchange.

It is a **security token service**, not an identity provider. The line:

- it never proves who anyone is; it verifies proofs produced elsewhere;
- it holds no passwords, no user records, no MFA, no consent screens, no
  self-registration, no second way in;
- break-glass lives outside it, in the cloud account and the cluster's
  own access mechanisms;
- its one operator page is read-only; policy changes are commits.

The day a requirement needs one of the things on that list is the day to
stop and reconsider, not to extend.

## What it verifies

| Proof | From | How |
|---|---|---|
| a corporate sign-in | Google Workspace, Microsoft Entra | an OIDC authorization-code flow the issuer starts and finishes, routed by email domain; the address is then resolved through the hub |
| a CI identity token | GitHub Actions, per organisation | RFC 8693 token exchange; verified against the platform's keys, the organisation checked against an allow-list, claims such as repository and ref fed to the rules |
| a workload token | a Kubernetes ServiceAccount | token exchange verified with TokenReview, for the rare in-cluster service that needs a token another system trusts |

Every human login and refresh asks the hub `ResolveUser`: is the account
live, which groups, and is that answer authoritative. A suspended account
gets no token even though its identity provider would still sign it in.
That is the second half of global logout: the proxy ends the session; the
issuer stops refreshing.

## What it issues, and to whom

A standard OpenID Provider surface, from a library rather than written:
discovery, JWKS with key rotation, authorization code with PKCE, refresh,
device authorization, client credentials, JWT profile, token exchange,
RP-initiated logout.

Claims: `sub` stable per identity, `email`, `name`, `groups` — the role
names relying parties already read — and `aud`, the set of audiences the
rules allow for this client and identity.

**Clients** come to exist in exactly two ways, never in a console:

| Way | Which |
|---|---|
| **declared** in the policy's `clients` table | one public client per cluster, the AWS roles as `exchange` clients, ArgoCD and Kargo as `confidential`, accessctl and kubelogin as `public`, and one `local-dev` public client for laptops |
| **self-registered** by an in-cluster workload through RFC 7591, authenticated with its ServiceAccount token and constrained by the host pattern allowed for its namespace | every `access-proxy` instance, and any other in-cluster relying party |

Dynamic registration is the convention that removes per-console
bookkeeping: a proxy comes up, registers `https://<its host>/oauth2/callback`,
receives a client id and secret, and is done. The issuer records the
registration in a ConfigMap and a Secret in its own namespace, keyed by
the registering ServiceAccount, and refuses a host outside that
namespace's allowed pattern.

**Audiences** carry the cloud and cluster decisions. A rule-gated audience
is minted only for identities the rules allow, and a role's trust policy
names only that audience: one trust policy per role, no per-user policies,
several organisations behind one issuer. For a custom issuer a cloud
trust policy can see only `sub`, `aud`, `amr` and `email`, which is why the
decision rides in `aud`. Whether the cloud passes a custom issuer's `amr`
through — a cleaner carrier for groups — is a spike item, not an
assumption.

**Discovery of what you are granted.** `GET /.access/grants` answers, for
the caller's identity, the audiences the rules allow. `accessctl
kubeconfig` and `accessctl aws-config` read it and write the files for
every cluster and role a person may use, so nobody maintains kubeconfigs
by hand.

## The policy

One file, shared with the hub: [reference/policy.md](../reference/policy.md).
Every proof resolves to internal groups — people through directory
membership the hub confirms, jobs and workloads through matchers — and
from there a person and a job are the same thing. The token is the fixed
identity claims plus the deep merge of the groups' claim fragments;
lifetime is the shortest across the groups, capped by the client. The
`clients` table is the audience: its id is `aud`, its `requires` is the
gate, its kind says whether there is a secret. AWS roles are clients of
kind `exchange`, which is where the earlier audience table went.

## State

No database. Signing keys in Secrets, rotated. Authorization codes,
refresh tokens, device codes and the last-known groups per identity in
Valkey, external to the chart. Static clients and rules from the
deployment; dynamic registrations in the issuer's own namespace.

## Failure semantics

| Situation | Effect |
|---|---|
| the hub answers non-authoritative | existing identities keep their last-known groups for the hold window; new identities get nothing |
| the hub is down | same, then no new human logins after the window; workload exchange unaffected |
| the issuer is down | no new logins anywhere; existing sessions and tokens live to expiry; break-glass is outside it |
| a proof fails verification | `invalid_grant`, never a partial token |
| an audience is not granted | `invalid_target`, the exchange is refused |
| a registration names a host outside its namespace's pattern | refused, logged |

## Before building: the spike

1. Rule-gated audiences accepted by trust policies across two cloud
   accounts.
2. Whether the cloud passes a custom issuer's `amr` values through.
3. The device flow through kubelogin against a cluster, and one console
   login through `access-proxy`.
4. One CI exchange from a real workflow, on a fork branch too.
5. Dynamic registration from a proxy's ServiceAccount, and its refusal
   for a foreign host.
6. The hold window when the hub answers non-authoritative.

Each with a number attached. The migration that follows is consumer by
consumer, the previous issuer running as fallback until it has no relying
party left ([operations/migration-from-an-idp.md](../operations/migration-from-an-idp.md)).
