---
title: Google Workspace
description: How sluis signs people in with Google accounts and reads a Workspace directory for users, groups and domains, with read-only scopes and a keyless option.
status: target
sidebar:
  order: 3
---

Google Workspace is the corporate directory in the common case. People sign in with their Google account, and sluis reads the tenant's users, groups and domains as facts.

## What it's for

- **People sign in with the account they already have.** An engineer opens a console or runs `sluis login`, is routed to the right tenant by the domain of their e-mail address, passes the tenant's MFA, and returns with a sluis session. sluis never sees a password.
- **Policy talks about groups that already exist.** "Members of `platform-engineers@example.org` may assume this role" needs the group's membership, which the directory integration supplies and keeps fresh.
- **A leaver loses access when the directory says so.** Membership changes reach sluis on the next refresh. A failed read is an error, never an empty answer that would remove everyone.

## Integration kinds

| Kind | What it does for Google |
|---|---|
| `Upstream` | Runs the sign-in: sends the person to Google, checks the returned ID token (issuer, audience, `nonce`, verified e-mail), and returns a verified identity. |
| `FactsSource` | Reads users, groups and domains into a snapshot per tenant, refreshed on an interval, and answers "which groups is this person in" with its freshness: `as_of`, `max_age` and whether the answer is authoritative. |

The two use different credentials, so they are **two processes per tenant**: `google-signin@<company>` holds the OAuth client secret and `google-directory@<company>` the directory credential. A compromise of one does not reach the other, and each tenant has its own pair.

## What sluis asks the vendor for

For sign-in, an OAuth client of type *Web application* with the scopes `openid`, `email` and `profile`, nothing else. For the directory, four read-only Admin SDK scopes (users, groups, group members, domains), granted in one of three ways, from least to most standing power:

| Method | What sluis holds |
|---|---|
| Workload Identity Federation with delegation (keyless) | Nothing long-lived: sluis exchanges its own workload token for a short-lived service-account identity. |
| Service-account key with delegation | A JSON key, as a credential. Some organisations forbid creating keys. |
| Admin consent | A Super Admin's refresh token, which dies with that account. |

The keyless method is the target for new installations. It needs the GCP exchange ([#871](https://github.com/truvity/sluis/issues/871)), with its token signed under the ES256 cloud-federation exception ([ADR 0012](/decisions/0012-cryptography-and-authority-keys/#named-exceptions)); until that is built, an installation uses a key or admin consent. The [setup patterns](/integrations/connecting/#google-workspace) compare the three.

## What policy controls

- **Which domains a tenant serves**: every domain it owns, or a list. A domain served by no tenant cannot sign in.
- **Which groups are read.** The mirrored groups can be narrowed, so a policy can refer only to those.
- **Who may sign in at all.** Sign-in proves an identity; whether it is admitted to a client is the client's `requires`.
- **Freshness.** How long a held snapshot may be used when the directory cannot be read; after that window sluis refuses rather than guesses, and a person disabled in the directory is refused at once ([ADR 0006](/decisions/0006-identity-issuers-audiences-and-sign-in/#directory-outages)).

sluis refuses a sign-in whose e-mail is unverified, and one whose Google `sub` differs from the one first recorded for the person (a deliberate move needs an operator). The person's sluis subject is an opaque id, never the e-mail address ([ADR 0006](/decisions/0006-identity-issuers-audiences-and-sign-in/#subjects)).

Google sends `amr` and `auth_time` only when the sign-in request carries a `claims` parameter that asks for them, and the console settings for them are on. Until the generic upstream can send a configured `claims` parameter ([#1154](https://github.com/truvity/sluis/issues/1154)), a Google sign-in reaches policy with no `amr`, which policy treats as unknown ([Policy](/reference/policy/#context)).

## What is audited

Each sign-in (client, class of session) and each refusal; a directory connected, changed or disconnected; a failed directory read, as a failure. No Google credential or refresh token is ever recorded.

## Setup

The full flow is in [the setup patterns](/integrations/connecting/#google-workspace); names and keys are [illustrative](/integrations/#examples-are-illustrative).

1. In Google Cloud, create a project, enable the Admin SDK API, and create the sign-in client with the redirect URI sluis prints.
2. In the Admin console, authorise the service account for the four scopes (domain-wide delegation), or consent as a Super Admin.
3. Run `sluis integrations connect google-workspace --tenant example.org`, and choose which domains the tenant serves.

```yaml
# /etc/sluis/install.yaml (example)
integrations:
  google-workspace:
    example-org:
      actors: [upstream, facts]
      admin: directory-reader@example.org   # the account the delegation impersonates
      serve: [example.org]                  # omitted: every domain the tenant owns
      oauth_client:
        id: cred:sluis-int-google.client-id
        secret: cred:sluis-int-google.client-secret
      auth: { method: federation, service_account: sluis-dir@project-id.iam.gserviceaccount.com }
```
