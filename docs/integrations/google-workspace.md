---
title: Google Workspace
description: How sluis signs people in with Google accounts and reads a Workspace directory for users, groups and domains, with read-only scopes and a keyless option.
status: target
sidebar:
  order: 3
---

Google Workspace is the corporate directory in the common case. People sign in with their Google account, and sluis reads the tenant's users, groups and domains as facts. `adapter-upstream-oidc@<boundary>` does both jobs, with two separate credentials.

## What it's for

- **People sign in with the account they already have.** An engineer opens a console or runs `sluis login`, is routed to the right tenant by the domain of their e-mail address, passes the tenant's MFA, and returns with a sluis session. sluis never sees a password.
- **Policy talks about groups that already exist.** "Members of `platform-engineers@example.org` may assume this role" needs the group's membership, which the adapter supplies and keeps fresh.
- **A leaver loses access when the directory says so.** Membership changes reach sluis on the next refresh. A failed read is an error, never an empty answer that would remove everyone.

## Integration kinds

| Kind | What it does for Google |
|---|---|
| `Upstream` | Runs the sign-in: sends the person to Google, exchanges the code, checks the returned ID token (signature, issuer, audience, `azp`, `nonce` and the time claims), and returns a verified identity to `session` ([0025](/decisions/0025-integrations/#the-upstream-contract)). |
| `FactsSource` | Reads users, groups and domains into directory facts of the tenant, refreshed on an interval, and answers "which groups is this person in" with its freshness: `as_of`, `max_age` and whether the answer is authoritative. |

## Connections

The two jobs use different credentials, so they are **two connections**. One adapter serves both, because it holds neither at rest, and a compromise of one connection does not reach the other.

| Credential | Kind | Class | Made by |
|---|---|---|---|
| The sign-in client of the operator | `Upstream` and `UpstreamSecret` | Config and secret | Hand or IaC, in a reviewed file |
| The directory | `DirectoryConnection`, written by `adapter-upstream-oidc` | Durable, per tenant, credential sealed | The UI or the API |

- **A tenant's directory is read through its own connection.** The facts are the temp kinds `DirectoryUser`, `DirectoryGroup` and `DirectoryMembership` of that tenant, sealed because they hold names and addresses, with a time to live of 24 hours by default and 7 days at most ([0025](/decisions/0025-integrations/#what-an-integration-may-return)).
- **A scheduled re-sync asks `policy` for a grant** for one tenant at a time, because no caller starts it. On boards, a full re-sync is many commits of the cluster; its cost is the subject of [#1180](https://github.com/truvity/sluis/issues/1180) and its result is recorded in [0037](/decisions/0037-capacity-is-measured-before-it-is-promised/#board-capacity).
- **The operator's own company is a tenant,** so its directory connection is durable too.

## What sluis asks the vendor for

For sign-in, an OAuth client of type *Web application* with the scopes `openid`, `email` and `profile`, nothing else. For the directory, four read-only Admin SDK scopes (users, groups, group members, domains), granted in one of three ways, from least to most standing power:

| Method | What the connection holds |
|---|---|
| Workload Identity Federation with delegation (keyless) | Nothing long-lived: the adapter exchanges its own workload token for a short-lived service-account identity. |
| Service-account key with delegation | A JSON key, sealed. Some organisations forbid creating keys. |
| Admin consent | A Super Admin's refresh token, sealed, which dies with that account. |

The keyless method is the target for new installations. It needs the GCP exchange ([#871](https://github.com/truvity/sluis/issues/871)), with its token signed under the ES256 cloud-federation exception ([0006](/decisions/0006-keys-and-sealing/#named-exceptions)); until that is built, an installation uses a key or admin consent. The [setup patterns](/integrations/connecting/#google-workspace) compare the three.

## What policy controls

- **Which domains route to which upstream**: the operator declares them in the `Upstream` ([0033](/decisions/0033-customer-connections/#which-upstreams-an-installation-has)); an address whose domain no upstream declares goes to the client's default upstream ([0033](/decisions/0033-customer-connections/#choosing-the-connection)).
- **Which groups are read.** The mirrored groups can be narrowed, so a policy can refer only to those.
- **Who may sign in at all.** Sign-in proves an identity; whether it is admitted to a client is the client's `requires`.
- **Freshness.** How long held facts may be used when the directory cannot be read; after that window sluis refuses rather than guesses, and a person disabled in the directory is refused at once ([0017](/decisions/0017-identity-and-sign-in/#directory-outages)).

sluis finds the person by the issuer and the Google `sub`, never by e-mail: a different `sub` is a different person, and a sign-in is refused when the configured subject claim contradicts the claim pinned for the issuer ([0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)). Whether Google verified the e-mail is a fact that policy may read. The person's sluis subject is an opaque id, never the e-mail address ([0017](/decisions/0017-identity-and-sign-in/#subjects)).

## What Google says about the sign-in

Read on 2026-11-06:

- **Google sends `amr` and `auth_time` only when the request asks for them.** The sign-in request has to carry a `claims` parameter that names both, and Google sends them only to verified apps, per its [announcement of 2026-06-16](https://developers.googleblog.com/en/enhance-security-and-trust-new-session-metadata-in-sign-in-with-google/). The values it documents are `pwd`, `mfa`, `hwk`, `swk`, `tel` and `sms` (RFC 8176 names). The claim can still be absent. Google's [OpenID reference](https://developers.google.com/identity/openid-connect/reference) lists no `acr` among the ID-token claims and documents no `acr_values` support.
- **Until the generic upstream can send a configured `claims` parameter ([#1154](https://github.com/truvity/sluis/issues/1154)), a Google sign-in reaches policy with no `amr`,** which policy treats as unknown ([Policy](/reference/policy/#context)). That issue gates every use of Google's evidence, so it comes first.
- **Whether a passkey sign-in yields `hwk` or `swk` is not known (to be confirmed).** The test is one afternoon: sign in with a hardware security key, with a synced passkey, with a phone prompt and with a one-time code, and record the `amr` of each. Until it is done, nobody relies on `hwk` from Google, and a synced passkey is not assumed to yield `swk`.
- **Workspace has no documented switch for attestation.** The 2-step verification setting "Only security key" accepts security keys and passkeys alike, and no Admin console setting that requires a device-bound key or restricts models was found.

What sluis does with it ([0017](/decisions/0017-identity-and-sign-in/#what-an-upstream-adds-to-a-tier)):

- **An `amr` from Google is a hint.** Google decides it and sluis cannot check how the person authenticated. It counts toward the hardware-attested tier only through the connection's mapping table, never above the connection's ceiling ([REQ-AUTHN-087](/requirements/authn/#REQ-AUTHN-087)).
- **A missing `amr` is unknown, and unknown is refused** for a grant that demands the tier. The signing and key-administration grants do not rely on Google at all: a boundary verifies the person's own security-key assertion.

## What is audited

Each sign-in (client, class of session) and each refusal; a directory connected, changed or disconnected; a failed directory read, as a failure. No Google credential or refresh token is ever recorded.

## Setup

The full flow is in [the setup patterns](/integrations/connecting/#google-workspace); names and keys are [illustrative](/integrations/#examples-are-illustrative).

1. In Google Cloud, create a project, enable the Admin SDK API, and create the sign-in client with the redirect URI sluis prints.
2. In the Admin console, authorise the service account for the four scopes (domain-wide delegation), or consent as a Super Admin.
3. Connect the directory in the console or through the API, and choose which domains the tenant serves: `sluis integrations connect google-workspace --tenant acme`. The adapter reads one page of users before it keeps the connection.
4. For the operator's own sign-in, commit the `Upstream` with its client id and subject claim, and put the client secret in the secret source.

```yaml
# Upstream, a config kind (example); its secret is an UpstreamSecret in the secret source
upstreams:
  - id: google
    issuer: https://accounts.google.com
    client_id: 123456789012-example.apps.googleusercontent.com
    subject_claim: sub
```
