---
title: More integrations
description: Slack, the Outline wiki, GoAlert and Telegram, the v1 parity integrations that keep channels, a wiki and an on-call tool in step with the directory.
status: target
sidebar:
  order: 20
---

These four integrations are part of v1 parity ([Roadmap](/roadmap/)); none is in the first working version. Each follows the [model](/integrations/): an adapter that holds no credential at rest and opens the tenant's sealed connection credential at key@ for each call, a desired state that core publishes, a dry run until enabled, and breakers against mass removals. A pass that no caller starts asks `policy` for a grant for one tenant at a time ([0025](/decisions/0025-integrations/#adapters-and-connections)). sluis does identity only: it does not read a wiki's documents or a channel's messages, and schedules and escalation stay in the on-call tool. What v1 does today is on the [v1 parity checklist](/features/).

## Slack

Slack channels follow directory groups. A private channel bound to a group holds exactly that group's members: a *strict* channel also removes people the directory no longer vouches for, an *extend* channel only adds. Slack Connect channels between the installation's own workspaces are records fed by groups and addresses, and channels kept from the console are records that never mix with the ones bound in reviewed policy. A leaver still in a channel is reported, and a pass that would remove too many people stops for a confirmation.

- **Kinds:** `Provisioner` (creates or adopts channels, invites, removes) and `Notifier` (sends a message), served by `adapter-slack`.
- **Needs:** one Slack App for the installation, created from a manifest, and one install per tenant's workspace. The least scopes for the jobs turned on: `users:read`, `users:read.email`, `channels:read`, `groups:read`, `channels:manage`, `groups:write`, `channels:join`, and the `conversations.connect` scopes for Slack Connect. The workspace recorded at the first install is pinned, and an install into any other workspace is refused ([Slack app manifests](/integrations/connecting/#slack-app-manifests)).
- **Parity:** [#812](https://github.com/truvity/sluis/issues/812) policy channels, [#813](https://github.com/truvity/sluis/issues/813) console and Slack Connect channels, [#814](https://github.com/truvity/sluis/issues/814) workspace connection.

Chat is the worked example of linked kinds ([0004](/decisions/0004-the-data-model/#layered-and-linked-kinds)): each kind is in one class, and the kinds refer to each other by id.

| Kind | Class | Holds | Writer |
|---|---|---|---|
| `SlackApp` | Config | The app id, client id, scopes and redirect URL, made once by hand or IaC | IaC |
| `SlackAppSecret` | Secret | The app's client secret, in a secret source | IaC |
| `SlackConnection` | Durable, per tenant, sealed | The workspace id, the bot user, the granted scopes and the bot token | `adapter-slack` |
| `SlackInstallState` | Temp, hashed, 10 minutes | The OAuth state of an install in progress | `adapter-slack` |
| `ReconcileTarget` | Durable, per tenant, sealed | The channels bound in reviewed policy, their mode and the breaker thresholds, for one connection of the tenant | `adapter-slack` |
| `ConsoleChannel` | Durable, per tenant, sealed | A channel made on the console | `adapter-slack` |
| `HeldChange` | Durable, per tenant, sealed | A change the breaker held, until an operator confirms it | `adapter-slack` |

Channels bound in reviewed policy and channels made on the console are two kinds with two owners and never mix ([0026](/decisions/0026-reconcilers/#safety)).

## Outline wiki

An Outline wiki's admins, groups, members, collections and grants follow the directory. A new employee reads the collections their group is bound to on day one; a leaver is suspended when the directory stops vouching for them; a *strict* collection loses grants and direct members the policy does not name. Risky settings, such as public sharing or a document shared with someone the directory does not serve, are reported, not silently changed. A pass that would remove over half of a group or a collection's grants, demote more than one admin (or the last), or suspend more than three accounts waits for an operator.

- **Kind:** `Provisioner`.
- **Needs:** an API key of an Outline admin, as a credential. Outline has no service accounts, so the key belongs to a person: use a dedicated admin account and put it on the ignore list, so the controller never demotes the account it runs as. The controller refuses a key whose user is not an admin, calls only the users, groups and collections API, and reaches the wiki over HTTPS only.
- **Parity:** [#815](https://github.com/truvity/sluis/issues/815).

## GoAlert

GoAlert gets the identity side of on-call. A person in the on-call group exists in GoAlert before their first sign-in, linked to their sluis subject, so they are pageable from day one. A rotation's participants are a group's members in order, and the person on call stays on call when the list changes (the update is positional, so the integration computes the active index). A leaver is deleted, which takes them out of every rotation. The administrator role comes from a named group, decided by `policy`, never by the integration.

- **Kind:** `Provisioner` (users, roles, rotation participants and contact methods).
- **Needs:** an administrator API key with a mandatory expiry, bound to one stored GraphQL document that holds a small fixed list of operations run with variables only. A GoAlert administrator mints it once and registers it with sluis, which warns before it expires.
- **Parity:** [#899](https://github.com/truvity/sluis/issues/899), with Telegram.

## Telegram

A person links their Telegram account to their sluis identity once, with a single-use link, and the on-call tool's contact method is then verified without anyone typing a code. Messages reach a person or a place through the bot.

- **Kinds:** `Notifier`, plus the account-link flow of the base contract.
- **Needs:** a bot token per purpose. The Bot API cannot create a bot, so an administrator creates it with Telegram's bot-management bot and enters the token through the UI or the API, which keeps it sealed in the tenant's connection (a bot that serves the whole installation keeps its token in a secret source instead, by the rule of [Connecting](/integrations/connecting/#two-paths-made-by-hand-or-made-in-the-ui)). sluis then sets the commands, description and webhook. A narrower GoAlert key, which can only verify a contact method, belongs to the Telegram side.
- **Parity:** [#899](https://github.com/truvity/sluis/issues/899).

## Connecting

Apart from Slack's manifest, each takes a key or token an administrator creates by hand ([Credentials without a ceremony](/integrations/connecting/#credentials-without-a-ceremony)). The credential is entered through the UI or the API, checked in a dry run and kept sealed in the tenant's connection; it is never inlined in a reviewed file and never recorded in the audit log.
