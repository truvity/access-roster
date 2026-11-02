---
title: Public content and secrets
description: What may appear in the public sluis repository, which example names to use instead of real ones, and how secrets and test hardware are handled.
status: page
sidebar:
  order: 6
---

This repository is public, and so is everything around it: code, docs, the CHANGELOG, tests, test data, commit messages, issues and pull requests.

## Use example names

Nothing names a real organisation account, hostname, cluster, ticket, secret path, customer, private installation or person other than the maintainer. Write the example instead:

| Instead of a real | Write |
|---|---|
| domain or hostname | `example.com`, `sluis.example.com`, `sluis.<env>.example.com` |
| organisation or company | `acme`, `globex` |
| IP address | an address from the documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` |
| cloud account id | `123456789012` |
| ticket or issue key of an internal tracker | nothing; link a public issue of this repository instead |
| person | a role: "the operator", "an administrator", "the relying party" |

Internal reasoning that needs real names stays internal; only the final, generic text is public ([GOVERNANCE.md](https://github.com/truvity/sluis/blob/main/GOVERNANCE.md), "From internal reasoning to a public ADR").

CI scans every tracked text file for content that must not be public, such as account-id-shaped numbers, private key blocks and token prefixes (`just check-public`). Maintainers run additional checks before merging. A pass is not permission: the rule above is.

Never write a cloud or service account identifier in the repository, a commit message, an issue or a pull request.

## Secrets

- Never print a secret or a token: not in a terminal you share, a log, a test fixture, a commit, an issue or a pull request. Use test values.
- If a secret was printed or pushed anyway, tell the maintainer at once.

## Vulnerabilities

A suspected vulnerability goes through [SECURITY.md](https://github.com/truvity/sluis/blob/main/SECURITY.md), privately. Never open an issue, a pull request or a discussion for it.

## Hardware tokens

A test device's serial number is not written into the repository. How tests use hardware tokens is in [Hardware tokens](/contributing/tools/#hardware-tokens).
