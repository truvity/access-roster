# The rules language

One file, evaluated in order, default deny. The hub's console uses it to
grant viewer and operator; the issuer uses it to grant `groups` values and
audiences. Same syntax, same engine (`pkg/rules`).

## Shape

```yaml
issuers:                      # who may present a proof (issuer only)
  corporate:
    - backend: google         # tenants are discovered by the hub
  github:
    - organisation: example-org

rules:
  - id: platform-admins       # stable, used in logs and WhoAmI
    when: { directory_group: platform-admins@example.com }
    grant:
      groups: [cluster-kernel:admin, cluster-prod:admin]
      audiences: [k8s:kernel, k8s:prod, aws:111122223333:power]
      role: operator          # hub console only

  - id: everyone-reads
    when: { email_domain: example.com }
    grant:
      role: viewer

  - id: gitops-deploys
    when: { github: { repository: example-org/gitops, ref: refs/heads/master } }
    grant:
      audiences: [aws:111122223333:gitops-deployer, k8s:devel]

defaults:
  unmatched: deny
  hold_window: 4h             # keep last-known grants when the hub is not authoritative
```

## Subjects

| Subject | Matches | Needs |
|---|---|---|
| `directory_group` | live members of a snapshotted group in a served domain; `workspace_id` optional | a connected workspace |
| `claim` | `{issuer, claim, value}` — a value in a named claim of a verified token from a named issuer | a corporate or external proof |
| `github` | `{repository?, owner?, ref?, workflow?, environment?}` — claims of a CI identity token; every listed field must match; globs allowed | a CI proof |
| `service_account` | `{namespace, name}` — a Kubernetes ServiceAccount | a workload proof |
| `email` | one address, case-insensitive | nothing |
| `email_domain` | every address in the domain | nothing |

## Grants

| Grant | Effect |
|---|---|
| `groups` | added to the token's `groups` claim; relying parties map them to their own roles |
| `audiences` | added to the set the identity may request; a token carries only the audiences its client asked for and this set allows |
| `role` | hub console only: `viewer` or `operator`; operator implies viewer |

Grants accumulate across matching rules. There is no deny rule; what no
rule grants, nobody has.

## Evaluation

1. The proof is verified; a directory subject is resolved through the hub.
2. Rules are walked in order; every match contributes its grant.
3. If the hub's answer was not authoritative, an identity seen before
   keeps its last-known grants for `hold_window`; an identity never seen
   gets nothing.
4. The result is cached per identity for the token's lifetime and
   recomputed on refresh.

## Testing the file

`accessctl rules test rules.yaml` evaluates fixtures — an identity with
groups, a CI token's claims — and prints the grants, so the file is
reviewed like code. The hub and the issuer refuse to start on an unknown
key (`KnownFields`), so a typo fails the rollout, not a login.
