# Testing

Three layers; the shape is fixed now so the prototype and the build can
grow into it.

## Unit

Pure packages with table tests: address routing (`internal/emailaddr`),
the authority rule (probe ok × snapshot age × conflict), the freshness
policy (`max_age` against `snapshot_at` per call kind), the domain-claim
conflict detection, the overlay merge.

## Fakes

- **Backend fake:** an in-memory Google Workspace with users, groups,
  members and domains, scriptable failures per call (a page that errors,
  a not-found, a revoked token), and a tenant whose domain list can
  change between probes. Every handler test runs against it.
- **Store fake:** the Kubernetes store behind an interface, with an
  in-memory implementation; the real one is exercised against `envtest`
  or a kind cluster.
- **Cache fake:** the snapshot store behind an interface; the in-memory
  backend is the fake. The Valkey backend is exercised against a real
  Valkey in the acceptance suite.

Handler tests are at the join level, not the unit level: they call the
Connect handler and assert the response, so a rule that exists but is
never wired shows up as a failing test.

## Issuer, proxy and CLI

The issuer's verifiers run against recorded tokens with rotated keys and
a fake hub; the rules engine against fixtures; the OpenID Provider glue
against the library's conformance tests plus kubelogin and an OAuth2
proxy as real clients in the acceptance suite. `access-proxy` is tested by
installing it in front of a fixture backend and driving a browser through
login, sign-out and a revoked identity. `accessctl` is tested against the
acceptance issuer with a fake cloud STS and a kind cluster, on a laptop
path and on a simulated CI path.

## Acceptance

`cmd/acceptance`: a Go program run against a live install (kind or a
development cluster) with two fake-backed workspaces and one real one
when credentials are provided. It walks the scenarios operators care
about and prints a table:

| Scenario | Asserts |
|---|---|
| connect, disconnect | domains appear and disappear in `Describe`; Secret and record created and deleted |
| revoked token | probe fails; domains non-authoritative; snapshot still served; Reconnect restores |
| domain move | a domain leaves one tenant and joins another across two probes; no window of "gone" |
| domain conflict | both list it; authoritative for neither; clears when one drops it |
| key upload | same record, different credential type |
| freshness | `max_age` omitted serves the snapshot; a short `max_age` triggers a point read; a miss goes live once |
| what the webhook sees | `ResolveUser` for live, suspended, deleted and out-of-domain addresses, with and without authority |
| consumer authentication | a projected token from an allow-listed ServiceAccount is accepted; a wrong audience, a foreign ServiceAccount and no token are refused |
| access rules | day one end to end: admin → connect → rule from the picker → directory sign-in → operator → admin off; a suspended account cannot sign in; a declared rule cannot be removed |
