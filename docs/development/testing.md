# Testing

Three layers; the shape is fixed now so the prototype and the build can
grow into it.

## Unit

Pure packages with table tests: address routing (`internal/emailaddr`),
the authority rule (probe ok × snapshot age × conflict), the freshness
policy (`max_age` against `snapshot_at` per call kind), the domain-claim
conflict detection, the overlay merge.

## Demonstration fixtures

`DEMO=1` brings up two tenants in memory and a policy that exercises every
mechanic, so the behaviour can be watched rather than described: two
companies feeding one internal group, two fragments whose lists merge, a
lifetime that differs by privilege with the shortest winning, a client
that caps it shorter still, machine groups for a CI job and a workload,
and one suspended account, because a leaver is the case the whole design
turns on.

It is the same code path as a real install: nothing in the fixtures is a
special case in the hub, only a backend with no network behind it.

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

## The wiring

`internal/app` assembles the service from its configuration — which
store, which shape of recovery, who may call the API listener, what URL
the OAuth redirects are built from — and every one of those is somewhere a
deployment can be quietly wrong. It is a package rather than the body of
`main` for exactly that reason: `main()` cannot be tested and this can.

Two suites live there. The **acceptance** tests boot a whole hub from the
environment, the way the chart configures one, and walk the use cases
over the real handlers: a person signs in through a directory and reaches
the console with the role their membership grants; recovery reaches it
without any membership at all; turning either off closes routes rather
than hiding buttons; the setup steps carry this installation's own
redirect URIs. The **environment** test compares every variable the binary
reads against every one the chart sets, reading both lists from the source
so neither can be restated wrongly. It exists because five settings were
being read and never set, and the worst of them built every OAuth redirect
from `http://localhost:8081` — invisible in every local run, fatal in the
first deployment.

## Against a real API server

`just acceptance` creates a throwaway kind cluster, runs `cmd/acceptance`
in it and deletes it again. The fakes are honest about most things and
silent about three, and all three are load-bearing here: a real API server
validates object names, refuses a create that raced another, and is the
only thing that can answer a TokenReview — which is what recovery and the
API listener's guard are made of.

So it checks that a workspace and its credential survive a restart and
that disconnecting takes both away; that every tenant id a backend might
hand us produces an object name the API server accepts; that two replicas
share one session key; that a recovery token admits the recovery account
and refuses another account's, a forged one and one minted for a different
audience; and the same three questions for a consumer on the API listener.

It is a command rather than a `go test` package because it needs a
cluster, and `go test ./...` should not assume one.

Installing the chart is the other half, and neither `helm lint` nor a
render can do it: they check that the YAML is well formed, not that the
thing it describes starts. The first real install refused to boot because
the rendered policy carried no `version`. Build an image with `ko build
--local`, load it, and install into the same throwaway cluster. Point it at any
cluster and namespace you may create objects in; it cleans up by the
labels it wrote, including when a check fails.

## Issuer, proxy and CLI

The issuer's verifiers run against recorded tokens with rotated keys and
a fake hub; the policy engine against fixtures; the OpenID Provider glue
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
| policy | day one end to end: admin → connect → membership from the picker → directory sign-in → operator → admin off; a suspended account cannot sign in; a declared membership cannot be removed; two fragments with a conflicting scalar fail to load; Explain names the membership behind every group held |
