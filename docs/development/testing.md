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
special case in the service, only a backend with no network behind it.

## Fakes

- **Backend fake:** an in-memory Google Workspace with users, groups,
  members and domains, scriptable failures per call (a page that errors,
  a not-found, a revoked token), and a tenant whose domain list can
  change between probes. Every handler test runs against it.
- **Store fake:** the Kubernetes store behind an interface, with an
  in-memory implementation over the fake clientset; the real one is
  exercised against a kind cluster in the acceptance suite. The restore
  and migration paths — four Secrets rebuilding a namespace, pre-1.7
  credential objects copied in by name — are tested here.
- **Cache fake:** the snapshot store behind an interface; the in-memory
  backend is the fake. The Valkey backend is exercised against an
  in-process Valkey (`miniredis`).
- **GitHub fake:** an in-memory organisation with members, teams,
  invitations and seats, which the controller's reconcile and pass tests
  drive through joiners, movers, leavers, the breaker and every held
  state.
- **Audit:** the S3 writer is tested for its ECS objects, its metrics and
  what it drops when full; the issuer's tests hold the one fail-closed
  path — an ordinary sign-in never waits on the trail, a recovery sign-in
  is refused when its record cannot be written.

Handler tests are at the join level, not the unit level: they call the
Connect handler and assert the response, so a rule that exists but is
never wired shows up as a failing test.

## The wiring

`internal/rosterapp` assembles the service from its two halves —
`internal/app`, the directory and the console, and `internal/issuerapp`,
the OpenID provider — from their configuration: which store, which shape
of recovery, what URL the OAuth redirects are built from. Every one of
those is somewhere a deployment can be quietly wrong. They are packages
rather than the body of `main` for exactly that reason: `main()` cannot
be tested and these can, and each of the three carries an acceptance
suite.

The **acceptance** tests boot the whole service from the
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
a fake directory; the policy engine against fixtures; the OpenID
Provider surface against the library's own tests, and, by hand and
before a release that touches it, against the OpenID Foundation's suite
([operations/conformance.md](../operations/conformance.md)), whose
results are [conformance.md](../conformance.md). `access-proxy` is tested by
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

## Charts

Both charts are tested without a cluster, in `just chart-lint`:

- **Golden renders.** Every `tests/cases/<chart>/<case>/values.yaml` is
  rendered with `helm template` (release name = chart name, namespace
  from an optional `namespace` file beside it) and compared byte for
  byte with `tests/golden/<chart>/<case>.yaml` by `hack/golden.sh`. A
  template change therefore arrives as a reviewable diff of what the
  cluster will be sent. Each chart has a `minimal` case and a `full` case
  that sets every value; the other cases take the other side of each
  switch (`headless`, `listenerset`, `attach`, `multiroute`, ...). After
  changing a template or a case, run `just golden` and review the diff
  before committing it.
- **Negative fixtures.** `tests/invalid/<chart>/<rule>.yaml`, one per
  refusal: every schema rule (an unknown key at each level, `required`,
  `enum`, `pattern`, `minLength` and the rest) and every render-time
  `required` or `fail` in a template. Each is otherwise valid, says on
  its first line why it must fail, and on its second (`# error: ...`)
  what the refusal says. The recipe renders every one and fails if one
  renders, or fails for any other reason. A new rule gets a fixture in
  the same change; a rule without one is a rule that can quietly stop
  working.
- **Properties across the goldens** that a regenerated golden could
  lose without anyone noticing: `/console` and `/console/` render the
  same, every SecurityPolicy asks Envoy for the session cookie, and every
  `backendRefs` entry writes its `weight` out.

`hack/golden.sh` is vendored verbatim from the shared CI repository;
update it by copying the canonical file again, not by editing this copy.

## What CI runs

`just check` runs every recipe CI runs — `build`, `test`, `lint`,
`chart-lint`, `archive-check`, `docs-check`, `ts`, `console` — plus
`vuln`, which CI runs in its own security workflow rather than on every
push. `ts` typechecks and tests the published TypeScript package;
`docs-check` refuses a documented Go symbol that does not exist;
`console` builds the bundle the binary embeds, which is why every recipe
that compiles Go runs it first.
