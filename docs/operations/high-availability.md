# High availability

Running access-issuer at more than one replica, safely: what has to be
shared for that to work, what happens to each piece when the shared store
is unreachable, and how key rotation stays safe across a rollout. For the
directory (hub) half's own scaling and cache behaviour, see
[runbook.md#scaling-and-cache](runbook.md#scaling-and-cache); this page is
about the issuer half — logins in progress, sessions, and signing keys.

## What state exists, and where

Everything a login touches lives behind one interface
(`issuer.State`, `internal/issuer/state.go`): a key/value store with TTLs,
plus small unordered sets for listing "every session for this identity" or
"every session for this client" without scanning keys. Two implementations
back it — an in-memory one, and one over Valkey (`internal/valkey/state.go`)
— and the issuer itself does not know which it was given.

| What | Key prefix | Lifetime | Why it exists |
|---|---|---|---|
| A pending authorize request | `issuer:request:` | 30 min | spans `/authorize` through the redirect back — long enough for someone to read a consent screen. The same record backs a CLI's device-code poll. |
| An authorization code | `issuer:code:` | 5 min | between the redirect and the token call — a machine talking to a machine, so short. |
| A code's session, for a replayed code | `issuer:code-session:` | 5 min | lets a repeated redemption of the same code return the same session rather than minting a second one. |
| A per-client session (one refresh token, described) | `issuer:session:` | the session lifetime | identity, client, resource, how it began (`code`, `device`, `exchange`), granted scopes, the SSO session it belongs to, when it was authenticated. This is the record an operator revokes. |
| The live refresh token → session | `issuer:session-token:` | the session lifetime | how a refresh call finds its session. |
| A spent refresh token's successor | `issuer:session-rotated:` | 30 seconds (`refreshGrace`) | the rotated-refresh-token grace record: a refresh call that arrives twice within 30 seconds (a retry, not theft) gets back the SAME new token both times, instead of the second call being treated as reuse of a token that is already spent. |
| Session indices | `issuer:sessions-of:`, `issuer:sessions-for:`, `issuer:sessions-all` | the session lifetime, refreshed on every write | "every session this identity holds" / "every session for this client" / "every session" — what makes a session listable and revocable. |
| The browser-wide SSO session | `issuer:sso:` | the session lifetime | one sign-in that several per-client sessions can be issued under, so a single logout can end all of them. |
| Which clients an SSO session covers | `issuer:sso-clients:` | the session lifetime | the set a browser-wide logout walks. |
| SSO indices | `issuer:sso-of:`, `issuer:sso-all` | the session lifetime | listing and revocation, same shape as the per-session indices. |
| A minted token's own record | `issuer:token:` | until the token expires | read by `/userinfo` and by exchanging a token as a subject token — see [Valkey down](#valkey-down), below — and deleted to revoke a specific token. |
| The signing-key schedule | `issuer:keyring:index:`, `issuer:keyring:entry:` | 30 days, refreshed on every poll | see [Signing keys across replicas](#signing-keys-across-replicas). |

Nothing here is swept: every record carries its own TTL and expires on its
own, on both implementations. The in-memory store (`MemoryState`) is
correct for one replica and a local run; the Valkey-backed one
(`valkey.State`) is what makes the table above shared.

## With Valkey, and without it

**With Valkey**, every replica reads and writes the same records, so a
browser that starts `/authorize` on one pod, comes back from the directory
at a second, and redeems the code at a third, works exactly as if there
were one process. So does a CLI polling a device code, and so does the
signing-key schedule (below).

**Without Valkey** (`valkey.address` empty in the chart, or no
`VALKEY_ADDRESS`), the issuer keeps this table in the memory of one
process, and says so at start:

> keeping logins in progress in memory: correct for one replica, and at
> more than one a browser that comes back to a different pod finds nothing

This is `internal/issuerapp/app.go`'s own log line for `openState`. It is
correct only for `replicaCount: 1`. At two or more replicas with no
Valkey, each of the following happens depending only on which pod a
request happens to land on:

- a browser redirected back from `/authorize` may reach a pod that never
  opened that request, and sees an error rather than a completed sign-in;
- a refresh call may reach a pod that has never heard of the session, and
  is refused as if the token were invalid;
- the signing-key schedule is not shared, so each replica decides for
  itself when it first saw a key and when to start signing with it (see
  below) — two replicas can end up signing at different moments, or, after
  a restart, one replica forgetting a key another is still publishing.

None of this corrupts anything; it reads as an intermittent failure that
gets worse the more replicas there are — the `issuer.State` interface's
own doc comment (`internal/issuer/state.go`) names the shape of it
directly: "a coin toss that looks like an intermittent failure — the same
shape of bug as a per-process signing key, and harder to see, because it
only appears at more than one replica and only sometimes." The chart's
`values.yaml` says the same thing above `valkey:`, and the merged app logs
it at start (`internal/issuerapp/app.go`, `openState`) whenever it keeps
logins in memory.

## Valkey down

Readiness and liveness are deliberately different (`internal/health`):
**liveness follows nothing outside the process**, so a Valkey outage never
restarts every replica at once; **readiness follows Valkey**
(`health.Follow` wraps the state's own `Ping`), so a replica that cannot
reach it leaves rotation at the gateway — fast refusals instead of a hang
— without anything being restarted. The package doc names the incident
this split was written for: a store that moved address while two services
kept dialling the old one and stayed "ready" throughout, for half an hour,
until a person noticed.

What actually fails when Valkey itself answers but is unreachable, read
from the code rather than assumed:

- **`State.Set` and `State.SetIfAbsent` refuse a call with no TTL up
  front** (`internal/valkey/state.go`) — not a Valkey-down case, but the
  same file's evidence that this store treats "no lifetime" as a
  programming error, never a default.
- **Every session and storage operation that touches the store returns
  the store's error to its caller** (`internal/issuer/session.go`,
  `internal/issuer/storage.go`): opening a session, rotating a refresh
  token, recording an authorization code, redeeming one. There is no
  fallback path and no in-memory degrade once Valkey was configured. The
  issuer **refuses** the request; it does not degrade and does not fail
  open. Concretely: **new sign-ins, refreshes, and code exchanges fail**
  while Valkey is unreachable.
- **Access tokens already issued keep working.** They are JWTs, verified
  offline by everything that accepts them, against the published JWKS —
  nothing about that check consults Valkey. The one exception is
  `/userinfo` (`Storage.SetUserinfoFromToken`), which looks up the
  token's own record to catch a token whose session was since revoked;
  that lookup fails closed like everything else above, so `/userinfo`
  specifically stops answering while Valkey is down even though the
  token itself is still good everywhere else. This matches
  [architecture.md#failure-semantics](../architecture.md#failure-semantics):
  *"access-roster is down: no new sign-ins anywhere; existing sessions and
  tokens live to expiry."*
- **The key ring degrades gracefully, on purpose.** `KeyRing.Observe`
  never returns a state error to its caller: a briefly unreachable Valkey
  must not stop a replica signing with the key it can already read from
  its own mounted file, nor block it starting. It logs the failure and
  retries the write on every later poll (`internal/issuer/keyring.go`,
  `record` and `refresh`). A replica that already knows the active key
  keeps signing with it uninterrupted; what it cannot do while Valkey is
  down is learn of a key rotated on a *different* replica, or newly agree
  on one with replicas that have not seen it yet.

**Sizing:** the chart documents Valkey's memory for the directory (hub)
half explicitly — "the size of the directories"
(`docs/operations/runbook.md#scaling-and-cache`) — but gives no equivalent
number for the issuer's own state. Not verified beyond what the code
implies: every record above is bounded by the count of concurrent
sessions and in-flight logins, not by the size of an installation's
directory, and every one of them expires on its own.

## Signing keys across replicas

Every replica mounts the **same** Secret (`signingKey.existingSecret`, or
the one the chart's own `Certificate` produces) at the same path, and
polls it on an interval (`SIGNING_KEY_POLL_INTERVAL`, chart default `30s`
via `signingKey.rotation.pollInterval`). Rotation is live: cert-manager (or
whatever manages the Secret) replaces the key, the kubelet projects the
change to each pod on its own schedule, and every replica notices on its
next poll — no restart.

What keeps replicas from disagreeing about *when* to start using a
rotated key is the schedule in `internal/issuer/keyring.go`
(`KeyRing`/`KeyRings`), shared through the same `State` as sessions:

- **Publish before sign.** A newly observed key is published in the JWKS
  immediately, but a replica will not *sign* with it until
  `ActivationDelay` has passed (chart default `15m`,
  `signingKey.rotation.activationDelay`). This covers the slowest kubelet
  anywhere in the cluster projecting the same Secret update (documented as
  roughly a minute) plus the longest JWKS cache among verifiers (Envoy's
  `jwt_authn` default is 10 minutes and does not refetch on an unknown
  `kid`) — so no replica can hand out a `kid` a slower verifier's cached
  JWKS does not have yet.
- **Overlap on retirement.** A key that stopped signing stays published
  for `Overlap` past being superseded (chart default: the deployment's own
  token lifetime plus 5 minutes of clock-skew margin,
  `signingKey.rotation.overlap`) — long enough that a token minted a
  moment before rotation still verifies for its whole life.
- **First-writer-wins.** Whichever replica records a given key id *first*
  in the shared store decides its `ActivateAt`, once
  (`KeyRing.record`); every other replica — including this one on a later
  restart — reads back that same value rather than computing its own.
  That is what makes "every replica starts signing with a key at the same
  moment" actually true instead of an approximation.
- **A replica never signs with a key it cannot read.** `KeyRing.Active`
  falls back to the newest key this replica has itself read from disk if
  the schedule's chosen key is one it has only heard about from another
  replica (`absorb`) — logged as an anomaly, not the ordinary path.

**Multiple algorithms are independent tracks.** `signingKey.additional`
lets an installation sign more than one algorithm at once — RS256 for a
relying party that lags, ES384 for everything else, say — and each
algorithm gets its own `KeyRing`, its own Secret, its own mount path, and
its own namespaced keys in the shared store (`issuer:keyring:index:<alg>`,
`issuer:keyring:entry:<alg>:<id>`). Rotating one algorithm's key never
touches another's schedule. Two keys for the same algorithm at once is
refused, both by the chart's values validation and again in
`NewKeyRings` — a key ring can publish only one key per algorithm.

## The client-metadata-document cache is per replica

For clients that identify themselves by an HTTPS URL rather than a row in
the policy (`policy.ClientDocuments`), the fetched document is cached in
plain process memory — a `sync.Mutex`-guarded map on the resolver
(`internal/issuer/clientdoc.go`), never in Valkey — for 10 minutes
(`documentCacheFor`). This is deliberate for the failure case: a document
that cannot be fetched has **no stale fallback** and the flow fails rather
than honouring redirect URIs a client may have retired.

The consequence for more than one replica: each one fetches and caches
independently. A client that changes its own served document (its
redirect URIs, most likely) can be seen with the old values by one replica
and the new ones by another for up to 10 minutes — not a correctness bug,
since every fetch re-checks that the document's own `client_id` matches
the URL it was served from, but worth knowing before treating "it worked
when I retried" as a fluke.

## PodDisruptionBudget, anti-affinity, probes

**The chart renders neither a PodDisruptionBudget nor any pod
anti-affinity or topology-spread rule** (checked against
`charts/access-issuer/templates/`). An installation that wants replicas
kept off the same node, or wants to guarantee at least one stays up
through a voluntary disruption (a node drain, a cluster upgrade), adds
these itself, for example:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: access-issuer
spec:
  minAvailable: 1
  selector:
    matchLabels:
      # The chart's own selector labels (`access-issuer.selectorLabels` in
      # _helpers.tpl): the chart name and the release name together.
      app.kubernetes.io/name: access-issuer
      app.kubernetes.io/instance: <the release name>
```

**Anti-affinity or a topology-spread constraint cannot be added through
`values.yaml` at all.** The chart passes through `nodeSelector` and
`tolerations` (both rendered in `deployment.yaml`), but there is no
`affinity` or `topologySpreadConstraints` value anywhere in
`charts/access-issuer/values.schema.json` — and the schema's top level is
`"additionalProperties": false`, so a stray `affinity:` key at the top of
a values file is refused at render rather than silently ignored. An
installation that wants pods spread across nodes has to patch the
rendered Deployment itself (a Helm post-renderer, or `kustomize` over
`helm template`'s output) rather than express it as a chart value.

**Probes are rendered**, and split the same way readiness and liveness are
described above: `livenessProbe` calls `/healthz` and follows nothing
outside the process; `readinessProbe` calls `/readyz`, follows Valkey
(when configured), and is tuned so a timeout answers with the real reason
— "the session store does not answer" — before the kubelet's own timeout
would fire first (`timeoutSeconds: 3` against the service's own 2-second
check; `failureThreshold: 3` at `periodSeconds: 10`, so a replica leaves
rotation within thirty seconds of real trouble, comfortably longer than a
reconnect takes).

## Upgrades

The chart sets no explicit `strategy` on the Deployment, so a rollout uses
Kubernetes' own default rolling update. That is safe here specifically
*because* of the key ring: a new pod starting mid-rollout reads the same
mounted Secret every other replica does, computes the same schedule from
the same shared store, and either signs with the key already active or
waits out the same `ActivationDelay` every other replica already observed
— it never mints a `kid` the pods it is rolling alongside cannot verify.
Sessions and pending logins are unaffected by which pod is up at a given
moment, provided Valkey is configured; a rollout on the in-memory store
loses whatever that one replica was holding, which is the same
one-replica trade-off described throughout this page, just triggered by a
deploy instead of a crash.
