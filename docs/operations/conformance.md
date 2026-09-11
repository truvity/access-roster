# The conformance run

access-issuer claims three OpenID Foundation profiles, and the claim is
worth exactly what the suite says about it. This is how to run it.

> The exit criterion for `v1.0.0` is a green run of all three
> (INF-683). One of them runs unattended; two need a person at a
> browser, because the whole point of them is that a person signs in.

| profile | plan | attended |
| -- | -- | -- |
| Config | `oidcc-config-certification-test-plan` | no |
| Basic OP | `oidcc-basic-certification-test-plan` | yes |
| RP-Initiated Logout | `oidcc-rp-initiated-logout-certification-test-plan` | yes |

## The suite

Self-hosted from the published images, so there is no Java build:

```bash
git clone --depth 1 https://gitlab.com/openid/conformance-suite.git
cd conformance-suite
docker compose -f docker-compose-prebuilt.yml up -d
```

It answers at `https://localhost.emobix.co.uk:8443` — a public name that
resolves to `127.0.0.1`, which is how the suite gets a real hostname and
a real certificate while running on your machine. Wait for
`/api/runner/available` to return 200; the first start takes a minute.

Everything below drives it over its REST API, so a run is a script and
not a sequence of clicks. `-k` is there because the suite serves its own
certificate.

## Config — unattended

Needs no client and no browser: it reads the discovery document and the
key set, and checks them against the specification.

```bash
S=https://localhost.emobix.co.uk:8443
cat > config.json <<'JSON'
{
  "alias": "access-issuer-config",
  "description": "access-issuer — Config profile",
  "server": { "discoveryUrl": "https://access.truvity.xyz/.well-known/openid-configuration" },
  "client": { "client_id": "conformance", "client_secret": "unused-here" }
}
JSON

PLAN=$(curl -sk -X POST "$S/api/plan?planName=oidcc-config-certification-test-plan" \
  -H 'Content-Type: application/json' --data-binary @config.json | jq -r .id)
TEST=$(curl -sk -X POST "$S/api/runner?test=oidcc-discovery-endpoint-verification&plan=$PLAN" | jq -r .id)
curl -sk "$S/api/info/$TEST" | jq '{status, result}'
```

Change the discovery URL to point at whichever installation is under
test. Nothing about this run touches the installation's configuration.

**Last run: 2026-09-11 against `access.truvity.xyz`, on the merged
service at 0.12.2 — FINISHED / PASSED, 34 checks, no failures and no
warnings.** Worth repeating after anything that changes discovery, since
that is the whole of what it reads.

## Basic OP and RP-Initiated Logout — attended

These sign somebody in, so they need clients at the issuer and a person
to complete the flow at the provider.

### 1. Declare the clients

The plans want **three** client slots and they map onto **two** clients:

| slot | what it is |
| -- | -- |
| `client` | the primary client, authenticating with `client_secret_basic` |
| `client_secret_post` | the same client again — the library takes the credential from the Basic header *or* the form, so one confidential client serves both |
| `client2` | a second client, for the tests that check a code issued to one cannot be redeemed by another |

They are ordinary declared rows (INF-688) in the estate's access matrix,
under `roster.clients`, and they are **temporary**: add them for the run
and take them out afterwards. A standing client whose only purpose was a
certification is surface with no consumer.

```yaml
  - name: conformance
    # WITH THE PORT. A row names one host, port included, and the
    # redirects below are on :8443 — the render refuses the mismatch with
    # "not this client's host".
    hostname: localhost.emobix.co.uk:8443
    redirects:
      - https://localhost.emobix.co.uk:8443/test/a/access-issuer/callback
    signed_out:
      - https://localhost.emobix.co.uk:8443/test/a/access-issuer/post_logout_redirect
    requires: [all:access-roster:viewer]
  - name: conformance-2
    hostname: localhost.emobix.co.uk:8443
    redirects:
      - https://localhost.emobix.co.uk:8443/test/a/access-issuer/callback
    signed_out:
      - https://localhost.emobix.co.uk:8443/test/a/access-issuer/post_logout_redirect
    requires: [all:access-roster:viewer]
```

The alias in those paths (`access-issuer`) has to match the `alias` in
the test configuration below — the suite serves each test plan's
callback under its own alias, and a mismatch reads as the issuer
refusing the redirect.

**`requires` is mandatory** and these are no exception: the policy
refuses to load a client that requires no group, with *"client
%q requires no group, so nobody may use it"*. An earlier version of this
page said to leave it off, which would have failed the render before a
single test ran.

Name a group the person running the suite already holds.
`all:access-roster:viewer` is the bootstrap matcher that admits the
`truvity.com` domain, so it is the smallest thing that works here — the
tests sign in as a real person, and that person has to be admitted like
any other.

### 2. Read the secrets

They are generated in the cluster and never leave it, which is the
point. Read them at the moment you need them, and do not put them in a
file that outlives the run:

```bash
kubectl -n access-issuer get secret conformance-client \
  -o jsonpath='{.data.client-secret}' | base64 -d
```

### 3. Configure and run

```bash
S=https://localhost.emobix.co.uk:8443
cat > basic.json <<JSON
{
  "alias": "access-issuer",
  "description": "access-issuer — Basic OP",
  "server": { "discoveryUrl": "https://access.truvity.xyz/.well-known/openid-configuration" },
  "client":  { "client_id": "conformance",   "client_secret": "$FIRST_SECRET" },
  "client2": { "client_id": "conformance-2", "client_secret": "$SECOND_SECRET" },
  "client_secret_post": { "client_id": "conformance", "client_secret": "$FIRST_SECRET" }
}
JSON

curl -sk -X POST "$S/api/plan?planName=oidcc-basic-certification-test-plan&variant=%7B%22server_metadata%22%3A%22discovery%22%2C%22client_registration%22%3A%22static_client%22%7D" \
  -H 'Content-Type: application/json' --data-binary @basic.json | jq -r .id
```

Then run every module of the plan in order:

```bash
hack/conformance-run.sh <plan-id>
```

The suite's own page has no *run all* — each module is a separate click,
and Basic OP has thirty of them. The script starts them in order, waits
for each, and prints the result, so the clicking that is left is only the
part that needs a person. A module waiting for a sign-in says so with the
URL to open; `--from <module>` resumes after a failure instead of
re-running what already passed.

Or open the suite at `https://localhost.emobix.co.uk:8443`, find the
plan, and run its modules by hand. Each one that reaches a sign-in stops and
waits for you: a browser window opens on the issuer's chooser, you sign
in with Google as usual, and the test continues on its own.

The logout plan is **not** the same call. It takes a different set of
variants — `client_registration` and `response_type`, with no
`server_metadata` — and posting the Basic OP variant to it returns an
error with no plan id rather than a plan:

```bash
variant='%7B%22client_registration%22%3A%22static_client%22%2C%22response_type%22%3A%22code%22%7D'
curl -sk -X POST "$S/api/plan?planName=oidcc-rp-initiated-logout-certification-test-plan&variant=$variant" \
  -H 'Content-Type: application/json' --data-binary @basic.json | jq -r .id
```

`response_type=code` because this issuer serves only `code` — which is
the whole reason the other response types are absent from discovery. Ask
the suite rather than guess; `GET /api/plan/available` lists each plan's
variant keys and their permitted values.

### 4. Afterwards

- Export each plan's results from the suite and attach them to the
  ticket. A green run nobody kept is a green run nobody can check.
- **Remove the two client rows.** This is the step that gets forgotten,
  and it is the only one that leaves anything behind.

## What the run has already found

Pointing the suite at the live issuer is not a formality. It found that
a refused bearer at `/userinfo` carried no `WWW-Authenticate` header,
which RFC 6750 requires — a 401 a conforming client cannot act on,
written inside a dependency and invisible from our side of it. Fixed in
v0.10.0.

## What is deliberately not in the target

Token exchange is served and is **not** part of any profile claimed
here. It is now the only one: the device flow, JWT bearer and client
credentials were served through 0.11 and are gone (INF-693).

The reverse also has to hold, and since 0.11 it is the half worth
running: nothing this family's design names as *out* may be found
served. A grant withdrawn from discovery that goes on ANSWERING is the
failure that hides, because the metadata looks right. See
[../reference/access-issuer.md](../reference/access-issuer.md#endpoints).
