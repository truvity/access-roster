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
    hostname: localhost.emobix.co.uk
    redirects:
      - https://localhost.emobix.co.uk:8443/test/a/access-issuer/callback
    signed_out:
      - https://localhost.emobix.co.uk:8443/test/a/access-issuer/post_logout_redirect
  - name: conformance-2
    hostname: localhost.emobix.co.uk
    redirects:
      - https://localhost.emobix.co.uk:8443/test/a/access-issuer/callback
    signed_out:
      - https://localhost.emobix.co.uk:8443/test/a/access-issuer/post_logout_redirect
```

The alias in those paths (`access-issuer`) has to match the `alias` in
the test configuration below — the suite serves each test plan's
callback under its own alias, and a mismatch reads as the issuer
refusing the redirect.

Neither declares `requires`: a certification run is not a role, and
gating it on one would fail every test for a reason that has nothing to
do with the specification.

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

Then open the suite at `https://localhost.emobix.co.uk:8443`, find the
plan, and run its modules. Each one that reaches a sign-in stops and
waits for you: a browser window opens on the issuer's chooser, you sign
in with Google as usual, and the test continues on its own.

The logout plan is the same with
`planName=oidcc-rp-initiated-logout-certification-test-plan`.

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
