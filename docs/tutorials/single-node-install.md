---
title: "Tutorial: a single-node local installation"
description: "Run sluis on one workstation: Docker Compose, one rqlite node, software keys and signed config; sign in, verify a token and find the audit record."
status: target
sidebar:
  order: 0
---

:::caution
This tutorial describes the intended experience. It can't be run yet, because sluis v2 is not released. The `sluis` commands are those of the [command reference](/reference/cli/) for the first working version; a step whose command does not exist yet says so. Outputs are examples ([examples are illustrative](/integrations/#examples-are-illustrative)).
:::

You run the [local installation](/runtimes/#local) on one workstation: Docker Compose, one container per actor and per driver, an rqlite engine of one node, and software keys. It is the installation for development, continuous integration and the integration tests, and it runs the release's published images ([0011](/decisions/0011-runtimes-and-installations/#the-local-installation)). You finish with a running sluis at `https://sluis.local.test`, a boundary `dev` at `https://sluis.dev.local.test`, a sign-in through a real identity provider, a token you have verified yourself, and the audit record of your sign-in.

The tutorial is a test: it lives under `tests/tutorials` and runs in CI on the local installation, so a step that stops working fails the build.

## 1. Prerequisites

- A workstation with Docker and Docker Compose, and port 443 free on the loopback address.
- A checkout of `truvity/sluis` at a release tag. The local installation's files are under `tests/installations/local/`: the bootstrap file, the config documents and the Compose project. The Compose project is generated from the registries ([The local installation](/runtimes/local/#topology)) and is planned.
- The `sluis` binary for your workstation ([Binaries](/distribution/packages/#binaries)).
- A Chromium-based browser, used with a profile made for this project, and Python 3 with `pyjwt[crypto]`.
- Four lines in the hosts file, so the browser and the CLI reach the project by name ([Host names](/runtimes/local/#host-names)):

  ```text
  127.0.0.1 sluis.local.test
  127.0.0.1 sluis.dev.local.test
  127.0.0.1 idp.local.test
  127.0.0.1 app.local.test
  ```

## 2. Read the bootstrap file

store@ reads one local file at start, the [bootstrap file](/reference/bootstrap-file/): the boundary, a driver socket for each of its four ports, and the public keys of the publishers that sign config. Everything else is a signed config document. The local one, abridged:

```yaml
# Abridged from tests/installations/local/bootstrap.yaml
boundary: dev
start_timeout: 30s

config_source: { driver: file, socket: /run/sluis/store/dev/config-source.sock }
secret_source: { driver: credential, socket: /run/sluis/store/dev/secret-source.sock }
durable: { driver: rqlite, socket: /run/sluis/store/dev/durable.sock }
temp: { driver: rqlite, socket: /run/sluis/store/dev/temp.sock }

publishers:
  - kid: publisher-1
    public_key: |
      -----BEGIN PUBLIC KEY-----
      ...
    spki_sha384: "db0b54d4…6ece58"
```

- **One rqlite node serves both engine ports,** the engine of the boards with a cluster of one ([0005](/decisions/0005-the-store/#engines)).
- **The publisher pin is the trust anchor of config.** store@ verifies every config document against a key in this list before it parses it, and refuses any other ([Verifying a document](/reference/signed-config/#verifying-a-document)). At the first start the setup makes a publisher key of its own, writes its pin here and signs the config documents with it ([The first start](/runtimes/local/#the-first-start)).
- **A duration is written with a unit,** here and in every config document: one whole number and one of `s`, `m`, `h` or `d`, such as `30s` or `15m` for fifteen minutes, never an ISO 8601 string such as `PT15M` ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf), [Durations](/reference/bootstrap-file/#durations)).

## 3. Start the project

```sh
# Example
cd tests/installations/local
docker compose up --detach
docker compose wait setup
```

`setup` is a one-shot service that does the first start and exits 0 ([The first start](/runtimes/local/#the-first-start)): it makes ritueel's software test root, signs the config, runs `sluis key request`, has ritueel certify the boundary's intermediate, runs `sluis key install`, makes the forwarder's certificate, and checks the result with `sluis doctor` and `sluis key status`. The services that need the keys start when it has completed. Its log ends with the key status:

```text
# Example output
purpose            store     fingerprint      expires     warning
x509-intermediate  software  SHA256:5mQ1…Xk4  2027-12-03  none
token-signing      software  SHA256:Qe7w…2Lb  2027-12-03  none
audit-log          software  SHA256:Hk3p…9Vd  -           none
```

The keys are software keys. key@'s `software` driver refuses to start in a production boundary and warns in a staging one, so these keys guard development data only ([0006](/decisions/0006-keys-and-sealing/#floors-in-code)).

## 4. Check the configuration

`sluis config check` validates the bootstrap file and the config documents the way store@ does at start: the schema and protovalidate, every signature against the pinned publisher keys, the sequence, and the whole set against the registries ([`sluis config check`](/reference/cli/#sluis-config-check-and-explain)). Run it from the setup image:

```sh
# Example
docker compose run --rm --entrypoint sluis setup \
  config check /etc/sluis/config/dev --bootstrap /etc/sluis/bootstrap.d/dev.yaml
```

```text
# Example output
ok    bootstrap file: schema v1, publisher-1 matches its pin
ok    config documents: every signature verifies against a pinned publisher key
ok    snapshot: the set validates against the kind registry
ok    drivers fit the runtime (bare-metal, 1 node)
warn  audit: no witness; with no witness a compromised writer can get a rewritten checkpoint signed
```

The warning is expected: the local installation has no witness ([0011](/decisions/0011-runtimes-and-installations/#the-local-installation)). A `fail` line exits 3.

## 5. Trust the test root

The setup wrote the test root's certificate, `ca-bundle.pem`, to the project's trust volume. Import it into the browser profile you made for this project, never into the system trust store ([TLS](/runtimes/local/#tls)). For the CLI, point `SSL_CERT_FILE` at a copy of the same file. The root is marked `TEST ONLY`, its key is a file with no passphrase, and `docker compose down --volumes` deletes it.

## 6. Sign in

People sign in through an upstream identity provider, never through accounts in sluis. Here it is Keycloak, in the project at `https://idp.local.test`.

1. In Keycloak's admin console, add a user with a password and a one-time-password credential. The realm sends `amr` with `mfa` after the one-time password ([Sign-in](/runtimes/local/#sign-in)).
2. Give the user the subject value `u-1001`. The local policy binds the account `workforce/u-1001` to the grant name `dev:example-app:user` ([A worked example](/reference/policy/#a-worked-example)).
3. Sign in:

   ```sh
   # Example
   SSL_CERT_FILE=./ca-bundle.pem sluis login --issuer https://sluis.local.test
   ```

   The command opens a browser at the group issuer, which sends you on to Keycloak. If the default browser does not trust the test root, open the URL that the command prints in the project's profile.

```text
# Example output
signed in to https://sluis.local.test
subject  3d7c1e9a-5b2f-4c8e-9a41-0f6b2d8e7c15
```

The subject is an opaque random id that sluis assigned at your first sign-in, never your e-mail address ([0017](/decisions/0017-identity-and-sign-in/#subjects)). `sluis login` then exchanges your token silently at the `dev` boundary's own token endpoint ([`sluis login`](/reference/cli/#sluis-login-and-sluis-token)).

## 7. Get a token and verify it

```sh
# Example
SSL_CERT_FILE=./ca-bundle.pem sluis token --boundary dev --audience example-app > token.jwt
```

`example-app` asks for multi-factor authentication no older than 900 seconds, so a later run asks you to sign in again ([A worked example](/reference/policy/#a-worked-example)).

A sluis token is a standard JWS. Any JOSE library verifies it against the key set of the boundary's issuer, which exporter@ publishes as a static document; sluis needs no client library:

```python
# Example
import json, ssl, urllib.request
import jwt  # pip install "pyjwt[crypto]"

issuer = "https://sluis.dev.local.test"
ctx = ssl.create_default_context(cafile="ca-bundle.pem")
with urllib.request.urlopen(issuer + "/.well-known/openid-configuration", context=ctx) as r:
    jwks_uri = json.load(r)["jwks_uri"]

token = open("token.jwt").read().strip()
key = jwt.PyJWKClient(jwks_uri, ssl_context=ctx).get_signing_key_from_jwt(token)
claims = jwt.decode(token, key.key, algorithms=["ES384"], issuer=issuer, audience="example-app")
print(claims["sub"], claims["groups"])
```

ES384 is sluis's default. The issuer is the `dev` boundary's own, with its own keys: a token of `dev` is refused by a relying party that pins another boundary's issuer ([0017](/decisions/0017-identity-and-sign-in/#issuers)). Each key-set entry carries an `x5c` chain to the test root, which a careful verifier checks.

## 8. Find the audit record

Your sign-in and the token are audit records of the `dev` boundary's audit, written by the writer to its `fs` blob and indexed for search ([0011](/decisions/0011-runtimes-and-installations/#the-local-installation), [Audit](/concepts/audit/)). Each names you by a keyed pseudonym, not by subject or e-mail. The tutorial's test reads them back through the reader, as the integration tests do. Reading them from the command line, `sluis audit`, is planned ([Later commands](/reference/cli/#later-commands)).

## 9. Stop, or start again

```sh
# Example
docker compose down             # keeps the volumes: same root, issuers and keys next time
docker compose down --volumes   # deletes the root, the keys, the signed config and the data
```

After `down --volumes` the next `up` is a first start with a new root, and a browser profile that trusted the old root trusts nothing that exists any more.

## Next steps

- What you ran, in detail: [The local installation](/runtimes/local/), the [bootstrap file](/reference/bootstrap-file/) and [signed config](/reference/signed-config/).
- What runs inside: the [families](/concepts/families/), the [store](/concepts/data/#the-store) and [keys](/concepts/keys/).
- The tested installations with hardware keys and a cluster: [boards](/runtimes/#boards), on the [bare-metal](/runtimes/bare-metal/) runtime.
- The tested installations with cloud keys: [lambda](/runtimes/#lambda), on the [serverless](/runtimes/serverless/) runtime, and [kubernetes](/runtimes/#kubernetes), on the [kubernetes](/runtimes/kubernetes/) runtime, which runs the same images from one Helm chart.
- The way back in when sign-in fails: [Break-glass recovery](/security/break-glass/).
