---
title: The local installation
description: "The local installation in detail: Compose with one rqlite node, host names, TLS, the first start and sign-in, with the measurements behind each choice."
status: target
sidebar:
  order: 5
---

The [local installation](/runtimes/#local) is Docker Compose on one workstation, with software keys and an rqlite engine of one node, for development, continuous integration and the integration tests ([ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)). This page fixes what the Compose project holds, the host names it uses, how a browser comes to trust it, and what happens at the first start. Its bootstrap file is the example on the [bootstrap file](/reference/bootstrap-file/) page, and its configuration is a directory of signed config documents that store@ verifies against a publisher key pinned in that file, as on any installation ([ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)). Everything outside sluis's own containers, the forwarder, the identity provider and the setup, belongs to the **harness**: files that ship beside the bootstrap file, and no code of the product (a development installation differs by configuration only, [Principles](/principles/#what-sluis-is-and-is-not)).

## Topology

```mermaid
flowchart LR
  b["Browser or<br/>test harness"] -- "https" --> f["forwarder<br/>(TLS ends)"]
  f -- "Unix socket" --> e["entry"]
  f -- "http" --> i["idp<br/>(Keycloak)"]
  e --> a["actors and<br/>drivers"]
  a -- "https" --> f
```

| Service | Image | What it is |
|---|---|---|
| The actors and drivers | The release's images | One container per actor and per driver, generated from the registries: the foundation (store@, key@ and exporter@) with their drivers, the work actors, the audit pieces `writer`, `indexer` and `reader`, `adapter-upstream-oidc`, and the drivers the bootstrap file names. `entry`'s container has no network |
| `rqlite` | The pinned rqlite release | The engine, one node, beside store@. Its client API is on the loopback address, and the driver's container shares rqlite's network namespace (`network_mode: service:rqlite`), so the driver is its only client ([ADR 0005](/decisions/0005-the-store/#engines), [ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)) |
| `forwarder` | Caddy, pinned by digest (v2.11.7, released 2026-10-03) | Ends TLS for every host of the project and forwards by `Host`: the sluis hosts to the socket of the `entry` that serves them, `idp.local.test` to `idp`, `app.local.test` to the harness's relying party. The only service that publishes a port, on the loopback address. Containers reach it by the host names too, as network aliases |
| `idp` | Keycloak 26.8.1 (released 2026-10-13), from a reviewed realm-import file | The upstream identity provider, on plain HTTP behind the forwarder. Users and groups are created per test through its admin API, and the realm sends `amr` ([Sign-in](#sign-in)). Dex v2.46.1 (2026-10-21) can run in its place, for an upstream that sends no `acr`, `amr` or `auth_time` |
| `setup` | The harness image, with the `ritueel` release and `sluis` | A one-shot service that does the [first start](#the-first-start) and exits. Every service that needs the keys or the trust files waits for it to complete |

- **The images' dependencies are in one matrix,** [Runtime dependencies](/distribution/dependencies/): a static executable on distroless static, rqlite on a glibc base, and for the opt-in development card a card driver image that is not built yet, with pcscd on the host.
- **The forwarder serves the key set that exporter@ publishes.** The directory driver of exporter@ writes `jwks` to a volume that the forwarder mounts read-only; for `/jwks` on the boundary's host the forwarder answers from that file with `Cache-Control: public, max-age=300` and `Access-Control-Allow-Origin: *` <!-- terms-allow: origin (the CORS header name) -->, and when the file is missing (before exporter@ has written it) the request goes on to `entry`, whose live key set is the fallback and leaves out revoked kids too ([ADR 0009](/decisions/0009-export/#publishing-public-material), [REQ-EXPORT-025](/requirements/export/#REQ-EXPORT-025)). The directory declares no public address, so the report says `written` and `signer` counts the lead time from the write. exporter@ reads its destinations from `tests/installations/local/exporter/destinations.json`, a file in the form of the `ExportDestination` message, until store@ serves that kind.
- **The forwarder is a generic reverse proxy, not a sluis component.** It is the local counterpart of Cloudflare's edge, of `cloudflared` and of the Gateway in front of the edge relay: public TLS ends at the edge, and the edge relay and `entry` stay key-less ([Deployment](/architecture/deployment/#listeners)). Nothing depends on it being Caddy: it is TLS in, HTTP over a Unix socket out, routed by `Host`. Caddy was picked for its short configuration; nginx would do the same.
- **The forwarder's certificate is not sluis's.** In production the edge holds a certificate that sluis did not issue. Locally it holds one from the harness's `edge` intermediate, certified by the same ritueel root as sluis's own intermediates ([TLS](#tls)).
- **The Compose file is generated from the registries,** like the systemd units, with the uids pinned ([ADR 0011](/decisions/0011-runtimes-and-installations/#consequences)). The harness services are written by hand beside it.

## Recipes

Run each as `devbox run -- just <recipe>`. The project needs Docker, and `SLUIS_UPSTREAM_TARGET` and `SLUIS_KEYCLOAK_SECRETS` in the environment; the repository names neither value.

| Recipe | What it does |
|---|---|
| `local-up` | Builds the executables and the images (or, with `SLUIS_LOCAL_IMAGES=release`, pulls those of a release, see [Images](#images)), makes the state of the run (harness CA, signed config, credentials) and starts the project; returns when every service that has a health check is healthy |
| `local-handoff`, `local-handoff-check` | The hand-off of the boundary's intermediate, which `local-up` ends with ([The first start](#the-first-start)): `sluis key request` against key@, a throwaway root certifies, `sluis key install`. `local-handoff` changes nothing once the intermediate is installed; `local-handoff-check` fails if a second run makes, issues or installs anything anew (it counts the audit records of the install of the intermediate only: `ca` has key@ keep the token certificate with a fact of the same action, for the purpose `token-signing`). The `smokes` job of CI runs the check |
| `local-smoke` | The M1 proof: a client under the uid of `exchange` asks `policy` for a `token.exchange` decision and `signer` for a token; the token is checked against `/jwks` through the forwarder, trusting only the harness CA; the records of the run are found in the audit log; `sluis audit verify` checks the log; `SigningRing` and `DataKeyWrap` are read through store@. The `smokes` job of CI runs it on every pull request |
| `local-keyset-check` | The key set that `/jwks` serves: every key carries an `x5c` chain of the token certificate, the intermediate and the root, and it verifies to the root of the hand-off. `local-up` runs it after the hand-off, with a wait, since `ca` makes the token certificate once the intermediate is installed |
| `local-person-smoke` | The M2 proof: `sluis login` signs a person in through the forwarder, `entry`, `session`, the upstream adapter and the identity provider, and `sluis token` exchanges the token for an audience. It then exchanges the same token as the confidential client `example-app`, which authenticates with its secret (HTTP Basic), after a wrong secret has been refused with `invalid_client`. It also checks that the ID token's `sub` and the exchanged token's `sub` are the same pairwise subject, asks for `prompt=none`, `max_age` and `prompt=login` of the identity provider (a silent code for a signed-in browser, `login_required` for one that is not, a form shown again for `login`), finds the audit record of every step and runs `sluis audit verify`. `session` seals the facts of the session chain under the tenant's `chain` key; `session` opens them again at a refresh and `exchange` opens them for a token exchange, and no other actor does either ([0006](/decisions/0006-keys-and-sealing/#data-keys)). The `smokes` job of CI runs it on every pull request |
| `local-deny` | The deny matrix ([ADR 0002](/decisions/0002-families-of-actors/)): for every caller and every socket, a probe as the caller's uid checks the call graph at the socket and at the guard. It starts a Compose project of its own and removes it, and leaves a `local-up` project alone. The matrix is the Go test `TestDenyMatrix`, and the `deny` job of CI runs it on every pull request, with a Keycloak container serving an empty realm as the upstream |
| `local-down` | Stops the project and deletes its volumes and the state of the run |

- **The firewall.** A host firewall may let a container reach the upstream from some Docker subnets only. The Compose project of `local-up` has a free /24 of `10.99.0.0/16`, chosen from the project name (`SLUIS_LOCAL_SUBNET` overrides it), because the subnet Docker picks may be one the firewall drops; the deny matrix, which runs its own project, takes `SLUIS_DENY_SUBNET` (for example `10.99.0.0/24`) to put its network on a subnet the firewall allows.

## Images

`local-up` builds every executable and image from the checkout by default, which is what a change to the code is judged by. The installation also runs the images of a release, the published ones, and then builds nothing ([0013](/decisions/0013-release-train-packaging-and-distribution/#packaging-per-runtime)):

```sh
# Example
SLUIS_LOCAL_IMAGES=release SLUIS_LOCAL_VERSION=2.0.0-alpha.1 devbox run -- just local-up
```

- **The same services.** `deploy/local/compose.release.yaml`, generated beside `compose.yaml`, goes after it and gives each service of sluis the image of the release that holds its executable (`ghcr.io/truvity/sluis/actor-store`, `driver-store-rqlite`, and `vendor-rqlite` for the engine), drops its build, and runs the executable at its install path, `/usr/libexec/sluis/actors/<name>` or `/usr/libexec/sluis/drivers/<owner>/<name>`. The uids, groups, mounts and commands are those of `compose.yaml`.
- **By tag or by digest.** `SLUIS_LOCAL_VERSION` is the tag of the release, without the `v`. `SLUIS_RELEASE_IMAGES` names the `release-images.txt` of the release (a file or an `https` URL) and pins every image by its digest instead; that is the way to reproduce a release exactly. `SLUIS_IMAGE_PREFIX` moves the namespace, which is how a registry mirror or a throwaway registry is used.
- **Proved when a change can affect the release.** The job `release` of CI builds the release as a tag would, pushes the images to a registry on the runner, starts this installation from them by digest, with nothing built, and runs both smokes against it; a push to `main` always runs it ([Releasing](/distribution/packages/#releasing)).

## Host names

| Host | Serves | Resolved to |
|---|---|---|
| `sluis.local.test` | The group issuer, the console and the front's API | `forwarder` |
| `sluis.dev.local.test` | The `dev` boundary's issuer | `forwarder` |
| `idp.local.test` | The upstream identity provider | `forwarder` |
| `app.local.test` | The example relying party the tests drive | `forwarder` |

The passkey relying-party ID is `local.test`, the registrable parent of every host, as in production ([ADR 0017](/decisions/0017-identity-and-sign-in/#passkeys)).

- **Why `.test`.** RFC 6761 reserves `.test` for testing: nobody can register a name under it, so the installation can never collide with a real one, and it lives outside the sluis host names as a test installation must ([ADR 0017](/decisions/0017-identity-and-sign-in/#issuers)). The RFC tells software not to treat `.test` as special and tells caching resolvers to answer it with an immediate negative ([RFC 6761, section 6.2](https://datatracker.ietf.org/doc/html/rfc6761#section-6.2), February 2013), so a name has to be mapped by the harness. That is a feature here: the mapping is the one place that says "this is a test".
- **Inside the project,** Compose gives `forwarder` the four names as network aliases, so the actors, Keycloak and the harness's clients reach each host by its name and cross the same TLS as a browser.
- **A test harness** points its browser at the published port with a name mapping, for Chromium `--host-resolver-rules="MAP *.local.test 127.0.0.1:<port>"`, so the URLs carry no port and the issuer stays `https://sluis.local.test`. A developer's own browser uses four lines of the hosts file for `127.0.0.1` and the project published on port 443.

### The dev domain: names for the nightly runs

The `.test` names above serve the runs that need no vendor. The nightly and pre-release runs sign in through the vendors' free test tenants ([Sign-in](#sign-in)), and a vendor must be given a redirect address that its own rules accept. Google requires that "Host TLDs (Top Level Domains) must belong to the public suffix list" and that "Hosts cannot be raw IP addresses" ([Google, Using OAuth 2.0 for web server applications](https://developers.google.com/identity/protocols/oauth2/web-server), READ 2026-11-02), and `test` is not a public suffix. Microsoft Entra requires `https`, with an exception for localhost only ([Microsoft, redirect URI best practices and limitations](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url), READ 2026-11-02). So the redirect addresses registered at the tenants are names under a real domain, which the browser must reach.

**The rule** (decided by the maintainer on 2026-11-02):

- **The browser-facing names of the nightly runs are the hosts of the table above, under a configurable dev domain** instead of `local.test`: `sluis.<dev domain>`, `sluis.dev.<dev domain>` and `app.<dev domain>`. There is no `idp` host: the vendor's tenant is the identity provider.
- **The setting is `SLUIS_DEV_DOMAIN`,** an environment variable of the harness, named like the other `SLUIS_` settings of the repository (for example `SLUIS_TARGET`). Only the runs against a vendor's tenant read it. A pull-request run and a developer's local run do not: they keep the `.test` names.
- **The public default is a nip.io name: `127.0.0.1.nip.io`,** so the front host is `sluis.127.0.0.1.nip.io`. Anyone can register `https://sluis.127.0.0.1.nip.io/…` at their own Entra or Google tenant and reproduce the run, with no domain of their own.
- **The project's own CI sets `SLUIS_DEV_DOMAIN` through its CI configuration,** to a domain it controls. That domain is never written in this repository, its documents, its tests or its commit messages.

**What does not change.** The `.test` names, and the harness's `forwarder` that serves them in the pull-request runs, stay as they are. A browser and a container must see the same names: the issuer is a URL that both read, so the forwarder carries every host of the run as a network alias, whatever the domain. nip.io does not change that; a name that resolves to `127.0.0.1` points a container at itself, so inside the project the alias has to answer for it, as it does for `.test`. The leaf of the run is made for the names under the domain in use, and the name constraint of `edge` (the one that waits on ritueel, [below](#sign-in)) is the domain in use too.

**The limits of nip.io.**

- **It is a third-party DNS service with no guarantee.** It answers a name that has an address in it with that address: `www.192.168.0.1.nip.io` gives `192.168.0.1` (READ 2026-11-02, [nip.io](https://nip.io)). The page states no uptime guarantee or service terms. A nightly run that fails to resolve the name is a failure of the service, not of sluis, and a team that needs certainty sets `SLUIS_DEV_DOMAIN` to a domain it controls.
- **A resolver with DNS-rebinding protection can refuse the name,** because the answer is a loopback address. dnsmasq, which many routers and home gateways run, rejects "addresses from upstream nameservers which are in the private ranges" with `--stop-dns-rebind`, and `--rebind-localhost-ok` exempts "127.0.0.0/8 and ::1 from rebinding checks" ([dnsmasq manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html), READ 2026-11-02). Unbound has no private addresses by default, and `private-domain` allows one domain "and all its subdomains" to contain them when `private-address` is set ([Unbound `unbound.conf`](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html), READ 2026-11-02).
- **What to do when the name is refused,** in this order:
  1. In the test harness's browser, skip DNS: Chromium's `--host-resolver-rules="MAP *.127.0.0.1.nip.io 127.0.0.1:<port>"` maps the names as it maps `.test` above, and the resolver is never asked.
  2. For a developer's own browser, add the hosts to the hosts file, as for `.test`.
  3. Or allow the domain at the resolver: `rebind-domain-ok=/nip.io/` for dnsmasq, `private-domain: "nip.io"` for Unbound.
  4. Or set `SLUIS_DEV_DOMAIN` to a domain you control.

The vendor still needs the redirect address to be a name it accepts, so the registration at the tenant is made once with the dev domain in use; the browser never needs the vendor to resolve it.

### A virtual authenticator accepts `local.test`

The WebAuthn specification lets a page claim an RP ID that is "a registrable domain suffix of or is equal to the caller's origin's effective domain" ([Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/), W3C Recommendation of 25 August 2026, read 2026-11-01). Chromium decides "registrable" with its list of registries and counts an unknown top-level domain as one: `OriginIsAllowedToClaimRelyingPartyId` calls `HostHasRegistryControlledDomain` with `INCLUDE_UNKNOWN_REGISTRIES`, and refuses a claimed ID no longer than the caller's registry ([`webauthn_security_utils.cc`](https://github.com/chromium/chromium/blob/main/components/webauthn/core/browser/webauthn_security_utils.cc), last changed 2026-10-12, read 2026-11-01). So `test` is a registry and `local.test` is registrable.

That was measured, not only read, on 2026-11-01: Chrome 156.0.8078.79, headless, with the virtual authenticator of the [DevTools protocol](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/) (CTAP2, internal, resident keys, user verification on), against a TLS server whose chain ends in a root that was trusted in a throwaway profile. Each row is one registration followed by one assertion.

| Page | RP ID | Result |
|---|---|---|
| `https://sluis.local.test` | `local.test` | works |
| `https://sluis.dev.local.test` | `local.test` | works: the credential is the same for both hosts |
| `https://sluis.local.test` | `sluis.local.test` | works |
| `https://sluis.dev.local.test` | `sluis.local.test` | refused: not a registrable suffix of the page's host |
| `https://sluis.local.test` | `test` | refused: the registry itself |
| `https://sluis.local.test` | `other.test` | refused |
| `https://sluis.local.test` | `dev.local.test` | refused: not a suffix of the page's host |
| any of the above, root not trusted | | not a secure context: the certificate error stops the API before the RP ID is looked at |

The last row is why TLS matters here: WebAuthn is exposed only in secure contexts, "established without errors" (the same specification), so a browser that does not trust the chain cannot test a passkey at all. `--ignore-certificate-errors` is not a substitute; a real chain tests the real path, including the intermediate's name constraints.

## TLS

The chain a browser sees is `root` (ritueel's software test root), `edge` (an intermediate, name-constrained to `local.test` once ritueel checks DNS names; see the note before the limits) and a leaf for the four hosts.

1. **The root** is the software root that `ritueel init --test-root` makes in the setup. It is marked `TEST ONLY` in its name and in every product, and ritueel refuses to mix it with a real root ([Commands](https://ritueel.id/reference/cli/#the-first-versions-commands)). Its key is a file in a volume of the project, with no passphrase.
2. **`edge`** is the harness's own intermediate. The setup makes a P-384 key, a request and a proof for the hand-off with `openssl`, and ritueel certifies it as the entry `edge` of its `ritueel.yaml`, the way it certifies `sluis-dev`, the intermediate of `sluis key request`. A software key is accepted by the hand-off contract when the policy says it is the development setting ([the contract](https://ritueel.id/reference/hand-off-contract/#software)).
3. **The leaf** is made by the setup with the `edge` key: `serverAuth`, DNS names for the four hosts, valid for seven days, made again at the next `up` when less than a day is left. The forwarder serves the leaf and `edge`.
4. **Trust is per run.** The root's certificate, from `ritueel bundle build`, goes to:
   - the project's containers, as the system bundle of their images, read-only;
   - the test harness's browser, in a throwaway profile. Chromium on Linux reads an NSS database in `$HOME/.pki/nssdb`, so the harness gives the browser a home of its own with the root imported (the measurement above did this) and deletes it with the run;
   - a developer's own browser, in a separate profile made for the project. The system trust store of the machine is not touched.
5. **`down -v` deletes the root's key,** and the next `up` makes a new root. A browser profile that trusted the old one trusts nothing that exists any more.

### Roads not taken for TLS

- **mkcert.** It installs a root into the system, Firefox and Java trust stores of the developer's machine and keeps its key beside it; its own README says that file "gives complete power to intercept secure requests from your machine" ([mkcert](https://github.com/FiloSottile/mkcert), last release v1.4.4 of 2022-04-26). It would also be a second root beside ritueel's, so the local run would not test the chain that the other installations use (sluis makes no root, [ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#sluis-holds-no-root)), and its certificates carry no name constraint. A test root that is trusted for a run, by a profile that is thrown away, does what mkcert does with none of that reach.
- **A certificate from sluis's `ca` for the forwarder.** Public TLS ends at the edge, and the certificate there is never the internal CA's in production; `ca`'s name constraints and leaf profiles are for the actors and hosts of the boundary ([ADR 0023](/decisions/0023-certificate-authorities/#leaf-profiles)). The forwarder is the edge.
- **Certificate errors switched off in the browser.** They would also switch off the secure context the passkey tests need to be honest about, and the name constraints.
- **Plain HTTP on `localhost`.** A browser treats `localhost` as a secure context, but an issuer must be an `https` URL and the relying-party ID would be `localhost` ([below](#roads-not-taken-for-names)).
- **A tunnel to a public name.** It needs an account and a network, and it would put the installation on a name that is not a test name.

### Roads not taken for names

- **`*.localhost`.** Browsers resolve it to the loopback address with no mapping, which is attractive. Measured on 2026-11-01 as above: `https://sluis.localhost` cannot claim the RP ID `localhost`, because a name with no registrable parent cannot be shared, so the two hosts of ADR 0017 would need two RP IDs, two passkeys and a different design from production. Only `https://sluis.dev.localhost` with RP ID `dev.localhost` worked, and then the front host could not share it.
- **`*.internal`.** ICANN reserved it for private use in 2024, and [ADR 0023](/decisions/0023-certificate-authorities/#the-intermediates-name-constraints) uses it for the private zones of real environments. A test installation must not look like one, and a developer's network may serve a real `.internal` zone.
- **`*.example` or a subdomain of a name sluis owns.** `.example` is reserved for documentation and `example.com` is not ours to resolve; a name under a real domain breaks "a test installation lives outside the sluis host names".

## The first start

`docker compose up` starts the project. The `setup` service runs these steps in order, and each step is skipped when its output already exists, so a second `up` changes nothing:

1. **Make the root.** `ritueel init --store software --roots 1 --test-root --key-dir /ritueel/keys`, with the `ritueel.yaml` of the example directory, which declares two intermediates: `sluis-dev` and `edge`. This writes the root, the first trust products (`root-list.json` and `root-list.jws`, `ca-bundle.pem`) and the key file.
2. **Publish the trust files.** The CA bundle goes into the `TrustAnchors` config document of the project, with the root list beside it, which is optional ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-floor)). The bundle is also the trust bundle the containers read.
3. **Sign the configuration.** The setup makes a publisher key of its own, writes its SPKI hash into the bootstrap file as the pin, and signs the config documents of the example directory with it, into `/etc/sluis/config/dev/`, the directory of the `file` driver ([Signed config](/reference/signed-config/#the-document)). store@ verifies every document against that pin before it parses it ([ADR 0005](/decisions/0005-the-store/#configuration-loading)), as it does on any installation. key@ reads the same pin from the bootstrap file, read-only, and verifies the `KeyPlan` against it itself ([ADR 0006](/decisions/0006-keys-and-sealing/#who-may-receive-a-wrap)).
4. **Ask for sluis's keys.** `sluis key request --boundary dev --trust-domain dev.example.org --dns-zone dev.example.org --out /requests` asks key@ for the key of the boundary's intermediate, which it made in the `software` store when it started, and writes `dev-x509-intermediate.csr.pem` and its proof ([Commands](/reference/cli/#the-key-commands)). The names are the boundary's trust domain and DNS zones.
5. **Have the intermediate certified.** `ritueel intermediate add sluis-dev --request dev-x509-intermediate --key-dir /ritueel/keys`, in the two runs of a script's ceremony: `--plan-only`, then the plan with `--confirm` and its digest ([ritueel commands](https://ritueel.id/reference/cli/#a-scripts-ceremony)). A test root asks no passphrase.
6. **Install the answer.** `sluis key install /ritueel/dir/answers --boundary dev --requests /requests --ca-bundle /ritueel/dir/trust/ca-bundle.pem` checks the certificate against the anchors (pass ritueel's signed root list with `--root-list /ritueel/dir/trust/root-list.json` and the pin of its root with `--root-pin`, the `x509_spki_sha256` that `ritueel init` printed; `--root-list` is refused without a pin) and installs it through key@. The token certificate is then issued on the node by the new intermediate, and `signer` writes the key set, the kind `SigningRing`, which exporter@ publishes as a static document to its directory destination ([ADR 0009](/decisions/0009-export/#destinations)). The setup renders the discovery document from the boundary's config and publishes it beside the key set, the part that infrastructure code does in the other installations ([ADR 0017](/decisions/0017-identity-and-sign-in/#issuers), [ADR 0009](/decisions/0009-export/#what-is-exportable)).
7. **Make the edge.** The `edge` key, request and proof, certified in the same two runs, and then the leaf for the four hosts. The forwarder starts when `leaf.pem` exists.
8. **Check.** `sluis doctor --boundary dev` and `sluis key status --boundary dev` run as root and must exit 0 ([`doctor`](/reference/cli/#sluis-doctor), [the key commands](/reference/cli/#the-key-commands)), and the setup fetches `https://sluis.dev.local.test/.well-known/openid-configuration` and the key set through the forwarder, which proves the chain, the names and the static documents at once. It then exits 0.

:::caution[Waiting on ritueel]
**Steps 1, 2 (the root list), 5 and 6 run today with a stand-in.** ritueel's repository holds the hand-off contract and its test vectors and no program yet, so its software-root mode, which CI is meant to run, does not exist (checked 2026-11-07). `deploy/local/local.sh up` therefore ends with the hand-off, in this order, and `just local-handoff` runs it again:

1. `tools/harness/certifier init` makes a throwaway software root for the run, in `.cache/local/root`, and writes the CA bundle, the signed root list and the root's pin (`trust/root.pin`). Nothing of it is in the repository: the key is made at setup, in a file with mode 0600 that no container mounts, and `down` deletes it. The root says `TEST ONLY` in its subject, and its name constraints are critical: DNS names and URI hosts under `local.test`, mail addresses at `local.test`, and no IP address at all (both families excluded). A chain from it therefore verifies for no name outside `local.test` of any kind (tested with Go's verifier for each kind), and no verifier that trusts a production root trusts it. Its root list names a placeholder OpenPGP fingerprint of zeros, because it has no OpenPGP primary.
2. The real `sluis key request --boundary dev --trust-domain dev.local.test --dns-zone dev.local.test` runs against the real key@, as root, in a one-shot container with no network, so the request and its proof are made by the key the installation holds.
3. `tools/harness/certifier certify` answers the request: it runs the contract's checks 1 to 5 on it with the kit's own code (`kits/go/handoff`), accepts the software store only, checks that the request asks for the three extensions of an intermediate with critical name constraints, issues a certificate valid for 13 months with the requested extensions, and reads the answer back with the requester's checks before it keeps it. It is not ritueel: it has no `ritueel.yaml`, no ceremony, no attestation check, and it refuses a card or KMS request that ritueel would accept (`store-not-allowed`).
4. The real `sluis key install` checks the answer against the CA bundle, the root list and the root's pin, and installs it through key@. A second start finds the request, the answer and the installed chain and changes nothing.

The KeyPlan source in the repository does not list `x509-intermediate`: `local.sh` adds the entry (slot 9c) to the copy it signs, because the boards sign a plan from the same source and the board run adds the key there deliberately. The root and its root list last a year at most; a run kept longer makes a new root at its next start, which leaves the installed intermediate under the old one, so `down` and start again.

**The CLI comes first.** The hand-off runs the `sluis` command-line tool, from `dist/local/bin/cli/sluis` or the file `SLUIS_LOCAL_CLI` names. A build puts it there. A run from the images of a release (`SLUIS_LOCAL_IMAGES=release`) builds nothing, so the tool is unpacked from the release archive before `local-up`, and `up` stops at the hand-off with a message naming the missing file otherwise. **The volumes and the state go together.** The request, the answer and the root are in `.cache/local`, the key they are for is in the project's key volume. If the volumes are made again and the state is kept, `up` says so and stops (the answer would be refused as `key-mismatch`); `just local-down` clears both.

A board needs the same flow with a card: `key request` on the board signs the request through the card and carries the attestation chain, and the certifier must check that attestation and the card's slot policy, which this stand-in does not. That is a job for ritueel, or for a card-aware extension of the stand-in; it is on the board run list, not in this change.
:::

The services that need the keys start when `setup` completes (`service_completed_successfully`). A failure of any step stops the project at that step with the command's own exit code and message; nothing starts on a half-made root.

**What persists.** The volumes hold the ritueel directory, the key file, the trust files, the signed config, the software keys and the rqlite data. `docker compose down` keeps them, and the next `up` starts with the same issuers and keys. `down -v` removes them all, and the next `up` is a first start with a new root.

## Sign-in

Tests sign in through the upstream identity provider, never through accounts in sluis ([ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)).

- **Every pull request: Keycloak,** from the reviewed realm-import file, `tests/installations/local/idp/realm.json`. `tests/installations/local/idp/start.sh` (`just local-idp`) imports it into a Keycloak container with secrets made for the run, and writes the secrets file that `SLUIS_KEYCLOAK_SECRETS` names; the `smokes` job of CI does so before `local-up`. The realm has the user `alice`, with a password and a one-time password. A test creates its users and groups through the admin API, and the harness drives the sign-in over HTTP with a client that follows the redirects, with no browser. The realm-import file makes every ID token carry `amr`, so the local multi-factor rule (`context.amr.contains("mfa")`) passes on every pull request ([REQ-TEST-010](/requirements/test/#REQ-TEST-010)):
  - **The mapper.** The client of the harness has the "Authentication Method Reference (AMR)" protocol mapper, which Keycloak has had since version 24 (READ 2026-11-02). Without it Keycloak sends no `amr`.
  - **The reference values.** In the browser flow, the password execution has the reference value `pwd`, the one-time-password execution has `otp`, and the step after it adds `mfa`. Each test user is created with a one-time-password credential, and the harness computes its code ([RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)).
  - **The test users are bound by `sub`.** The upstream's subject claim is `sub`, the user's id in the realm, never the user name ([REQ-SUBJ-044](/requirements/subj/#REQ-SUBJ-044)). Keycloak makes the id when it imports the user, so the policy source names a test user as `{{sub:alice}}`: at `local-up` the harness reads each user's id through the admin API, as the realm's bootstrap administrator, and fills it in before it signs the `Policy` document; a placeholder left unfilled is not signed. The deny matrix, whose realm is empty and where nobody signs in, gives each user a random UUID that no account has.
  - **`default.reference.maxAge` is set on each execution.** Its default, 0, makes Keycloak add `amr` only when the token is minted in the same second as the authentication (Keycloak issue 54497, READ 2026-11-02), so a token minted a moment later has no `amr` and the test fails at random. The realm sets a value that outlasts a test run, and a test mints its token later than a second after the authentication to pin the trap.
- **Passkeys: a browser.** The test that registers and uses a passkey runs in a Chromium that has a virtual authenticator and the root trusted as above, for the front host and a boundary host, with the RP ID `local.test`. A software authenticator library drives the same ceremony without a browser ([ADR 0017](/decisions/0017-identity-and-sign-in/#passkeys)).
- **Optionally: Dex,** as an upstream that sends no `acr`, `amr` or `auth_time`, to prove that a missing value is treated as unknown ([Policy](/reference/policy/#context)).
- **Nightly and before a release:** the two free cloud tenants, outside this project, on the private runner group ([#891](https://github.com/truvity/sluis/issues/891)). They check the vendors' own `amr` values. Entra adds `amr` to the ID token only when the app registration lists it as an optional ID-token claim, so the nightly app registration does (a one-time-password sign-in then gives `totp` and `mfa`; READ 2026-11-02). The redirect addresses registered at the tenants are on the names of [the dev domain](#the-dev-domain-names-for-the-nightly-runs), not on `local.test`. Google adds `amr` and `auth_time` only when the request carries a `claims` parameter, which the generic upstream cannot send yet ([#1154](https://github.com/truvity/sluis/issues/1154)).

:::caution[Waiting on ritueel]
**DNS names in ritueel's policy.** ritueel's `ritueel.yaml` limits the name constraints of an X.509 intermediate request to `permitted_uri_hosts`, URI hosts. The `edge` intermediate is constrained to a DNS subtree, `local.test`, and so is the DNS part of the constraints of `sluis-dev` ([ADR 0023](/decisions/0023-certificate-authorities/#the-intermediates-name-constraints)). Until ritueel's policy lists DNS subtrees and checks them, the constraint of the `edge` entry waits: ritueel cannot check it, so nothing it certifies for `edge` is constrained by its policy, and the constraint described on this page takes effect when ritueel has the change. The wait is on a change in ritueel, tracked in [truvity/ritueel#70](https://github.com/truvity/ritueel/issues/70).
:::

## Limits

The limits of the installation are on [Runtimes](/runtimes/#local): a software key can be read by anyone who can read its volume, one node proves behaviour and not availability, and the platform controls of the other installations are not exercised. The test root is the extra limit of this page: its key is a file with no passphrase, so the trust a browser gives it lasts as long as the run and no longer.
