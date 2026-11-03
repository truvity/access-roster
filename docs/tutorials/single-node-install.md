---
title: "Tutorial: install on a board"
description: Install sluis on one arm64 board with a YubiKey, get its intermediate certified, sign in, verify a token against the JWKS and read the audit trail.
status: target
sidebar:
  order: 0
---

:::caution
This tutorial describes the intended experience. It can't be run yet, because sluis v2 is not released. The commands, outputs and file names are examples of what the finished product shows ([examples are illustrative](/integrations/#examples-are-illustrative)). Every command is a subcommand of the one `sluis` binary.
:::

You install sluis on one arm64 single-board computer with a YubiKey: the [boards](/runtimes/installations/#boards) installation reduced to one node, on the [bare-metal](/runtimes/bare-metal/) runtime. One board is a possible installation under the same rules as the three-board cluster, not a tested one, and the steps are the ones you repeat on each board of the cluster. You finish with a running sluis at `https://sluis.example.com`, a certified node intermediate, a token you have verified yourself, and the audit record of your own sign-in.

The tutorial becomes part of the test suite: it lives under `tests/tutorials` and runs on the installation it is written for, so a step that stops working fails CI. Development itself uses the [local](/runtimes/installations/#local) installation, with software keys.

## 1. Prerequisites

- An arm64 single-board computer with 2 GB of RAM and eMMC storage. It runs a [supported platform](/distribution/packages/#supported-platforms), or a board image older than the systemd floor, which is a declared exception until board images for the supported distributions exist ([#881](https://github.com/truvity/sluis/issues/881)).
- A YubiKey 5 with firmware 5.7 or newer, which includes the EUCLEAK fix. It is for this board only: no other card software uses it.
- A domain you control, here `example.com`, on Cloudflare, and a Cloudflare tunnel for `sluis.example.com`. You use the tunnel in step 11.
- An upstream identity provider you can sign in with, here an OIDC provider at `https://idp.example.org`, with a client ID and a client secret you can register a redirect URI for.
- A workstation with a browser, `ssh`, `curl`, `gh`, `ykman`, Python 3, and ritueel's setup script for the software root ([ritueel.id](https://ritueel.id)).

Log in to the board and become root for the install steps.

## 2. Download and verify the packages

Releases carry checksums and GitHub build provenance attestations, and nothing else, until ritueel's roots exist. So there is no signed apt repository to add yet: download the `.deb` files and the release's `SHA256SUMS` from GitHub Releases, which is the immutable record, and check them ([Release signing](/distribution/release-signing/)).

```sh
# Example
gh release download v2.0.0 --repo truvity/sluis --dir sluis-debs \
  --pattern SHA256SUMS --pattern '*_arm64.deb'
cd sluis-debs
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify sluis-server_2.0.0_arm64.deb --repo truvity/sluis
```

Every line must say `OK`. A failed check means the file is not the one the release published: stop. Once releases are signed, you add the apt repository with the release keyring instead ([Packages](/distribution/packages/#apt-debian-and-ubuntu)).

## 3. Install the packages

```sh
# Example
apt install ./{sluis,sluis-node,sluis-server,sluis-audit-writer,sluis-audit-search,sluis-driver-yubikey-piv}_2.0.0_arm64.deb
```

The packages install the actors, drivers and the node agent (`sluis-node`) under `/usr/libexec/sluis/{actors,drivers,integrations,node,vendor}/<short-name>`, and systemd template units. `sluis-driver-yubikey-piv` brings `pcscd`, which on a node serves the `key-holder` user only. Nothing is enabled yet.

```sh
# Example
ls /usr/libexec/sluis/actors
```

```text
# Example output
audit-indexer  audit-reader  audit-witness  audit-writer  ca  console  entry  exchange  policy  session  signer  ssh-ca
```

These are the [core actors](/decisions/0041-core-actors-with-one-responsibility-each/#the-actors) and the audit actors; the install file decides which of them run.

## 4. Run `sluis doctor`

`sluis doctor` checks the platform before you create any key.

```sh
sluis doctor
```

```text
# Example output
ok    architecture        arm64
warn  systemd             249 < 252: board-image exception, units use LoadCredential=
warn  kernel randomness   5.10 < 5.18: VM-clone reseeding is not covered by the kernel
ok    hwrng               absent (deliberate on this SoC)
ok    entropy             initialised before key generation
ok    pcscd               running, access limited to sluis-key-holder
ok    yubikey             found, PIV, firmware 5.7.4
ok    filesystem          /var/lib/sluis on eMMC, 28 GB free
```

The two warnings are the board-image exception, and a warning is not a failure. A `fail` line stops the install: fix it, then run `sluis doctor` again.

## 5. Prepare the YubiKey

On the workstation, before the card goes into the board, set a new PIN and PUK, and a management key protected by the PIN, so that `key-holder` can generate keys once it has the PIN:

```sh
# Example, on the workstation
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key --generate --protect
```

Then plug the card into the board. From now on only `key-holder` talks to it.

## 6. Write a minimal config

Configuration has four layers inside declared configuration: defaults, the runtime, your install file, and overrides per environment ([ADR 0004](/decisions/0004-the-data-model/)). The bare-metal runtime sets the key mode and the audit spool. The keys are those of [install-file schema v1](/reference/install-file/); start from the [local example file](/reference/install-file/#the-example-file-for-local) and change what differs on a board: the environment, the hosts, the keys driver and the upstream.

```yaml
# Example: /etc/sluis/install.yaml
$schema: https://sluis.id/schema/install/v1/install.schema.json
runtime: bare-metal
environment: production
nodes: 1

front:
  host: sluis.example.com
  rp_id: example.com

boundaries:
  prod:
    kind: environment
    level: L2
    host: sluis.prod.example.com

drivers:
  keys: yubikey-piv    # the board's card; schema v1 lists it with the boards installation
  state: embedded      # one node: a SQLite file per actor, no Raft
  lease: local-lock
  blob: fs             # on the board's disk; the cluster uses R2
  transport: spool
  index: sqlite        # one node: no replicated index

upstreams:
  workforce:
    kind: oidc
    issuer: https://idp.example.org
    client_id: sluis-example
    client_secret: { credential: idp-client-secret }   # referenced, never inlined

clients:
  sluis-cli:
    kind: public
    redirects: [http://127.0.0.1/callback]

policy:
  files: [policy/board.cedar]

trust:
  root_list: trust/root-list.json
  ca_bundle: trust/ca-bundle.pem
```

This file enables neither SSH certificates nor release signing, so `ssh-ca` does not run and the node gets no `ssh-user`, `ssh-host` or release-signing key. Only an enabled purpose gets a slot ([the card slot map](/concepts/keys/#the-card-slot-map)).

The client secret is referenced: the config names a credential, and the secret itself is a file, the unit's systemd credential ([secrets in the install file](/reference/install-file/#format)).

```sh
# Example
install -m 0600 /dev/stdin /etc/sluis/credentials/idp-client-secret
```

## 7. Start `key-holder` and unlock the card

```sh
# Example
systemctl enable --now sluis-key-holder@prod.service
sluis node unlock node-1
```

`sluis node unlock` asks for the PIN and hands it to `key-holder`, which keeps it in locked memory only. The PIN is never written to disk. In a cluster an unlocked peer unlocks a rebooted node; a single board needs this one manual unlock after every boot.

## 8. Request the node's keys

```sh
# Example
sluis key request
```

```text
# Example output
purpose         slot  store         state
intermediate    9c    yubikey-piv   generated on device, P-384; request written
token signing   9a    yubikey-piv   generated on device, P-384; certificate after install
sealing         9d    yubikey-piv   generated on device, P-384
log key         84    yubikey-piv   generated on device, P-384
intermediate fingerprint  SHA256:5mQ1…Xk4
request  /var/lib/sluis/keys/request/prod-x509-intermediate.csr.pem
proof    /var/lib/sluis/keys/request/prod-x509-intermediate.proof.json
```

The keys are generated on the card and never leave it. The request is a PKCS#10 certificate request; the proof file says the key lives in a PIV slot and carries the card's attestation chain, which sluis has already checked against Yubico's attestation root. The files are those of ritueel's [hand-off contract](https://ritueel.id/reference/hand-off-contract/) ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)).

## 9. Get the intermediate certified

sluis holds no root and never makes one. The roots are [ritueel](https://ritueel.id)'s. For a first installation, ritueel's software-root mode stands in for the root cards: a setup script runs the ritueel commands that check the request and its attestation, certify the intermediate under a software root, and write the certificate, a result file and a signed root list.

```sh
# Example, on the workstation
scp -r root@board:/var/lib/sluis/keys/request ./request
./setup-software-root.sh ./request ./response   # runs ritueel in software-root mode
scp -r ./response root@board:/var/lib/sluis/keys/response
```

A production installation gets the same files from a ritueel ceremony with the root cards instead.

Back on the board, put the root list and the CA bundle where the install file names them (`trust.root_list` and `trust.ca_bundle`), then install the answer:

```sh
# Example
install -D -m 0644 -t /etc/sluis/trust /var/lib/sluis/keys/response/root-list.json /var/lib/sluis/keys/response/root-list.jws /var/lib/sluis/keys/response/ca-bundle.pem
sluis key install /var/lib/sluis/keys/response
sluis key status
```

```text
# Example output
installed  intermediate  certificate verifies to a root in the root list (trust sequence 1); matches slot 9c
issued     token signing certificate (non-CA, digital signature only) by the node intermediate

purpose         slot  expires       warning
intermediate    9c    2027-12-02    none
token signing   9a    2027-12-02    none
sealing         9d    -             none
log key         84    -             none
```

`sluis key install` uses the certificate only after it has checked the issuer against the root list, the key match, the validity and the constraints. The intermediate lasts 13 months; ritueel re-signs the same key in month 12, and sluis warns 60, 30 and 14 days before expiry.

## 10. Check the config and start the units

```sh
sluis config check /etc/sluis/install.yaml
```

```text
# Example output
ok    /etc/sluis/install.yaml validates against the schema (unevaluatedProperties: false)
ok    drivers satisfy the runtime and the node count (bare-metal, 1 node)
ok    every enabled purpose has a slot and a key; no collision
ok    intermediate certified; root list trust sequence 1
warn  audit.witness: none; with no witness a compromised writer can get a rewritten checkpoint signed
```

The warning is expected on one node: peer witnesses need two or more nodes. The schema is strict, so an unknown key is an error; `sluis config explain` shows each value in force and the layer it came from.

Start the target that groups the units:

```sh
# Example
systemctl enable --now sluis.target
systemctl list-units 'sluis-*' --no-legend
```

```text
# Example output
sluis-key-holder@prod.service     loaded active running  sluis key-holder
sluis-entry@prod.service          loaded active running  sluis entry
sluis-session@prod.service        loaded active running  sluis session
sluis-console@prod.service        loaded active running  sluis console
sluis-exchange@prod.service       loaded active running  sluis exchange
sluis-signer@prod.service         loaded active running  sluis signer
sluis-policy@prod.service         loaded active running  sluis policy
sluis-ca@prod.service             loaded active running  sluis ca
sluis-audit-writer@prod.service   loaded active running  sluis audit-writer
sluis-audit-indexer@prod.service  loaded active running  sluis audit-indexer
sluis-audit-reader@prod.service   loaded active running  sluis audit-reader
sluis-node.service                loaded active running  sluis node agent
```

Each unit runs as its own user; `ssh-ca` and the witness are not enabled. sluis opens no TCP listener: `entry` runs with `PrivateNetwork=yes` on `/run/sluis/entry/prod.sock`, every other actor and driver listens on a Unix socket under `/run/sluis/<actor>/`, and the embedded state driver has no Raft port, so `ss -ltn` lists no sluis listener.

## 11. Connect cloudflared to `entry`

`cloudflared` forwards to `entry`'s Unix socket as a `unix:` origin and makes outbound connections only, so the board opens no inbound port. Install it from Cloudflare's own repository, run it in the group of `entry`'s socket, and point the ingress at the socket.

```yaml
# Example: /etc/cloudflared/config.yaml
tunnel: <tunnel-id-from-cloudflare>
credentials-file: /etc/cloudflared/credentials.json
ingress:
  - hostname: sluis.example.com
    service: unix:/run/sluis/entry/prod.sock
  - service: http_status:404
```

```sh
# Example
systemctl enable --now cloudflared
curl -s https://sluis.example.com/.well-known/openid-configuration | head -4
```

```text
# Example output
{
  "issuer": "https://sluis.example.com",
  "jwks_uri": "https://sluis.example.com/.well-known/jwks.json",
  ...
```

## 12. Sign in

On the workstation, sign in through the upstream provider.

```sh
# Example
sluis login --issuer https://sluis.example.com
```

A browser opens at the upstream provider, and sluis relies on its multi-factor authentication. After you sign in, `policy` maps the provider's facts to grants and `signer` issues a token.

```text
# Example output
signed in to https://sluis.example.com
subject  3d7c1e9a-5b2f-4c8e-9a41-0f6b2d8e7c15
email    you@example.org
token stored in ~/.cache/sluis/token.jwt  (expires in 1h)
```

The subject is an opaque random id that sluis assigned when it first saw you in the directory. It is never your e-mail address, which is a separate `email` claim.

## 13. Verify a token against the JWKS

A sluis token is a standard JWS. Any JOSE library verifies it against the published key set, and sluis needs no client library. This example uses Python with PyJWT.

```python
# Example
import jwt  # pip install "pyjwt[crypto]"

token = open("token.jwt").read().strip()
jwks = jwt.PyJWKClient("https://sluis.example.com/.well-known/jwks.json")
key = jwks.get_signing_key_from_jwt(token)
claims = jwt.decode(
    token,
    key.key,
    algorithms=["ES384"],
    issuer="https://sluis.example.com",
    audience="example-service",
)
print(claims["sub"], claims.get("email"))
```

ES384 (P-384) is sluis's default. Each key-set entry carries an `x5c` chain, the token certificate, the node intermediate and the root, which a standard client ignores and a careful verifier checks down to the root it pins. The signing key stays on the card, and `signer` uses it only through `key-holder`.

## 14. Read the audit trail

Your sign-in produced audit records. They went through the spool into a sealed batch, and the writer asked `key-holder` to sign the checkpoint with the log key.

```sh
# Example
sluis audit tail --last 2
sluis audit verify
```

```text
# Example output
2026-11-02T09:14:01Z  3002/1  Logon        actor.user.uid=session@prod  status=Success
2026-11-02T09:14:02Z  3002/99 Token Grant  actor.user.uid=signer@prod   status=Success
chain ok: 1 batch, checkpoint signed by the log key, 0 gaps
```

Each record is an OCSF event; you appear in it as a keyed pseudonym, not by subject or e-mail. `audit verify` walks the chain from the sealed batches in the blob store and never trusts the index, so a damaged index can't hide a missing record. See [Audit](/concepts/audit/).

## 15. Next steps

- Read what you installed: the [actors](/concepts/actors/), the [drivers](/concepts/drivers/) and the [keys](/concepts/keys/).
- Add a second and a third board, a YubiKey each, and move to the tested [boards installation](/runtimes/installations/#boards), with rqlite state and blobs on R2 so that the audit chain outlives a board ([Limits and residual risk](/runtimes/bare-metal/#limits-and-residual-risk)).
- Read how releases are verified now and once they are signed: [Packages](/distribution/packages/) and [Release signing](/distribution/release-signing/).
