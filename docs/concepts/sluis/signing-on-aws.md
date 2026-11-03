# How does sluis sign tokens on AWS?

The aws-serverless, aws-hybrid and k8s-aws presets sign with the `kms-wrapped` adapter, called the ring. The key
policy and IAM statements are in [the signing key policy](../../reference/sluis/aws-signing-key.md). The library
arguments are in [the Pulumi library](../../reference/sluis/pulumi-library.md#inputs-lambdaargs). Direct signing with
`signingKey.kms` is deprecated and warns at start.

| | `kms` (direct, deprecated) | the ring (`kms-wrapped`) |
|---|---|---|
| Keys | one asymmetric KMS key per algorithm | one symmetric key the estate supplies, named by alias (`keys.sign`) |
| Signing | one `kms:Sign` per token; the private key never leaves KMS | local, with a key decrypted into memory (`kms:Decrypt` once per key per process) |
| Verifying | the published public keys | the published public keys, with no KMS call |
| If the signing role leaks | the holder signs only while it holds the role, and CloudTrail records every signature | the holder decrypts the wrapped keys in the State and signs offline with no trace while they are published |
| Throughput | the account's `Sign` quota | none from KMS |
| Rotation | append a key by hand | automatic, every `rotateEvery` (default 24h) |

## How does the ring work?

For each algorithm (ES384, RS256) the process generates a key pair locally. It wraps the private half with `kms:Encrypt`
under the sign key and the context `{instance, purpose: sign}`. It records the public key, the wrapped key and that context
in the State as `issuer:keyring:entry:<alg>:<kid>`. The `kid` is a random 128-bit id. `instance` is the document's
`instance`, falling back to its `release`.

To sign, a process calls `kms:Decrypt`, keeps the key in memory and signs locally. EdDSA is refused, because the issuer
knows only RSA and ECDSA.

Every `rotateEvery` a replica generates a new pair per algorithm under the State lease `lease.signing-keygen:<alg>`. A lost
race costs one more published key, never a wrong token.

A new key enters the JWKS at once and signs after `prepublish`, unset half of `rotateEvery` (`12h`) and never under
`activationDelay`: longer than any verifier caches the key set. A replaced key stays published for `retain`, which
defaults to `lifetimes.token` plus 5m of skew. At start `retain` must be at least that, and `rotateEvery` must exceed
`prepublish` and be at most 168h.

A process looks for work at most every `pollInterval` (30s), on a request, and on Kubernetes on a timer.

## The sign key, and moving between signers

The estate owns the key that wraps the ring. Name it by alias in `keys.sign` and in the Pulumi library's `Keys.Sign`:

```yaml
keys:
  adapter: kms
  sign: alias/sluis-<instance>-sign      # or {key: alias/..., context: off | {..}}
```

The library grants Encrypt, Decrypt and GenerateDataKey on the key behind the alias, only under the context
`{instance, purpose: sign}`. It creates no key and no `kms:Sign` grant. Other workloads may share the key, because the
context keeps ciphertexts apart.

Letting the library create the key (`WrappedSigning`) is deprecated. See [its policy](../../reference/sluis/aws-signing-key.md#legacy-wrappedsigning-the-library-creates-the-key)
and [the move to supplied aliases](../../guides/sluis/migrate/supply-your-own-signing-keys.md).

An entry from an earlier release records no context and opens with `{purpose: sluis-signing, alg, kid}`. The ring turns
over within `rotateEvery` plus `retain`, so no entry needs migrating. The library keeps the older grant while
`Keys.LegacySigningContext` is true (the default). Set it false once the ring has rotated. Setting it early stops signing
if the active key is an old one.

To move from direct KMS signing, list each direct key's public key under `signingKey.verifyOnly` with its `kid` and an
`until` that covers its tokens plus the verifiers' cache. Replace `signingKey.kms` with `keys.sign`. The ring signs from
the first start and old tokens keep verifying. `signingKey.kmsWrapped.keyId` is the deprecated spelling of `keys.sign`.

## Trust boundary

Whoever may call `kms:Decrypt` with the signing context can extract a wrapped key, and the ciphertext is in the State.
A direct key is not extractable. Choose `kms` where that matters more than rotation and quota.

Write access to the State is inside the trust boundary. Whoever can write the key ring items (`keyring`,
`keyring-index`, `keyring-retired`) or the lease can plant a public key, retire a key early or stop rotation.

A key a leaked role has decrypted stays valid while published: its life as the active key plus `retain`. No role is
denied the key ring, because the controllers run in the signing process.

The key policy and the account's IAM decide who may call `kms:Decrypt`. Keep that to the signing roles. Otherwise a CI role
or a PowerUser can read a wrapped key from the State and forge. Only a CloudTrail `Decrypt` records it. On a shared key,
deny `purpose=sign` to every principal but the signing roles.

Principals with `kms:PutKeyPolicy` can widen who may decrypt, so they are inside the boundary. Its key policy leaves the
control plane to the named key administrators ([key policy](../../reference/sluis/aws-signing-key.md)). A multi-Region key needs
the same policy in every replica.

## Known limits

A process publishes a key it reads from the State without unwrapping it. Foreign entries are published with no allowlist.
The encryption context has no creation time, so an over-age wrapped key is not refused.

A process that cannot unwrap the newest key signs with an older one and logs it. The first key of a cutover is active at
once, so a verifier with a cached JWKS rejects the new `kid` for its cache lifetime.

## Decided in

- [ADR 0009](../../decisions/0009-a-default-signing-algorithm-and-per-audience-exceptions.md): default algorithm and exceptions
- [ADR 0041](../../decisions/0041-the-secret-contract.md): the secret contract, `keys.sign` and its context
