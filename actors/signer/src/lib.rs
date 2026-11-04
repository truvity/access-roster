//! `signer`: the actor that issues tokens (ADR 0002 "Work actors", ADR 0006 "The token-signing
//! key", ADR 0017 "Issuers", ADR 0020 "The claims of a token").
//!
//! A caller the registry allows (`session`, `exchange`) asks for a token with its claims. `signer`
//! checks them against the config of the boundary: the issuer, a registered audience, the closed set
//! of claims of ADR 0020 and the lifetime cap. It builds the signing input itself from the claims it
//! checked, has key@ sign it with the `token-signing` key (ES384, RFC 7518 section 3.4) and returns
//! the compact JWS (RFC 7515). It holds no key and no secret: the private key never leaves key@.
//!
//! It also keeps the published key set, the kind `SigningRing`, in store@: a key is published for at
//! least the prepublish window before it signs, and stays published for the token lifetime plus
//! the clock skew after it stops (ADR 0006 "Rotation"; REQ-KEYS-007).
//!
//! # Refusals
//!
//! Every refusal is a Connect error with the `Refusal` detail, a reason from this closed list and the
//! path of the field at fault, never a value, and it is an audit fact.
//!
//! | Code | Reason | When |
//! |---|---|---|
//! | `invalid_argument` | `typ` | the token type is neither `JWT` nor `at+jwt` |
//! | `invalid_argument` | `claims` | the claims do not fit: the same answer for a wrong issuer, an audience nobody registered and a lifetime past the cap |
//! | `permission_denied` | `caller` | the transport names no caller |
//! | `unavailable` | `config` | the boundary's config cannot be read |
//! | `unavailable` | `store` | store@ cannot be reached |
//! | `unavailable` | `key` | key@ cannot be reached or refused |
//! | `unavailable` | `key_set` | the key that key@ signs with is not yet, or no longer, an active key of the ring |
//! | `internal` | `signature` | key@ returned a signature that does not verify |

pub mod audit;
pub mod claims;
pub mod config;
pub mod jwks;
pub mod keys;
pub mod ring;
pub mod run;
pub mod service;

#[cfg(feature = "test-identities")]
pub use service::serve_with;
pub use service::{Clock, Config, Signer, Sockets, serve};
