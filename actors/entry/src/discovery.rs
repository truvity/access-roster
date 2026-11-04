//! The discovery document and the key set (decision D-7), built from the kinds `Boundary` and
//! `SigningRing` that store@ holds, read through the typed store client.
//!
//! 0017 wants these as static documents in a bucket so that a verifier works while compute is
//! down; until exporter@ publishes them, `entry` serves them (PLAN.md D-7). It keeps the built
//! pair for a few seconds, so a flood of anonymous reads is one read of the store, and never
//! serves a pair it could not build: on a store failure it answers 503 (fail closed).

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use serde_json::{Value, json};
use sluis_kit::{Client, dial};
use sluis_proto::sluis::config::v2alpha1::Boundary;
use sluis_proto::sluis::signer::v2alpha1::SigningRing;
use sluis_store::{Kind, Store};
use tokio::sync::Mutex;

use crate::refuse::Refuse;

/// The singleton id of both kinds (PLAN.md D-17).
const ID: &str = "default";
/// How long a built pair is kept.
const KEEP: Duration = Duration::from_secs(5);
/// How long a read of the store may take.
const READ: Duration = Duration::from_secs(5);

struct BoundaryKind;
impl Kind for BoundaryKind {
    type Id = &'static str;
    type Value = Boundary;
    const NAME: &'static str = "Boundary";
}

struct RingKind;
impl Kind for RingKind {
    type Id = &'static str;
    type Value = SigningRing;
    const NAME: &'static str = "SigningRing";
}

/// The two public documents, as served.
#[derive(Clone)]
pub(crate) struct Documents {
    pub discovery: Bytes,
    pub jwks: Bytes,
}

pub(crate) struct Source {
    store: Client,
    kept: Mutex<Option<(Instant, Documents)>>,
}

impl Source {
    pub(crate) fn new(store_socket: &std::path::Path) -> Self {
        Self {
            store: dial(store_socket),
            kept: Mutex::new(None),
        }
    }

    pub(crate) async fn get(&self) -> Result<Documents, Refuse> {
        // The lock is held across the read: concurrent callers wait for one read, not make many.
        let mut kept = self.kept.lock().await;
        if let Some((at, docs)) = kept.as_ref()
            && at.elapsed() < KEEP
        {
            return Ok(docs.clone());
        }
        let docs = self.build().await?;
        *kept = Some((Instant::now(), docs.clone()));
        Ok(docs)
    }

    async fn build(&self) -> Result<Documents, Refuse> {
        let unavailable = Refuse::new(503, "store");
        let boundary = Store::<BoundaryKind>::new(self.store.clone()).map_err(|_| unavailable)?;
        let ring = Store::<RingKind>::new(self.store.clone()).map_err(|_| unavailable)?;
        let (b, r) = tokio::join!(
            tokio::time::timeout(READ, boundary.get("", ID)),
            tokio::time::timeout(READ, ring.get("", ID)),
        );
        let b = b.map_err(|_| unavailable)?.map_err(|_| unavailable)?;
        let r = r.map_err(|_| unavailable)?.map_err(|_| unavailable)?;
        let discovery = discovery(&b.value).ok_or(Refuse::new(503, "boundary_issuer"))?;
        Ok(Documents {
            discovery: Bytes::from(discovery),
            jwks: Bytes::from(jwks(&r.value)),
        })
    }
}

/// The issuer must be an `https` URL with no query, fragment or trailing slash (OpenID Connect
/// Discovery 1.0 section 3, RFC 8414 section 2).
fn issuer_ok(i: &str) -> bool {
    i.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty()
            && !rest.ends_with('/')
            && !rest.contains(['?', '#'])
            && !i.chars().any(|c| c.is_whitespace() || c.is_control())
    })
}

/// The OpenID Provider Metadata (OpenID Connect Discovery 1.0 section 3). `None` when the boundary
/// names no usable issuer. The endpoints are the routes of this crate.
pub(crate) fn discovery(b: &Boundary) -> Option<Vec<u8>> {
    let iss = b.issuer.as_str();
    if !issuer_ok(iss) {
        return None;
    }
    let doc = json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/authorize"),
        "token_endpoint": format!("{iss}/token"),
        "jwks_uri": format!("{iss}/jwks"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES384"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
    });
    serde_json::to_vec(&doc).ok()
}

/// The 120-byte SubjectPublicKeyInfo of a P-384 key (RFC 5480 section 2.1.1, RFC 5480 section 2.2
/// for the uncompressed point) starts with these 24 bytes (the last is the uncompressed-point marker), then 48 bytes of x and 48 of y.
const P384_SPKI_PREFIX: [u8; 24] = [
    0x30, 0x76, // SEQUENCE, 118 bytes
    0x30, 0x10, // SEQUENCE, 16 bytes: AlgorithmIdentifier
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, // secp384r1
    0x03, 0x62, 0x00, // BIT STRING, 98 bytes, no unused bits
    0x04, // uncompressed point
];

/// The coordinates of a P-384 SubjectPublicKeyInfo (RFC 7518 section 6.2.1), or `None` for anything else.
fn p384_coordinates(spki: &[u8]) -> Option<(&[u8], &[u8])> {
    let point = spki.strip_prefix(&P384_SPKI_PREFIX[..])?;
    (point.len() == 96).then(|| point.split_at(48))
}

/// The JWK Set (RFC 7517 section 5) of the ring: one ES384 key per ring key that is a P-384 key.
/// A key the document cannot describe is left out, never guessed.
pub(crate) fn jwks(ring: &SigningRing) -> Vec<u8> {
    let keys: Vec<Value> = ring
        .keys
        .iter()
        .filter(|k| k.algorithm == "ES384" && !k.key_id.is_empty())
        .filter_map(|k| {
            let (x, y) = p384_coordinates(&k.spki_der)?;
            let mut jwk = json!({
                "kty": "EC",
                "crv": "P-384",
                "alg": "ES384",
                "use": "sig",
                "kid": k.key_id,
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
            });
            if !k.x5c.is_empty() {
                // RFC 7517 section 4.7: standard base64 (not URL-safe) of each DER certificate.
                jwk["x5c"] = k.x5c.iter().map(|c| STANDARD.encode(c)).collect();
            }
            Some(jwk)
        })
        .collect();
    serde_json::to_vec(&json!({ "keys": keys })).unwrap_or_else(|_| b"{\"keys\":[]}".to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluis_proto::sluis::signer::v2alpha1::SigningKey;

    pub(crate) fn spki(x: u8, y: u8) -> Vec<u8> {
        let mut v = P384_SPKI_PREFIX.to_vec();
        v.extend(std::iter::repeat_n(x, 48));
        v.extend(std::iter::repeat_n(y, 48));
        v
    }

    fn key(id: &str, alg: &str, spki: Vec<u8>) -> SigningKey {
        SigningKey {
            key_id: id.into(),
            algorithm: alg.into(),
            spki_der: spki,
            ..SigningKey::default()
        }
    }

    #[test]
    fn the_key_set_lists_the_p384_keys_and_leaves_out_what_it_cannot_describe() {
        let ring = SigningRing {
            keys: vec![
                key("k1", "ES384", spki(1, 2)),
                key("k2", "ES256", spki(1, 2)),
                key("k3", "ES384", vec![0; 10]),
                key("", "ES384", spki(1, 2)),
                SigningKey {
                    x5c: vec![vec![1, 2, 3]],
                    ..key("k5", "ES384", spki(3, 4))
                },
            ],
            ..SigningRing::default()
        };
        let v: Value = serde_json::from_slice(&jwks(&ring)).unwrap();
        let keys = v["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0]["kid"], "k1");
        assert_eq!(keys[0]["x"], URL_SAFE_NO_PAD.encode([1u8; 48]));
        assert_eq!(keys[0]["y"], URL_SAFE_NO_PAD.encode([2u8; 48]));
        assert_eq!(
            (keys[0]["kty"].as_str(), keys[0]["crv"].as_str()),
            (Some("EC"), Some("P-384"))
        );
        assert!(keys[0].get("x5c").is_none());
        assert_eq!(keys[1]["x5c"][0], "AQID");
    }

    #[test]
    fn an_empty_ring_is_an_empty_key_set() {
        assert_eq!(jwks(&SigningRing::default()), br#"{"keys":[]}"#);
    }

    #[test]
    fn discovery_follows_the_issuer_and_refuses_a_bad_one() {
        let b = |iss: &str| Boundary {
            issuer: iss.into(),
            ..Boundary::default()
        };
        let v: Value =
            serde_json::from_slice(&discovery(&b("https://sluis.dev.local.test")).unwrap())
                .unwrap();
        assert_eq!(v["issuer"], "https://sluis.dev.local.test");
        assert_eq!(v["jwks_uri"], "https://sluis.dev.local.test/jwks");
        assert_eq!(v["token_endpoint"], "https://sluis.dev.local.test/token");
        assert_eq!(v["id_token_signing_alg_values_supported"][0], "ES384");
        for bad in [
            "",
            "http://x.test",
            "https://",
            "https://x.test/",
            "https://x.test?a=1",
            "https://x.test#f",
            "https://x .test",
        ] {
            assert!(discovery(&b(bad)).is_none(), "{bad:?}");
        }
    }
}
