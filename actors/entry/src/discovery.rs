//! The discovery document and the key set (decision D-7), built from the kinds `Boundary` and
//! `SigningRing` that store@ holds, read through the typed store client.
//!
//! 0017 wants these as static documents in a bucket so that a verifier works while compute is
//! down; until exporter@ publishes them, `entry` serves them (PLAN.md D-7). It keeps the built
//! pair for a few seconds, so a flood of anonymous reads is one read of the store, and never
//! serves a pair it could not build: on a store failure it answers 503 (fail closed).
//!
//! The key set leaves out every kid that `KeyRevocation` lists (ADR 0041, REQ-KEYS-107). That is a
//! filter at publication, so it does not depend on `signer` or on the node that owns the key, and the
//! kind is read each time the pair is built (at most every few seconds): a revocation reaches the
//! served set within that time. A `KeyRevocation` that cannot be read refuses the key set only: a set that
//! might list a revoked key is not served, while the discovery document names no key and is unaffected.

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use serde_json::{Value, json};
use sluis_kit::{Client, dial};
use sluis_proto::sluis::config::v2alpha1::Boundary;
use sluis_proto::sluis::signer::v2alpha1::SigningRing;
use sluis_store::revocation::{KeyRevocations, without_revoked};
use sluis_store::{Kind, Store};
use tokio::sync::Mutex;

use crate::handler::TOKEN_ENDPOINT_AUTH_METHODS;
use crate::refuse::Refuse;

/// The singleton id of both kinds (PLAN.md D-17).
const ID: &str = "default";
/// How long a built pair is kept: the time `signer` waits before it signs with a key that skipped the
/// lead time, so the constant is shared (`sluis_store::KEY_SET_CACHE`).
const KEEP: Duration = sluis_store::KEY_SET_CACHE;
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
    /// `None` when `KeyRevocation` could not be read: the key set is then refused (503), the discovery document is not.
    pub jwks: Option<Bytes>,
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
        let revocations = KeyRevocations::new(&self.store).map_err(|_| unavailable)?;
        let (b, r, revoked) = tokio::join!(
            tokio::time::timeout(READ, boundary.get("", ID)),
            tokio::time::timeout(READ, ring.get("", ID)),
            tokio::time::timeout(READ, revocations.revoked_kids()),
        );
        let b = b.map_err(|_| unavailable)?.map_err(|_| unavailable)?;
        let r = r.map_err(|_| unavailable)?.map_err(|_| unavailable)?;
        // An unreadable KeyRevocation is no revocation to apply, and not "none revoked": the key set is withheld.
        let revoked = revoked.ok().and_then(Result::ok);
        let discovery = discovery(&b.value).ok_or(Refuse::new(503, "boundary_issuer"))?;
        Ok(Documents {
            discovery: Bytes::from(discovery),
            jwks: revoked.map(|kids| Bytes::from(jwks(&without_revoked(r.value, &kids)))),
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
        // `sub` is the tenant's pairwise subject (ADR 0034): a keyed hash of the sector and the person, and the person's
        // own id only for a sector declared public, which the first version has no way to declare. So "public" is not
        // served, and the list says only what is.
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["ES384"],
        "code_challenge_methods_supported": ["S256"],
        // The union over the grants of /token (RFC 8414 has no list per grant): `none` for sign-in and
        // refresh, the two secret methods for token exchange. The list is the handler's.
        "token_endpoint_auth_methods_supported": TOKEN_ENDPOINT_AUTH_METHODS,
        // The field defaults to true (OpenID Connect Discovery 1.0 section 3) and `/authorize` serves no `request_uri`
        // (`session` answers it with request_uri_not_supported), so the document says false. `request_parameter_supported`
        // and `claims_parameter_supported` default to false and stay out.
        "request_uri_parameter_supported": false,
        // The scopes `session` grants (OpenID Connect Discovery 1.0 section 3: RECOMMENDED). A client that reads the list
        // does not ask for address or phone and is not refused with invalid_scope, which is how a scope that is not served
        // is answered (REQ-CLIENT-022). `session`'s tests hold the list to its own.
        "scopes_supported": ["openid", "profile", "email"],
        // RFC 9207 section 3: `session` puts the issuer in `iss` on every redirect to a client, a code and an error
        // alike, and the field defaults to false, so the document says true.
        "authorization_response_iss_parameter_supported": true,
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

/// The states of a ring key that the key set publishes: a key verifiers must know before it signs,
/// one that signs, and one that has stopped signing but whose tokens are still valid (0006
/// "Rotation"). Any other state, an unknown or an empty one included, is not published.
const PUBLISHED: [&str; 3] = ["pre-published", "active", "retiring"];

/// The JWK Set (RFC 7517 section 5) of the ring: one ES384 key per published ring key that is a
/// P-384 key. A key the document cannot describe, or whose state is not published, is left out,
/// never guessed.
pub(crate) fn jwks(ring: &SigningRing) -> Vec<u8> {
    let keys: Vec<Value> = ring
        .keys
        .iter()
        .filter(|k| k.algorithm == "ES384" && !k.key_id.is_empty())
        .filter(|k| PUBLISHED.contains(&k.state.as_str()))
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
            state: "active".into(),
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

    /// verifies: REQ-TOKEN-020
    #[test]
    fn only_published_states_are_in_the_key_set() {
        let with = |id: &str, state: &str| SigningKey {
            state: state.into(),
            ..key(id, "ES384", spki(1, 2))
        };
        let ring = SigningRing {
            keys: [
                "pre-published",
                "active",
                "retiring",
                "revoked",
                "destroyed",
                "",
                "Active",
            ]
            .iter()
            .enumerate()
            .map(|(i, s)| with(&format!("k{i}"), s))
            .collect(),
            ..SigningRing::default()
        };
        let v: Value = serde_json::from_slice(&jwks(&ring)).unwrap();
        let kids: Vec<&str> = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap())
            .collect();
        assert_eq!(kids, ["k0", "k1", "k2"]);
    }

    /// The bytes of a lower-case hex string (the vector files write binary values that way).
    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "{s}");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The ring key of a case of `keyset-vectors.json`.
    fn ring_key(case: &Value) -> SigningKey {
        let text = |name: &str| case[name].as_str().unwrap().to_owned();
        SigningKey {
            key_id: text("key_id"),
            algorithm: text("algorithm"),
            state: text("state"),
            spki_der: unhex(case["spki"].as_str().unwrap()),
            x5c: case["x5c"]
                .as_array()
                .map(|a| a.iter().map(|c| unhex(c.as_str().unwrap())).collect())
                .unwrap_or_default(),
            ..SigningKey::default()
        }
    }

    /// The key set that `/jwks` serves equals the known answers of `tests/testdata/key/keyset-vectors.json` (two P-384
    /// keys made and read with `openssl`, so x and y do not come from the code under test), lists a ring key only when
    /// the file says so, and each entry carries `kid`, `kty`, `alg` and `use` (RFC 7517 section 4) and nothing private.
    ///
    /// verifies: REQ-KEYS-006
    #[test]
    fn the_key_set_equals_the_known_answers_and_each_entry_carries_kid_kty_alg_use() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../tests/testdata/key/keyset-vectors.json"
        ))
        .unwrap();
        let published = vectors["published"].as_array().unwrap();
        let left_out = vectors["left_out"].as_array().unwrap();
        assert!(published.len() >= 3 && left_out.len() >= 5);
        let ring = SigningRing {
            keys: left_out.iter().chain(published).map(ring_key).collect(),
            ..SigningRing::default()
        };
        let set: Value = serde_json::from_slice(&jwks(&ring)).unwrap();
        let want: Vec<&Value> = published.iter().map(|c| &c["jwk"]).collect();
        let got: Vec<&Value> = set["keys"].as_array().unwrap().iter().collect();
        assert_eq!(got, want);
        for entry in got {
            for member in ["kid", "kty", "alg", "use"] {
                assert!(
                    entry[member].as_str().is_some_and(|v| !v.is_empty()),
                    "{member} of {entry}"
                );
            }
            for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
                assert!(entry.get(private).is_none(), "{private} of {entry}");
            }
        }
    }

    #[test]
    fn an_empty_ring_is_an_empty_key_set() {
        assert_eq!(jwks(&SigningRing::default()), br#"{"keys":[]}"#);
    }

    /// The document for one issuer equals the golden file (`tests/testdata/discovery.json`) as JSON, so a field
    /// added, dropped or changed is a reviewed change to the golden.
    ///
    /// verifies: REQ-AUTHN-006
    #[test]
    fn the_discovery_document_equals_its_golden() {
        let b = Boundary {
            issuer: "https://sluis.example.test".into(),
            ..Boundary::default()
        };
        let got: Value = serde_json::from_slice(&discovery(&b).unwrap()).unwrap();
        let golden: Value =
            serde_json::from_str(include_str!("../tests/testdata/discovery.json")).unwrap();
        assert_eq!(got, golden);
        assert_eq!(got["request_uri_parameter_supported"], false);
        // The claim is true: `/authorize` accepts `request_uri` only to have `session` answer request_uri_not_supported
        // (`session`'s tests, which read the same golden file, hold that side).
        assert!(crate::routes::AUTHORIZE.contains(&"request_uri"));
        // The other two claims that are not about a route: `session`'s tests (`discovery_claims_test.go`) read the same
        // golden file and hold the redirect's `iss` and the subject type to it.
        assert_eq!(got["authorization_response_iss_parameter_supported"], true);
        assert_eq!(got["subject_types_supported"], json!(["pairwise"]));
    }

    /// The issuer of the document is the boundary's issuer as it was written: no case folding, no dropped default port,
    /// no normalised path or escape, and every endpoint is that string and a path. `session` and `exchange` put the same
    /// string in `iss` (their tests hold that side, for the same issuers).
    ///
    /// verifies: REQ-AUTHN-030
    #[test]
    fn the_issuer_of_the_document_is_the_boundarys_byte_for_byte() {
        for iss in [
            "https://sluis.example.test",
            "https://sluis.example.test:8443",
            "https://sluis.example.test:8443/tenant-a/v2",
            "https://Sluis.Example.TEST:443/Tenant%2FA/%7e",
            "https://xn--bcher-kva.example.test/a//b",
        ] {
            let b = Boundary {
                issuer: iss.into(),
                ..Boundary::default()
            };
            let v: Value = serde_json::from_slice(&discovery(&b).unwrap()).unwrap();
            assert_eq!(v["issuer"].as_str().unwrap().as_bytes(), iss.as_bytes());
            for endpoint in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
                let url = v[endpoint].as_str().unwrap();
                assert!(
                    url.starts_with(iss) && url[iss.len()..].starts_with('/'),
                    "{endpoint} {url}"
                );
            }
        }
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
