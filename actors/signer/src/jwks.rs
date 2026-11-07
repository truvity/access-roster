//! Public keys: the SubjectPublicKeyInfo of a P-384 key (RFC 5480), its JWK thumbprint (RFC 7638),
//! the verification of an ES384 signature (RFC 7518 section 3.4) and the JWK Set of the ring
//! (RFC 7517 section 5).

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sluis_proto::sluis::signer::v2alpha1::SigningRing;

use crate::ring::{ACTIVE, PRE_PUBLISHED, RETIRING};

/// A SubjectPublicKeyInfo of a P-384 key starts with these 23 bytes (RFC 5480 section 2.1.1:
/// id-ecPublicKey with the curve secp384r1; the BIT STRING of 98 bytes, no unused bits), then the
/// uncompressed point: 0x04, 48 bytes of x, 48 of y (RFC 5480 section 2.2).
const P384_SPKI_PREFIX: [u8; 23] = [
    0x30, 0x76, // SEQUENCE, 118 bytes
    0x30, 0x10, // SEQUENCE, 16 bytes: AlgorithmIdentifier
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, // secp384r1
    0x03, 0x62, 0x00, // BIT STRING, 98 bytes, no unused bits
];

/// The uncompressed point (97 bytes) of a P-384 SubjectPublicKeyInfo, or `None` for anything else.
#[must_use]
pub fn p384_point(spki: &[u8]) -> Option<&[u8]> {
    let point = spki.strip_prefix(&P384_SPKI_PREFIX[..])?;
    (point.len() == 97 && point[0] == 0x04).then_some(point)
}

/// The coordinates of a P-384 key (RFC 7518 section 6.2.1).
fn coordinates(spki: &[u8]) -> Option<(&[u8], &[u8])> {
    p384_point(spki).map(|p| p[1..].split_at(48))
}

/// The RFC 7638 thumbprint of a P-384 key, base64url: SHA-256 of the JWK with its required members
/// in lexicographic order and no white space (section 3.2). It is the `kid` of the key.
#[must_use]
pub fn thumbprint(spki: &[u8]) -> Option<String> {
    let (x, y) = coordinates(spki)?;
    let jwk = format!(
        r#"{{"crv":"P-384","kty":"EC","x":"{}","y":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(x),
        URL_SAFE_NO_PAD.encode(y)
    );
    Some(URL_SAFE_NO_PAD.encode(digest(&SHA256, jwk.as_bytes())))
}

/// Whether `signature` (raw r||s, 96 bytes) is the ES384 signature of `message` under the key.
#[must_use]
pub fn verifies(spki: &[u8], message: &[u8], signature: &[u8]) -> bool {
    p384_point(spki).is_some_and(|point| {
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, point)
            .verify(message, signature)
            .is_ok()
    })
}

/// The states of a ring key that the key set publishes: a key verifiers must know before it signs,
/// one that signs, and one that has stopped signing but whose tokens are still valid (ADR 0006
/// "Rotation"). `entry` publishes the same three.
const PUBLISHED: [&str; 3] = [PRE_PUBLISHED, ACTIVE, RETIRING];

/// The JWK Set of the ring: one ES384 key for each published ring key that is a P-384 key. A key
/// the document cannot describe, or whose state is not published, is left out.
#[must_use]
pub fn jwks(ring: &SigningRing) -> Vec<u8> {
    let keys: Vec<Value> = ring
        .keys
        .iter()
        .filter(|k| k.algorithm == "ES384" && !k.key_id.is_empty())
        .filter(|k| PUBLISHED.contains(&k.state.as_str()))
        .filter_map(|k| {
            let (x, y) = coordinates(&k.spki_der)?;
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
    serde_json::to_vec(&json!({ "keys": keys })).unwrap_or_else(|_| br#"{"keys":[]}"#.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
    use sluis_proto::sluis::signer::v2alpha1::SigningKey;

    /// A P-384 key made for the test: its SubjectPublicKeyInfo and a signer.
    pub(crate) fn test_key() -> (Vec<u8>, EcdsaKeyPair) {
        let pair = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).unwrap();
        let mut spki = P384_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(pair.public_key().as_ref());
        (spki, pair)
    }

    #[test]
    fn a_signature_verifies_only_under_its_key_and_message() {
        let (spki, pair) = test_key();
        let (other, _) = test_key();
        let sig = pair
            .sign(&aws_lc_rs::rand::SystemRandom::new(), b"abc")
            .unwrap();
        assert!(verifies(&spki, b"abc", sig.as_ref()));
        assert!(!verifies(&spki, b"abd", sig.as_ref()));
        assert!(!verifies(&other, b"abc", sig.as_ref()));
        assert!(!verifies(&spki, b"abc", &sig.as_ref()[..95]));
    }

    #[test]
    fn the_thumbprint_follows_rfc_7638() {
        let (spki, _) = test_key();
        let t = thumbprint(&spki).unwrap();
        assert_eq!(t.len(), 43, "SHA-256 in base64url without padding");
        let (spki2, _) = test_key();
        assert_ne!(Some(t), thumbprint(&spki2));
        assert_eq!(thumbprint(&[0u8; 10]), None);
        let mut p256 = spki.clone();
        p256[20] ^= 1; // another curve OID
        assert_eq!(thumbprint(&p256), None);
    }

    #[test]
    fn the_key_set_lists_published_p384_keys_only() {
        let (spki, _) = test_key();
        let key = |id: &str, alg: &str, state: &str, spki: &[u8]| SigningKey {
            key_id: id.into(),
            algorithm: alg.into(),
            spki_der: spki.to_vec(),
            state: state.into(),
            ..SigningKey::default()
        };
        let ring = SigningRing {
            keys: vec![
                key("a", "ES384", ACTIVE, &spki),
                key("b", "ES384", PRE_PUBLISHED, &spki),
                key("c", "ES384", RETIRING, &spki),
                key("d", "ES384", "revoked", &spki),
                // A tombstone of a dropped key is not published, whatever it holds (REQ-KEYS-079).
                key("h", "ES384", crate::ring::DROPPED, &spki),
                key("e", "ES256", ACTIVE, &spki),
                key("f", "ES384", ACTIVE, &[1, 2, 3]),
                key("", "ES384", ACTIVE, &spki),
                SigningKey {
                    x5c: vec![vec![1, 2, 3]],
                    ..key("g", "ES384", ACTIVE, &spki)
                },
            ],
            ..SigningRing::default()
        };
        let v: Value = serde_json::from_slice(&jwks(&ring)).unwrap();
        let kids: Vec<&str> = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap())
            .collect();
        assert_eq!(kids, ["a", "b", "c", "g"]);
        assert_eq!(v["keys"][3]["x5c"][0], "AQID");
        assert!(v["keys"][0].get("x5c").is_none());
        assert_eq!(jwks(&SigningRing::default()), br#"{"keys":[]}"#);
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

    /// The key set that `KeySet` answers (the one `exchange` verifies its own tokens with) equals the known answers of
    /// `tests/testdata/key/keyset-vectors.json`, which `entry` holds its published copy to as well: two P-384 keys made
    /// and read with `openssl`, so x and y do not come from the code under test. Each entry carries `kid`, `kty`, `alg`
    /// and `use` (RFC 7517 section 4) and nothing private.
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

    /// A verifier that reads only the key set can check a signature: the point rebuilt from the published `x` and `y`
    /// (RFC 7518 section 6.2.1) verifies an ES384 signature of the ring key's pair, and no other key's.
    ///
    /// verifies: REQ-KEYS-006
    #[test]
    fn a_signature_verifies_under_the_published_x_and_y() {
        let (spki, pair) = test_key();
        let (other, _) = test_key();
        let ring = SigningRing {
            keys: vec![SigningKey {
                key_id: "k".into(),
                algorithm: "ES384".into(),
                state: ACTIVE.into(),
                spki_der: spki,
                ..SigningKey::default()
            }],
            ..SigningRing::default()
        };
        let set: Value = serde_json::from_slice(&jwks(&ring)).unwrap();
        let jwk = &set["keys"][0];
        assert_eq!(
            (jwk["kty"].as_str(), jwk["crv"].as_str()),
            (Some("EC"), Some("P-384"))
        );
        assert_eq!(
            (jwk["alg"].as_str(), jwk["use"].as_str()),
            (Some("ES384"), Some("sig"))
        );
        let part = |name: &str| URL_SAFE_NO_PAD.decode(jwk[name].as_str().unwrap()).unwrap();
        let (x, y) = (part("x"), part("y"));
        assert_eq!((x.len(), y.len()), (48, 48));
        let mut point = vec![0x04];
        point.extend(x);
        point.extend(y);
        let sig = pair
            .sign(&aws_lc_rs::rand::SystemRandom::new(), b"a token")
            .unwrap();
        let check = |point: &[u8], message: &[u8]| {
            UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, point)
                .verify(message, sig.as_ref())
                .is_ok()
        };
        assert!(check(&point, b"a token"));
        assert!(!check(&point, b"another token"));
        assert!(!check(p384_point(&other).unwrap(), b"a token"));
    }
}
