//! Public keys: the SubjectPublicKeyInfo of a P-384 key (RFC 5480) or of the RSA-2048 key of the RS256 exception (RFC
//! 8017), its JWK thumbprint (RFC 7638), the verification of an ES384 or RS256 signature (RFC 7518 sections 3.4 and 3.3)
//! and the JWK Set of the ring (RFC 7517 section 5).

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{
    ECDSA_P384_SHA384_FIXED, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey,
};
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

/// A SubjectPublicKeyInfo of an RSA-2048 key with the public exponent 65537 (RFC 8017 appendix A.1.1; the only RSA key the
/// ring holds) is these 33 bytes, then the 256 bytes of the modulus, then the 5 bytes of [`RSA_SPKI_SUFFIX`]: the
/// SEQUENCE of 290 bytes, the AlgorithmIdentifier rsaEncryption with NULL parameters, the BIT STRING of 271 bytes with no
/// unused bits, the RSAPublicKey SEQUENCE of 266 bytes, and the INTEGER of 257 bytes whose first byte is the 0x00 that
/// keeps it positive (the modulus has its top bit set).
const RSA_SPKI_PREFIX: [u8; 33] = [
    0x30, 0x82, 0x01, 0x22, // SEQUENCE, 290 bytes
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
    0x00, // rsaEncryption, NULL
    0x03, 0x82, 0x01, 0x0f, 0x00, // BIT STRING, 271 bytes, no unused bits
    0x30, 0x82, 0x01, 0x0a, // SEQUENCE, 266 bytes
    0x02, 0x82, 0x01, 0x01, 0x00, // INTEGER, 257 bytes: 0x00 and the modulus
];
/// Where the RSAPublicKey starts in an RSA-2048 SubjectPublicKeyInfo: 4 (SEQUENCE), 15 (AlgorithmIdentifier), 5 (BIT STRING).
const RSA_PUBLIC_KEY_AT: usize = 24;
/// The public exponent 65537 as an INTEGER, the end of an RSA-2048 SubjectPublicKeyInfo.
const RSA_SPKI_SUFFIX: [u8; 5] = [0x02, 0x03, 0x01, 0x00, 0x01];
/// The public exponent 65537 as a JWK `e` member (RFC 7518 section 6.3.1.2: base64url of the big-endian octets).
const RSA_E: &str = "AQAB";

/// The modulus (256 octets, top bit set) of an RSA-2048 SubjectPublicKeyInfo with the exponent 65537, or `None` for
/// anything else: another size, another exponent, another key type, or a modulus that is not 2048 bits.
#[must_use]
pub fn rsa2048_modulus(spki: &[u8]) -> Option<&[u8]> {
    let rest = spki.strip_prefix(&RSA_SPKI_PREFIX[..])?;
    let n = rest.strip_suffix(&RSA_SPKI_SUFFIX[..])?;
    (n.len() == 256 && n[0] & 0x80 != 0).then_some(n)
}

/// The coordinates of a P-384 key (RFC 7518 section 6.2.1).
fn coordinates(spki: &[u8]) -> Option<(&[u8], &[u8])> {
    p384_point(spki).map(|p| p[1..].split_at(48))
}

/// The RFC 7638 thumbprint of a P-384 key or of an RSA-2048 key (exponent 65537), base64url: SHA-256 of the JWK with its
/// required members in lexicographic order and no white space (section 3.2). It is the `kid` of the key. Which of the two
/// it is comes from the key itself, so a kid never names a key under the wrong type.
#[must_use]
pub fn thumbprint(spki: &[u8]) -> Option<String> {
    let jwk = if let Some((x, y)) = coordinates(spki) {
        format!(
            r#"{{"crv":"P-384","kty":"EC","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(x),
            URL_SAFE_NO_PAD.encode(y)
        )
    } else {
        let n = rsa2048_modulus(spki)?;
        format!(
            r#"{{"e":"{RSA_E}","kty":"RSA","n":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(n)
        )
    };
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

/// Whether `signature` (256 octets) is the RS256 signature, RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 section 3.3), of
/// `message` under the RSA-2048 key. Nothing shorter or longer verifies, and a PSS signature does not.
#[must_use]
pub fn verifies_rs256(spki: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if rsa2048_modulus(spki).is_none() || signature.len() != 256 {
        return false;
    }
    // aws-lc-rs takes the RSAPublicKey (RFC 8017 appendix A.1.1): the SEQUENCE of n and e, which is what the BIT STRING of
    // the SubjectPublicKeyInfo holds, after its 24 header bytes.
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &spki[RSA_PUBLIC_KEY_AT..])
        .verify(message, signature)
        .is_ok()
}

/// The states of a ring key that the key set publishes: a key verifiers must know before it signs,
/// one that signs, and one that has stopped signing but whose tokens are still valid (ADR 0006
/// "Rotation"). `entry` publishes the same three.
const PUBLISHED: [&str; 3] = [PRE_PUBLISHED, ACTIVE, RETIRING];

/// The JWK Set of the ring: one ES384 key for each published ring key that is a P-384 key, and one RS256 key for each
/// published ring key that is an RSA-2048 key with the exponent 65537, in the order of the ring. A key the document cannot
/// describe, or whose state is not published, is left out. The RSA entry carries no `x5c`: `ca` certifies the ES384 token
/// key alone, and an RSA key is trusted for the TLS fetch of the set (ADR 0006, "Named exceptions").
#[must_use]
pub fn jwks(ring: &SigningRing) -> Vec<u8> {
    let keys: Vec<Value> = ring
        .keys
        .iter()
        .filter(|k| !k.key_id.is_empty() && PUBLISHED.contains(&k.state.as_str()))
        .filter_map(|k| match k.algorithm.as_str() {
            "ES384" => {
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
            }
            "RS256" => Some(json!({
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": k.key_id,
                "n": URL_SAFE_NO_PAD.encode(rsa2048_modulus(&k.spki_der)?),
                "e": RSA_E,
            })),
            _ => None,
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
    /// verifies: REQ-KEYS-006, REQ-KEYS-271
    #[test]
    fn the_key_set_equals_the_known_answers_and_each_entry_carries_kid_kty_alg_use() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../tests/testdata/key/keyset-vectors.json"
        ))
        .unwrap();
        let published = vectors["published"].as_array().unwrap();
        let left_out = vectors["left_out"].as_array().unwrap();
        assert!(published.len() >= 6 && left_out.len() >= 12);
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
            if entry["kty"] == "RSA" {
                // An RSA entry holds the public key as n and e, and no certificate chain (REQ-KEYS-271).
                assert_eq!(entry["alg"], "RS256", "{entry}");
                assert_eq!(entry["e"], "AQAB", "{entry}");
                assert_eq!(entry["n"].as_str().map(str::len), Some(342), "{entry}");
                assert!(entry.get("x5c").is_none(), "x5c of {entry}");
                assert!(
                    entry.get("crv").is_none() && entry.get("x").is_none(),
                    "{entry}"
                );
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

    // ---- RS256

    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../../../tests/testdata/key/keyset-vectors.json"
        ))
        .unwrap()
    }

    /// The RS256 signature of RFC 7515 appendix A.2 verifies under its key and under nothing else: not another message, not a
    /// signature a byte short or long or with a bit flipped, not another key. The thumbprints are the RFCs' (RFC 7638 section
    /// 3.1 for the key of the second vector), so the kid does not come from the code under test.
    ///
    /// verifies: REQ-KEYS-271
    #[test]
    fn an_rs256_signature_verifies_only_under_its_key_and_message_and_the_thumbprint_is_the_rfcs() {
        let v = vectors();
        let r = &v["rs256_signature"];
        let spki = unhex(r["spki"].as_str().unwrap());
        let other = unhex(r["other_spki"].as_str().unwrap());
        let sig = unhex(r["signature"].as_str().unwrap());
        let msg = r["message"].as_str().unwrap().as_bytes();
        assert!(verifies_rs256(&spki, msg, &sig));
        assert!(!verifies_rs256(&spki, b"another message", &sig));
        assert!(!verifies_rs256(&other, msg, &sig));
        assert!(!verifies_rs256(&spki, msg, &sig[..255]));
        assert!(!verifies_rs256(
            &spki,
            msg,
            &[sig.clone(), vec![0]].concat()
        ));
        let mut flipped = sig.clone();
        flipped[100] ^= 1;
        assert!(!verifies_rs256(&spki, msg, &flipped));
        assert!(!verifies_rs256(&spki, msg, &[]));
        // Not a key this version knows: P-384 is not RSA.
        let (ec, _) = test_key();
        assert!(!verifies_rs256(&ec, msg, &sig));
        assert_eq!(thumbprint(&spki).as_deref(), r["thumbprint"].as_str());
        assert_eq!(
            thumbprint(&other).as_deref(),
            Some("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
        );
    }

    /// The SubjectPublicKeyInfo of an RSA key is taken only in the one shape the ring holds: 2048 bits, the exponent 65537.
    ///
    /// verifies: REQ-KEYS-271
    #[test]
    fn only_an_rsa_2048_key_with_the_exponent_65537_is_described() {
        let v = vectors();
        let good = unhex(v["rs256_signature"]["spki"].as_str().unwrap());
        assert_eq!(good.len(), 294);
        assert_eq!(rsa2048_modulus(&good).map(<[u8]>::len), Some(256));
        let mutated = |at: usize, with: u8| {
            let mut s = good.clone();
            s[at] = with;
            s
        };
        for (what, spki) in [
            ("a byte short", good[..293].to_vec()),
            ("a byte long", [good.clone(), vec![0]].concat()),
            ("empty", vec![]),
            ("exponent 65539", mutated(293, 0x03)),
            ("exponent 131073", mutated(291, 0x02)),
            ("rsaEncryption OID changed", mutated(16, 0x0e)),
            ("PSS in place of rsaEncryption", mutated(15, 0x0a)),
            ("sequence length changed", mutated(3, 0x21)),
            ("modulus top bit clear", mutated(33, 0x7f)),
            ("an EC key", test_key().0),
        ] {
            assert!(rsa2048_modulus(&spki).is_none(), "{what}");
            assert!(thumbprint(&spki).is_none() || what == "an EC key", "{what}");
        }
        assert!(thumbprint(&test_key().0).is_some());
    }

    /// A key made now: a signature of the form RS256 names verifies, and the same key's PSS signature does not (RS256 is
    /// RSASSA-PKCS1-v1_5, not PS256).
    ///
    /// verifies: REQ-KEYS-271
    #[test]
    fn a_pss_signature_is_not_an_rs256_signature() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::rsa::{KeyPair, KeySize};
        use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RSA_PSS_SHA256};
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        // The RSAPublicKey inside the 24 bytes of a SubjectPublicKeyInfo header.
        let spki = [
            &RSA_SPKI_PREFIX[..RSA_PUBLIC_KEY_AT],
            aws_lc_rs::signature::KeyPair::public_key(&pair).as_ref(),
        ]
        .concat();
        assert!(
            rsa2048_modulus(&spki).is_some(),
            "the made key is RSA-2048 with 65537"
        );
        let rng = SystemRandom::new();
        let msg = b"a signing input";
        let mut pkcs1 = vec![0; 256];
        pair.sign(&RSA_PKCS1_SHA256, &rng, msg, &mut pkcs1).unwrap();
        let mut pss = vec![0; 256];
        pair.sign(&RSA_PSS_SHA256, &rng, msg, &mut pss).unwrap();
        assert!(verifies_rs256(&spki, msg, &pkcs1));
        assert!(!verifies_rs256(&spki, msg, &pss));
    }

    /// An RSA ring key is published as an RSA entry and never with a certificate chain; a key of one algorithm over the key
    /// type of the other is not published.
    ///
    /// verifies: REQ-KEYS-271
    #[test]
    fn an_rsa_entry_has_n_and_e_and_no_chain() {
        let v = vectors();
        let spki = unhex(v["rs256_signature"]["spki"].as_str().unwrap());
        let ring = SigningRing {
            keys: vec![SigningKey {
                key_id: "r".into(),
                algorithm: "RS256".into(),
                state: ACTIVE.into(),
                spki_der: spki.clone(),
                x5c: vec![vec![1, 2, 3]],
                ..SigningKey::default()
            }],
            ..SigningRing::default()
        };
        let set: Value = serde_json::from_slice(&jwks(&ring)).unwrap();
        let k = &set["keys"][0];
        assert_eq!(
            (k["kty"].as_str(), k["alg"].as_str(), k["use"].as_str()),
            (Some("RSA"), Some("RS256"), Some("sig"))
        );
        assert_eq!(k["e"], "AQAB");
        assert_eq!(
            k["n"],
            URL_SAFE_NO_PAD.encode(rsa2048_modulus(&spki).unwrap())
        );
        assert!(k.get("x5c").is_none());
    }
}
