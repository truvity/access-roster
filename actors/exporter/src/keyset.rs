//! The static key set: the JSON Web Key Set of RFC 7517 for the ring, without a `kid` that `KeyRevocation` lists
//! (REQ-EXPORT-020). It is built by the rule `entry` uses for its live key set (ADR 0009, "Publishing public
//! material"): one ES384 key for each ring key in a published state that is a P-384 key, in the order of the ring, and
//! nothing else. `entry` and `signer` each keep their own copy of that rule in their own crate (actors import nothing
//! of each other); all three are held to the same known answers, `tests/testdata/key/keyset-vectors.json`, which two
//! P-384 keys made and read with `openssl` produce, so a drift of one copy fails its own test.
//!
//! The output is deterministic (members in sorted order, no white space), so the digest of a document is the same
//! for the same ring and the same revocations, and a reconcile that finds the digest at the destination writes nothing.

use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sluis_proto::sluis::signer::v2alpha1::SigningRing;
use sluis_store::revocation::without_revoked;

/// The states of a ring key that the key set publishes: a key verifiers must know before it signs, one that signs, and
/// one that has stopped signing but whose tokens are still valid (ADR 0006, "Rotation").
const PUBLISHED: [&str; 3] = ["pre-published", "active", "retiring"];

/// A SubjectPublicKeyInfo of a P-384 key starts with these 24 bytes (RFC 5480 sections 2.1.1 and 2.2: id-ecPublicKey
/// with secp384r1, the BIT STRING of 98 bytes, then the uncompressed-point marker), then 48 bytes of x and 48 of y.
const P384_SPKI_PREFIX: [u8; 24] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
];

fn coordinates(spki: &[u8]) -> Option<(&[u8], &[u8])> {
    let point = spki.strip_prefix(&P384_SPKI_PREFIX[..])?;
    (point.len() == 96).then(|| point.split_at(48))
}

/// The JWK Set of the ring as it is. A key the document cannot describe, or whose state is not published, is left
/// out, never guessed.
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
    serde_json::to_vec(&json!({ "keys": keys })).unwrap_or_else(|_| b"{\"keys\":[]}".to_vec())
}

/// A key set built for publication: the bytes, and the kids it lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Built {
    /// The document.
    pub body: Vec<u8>,
    /// The `kid` of each key in it, in order.
    pub kids: Vec<String>,
}

/// The key set of the ring without the kids `KeyRevocation` lists.
#[must_use]
pub fn build(ring: &SigningRing, revoked: &HashSet<String>) -> Built {
    let body = jwks(&without_revoked(ring.clone(), revoked));
    let kids = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| {
            v["keys"].as_array().map(|a| {
                a.iter()
                    .filter_map(|k| k["kid"].as_str().map(str::to_owned))
                    .collect()
            })
        })
        .unwrap_or_default();
    Built { body, kids }
}

/// A key set document without the keys whose `kid` is in `removed`, in the order it had, or `None` when none of them is in
/// it (or it is not a key set, which is left alone). Removal is monotone: a key that `KeyRevocation` lists leaves a
/// document, and no revocation can put one back, so this can be applied to the last good document without knowing the
/// rest of the revocations (ADR 0009, "Refusals").
#[must_use]
pub fn without_kids(body: &[u8], removed: &HashSet<String>) -> Option<Built> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let keys = v.get("keys")?.as_array()?;
    let kept: Vec<Value> = keys
        .iter()
        .filter(|k| k["kid"].as_str().is_none_or(|kid| !removed.contains(kid)))
        .cloned()
        .collect();
    if kept.len() == keys.len() {
        return None;
    }
    let kids = kept
        .iter()
        .filter_map(|k| k["kid"].as_str().map(str::to_owned))
        .collect();
    let body = serde_json::to_vec(&json!({ "keys": kept })).ok()?;
    Some(Built { body, kids })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluis_proto::sluis::signer::v2alpha1::SigningKey;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "{s}");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

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

    fn vectors() -> (Vec<SigningKey>, Vec<SigningKey>, Vec<Value>) {
        let v: Value = serde_json::from_str(include_str!(
            "../../../tests/testdata/key/keyset-vectors.json"
        ))
        .unwrap();
        let published = v["published"].as_array().unwrap();
        let left_out = v["left_out"].as_array().unwrap();
        assert!(published.len() >= 3 && left_out.len() >= 5);
        (
            left_out.iter().map(ring_key).collect(),
            published.iter().map(ring_key).collect(),
            published.iter().map(|c| c["jwk"].clone()).collect(),
        )
    }

    /// The key set equals the known answers that `entry` and `signer` hold their copies to.
    ///
    /// verifies: REQ-KEYS-006
    #[test]
    fn the_key_set_equals_the_known_answers_of_entry_and_signer() {
        let (left_out, published, jwks_want) = vectors();
        let ring = SigningRing {
            keys: left_out.into_iter().chain(published).collect(),
            ..SigningRing::default()
        };
        let set: Value = serde_json::from_slice(&jwks(&ring)).unwrap();
        let got: Vec<&Value> = set["keys"].as_array().unwrap().iter().collect();
        assert_eq!(got, jwks_want.iter().collect::<Vec<_>>());
        for entry in got {
            for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
                assert!(entry.get(private).is_none(), "{private}");
            }
        }
    }

    #[test]
    fn a_revoked_kid_is_left_out_in_every_state_and_the_rest_is_unchanged() {
        let (_, published, _) = vectors();
        let ring = SigningRing {
            keys: published.clone(),
            ..SigningRing::default()
        };
        let all = build(&ring, &HashSet::new());
        assert_eq!(
            all.kids,
            published
                .iter()
                .map(|k| k.key_id.clone())
                .collect::<Vec<_>>()
        );
        let gone = published[1].key_id.clone();
        let some = build(&ring, &HashSet::from([gone.clone(), "unknown".into()]));
        assert_eq!(some.kids.len(), published.len() - 1);
        assert!(!some.kids.contains(&gone));
        // The same ring and revocations give the same bytes.
        assert_eq!(some, build(&ring, &HashSet::from([gone.clone()])));
        let none = build(&ring, &published.iter().map(|k| k.key_id.clone()).collect());
        assert_eq!(none.body, br#"{"keys":[]}"#);
        assert!(none.kids.is_empty());
    }

    /// Removing kids from a built document gives the bytes that building without them gives, so a document that was
    /// trimmed and one that was rebuilt are the same document.
    ///
    /// verifies: REQ-EXPORT-020
    #[test]
    fn removing_kids_from_a_document_equals_building_without_them() {
        let (_, published, _) = vectors();
        let ring = SigningRing {
            keys: published.clone(),
            ..SigningRing::default()
        };
        let all = build(&ring, &HashSet::new());
        let gone = HashSet::from([published[1].key_id.clone(), "unknown".to_owned()]);
        let trimmed = without_kids(&all.body, &gone).expect("a listed kid is removed");
        assert_eq!(trimmed, build(&ring, &gone));
        assert_eq!(
            without_kids(&all.body, &HashSet::from(["unknown".into()])),
            None
        );
        assert_eq!(without_kids(b"not json", &gone), None);
        assert_eq!(without_kids(br#"{"other":1}"#, &gone), None);
    }
}
