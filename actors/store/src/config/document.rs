//! A signed config document: its structure and its signatures (signed-config.md "The document"
//! and "Verifying a document", steps 1 to 4).
//!
//! Nothing here reads the payload. A refusal names the step and the rule, never a value.

use std::collections::HashSet;
use std::fmt;

use aws_lc_rs::digest;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use sluis_registry::Kind;

use crate::bootstrap::Publisher;

/// The DER prefix of a P-384 SubjectPublicKeyInfo: what precedes the 97-byte point.
const SPKI_P384_PREFIX_LEN: usize = 23;
/// `seq` is below 2^53, so that a JSON number holds it exactly in every reader.
const SEQ_LIMIT: u64 = 1 << 53;
/// An ECDSA P-384 signature, `r` then `s`, 48 bytes each (RFC 7518, section 3.4).
const SIGNATURE_LEN: usize = 96;

/// Why a document was refused: the step of signed-config.md and the rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    pub step: u8,
    pub rule: &'static str,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "step {}: {}", self.step, self.rule)
    }
}

fn refuse<T>(step: u8, rule: &'static str) -> Result<T, Refused> {
    Err(Refused { step, rule })
}

/// A document whose signatures verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub seq: u64,
    /// The payload, decoded.
    pub payload: Vec<u8>,
    /// The SHA-384 of the payload (the digest the audit fact names).
    pub digest: [u8; 48],
}

/// JSON with the one rule serde_json does not have: a duplicate key is an error, at any depth.
enum Json {
    Null,
    Bool,
    Num(serde_json::Number),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Json;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Json, E> {
                Ok(Json::Null)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Json, E> {
                Ok(Json::Bool)
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Json, E> {
                Ok(Json::Num(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Json, E> {
                Ok(Json::Num(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Json, E> {
                serde_json::Number::from_f64(v)
                    .map(Json::Num)
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Json, E> {
                Ok(Json::Str(v.to_owned()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Json, A::Error> {
                let mut v = Vec::new();
                while let Some(x) = a.next_element()? {
                    v.push(x);
                }
                Ok(Json::Arr(v))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Json, A::Error> {
                let mut seen = HashSet::new();
                let mut v = Vec::new();
                while let Some((k, x)) = a.next_entry::<String, Json>()? {
                    if !seen.insert(k.clone()) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    v.push((k, x));
                }
                Ok(Json::Obj(v))
            }
        }
        d.deserialize_any(V)
    }
}

fn parse(bytes: &[u8]) -> Option<Json> {
    serde_json::from_slice(bytes).ok()
}

/// The members of an object, when its keys are exactly `keys` (any order).
fn exactly<'a>(j: &'a Json, keys: &[&str]) -> Option<Vec<&'a Json>> {
    let Json::Obj(m) = j else { return None };
    if m.len() != keys.len() {
        return None;
    }
    keys.iter()
        .map(|k| m.iter().find(|(name, _)| name == k).map(|(_, v)| v))
        .collect()
}

fn b64(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()
}

struct Signature<'a> {
    protected: &'a str,
    signature: &'a str,
    kid: String,
    seq: u64,
}

/// Verifies the document `doc` of the kind `kind` against the pinned `publishers`: steps 1 to 4
/// of signed-config.md. The sequence number (step 5) and the payload (step 6) are the caller's.
///
/// # Errors
///
/// [`Refused`] with the step at which the document failed.
pub fn verify(doc: &[u8], kind: &Kind, publishers: &[Publisher]) -> Result<Verified, Refused> {
    // Step 1: structure. The general JSON serialisation; the compact and the flattened ones, an
    // unprotected `header` and any other member are all refused here.
    let Some(json) = parse(doc) else {
        return refuse(1, "not a JSON object in the general serialisation");
    };
    let Some([Json::Str(payload), Json::Arr(sigs)]) =
        exactly(&json, &["payload", "signatures"]).as_deref()
    else {
        return refuse(1, "needs a payload and signatures, and no other member");
    };
    if sigs.is_empty() {
        return refuse(1, "needs at least one signature");
    }
    let mut parsed = Vec::with_capacity(sigs.len());
    for s in sigs {
        let Some([Json::Str(protected), Json::Str(signature)]) =
            exactly(s, &["protected", "signature"]).as_deref()
        else {
            return refuse(
                1,
                "a signature has protected and signature, and no other member",
            );
        };
        parsed.push((protected.as_str(), signature.as_str()));
    }

    // Step 2: headers.
    let mut signatures = Vec::with_capacity(parsed.len());
    for (protected, signature) in parsed {
        let Some(header) = b64(protected).and_then(|b| parse(&b)) else {
            return refuse(2, "the protected header is not base64url JSON");
        };
        let Some([Json::Str(alg), Json::Str(kid), Json::Num(seq)]) =
            exactly(&header, &["alg", "kid", "seq"]).as_deref()
        else {
            return refuse(
                2,
                "the protected header needs alg, kid and seq, and no other member",
            );
        };
        if alg != "ES384" {
            return refuse(2, "alg must be ES384");
        }
        let Some(seq) = seq.as_u64().filter(|s| (1..SEQ_LIMIT).contains(s)) else {
            return refuse(2, "seq must be a positive integer below 2^53");
        };
        signatures.push(Signature {
            protected,
            signature,
            kid: kid.clone(),
            seq,
        });
    }
    let seq = signatures[0].seq;
    if signatures.iter().any(|s| s.seq != seq) {
        return refuse(2, "the signatures carry different seq");
    }

    // Step 3: keys.
    let mut used = HashSet::new();
    let mut keys = Vec::with_capacity(signatures.len());
    for s in &signatures {
        let Some(p) = publishers.iter().find(|p| p.kid == s.kid) else {
            return refuse(3, "a kid is not in the bootstrap file");
        };
        if !used.insert(s.kid.as_str()) {
            return refuse(3, "a kid is used twice");
        }
        keys.push(p);
    }

    // Step 4: signatures, over the bytes as they were received.
    for (s, p) in signatures.iter().zip(&keys) {
        let Some(sig) = b64(s.signature).filter(|b| b.len() == SIGNATURE_LEN) else {
            return refuse(4, "a signature is not 96 bytes of r then s");
        };
        let input = format!("{}.{}", s.protected, payload);
        let key = p.spki_der.get(SPKI_P384_PREFIX_LEN..).unwrap_or_default();
        if UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, key)
            .verify(input.as_bytes(), &sig)
            .is_err()
        {
            return refuse(4, "a signature does not verify");
        }
    }
    // One publisher key without `co_signs`, and every key whose `co_signs` names this kind.
    let signed_by = |kid: &str| used.contains(kid);
    if !keys.iter().any(|p| p.co_signs.is_empty()) {
        return refuse(4, "no publisher key signed it");
    }
    if publishers
        .iter()
        .any(|p| p.co_signs.iter().any(|k| k == kind.name) && !signed_by(&p.kid))
    {
        return refuse(4, "a co-signer's signature is missing");
    }
    let Some(payload) = b64(payload) else {
        return refuse(4, "the payload is not base64url");
    };

    let mut d = [0u8; 48];
    d.copy_from_slice(digest::digest(&digest::SHA384, &payload).as_ref());
    Ok(Verified {
        seq,
        payload,
        digest: d,
    })
}

/// What the sequence number says about a document (step 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sequence {
    /// A higher `seq` than the one in force, or nothing in force: it replaces it.
    Newer,
    /// The same `seq` and the same payload: nothing changes.
    Same,
    /// The same `seq` with another payload: two documents must not share a number.
    Conflict,
    /// A lower `seq`: an older document must not come back.
    Older,
}

/// Step 5. `in_force` is the `seq` and the payload digest of the document in force, if there is
/// one. A store that starts has nothing in force and takes whatever `seq` it is given
/// (signed-config.md "The sequence number").
#[must_use]
pub fn sequence(in_force: Option<(u64, &[u8; 48])>, v: &Verified) -> Sequence {
    match in_force {
        None => Sequence::Newer,
        Some((seq, digest)) => match v.seq.cmp(&seq) {
            std::cmp::Ordering::Greater => Sequence::Newer,
            std::cmp::Ordering::Equal if v.digest == *digest => Sequence::Same,
            std::cmp::Ordering::Equal => Sequence::Conflict,
            std::cmp::Ordering::Less => Sequence::Older,
        },
    }
}

/// The digest in lower-case hex, as the audit fact and `sha384sum` show it.
#[must_use]
pub fn hex(d: &[u8]) -> String {
    use std::fmt::Write as _;
    d.iter()
        .fold(String::with_capacity(d.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
