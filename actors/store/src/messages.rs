//! The Protobuf message of a plain or hashed kind (`sluis.<writer>.v2alpha1.<Kind>`), when the
//! contracts have one, and the sealed envelope check.

/// The sealed envelope's version byte (store-api.md "The sealed envelope").
const ENVELOPE_VERSION: u8 = 0x01;
/// The purpose byte of a stored item: `data`, the only purpose of a stored item.
const PURPOSE_DATA: u8 = 0x01;
/// version (1) + purpose (1) + generation (4) + nonce (12) + tag (16).
const ENVELOPE_MIN: usize = 34;

/// Whether `value` has the header and the size of an envelope. store@ never opens it.
#[must_use]
pub fn envelope_ok(value: &[u8]) -> bool {
    value.len() >= ENVELOPE_MIN && value[0] == ENVELOPE_VERSION && value[1] == PURPOSE_DATA
}

#[cfg(test)]
fn decodes_as<M: buffa::Message>(bytes: &[u8]) -> bool {
    M::decode_from_slice(bytes).is_ok()
}

/// The reasons of a `KeyRevocation` (key.proto): a closed list.
const REVOCATION_REASONS: [&str; 4] = ["compromise", "suspicion", "lost-board", "drill"];

/// The lower-case base32 of a thumbprint's 32 bytes, without padding (RFC 4648 section 6): 52 characters, the label
/// that names a kid or a recipient in an address, which does not allow upper case. key@ derives it the same way
/// (`recipientLabel`), and tests/testdata/keyrevocation/ids.json holds both to the encoding.
#[must_use]
pub fn thumbprint_label(thumbprint: &str) -> Option<String> {
    use base64::Engine as _;
    if thumbprint.len() != 43 {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(thumbprint)
        .ok()?;
    if raw.len() != 32 {
        return None;
    }
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0u32);
    for b in raw {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buf >> bits) & 31) as usize]));
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buf << (5 - bits)) & 31) as usize]));
    }
    Some(out)
}

/// A `KeyRevocation` item is valid when its message decodes, names one of the four target kinds, a target of that
/// kind's form, a reason of the closed list and a time, and when its id is the one that names the target. The kind is
/// create only (ADR 0041), so an item that is wrong cannot be corrected later: it is refused at the write.
fn key_revocation_ok(id: &str, bytes: &[u8]) -> bool {
    use sluis_proto::sluis::key::v2alpha1::KeyRevocation;
    let Ok(m) = <KeyRevocation as buffa::Message>::decode_from_slice(bytes) else {
        return false;
    };
    if !REVOCATION_REASONS.contains(&m.reason_code.as_str()) || m.revoked_at.as_option().is_none() {
        return false;
    }
    let want = match m.target_kind.as_str() {
        "kid" | "recipient" => {
            thumbprint_label(&m.target).map(|l| format!("{}/{l}", m.target_kind))
        }
        "purpose" => crate::address::valid_part(&m.target).then(|| format!("purpose/{}", m.target)),
        "generation" => m
            .target
            .split_once('/')
            .is_some_and(|(p, n)| {
                crate::address::valid_part(p)
                    && !n.is_empty()
                    && !n.starts_with('0')
                    && n.bytes().all(|b| b.is_ascii_digit())
            })
            .then(|| format!("generation/{}", m.target)),
        _ => None,
    };
    want.is_some_and(|w| w == id)
}

/// The kinds whose Protobuf message is in `sluis-proto`, by segment.
//
// planned: every other durable and temp kind that is plain or hashed is passed as bytes today, because
// `sluis-proto` holds no message for it yet (its writer's contract adds it).
type Check = fn(&str, &[u8]) -> bool;
const MAPPED: &[(&str, Check)] = &[("key-revocation", key_revocation_ok)];

/// Whether the bytes are the kind's message (and, for a kind that has rules of its own, a valid one for the id). None
/// when the contracts have no message for the kind yet: the bytes are then passed on as they are.
#[must_use]
pub fn decodes(segment: &str, id: &str, bytes: &[u8]) -> Option<bool> {
    MAPPED
        .iter()
        .find(|(s, _)| *s == segment)
        .map(|(_, check)| check(id, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message as _;
    use sluis_proto::sluis::r#type::v2alpha1::Refusal;

    fn item(kind: &str, target: &str, reason: &str, time: bool) -> Vec<u8> {
        use buffa::Message as _;
        use sluis_proto::sluis::key::v2alpha1::KeyRevocation;
        KeyRevocation {
            target_kind: kind.into(),
            target: target.into(),
            reason_code: reason.into(),
            revoked_at: if time {
                buffa::MessageField::some(buffa_types::google::protobuf::Timestamp {
                    seconds: 1_793_800_000,
                    ..Default::default()
                })
            } else {
                buffa::MessageField::none()
            },
            ..KeyRevocation::default()
        }
        .encode_to_vec()
    }

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../tests/testdata/keyrevocation/ids.json"
        ))
        .unwrap()
    }

    /// verifies: REQ-KEYS-091
    /// The id of an item is the one that names its target, with the encoding of the shared vectors (which key@ in Go and
    /// the readers to come in Rust hold to): the label of a kid or a recipient is the lower-case base32 of its
    /// thumbprint.
    #[test]
    fn a_key_revocation_is_valid_only_under_the_id_that_names_its_target() {
        let v = vectors();
        let ids = v["ids"].as_array().unwrap();
        assert!(ids.len() >= 10, "a sweep over nothing proves nothing");
        for c in ids {
            let (kind, target, id) = (
                c["target_kind"].as_str().unwrap(),
                c["target"].as_str().unwrap(),
                c["id"].as_str().unwrap(),
            );
            let bytes = item(kind, target, "compromise", true);
            assert_eq!(
                decodes("key-revocation", id, &bytes),
                Some(true),
                "{kind} {target}"
            );
            // Another id, and a reason outside the list, and no time, are refused: the item cannot be corrected later.
            assert_eq!(
                decodes("key-revocation", "kid/other", &bytes),
                Some(false),
                "{id}"
            );
            assert_eq!(
                decodes("key-revocation", id, &item(kind, target, "because", true)),
                Some(false)
            );
            assert_eq!(
                decodes("key-revocation", id, &item(kind, target, "drill", false)),
                Some(false)
            );
            if kind == "kid" || kind == "recipient" {
                assert_eq!(
                    thumbprint_label(target).as_deref(),
                    id.split_once('/').map(|x| x.1)
                );
            }
        }
        for c in v["refused"].as_array().unwrap() {
            let (kind, target) = (
                c["target_kind"].as_str().unwrap(),
                c["target"].as_str().unwrap(),
            );
            for id in [format!("{kind}/{target}"), format!("{kind}/x")] {
                assert_eq!(
                    decodes(
                        "key-revocation",
                        &id,
                        &item(kind, target, "compromise", true)
                    ),
                    Some(false),
                    "{} {id}",
                    c["name"]
                );
            }
        }
        assert_eq!(
            decodes("key-revocation", "kid/x", &[0xff, 0xff]),
            Some(false)
        );
        for reason in ["compromise", "suspicion", "lost-board", "drill"] {
            assert_eq!(
                decodes(
                    "key-revocation",
                    "purpose/mac",
                    &item("purpose", "mac", reason, true)
                ),
                Some(true)
            );
        }
    }

    #[test]
    fn the_envelope_header_and_size() {
        let mut e = vec![0u8; 34];
        e[0] = 1;
        e[1] = 1;
        assert!(envelope_ok(&e));
        assert!(!envelope_ok(&e[..33]));
        e[0] = 2;
        assert!(!envelope_ok(&e));
        e[0] = 1;
        e[1] = 2; // evidence: not a purpose of a stored item
        assert!(!envelope_ok(&e));
        assert!(!envelope_ok(&[]));
    }

    #[test]
    fn a_decoder_accepts_its_message_and_refuses_other_bytes() {
        let m = Refusal {
            reason: "x".into(),
            ..Refusal::default()
        }
        .encode_to_vec();
        assert!(decodes_as::<Refusal>(&m));
        assert!(!decodes_as::<Refusal>(&[0xff, 0xff, 0xff]));
        assert_eq!(decodes("person", "x", &m), None);
    }
}
