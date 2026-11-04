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

#[allow(dead_code)] // planned: the first mapped kind (below) is its consumer; the tests use it now
fn decodes_as<M: buffa::Message>(bytes: &[u8]) -> bool {
    M::decode_from_slice(bytes).is_ok()
}

/// The kinds whose Protobuf message is in `sluis-proto`, by segment.
//
// planned: every durable and temp kind that is plain or hashed is passed as bytes today, because
// `sluis-proto` holds no message for it yet (its writer's contract adds it). The first one is
// `KeyCertificate` (WP-08): `("key-certificate", decodes_as::<sluis::key::v2alpha1::KeyCertificate>)`.
type Check = fn(&[u8]) -> bool;
const MAPPED: &[(&str, Check)] = &[];

/// Whether the bytes are the kind's message. None when the contracts have no message for the kind
/// yet: the bytes are then passed on as they are.
#[must_use]
pub fn decodes(segment: &str, bytes: &[u8]) -> Option<bool> {
    MAPPED
        .iter()
        .find(|(s, _)| *s == segment)
        .map(|(_, check)| check(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message as _;
    use sluis_proto::sluis::r#type::v2alpha1::Refusal;

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
        assert_eq!(decodes("person", &m), None);
    }
}
