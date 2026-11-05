//! Reading the kind `KeyRevocation` (ADR 0041, "The tighten-only record"), for the actors that read it:
//! `signer` and `entry` here. The kind is create only (REQ-KEYS-091), so a kid that was listed once is
//! listed for good, and a reader never has to doubt an item it saw. The readers fail closed: a
//! `KeyRevocation` that cannot be read is an error, never an empty list, because "not revoked" is a claim
//! that has to be verified (principle 4).
//!
//! A revocation of a token-signing key is the item `kid/<label>` at no tenant, where the label is the
//! lower-case base32 (RFC 4648, no padding) of the thumbprint's bytes: a thumbprint has upper-case letters,
//! which an id part does not allow. `key@` derives the same id (`recipientLabel`).

use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sluis_kit::Client;
use sluis_proto::sluis::key::v2alpha1::KeyRevocation;
use sluis_proto::sluis::signer::v2alpha1::SigningRing;

use crate::{Error, Kind, Store};

/// The target kind of an item that revokes one key by its kid.
pub const TARGET_KID: &str = "kid";

/// More pages than this are not read: the set is the keys that a person revoked by hand, and a list that
/// does not end is a store that is not answering as it should.
const MAX_PAGES: usize = 1000;

/// The kind `KeyRevocation`.
pub struct KeyRevocationKind;

impl Kind for KeyRevocationKind {
    type Id = String;
    type Value = KeyRevocation;
    const NAME: &'static str = "KeyRevocation";
}

/// The lower-case base32 of a thumbprint's 32 bytes, without padding (RFC 4648 section 6): 52 characters, the label
/// that names a kid or a recipient in an address, which does not allow upper case. `None` for anything that is not an
/// RFC 7638 SHA-256 thumbprint (43 base64url characters, 32 bytes). store@ holds a `KeyRevocation` item to the id
/// this gives, the readers derive the id with it, and `key@` derives the same label in Go (`recipientLabel`);
/// `tests/testdata/keyrevocation/ids.json` holds all of them to the encoding.
#[must_use]
pub fn thumbprint_label(thumbprint: &str) -> Option<String> {
    if thumbprint.len() != 43 {
        return None;
    }
    let raw = URL_SAFE_NO_PAD.decode(thumbprint).ok()?;
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

/// The id of the item that revokes the key `kid` (an RFC 7638 thumbprint), or `None` for a kid that is not one.
#[must_use]
pub fn kid_item_id(kid: &str) -> Option<String> {
    thumbprint_label(kid).map(|l| format!("{TARGET_KID}/{l}"))
}

/// The ring without the keys that `KeyRevocation` lists, in every state: the ring that a published key set is
/// built from (REQ-KEYS-107).
#[must_use]
pub fn without_revoked(mut ring: SigningRing, revoked: &HashSet<String>) -> SigningRing {
    ring.keys.retain(|k| !revoked.contains(&k.key_id));
    ring
}

/// A reader of the revocations of the boundary's token-signing keys.
pub struct KeyRevocations {
    store: Store<KeyRevocationKind>,
}

impl KeyRevocations {
    /// A reader over store@'s socket.
    ///
    /// # Errors
    ///
    /// When the kind is not in the registry.
    pub fn new(client: &Client) -> Result<Self, Error> {
        Ok(Self {
            store: Store::new_optional_tenant(client.clone())?,
        })
    }

    /// Whether `KeyRevocation` lists the key.
    ///
    /// # Errors
    ///
    /// [`Error::Address`] for a kid that is not a thumbprint, so that it is refused and not taken as
    /// not revoked; any other error when the store cannot answer.
    pub async fn is_revoked(&self, kid: &str) -> Result<bool, Error> {
        let id = kid_item_id(kid).ok_or_else(|| Error::Address("kid".into()))?;
        match self.store.get("", &id).await {
            Ok(_) => Ok(true),
            Err(Error::NotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Every kid that `KeyRevocation` lists.
    ///
    /// # Errors
    ///
    /// When the store cannot answer, or a list does not end.
    pub async fn revoked_kids(&self) -> Result<HashSet<String>, Error> {
        let mut kids = HashSet::new();
        let mut page = None;
        for _ in 0..MAX_PAGES {
            let (items, next) = self.store.list("", page).await?;
            for i in items {
                if i.value.target_kind == TARGET_KID && !i.value.target.is_empty() {
                    kids.insert(i.value.target);
                }
            }
            match next {
                Some(n) => page = Some(n),
                None => return Ok(kids),
            }
        }
        Err(Error::Address(format!(
            "list: more than {MAX_PAGES} pages of KeyRevocation"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../tests/testdata/keyrevocation/ids.json"
        ))
        .unwrap()
    }

    /// The shared vectors that `key@` in Go and store@ hold to: a kid names the item `kid/<label>`.
    #[test]
    fn the_item_id_of_a_kid_follows_the_shared_vectors() {
        let v = vectors();
        let rows = v["ids"].as_array().unwrap();
        assert!(rows.len() >= 10, "a sweep over nothing proves nothing");
        let mut kids = 0;
        for r in rows {
            let (kind, target, id) = (
                r["target_kind"].as_str().unwrap(),
                r["target"].as_str().unwrap(),
                r["id"].as_str().unwrap(),
            );
            if kind == "kid" {
                assert_eq!(kid_item_id(target).as_deref(), Some(id), "{target}");
                kids += 1;
            }
            if kind == "kid" || kind == "recipient" {
                assert_eq!(
                    thumbprint_label(target).as_deref(),
                    id.split_once('/').map(|(_, l)| l),
                    "{target}"
                );
            }
        }
        assert!(kids >= 3, "{kids} kid rows");
    }

    #[test]
    fn only_a_thumbprint_names_an_item() {
        assert_eq!(kid_item_id(""), None);
        assert_eq!(kid_item_id("not base64url!"), None);
        // Base64url of the wrong length: 31 bytes (42 characters) and 33 bytes (44 characters).
        assert_eq!(kid_item_id(&URL_SAFE_NO_PAD.encode([1u8; 31])), None);
        assert_eq!(kid_item_id(&URL_SAFE_NO_PAD.encode([1u8; 33])), None);
        assert!(kid_item_id(&URL_SAFE_NO_PAD.encode([1u8; 32])).is_some());
    }

    #[test]
    fn the_ring_without_revoked_lacks_a_revoked_kid_in_every_state() {
        use sluis_proto::sluis::signer::v2alpha1::SigningKey;
        let key = |id: &str, state: &str| SigningKey {
            key_id: id.into(),
            state: state.into(),
            ..SigningKey::default()
        };
        let ring = SigningRing {
            keys: vec![
                key("a", "active"),
                key("b", "pre-published"),
                key("c", "retiring"),
                key("d", "active"),
            ],
            ..SigningRing::default()
        };
        let revoked: HashSet<String> = ["a", "b", "c", "unknown"].map(String::from).into();
        let out = without_revoked(ring.clone(), &revoked);
        let ids: Vec<_> = out.keys.iter().map(|k| k.key_id.as_str()).collect();
        assert_eq!(ids, ["d"]);
        assert_eq!(without_revoked(ring.clone(), &HashSet::new()), ring);
    }
}
