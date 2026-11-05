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

/// The RFC 4648 section 6 alphabet, lower case.
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Lower-case base32 without padding.
fn base32_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

/// The id of the item that revokes the key `kid` (a base64url thumbprint), or `None` for a kid that is not
/// base64url.
#[must_use]
pub fn kid_item_id(kid: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(kid).ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(format!("{TARGET_KID}/{}", base32_lower(&bytes)))
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
        Err(Error::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_item_id_of_a_kid_is_its_lower_case_base32() {
        // RFC 4648 section 10 vectors, lower-cased and unpadded.
        assert_eq!(base32_lower(b""), "");
        assert_eq!(base32_lower(b"f"), "my");
        assert_eq!(base32_lower(b"fo"), "mzxq");
        assert_eq!(base32_lower(b"foo"), "mzxw6");
        assert_eq!(base32_lower(b"foob"), "mzxw6yq");
        assert_eq!(base32_lower(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
        // A 32-byte thumbprint is 52 characters, as key@'s label is.
        let kid = URL_SAFE_NO_PAD.encode([0xffu8; 32]);
        let id = kid_item_id(&kid).unwrap();
        assert_eq!(id, format!("kid/{}", "7".repeat(51) + "q"));
        assert_eq!(id.len(), 4 + 52);
        assert_eq!(kid_item_id("not base64url!"), None);
        assert_eq!(kid_item_id(""), None);
    }
}
