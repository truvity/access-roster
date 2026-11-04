//! The checkpoint of a log: a C2SP signed note of type 0x02 (ECDSA) over a `tlog-checkpoint` body, read
//! exactly as the writer makes it and as `sluis audit verify` reads it (cli/sluis/auditverify.go).
//!
//! - **signed-note** (C2SP): the text is the checkpoint body, then a blank line, then one signature
//!   line `— <name> <base64(key hash || signature)>` for each signer. The key hash of type 0x02 is the
//!   first four octets of the SHA-256 of the DER `SubjectPublicKeyInfo`. The verifier key is
//!   `name+hex(key hash)+base64(0x02 || SubjectPublicKeyInfo)`.
//! - **tlog-checkpoint** (C2SP): the origin line, the tree size in decimal, the root hash in standard
//!   base64, then optional extension lines.
//! - **The digest** is the one difference from the witness implementation and is decision D-25: the
//!   log key is a P-384 key that key@ and AWS KMS use only for SHA-384, so the note text is signed as
//!   its SHA-384, and the signature is ASN.1 DER. It is named once, in [`DIGEST`].
//!
//! A signature line of another name or another key hash is ignored (signed-note: a verifier ignores a
//! signer it does not know); one that names this key and does not verify refuses the note.

use aws_lc_rs::digest;
use aws_lc_rs::signature::{ECDSA_P384_SHA384_ASN1, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// The digest key@ signs for a checkpoint (decision D-25): the SHA-384 of the note text. The ECDSA
/// verifier below hashes with it; there is no other place that names it.
pub const DIGEST: &digest::Algorithm = &digest::SHA384;

/// The signature type byte of an ECDSA key in a signed note.
const SIG_TYPE_ECDSA: u8 = 0x02;
/// The DER prefix of a P-384 `SubjectPublicKeyInfo` (RFC 5480): SEQUENCE { SEQUENCE { id-ecPublicKey,
/// secp384r1 }, BIT STRING of 98 octets (no unused bits) } up to the point, which begins with 0x04.
const SPKI_P384_PREFIX: [u8; 23] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];
/// The em dash and the space that open a signature line.
const SIG_LINE: &str = "\u{2014} ";

/// Why a note or a key is refused. Each is a closed word; none carries a value of the note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The verifier key is not `name+hash+key` of a P-384 ECDSA key.
    Key,
    /// The note is not a signed note.
    Format,
    /// No signature of the key verifies, or one that names the key does not.
    Signature,
    /// The text is not a checkpoint.
    Checkpoint,
}

impl Error {
    /// The word for logs and refusals.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Format => "note.format",
            Self::Signature => "note.signature",
            Self::Checkpoint => "checkpoint.format",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.word())
    }
}

impl std::error::Error for Error {}

/// A parsed checkpoint body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The origin line.
    pub origin: String,
    /// The tree size.
    pub size: u64,
    /// The root hash (SHA-256, RFC 6962).
    pub root: [u8; 32],
}

/// The verifier key of a log: the public half of its key, with the name and key hash a signature line
/// carries.
#[derive(Clone)]
pub struct LogKey {
    name: String,
    id: u32,
    point: Vec<u8>,
}

impl LogKey {
    /// Reads `name+hex(key hash)+base64(0x02 || SubjectPublicKeyInfo)`.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] when it is not that, when the key is not P-384, or when the hash is not the
    /// key's.
    pub fn parse(text: &str) -> Result<Self, Error> {
        // The key data is base64 and may hold a plus sign, so split into three at most.
        let mut parts = text.trim().splitn(3, '+');
        let (Some(name), Some(hash), Some(data)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::Key);
        };
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(Error::Key);
        }
        let id = u32::from_str_radix(hash, 16)
            .ok()
            .filter(|_| hash.len() == 8)
            .ok_or(Error::Key)?;
        let data = STANDARD.decode(data).map_err(|_| Error::Key)?;
        let (&kind, spki) = data.split_first().ok_or(Error::Key)?;
        if kind != SIG_TYPE_ECDSA {
            return Err(Error::Key);
        }
        if key_id(spki) != id {
            return Err(Error::Key);
        }
        // A P-384 key has one DER form, so the prefix check also checks the curve.
        let point = spki
            .strip_prefix(&SPKI_P384_PREFIX[..])
            .filter(|p| p.len() == 97 && p[0] == 0x04)
            .ok_or(Error::Key)?;
        Ok(Self {
            name: name.to_owned(),
            id,
            point: point.to_vec(),
        })
    }

    /// The name the key signs under.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Opens the note with this key and reads its checkpoint. The note's text is the checkpoint body;
    /// the key must have signed it.
    ///
    /// # Errors
    ///
    /// [`Error::Format`], [`Error::Signature`] or [`Error::Checkpoint`].
    pub fn open(&self, note: &[u8]) -> Result<Checkpoint, Error> {
        let note = std::str::from_utf8(note).map_err(|_| Error::Format)?;
        // The text ends at its last newline; a blank line follows; the signature lines end the note.
        let cut = note.find("\n\n").ok_or(Error::Format)?;
        let (text, sigs) = (&note[..=cut], &note[cut + 2..]);
        if sigs.is_empty() || !sigs.ends_with('\n') {
            return Err(Error::Format);
        }
        let key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, &self.point);
        let mut good = false;
        for line in sigs.strip_suffix('\n').unwrap_or(sigs).split('\n') {
            let rest = line.strip_prefix(SIG_LINE).ok_or(Error::Format)?;
            let (name, b64) = rest.split_once(' ').ok_or(Error::Format)?;
            let blob = STANDARD.decode(b64).map_err(|_| Error::Format)?;
            if blob.len() < 5 {
                return Err(Error::Format);
            }
            let (hash, sig) = blob.split_at(4);
            // A signer this verifier does not know is ignored.
            if name != self.name || hash != self.id.to_be_bytes() {
                continue;
            }
            // The key aws-lc-rs verifies is the one SHA-384 of the text (D-25).
            if key.verify(text.as_bytes(), sig).is_err() {
                return Err(Error::Signature);
            }
            good = true;
        }
        if !good {
            return Err(Error::Signature);
        }
        parse_checkpoint(text)
    }
}

/// The key hash of a DER `SubjectPublicKeyInfo`: the first four octets of its SHA-256.
fn key_id(spki: &[u8]) -> u32 {
    let d = digest::digest(&digest::SHA256, spki);
    let b = d.as_ref();
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Reads a checkpoint body: origin, size, root, and any extension lines (tlog-checkpoint).
fn parse_checkpoint(text: &str) -> Result<Checkpoint, Error> {
    let lines: Vec<&str> = text.split('\n').collect();
    // The body ends with a newline, so the last element is empty.
    if lines.len() < 4 || lines.last() != Some(&"") || lines[0].is_empty() {
        return Err(Error::Checkpoint);
    }
    let size: u64 = lines[1].parse().map_err(|_| Error::Checkpoint)?;
    // A size with a sign, a plus or leading zeros is not the decimal form the format fixes.
    if size.to_string() != lines[1] {
        return Err(Error::Checkpoint);
    }
    let root = STANDARD.decode(lines[2]).map_err(|_| Error::Checkpoint)?;
    let root: [u8; 32] = root.try_into().map_err(|_| Error::Checkpoint)?;
    Ok(Checkpoint {
        origin: lines[0].to_owned(),
        size,
        root,
    })
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};

    use super::*;

    struct Signer {
        pair: EcdsaKeyPair,
        spki: Vec<u8>,
    }

    fn signer() -> Signer {
        let pair = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_ASN1_SIGNING).expect("key");
        let spki = [&SPKI_P384_PREFIX[..], pair.public_key().as_ref()].concat();
        Signer { pair, spki }
    }

    impl Signer {
        fn vkey(&self, name: &str) -> String {
            let hex: String = key_id(&self.spki)
                .to_be_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let data = [&[SIG_TYPE_ECDSA][..], &self.spki].concat();
            format!("{name}+{hex}+{}", STANDARD.encode(data))
        }

        fn line(&self, name: &str, text: &str) -> String {
            let sig = self
                .pair
                .sign(&SystemRandom::new(), text.as_bytes())
                .expect("sign");
            let blob = [&key_id(&self.spki).to_be_bytes()[..], sig.as_ref()].concat();
            format!("{SIG_LINE}{name} {}\n", STANDARD.encode(blob))
        }

        fn note(&self, name: &str, text: &str) -> Vec<u8> {
            format!("{text}\n{}", self.line(name, text)).into_bytes()
        }
    }

    const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn text(size: &str) -> String {
        format!("example.test/dev/p/audit/main\n{size}\n{ROOT}\n")
    }

    #[test]
    fn a_note_signed_by_the_key_opens_and_gives_the_checkpoint() {
        let s = signer();
        let key = LogKey::parse(&s.vkey("log")).expect("key");
        let cp = key.open(&s.note("log", &text("42"))).expect("open");
        assert_eq!(
            (cp.origin.as_str(), cp.size, cp.root),
            ("example.test/dev/p/audit/main", 42, [0u8; 32])
        );
        // Extension lines are allowed (tlog-checkpoint).
        let ext = format!("{}an extension\n", text("42"));
        assert!(key.open(&s.note("log", &ext)).is_ok());
    }

    #[test]
    fn a_changed_text_a_foreign_key_or_a_missing_signature_is_refused() {
        let (s, other) = (signer(), signer());
        let key = LogKey::parse(&s.vkey("log")).expect("key");
        let good = String::from_utf8(s.note("log", &text("42"))).expect("utf8");
        let changed = good.replacen("\n42\n", "\n43\n", 1);
        assert_eq!(key.open(changed.as_bytes()), Err(Error::Signature));
        // Another key under the same name and the same key hash cannot be made, and under its own hash it
        // is a signer this verifier does not know: ignored, so no signature of the key is there.
        assert_eq!(
            key.open(&other.note("log", &text("42"))),
            Err(Error::Signature)
        );
        assert_eq!(
            key.open(&other.note("elsewhere", &text("42"))),
            Err(Error::Signature)
        );
        // A note with no signature, or no blank line, is not a signed note.
        assert_eq!(key.open(text("42").as_bytes()), Err(Error::Format));
        assert_eq!(
            key.open(format!("{}\n", text("42")).as_bytes()),
            Err(Error::Format)
        );
        assert_eq!(key.open(&[0xff, 0xfe]), Err(Error::Format));
        // A signature of the key beside one of an unknown signer is enough; a bad one of the key is not.
        let both = format!("{}{}", good, other.line("witness", &text("42")));
        assert!(key.open(both.as_bytes()).is_ok());
        let sig_line = s.line("log", &text("41"));
        let bad = format!("{}\n{sig_line}", text("42"));
        assert_eq!(key.open(bad.as_bytes()), Err(Error::Signature));
    }

    #[test]
    fn a_checkpoint_has_the_decimal_size_and_a_32_octet_root() {
        let s = signer();
        let key = LogKey::parse(&s.vkey("log")).expect("key");
        for bad in ["042", "+42", "-1", "4 2"] {
            assert_eq!(
                key.open(&s.note("log", &text(bad))),
                Err(Error::Checkpoint),
                "size {bad:?}"
            );
        }
        let short = "example.test/x\n1\nAAAA\n".to_owned();
        assert_eq!(key.open(&s.note("log", &short)), Err(Error::Checkpoint));
        let empty_origin = format!("\n1\n{ROOT}\n");
        assert_eq!(
            key.open(&s.note("log", &empty_origin)),
            Err(Error::Checkpoint)
        );
        let no_newline = format!("example.test/x\n1\n{ROOT}");
        assert!(key.open(&s.note("log", &no_newline)).is_err());
    }

    #[test]
    fn a_verifier_key_must_be_a_p384_ecdsa_key_with_its_own_hash() {
        let s = signer();
        let good = s.vkey("log");
        assert!(LogKey::parse(&good).is_ok());
        let (name, rest) = good.split_once('+').expect("plus");
        let (hash, data) = rest.split_once('+').expect("plus");
        // The hash is not the key's; the type byte is Ed25519's; the name holds a space; the data is cut.
        assert_eq!(
            LogKey::parse(&format!("{name}+00000000+{data}")).err(),
            Some(Error::Key)
        );
        let ed = STANDARD.encode([&[0x01u8][..], &s.spki].concat());
        assert_eq!(
            LogKey::parse(&format!("{name}+{hash}+{ed}")).err(),
            Some(Error::Key)
        );
        assert_eq!(
            LogKey::parse(&format!("a b+{hash}+{data}")).err(),
            Some(Error::Key)
        );
        assert_eq!(
            LogKey::parse(&format!("{name}+{hash}+{}", &data[..20])).err(),
            Some(Error::Key)
        );
        assert_eq!(
            LogKey::parse(&format!("{name}+{hash}")).err(),
            Some(Error::Key)
        );
        assert_eq!(LogKey::parse("").err(), Some(Error::Key));
        // A P-256 key is not accepted: the prefix of the SubjectPublicKeyInfo names the curve.
        let mut p256 = s.spki.clone();
        p256[18] = 0x07;
        let id: String = key_id(&p256)
            .to_be_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let d = STANDARD.encode([&[SIG_TYPE_ECDSA][..], &p256].concat());
        assert_eq!(
            LogKey::parse(&format!("{name}+{id}+{d}")).err(),
            Some(Error::Key)
        );
    }
}
