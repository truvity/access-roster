//! The checkpoint of a log: a C2SP signed note of type 0x02 (ECDSA) over a `tlog-checkpoint` body, read
//! exactly as the writer makes it and as `sluis audit verify` reads it (cli/sluis/auditverify.go).
//!
//! The note and the checkpoint are read by a library, not by this file (REQ-SEC-018):
//!
//! - **signed-note** (C2SP): `signed_note` of Cloudflare's azul splits the note, reads the signature
//!   lines, refuses an oversized note, control characters, more than 100 signatures and a bad name, and
//!   verifies the signatures a [`NoteVerifier`] knows.
//! - **tlog-checkpoint** (C2SP): `tlog_checkpoint::CheckpointText` reads the origin line, the tree size
//!   in decimal, the root hash in standard base64 and the extension lines.
//!
//! What stays here is what no library has: the verifier of the log key, a P-256 key of signature type
//! 0x02, which `signed_note` does not ship (it ships Ed25519). It is a [`NoteVerifier`] on `aws-lc-rs`:
//!
//! - The verifier key is `name+hex(key hash)+base64(0x02 || SubjectPublicKeyInfo)`. The key hash of
//!   type 0x02 is the first four octets of the SHA-256 of the DER `SubjectPublicKeyInfo`, as the writer
//!   makes it (the wire format is fixed by the Go writer, so this is not the hash that signed-note
//!   recommends for new types).
//! - **The signature** is the standard one, as the witness implementation of transparency-dev has it
//!   (decision D-25; ADR 0006, "Named exceptions"): the log key is a P-256 key, the one exception to
//!   P-384, and the signature is ASN.1 DER ECDSA over the SHA-256 of the note text.
//!
//! A signature line of another name or another key hash is ignored (signed-note: a verifier ignores a
//! signer it does not know); one that names this key and does not verify refuses the note, and so does
//! a repeat of such a line.

use aws_lc_rs::digest;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use signed_note::{KeyName, Note, NoteError, NoteVerifier, VerifierList};
use tlog_checkpoint::CheckpointText;

/// The signature type byte of an ECDSA key in a signed note.
const SIG_TYPE_ECDSA: u8 = 0x02;
/// The DER prefix of a P-256 `SubjectPublicKeyInfo` (RFC 5480): SEQUENCE { SEQUENCE { id-ecPublicKey,
/// prime256v1 }, BIT STRING of 66 octets (no unused bits) } up to the point, which begins with 0x04.
const SPKI_P256_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Why a note or a key is refused. Each is a closed word; none carries a value of the note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The verifier key is not `name+hash+key` of a P-256 ECDSA key.
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

/// The [`NoteVerifier`] of a P-256 ECDSA key, signature type 0x02.
#[derive(Clone)]
struct EcdsaP256Verifier {
    name: KeyName,
    id: u32,
    point: Vec<u8>,
}

impl NoteVerifier for EcdsaP256Verifier {
    fn name(&self) -> &KeyName {
        &self.name
    }

    fn key_id(&self) -> u32 {
        self.id
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        // ECDSA over the SHA-256 of the text, as C2SP signature type 0x02 fixes (D-25).
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.point)
            .verify(msg, sig)
            .is_ok()
    }

    fn extract_timestamp_millis(&self, _sig: &[u8]) -> Result<Option<u64>, NoteError> {
        // Type 0x02 carries no timestamp.
        Ok(None)
    }
}

/// The verifier key of a log: the public half of its key, with the name and key hash a signature line
/// carries.
#[derive(Clone)]
pub struct LogKey {
    verifier: EcdsaP256Verifier,
}

impl LogKey {
    /// Reads `name+hex(key hash)+base64(0x02 || SubjectPublicKeyInfo)`.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] when it is not that, when the key is not P-256, or when the hash is not the
    /// key's.
    pub fn parse(text: &str) -> Result<Self, Error> {
        // The key data is base64 and may hold a plus sign, so split into three at most.
        let mut parts = text.trim().splitn(3, '+');
        let (Some(name), Some(hash), Some(data)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::Key);
        };
        let name = KeyName::new(name.to_owned()).map_err(|_| Error::Key)?;
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
        // A P-256 key has one DER form, so the prefix check also checks the curve.
        let point = spki
            .strip_prefix(&SPKI_P256_PREFIX[..])
            .filter(|p| p.len() == 65 && p[0] == 0x04)
            .ok_or(Error::Key)?;
        Ok(Self {
            verifier: EcdsaP256Verifier {
                name,
                id,
                point: point.to_vec(),
            },
        })
    }

    /// The name the key signs under.
    #[must_use]
    pub fn name(&self) -> &str {
        self.verifier.name.as_str()
    }

    /// Opens the note with this key and reads its checkpoint. The note's text is the checkpoint body;
    /// the key must have signed it.
    ///
    /// # Errors
    ///
    /// [`Error::Format`], [`Error::Signature`] or [`Error::Checkpoint`].
    pub fn open(&self, note: &[u8]) -> Result<Checkpoint, Error> {
        let note = Note::from_bytes(note).map_err(|_| Error::Format)?;
        let known = VerifierList::new(vec![Box::new(self.verifier.clone())]);
        match note.verify(&known) {
            Ok(_) => {}
            // A bad signature of the key, or none of the key at all (an unknown signer is ignored).
            Err(NoteError::InvalidSignature { .. } | NoteError::UnverifiedNote) => {
                return Err(Error::Signature);
            }
            Err(_) => return Err(Error::Format),
        }
        // The library checks the first line of each (name, key hash) and skips a repeat of it; a repeat
        // that does not verify refuses the note here, as every line of the key always did.
        for sig in note.signatures() {
            if sig.name() == &self.verifier.name
                && sig.id() == self.verifier.id
                && !self.verifier.verify(note.text(), sig.signature())
            {
                return Err(Error::Signature);
            }
        }
        let text = CheckpointText::from_bytes(note.text()).map_err(|_| Error::Checkpoint)?;
        Ok(Checkpoint {
            origin: text.origin().to_owned(),
            size: text.size(),
            root: text.hash().0,
        })
    }
}

/// The key hash of a DER `SubjectPublicKeyInfo`: the first four octets of its SHA-256.
fn key_id(spki: &[u8]) -> u32 {
    let d = digest::digest(&digest::SHA256, spki);
    let b = d.as_ref();
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _,
    };

    use super::*;

    /// The em dash and the space that open a signature line.
    const SIG_LINE: &str = "\u{2014} ";

    struct Signer {
        pair: EcdsaKeyPair,
        spki: Vec<u8>,
    }

    fn signer() -> Signer {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("key");
        let spki = [&SPKI_P256_PREFIX[..], pair.public_key().as_ref()].concat();
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

    /// verifies: REQ-SEC-018
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

    /// verifies: REQ-SEC-018
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

    /// verifies: REQ-SEC-018
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

    /// verifies: REQ-SEC-018
    #[test]
    fn a_verifier_key_must_be_a_p256_ecdsa_key_with_its_own_hash() {
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
        // A P-384 key is not accepted: the prefix of the SubjectPublicKeyInfo names the curve.
        let p384 = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_ASN1_SIGNING).expect("key");
        let p384_prefix: [u8; 23] = [
            0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
        ];
        let spki = [&p384_prefix[..], p384.public_key().as_ref()].concat();
        let id: String = key_id(&spki)
            .to_be_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let d = STANDARD.encode([&[SIG_TYPE_ECDSA][..], &spki].concat());
        assert_eq!(
            LogKey::parse(&format!("{name}+{id}+{d}")).err(),
            Some(Error::Key)
        );
    }

    /// verifies: REQ-SEC-018
    #[test]
    fn an_oversized_note_a_control_character_or_too_many_signatures_is_refused() {
        let s = signer();
        let key = LogKey::parse(&s.vkey("log")).expect("key");
        // Signed correctly, and still refused: the library reads no note over 1,000,000 octets.
        let big = format!("{}{}\n", text("42"), "x".repeat(1_000_000));
        let note = s.note("log", &big);
        assert!(note.len() > 1_000_000);
        assert_eq!(key.open(&note), Err(Error::Format));
        // A note a little under the limit is read.
        let fits = format!("{}{}\n", text("42"), "x".repeat(900_000));
        assert!(key.open(&s.note("log", &fits)).is_ok());
        // A control character other than the newline in the text, or in a signature line.
        for c in ["\t", "\r", "\u{0}", "\u{1b}"] {
            let ext = format!("{}a{c}b\n", text("42"));
            assert_eq!(key.open(&s.note("log", &ext)), Err(Error::Format), "{c:?}");
        }
        // 100 signature lines are read, 101 are not, whoever signed them.
        let good = String::from_utf8(s.note("log", &text("42"))).expect("utf8");
        let other = signer();
        for (extra, ok) in [(99, true), (100, false)] {
            let mut n = good.clone();
            for i in 0..extra {
                n.push_str(&other.line(&format!("w{i}"), &text("42")));
            }
            assert_eq!(key.open(n.as_bytes()).is_ok(), ok, "{extra} more lines");
        }
    }

    /// verifies: REQ-SEC-018
    #[test]
    fn a_malformed_signature_line_refuses_the_note_even_beside_a_good_one() {
        let s = signer();
        let key = LogKey::parse(&s.vkey("log")).expect("key");
        let good = String::from_utf8(s.note("log", &text("42"))).expect("utf8");
        for line in [
            "not a signature line\n",
            "\u{2014} log\n",
            "\u{2014} log !!!!\n",
            // Fewer than five octets of key hash and signature.
            "\u{2014} log AAAAAA==\n",
            // A name with a plus, which signed-note forbids.
            "\u{2014} a+b AAAAAAAAAA==\n",
            "\u{2014}  AAAAAAAAAA==\n",
        ] {
            let n = format!("{good}{line}");
            assert_eq!(key.open(n.as_bytes()), Err(Error::Format), "{line:?}");
        }
        // The signature block must end in a newline, and the blank line must come before it.
        let no_end = good.trim_end_matches('\n');
        assert_eq!(key.open(no_end.as_bytes()), Err(Error::Format));
    }

    /// verifies: REQ-SEC-018
    #[test]
    fn a_repeated_line_of_the_key_that_does_not_verify_refuses_the_note() {
        let s = signer();
        let key = LogKey::parse(&s.vkey("log")).expect("key");
        let good = String::from_utf8(s.note("log", &text("42"))).expect("utf8");
        // The library checks the first line of a key only; the second is the one this crate checks.
        let bad = s.line("log", &text("41"));
        assert_eq!(
            key.open(format!("{good}{bad}").as_bytes()),
            Err(Error::Signature)
        );
        let twice = format!("{good}{}", s.line("log", &text("42")));
        assert!(key.open(twice.as_bytes()).is_ok());
    }

    /// verifies: REQ-SEC-018
    #[test]
    fn a_cut_or_changed_note_is_refused_or_gives_the_same_checkpoint() {
        let s = signer();
        let key = LogKey::parse(&s.vkey("log")).expect("key");
        let note = s.note("log", &text("42"));
        let want = key.open(&note).expect("open");
        // Every prefix of the note is refused, but the whole one.
        for n in 0..note.len() {
            assert!(key.open(&note[..n]).is_err(), "cut at {n}");
        }
        // Every octet changed to every other value of a sample: refused, or still the same checkpoint
        // (a change can only land where it cannot alter what was signed or what is read).
        let mut rng = crate::testrng::Rng::new(0xc2_5b);
        for at in 0..note.len() {
            for _ in 0..4 {
                let mut m = note.clone();
                m[at] ^= rng.byte() | 1;
                if let Ok(cp) = key.open(&m) {
                    assert_eq!(cp, want, "change at {at}");
                }
            }
        }
    }

    /// verifies: REQ-SEC-018
    #[test]
    fn any_bytes_are_refused_or_read_and_never_panic() {
        let s = signer();
        let key = LogKey::parse(&s.vkey("log")).expect("key");
        let note = s.note("log", &text("42"));
        let mut rng = crate::testrng::Rng::new(0x5eed_f00d);
        for round in 0..3000 {
            // Random octets; or the note with a random run overwritten, dropped or doubled.
            let b: Vec<u8> = if round % 3 == 0 {
                let len = rng.below(400);
                (0..len).map(|_| rng.byte()).collect()
            } else {
                let mut m = note.clone();
                let (a, len) = (rng.below(m.len()), rng.below(8) + 1);
                let end = (a + len).min(m.len());
                match round % 3 {
                    1 => m.drain(a..end).for_each(drop),
                    _ => {
                        let run = m[a..end].to_vec();
                        m.splice(a..a, run);
                    }
                }
                m
            };
            let _ = key.open(&b);
            let _ = LogKey::parse(&String::from_utf8_lossy(&b));
        }
        // The verifier key too: random changes of a valid one are refused or give a key that is the same.
        let vkey = s.vkey("log");
        for at in 0..vkey.len() {
            let mut m = vkey.clone().into_bytes();
            m[at] = m[at].wrapping_add(1);
            if let Ok(k) = LogKey::parse(&String::from_utf8_lossy(&m)) {
                // Only the name can change freely; it then names another signer, and the note is refused.
                assert_ne!(k.name(), "log", "change at {at}");
                assert_eq!(k.open(&note), Err(Error::Signature), "change at {at}");
            }
        }
    }
}
