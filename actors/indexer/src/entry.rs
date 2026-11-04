//! The entries of a log and the records in them, as the writer makes them (actors/writer/internal/writerd/
//! entry.go, tree.go).
//!
//! - **Paths** (C2SP tlog-tiles): an entry bundle is `tile/entries/<N>`, with `N` as groups of three
//!   digits led by `x`, and a bundle that is not full is `<N>.p/<W>`. A bundle holds up to 256 entries,
//!   each with a two-octet length before it.
//! - **An entry** is RFC 8785 canonical JSON of one of two kinds: a `record` entry, which is the clear
//!   envelope of a record and the record sealed under its tenant's evidence key, and a `seal` entry,
//!   which ends a batch and holds no tenant data (0029, "Sealing").
//! - **The record** is what key@ opens. The envelope is a projection of it that the writer computed
//!   before sealing, so a reader that opens the record checks that the two agree and catches a writer
//!   that lies in the envelope (0029, "Encryption and crypto-shredding"). [`Opened::check`] does.

use aws_lc_rs::digest;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use sluis_proto::sluis::port::index::v2alpha1::Row;

/// The height of every tile of a `tlog-tiles` log: 256 hashes or entries.
pub const TILE: u64 = 256;

/// The kind of the address a record is sealed at; the id is [`seal_id`]. key@ binds the boundary, the
/// tenant, the kind and the id into the envelope (writerd.SealKind).
pub const SEAL_KIND: &str = "audit-entry";

/// The id of the address a record is sealed at: `<project>/<kind>/<log>/<record id>` (writerd.SealID).
#[must_use]
pub fn seal_id(project: &str, kind: &str, log: &str, uid: &str) -> String {
    format!("{project}/{kind}/{log}/{uid}")
}

/// The path of an entry bundle below the log's prefix: `tile/entries/<N>`, and `<N>.p/<W>` for a bundle
/// of `width` entries when that is fewer than a full tile.
#[must_use]
pub fn bundle_path(mut n: u64, width: u64) -> String {
    let mut s = format!("{:03}", n % 1000);
    while n >= 1000 {
        n /= 1000;
        s = format!("x{:03}/{s}", n % 1000);
    }
    let mut p = format!("tile/entries/{s}");
    if width < TILE {
        p.push_str(&format!(".p/{width}"));
    }
    p
}

/// Reads the entries of a bundle: each is a two-octet length and the entry.
///
/// # Errors
///
/// `None` when the bundle is cut short.
#[must_use]
pub fn parse_bundle(mut b: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let n = usize::from(u16::from_be_bytes([*b.first()?, *b.get(1)?]));
        out.push(b.get(2..2 + n)?);
        b = &b[2 + n..];
    }
    Some(out)
}

/// An entry of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// The end of a batch. It holds no record.
    Seal,
    /// A record, sealed.
    Record(RecordEntry),
}

/// The envelope of a record entry, and the record sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEntry {
    /// The record id, `metadata.uid`.
    pub uid: String,
    /// The tenant the record was routed to, `metadata.tenant_uid`.
    pub tenant: String,
    /// `time`, in milliseconds.
    pub time_ms: i64,
    /// `class_uid`.
    pub class_uid: i64,
    /// `activity_id`.
    pub activity_id: i64,
    /// `status_id`.
    pub status_id: i64,
    /// `actor.user.type_id`.
    pub actor_type_id: i64,
    /// The writer's stamp, in milliseconds.
    pub recorded_ms: i64,
    /// The envelope key@ made.
    pub sealed: Vec<u8>,
}

/// Why an entry or a record is not what the writer makes. A closed word; never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The entry is not canonical JSON of a known kind.
    Entry,
    /// The record is not a record of the sluis form.
    Record,
    /// The record and the envelope of its entry disagree.
    Envelope,
}

impl Error {
    /// The word for logs and refusals.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Entry => "entry.format",
            Self::Record => "record.format",
            Self::Envelope => "envelope.disagrees",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.word())
    }
}

impl std::error::Error for Error {}

fn int(v: &Value, path: &[&str]) -> Option<i64> {
    get(v, path)?.as_i64()
}

fn text<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    get(v, path)?.as_str()
}

fn get<'a>(mut v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    for k in path {
        v = v.get(k)?;
    }
    Some(v)
}

/// Reads an entry of the log.
///
/// # Errors
///
/// [`Error::Entry`] for anything the writer does not make.
pub fn parse_entry(bytes: &[u8]) -> Result<Entry, Error> {
    let v: Value = serde_json::from_slice(bytes).map_err(|_| Error::Entry)?;
    match text(&v, &["entry"]) {
        Some("seal") => Ok(Entry::Seal),
        Some("record") => {
            let sealed = STANDARD
                .decode(text(&v, &["sealed"]).ok_or(Error::Entry)?)
                .map_err(|_| Error::Entry)?;
            let n = |p: &[&str]| int(&v, p).ok_or(Error::Entry);
            let s = |p: &[&str]| text(&v, p).filter(|s| !s.is_empty()).ok_or(Error::Entry);
            Ok(Entry::Record(RecordEntry {
                uid: s(&["metadata", "uid"])?.to_owned(),
                tenant: s(&["metadata", "tenant_uid"])?.to_owned(),
                time_ms: n(&["time"])?,
                class_uid: n(&["class_uid"])?,
                activity_id: n(&["activity_id"])?,
                status_id: n(&["status_id"])?,
                actor_type_id: n(&["actor", "user", "type_id"])?,
                recorded_ms: n(&["writer", "recorded_at"])?,
                sealed,
            }))
        }
        _ => Err(Error::Entry),
    }
}

/// A record key@ opened, with the entry it came from.
pub struct Opened {
    value: Value,
}

impl Opened {
    /// Reads the plaintext key@ returned as a record.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] when it is not JSON.
    pub fn parse(plaintext: &[u8]) -> Result<Self, Error> {
        let value: Value = serde_json::from_slice(plaintext).map_err(|_| Error::Record)?;
        value
            .is_object()
            .then_some(Self { value })
            .ok_or(Error::Record)
    }

    /// Checks that the record and the clear envelope of its entry agree on every field the envelope
    /// projects, and that the record names this boundary (`metadata.log_name`, which the writer checks
    /// against the log). A record that names a tenant must name the one it was routed to; a record that
    /// names none was routed to the operator's own tenant, which the envelope alone states.
    ///
    /// # Errors
    ///
    /// [`Error::Envelope`] on any disagreement, [`Error::Record`] when a field is missing.
    pub fn check(&self, e: &RecordEntry, boundary: &str) -> Result<(), Error> {
        let v = &self.value;
        let agree = int(v, &["time"]) == Some(e.time_ms)
            && int(v, &["class_uid"]) == Some(e.class_uid)
            && int(v, &["activity_id"]) == Some(e.activity_id)
            && int(v, &["status_id"]) == Some(e.status_id)
            && int(v, &["actor", "user", "type_id"]) == Some(e.actor_type_id)
            && text(v, &["metadata", "uid"]) == Some(e.uid.as_str())
            && text(v, &["metadata", "tenant_uid"]).is_none_or(|t| t == e.tenant);
        if !agree {
            return Err(Error::Envelope);
        }
        if text(v, &["metadata", "log_name"]) != Some(boundary) {
            return Err(Error::Envelope);
        }
        Ok(())
    }

    /// The row of the index for this record: the fixed columns of 0028 and the record once. `plaintext`
    /// is the bytes key@ opened, which are kept as they are (RFC 8785 bytes; nothing re-encodes a record).
    ///
    /// # Errors
    ///
    /// [`Error::Record`] when a column the writer requires is missing.
    pub fn row(&self, e: &RecordEntry, seq: u64, plaintext: Vec<u8>) -> Result<Row, Error> {
        let v = &self.value;
        let req = |p: &[&str]| text(v, p).filter(|s| !s.is_empty()).ok_or(Error::Record);
        let opt = |p: &[&str]| text(v, p).unwrap_or_default().to_owned();
        // The hash of the record is the SHA-384 of its bytes, the digest 0006 fixes for hashes.
        let hash = digest::digest(&digest::SHA384, &plaintext)
            .as_ref()
            .to_vec();
        Ok(Row {
            tenant: e.tenant.clone(),
            hash,
            seq: i64::try_from(seq).map_err(|_| Error::Record)?,
            time_ms: e.time_ms,
            recorded_ms: e.recorded_ms,
            boundary: req(&["metadata", "log_name"])?.to_owned(),
            action: req(&["metadata", "event_code"])?.to_owned(),
            class_uid: e.class_uid,
            activity_id: e.activity_id,
            status_id: e.status_id,
            status_code: opt(&["status_code"]),
            actor_uid: req(&["actor", "user", "uid"])?.to_owned(),
            actor_type_id: e.actor_type_id,
            trace_id: opt(&["metadata", "correlation_uid"]),
            record_id: e.uid.clone(),
            product: req(&["metadata", "product", "name"])?.to_owned(),
            record: plaintext,
            ..Row::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_paths_follow_tlog_tiles() {
        assert_eq!(bundle_path(0, 256), "tile/entries/000");
        assert_eq!(bundle_path(7, 3), "tile/entries/007.p/3");
        assert_eq!(bundle_path(1234, 256), "tile/entries/x001/234");
        assert_eq!(
            bundle_path(1_234_067, 12),
            "tile/entries/x001/x234/067.p/12"
        );
    }

    #[test]
    fn a_bundle_is_length_prefixed_and_a_cut_one_is_refused() {
        let b = [0, 2, b'a', b'b', 0, 1, b'c'];
        assert_eq!(parse_bundle(&b), Some(vec![&b"ab"[..], &b"c"[..]]));
        assert_eq!(parse_bundle(&b[..5]), None);
        assert_eq!(parse_bundle(&[]), Some(vec![]));
    }
}
