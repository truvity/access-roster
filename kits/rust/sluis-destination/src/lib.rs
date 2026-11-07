#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine
//! The destination port of exporter@ (ADR 0009, "The destination port").
//!
//! A destination is where a published document goes: a directory, later a bucket behind an edge. The port has five
//! calls, and a driver for each destination type implements them: [`Destination::put`] writes a document whole and
//! atomically, [`Destination::delete`] removes one exporter@ wrote, [`Destination::list`] lists what exporter@ wrote
//! with the digests, [`Destination::purge`] evicts the edge copy of public addresses, and [`Destination::read_back`]
//! fetches a public address the way a verifier does. A driver with no public address answers
//! [`Error::Unsupported`] to `read_back`, and a driver with no edge answers [`Purged::None`] to `purge`.
//!
//! - [`rpc`] serves any [`Destination`] as the Connect `DestinationService` on a driver's socket, and is the client
//!   exporter@ calls it with.
//! - [`memory`] is the in-memory driver (tests only; it records every call and can play a stale edge).
//! - [`suite`] is the conformance suite: every driver runs it from its `conformance` command, and the in-memory driver
//!   passes it (REQ-EXPORT-027).

use std::future::Future;

use aws_lc_rs::digest::{SHA256, digest};

pub mod memory;
pub mod rpc;
pub mod suite;

/// The longest address, in bytes.
pub const ADDRESS_MAX: usize = 512;
/// The most segments an address has.
pub const SEGMENTS_MAX: usize = 8;
/// The longest segment, in bytes.
pub const SEGMENT_MAX: usize = 128;
/// The default and the largest page of a listing.
pub const PAGE_DEFAULT: usize = 200;
/// The largest page of a listing.
pub const PAGE_MAX: usize = 1000;
/// The largest document a destination takes, in bytes. A published document is small; a larger one is a mistake. It
/// is below the size of a message the Connect server takes (4 MiB), so the refusal is this one on both sides.
pub const BODY_MAX: usize = 2 << 20;

/// Why a call did not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The destination has no public address (no edge to purge, nothing to read back from), or it is a kind of
    /// destination that cannot do this call. `unimplemented` / `unsupported`.
    Unsupported,
    /// The address, the page token, the prefix or the body is not acceptable. The string names the field.
    Invalid(&'static str),
    /// The destination could not be reached or failed: try again later. The text names no value.
    Unavailable(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => f.write_str("unsupported"),
            Self::Invalid(field) => write!(f, "invalid: {field}"),
            Self::Unavailable(why) => write!(f, "unavailable: {why}"),
        }
    }
}

impl std::error::Error for Error {}

/// A document to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// Where it goes: [`check_address`] says what is acceptable.
    pub address: String,
    /// The `Content-Type` it is served with.
    pub content_type: String,
    /// The `Cache-Control` it is served with.
    pub cache_control: String,
    /// The whole document.
    pub body: Vec<u8>,
}

/// What a destination holds after a [`Destination::put`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// The destination's own version (opaque).
    pub version: String,
    /// The SHA-256 of the body it holds, lower-case hex.
    pub sha256: String,
}

/// One document in a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// The address.
    pub address: String,
    /// The SHA-256 of the body the destination holds now, lower-case hex.
    pub sha256: String,
    /// The `Content-Type` it was written with.
    pub content_type: String,
    /// The `Cache-Control` it was written with.
    pub cache_control: String,
    /// The length of the body.
    pub size: u64,
}

/// One page of a listing, in address order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    /// The documents.
    pub documents: Vec<Listed>,
    /// The token of the next page; `None` on the last.
    pub next: Option<String>,
}

/// What a purge did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purged {
    /// There is no edge: nothing to evict.
    None,
    /// The edge accepted the purge.
    Purged,
}

/// What a verifier would have seen at a public address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// The HTTP status.
    pub status: u16,
    /// The `Cache-Control` of the answer.
    pub cache_control: String,
    /// The `Content-Type` of the answer.
    pub content_type: String,
    /// The `Age` of the answer as sent; empty when it has none.
    pub age: String,
    /// The cache state the edge reports; empty when it reports none.
    pub cache_state: String,
    /// The body.
    pub body: Vec<u8>,
}

/// A driver of the destination port. The calls take `&self`: a driver is shared by the tasks of a server.
pub trait Destination: Send + Sync {
    /// Writes the document whole and atomically: a reader sees the old document or the new one, never half of it. A
    /// document already at the address is replaced.
    fn put(&self, doc: Document) -> impl Future<Output = Result<Written, Error>> + Send;

    /// Removes the document at the address if exporter@ wrote it; `false` when there was none. Anything else at the
    /// destination is left alone.
    fn delete(&self, address: &str) -> impl Future<Output = Result<bool, Error>> + Send;

    /// The documents exporter@ wrote under the prefix, in address order, with the digest of what the destination holds
    /// now (so an edit made at the destination shows). `page_size` 0 is [`PAGE_DEFAULT`].
    fn list(
        &self,
        prefix: &str,
        page: Option<&str>,
        page_size: usize,
    ) -> impl Future<Output = Result<Page, Error>> + Send;

    /// Evicts the edge copy of the public addresses; [`Purged::None`] where there is no edge.
    fn purge(&self, addresses: &[String]) -> impl Future<Output = Result<Purged, Error>> + Send;

    /// Fetches a public address the way a verifier does: no credential and no cache-buster. [`Error::Unsupported`]
    /// where the destination has no public address.
    fn read_back(&self, address: &str) -> impl Future<Output = Result<Fetched, Error>> + Send;
}

/// The SHA-256 of `body`, lower-case hex.
#[must_use]
pub fn sha256_hex(body: &[u8]) -> String {
    hex(digest(&SHA256, body).as_ref())
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Checks an address: one to [`SEGMENTS_MAX`] segments joined by `/`, each 1 to [`SEGMENT_MAX`] characters of lower-case
/// letters, digits, `-`, `_` and `.`, never `.` or `..`, at most [`ADDRESS_MAX`] bytes. The first segment is not
/// `.sluis`, which a driver may keep for itself, and no segment starts with `.tmp-`, the name of a driver's temporary
/// file. A leading dot is allowed otherwise, for `.well-known`.
///
/// # Errors
///
/// [`Error::Invalid`] naming `address`.
pub fn check_address(address: &str) -> Result<(), Error> {
    if address.is_empty() || address.len() > ADDRESS_MAX {
        return Err(Error::Invalid("address"));
    }
    let mut n = 0;
    for seg in address.split('/') {
        n += 1;
        let ok = !seg.is_empty()
            && seg.len() <= SEGMENT_MAX
            && seg != "."
            && seg != ".."
            && seg
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'));
        if !ok || n > SEGMENTS_MAX {
            return Err(Error::Invalid("address"));
        }
    }
    // A driver keeps `.sluis` for itself and makes its temporary files `.tmp-*` beside the document it writes.
    if address.split('/').next() == Some(".sluis")
        || address.split('/').any(|s| s.starts_with(".tmp-"))
    {
        return Err(Error::Invalid("address"));
    }
    Ok(())
}

/// Checks a prefix of a listing: empty, or an address prefix that ends at a segment boundary or inside a segment (a
/// prefix `.well` matches `.well-known/jwks`). It has the characters of an address and no `..` segment.
///
/// # Errors
///
/// [`Error::Invalid`] naming `prefix`.
pub fn check_prefix(prefix: &str) -> Result<(), Error> {
    if prefix.len() > ADDRESS_MAX {
        return Err(Error::Invalid("prefix"));
    }
    let ok = prefix
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'/'))
        && !prefix.starts_with('/')
        && !prefix.contains("//")
        && prefix.split('/').all(|s| s != "." && s != "..");
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid("prefix"))
    }
}

/// Checks a document before a driver writes it.
///
/// # Errors
///
/// [`Error::Invalid`] naming the field.
pub fn check_document(d: &Document) -> Result<(), Error> {
    check_address(&d.address)?;
    if d.body.len() > BODY_MAX {
        return Err(Error::Invalid("body"));
    }
    for (name, v) in [
        ("content_type", &d.content_type),
        ("cache_control", &d.cache_control),
    ] {
        // These become header values: printable ASCII only, and bounded.
        if v.len() > 256 || !v.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err(Error::Invalid(name));
        }
    }
    Ok(())
}

/// The page size to use for a request: 0 is the default, and no page is larger than [`PAGE_MAX`].
#[must_use]
pub fn page_size(requested: usize) -> usize {
    match requested {
        0 => PAGE_DEFAULT,
        n => n.min(PAGE_MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_a_short_path_of_plain_segments() {
        for ok in [
            "jwks",
            "jwks.json",
            ".well-known/jwks.json",
            "a/b/c",
            "a_b-c.d",
        ] {
            assert_eq!(check_address(ok), Ok(()), "{ok}");
        }
        let long = "a".repeat(SEGMENT_MAX + 1);
        let deep = ["a"; SEGMENTS_MAX + 1].join("/");
        for bad in [
            "", "/a", "a/", "a//b", ".", "..", "a/../b", "./a", "A", "a b", "a\\b", "a\0b",
            ".sluis/x", ".sluis", ".tmp-1-2", "a/.tmp-x", "é", &long, &deep,
        ] {
            assert_eq!(
                check_address(bad),
                Err(Error::Invalid("address")),
                "{bad:?}"
            );
        }
        assert_eq!(check_prefix(""), Ok(()));
        assert_eq!(check_prefix(".well"), Ok(()));
        assert_eq!(check_prefix("a/"), Ok(()));
        assert!(check_prefix("../").is_err() && check_prefix("/a").is_err());
    }

    #[test]
    fn the_digest_is_sha256_in_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
