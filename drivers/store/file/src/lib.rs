//! The `file` driver of store@: the config source contract (store-api.md "The source contract")
//! over a directory of signed config documents.
//!
//! - A document is asked for by the kebab-case name of its kind (`boundary`, `upstream`) and read
//!   from `<name>.jws` in the directory (signed-config.md "The document"). The driver returns the
//!   bytes and never parses them; the signature is store@'s to check.
//! - The version label is the SHA-384 of the file, in hex, so the same bytes give the same label
//!   whichever way they arrived.
//! - A path is opened with `openat2(RESOLVE_BENEATH)`. A symlink that stays below the directory is
//!   followed, because a mounted ConfigMap is a tree of such links and its update is the swap of
//!   one of them (signed-config.md "What a config source driver returns"); one that leaves the
//!   directory is refused.
//! - A file is opened with `O_NONBLOCK`, so that a FIFO in the directory cannot hang the open (and
//!   the thread with it), and anything that is not a regular file is refused. (`O_NOFOLLOW` is not
//!   set: a link inside the directory is followed on purpose, see above.)
//! - `Watch` looks at the file again every [`WATCH_EVERY`] and says when the label changes, so a
//!   replaced file and the swap of a mounted ConfigMap are both seen.

pub mod service;
pub mod suite;

use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;

use rustix::fs::{Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

/// The extension of a document.
const EXTENSION: &str = ".jws";
/// A document larger than this is refused. The payload is a third larger in base64url than the
/// file; the largest config service limit known is 2 MiB (signed-config.md "The payload").
pub const DOCUMENT_MAX: u64 = 4 * 1024 * 1024;
/// How often a watcher looks at its file again.
pub const WATCH_EVERY: Duration = Duration::from_millis(200);

/// Why a read was refused. [`service`] turns each into a Connect code and a reason.
#[derive(Debug)]
pub enum Error {
    /// The name is not a kind's kebab-case name.
    Name,
    /// There is no such document.
    Absent,
    /// The document is larger than [`DOCUMENT_MAX`], or is not a regular file.
    Bound,
    /// The filesystem failed.
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name => f.write_str("name"),
            Self::Absent => f.write_str("absent"),
            Self::Bound => f.write_str("bound"),
            Self::Io(e) => write!(f, "io: {:?}", e.kind()),
        }
    }
}

impl std::error::Error for Error {}

/// A document read from the directory.
pub struct Document {
    pub data: Vec<u8>,
    /// The SHA-384 of `data`, in lower-case hex.
    pub version: String,
}

/// An open directory of documents. Cheap to clone.
#[derive(Clone)]
pub struct Dir {
    root: std::sync::Arc<OwnedFd>,
}

impl Dir {
    /// Opens `dir`, which must be a directory.
    ///
    /// # Errors
    ///
    /// Fails when `dir` is missing or is not a directory.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        let fd = rustix::fs::open(
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("open the config directory")?;
        Ok(Self {
            root: std::sync::Arc::new(fd),
        })
    }

    /// Reads the document of the kind with this kebab-case name.
    ///
    /// # Errors
    ///
    /// [`Error::Name`] for a name that is not kebab-case, [`Error::Absent`] when there is no such
    /// file, [`Error::Bound`] for a file that is too large or is not a regular file.
    pub fn read(&self, name: &str) -> Result<Document, Error> {
        if !valid_name(name) {
            return Err(Error::Name);
        }
        let fd = rustix::fs::openat2(
            &*self.root,
            format!("{name}{EXTENSION}"),
            // NONBLOCK: the open of a FIFO returns at once, and `is_file` below refuses it.
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::BENEATH,
        )
        .map_err(|e| match e {
            Errno::NOENT => Error::Absent,
            // ELOOP, EXDEV and the like: a link that goes where it must not.
            Errno::LOOP | Errno::XDEV => Error::Bound,
            e => Error::Io(e.into()),
        })?;
        let file = std::fs::File::from(fd);
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() > DOCUMENT_MAX {
            return Err(Error::Bound);
        }
        let mut data = Vec::new();
        // One byte over the limit, so a file that grew since `metadata` is caught too.
        file.take(DOCUMENT_MAX + 1).read_to_end(&mut data)?;
        if data.len() as u64 > DOCUMENT_MAX {
            return Err(Error::Bound);
        }
        let version = label(&data);
        Ok(Document { data, version })
    }

    /// The version label of the document now, or None when there is none.
    ///
    /// # Errors
    ///
    /// As [`Dir::read`], except that an absent document is `None`.
    pub fn version(&self, name: &str) -> Result<Option<String>, Error> {
        match self.read(name) {
            Ok(d) => Ok(Some(d.version)),
            Err(Error::Absent) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// A kind's kebab-case name: 1 to 63 characters of lower-case letters, digits and `-`, starting
/// with a letter. It cannot hold a `/` or a `.`, so it cannot leave the directory.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    let mut b = name.bytes();
    name.len() <= 63
        && b.next().is_some_and(|c| c.is_ascii_lowercase())
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// The version label: the SHA-384 of the bytes, in lower-case hex.
fn label(data: &[u8]) -> String {
    use std::fmt::Write as _;
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, data)
        .as_ref()
        .iter()
        .fold(String::with_capacity(96), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
mod tests {
    use super::*;

    #[test]
    fn a_fifo_is_refused_at_once_and_does_not_hang_the_open() {
        let t = tempfile::tempdir().unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            t.path().join("boundary.jws"),
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let dir = Dir::open(t.path()).unwrap();
        // A blocking open of a FIFO with no writer never returns; run it aside to bound the wait.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(dir.read("boundary").err().map(|e| e.to_string())));
        let got = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the open of a FIFO hung");
        assert_eq!(got.as_deref(), Some("bound"));
    }
}
