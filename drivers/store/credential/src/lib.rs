//! The `credential` driver of store@: the secret source contract (store-api.md "The source
//! contract") over systemd credentials (ADR 0005, "Secret sources").
//!
//! - A secret is the file of that name in the credentials directory: `$CREDENTIALS_DIRECTORY` for
//!   a service started with `LoadCredential=`, or the directory `--dir` names in the local
//!   installation. The directory is read-only to the driver; nothing is written, cached or logged.
//! - The value is returned to the owner of the socket only (store@, by the registry), and nothing
//!   about it leaves this process but the answer to a `Read`: no log line, no error text, no
//!   version label that is a hash of the value.
//! - A file readable by group or others is refused. systemd makes a credential `0400`; a local
//!   directory must follow, or the driver would hand out a value that anyone could already read.
//! - A symlink is refused in the path and as the file: a credential is a plain file.
//! - The capability is `NONE`: a credential cannot change under a running service.

pub mod service;
pub mod suite;

use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use rustix::fs::{Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

/// A value larger than this is refused. SSM's standard limit is 4 KiB and its advanced one is
/// 8 KiB; a credential beyond that is not a secret of sluis.
pub const SECRET_MAX: u64 = 64 * 1024;

/// Why a read was refused. [`service`] turns each into a Connect code and a reason.
#[derive(Debug)]
pub enum Error {
    /// The name is not a credential name.
    Name,
    /// There is no such credential.
    Absent,
    /// The file is larger than [`SECRET_MAX`] or is not a regular file.
    Bound,
    /// The file is open to group or others.
    Rule,
    /// The filesystem failed.
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Name => f.write_str("name"),
            Self::Absent => f.write_str("absent"),
            Self::Bound => f.write_str("bound"),
            Self::Rule => f.write_str("rule"),
            Self::Io(k) => write!(f, "io: {k:?}"),
        }
    }
}

impl std::error::Error for Error {}

/// A secret read from the directory. It has no `Debug`, so it cannot reach a log by accident.
pub struct Secret {
    pub data: Vec<u8>,
    /// Changes when the file does; it is made of the modification time, the size and the inode,
    /// never of the value.
    pub version: String,
}

/// An open credentials directory. Cheap to clone.
#[derive(Clone)]
pub struct Dir {
    root: std::sync::Arc<OwnedFd>,
}

impl Dir {
    /// Opens `dir`, which must be a directory (not a symlink).
    ///
    /// # Errors
    ///
    /// Fails when `dir` is missing or is not a directory.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        let fd = rustix::fs::open(
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("open the credentials directory")?;
        Ok(Self {
            root: std::sync::Arc::new(fd),
        })
    }

    /// Reads the credential with this name.
    ///
    /// # Errors
    ///
    /// [`Error::Name`], [`Error::Absent`], [`Error::Bound`] or [`Error::Rule`] as they are
    /// described; [`Error::Io`] when the filesystem fails.
    pub fn read(&self, name: &str) -> Result<Secret, Error> {
        if !valid_name(name) {
            return Err(Error::Name);
        }
        let fd = rustix::fs::openat2(
            &*self.root,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|e| match e {
            Errno::NOENT => Error::Absent,
            // ELOOP: a symlink, which a credential is not.
            Errno::LOOP | Errno::XDEV => Error::Bound,
            e => Error::Io(std::io::Error::from(e).kind()),
        })?;
        let file = std::fs::File::from(fd);
        let meta = file.metadata().map_err(|e| Error::Io(e.kind()))?;
        if !meta.is_file() || meta.len() > SECRET_MAX {
            return Err(Error::Bound);
        }
        if meta.mode() & 0o077 != 0 {
            return Err(Error::Rule);
        }
        let mut data = Vec::new();
        file.take(SECRET_MAX + 1)
            .read_to_end(&mut data)
            .map_err(|e| Error::Io(e.kind()))?;
        if data.len() as u64 > SECRET_MAX {
            return Err(Error::Bound);
        }
        let version = format!("{:x}-{:x}-{:x}", meta.mtime_nsec(), meta.size(), meta.ino());
        Ok(Secret { data, version })
    }
}

/// A credential name as systemd has it (`systemd.exec`, `LoadCredential=`): letters, digits, `-`,
/// `_` and `.`, not starting with a dot and not holding a `/`; at most 128 characters.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    let mut b = name.bytes();
    name.len() <= 128
        && b.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}
