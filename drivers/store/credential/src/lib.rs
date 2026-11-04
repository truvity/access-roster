//! The `credential` driver of store@: the secret source contract (store-api.md "The source
//! contract") over systemd credentials (ADR 0005, "Secret sources").
//!
//! - A secret is the file of that name in the credentials directory: `$CREDENTIALS_DIRECTORY` for
//!   a service started with `LoadCredential=`, or the directory `--dir` names in the local
//!   installation. The directory is read-only to the driver; nothing is written, cached or logged.
//! - The value is returned to the owner of the socket only (store@, by the registry), and nothing
//!   about it leaves this process but the answer to a `Read`: no log line, no error text, no
//!   version label that is a hash of the value.
//! - A file readable by group or others is refused, and so is a file the driver's own uid does not
//!   own. systemd makes a credential `0400`; a local directory must follow, or the driver would
//!   hand out a value that anyone could already read, or that someone else could have replaced.
//! - A directory the driver's own uid does not own, or that group or others can write, is
//!   refused when it is opened: whoever can write there can put a credential of their own in it.
//! - A file is opened with `O_NONBLOCK`, so that a FIFO in the directory cannot hang the open
//!   (and the worker thread with it), and anything that is not a regular file is refused.
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
    /// Changes when the file does; it is made of the modification time (seconds and nanoseconds),
    /// the size and the inode, never of the value.
    pub version: String,
}

/// An open credentials directory. Cheap to clone.
#[derive(Clone)]
pub struct Dir {
    root: std::sync::Arc<OwnedFd>,
}

impl Dir {
    /// Opens `dir`, which must be a directory (not a symlink), owned by the uid of this process
    /// and not writable by group or others.
    ///
    /// # Errors
    ///
    /// Fails when `dir` is missing, is not a directory, or breaks the owner or mode rule.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        let fd = rustix::fs::open(
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("open the credentials directory")?;
        let st = rustix::fs::fstat(&fd).context("stat the credentials directory")?;
        anyhow::ensure!(
            dir_ok(st.st_uid, st.st_mode, own_uid()),
            "the credentials directory must be owned by the uid of this process and not writable by group or others"
        );
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
            // NONBLOCK: the open of a FIFO returns at once, and `is_file` below refuses it.
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::NOFOLLOW,
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
        if !file_ok(meta.uid(), meta.mode(), own_uid()) {
            return Err(Error::Rule);
        }
        let mut data = Vec::new();
        file.take(SECRET_MAX + 1)
            .read_to_end(&mut data)
            .map_err(|e| Error::Io(e.kind()))?;
        if data.len() as u64 > SECRET_MAX {
            return Err(Error::Bound);
        }
        let version = format!(
            "{:x}.{:09x}-{:x}-{:x}",
            meta.mtime(),
            meta.mtime_nsec(),
            meta.size(),
            meta.ino()
        );
        Ok(Secret { data, version })
    }
}

/// The uid this process runs as: the owner a directory and a credential must have.
fn own_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A directory is trusted when `uid` owns it and neither group nor others can write to it.
fn dir_ok(owner: u32, mode: u32, uid: u32) -> bool {
    owner == uid && mode & 0o022 == 0
}

/// A credential is trusted when `uid` owns it and group and others have no access at all.
fn file_ok(owner: u32, mode: u32, uid: u32) -> bool {
    owner == uid && mode & 0o077 == 0
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// A directory the driver takes whatever the umask is.
    fn closed_dir() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        t
    }

    #[test]
    fn an_owner_other_than_this_uid_is_refused() {
        let me = own_uid();
        assert!(dir_ok(me, 0o40700, me) && dir_ok(me, 0o40755, me));
        assert!(!dir_ok(me + 1, 0o40700, me), "a directory of another uid");
        assert!(!dir_ok(me, 0o40770, me), "group-writable");
        assert!(!dir_ok(me, 0o40707, me), "world-writable");
        assert!(file_ok(me, 0o100400, me) && file_ok(me, 0o100600, me));
        assert!(!file_ok(me + 1, 0o100400, me), "a file of another uid");
        assert!(!file_ok(me, 0o100640, me), "group-readable");
        assert!(!file_ok(me, 0o100604, me), "readable by others");
        assert!(!file_ok(me, 0o100620, me), "group-writable");
    }

    #[test]
    fn a_directory_that_group_or_others_can_write_is_not_opened() {
        let t = tempfile::tempdir().unwrap();
        let set = |m| std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(m));
        set(0o700).unwrap();
        assert!(Dir::open(t.path()).is_ok());
        set(0o755).unwrap();
        assert!(Dir::open(t.path()).is_ok(), "read-only to others is fine");
        for m in [0o770, 0o707, 0o777] {
            set(m).unwrap();
            let e = Dir::open(t.path()).err().unwrap();
            assert!(e.to_string().contains("not writable"), "{m:o}: {e}");
        }
    }

    #[test]
    fn a_file_that_is_open_to_group_or_others_is_refused_and_a_closed_one_is_read() {
        let t = closed_dir();
        let p = t.path().join("c");
        std::fs::write(&p, b"v").unwrap();
        let dir = Dir::open(t.path()).unwrap();
        for (m, ok) in [
            (0o400, true),
            (0o600, true),
            (0o440, false),
            (0o404, false),
            (0o660, false),
        ] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(m)).unwrap();
            assert_eq!(dir.read("c").is_ok(), ok, "{m:o}");
        }
    }

    #[test]
    fn the_label_follows_the_seconds_and_the_nanoseconds_of_the_file() {
        use std::time::{Duration, SystemTime};
        let t = closed_dir();
        let p = t.path().join("c");
        std::fs::write(&p, b"v").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let dir = Dir::open(t.path()).unwrap();
        let at = |secs, nanos| {
            let f = std::fs::File::options().write(true).open(&p).unwrap();
            f.set_modified(SystemTime::UNIX_EPOCH + Duration::new(secs, nanos))
                .unwrap();
            dir.read("c").unwrap().version
        };
        // The same nanoseconds in another second, and the same second in other nanoseconds, are
        // two labels: a label of the nanoseconds alone would repeat.
        let labels = [at(1_000, 5), at(2_000, 5), at(2_000, 6)];
        assert_ne!(labels[0], labels[1]);
        assert_ne!(labels[1], labels[2]);
    }

    #[test]
    fn a_fifo_is_refused_at_once_and_does_not_hang_the_open() {
        let t = closed_dir();
        let p = t.path().join("pipe");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &p,
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let dir = Dir::open(t.path()).unwrap();
        // A blocking open of a FIFO with no writer never returns; run it aside to bound the wait.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(dir.read("pipe").err().map(|e| e.to_string())));
        let got = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the open of a FIFO hung");
        assert_eq!(got.as_deref(), Some("bound"));
    }
}
