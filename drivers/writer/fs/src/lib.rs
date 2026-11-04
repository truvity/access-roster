//! The `fs` blob driver of the audit writer (ADR 0029, "The write-once fence"): the blob port over
//! a local directory.
//!
//! - `create` is the fence: the bytes go to a temporary file in the target's directory, are
//!   fsynced, then `link()`ed to the name, which fails if the name exists, and the directory is
//!   fsynced. Of many racing creators exactly one wins.
//! - `put` overwrites only a pointer (see [`POINTERS`]), under an entity tag.
//! - Every path is checked textually and then opened with `openat2(RESOLVE_NO_SYMLINKS)` below the
//!   root, so no `..`, absolute path or symlink leaves it.

pub mod service;
pub mod suite;

use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

/// The last path segment of an object that `put` may overwrite: the `tlog-tiles` checkpoint
/// pointer and the writer's state (0029: "Every object but the checkpoint pointer and the
/// writer's state is written once"). The records name no path for the state: see the PR.
pub const POINTERS: [&str; 2] = ["checkpoint", "writer-state"];

const FILE_MODE: u32 = 0o640;
const DIR_MODE: u32 = 0o750;
const MAX_PATH: usize = 1024;
const MAX_PAGE: usize = 10_000;
const DEFAULT_PAGE: usize = 1000;
/// Temporary files start with a dot; no valid path segment does, and `list` skips them.
const TMP: &str = ".tmp-";

/// Why an operation was refused. [`service`] turns each into a Connect code and reason.
#[derive(Debug)]
pub enum Error {
    /// `create` found the path in use.
    Taken,
    /// No such object.
    Absent,
    /// A conditional `put` found another entity tag, or an object where none was wanted.
    Version,
    /// `put` on a path that is not a pointer.
    Rule,
    /// The path or the page token is not acceptable.
    Path,
    /// The filesystem failed.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Taken => f.write_str("taken"),
            Self::Absent => f.write_str("absent"),
            Self::Version => f.write_str("version"),
            Self::Rule => f.write_str("rule"),
            Self::Path => f.write_str("path"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Errno> for Error {
    fn from(e: Errno) -> Self {
        match e {
            Errno::NOENT => Self::Absent,
            // ELOOP and EXDEV are what RESOLVE_NO_SYMLINKS and RESOLVE_BENEATH answer.
            Errno::LOOP | Errno::XDEV | Errno::NOTDIR | Errno::ISDIR => Self::Path,
            e => Self::Io(e.into()),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

type Result<T> = std::result::Result<T, Error>;

/// A blob directory. Cheap to clone; clones share the lock that orders conditional puts.
#[derive(Clone)]
pub struct Fs {
    root: Arc<OwnedFd>,
    puts: Arc<Mutex<()>>,
}

impl Fs {
    /// Opens `root`, which must be a directory (not a symlink), owned by this process's uid and
    /// closed to others (mode no wider than 0750). It is checked at every start.
    ///
    /// # Errors
    ///
    /// Fails when the root is missing, is not such a directory, or cannot be opened.
    pub fn open(root: &Path) -> anyhow::Result<Self> {
        use anyhow::{Context, bail};
        let m = std::fs::symlink_metadata(root).context("the blob root")?;
        if !m.is_dir() {
            bail!("the blob root is not a directory (a symlink is refused)");
        }
        let me = rustix::process::geteuid().as_raw();
        if m.uid() != me {
            bail!(
                "the blob root is owned by uid {}, not by this driver's uid {me}",
                m.uid()
            );
        }
        if m.mode() & !(0o40000 | DIR_MODE) != 0 {
            bail!(
                "the blob root has mode {:o}, wider than {DIR_MODE:o}",
                m.mode() & 0o7777
            );
        }
        let fd = rustix::fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("open the blob root")?;
        Ok(Self {
            root: Arc::new(fd),
            puts: Arc::default(),
        })
    }

    /// Writes `data` at `path` if nothing is there; returns the entity tag.
    ///
    /// # Errors
    ///
    /// [`Error::Taken`] when the path exists.
    pub fn create(&self, path: &str, data: &[u8]) -> Result<String> {
        let (dirs, name) = split(&segments(path, false)?);
        let d = self.dir(&dirs, true)?;
        link_new(&d, name, data)
    }

    /// Overwrites a pointer when its entity tag is `if_match`; an empty `if_match` means the
    /// pointer must be absent.
    ///
    /// # Errors
    ///
    /// [`Error::Rule`] on a path that is not a pointer, [`Error::Version`] on another tag.
    pub fn put(&self, path: &str, data: &[u8], if_match: &str) -> Result<String> {
        let parts = segments(path, false)?;
        let (dirs, name) = split(&parts);
        if !POINTERS.contains(&name) {
            return Err(Error::Rule);
        }
        let d = self.dir(&dirs, true)?;
        if if_match.is_empty() {
            return match link_new(&d, name, data) {
                Err(Error::Taken) => Err(Error::Version),
                r => r,
            };
        }
        // One driver serves one directory: the lock makes compare and replace one step.
        let _held = self.puts.lock().map_err(|_| Error::Version)?;
        match self.get(path) {
            Ok((_, tag)) if tag == if_match => {}
            Ok(_) | Err(Error::Absent) => return Err(Error::Version),
            Err(e) => return Err(e),
        }
        let (tmp, tag) = write_tmp(&d, data)?;
        let moved = rustix::fs::renameat(&d, tmp.as_str(), &d, name).map_err(Error::from);
        if moved.is_err() {
            let _ = rustix::fs::unlinkat(&d, tmp.as_str(), AtFlags::empty());
        }
        moved?;
        rustix::fs::fsync(&d)?;
        Ok(tag)
    }

    /// Reads an object and its entity tag.
    ///
    /// # Errors
    ///
    /// [`Error::Absent`] when there is none.
    pub fn get(&self, path: &str) -> Result<(Vec<u8>, String)> {
        segments(path, false)?;
        let fd = self.open_below(path, OFlags::RDONLY)?;
        let mut f = File::from(fd);
        let m = f.metadata()?;
        if !m.is_file() {
            return Err(Error::Absent);
        }
        let mut data = Vec::new();
        f.read_to_end(&mut data)?;
        Ok((data, etag(&m)))
    }

    /// One page of the paths that start with `prefix`, in byte order, after `token` (the last
    /// path of the previous page). The token of the next page is empty on the last page.
    ///
    /// # Errors
    ///
    /// [`Error::Path`] for a prefix, token or page size that is not acceptable.
    pub fn list(&self, prefix: &str, after: &str, page_size: i32) -> Result<(Vec<String>, String)> {
        let size = match usize::try_from(page_size).map_err(|_| Error::Path)? {
            0 => DEFAULT_PAGE,
            n => n.min(MAX_PAGE),
        };
        let parts = segments(prefix, true)?;
        // Everything up to the last '/' is a directory to walk; the rest filters its entries.
        let (dirs, rest) = split(&parts);
        let mut found = Vec::new();
        match self.dir(&dirs, false) {
            Ok(d) => walk(&d, &dirs.join("/"), rest, &mut found)?,
            Err(Error::Absent) => {}
            Err(e) => return Err(e),
        }
        found.retain(|p| p.starts_with(prefix) && p.as_str() > after);
        found.sort();
        let more = found.len() > size;
        found.truncate(size);
        let next = if more {
            found.last().cloned().unwrap_or_default()
        } else {
            String::new()
        };
        Ok((found, next))
    }

    /// Opens (and with `make`, creates) the directory below the root, refusing symlinks.
    fn dir(&self, parts: &[&str], make: bool) -> Result<OwnedFd> {
        let mut cur = self.root.try_clone()?;
        for part in parts {
            if make {
                match rustix::fs::mkdirat(&cur, *part, Mode::from_raw_mode(DIR_MODE)) {
                    Ok(()) => {
                        // A new directory must outlive a crash, and so must its entry.
                        let new = open_dir(&cur, part)?;
                        rustix::fs::fchmod(&new, Mode::from_raw_mode(DIR_MODE))?;
                        rustix::fs::fsync(&cur)?;
                        cur = new;
                        continue;
                    }
                    Err(Errno::EXIST) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            cur = open_dir(&cur, part)?;
        }
        Ok(cur)
    }

    fn open_below(&self, path: &str, flags: OFlags) -> Result<OwnedFd> {
        Ok(rustix::fs::openat2(
            &*self.root,
            path,
            flags | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::BENEATH,
        )?)
    }
}

fn open_dir(parent: &OwnedFd, name: &str) -> Result<OwnedFd> {
    Ok(rustix::fs::openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::BENEATH,
    )?)
}

/// The segments of a path. A path has no empty, dot-led or NUL-holding segment, so `..`, `.`, `//`
/// and an absolute path are all refused. A prefix may end in a partial (or empty) segment.
fn segments(path: &str, prefix: bool) -> Result<Vec<&str>> {
    let parts: Vec<&str> = path.split('/').collect();
    let n = parts.len();
    let ok = |i: usize, s: &str| {
        let partial = prefix && i == n - 1;
        (partial || !s.is_empty()) && !s.starts_with('.') && s.len() <= 255 && !s.contains('\0')
    };
    if path.len() > MAX_PATH || !parts.iter().enumerate().all(|(i, s)| ok(i, s)) {
        return Err(Error::Path);
    }
    Ok(parts)
}

/// The directories and the last segment.
fn split<'a>(parts: &[&'a str]) -> (Vec<&'a str>, &'a str) {
    match parts.split_last() {
        Some((last, dirs)) => (dirs.to_vec(), last),
        None => (Vec::new(), ""),
    }
}

fn etag(m: &std::fs::Metadata) -> String {
    // A replaced file is a new inode written at a new time, so the tag changes on every put.
    format!(
        "{:x}-{:x}-{:x}-{:x}",
        m.ino(),
        m.size(),
        m.mtime(),
        m.mtime_nsec()
    )
}

/// Writes `data` to a fresh temporary file in `d`, fsynced, mode 0640; returns its name and tag.
fn write_tmp(d: &OwnedFd, data: &[u8]) -> Result<(String, String)> {
    static N: AtomicU64 = AtomicU64::new(0);
    let tmp = format!(
        "{TMP}{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    );
    let fd = rustix::fs::openat(
        d,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(FILE_MODE),
    )?;
    let mut f = File::from(fd);
    let written = (|| -> std::io::Result<String> {
        f.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(etag(&f.metadata()?))
    })();
    match written {
        Ok(tag) => Ok((tmp, tag)),
        Err(e) => {
            let _ = rustix::fs::unlinkat(d, tmp.as_str(), AtFlags::empty());
            Err(e.into())
        }
    }
}

/// The create-if-absent of 0029: link the synced temporary file to `name`, then sync `d`.
fn link_new(d: &OwnedFd, name: &str, data: &[u8]) -> Result<String> {
    let (tmp, tag) = write_tmp(d, data)?;
    let linked = rustix::fs::linkat(d, tmp.as_str(), d, name, AtFlags::empty());
    let _ = rustix::fs::unlinkat(d, tmp.as_str(), AtFlags::empty());
    match linked {
        Ok(()) => {
            rustix::fs::fsync(d)?;
            Ok(tag)
        }
        Err(Errno::EXIST) => Err(Error::Taken),
        Err(e) => Err(e.into()),
    }
}

/// Collects the regular files below `d` (named `rel`), skipping dot names and everything that is
/// not a file or a directory. `only` filters the first level.
fn walk(d: &OwnedFd, rel: &str, only: &str, out: &mut Vec<String>) -> Result<()> {
    for entry in Dir::read_from(d)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if name.starts_with('.') || !name.starts_with(only) {
            continue;
        }
        let path = if rel.is_empty() {
            name.to_owned()
        } else {
            format!("{rel}/{name}")
        };
        match entry.file_type() {
            FileType::RegularFile => out.push(path),
            FileType::Directory => walk(&open_dir(d, name)?, &path, "", out)?,
            _ => {}
        }
    }
    Ok(())
}
