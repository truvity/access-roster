//! The `fs` blob driver of the audit writer (ADR 0029, "The write-once fence"): the blob port over
//! a local directory.
//!
//! - `create` is the fence: the bytes go to a temporary file in the target's directory, are
//!   fsynced, then `link()`ed to the name, which fails if the name exists, and the directory is
//!   fsynced. Of many racing creators exactly one wins.
//! - `put` overwrites only a pointer (see [`POINTERS`]), under an entity tag.
//! - Every path is checked textually and then opened with `openat2(RESOLVE_NO_SYMLINKS |
//!   RESOLVE_BENEATH)` below the root, so no `..`, absolute path or symlink leaves it.
//! - Where `openat2` answers `ENOSYS` (systemd's `RestrictSUIDSGID=yes` makes its seccomp filter
//!   do so, and so does a kernel older than 5.6) and only then, the same path is walked one
//!   component at a time with `openat(O_NOFOLLOW)`, which refuses the same things: see
//!   [`open_nosymlinks`]. Any other error of `openat2` is the answer.

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
        Self::open_owned_by(root, rustix::process::geteuid().as_raw())
    }

    /// Opens `root` for a driver that only reads it: the directory belongs to `owner`, the uid of
    /// the writer's driver, and this process reads it through the group of that driver (the files
    /// are 0640 and the directories 0750). The other checks are those of [`Fs::open`]. The type
    /// does not stop a caller from calling `create` or `put`; the read-only driver's service never
    /// does, and the volume it mounts is read-only.
    ///
    /// # Errors
    ///
    /// Fails when the root is missing, is not a directory of `owner` closed to others, or cannot
    /// be opened.
    pub fn open_read_only(root: &Path, owner: u32) -> anyhow::Result<Self> {
        Self::open_owned_by(root, owner)
    }

    fn open_owned_by(root: &Path, owner: u32) -> anyhow::Result<Self> {
        use anyhow::{Context, bail};
        let m = std::fs::symlink_metadata(root).context("the blob root")?;
        if !m.is_dir() {
            bail!("the blob root is not a directory (a symlink is refused)");
        }
        if m.uid() != owner {
            bail!(
                "the blob root is owned by uid {}, not by uid {owner}",
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

    /// Removes the temporary files a crash left behind: regular files named exactly
    /// `.tmp-<digits>-<digits>`, nothing else. Only `serve` calls it, because a running driver's
    /// own temporary files match too; `check` must not. Returns how many it removed.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be read.
    pub fn sweep(&self) -> Result<usize> {
        sweep_dir(&self.root.try_clone()?)
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
        // Compare and replace are one step: the mutex orders the threads of this process, the
        // flock on the root orders processes (a second driver on the same directory).
        let _held = self.puts.lock().map_err(|_| Error::Version)?;
        let _flock = Flock::take(&self.root)?;
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
        if !f.metadata()?.is_file() {
            return Err(Error::Absent);
        }
        let mut data = Vec::new();
        f.read_to_end(&mut data)?;
        let tag = etag(&data);
        Ok((data, tag))
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
        Ok(open_beneath(&self.root, path, flags)?)
    }
}

/// Opens `path` below `parent` and follows no symlink on the way: `openat2` where the system
/// has it, the walk of [`open_nosymlinks`] where it answers `ENOSYS` and for no other error.
fn open_beneath(
    parent: &OwnedFd,
    path: &str,
    flags: OFlags,
) -> std::result::Result<OwnedFd, Errno> {
    let first = {
        #[cfg(test)]
        let refused = tests::OPENAT2_REFUSED.get();
        #[cfg(not(test))]
        let refused = false;
        if refused {
            // The seccomp filter's answer, for the tests of the fallback.
            Err(Errno::NOSYS)
        } else {
            rustix::fs::openat2(
                parent,
                path,
                flags | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS | ResolveFlags::BENEATH,
            )
        }
    };
    or_fallback(first, || open_nosymlinks(parent, path, flags))
}

/// `first`, unless it is `ENOSYS`: only then is `fallback` tried. An `EPERM`, an `ELOOP` or any
/// other error is the answer and must not be asked again by another road.
fn or_fallback<T>(
    first: std::result::Result<T, Errno>,
    fallback: impl FnOnce() -> std::result::Result<T, Errno>,
) -> std::result::Result<T, Errno> {
    match first {
        Err(Errno::NOSYS) => fallback(),
        other => other,
    }
}

/// What `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH)` does, with `openat` only: every component
/// is opened from the one before with `O_NOFOLLOW`, the ones before the last also with
/// `O_DIRECTORY`. A symlink is refused wherever it stands (`ELOOP` or `ENOTDIR`), an absolute
/// path, `..` and an empty component are refused (`EXDEV`) before any open, so no step can leave
/// `parent`, and no race can put a link in the way and be followed.
fn open_nosymlinks(
    parent: &OwnedFd,
    path: &str,
    flags: OFlags,
) -> std::result::Result<OwnedFd, Errno> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return Err(Errno::XDEV);
    }
    let Some((last, dirs)) = parts.split_last() else {
        return Err(Errno::XDEV);
    };
    let mut cur = parent
        .try_clone()
        .map_err(|e| Errno::from_io_error(&e).unwrap_or(Errno::IO))?;
    for part in dirs {
        cur = rustix::fs::openat(
            &cur,
            *part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
    }
    rustix::fs::openat(
        &cur,
        *last,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// An exclusive `flock` on a directory, released on drop.
struct Flock<'a>(&'a OwnedFd);

impl<'a> Flock<'a> {
    fn take(fd: &'a OwnedFd) -> Result<Self> {
        loop {
            match rustix::fs::flock(fd, rustix::fs::FlockOperation::LockExclusive) {
                Ok(()) => return Ok(Self(fd)),
                Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
}

impl Drop for Flock<'_> {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(self.0, rustix::fs::FlockOperation::Unlock);
    }
}

fn open_dir(parent: &OwnedFd, name: &str) -> Result<OwnedFd> {
    Ok(open_beneath(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY,
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

/// The entity tag: the SHA-384 of the content, in hex (ADR 0006 fixes SHA-384). A tag that depends
/// on the content only cannot repeat for two contents, whatever the inode or clock does.
fn etag(data: &[u8]) -> String {
    use std::fmt::Write as _;
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, data)
        .as_ref()
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
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
    let written = (|| -> std::io::Result<()> {
        f.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    })();
    match written {
        Ok(()) => Ok((tmp, etag(data))),
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

/// True for `.tmp-<digits>-<digits>`, the names [`write_tmp`] makes.
fn is_tmp(name: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    name.strip_prefix(TMP)
        .and_then(|r| r.split_once('-'))
        .is_some_and(|(pid, n)| digits(pid) && digits(n))
}

fn sweep_dir(d: &OwnedFd) -> Result<usize> {
    let mut removed = 0;
    for entry in Dir::read_from(d)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        match entry.file_type() {
            FileType::RegularFile if is_tmp(name) => {
                rustix::fs::unlinkat(d, name, AtFlags::empty())?;
                removed += 1;
            }
            FileType::Directory if !name.starts_with('.') => {
                removed += sweep_dir(&open_dir(d, name)?)?;
            }
            _ => {}
        }
    }
    Ok(removed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        /// Set, `openat2` answers `ENOSYS` on this thread, as it does under `RestrictSUIDSGID=yes`.
        pub(super) static OPENAT2_REFUSED: Cell<bool> = const { Cell::new(false) };
    }

    /// Runs `body` once with `openat2` as the system has it and once with `ENOSYS` answered, so
    /// each case holds on both roads.
    fn both(body: impl Fn()) {
        for refused in [false, true] {
            OPENAT2_REFUSED.set(refused);
            body();
        }
        OPENAT2_REFUSED.set(false);
    }

    fn root() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        t
    }

    fn is_path_error(e: &Error) -> bool {
        matches!(e, Error::Path)
    }

    #[test]
    fn the_fallback_road_reads_what_it_wrote() {
        both(|| {
            let t = root();
            let fs = Fs::open(t.path()).unwrap();
            let tag = fs.create("a/b/c", b"hello").unwrap();
            let (data, got) = fs.get("a/b/c").unwrap();
            assert_eq!(data, b"hello");
            assert_eq!(got, tag);
            assert!(matches!(fs.get("a/b/none"), Err(Error::Absent)));
            assert!(matches!(fs.get("none/b/c"), Err(Error::Absent)));
            assert_eq!(fs.list("a/", "", 10).unwrap().0, vec!["a/b/c".to_owned()]);
        });
    }

    #[test]
    fn a_symlink_to_a_file_in_the_root_is_refused_on_both_roads() {
        both(|| {
            let t = root();
            let fs = Fs::open(t.path()).unwrap();
            fs.create("real", b"x").unwrap();
            std::os::unix::fs::symlink("real", t.path().join("link")).unwrap();
            assert!(is_path_error(&fs.get("link").unwrap_err()));
        });
    }

    #[test]
    fn a_symlink_that_leaves_the_root_is_refused_as_the_file_and_as_a_directory() {
        both(|| {
            let out = tempfile::tempdir().unwrap();
            std::fs::write(out.path().join("secret"), b"s").unwrap();
            let t = root();
            let fs = Fs::open(t.path()).unwrap();
            std::os::unix::fs::symlink(out.path().join("secret"), t.path().join("file")).unwrap();
            std::os::unix::fs::symlink(out.path(), t.path().join("dir")).unwrap();
            std::os::unix::fs::symlink("../", t.path().join("up")).unwrap();
            assert!(is_path_error(&fs.get("file").unwrap_err()));
            assert!(is_path_error(&fs.get("dir/secret").unwrap_err()));
            assert!(is_path_error(&fs.get("up/secret").unwrap_err()));
            // A create through a link in the path must not write outside either.
            assert!(is_path_error(&fs.create("dir/new", b"x").unwrap_err()));
            assert!(!out.path().join("new").exists());
        });
    }

    #[test]
    fn dot_dot_absolute_and_empty_components_are_refused_before_any_open() {
        both(|| {
            let t = root();
            let fs = Fs::open(t.path()).unwrap();
            fs.create("a/b", b"x").unwrap();
            for p in ["../x", "a/../a/b", "/a/b", "a//b", "a/./b", "a/.."] {
                assert!(is_path_error(&fs.get(p).unwrap_err()), "{p}");
            }
            // The fallback itself, called with the paths the textual check would have stopped.
            for p in ["..", "../x", "/etc/passwd", "a/../b", "a//b", ".", ""] {
                assert_eq!(
                    open_nosymlinks(&fs.root, p, OFlags::RDONLY).err(),
                    Some(Errno::XDEV),
                    "{p:?}"
                );
            }
        });
    }

    #[test]
    fn the_walk_refuses_a_symlink_in_every_position() {
        let t = root();
        let fs = Fs::open(t.path()).unwrap();
        std::fs::create_dir_all(t.path().join("a/b")).unwrap();
        std::fs::write(t.path().join("a/b/f"), b"x").unwrap();
        std::os::unix::fs::symlink("a", t.path().join("first")).unwrap();
        std::os::unix::fs::symlink("b", t.path().join("a/mid")).unwrap();
        std::os::unix::fs::symlink("f", t.path().join("a/b/last")).unwrap();
        let open = |p: &str| open_nosymlinks(&fs.root, p, OFlags::RDONLY);
        assert!(open("a/b/f").is_ok());
        for p in ["first/b/f", "a/mid/f", "a/b/last"] {
            let e = open(p).err().unwrap();
            assert!(matches!(e, Errno::LOOP | Errno::NOTDIR), "{p}: {e:?}");
        }
    }

    #[test]
    fn a_fifo_is_refused_as_a_directory_of_the_path_on_both_roads() {
        both(|| {
            let t = root();
            let fs = Fs::open(t.path()).unwrap();
            rustix::fs::mknodat(
                rustix::fs::CWD,
                t.path().join("pipe"),
                FileType::Fifo,
                Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap();
            // As a directory in the path it is refused without being opened.
            assert!(is_path_error(&fs.get("pipe/x").unwrap_err()));
            // As the object, `get` opens it for reading: it must not be reached with a writer
            // missing. The open below is non-blocking, as the walk passes `flags` through.
            let fd = open_beneath(&fs.root, "pipe", OFlags::RDONLY | OFlags::NONBLOCK).unwrap();
            assert!(!File::from(fd).metadata().unwrap().is_file());
        });
    }

    #[test]
    fn only_enosys_asks_for_the_fallback() {
        for (first, want_asked) in [
            (Err(Errno::NOSYS), 1),
            (Err(Errno::PERM), 0),
            (Err(Errno::LOOP), 0),
            (Err(Errno::XDEV), 0),
            (Err(Errno::NOENT), 0),
            (Ok(1), 0),
        ] {
            let mut asked = 0;
            let _ = or_fallback(first, || {
                asked += 1;
                Ok(2)
            });
            assert_eq!(asked, want_asked, "{first:?}");
        }
    }
}
