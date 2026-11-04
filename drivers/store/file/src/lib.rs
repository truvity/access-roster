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
//! - Where `openat2` answers `ENOSYS` (systemd's `RestrictSUIDSGID=yes` makes its seccomp filter
//!   do so, and so does a kernel older than 5.6) and only then, the path is resolved by
//!   [`open_beneath_by_walk`] with `openat` and `readlinkat` alone, under the same rules: links
//!   below the directory are followed, and `..`, an absolute link target or a link that points
//!   outside the directory is refused.
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
        let fd = open_beneath(
            &self.root,
            &format!("{name}{EXTENSION}"),
            // NONBLOCK: the open of a FIFO returns at once, and `is_file` below refuses it.
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
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

/// Opens `path` below `parent`, following the symlinks that stay below it: `openat2` where the
/// system has it, [`open_beneath_by_walk`] where it answers `ENOSYS` and for no other error.
fn open_beneath(parent: &OwnedFd, path: &str, flags: OFlags) -> Result<OwnedFd, Errno> {
    let first = {
        #[cfg(test)]
        let refused = tests::OPENAT2_REFUSED.get();
        #[cfg(not(test))]
        let refused = false;
        if refused {
            // The seccomp filter's answer, for the tests of the fallback.
            Err(Errno::NOSYS)
        } else {
            rustix::fs::openat2(parent, path, flags, Mode::empty(), ResolveFlags::BENEATH)
        }
    };
    or_fallback(first, || open_beneath_by_walk(parent, path, flags))
}

/// `first`, unless it is `ENOSYS`: only then is `fallback` tried. An `EPERM`, an `ELOOP` or any
/// other error is the answer and must not be asked again by another road.
fn or_fallback<T>(
    first: Result<T, Errno>,
    fallback: impl FnOnce() -> Result<T, Errno>,
) -> Result<T, Errno> {
    match first {
        Err(Errno::NOSYS) => fallback(),
        other => other,
    }
}

/// The most symlinks one resolution follows, the kernel's own limit (`MAXSYMLINKS`).
const MAX_LINKS: usize = 40;

/// What `openat2(RESOLVE_BENEATH)` does, with `openat` and `readlinkat` only.
///
/// The path is taken a component at a time, from a stack of the directories walked (the root at
/// the bottom). A component that is a symlink is not opened: its target is read and put in front
/// of the rest of the path, and the walk goes on from the directory the link was in, as the kernel
/// does. So:
///
/// - `..` pops the stack, and `..` at the root is refused (`EXDEV`): nothing above the root is
///   ever opened, however the links and the `..` are arranged;
/// - an absolute path or an absolute link target is refused (`EXDEV`);
/// - more than [`MAX_LINKS`] links is `ELOOP`;
/// - every open is `O_NOFOLLOW` (and a directory step `O_DIRECTORY`), so a name swapped for a
///   symlink after it was looked at is refused (`ELOOP` or `ENOTDIR`) and never followed.
///
/// A trailing slash is not enforced: `link/` opens what `link` does, which the caller's own file
/// type check judges.
fn open_beneath_by_walk(root: &OwnedFd, path: &str, flags: OFlags) -> Result<OwnedFd, Errno> {
    use std::collections::VecDeque;

    if path.starts_with('/') {
        return Err(Errno::XDEV);
    }
    let split =
        |p: &[u8]| -> Vec<Vec<u8>> { p.split(|b| *b == b'/').map(<[u8]>::to_vec).collect() };
    let mut todo: VecDeque<Vec<u8>> = split(path.as_bytes()).into();
    let mut stack: Vec<OwnedFd> = vec![rustix::io::fcntl_dupfd_cloexec(root, 0)?];
    let mut links = 0;
    while let Some(part) = todo.pop_front() {
        match part.as_slice() {
            b"" | b"." => continue,
            b".." => {
                // The root stays: a `..` that would leave it is the escape this refuses.
                if stack.len() == 1 {
                    return Err(Errno::XDEV);
                }
                stack.pop();
                continue;
            }
            _ => {}
        }
        let Some(cur) = stack.last() else {
            return Err(Errno::XDEV);
        };
        match rustix::fs::readlinkat(cur, part.as_slice(), Vec::new()) {
            Ok(target) => {
                links += 1;
                if links > MAX_LINKS {
                    return Err(Errno::LOOP);
                }
                let target = target.to_bytes();
                if target.starts_with(b"/") {
                    return Err(Errno::XDEV);
                }
                for p in split(target).into_iter().rev() {
                    todo.push_front(p);
                }
                continue;
            }
            // Not a symlink (EINVAL) is the common case; a missing name is for the open to say.
            Err(Errno::INVAL | Errno::NOENT) => {}
            Err(e) => return Err(e),
        }
        let more = todo.iter().any(|p| !p.is_empty() && p.as_slice() != b".");
        if more {
            let next = rustix::fs::openat(
                cur,
                part.as_slice(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            stack.push(next);
        } else {
            return rustix::fs::openat(
                cur,
                part.as_slice(),
                flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            );
        }
    }
    // The path ended on the directory itself ("", ".", "a/.", or a link to one).
    let Some(cur) = stack.last() else {
        return Err(Errno::XDEV);
    };
    rustix::fs::openat(
        cur,
        ".",
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
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
    use std::cell::Cell;
    use std::os::unix::fs::symlink;

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

    fn put(dir: &Path, rel: &str, data: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    /// The text of a refusal of `name`, or `ok`.
    fn answer(dir: &Dir, name: &str) -> String {
        match dir.read(name) {
            Ok(_) => "ok".to_owned(),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn a_configmap_tree_of_links_is_followed_on_both_roads() {
        both(|| {
            // The layout of a mounted ConfigMap: name -> ..data/name, ..data -> ..<stamp>.
            let t = tempfile::tempdir().unwrap();
            put(t.path(), "..2026_11_04/boundary.jws", b"v1");
            symlink("..2026_11_04", t.path().join("..data")).unwrap();
            symlink("..data/boundary.jws", t.path().join("boundary.jws")).unwrap();
            let dir = Dir::open(t.path()).unwrap();
            let d = dir.read("boundary").unwrap();
            assert_eq!(d.data, b"v1");
            // The swap of the update: ..data now names another directory.
            put(t.path(), "..2026_11_05/boundary.jws", b"v2");
            symlink("..2026_11_05", t.path().join("..data.tmp")).unwrap();
            std::fs::rename(t.path().join("..data.tmp"), t.path().join("..data")).unwrap();
            assert_eq!(dir.read("boundary").unwrap().data, b"v2");
            assert_ne!(dir.read("boundary").unwrap().version, d.version);
        });
    }

    #[test]
    fn links_and_dot_dot_that_stay_below_the_directory_are_followed() {
        both(|| {
            let t = tempfile::tempdir().unwrap();
            put(t.path(), "real/a.jws", b"a");
            std::fs::create_dir_all(t.path().join("sub/deep")).unwrap();
            // sub/deep/../../real/a.jws is below the directory throughout.
            symlink("sub/deep/../../real/a.jws", t.path().join("viadots.jws")).unwrap();
            // A link in a subdirectory that climbs one level, still below the directory.
            symlink("../real/a.jws", t.path().join("sub/up.jws")).unwrap();
            symlink("sub/up.jws", t.path().join("twice.jws")).unwrap();
            let dir = Dir::open(t.path()).unwrap();
            for n in ["viadots", "twice"] {
                assert_eq!(answer(&dir, n), "ok", "{n}");
            }
            assert_eq!(answer(&dir, "gone"), "absent");
        });
    }

    #[test]
    fn a_link_that_leaves_the_directory_is_refused_however_it_goes() {
        both(|| {
            let out = tempfile::tempdir().unwrap();
            put(out.path(), "secret.jws", b"s");
            let t = tempfile::tempdir().unwrap();
            // Every escape below reaches a file that exists, so a refusal is not an absence.
            put(t.path(), "secret.jws", b"s");
            let base = t.path().join("conf");
            std::fs::create_dir_all(base.join("sub")).unwrap();
            // A relative target above the directory.
            symlink("../secret.jws", base.join("up.jws")).unwrap();
            // An absolute target, even one that names a file below the directory.
            symlink(out.path().join("secret.jws"), base.join("abs.jws")).unwrap();
            put(&base, "real.jws", b"r");
            symlink(base.join("real.jws"), base.join("absinside.jws")).unwrap();
            // A directory link above, and a file reached through it.
            symlink("../..", base.join("sub/parent")).unwrap();
            symlink("sub/parent/secret.jws", base.join("viadir.jws")).unwrap();
            // More `..` than the depth, in the middle of a path.
            symlink("sub/../../secret.jws", base.join("mid.jws")).unwrap();
            // A chain whose last link is the escape.
            symlink("chain2.jws", base.join("chain1.jws")).unwrap();
            symlink("../secret.jws", base.join("chain2.jws")).unwrap();
            let dir = Dir::open(&base).unwrap();
            for n in ["up", "abs", "absinside", "viadir", "mid", "chain1"] {
                assert_eq!(answer(&dir, n), "bound", "{n}");
            }
            assert_eq!(answer(&dir, "real"), "ok");
        });
    }

    #[test]
    fn a_loop_of_links_is_refused() {
        both(|| {
            let t = tempfile::tempdir().unwrap();
            symlink("b.jws", t.path().join("a.jws")).unwrap();
            symlink("a.jws", t.path().join("b.jws")).unwrap();
            symlink("self.jws", t.path().join("self.jws")).unwrap();
            let dir = Dir::open(t.path()).unwrap();
            assert_eq!(answer(&dir, "a"), "bound");
            assert_eq!(answer(&dir, "self"), "bound");
        });
    }

    #[test]
    fn a_directory_or_a_link_to_one_is_not_a_document() {
        both(|| {
            let t = tempfile::tempdir().unwrap();
            std::fs::create_dir(t.path().join("dir.jws")).unwrap();
            symlink("dir.jws", t.path().join("linked.jws")).unwrap();
            let dir = Dir::open(t.path()).unwrap();
            assert_eq!(answer(&dir, "dir"), "bound");
            assert_eq!(answer(&dir, "linked"), "bound");
        });
    }

    #[test]
    fn the_walk_alone_refuses_an_absolute_path_and_a_dot_dot_at_the_root() {
        let t = tempfile::tempdir().unwrap();
        put(t.path(), "a/f", b"x");
        let dir = Dir::open(t.path()).unwrap();
        let open = |p: &str| open_beneath_by_walk(&dir.root, p, OFlags::RDONLY);
        for p in ["/a/f", "..", "../x", "a/../../x", "a/../.."] {
            assert_eq!(open(p).err(), Some(Errno::XDEV), "{p}");
        }
        for p in ["a/f", "a/../a/f", "./a/./f", "a//f", "a"] {
            assert!(open(p).is_ok(), "{p}");
        }
        assert_eq!(open("a/none").err(), Some(Errno::NOENT));
        assert_eq!(open("a/f/x").err(), Some(Errno::NOTDIR));
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

    #[test]
    fn a_fifo_is_refused_at_once_and_does_not_hang_the_open() {
        // The seam is per thread: set it in the thread that opens.
        for refused in [false, true] {
            let t = tempfile::tempdir().unwrap();
            rustix::fs::mknodat(
                rustix::fs::CWD,
                t.path().join("boundary.jws"),
                rustix::fs::FileType::Fifo,
                Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap();
            // The same FIFO reached through a link.
            symlink("boundary.jws", t.path().join("upstream.jws")).unwrap();
            let dir = Dir::open(t.path()).unwrap();
            for name in ["boundary", "upstream"] {
                let dir = dir.clone();
                // A blocking open of a FIFO with no writer never returns; run it aside to bound the wait.
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    OPENAT2_REFUSED.set(refused);
                    tx.send(dir.read(name).err().map(|e| e.to_string()))
                });
                let got = rx
                    .recv_timeout(Duration::from_secs(10))
                    .expect("the open of a FIFO hung");
                assert_eq!(
                    got.as_deref(),
                    Some("bound"),
                    "{name}, openat2 refused: {refused}"
                );
            }
        }
    }
}
