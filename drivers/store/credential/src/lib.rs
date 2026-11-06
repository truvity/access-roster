//! The `credential` driver of store@: the secret source contract (store-api.md "The source
//! contract") over systemd credentials (ADR 0005, "Secret sources").
//!
//! - A secret is the file of that name in the credentials directory: `$CREDENTIALS_DIRECTORY` for
//!   a service started with `LoadCredential=`, or the directory `--dir` names in the local
//!   installation. The directory is read-only to the driver; nothing is written, cached or logged.
//! - The value is returned to the owner of the socket only (store@, by the registry), and nothing
//!   about it leaves this process but the answer to a `Read`: no log line, no error text, no
//!   version label that is a hash of the value.
//! - A file readable by others is refused, and so is a file that group can write, and so is a file
//!   that neither the driver's own uid nor root owns. A file readable by group is refused unless it
//!   carries an access ACL (below). A local directory must follow, or the driver would hand out a
//!   value that anyone could already read, or that someone else could have replaced.
//! - A directory that group or others can write, or that neither the driver's own uid nor root
//!   owns, is refused when it is opened: whoever can write there can put a credential of their own
//!   in it.
//! - Root counts as an owner only for the directory systemd made, which is the one `$CREDENTIALS_DIRECTORY`
//!   names (the same inode once canonicalised). systemd chowns that directory to the service user
//!   only where the filesystem has no ACL support; where it has, the directory stays `root:root`
//!   `0550` and the service user is granted read by a POSIX ACL (MEASURED on Ubuntu 26.04, systemd 259).
//!   Root is trusted on the host already, so a root-owned credential cannot be planted by anyone
//!   else. A directory named with `--dir` that is not that one must be owned by the driver's uid.
//! - With a POSIX ACL the group bits of `st_mode` are the ACL mask (acl(5): "the mask entry
//!   specifies the maximum access which can be granted by any entry except the owner and others"),
//!   which caps the owning group and every named user and group. So `mode & 0o020 == 0` means no
//!   ACL entry grants write, and the one bit that an ACL can show in group is read, which is how
//!   systemd grants the service user the read of a credential. Others stay `mode & 0o007 == 0`.
//!   Only the owner or root can set an ACL, and both are trusted.
//! - A file is opened with `O_NONBLOCK`, so that a FIFO in the directory cannot hang the open
//!   (and the worker thread with it), and anything that is not a regular file is refused.
//! - A symlink is refused in the path and as the file: a credential is a plain file.
//! - The file is opened with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`. Where that answers
//!   `ENOSYS` (systemd's `RestrictSUIDSGID=yes` makes its seccomp filter do so, and so does a
//!   kernel older than 5.6) and only then, the name is opened with `openat(O_NOFOLLOW)` instead:
//!   a name is one component, so the two refuse the same things, and the owner, mode and type
//!   checks are made on the open descriptor either way.
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
    /// This is the directory systemd gave the process (`$CREDENTIALS_DIRECTORY`), so root may own
    /// it and the files in it.
    systemd: bool,
}

impl Dir {
    /// Opens `dir`, which must be a directory (not a symlink), not writable by group or others,
    /// and owned by the uid of this process, or by root where `dir` is `$CREDENTIALS_DIRECTORY`.
    ///
    /// # Errors
    ///
    /// Fails when `dir` is missing, is not a directory, or breaks the owner or mode rule.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        let given = std::env::var_os("CREDENTIALS_DIRECTORY").filter(|d| !d.is_empty());
        Self::open_in(dir, given.as_deref().map(Path::new))
    }

    /// [`Dir::open`] with the directory systemd gave the process named by the caller
    /// (`$CREDENTIALS_DIRECTORY`, or none).
    fn open_in(dir: &Path, systemd_dir: Option<&Path>) -> anyhow::Result<Self> {
        use anyhow::Context as _;
        let fd = rustix::fs::open(
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("open the credentials directory")?;
        let st = rustix::fs::fstat(&fd).context("stat the credentials directory")?;
        let systemd = systemd_dir.is_some_and(|d| same_directory(&st, d));
        anyhow::ensure!(
            dir_ok(st.st_uid, st.st_mode, own_uid(), systemd),
            "the credentials directory must be owned by the uid of this process (or by root, for the directory systemd made) and not writable by group or others"
        );
        Ok(Self {
            root: std::sync::Arc::new(fd),
            systemd,
        })
    }

    /// Reads every credential in the directory and drops the values: the names that are credential
    /// names are each opened and checked by the rules of [`Dir::read`] (owner, mode, type, size),
    /// the others are not credentials and are left alone. Returns how many were read.
    ///
    /// # Errors
    ///
    /// The name of the first credential that [`Dir::read`] refuses, and why; never a value.
    pub fn verify(&self) -> anyhow::Result<usize> {
        use anyhow::Context as _;
        // A description of its own, so that the listing does not move the offset of the one held.
        let fd = rustix::fs::openat(
            &self.root,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("open the directory again")?;
        let mut n = 0;
        for entry in rustix::fs::Dir::read_from(fd).context("list the credentials directory")? {
            let entry = entry.context("list the credentials directory")?;
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            if !valid_name(name) {
                continue;
            }
            self.read(name)
                .map_err(|e| anyhow::anyhow!("credential {name}: {e}"))?;
            n += 1;
        }
        Ok(n)
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
        // NONBLOCK: the open of a FIFO returns at once, and `is_file` below refuses it.
        let flags =
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::NOFOLLOW;
        let fd = open_beneath(&self.root, name, flags).map_err(|e| match e {
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
        // Asked only when the group bits show a read, the one case in which it matters.
        let acl = meta.mode() & 0o040 != 0 && has_access_acl(&file);
        if !file_ok(meta.uid(), meta.mode(), own_uid(), self.systemd, acl) {
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

/// Opens the one-component `name` below `parent` and follows no symlink: `openat2` where the system
/// has it, [`open_name`] where it answers `ENOSYS` and for no other error.
fn open_beneath(parent: &OwnedFd, name: &str, flags: OFlags) -> Result<OwnedFd, Errno> {
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
                name,
                flags,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            )
        }
    };
    or_fallback(first, || open_name(parent, name, flags))
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

/// What the `openat2` above does for a name of one component, with `openat` only. `O_NOFOLLOW`
/// refuses a symlink as the file (`ELOOP`); a `/`, `.` or `..` is refused (`EXDEV`) before any
/// open, so the open cannot leave `parent`.
fn open_name(parent: &OwnedFd, name: &str, flags: OFlags) -> Result<OwnedFd, Errno> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(Errno::XDEV);
    }
    rustix::fs::openat(parent, name, flags | OFlags::NOFOLLOW, Mode::empty())
}

/// The uid this process runs as: the owner a directory and a credential must have.
fn own_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Whether the opened directory `st` is the directory `systemd_dir` names, once that is
/// canonicalised: the same device and inode, which a path compare could not promise (a bind mount,
/// a rename between the two calls). A path that does not resolve is not the directory.
fn same_directory(st: &rustix::fs::Stat, systemd_dir: &Path) -> bool {
    std::fs::canonicalize(systemd_dir)
        .and_then(std::fs::metadata)
        .is_ok_and(|m| m.dev() == st.st_dev && m.ino() == st.st_ino)
}

/// Whether the open file carries an access ACL. An error is "no": the file is then held to the
/// plain rule, which refuses a group read.
fn has_access_acl(file: &std::fs::File) -> bool {
    // Only whether the attribute exists is asked, so the buffer is empty: the size comes back.
    rustix::fs::fgetxattr(file, "system.posix_acl_access", &mut [0u8; 0]).is_ok()
}

/// Whether `owner` may own a directory or file that the driver trusts: its own uid, or root where
/// the directory is the one systemd made (`systemd`).
fn owner_ok(owner: u32, uid: u32, systemd: bool) -> bool {
    owner == uid || (systemd && owner == 0)
}

/// A directory is trusted when `uid` owns it (or root does, for the directory systemd made) and
/// neither group nor others can write to it. With a POSIX ACL the group bits are the mask, so a
/// clear group-write bit also means that no named entry can write (see the module documentation).
fn dir_ok(owner: u32, mode: u32, uid: u32, systemd: bool) -> bool {
    owner_ok(owner, uid, systemd) && mode & 0o022 == 0
}

/// A credential is trusted when `uid` owns it (or root does, in the directory systemd made),
/// others have no access at all, group cannot write, and group cannot read either unless the file
/// carries an access ACL (`acl`) in the directory systemd made. The group bits then are the mask
/// of that ACL, which is systemd's grant of the read to the service user.
fn file_ok(owner: u32, mode: u32, uid: u32, systemd: bool, acl: bool) -> bool {
    let group_read = if acl && systemd { 0 } else { 0o040 };
    owner_ok(owner, uid, systemd) && mode & (0o007 | 0o020 | group_read) == 0
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
    use std::cell::Cell;
    use std::os::unix::fs::PermissionsExt as _;

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

    /// A directory the driver takes whatever the umask is.
    fn closed_dir() -> tempfile::TempDir {
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        t
    }

    /// verifies: REQ-DATA-112
    #[test]
    fn an_owner_other_than_this_uid_is_refused() {
        let me = own_uid();
        let other = me + 1;
        assert!(dir_ok(me, 0o40700, me, false) && dir_ok(me, 0o40755, me, false));
        assert!(
            !dir_ok(other, 0o40700, me, false),
            "a directory of another uid"
        );
        assert!(!dir_ok(me, 0o40770, me, false), "group-writable");
        assert!(!dir_ok(me, 0o40707, me, false), "world-writable");
        assert!(file_ok(me, 0o100400, me, false, false) && file_ok(me, 0o100600, me, false, false));
        assert!(
            !file_ok(other, 0o100400, me, false, false),
            "a file of another uid"
        );
        assert!(!file_ok(me, 0o100640, me, false, false), "group-readable");
        assert!(
            !file_ok(me, 0o100604, me, false, false),
            "readable by others"
        );
        assert!(!file_ok(me, 0o100620, me, false, false), "group-writable");
    }

    // The directory systemd 259 makes where the filesystem has ACLs: root:root, dr-xr-x---, the
    // service user granted read by an ACL whose mask is the group bits.
    const SYSTEMD_DIR: u32 = 0o40550;
    const SYSTEMD_FILE: u32 = 0o100440;

    /// verifies: REQ-DATA-112
    #[test]
    fn a_root_owned_acl_directory_of_systemd_is_accepted() {
        // A service user; with a mode a plain directory could have, too.
        let me = 61_022;
        assert!(dir_ok(0, SYSTEMD_DIR, me, true));
        assert!(dir_ok(0, 0o40500, me, true));
        assert!(
            dir_ok(0, 0o40755, me, true),
            "read-only to others is the rule of any directory"
        );
        assert!(
            dir_ok(me, SYSTEMD_DIR, me, true),
            "and the chown of a filesystem without ACLs"
        );
        // Root is not trusted anywhere else: a directory named by --dir stays the uid's own.
        assert!(
            !dir_ok(0, SYSTEMD_DIR, me, false),
            "root-owned, not the directory of systemd"
        );
        // The dir of a root process is its own whichever way it is told.
        assert!(dir_ok(0, 0o40700, 0, false));
    }

    /// verifies: REQ-DATA-112
    #[test]
    fn another_uid_or_a_writable_mode_is_refused_for_root_too() {
        let me = 61_022;
        for systemd in [false, true] {
            assert!(
                !dir_ok(me + 1, SYSTEMD_DIR, me, systemd),
                "another non-root uid owns it"
            );
            assert!(
                !dir_ok(me + 1, 0o40700, me, systemd),
                "another non-root uid, closed"
            );
        }
        // Group write is the ACL mask's write: no named entry may write either.
        assert!(
            !dir_ok(0, 0o40570, me, true),
            "root-owned, group-writable (mask rwx)"
        );
        assert!(!dir_ok(0, 0o40770, me, true));
        assert!(!dir_ok(0, 0o40552, me, true), "root-owned, others write");
        assert!(!dir_ok(0, 0o40557, me, true), "root-owned, world-writable");
        assert!(!dir_ok(me, 0o40570, me, true), "own uid, group-writable");
        assert!(!dir_ok(me, 0o40502, me, true), "own uid, others write");
    }

    /// verifies: REQ-DATA-112
    #[test]
    fn a_file_of_systemd_is_accepted_with_its_acl_and_refused_without() {
        let me = 61_022;
        // -r--r-----+ root:root
        assert!(file_ok(0, SYSTEMD_FILE, me, true, true));
        assert!(
            file_ok(0, 0o100400, me, true, false),
            "root-owned, owner-only"
        );
        assert!(
            file_ok(me, 0o100400, me, true, false),
            "chowned to the service user"
        );
        // The same bits without an ACL are a real group that can read it.
        assert!(
            !file_ok(0, SYSTEMD_FILE, me, true, false),
            "group-readable and no ACL"
        );
        // Outside the directory of systemd root's file and an ACL do not count.
        assert!(
            !file_ok(0, 0o100400, me, false, false),
            "root-owned, not systemd's directory"
        );
        assert!(
            !file_ok(0, SYSTEMD_FILE, me, false, true),
            "an ACL elsewhere is not systemd's grant"
        );
        assert!(
            !file_ok(me, 0o100440, me, false, true),
            "an ACL elsewhere is not systemd's grant"
        );
    }

    /// verifies: REQ-DATA-112
    #[test]
    fn a_file_of_another_uid_or_a_writable_or_open_file_is_refused_for_root_too() {
        let me = 61_022;
        for (systemd, acl) in [(false, false), (true, false), (true, true)] {
            assert!(
                !file_ok(me + 1, 0o100400, me, systemd, acl),
                "a non-root uid, {systemd} {acl}"
            );
            assert!(
                !file_ok(me + 1, SYSTEMD_FILE, me, systemd, acl),
                "{systemd} {acl}"
            );
            assert!(
                !file_ok(0, 0o100404, me, systemd, acl),
                "others read, {systemd} {acl}"
            );
            assert!(
                !file_ok(0, 0o100402, me, systemd, acl),
                "others write, {systemd} {acl}"
            );
            assert!(
                !file_ok(0, 0o100420, me, systemd, acl),
                "group write, {systemd} {acl}"
            );
            assert!(
                !file_ok(0, 0o100660, me, systemd, acl),
                "group read-write, {systemd} {acl}"
            );
            assert!(
                !file_ok(me, 0o100420, me, systemd, acl),
                "own uid, group write, {systemd} {acl}"
            );
        }
    }

    /// verifies: REQ-DATA-112
    #[test]
    fn a_directory_is_systemds_by_its_inode_once_canonicalised() {
        let t = closed_dir();
        let real = t.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real, t.path().join("link")).unwrap();
        let other = t.path().join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700)).unwrap();
        let by = |dir: &Path, named: Option<&Path>| Dir::open_in(dir, named).unwrap().systemd;
        assert!(by(&real, Some(&real)));
        assert!(
            by(&real, Some(&t.path().join("link"))),
            "the symlink is canonicalised"
        );
        assert!(by(&real, Some(&t.path().join("real/../real"))));
        assert!(!by(&real, Some(&other)), "another directory");
        assert!(
            !by(&real, Some(&t.path().join("missing"))),
            "a path that does not resolve"
        );
        assert!(!by(&real, None), "$CREDENTIALS_DIRECTORY unset");
        // A symlink as the directory to open is still refused, even when it points at systemd's.
        assert!(Dir::open_in(&t.path().join("link"), Some(&real)).is_err());
    }

    /// The `system.posix_acl_access` value that systemd leaves on a credential for a service user:
    /// version 2, then `user::rw-`, `user:<uid>:r--`, `group::---`, `mask::r--`, `other::---`
    /// (tag, perm, id; little endian). The group bits of the mode become `r--`.
    fn systemd_acl(uid: u32) -> Vec<u8> {
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (1u16, 6u16, u32::MAX),
            (2, 4, uid),
            (4, 0, u32::MAX),
            (0x10, 4, u32::MAX),
            (0x20, 0, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&perm.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        acl
    }

    /// verifies: REQ-DATA-112
    #[test]
    fn a_file_with_systemds_acl_is_read_in_systemds_directory_and_refused_elsewhere() {
        both(|| {
            let t = closed_dir();
            let p = t.path().join("c");
            std::fs::write(&p, b"v").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            let f = std::fs::File::open(&p).unwrap();
            let set = rustix::fs::fsetxattr(
                &f,
                "system.posix_acl_access",
                &systemd_acl(own_uid()),
                rustix::fs::XattrFlags::empty(),
            );
            if set.is_err() {
                eprintln!("no ACL support below {}", t.path().display());
                return;
            }
            assert_eq!(
                f.metadata().unwrap().mode() & 0o777,
                0o640,
                "the mask shows"
            );
            let systemd = Dir::open_in(t.path(), Some(t.path())).unwrap();
            assert_eq!(systemd.read("c").unwrap().data, b"v");
            let elsewhere = Dir::open_in(t.path(), None).unwrap();
            assert!(
                matches!(elsewhere.read("c"), Err(Error::Rule)),
                "an ACL outside the directory of systemd is not its grant"
            );
        });
    }

    #[test]
    fn verify_reads_every_credential_and_names_the_first_that_is_refused() {
        both(|| {
            let t = closed_dir();
            for n in ["a", "b"] {
                std::fs::write(t.path().join(n), b"v").unwrap();
                std::fs::set_permissions(t.path().join(n), std::fs::Permissions::from_mode(0o400))
                    .unwrap();
            }
            std::fs::write(t.path().join(".hidden"), b"not a credential").unwrap();
            let dir = Dir::open(t.path()).unwrap();
            assert_eq!(
                dir.verify().unwrap(),
                2,
                "the hidden file is not a credential"
            );
            std::fs::set_permissions(t.path().join("b"), std::fs::Permissions::from_mode(0o440))
                .unwrap();
            let e = dir.verify().unwrap_err().to_string();
            assert_eq!(e, "credential b: rule");
        });
    }

    #[test]
    fn an_access_acl_is_seen_on_the_open_file() {
        let acl = systemd_acl(own_uid());
        let t = closed_dir();
        let p = t.path().join("c");
        std::fs::write(&p, b"v").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let f = std::fs::File::open(&p).unwrap();
        assert!(!has_access_acl(&f), "a plain file");
        match rustix::fs::fsetxattr(
            &f,
            "system.posix_acl_access",
            &acl,
            rustix::fs::XattrFlags::empty(),
        ) {
            Ok(()) => {
                assert!(has_access_acl(&f), "a file with an ACL");
                // What systemd shows: the group bits became the mask.
                assert_eq!(f.metadata().unwrap().mode() & 0o777, 0o640);
            }
            // A filesystem without ACLs (the temporary directory of an unusual host).
            Err(Errno::OPNOTSUPP) => eprintln!("no ACL support below {}", t.path().display()),
            Err(e) => panic!("{e}"),
        }
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
        both(|| {
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
        });
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
        // The seam is per thread: set it in the thread that opens.
        for refused in [false, true] {
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
            std::thread::spawn(move || {
                OPENAT2_REFUSED.set(refused);
                tx.send(dir.read("pipe").err().map(|e| e.to_string()))
            });
            let got = rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("the open of a FIFO hung");
            assert_eq!(got.as_deref(), Some("bound"), "openat2 refused: {refused}");
        }
    }

    #[test]
    fn a_symlink_as_the_file_is_refused_on_both_roads_and_its_target_is_not_read() {
        both(|| {
            let t = closed_dir();
            let real = t.path().join("real");
            std::fs::write(&real, b"v").unwrap();
            std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::os::unix::fs::symlink("real", t.path().join("inside")).unwrap();
            let out = tempfile::tempdir().unwrap();
            let outside = out.path().join("secret");
            std::fs::write(&outside, b"s").unwrap();
            std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::os::unix::fs::symlink(&outside, t.path().join("escape")).unwrap();
            std::os::unix::fs::symlink("../x", t.path().join("up")).unwrap();
            let dir = Dir::open(t.path()).unwrap();
            assert!(dir.read("real").is_ok());
            for n in ["inside", "escape", "up"] {
                assert_eq!(
                    dir.read(n).err().map(|e| e.to_string()).as_deref(),
                    Some("bound"),
                    "{n}"
                );
            }
        });
    }

    #[test]
    fn a_name_that_is_not_one_component_is_refused_by_the_name_rule_and_by_the_fallback() {
        both(|| {
            let t = closed_dir();
            let dir = Dir::open(t.path()).unwrap();
            for n in ["..", "../x", "/etc/passwd", "a/b", ".hidden", ""] {
                assert_eq!(
                    dir.read(n).err().map(|e| e.to_string()).as_deref(),
                    Some("name"),
                    "{n:?}"
                );
            }
        });
        // The fallback alone, past the name rule.
        let t = closed_dir();
        let dir = Dir::open(t.path()).unwrap();
        for n in ["", ".", "..", "../x", "/etc/passwd", "a/b"] {
            let e = open_name(&dir.root, n, OFlags::RDONLY).err();
            assert_eq!(e, Some(Errno::XDEV), "{n:?}");
        }
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
