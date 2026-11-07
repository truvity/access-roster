//! The `directory` driver of exporter@ (ADR 0009, "Destinations"): the destination port over a local directory that a
//! forwarder (or, on a board, a file server) serves as static files. It receives public material only; a sealed kind
//! is never sent to it, and the configuration check refuses that pairing.
//!
//! # Layout
//!
//! - **`root`** holds the documents, one file per address, and is what the server serves. It belongs to the driver's
//!   user and is closed to writes by anyone else. Files are 0644 and directories 0755: the material is public, and the
//!   server that reads it runs as another user.
//! - **`state`** is the driver's own (0700). `state/meta/<address>.json` records what the driver wrote at an address:
//!   its content type, its `Cache-Control`, a version. A document is the driver's, and is listed and removed, only
//!   while it has such a record, so a file someone else put in `root` is never listed and never removed.
//!
//! # A write is whole
//!
//! `put` writes the body to a temporary file in the target's directory (`.tmp-<pid>-<n>`), fsyncs it, renames it over
//! the target and fsyncs the directory. A reader opens the old file or the new one; a crash leaves either, and a stray
//! temporary file that `serve` removes at its start. The record is written after the document, the same way, so a
//! crash between the two leaves a new document with an old record: `list` reports the digest of the file itself, so the
//! reconcile still sees what is there.
//!
//! # Links
//!
//! Every path is checked as an address (no `..`, no empty segment) and every existing component under `root` is
//! looked at with `lstat`: a symlink is refused. Only the driver's user can write under `root`, so the check is a
//! second line, not the first.

#![allow(refining_impl_trait)] // the generated trait returns `impl Encodable`; a concrete type is fine

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, bail};
use serde_json::{Value, json};
use sluis_destination::{
    Destination, Document, Error, Fetched, Listed, Page, Purged, Written, check_address,
    check_document, check_prefix, page_size, sha256_hex,
};

pub mod suite;

/// The registry name of this driver's user.
pub const NAME: &str = "driver-exporter-directory";
/// The registry name of its one caller.
pub const OWNER: &str = "exporter";

const FILE_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o755;
const TMP: &str = ".tmp-";

/// Where a crash is played in a write (tests only).
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Until {
    /// The temporary file is written and synced; nothing is renamed.
    Temp,
    /// The document is in place; its record is not.
    Document,
    /// The whole write.
    Done,
}

struct Inner {
    root: PathBuf,
    meta: PathBuf,
    tmp: PathBuf,
    /// Orders the writers of this process; readers do not take it.
    writes: Mutex<()>,
    counter: AtomicU64,
}

/// The driver. Clones share the directory.
#[derive(Clone)]
pub struct Directory(Arc<Inner>);

fn io(e: &std::io::Error) -> Error {
    // An error of the file system is the destination failing; it names no path.
    Error::Unavailable(format!("{:?}", e.kind()))
}

fn invalid_or_io(e: &std::io::Error) -> Error {
    match e.kind() {
        // A file where a directory is wanted, or the other way round: the address collides with another document.
        std::io::ErrorKind::NotADirectory | std::io::ErrorKind::IsADirectory => {
            Error::Invalid("address")
        }
        _ if e.raw_os_error() == Some(rustix::io::Errno::NOTDIR.raw_os_error()) => {
            Error::Invalid("address")
        }
        _ => io(e),
    }
}

impl Directory {
    /// Opens the directories: `root` for the documents and `state` for the driver's records. Each must be a real
    /// directory (not a symlink) owned by this process's user; `root` must not be writable by anyone else and `state`
    /// must be closed to everyone else.
    ///
    /// # Errors
    ///
    /// When a directory is missing, is not one, belongs to another user, or is open too wide.
    pub fn open(root: &Path, state: &Path) -> anyhow::Result<Self> {
        let me = rustix::process::geteuid().as_raw();
        for (what, dir, wide) in [("root", root, 0o022), ("state", state, 0o077)] {
            let m = fs::symlink_metadata(dir).with_context(|| format!("the {what} directory"))?;
            if !m.is_dir() {
                bail!("the {what} directory is not a directory (a symlink is refused)");
            }
            if m.uid() != me {
                bail!(
                    "the {what} directory is owned by uid {}, not by uid {me}",
                    m.uid()
                );
            }
            if m.mode() & wide != 0 {
                bail!(
                    "the {what} directory has mode {:o}, wider than allowed",
                    m.mode() & 0o7777
                );
            }
        }
        let meta = state.join("meta");
        let tmp = state.join("tmp");
        for d in [&meta, &tmp] {
            fs::create_dir_all(d).context("the driver's state directory")?;
            fs::set_permissions(d, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self(Arc::new(Inner {
            root: root.to_path_buf(),
            meta,
            tmp,
            writes: Mutex::new(()),
            counter: AtomicU64::new(0),
        })))
    }

    /// Removes what a crash left behind: temporary files under `root` (`.tmp-*`) and in the state directory. Only
    /// `serve` calls it, because a running driver's own temporary files match too. Returns how many it removed.
    ///
    /// # Errors
    ///
    /// When a directory cannot be read.
    pub fn sweep(&self) -> std::io::Result<usize> {
        fn walk(dir: &Path, n: &mut usize) -> std::io::Result<()> {
            for e in fs::read_dir(dir)? {
                let e = e?;
                let t = e.file_type()?;
                let name = e.file_name();
                if t.is_dir() {
                    walk(&e.path(), n)?;
                } else if t.is_file() && name.to_string_lossy().starts_with(TMP) {
                    fs::remove_file(e.path())?;
                    *n += 1;
                }
            }
            Ok(())
        }
        let mut n = 0;
        walk(&self.0.root, &mut n)?;
        for e in fs::read_dir(&self.0.tmp)? {
            fs::remove_file(e?.path())?;
            n += 1;
        }
        Ok(n)
    }

    /// The path of an address under `base`, with no symlink among the components that exist.
    fn path(base: &Path, address: &str) -> Result<PathBuf, Error> {
        let mut p = base.to_path_buf();
        for seg in address.split('/') {
            p.push(seg);
            if let Ok(m) = fs::symlink_metadata(&p)
                && m.file_type().is_symlink()
            {
                return Err(Error::Invalid("address"));
            }
        }
        Ok(p)
    }

    fn meta_path(&self, address: &str) -> Result<PathBuf, Error> {
        let mut p = Self::path(&self.0.meta, address)?;
        let mut name = p.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        name.push(".json");
        p.set_file_name(name);
        Ok(p)
    }

    fn temp_name(&self) -> String {
        format!(
            "{TMP}{}-{}",
            std::process::id(),
            self.0.counter.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Writes `body` to a temporary file in `dir` and syncs it; returns its path.
    fn stage(&self, dir: &Path, body: &[u8]) -> std::io::Result<PathBuf> {
        let path = dir.join(self.temp_name());
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)?;
        f.write_all(body)?;
        f.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
        f.sync_all()?;
        Ok(path)
    }

    fn sync_dir(dir: &Path) -> std::io::Result<()> {
        File::open(dir)?.sync_all()
    }

    /// The write of [`Destination::put`], optionally stopped half way (a crash, played by a test).
    ///
    /// # Errors
    ///
    /// As [`Destination::put`].
    #[doc(hidden)]
    pub fn put_until(&self, doc: &Document, until: Until) -> Result<Written, Error> {
        check_document(doc)?;
        let _held = self.0.writes.lock().unwrap_or_else(PoisonError::into_inner);
        let target = Self::path(&self.0.root, &doc.address)?;
        let dir = target
            .parent()
            .ok_or(Error::Invalid("address"))?
            .to_path_buf();
        mkdirs(&self.0.root, &dir).map_err(|e| invalid_or_io(&e))?;
        if fs::symlink_metadata(&target).is_ok_and(|m| m.is_dir()) {
            return Err(Error::Invalid("address"));
        }
        let meta_path = self.meta_path(&doc.address)?;
        let version = fs::read(&meta_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v["version"].as_u64())
            .map_or(1, |v| v.saturating_add(1));
        let sha256 = sha256_hex(&doc.body);

        let staged = self.stage(&dir, &doc.body).map_err(|e| invalid_or_io(&e))?;
        if until == Until::Temp {
            return Ok(Written {
                version: version.to_string(),
                sha256,
            });
        }
        fs::rename(&staged, &target).map_err(|e| {
            let _ = fs::remove_file(&staged);
            invalid_or_io(&e)
        })?;
        Self::sync_dir(&dir).map_err(|e| io(&e))?;
        if until == Until::Document {
            return Ok(Written {
                version: version.to_string(),
                sha256,
            });
        }

        let record = json!({
            "content_type": doc.content_type,
            "cache_control": doc.cache_control,
            "sha256": sha256,
            "version": version,
        });
        let mdir = meta_path
            .parent()
            .ok_or(Error::Invalid("address"))?
            .to_path_buf();
        fs::create_dir_all(&mdir).map_err(|e| invalid_or_io(&e))?;
        let mtmp = self
            .stage(&self.0.tmp, record.to_string().as_bytes())
            .map_err(|e| io(&e))?;
        fs::rename(&mtmp, &meta_path).map_err(|e| {
            let _ = fs::remove_file(&mtmp);
            io(&e)
        })?;
        Self::sync_dir(&mdir).map_err(|e| io(&e))?;
        Ok(Written {
            version: version.to_string(),
            sha256,
        })
    }

    fn delete_sync(&self, address: &str) -> Result<bool, Error> {
        check_address(address)?;
        let _held = self.0.writes.lock().unwrap_or_else(PoisonError::into_inner);
        let meta_path = self.meta_path(address)?;
        if !meta_path.is_file() {
            // Not something this driver wrote: left alone.
            return Ok(false);
        }
        let target = Self::path(&self.0.root, address)?;
        match fs::remove_file(&target) {
            Ok(()) => {
                if let Some(dir) = target.parent() {
                    let _ = Self::sync_dir(dir);
                    prune(&self.0.root, dir);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(&e)),
        }
        fs::remove_file(&meta_path).map_err(|e| io(&e))?;
        if let Some(dir) = meta_path.parent() {
            prune(&self.0.meta, dir);
        }
        Ok(true)
    }

    fn list_sync(&self, prefix: &str, page: Option<&str>, size: usize) -> Result<Page, Error> {
        check_prefix(prefix)?;
        let after = page.filter(|t| !t.is_empty());
        if let Some(t) = after {
            check_address(t).map_err(|_| Error::Invalid("page_token"))?;
        }
        let size = page_size(size);
        let mut addresses = BTreeSet::new();
        collect(&self.0.meta, "", &mut addresses).map_err(|e| io(&e))?;
        let mut documents = Vec::new();
        let mut more = false;
        for address in addresses {
            if !address.starts_with(prefix) || after.is_some_and(|t| address.as_str() <= t) {
                continue;
            }
            let Ok(path) = Self::path(&self.0.root, &address) else {
                continue;
            };
            let Ok(body) = read_file(&path) else { continue };
            let record: Value = fs::read(self.meta_path(&address)?)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or(Value::Null);
            if documents.len() == size {
                more = true;
                break;
            }
            let text = |k: &str| record[k].as_str().unwrap_or_default().to_owned();
            documents.push(Listed {
                sha256: sha256_hex(&body),
                size: body.len() as u64,
                content_type: text("content_type"),
                cache_control: text("cache_control"),
                address,
            });
        }
        let next = if more {
            documents.last().map(|d| d.address.clone())
        } else {
            None
        };
        Ok(Page { documents, next })
    }
}

fn read_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() {
        return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
    }
    let mut v = Vec::with_capacity(usize::try_from(m.len()).unwrap_or(0));
    File::open(path)?.read_to_end(&mut v)?;
    Ok(v)
}

/// Makes `dir` and the directories above it below `root`, each 0755.
fn mkdirs(root: &Path, dir: &Path) -> std::io::Result<()> {
    let rel = dir
        .strip_prefix(root)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut p = root.to_path_buf();
    for seg in rel.components() {
        p.push(seg);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => {}
            Ok(m) if m.file_type().is_symlink() => {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
            }
            Ok(_) => return Err(std::io::Error::from(std::io::ErrorKind::NotADirectory)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&p)?;
                fs::set_permissions(&p, fs::Permissions::from_mode(DIR_MODE))?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Removes the empty directories from `dir` up to, and not including, `base`.
fn prune(base: &Path, dir: &Path) {
    let mut d = dir.to_path_buf();
    while d != base && d.starts_with(base) {
        if fs::remove_dir(&d).is_err() {
            break;
        }
        if !d.pop() {
            break;
        }
    }
}

/// The addresses that have a record below `dir` (a record is `<address>.json`).
fn collect(dir: &Path, rel: &str, out: &mut BTreeSet<String>) -> std::io::Result<()> {
    for e in fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let t = e.file_type()?;
        if t.is_dir() {
            collect(&e.path(), &format!("{rel}{name}/"), out)?;
        } else if t.is_file()
            && let Some(stem) = name.strip_suffix(".json")
            && !name.starts_with(TMP)
        {
            out.insert(format!("{rel}{stem}"));
        }
    }
    Ok(())
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|_| Err(Error::Unavailable("the driver's task failed".into())))
}

impl Destination for Directory {
    async fn put(&self, doc: Document) -> Result<Written, Error> {
        let me = self.clone();
        blocking(move || me.put_until(&doc, Until::Done)).await
    }

    async fn delete(&self, address: &str) -> Result<bool, Error> {
        let (me, address) = (self.clone(), address.to_owned());
        blocking(move || me.delete_sync(&address)).await
    }

    async fn list(&self, prefix: &str, page: Option<&str>, size: usize) -> Result<Page, Error> {
        let (me, prefix, page) = (self.clone(), prefix.to_owned(), page.map(str::to_owned));
        blocking(move || me.list_sync(&prefix, page.as_deref(), size)).await
    }

    /// A directory has no edge.
    async fn purge(&self, _addresses: &[String]) -> Result<Purged, Error> {
        Ok(Purged::None)
    }

    /// A directory declares no public address to this driver: what a verifier sees is the forwarder's.
    async fn read_back(&self, _address: &str) -> Result<Fetched, Error> {
        Err(Error::Unsupported)
    }
}
